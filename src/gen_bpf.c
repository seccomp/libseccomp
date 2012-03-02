/**
 * Seccomp BPF Translator
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
 */

/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* XXX - only 32bit at present, although 64bit should be easy to add */

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/filter.h>

#include <seccomp.h>

#include "gen_bpf.h"
#include "db.h"
#include "hash.h"

/* are we 32bit or 64bit? */
#if __BITS_PER_LONG == 32
#define _BPF_32
#elif __BITS_PER_LONG == 64
#define _BPF_64
#else
#error unknown platform
#endif

/* allocation increments */
#define AINC_BLK		8
#define AINC_PROG		64

enum bpf_jump_type {
	TGT_NONE = 0,
	TGT_K,			/* immediate "k" value */
	TGT_NXT,		/* fall through to the next block */
	TGT_IMM,		/* resolved immediate value */
	TGT_PTR_DB,		/* pointer to part of the filter db */
	TGT_PTR_BLK,		/* pointer to an instruction block */
	TGT_PTR_HSH,		/* pointer to a block hash table */
};

struct bpf_jump {
	enum bpf_jump_type type;
	union {
		uint8_t imm_j;
		uint32_t imm_k;
		uint64_t hash;
		void *ptr;
	} tgt;
};
#define _BPF_JMP_NO \
	((struct bpf_jump) { TGT_NONE, { .ptr = 0 } })
#define _BPF_JMP_NXT \
	((struct bpf_jump) { TGT_NXT, { .ptr = 0 } })  /* be careful! */
#define _BPF_JMP_IMM(x) \
	((struct bpf_jump) { TGT_IMM, { .imm_j = (x) } })
#define _BPF_JMP_DB(x) \
	((struct bpf_jump) { TGT_PTR_DB, { .ptr = (x) } })
#define _BPF_JMP_BLK(x) \
	((struct bpf_jump) { TGT_PTR_BLK, { .ptr = (x) } })
#define _BPF_JMP_HSH(x) \
	((struct bpf_jump) { TGT_PTR_HSH, { .hash = (x) } })
#define _BPF_K(x) \
	((struct bpf_jump) { TGT_K, { .imm_k = (x) } })
#define _BPF_JMP_MAX		255

struct bpf_instr {
	uint16_t op;
	struct bpf_jump jt;
	struct bpf_jump jf;
	struct bpf_jump k;
};
#define _BPF_SYSCALL		_BPF_K(0)
#define _BPF_ARG(x)		_BPF_K((8 + ((x) * 4)))
#define _BPF_ALLOW		_BPF_K(0xffffffff)
#define _BPF_DENY		_BPF_K(0)

struct bpf_blk {
	struct bpf_instr *blks;
	unsigned int blk_cnt;
	unsigned int blk_alloc;

	/* priority - higher is better */
	unsigned int priority;

	/* used during final block assembly */
	uint64_t hash;
	struct bpf_blk *prev, *next;
};
#define _BLK_MSZE(x) \
	((x)->blk_cnt * sizeof(*((x)->blks)))

struct bpf_hash_bkt {
	struct bpf_blk *blk;
	unsigned int refcnt;

	unsigned int found;

	struct bpf_hash_bkt *next;
};

#define _BPF_HASH_BITS		8
#define _BPF_HASH_SIZE		(1 << _BPF_HASH_BITS)
#define _BPF_HASH_MASK		(_BPF_HASH_BITS - 1)
struct bpf_state {
	/* filter actions */
	enum scmp_flt_action def_action;
	enum scmp_flt_action blk_action;

	/* default action */
	uint64_t def_hsh;

	/* block hash table */
	struct bpf_hash_bkt *htbl[_BPF_HASH_SIZE];

	/* bpf program */
	struct bpf_program *bpf;
};

/**
 * Populate a BPF instruction
 * @param _ins the BPF instruction
 * @param _op the BPF operand
 * @param _jt the BPF jt value
 * @param _jf the BPF jf value
 * @param _k the BPF k value
 *
 * Set the given values on the provided bpf_instr struct.
 *
 */
#define _BPF_INSTR(_ins,_op,_jt,_jf,_k) \
	do { \
		memset(&(_ins), 0, sizeof(_ins)); \
		(_ins).op = (_op); \
		(_ins).jt = _jt; \
		(_ins).jf = _jf; \
		(_ins).k = _k; \
	} while (0)

static struct bpf_blk *_gen_bpf_chain(struct bpf_state *state,
				      const struct db_arg_chain_tree *chain);

static struct bpf_blk *_hsh_remove(struct bpf_state *state, uint64_t h_val);
static struct bpf_blk *_hsh_find(const struct bpf_state *state, uint64_t h_val);

/**
 * Free the BPF instruction block
 * @param state the BPF state
 * @param blk the BPF instruction block
 *
 * Free the BPF instruction block, any linked blocks are preserved and the hash
 * table is not modified.  In general, you probably want to use _blk_free()
 * instead.
 *
 */
static void __blk_free(struct bpf_state *state, struct bpf_blk *blk)
{
	if (blk->blks != NULL)
		free(blk->blks);
	free(blk);
}

/**
* Free the BPF instruction block
 * @param state the BPF state
 * @param blk the BPF instruction block
 *
 * Free the BPF instruction block including any linked blocks.  The hash table
 * is updated to reflect the newly removed block(s).
 *
 */
static void _blk_free(struct bpf_state *state, struct bpf_blk *blk)
{
	int iter;
	struct bpf_blk *b_iter;
	struct bpf_instr *i_iter;

	if (blk == NULL)
		return;

	/* remove this block from the hash table */
	_hsh_remove(state, blk->hash);

	/* run through the block freeing TGT_PTR_{BLK,HSH} jump targets */
	for (iter = 0; iter < blk->blk_cnt; iter++) {
		i_iter = &blk->blks[iter];
		switch (i_iter->jt.type) {
		case TGT_PTR_BLK:
			_blk_free(state, i_iter->jt.tgt.ptr);
			break;
		case TGT_PTR_HSH:
			b_iter = _hsh_find(state, i_iter->jt.tgt.hash);
			_blk_free(state, b_iter);
			break;
		default:
			/* do nothing */
			break;
		}
		switch (i_iter->jf.type) {
		case TGT_PTR_BLK:
			_blk_free(state, i_iter->jf.tgt.ptr);
			break;
		case TGT_PTR_HSH:
			b_iter = _hsh_find(state, i_iter->jf.tgt.hash);
			_blk_free(state, b_iter);
			break;
		default:
			/* do nothing */
			break;
		}
	}
	__blk_free(state, blk);
}

/**
 * Append a new BPF instruction to an instruction block
 * @param state the BPF state
 * @param blk the existing instruction block, or NULL
 * @param instr the new instruction
 *
 * Add the new BPF instruction to the end of the give instruction block.  If
 * the given instruction block is NULL, a new block will be allocated.  Returns
 * a pointer to the block on success, NULL on failure and in the case of
 * failure the instruction block is free'd.
 *
 */
static struct bpf_blk *_blk_append(struct bpf_state *state,
				   struct bpf_blk *blk,
				   const struct bpf_instr *instr)
{
	struct bpf_instr *new;

	if (blk == NULL) {
		blk = malloc(sizeof(*blk));
		if (blk == NULL)
			return NULL;
		memset(blk, 0, sizeof(*blk));
	}
	if ((blk->blk_cnt + 1) > blk->blk_alloc) {
		blk->blk_alloc += AINC_BLK;
		new = realloc(blk->blks, blk->blk_alloc * sizeof(*(blk->blks)));
		if (new == NULL) {
			_blk_free(state, blk);
			return NULL;
		}
		blk->blks = new;
	}
	memcpy(&blk->blks[blk->blk_cnt++], instr, sizeof(*instr));

	return blk;
}

/**
 * Append a block of BPF instructions to the final BPF program
 * @param prg the BPF program
 * @param blk the BPF instruction block
 *
 * Add the BPF instruction block to the end of the BPF program and perform the
 * necssary translation.  Returns zero on success, negative values on failure
 * and in the case of failure the BPF program is free'd.
 *
 */
static int _bpf_append_blk(struct bpf_program *prg, const struct bpf_blk *blk)
{
	int rc;
	struct bpf_instr_raw *i_new;
	struct bpf_instr_raw *i_iter;
	unsigned int old_cnt = prg->blk_cnt;
	unsigned int iter;

	/* (re)allocate the program memory */
	prg->blk_cnt += blk->blk_cnt;
	i_new = realloc(prg->blks, BPF_PGM_SIZE(prg));
	if (i_new == NULL) {
		rc = -ENOMEM;
		goto bpf_append_blk_failure;
	}
	prg->blks = i_new;

	/* transfer and translate the blocks to raw instructions */
	for (iter = 0; iter < blk->blk_cnt; iter++) {
		i_iter = &(prg->blks[old_cnt + iter]);

		i_iter->op = blk->blks[iter].op;
		switch (blk->blks[iter].jt.type) {
		case TGT_NONE:
			i_iter->jt = 0;
			break;
		case TGT_IMM:
			/* jump to the value specified */
			i_iter->jt = blk->blks[iter].jt.tgt.imm_j;
			break;
		default:
			/* fatal error - we should never get here */
			rc = -EFAULT;
			goto bpf_append_blk_failure;
		}
		switch (blk->blks[iter].jf.type) {
		case TGT_NONE:
			i_iter->jf = 0;
			break;
		case TGT_IMM:
			/* jump to the value specified */
			i_iter->jf = blk->blks[iter].jf.tgt.imm_j;
			break;
		default:
			/* fatal error - we should never get here */
			rc = -EFAULT;
			goto bpf_append_blk_failure;
		}
		switch (blk->blks[iter].k.type) {
		case TGT_NONE:
			i_iter->k = 0;
			break;
		case TGT_K:
			i_iter->k = blk->blks[iter].k.tgt.imm_k;
			break;
		default:
			/* fatal error - we should never get here */
			rc = -EFAULT;
			goto bpf_append_blk_failure;
		}
	}

	return prg->blk_cnt;

bpf_append_blk_failure:
	prg->blk_cnt = 0;
	free(prg->blks);
	return rc;
}

/**
 * Append a single BPF instruction to the final BPF program
 * @param prg the BPF program
 * @param instr the BPF instruction
 *
 * Add the BPF instruction to the end of the BPF program and perform the
 * necssary translation.  Returns zero on success, negative values on failure
 * and in the case of failure the BPF program is free'd.
 *
 */
static int _bpf_append_instr(struct bpf_program *prg,
			     struct bpf_instr *instr)
{
	struct bpf_blk blk;

	memset(&blk, 0, sizeof(blk));
	blk.blk_cnt = 1;
	blk.blk_alloc = 1;
	blk.blks = instr;

	return _bpf_append_blk(prg, &blk);
}

/**
 * Free the BPF program
 * @param prg the BPF program
 *
 * Free the BPF program.  None of the associated BPF state used to generate the
 * BPF program is released in this function.
 *
 */
static void _program_free(struct bpf_program *prg)
{
	if (prg == NULL)
		return;

	if (prg->blks != NULL)
		free(prg->blks);
	free(prg);
}

/**
 * Free the BPF state
 * @param the BPF state
 *
 * Free all of the BPF state, including the BPF program if present.
 *
 */
static void _state_release(struct bpf_state *state)
{
	unsigned int bkt;
	struct bpf_hash_bkt *iter;

	if (state == NULL)
		return;

	/* release all of the hash table entries */
	for (bkt = 0; bkt < _BPF_HASH_SIZE; bkt++) {
		while (state->htbl[bkt]) {
			iter = state->htbl[bkt];
			state->htbl[bkt] = iter->next;
			__blk_free(state, iter->blk);
			free(iter);
		}
	}
	_program_free(state->bpf);

	memset(state, 0, sizeof(*state));
}

/**
 * Add an instruction block to the BPF state hash table
 * @param state the BPF state
 * @param blk_p pointer to the BPF instruction block
 * @param found initial found value (see _hsh_find_once() for description)
 *
 * This function adds an instruction block to the hash table, and frees the
 * block if an identical instruction block already exists, returning a pointer
 * to the original block in place of the given block.  Returns zero on success
 * and negative values on failure.
 *
 */
static int _hsh_add(struct bpf_state *state, struct bpf_blk **blk_p,
		    unsigned int found)
{
	uint64_t h_val;
	struct bpf_hash_bkt *h_new, *h_iter, *h_prev = NULL;
	struct bpf_blk *blk = *blk_p;

	h_new = malloc(sizeof(*h_new));
	if (h_new == NULL)
		return -ENOMEM;
	memset(h_new, 0, sizeof(*h_new));

	/* generate the hash */
	h_val = jhash(blk->blks, _BLK_MSZE(blk), 0);
	h_new->blk = blk;
	h_new->blk->hash = h_val;
	h_new->refcnt = 1;
	h_new->found = (found ? 1 : 0);

	/* insert the block into the hash table */
	h_iter = state->htbl[h_val & _BPF_HASH_MASK];
	if (h_iter != NULL) {
		do {
			if ((h_iter->blk->hash == h_val) &&
			    (_BLK_MSZE(h_iter->blk) == _BLK_MSZE(blk)) &&
			    (memcmp(h_iter->blk->blks, blk->blks,
				    _BLK_MSZE(blk)) == 0)) {
				/* duplicate block */
				free(h_new);

				/* update the priority if needed */
				if (h_iter->blk->priority < blk->priority)
					h_iter->blk->priority = blk->priority;

				/* free the block */
				__blk_free(state, blk);
				h_iter->refcnt++;
				*blk_p = h_iter->blk;
				return 0;
			} else if (h_iter->blk->hash == h_val) {
				/* hash collision */
				if ((h_val >> 32) == 0xffffffff)
					/* overflow */
					return -EFAULT;
				h_val += ((uint64_t)1 << 32);
				h_new->blk->hash = h_val;

				/* restart at the beginning of the bucket */
				h_iter = state->htbl[h_val & _BPF_HASH_MASK];
			} else {
				/* no match, move along */
				h_prev = h_iter;
				h_iter = h_iter->next;
			}
		} while (h_iter != NULL);
		h_prev->next = h_new;
	} else
		state->htbl[h_val & _BPF_HASH_MASK] = h_new;

	return 0;
}

/**
 * Remove an entry from the hash table
 * @param state the BPF state
 * @param h_val the hash value
 *
 * Remove an entry from the hash table and return it to the caller, NULL is
 * returned if the entry can not be found.
 *
 */
static struct bpf_blk *_hsh_remove(struct bpf_state *state, uint64_t h_val)
{
	unsigned int bkt = h_val & _BPF_HASH_MASK;
	struct bpf_blk *blk;
	struct bpf_hash_bkt *h_iter, *h_prev = NULL;

	h_iter = state->htbl[bkt];
	while (h_iter != NULL) {
		if (h_iter->blk->hash == h_val) {
			if (h_prev != NULL)
				h_prev->next = h_iter->next;
			else
				state->htbl[bkt] = h_iter->next;
			blk = h_iter->blk;
			free(h_iter);
			return blk;
		}
		h_prev = h_iter;
		h_iter =  h_iter->next;
	}

	return NULL;
}

/**
 * Find and return a hash bucket
 * @param state the BPF state
 * @param h_val the hash value
 *
 * Find the entry associated with the given hash value and return it to the
 * caller, NULL is returned if the entry can not be found.  This function
 * should not be called directly; use _hsh_find() and _hsh_find_once() instead.
 *
 */
static struct bpf_hash_bkt *_hsh_find_bkt(const struct bpf_state *state,
					  uint64_t h_val)
{
	struct bpf_hash_bkt *h_iter;

	h_iter = state->htbl[h_val & _BPF_HASH_MASK];
	while (h_iter != NULL) {
		if (h_iter->blk->hash == h_val)
			return h_iter;
		h_iter = h_iter->next;
	}

	return NULL;
}

/**
 * Find and only return an entry in the hash table once
 * @param state the BPF state
 * @param h_val the hash value
 *
 * Find the entry associated with the given hash value and return it to the
 * caller if it has not be returned previously by this function; returns NULL
 * if the entry can not be found or has already been returned in a previous
 * call.
 *
 */
static struct bpf_blk *_hsh_find_once(const struct bpf_state *state,
				      uint64_t h_val)
{
	struct bpf_hash_bkt *h_iter;

	h_iter = _hsh_find_bkt(state, h_val);
	if (h_iter == NULL || h_iter->found != 0)
		return NULL;
	h_iter->found = 1;
	return h_iter->blk;
}

/**
 * Finds an entry in the hash table
 * @param state the BPF state
 * @param h_val the hash value
 *
 * Find the entry associated with the given hash value and return it to the
 * caller, NULL is returned if the entry can not be found.
 *
 */
static struct bpf_blk *_hsh_find(const struct bpf_state *state, uint64_t h_val)
{
	struct bpf_hash_bkt *h_iter;

	h_iter = _hsh_find_bkt(state, h_val);
	if (h_iter == NULL)
		return NULL;
	return h_iter->blk;
}

/**
 * Generate a BPF instruction block for a given chain node
 * @param state the BPF state
 * @param node the filter chain node
 * @param acc_arg the argument loaded into the accumulator
 *
 * Generate the BPF instructions to execute the filter specified by the given
 * chain node.  Returns a pointer to the instruction block on success, NULL on
 * failure.
 *
 */
static struct bpf_blk *_gen_bpf_chain_node(struct bpf_state *state,
					   const struct db_arg_chain_tree *node,
					   int *acc_arg)
{
	struct bpf_blk *blk = NULL;
	struct bpf_instr instr;

	if (node->arg != *acc_arg) {
		/* reload the accumulator */
		*acc_arg = node->arg;
		_BPF_INSTR(instr, BPF_LD+BPF_ABS,
			_BPF_JMP_NO, _BPF_JMP_NO, _BPF_ARG(*acc_arg));
		blk = _blk_append(state, blk, &instr);
		if (blk == NULL)
			goto chain_node_failure;
	}

	/* do any necessary alu operations */
	/* XXX - only needed for bitmask which we don't support yet as it
	 *       messes up the accumulator value */

	/* check the accumulator against the datum */
	switch (node->op) {
	case SCMP_CMP_EQ:
		_BPF_INSTR(instr, BPF_JMP+BPF_JEQ,
			   _BPF_JMP_NO, _BPF_JMP_NO, _BPF_K(node->datum));
			break;
	case SCMP_CMP_GT:
		_BPF_INSTR(instr, BPF_JMP+BPF_JGT,
			   _BPF_JMP_NO, _BPF_JMP_NO, _BPF_K(node->datum));
		break;
	case SCMP_CMP_GE:
		_BPF_INSTR(instr, BPF_JMP+BPF_JGE,
			   _BPF_JMP_NO, _BPF_JMP_NO, _BPF_K(node->datum));
		break;
	case SCMP_CMP_NE:
	case SCMP_CMP_LT:
	case SCMP_CMP_LE:
		/* if we hit here it means the filter db isn't correct */
	default:
		/* fatal error, we should never get here */
		goto chain_node_failure;
	}

	/* fixup the jump targets */
	if (node->nxt_t != NULL)
		instr.jt = _BPF_JMP_DB(node->nxt_t);
	else if ((node->action != 0) && (node->action_flag))
		instr.jt = _BPF_JMP_IMM(0);
	else
		instr.jt = _BPF_JMP_NXT;
	if (node->nxt_f != NULL)
		instr.jf = _BPF_JMP_DB(node->nxt_f);
	else if ((node->action != 0) && (!node->action_flag))
		instr.jf = _BPF_JMP_IMM(0);
	else
		instr.jf = _BPF_JMP_NXT;
	blk = _blk_append(state, blk, &instr);
	if (blk == NULL)
		goto chain_node_failure;

	/* take any action needed */
	if (node->action != 0) {
		if (node->action == SCMP_ACT_ALLOW)
			_BPF_INSTR(instr, BPF_RET,
				   _BPF_JMP_NO, _BPF_JMP_NO, _BPF_ALLOW);
		else if (node->action == SCMP_ACT_DENY)
			_BPF_INSTR(instr, BPF_RET,
				   _BPF_JMP_NO, _BPF_JMP_NO, _BPF_DENY);
		blk = _blk_append(state, blk, &instr);
		if (blk == NULL)
			goto chain_node_failure;
	}

	return blk;

chain_node_failure:
	_blk_free(state, blk);
	return NULL;
}

/**
 * Generate a BPF instruction block for a given filter DB level
 * @param state the BPF state
 * @param node the filter DB node
 *
 * Generate a BPF instruction block which executes the filter specified by the
 * given filter DB level.  Returns a pointer to the instruction block on
 * success, NULL on failure.  The given BPF block is free'd on failure.
 *
 */
static struct bpf_blk *_gen_bpf_chain_lvl(struct bpf_state *state,
					  const struct db_arg_chain_tree *node)
{
	struct bpf_blk *blk;
	struct bpf_blk *b_head = NULL, *b_prev = NULL, *b_next, *b_iter;
	struct bpf_instr instr;
	struct bpf_instr *i_iter;
	const struct db_arg_chain_tree *l_iter;
	int acc_arg = -1;
	unsigned int iter;

	if (node == NULL) {
		if (state->blk_action == SCMP_ACT_ALLOW)
			_BPF_INSTR(instr, BPF_RET,
				   _BPF_JMP_NO, _BPF_JMP_NO,
				   _BPF_ALLOW);
		else if (state->blk_action == SCMP_ACT_DENY)
			_BPF_INSTR(instr, BPF_RET,
				   _BPF_JMP_NO, _BPF_JMP_NO,
				   _BPF_DENY);
		blk = _blk_append(state, NULL, &instr);
		if (blk == NULL)
			goto chain_lvl_failure;
		return blk;
	}

	/* find the starting node of the level */
	l_iter = node;
	while (l_iter->lvl_prv != NULL)
		l_iter = l_iter->lvl_prv;

	/* build all of the blocks for this level */
	do {
		blk = _gen_bpf_chain_node(state, l_iter, &acc_arg);
		if (blk == NULL)
			goto chain_lvl_failure;
		if (b_head != NULL) {
			b_prev->next = blk;
			blk->prev = b_prev;
		} else
			b_head = blk;

		b_prev = blk;
		l_iter = l_iter->lvl_nxt;
	} while (l_iter != NULL);

	/* resolve the TGT_NXT jumps */
	b_iter = b_head;
	do {
		b_next = b_iter->next;
		for (iter = 0; iter < b_iter->blk_cnt; iter++) {
			i_iter = &b_iter->blks[iter];
			switch (i_iter->jt.type) {
			case TGT_NONE:
			case TGT_IMM:
			case TGT_PTR_DB:
				/* ignore these jump types */
				break;
			case TGT_NXT:
				if (b_next != NULL)
					i_iter->jt = _BPF_JMP_BLK(b_next);
				else
					i_iter->jt = _BPF_JMP_HSH(
								state->def_hsh);
				break;
			default:
				/* we should not be here */
				goto chain_lvl_failure;
			}
			switch (i_iter->jf.type) {
			case TGT_NONE:
			case TGT_IMM:
			case TGT_PTR_DB:
				/* ignore these jump types */
				break;
			case TGT_NXT:
				if (b_next != NULL)
					i_iter->jf = _BPF_JMP_BLK(b_next);
				else
					i_iter->jf = _BPF_JMP_HSH(
								state->def_hsh);
				break;
			default:
				/* we should not be here */
				goto chain_lvl_failure;
			}
		}
		b_iter->prev = NULL;
		b_iter->next = NULL;
		b_iter = b_next;
	} while (b_iter != NULL);

	return b_head;

chain_lvl_failure:
	while (b_head != NULL) {
		b_iter = b_head;
		b_head = b_iter->next;
		_blk_free(state, b_iter);
	}
	return NULL;
}

/**
 * Resolve the jump targets in a BPF instruction block
 * @param state the BPF state
 * @param blk the BPF instruction block
 *
 * Resolve the jump targets in a BPF instruction block generated by the
 * _gen_bpf_chain_lvl() function and adds the resulting block to the hash
 * table.  Returns a pointer to the new instruction block on success, NULL on
 * failure.
 *
 */
static struct bpf_blk *_gen_bpf_chain_lvl_res(struct bpf_state *state,
					      struct bpf_blk *blk)
{
	int rc;
	unsigned int iter;
	struct bpf_blk *b_new;
	struct bpf_instr *i_iter;

	/* convert TGT_PTR_DB to TGT_PTR_HSH references */
	for (iter = 0; iter < blk->blk_cnt; iter++) {
		i_iter = &blk->blks[iter];
		switch (i_iter->jt.type) {
		case TGT_NONE:
		case TGT_IMM:
		case TGT_PTR_HSH:
			/* ignore these jump types */
			break;
		case TGT_PTR_BLK:
			b_new = _gen_bpf_chain_lvl_res(state,
						       i_iter->jt.tgt.ptr);
			if (b_new == NULL)
				return NULL;
			i_iter->jt = _BPF_JMP_HSH(b_new->hash);
			break;
		case TGT_PTR_DB:
			b_new = _gen_bpf_chain(state, i_iter->jt.tgt.ptr);
			if (b_new == NULL)
				return NULL;
			i_iter->jt = _BPF_JMP_HSH(b_new->hash);
			break;
		default:
			/* we should not be here */
			return NULL;
		}
		switch (i_iter->jf.type) {
		case TGT_NONE:
		case TGT_IMM:
		case TGT_PTR_HSH:
			/* ignore these jump types */
			break;
		case TGT_PTR_BLK:
			b_new = _gen_bpf_chain_lvl_res(state,
						       i_iter->jf.tgt.ptr);
			if (b_new == NULL)
				return NULL;
			i_iter->jf = _BPF_JMP_HSH(b_new->hash);
			break;
		case TGT_PTR_DB:
			b_new = _gen_bpf_chain(state, i_iter->jf.tgt.ptr);
			if (b_new == NULL)
				return NULL;
			i_iter->jf = _BPF_JMP_HSH(b_new->hash);
			break;
		default:
			/* we should not be here */
			return NULL;
		}
		switch (i_iter->k.type) {
		case TGT_NONE:
		case TGT_K:
		case TGT_PTR_HSH:
			/* ignore these jump types */
			break;
		case TGT_PTR_DB:
			b_new = _gen_bpf_chain(state, i_iter->k.tgt.ptr);
			if (b_new == NULL)
				return NULL;
			i_iter->k = _BPF_JMP_HSH(b_new->hash);
			break;
		default:
			/* we should not be here */
			return NULL;
		}
	}

	/* insert the block into the hash table */
	rc = _hsh_add(state, &blk, 0);
	if (rc < 0)
		return NULL;

	return blk;
}

/**
 * Generates the BPF instruction blocks for a given filter chain
 * @param state the BPF state
 * @param chain the filter chain
 *
 * Generate the BPF instruction blocks for the given filter chain and return
 * a pointer to the first block on success; returns NULL on failure.
 *
 */
static struct bpf_blk *_gen_bpf_chain(struct bpf_state *state,
				      const struct db_arg_chain_tree *chain)
{
	struct bpf_blk *blk;

	blk = _gen_bpf_chain_lvl(state, chain);
	if (blk == NULL)
		return NULL;
	return _gen_bpf_chain_lvl_res(state, blk);
}

/**
 * Generate the BPF instruction blocks for a given syscall
 * @param state the BPF state
 * @param sys the syscall filter DB entry
 *
 * Generate the BPF instruction blocks for the given syscall filter and return
 * a pointer to the first block on success; returns NULL on failure.
 *
 */
static struct bpf_blk *_gen_bpf_syscall(struct bpf_state *state,
					const struct db_sys_list *sys)
{
	int rc;
	struct bpf_instr instr;
	struct bpf_blk *blk_c, *blk_s;

	/* generate the argument chains */
	blk_c = _gen_bpf_chain(state, sys->chains);
	if (blk_c == NULL)
		return NULL;

	/* syscall check (syscall number is still in the accumulator) */
	_BPF_INSTR(instr, BPF_JMP+BPF_JEQ,
		   _BPF_JMP_HSH(blk_c->hash), _BPF_JMP_NXT, _BPF_K(sys->num));
	blk_s = _blk_append(state, NULL, &instr);
	if (blk_s == NULL)
		return NULL;
	blk_s->priority = sys->priority;
	rc = _hsh_add(state, &blk_s, 1);
	if (rc < 0)
		return NULL;

	return blk_s;
}

/**
 * Add long jumps to the list of BPF instruction blocks if needed
 * @param state the BPF state
 * @param tail the tail of the instruction block list
 * @param blk the instruction block to check
 * @param offset the instruction offset into the instruction block
 * @param tgt_hash the hash of the jump destination block
 *
 * Using the given block and instruction offset, calculate the jump distance
 * between the jumping instruction and the destination.  If the jump distance
 * is too great, add a long jump instruction to reduce the distance to a legal
 * value.  Returns 1 if a long jump was added, zero if the existing jump is
 * valid, and negative values on failure.
 *
 */
static int _gen_bpf_build_jmp(struct bpf_state *state,
			      struct bpf_blk *tail,
			      struct bpf_blk *blk, unsigned int offset,
			      uint64_t tgt_hash)
{
	unsigned int jmp_len;
	struct bpf_instr instr;
	struct bpf_blk *b_new, *b_jmp, *b_tgt;

	/* find the jump target */
	b_tgt = tail;
	while (b_tgt != blk && b_tgt->hash != tgt_hash)
		b_tgt = b_tgt->prev;
	if (b_tgt == blk)
		return -EFAULT;

	/* calculate the jump distance */
	jmp_len = blk->blk_cnt - (offset + 1);
	b_jmp = blk->next;
	while (b_jmp != NULL && b_jmp != b_tgt && jmp_len < _BPF_JMP_MAX) {
		jmp_len += b_jmp->blk_cnt;
		b_jmp = b_jmp->next;
	}
	if (b_jmp == b_tgt)
		return 0;
	if (b_jmp == NULL)
		return -EFAULT;

	/* we need a long jump, see if one already exists */
	jmp_len = blk->blk_cnt - (offset + 1);
	b_jmp = blk->next;
	while (b_jmp != NULL && b_jmp->hash != tgt_hash &&
	       jmp_len < _BPF_JMP_MAX) {
		jmp_len += b_jmp->blk_cnt;
		b_jmp = b_jmp->next;
	}
	if (b_jmp->hash == tgt_hash)
		return 0;
	if (b_jmp == NULL)
		return -EFAULT;

	/* we need to insert a long jump - create one */
	_BPF_INSTR(instr, BPF_JMP+BPF_JA,
		   _BPF_JMP_NO, _BPF_JMP_NO, _BPF_JMP_HSH(tgt_hash));
	b_new = _blk_append(state, NULL, &instr);
	if (b_new == NULL)
		return -EFAULT;

	/* NOTE - we need to be careful here, we're giving the block a hash
	 *	  value (this is a sneaky way to ensure we leverage the
	 *	  inserted long jumps as much as possible) but we never add the
	 *	  block to the hash table so it won't get cleaned up
	 *	  automatically */
	b_new->hash = tgt_hash;

	/* insert the jump after the current jumping block */
	b_new->prev = blk;
	b_new->next = blk->next;
	blk->next->prev = b_new;
	blk->next = b_new;

	return 1;
}

/**
 * Generate the BPF program for the given filter DB
 * @param state the BPF state
 * @param db the filter DB
 *
 * Generate the BPF program for the given filter DB.  Returns zero on success,
 * negative values on failure.
 *
 */
static int _gen_bpf_build_bpf(struct bpf_state *state,
			      const struct db_filter *db)
{
	int rc;
	int iter;
	uint64_t h_val;
	unsigned int res_cnt;
	unsigned int jmp_len;
	struct bpf_instr instr;
	struct bpf_instr *i_iter;
	struct db_sys_list *s_iter;
	struct bpf_blk *def_blk;
	struct bpf_blk *b_head = NULL, *b_tail = NULL, *b_iter, *b_new, *b_jmp;

	/* create the default action */
	if (state->def_action == SCMP_ACT_ALLOW)
		_BPF_INSTR(instr, BPF_RET,
			   _BPF_JMP_NO, _BPF_JMP_NO, _BPF_ALLOW);
	else if (state->def_action == SCMP_ACT_DENY)
		_BPF_INSTR(instr, BPF_RET,
			   _BPF_JMP_NO, _BPF_JMP_NO, _BPF_DENY);
	else
		return -EFAULT;
	def_blk = _blk_append(state, NULL, &instr);
	if (def_blk == NULL)
		return -ENOMEM;
	rc = _hsh_add(state, &def_blk, 1);
	if (rc < 0)
		return rc;
	state->def_hsh = def_blk->hash;

	/* create the syscall filters and add them to the top block group */
	db_list_foreach(s_iter, db->syscalls) {
		/* build the syscall filter */
		b_new = _gen_bpf_syscall(state, s_iter);
		if (b_new == NULL)
			return -ENOMEM;
		/* add the filter to the list, sorting based on priority */
		if (b_head != NULL) {
			b_iter = b_head;
			do {
				if (b_new->priority > b_iter->priority) {
					if (b_iter == b_head) {
						b_new->next = b_head;
						b_head->prev = b_new;
						b_head = b_new;
					} else {
						b_iter->prev->next = b_new;
						b_new->prev = b_iter->prev;
						b_new->next = b_iter;
						b_iter->prev = b_new;
					}
					b_iter = NULL;
				} else {
					if (b_iter->next == NULL) {
						b_iter->next = b_new;
						b_new->prev = b_iter;
						b_iter = NULL;
					} else
						b_iter = b_iter->next;
				}
			} while (b_iter != NULL);
			if (b_tail->next != NULL)
				b_tail = b_tail->next;
		} else {
			b_head = b_new;
			b_tail = b_head;
			b_head->prev = NULL;
			b_head->next = NULL;
		}
	}

	/* tack on the default action to the end of the top block group */
	if (b_tail != NULL) {
		b_tail->next = def_blk;
		def_blk->prev = b_tail;
		b_tail = def_blk;
	} else {
		b_head = def_blk;
		b_tail = b_head;
	}

	/* resolve any TGT_NXT jumps at the top level */
	b_iter = b_head;
	while (b_iter != NULL && b_iter->next != NULL) {
		b_jmp = b_iter->next;
		for (iter = 0; iter < b_iter->blk_cnt; iter++) {
			i_iter = &b_iter->blks[iter];
			if (i_iter->jt.type == TGT_NXT)
				i_iter->jt = _BPF_JMP_HSH(b_jmp->hash);
			if (i_iter->jf.type == TGT_NXT)
				i_iter->jf = _BPF_JMP_HSH(b_jmp->hash);
			/* we shouldn't need to worry about a TGT_NXT in k */
		}
		b_iter = b_iter->next;
	}

	/* pull in all of the TGT_PTR_HSH jumps, one layer at a time */
	do {
		res_cnt = 0;
		b_iter = b_tail;
		/* go through the block list backwards (no reverse jumps) */
		while (b_iter != NULL) {
			/* look for jumps - backwards (shorter jumps) */
			for (iter = b_iter->blk_cnt - 1; iter >= 0; iter--) {
				i_iter = &b_iter->blks[iter];
				switch (i_iter->jt.type) {
				case TGT_NONE:
				case TGT_IMM:
					break;
				case TGT_PTR_HSH:
					b_jmp = _hsh_find_once(state,
							   i_iter->jt.tgt.hash);
					if (b_jmp == NULL)
						break;
					/* insert the block immediately after*/
					res_cnt++;
					b_jmp->prev = b_iter;
					b_jmp->next = b_iter->next;
					b_iter->next = b_jmp;
					if (b_jmp->next)
						b_jmp->next->prev = b_jmp;
					break;
				default:
					/* fatal error */
					return -EFAULT;
				}
				switch (i_iter->jf.type) {
				case TGT_NONE:
				case TGT_IMM:
					break;
				case TGT_PTR_HSH:
					b_jmp = _hsh_find_once(state,
							   i_iter->jf.tgt.hash);
					if (b_jmp == NULL)
						break;
					/* insert the block immediately after*/
					res_cnt++;
					b_jmp->prev = b_iter;
					b_jmp->next = b_iter->next;
					b_iter->next = b_jmp;
					if (b_jmp->next)
						b_jmp->next->prev = b_jmp;
					break;
				default:
					/* fatal error */
					return -EFAULT;
				}
				switch (i_iter->k.type) {
				case TGT_NONE:
				case TGT_K:
					break;
				case TGT_PTR_HSH:
					b_jmp = _hsh_find_once(state,
							   i_iter->k.tgt.hash);
					if (b_jmp == NULL)
						break;
					/* insert the block immediately after*/
					res_cnt++;
					b_jmp->prev = b_iter;
					b_jmp->next = b_iter->next;
					b_iter->next = b_jmp;
					if (b_jmp->next)
						b_jmp->next->prev = b_jmp;
					break;
				default:
					/* fatal error */
					return -EFAULT;
				}
			}
			b_iter = b_iter->prev;
		}
		/* reset the tail pointer as it may have changed */
		while (b_tail->next != NULL)
			b_tail = b_tail->next;
	} while (res_cnt != 0);

	/* load the syscall into the accumulator */
	_BPF_INSTR(instr, BPF_LD+BPF_ABS,
		   _BPF_JMP_NO, _BPF_JMP_NO, _BPF_SYSCALL);
	rc = _bpf_append_instr(state->bpf, &instr);
	if (rc < 0)
		return rc;

	/* NOTE - from here to the end of the function we need to fail via the
	 *	  the build_bpf_free_blks label, not just return an error; see
	 *	  the _gen_bpf_build_jmp() function for details */

	/* check for long jumps and insert if necessary */
	b_iter = b_tail;
	while (b_iter != NULL) {
		res_cnt = 0;
		for (iter = b_iter->blk_cnt - 1; iter >= 0; iter--) {
			i_iter = &b_iter->blks[iter];
			switch (i_iter->jt.type) {
			case TGT_NONE:
			case TGT_IMM:
				break;
			case TGT_PTR_HSH:
				h_val = i_iter->jt.tgt.hash;
				rc = _gen_bpf_build_jmp(state, b_tail,
							b_iter, iter,
							h_val);
				if (rc < 0)
					goto build_bpf_free_blks;
				res_cnt += rc;
				break;
			default:
				/* fatal error */
				goto build_bpf_free_blks;
			}
			switch (i_iter->jf.type) {
			case TGT_NONE:
			case TGT_IMM:
				break;
			case TGT_PTR_HSH:
				h_val = i_iter->jf.tgt.hash;
				rc = _gen_bpf_build_jmp(state, b_tail,
							b_iter, iter,
							h_val);
				if (rc < 0)
					goto build_bpf_free_blks;
				res_cnt += rc;
				break;
			default:
				/* fatal error */
				goto build_bpf_free_blks;
			}
		}
		if (res_cnt == 0)
			b_iter = b_iter->prev;
	}

	/* build the bpf program */
	b_iter = b_head;
	while (b_iter != NULL) {
		/* resolve the TGT_PTR_HSH jumps */
		for (iter = 0; iter < b_iter->blk_cnt; iter++) {
			i_iter = &b_iter->blks[iter];
			if (i_iter->jt.type == TGT_PTR_HSH) {
				h_val = i_iter->jt.tgt.hash;
				jmp_len = b_iter->blk_cnt - (iter + 1);
				b_jmp = b_iter->next;
				while (b_jmp != NULL && b_jmp->hash != h_val) {
					jmp_len += b_jmp->blk_cnt;
					b_jmp = b_jmp->next;
				}
				if (b_jmp == NULL || jmp_len > _BPF_JMP_MAX)
					goto build_bpf_free_blks;
				i_iter->jt = _BPF_JMP_IMM(jmp_len);
			}
			if (i_iter->jf.type == TGT_PTR_HSH) {
				h_val = i_iter->jf.tgt.hash;
				jmp_len = b_iter->blk_cnt - (iter + 1);
				b_jmp = b_iter->next;
				while (b_jmp != NULL && b_jmp->hash != h_val) {
					jmp_len += b_jmp->blk_cnt;
					b_jmp = b_jmp->next;
				}
				if (b_jmp == NULL || jmp_len > _BPF_JMP_MAX)
					goto build_bpf_free_blks;
				i_iter->jf = _BPF_JMP_IMM(jmp_len);
			}
			if (i_iter->k.type == TGT_PTR_HSH) {
				h_val = i_iter->k.tgt.hash;
				jmp_len = b_iter->blk_cnt - (iter + 1);
				b_jmp = b_tail;
				while (b_jmp->hash != h_val)
					b_jmp = b_jmp->prev;
				b_jmp = b_jmp->prev;
				while (b_jmp != b_iter) {
					jmp_len += b_jmp->blk_cnt;
					b_jmp = b_jmp->prev;
				}
				if (b_jmp == NULL)
					goto build_bpf_free_blks;
				i_iter->k = _BPF_K(jmp_len);
			}
		}

		/* build the bpf program */
		if (_bpf_append_blk(state->bpf, b_iter) < 0)
			goto build_bpf_free_blks;

		/* we're done with the block, free it */
		b_jmp = b_iter->next;
		_blk_free(state, b_iter);
		b_iter = b_jmp;
	}

	return 0;

build_bpf_free_blks:
	b_iter = b_head;
	while (b_iter != NULL) {
		b_jmp = b_iter->next;
		_hsh_remove(state, b_iter->hash);
		__blk_free(state, b_iter);
		b_iter = b_jmp;
	}
	return -EFAULT;
}

/**
 * Generate a BPF representation of the filter DB
 * @param db the seccomp filter DB
 *
 * This function generates a BPF representation of the given filter DB.
 * Returns a pointer to a valid bpf_program on success, NULL on failure.
 *
 */
struct bpf_program *gen_bpf_generate(const struct db_filter *db)
{
	int rc;
	struct bpf_state state;

	memset(&state, 0, sizeof(state));
	state.def_action = db->def_action;
	state.blk_action = (db->def_action == SCMP_ACT_ALLOW ?
			    SCMP_ACT_DENY : SCMP_ACT_ALLOW);

	state.bpf = malloc(sizeof(*(state.bpf)));
	if (state.bpf == NULL)
		return NULL;
	memset(state.bpf, 0, sizeof(*(state.bpf)));

	rc = _gen_bpf_build_bpf(&state, db);
	if (rc < 0)
		goto bpf_generate_end;

bpf_generate_end:
	if (rc < 0)
		_state_release(&state);
	return state.bpf;
}

/**
 * Free memory associated with a BPF representation
 * @param fprog the BPF representation
 *
 * Free the memory associated with a BPF representation generated by the
 * gen_bpf_generate() function.
 *
 */
void gen_bpf_destroy(struct bpf_program *program)
{
	_program_free(program);
}
