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

/* XXX - this file is a new version under test */

/* XXX - only 32bit at present, although 64bit should be easy to add */

/* XXX - the hash functions, or related code, doesn't handle collisions */

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
#define AINC_BLKGRP		8
#define AINC_PROG		64

enum bpf_jump_type {
	TGT_NONE = 0,
	TGT_NXT,		/* fall through to the next block */
	TGT_IMM,		/* resolved immediate value */
	TGT_PTR_DB,		/* pointer to part of the filter db */
	TGT_PTR_BLK,		/* pointer to an instruction block */
	TGT_PTR_HSH,		/* pointer to a block hash table */
};

struct bpf_jump {
	enum bpf_jump_type type;
	union {
		uint8_t imm;
		unsigned int hash;
		void *ptr;
	} tgt;
};
#define _BPF_JMP_NO \
	((struct bpf_jump) { TGT_NONE, { .ptr = 0 } })
#define _BPF_JMP_NXT \
	((struct bpf_jump) { TGT_NXT, { .ptr = 0 } })  /* be careful! */
#define _BPF_JMP_IMM(x) \
	((struct bpf_jump) { TGT_IMM, { .imm = (x) } })
#define _BPF_JMP_DB(x) \
	((struct bpf_jump) { TGT_PTR_DB, { .ptr = (x) } })
#define _BPF_JMP_BLK(x) \
	((struct bpf_jump) { TGT_PTR_BLK, { .ptr = (x) } })
#define _BPF_JMP_HSH(x) \
	((struct bpf_jump) { TGT_PTR_HSH, { .hash = (x) } })
#define _BPF_JMP_MAX		255

struct bpf_instr {
	uint16_t op;
	struct bpf_jump jt;
	struct bpf_jump jf;
	uint32_t k;
};
#define _BPF_SYSCALL		(0)
#define _BPF_ARG(x)		(8 + ((x) * 4))
#define _BPF_ALLOW		(0xffffffff)
#define _BPF_DENY		(0)

struct bpf_blk {
	struct bpf_instr *blks;
	unsigned int blk_cnt;
	unsigned int blk_alloc;

	/* used during final block assembly */
	unsigned int hash;
	struct bpf_blk *prev, *next;
};
#define _BPF_BLK_MSZE(x) \
	((x)->blk_cnt * sizeof(*((x)->blks)))

struct bpf_blk_grp {
	struct bpf_blk **grps;
	unsigned int grp_cnt;
	unsigned int grp_alloc;
};

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

	/* top level block groups */
	struct bpf_blk_grp tg_chains;
	struct bpf_blk *def_blk;
	unsigned int def_hsh;

	/* block hash table */
	struct bpf_hash_bkt *htbl[_BPF_HASH_SIZE];

	/* bpf program */
	struct bpf_program *bpf;
};

#define _max(x,y) \
	((x) > (y) ? (x) : (y))

/**
 * XXX
 */
#define _BPF_INSTR(_ins,_op,_jt,_jf,_k) \
	do { \
		(_ins).op = (_op); \
		(_ins).jt = _jt; \
		(_ins).jf = _jf; \
		(_ins).k = (_k); \
	} while (0)

/**
 * Iterate over each item in the hash bucket
 * @param iter the iterator
 * @param bucket the bucket
 *
 * This macro acts as for()/while() conditional and iterates the following
 * statement for each item in the given hash bucket.
 *
 */
#define _hash_bucket_foreach(iter,bucket) \
	for (iter = (bucket); iter != NULL; iter = iter->next)

static struct bpf_blk *_gen_bpf_chain(struct bpf_state *state,
				      struct bpf_blk *blk,
				      const struct db_arg_chain_tree *c);

static struct bpf_blk *_hsh_remove(struct bpf_state *state, unsigned int h_val);

/**
 * XXX
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
			b_iter = _hsh_remove(state, i_iter->jt.tgt.hash);
			if (b_iter != NULL)
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
			b_iter = _hsh_remove(state, i_iter->jf.tgt.hash);
			if (b_iter != NULL)
				_blk_free(state, b_iter);
			break;
		default:
			/* do nothing */
			break;
		}
	}
	if (blk->blks != NULL)
		free(blk->blks);
	free(blk);
}

/**
 * XXX
 */
static struct bpf_blk *_blk_grow(struct bpf_state *state,
				 struct bpf_blk *blk, unsigned int incr)
{
	unsigned int cnt = _max(AINC_BLK, incr);
	struct bpf_instr *new;

	if (blk == NULL) {
		blk = malloc(sizeof(*blk));
		if (blk == NULL)
			return NULL;
		memset(blk, 0, sizeof(*blk));
	} else if ((blk->blk_cnt + cnt) <= blk->blk_alloc)
		return blk;

	blk->blk_alloc += cnt;
	new = realloc(blk->blks, blk->blk_alloc * sizeof(*(blk->blks)));
	if (new == NULL) {
		_blk_free(state, blk);
		return NULL;
	}
	blk->blks = new;

	return blk;
}

/**
 * XXX
 */
static struct bpf_blk *_blk_append(struct bpf_state *state,
				   struct bpf_blk *blk,
				   const struct bpf_instr *instr)
{
	struct bpf_blk *new;

	new = _blk_grow(state, blk, 1);
	if (new == NULL)
		return NULL;
	memcpy(&new->blks[new->blk_cnt++], instr, sizeof(*instr));

	return new;
}

/**
 * XXX
 */
static void _grp_reset(struct bpf_state *state, struct bpf_blk_grp *grp)
{
	unsigned int iter;

	if (grp == NULL)
		return;

	for (iter = 0; iter < grp->grp_cnt; iter++)
		_blk_free(state, grp->grps[iter]);
	if (grp->grps != NULL)
		free(grp->grps);
	memset(grp, 0, sizeof(*grp));
}

/**
 * XXX
 */
static int _grp_grow(struct bpf_state *state,
		     struct bpf_blk_grp *grp, unsigned int incr)
{
	int iter;
	unsigned int cnt = _max(AINC_BLKGRP, incr);
	struct bpf_blk **new;

	if ((grp->grp_cnt + cnt) <= grp->grp_alloc)
		return 0;

	grp->grp_alloc += cnt;
	new = realloc(grp->grps, grp->grp_alloc * sizeof(*(grp->grps)));
	if (new == NULL) {
		for (iter = 0; iter < grp->grp_cnt; iter++)
			_blk_free(state, grp->grps[iter]);
		free(grp->grps);
		memset(grp, 0, sizeof(*grp));
		return -ENOMEM;
	}
	grp->grps = new;

	return 0;
}

/**
 * XXX
 */
static int _grp_append(struct bpf_state *state,
		       struct bpf_blk_grp *grp, struct bpf_blk *blk)
{
	int rc;

	rc = _grp_grow(state, grp, 1);
	if (rc < 0)
		return rc;
	grp->grps[grp->grp_cnt++] = blk;

	return 0;
}

/**
 * XXX
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

	/* XXX - not sure yet, but we may want to remove the TGT_NXT code */

	/* transfer and translate the blocks to raw instructions */
	for (iter = 0; iter < blk->blk_cnt; iter++) {
		i_iter = &(prg->blks[old_cnt + iter]);

		i_iter->op = blk->blks[iter].op;
		switch (blk->blks[iter].jt.type) {
		case TGT_NONE:
			i_iter->jt = 0;
			break;
		case TGT_NXT:
			/* jump the the end of the block */
			i_iter->jt = blk->blk_cnt - (iter + 1);
			break;
		case TGT_IMM:
			/* jump to the value specified */
			i_iter->jt = blk->blks[iter].jt.tgt.imm;
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
		case TGT_NXT:
			/* jump the the end of the block */
			i_iter->jf = blk->blk_cnt - (iter + 1);
			break;
		case TGT_IMM:
			/* jump to the value specified */
			i_iter->jf = blk->blks[iter].jf.tgt.imm;
			break;
		default:
			/* fatal error - we should never get here */
			rc = -EFAULT;
			goto bpf_append_blk_failure;
		}
		i_iter->k = blk->blks[iter].k;
	}

	return prg->blk_cnt;

bpf_append_blk_failure:
	prg->blk_cnt = 0;
	free(prg->blks);
	return rc;
}

/**
 * XXX
 */
static int _bpf_append_instr(struct bpf_program *prg,
			     const struct bpf_instr *instr)
{
	int rc;
	struct bpf_instr_raw *i_raw;
	unsigned int old_cnt = prg->blk_cnt;

	/* (re)allocate the program memory */
	prg->blk_cnt++;
	i_raw = realloc(prg->blks, BPF_PGM_SIZE(prg));
	if (i_raw == NULL) {
		rc = -ENOMEM;
		goto bpf_append_instr_failure;
	}
	prg->blks = i_raw;

	i_raw = &(prg->blks[old_cnt]);
	i_raw->op = instr->op;
	switch (instr->jt.type) {
		case TGT_NONE:
			i_raw->jt = 0;
			break;
		case TGT_IMM:
			/* jump to the value specified */
			i_raw->jt = instr->jt.tgt.imm;
			break;
		default:
			/* fatal error - we should never get here */
			rc = -EFAULT;
			goto bpf_append_instr_failure;
	}
	switch (instr->jf.type) {
		case TGT_NONE:
			i_raw->jf = 0;
			break;
		case TGT_IMM:
			/* jump to the value specified */
			i_raw->jf = instr->jf.tgt.imm;
			break;
		default:
			/* fatal error - we should never get here */
			rc = -EFAULT;
			goto bpf_append_instr_failure;
	}
	i_raw->k = instr->k;

	return prg->blk_cnt;

bpf_append_instr_failure:
	prg->blk_cnt = 0;
	free(prg->blks);
	return rc;
}

/**
 * XXX
 */
static void _program_free(struct bpf_program *program)
{
	if (program == NULL)
		return;

	if (program->blks != NULL)
		free(program->blks);
	free(program);
}

/**
 * XXX
 */
static void _state_release(struct bpf_state *state)
{
	if (state == NULL)
		return;

	_grp_reset(state, &state->tg_chains);
}

/**
 * XXX
 */
static void _state_reset_all(struct bpf_state *state)
{
	if (state == NULL)
		return;

	_state_release(state);
	_program_free(state->bpf);

	memset(state, 0, sizeof(*state));
}

/**
 * XXX
 */
static int _hsh_add(struct bpf_state *state, struct bpf_blk **blk_p,
		    unsigned int found,
		    unsigned int *h_val_ret)
{
	unsigned int h_val;
	struct bpf_hash_bkt *h_new, *h_iter;
	struct bpf_blk *blk = *blk_p;

	h_new = malloc(sizeof(*h_new));
	if (h_new == NULL)
		return -ENOMEM;
	memset(h_new, 0, sizeof(*h_new));

	/* generate the hash */
	h_val = jhash(blk->blks, _BPF_BLK_MSZE(blk), 0);
	h_new->blk = blk;
	h_new->blk->hash = h_val;
	h_new->refcnt = 1;
	h_new->found = (found ? 1 : 0);

	/* insert the block into the hash table */
	h_iter = state->htbl[h_val & _BPF_HASH_MASK];
	if (h_iter != NULL) {
		while (h_iter->next != NULL) {
			if (h_iter->blk->hash == h_val) {
				/* duplicate block */
				_blk_free(state, blk);
				h_iter->refcnt++;
				*blk_p = h_iter->blk;
				*h_val_ret = h_val;
				return 0;
			}
			h_iter = h_iter->next;
		}
		h_iter->next = h_new;
	} else
		state->htbl[h_val & _BPF_HASH_MASK] = h_new;

	*h_val_ret = h_val;
	return 0;
}

/**
 * XXX
 */
static struct bpf_blk *_hsh_remove(struct bpf_state *state, unsigned int h_val)
{
	unsigned int bkt = h_val & _BPF_HASH_MASK;
	struct bpf_blk *blk;
	struct bpf_hash_bkt *h_iter, *h_prev = NULL;

	h_iter = state->htbl[bkt];
	if (h_iter != NULL) {
		while (h_iter->next != NULL) {
			if (h_iter->blk->hash == h_val) {
				if (--h_iter->refcnt > 0)
					return NULL;

				if (h_prev != NULL)
					h_prev->next = h_iter->next;
				else
					state->htbl[bkt] = h_iter->next;
				blk = h_iter->blk;
				free(h_iter);
				return blk;
			}
			h_iter =  h_iter->next;
		}
	}

	return NULL;
}

/**
 * XXX
 */
static struct bpf_blk *_hsh_find_once(const struct bpf_state *state,
				      unsigned int h_val)
{
	struct bpf_hash_bkt *h_iter;

	h_iter = state->htbl[h_val & _BPF_HASH_MASK];
	while (h_iter != NULL) {
		if (h_iter->blk->hash == h_val) {
			if (h_iter->found == 0) {
				h_iter->found = 1;
				return h_iter->blk;
			} else
				return NULL;
		}
		h_iter = h_iter->next;
	}

	return NULL;
}

/**
 * XXX
 */
static struct bpf_blk *_gen_bpf_chain_lvl(struct bpf_state *state,
					  struct bpf_blk *blk,
					  const struct db_arg_chain_tree *node)
{
	struct bpf_instr instr;
	const struct db_arg_chain_tree *l_iter;
	int acc_arg = -1;
	int last_flag = 0;

	if (node == NULL) {
		if (state->blk_action == SCMP_ACT_ALLOW)
			_BPF_INSTR(instr, BPF_RET,
				   _BPF_JMP_NO, _BPF_JMP_NO,
				   _BPF_ALLOW);
		else if (state->blk_action == SCMP_ACT_DENY)
			_BPF_INSTR(instr, BPF_RET,
				   _BPF_JMP_NO, _BPF_JMP_NO,
				   _BPF_DENY);
		blk = _blk_append(state, blk, &instr);
		if (blk == NULL)
			goto chain_lvl_failure;
		return blk;
	}

	/* find the starting node of the level */
	l_iter = node;
	while (l_iter->lvl_prv != NULL)
		l_iter = l_iter->lvl_prv;

	/* note - if the filter db was built correctly, we shouldn't have any
	 * duplicate instruction block on the same level so include them all
	 * in the same instruction block */
	do {
		/* are we the last node on this level */
		if (l_iter->lvl_nxt == NULL)
			last_flag = 1;

		if (l_iter->arg != acc_arg) {
			/* reload the accumulator */
			acc_arg = l_iter->arg;
			_BPF_INSTR(instr, BPF_LD+BPF_ABS,
				_BPF_JMP_NO, _BPF_JMP_NO, _BPF_ARG(acc_arg));
			blk = _blk_append(state, blk, &instr);
			if (blk == NULL)
				goto chain_lvl_failure;
		}

		/* do any necessary alu operations */
		/* XXX - only needed for bitmask which we don't support yet */
		/* XXX - this messes up the accumulator value */

		/* check the accumulator against the datum */
		switch (l_iter->op) {
		case SCMP_CMP_EQ:
			_BPF_INSTR(instr, BPF_JMP+BPF_JEQ,
				   _BPF_JMP_NO, _BPF_JMP_NO, l_iter->datum);
			break;
		case SCMP_CMP_GT:
			_BPF_INSTR(instr, BPF_JMP+BPF_JGT,
				   _BPF_JMP_NO, _BPF_JMP_NO, l_iter->datum);
			break;
		case SCMP_CMP_GE:
			_BPF_INSTR(instr, BPF_JMP+BPF_JGE,
				   _BPF_JMP_NO, _BPF_JMP_NO, l_iter->datum);
			break;
		case SCMP_CMP_NE:
		case SCMP_CMP_LT:
		case SCMP_CMP_LE:
			/* if we hit here it means that we didn't build
			 * the filter db correctly */
		default:
			/* fatal error, we should never get here */
			goto chain_lvl_failure;
		}

		/* fixup the jump targets */
		if (l_iter->nxt_t != NULL)
			instr.jt = _BPF_JMP_DB(l_iter->nxt_t);
		else if ((l_iter->action != 0) && (l_iter->action_flag))
			/* true falls through to the action by default */
			instr.jf = _BPF_JMP_IMM(1);
		else if (last_flag)
			instr.jt = _BPF_JMP_HSH(state->def_hsh);
		if (l_iter->nxt_f != NULL)
			instr.jf = _BPF_JMP_DB(l_iter->nxt_f);
		else if ((l_iter->action != 0) && (!l_iter->action_flag))
			/* false falls through to the action by default */
			instr.jt = _BPF_JMP_IMM(1);
		else if (last_flag)
			instr.jf = _BPF_JMP_HSH(state->def_hsh);
		blk = _blk_append(state, blk, &instr);
		if (blk == NULL)
			goto chain_lvl_failure;

		/* are we at least partially a leaf node? */
		if (l_iter->action != 0) {
			if (l_iter->action == SCMP_ACT_ALLOW)
				_BPF_INSTR(instr, BPF_RET,
					   _BPF_JMP_NO, _BPF_JMP_NO,
					   _BPF_ALLOW);
			else if (l_iter->action == SCMP_ACT_DENY)
				_BPF_INSTR(instr, BPF_RET,
					   _BPF_JMP_NO, _BPF_JMP_NO,
					   _BPF_DENY);
			blk = _blk_append(state, blk, &instr);
			if (blk == NULL)
				goto chain_lvl_failure;
		}

		l_iter = l_iter->lvl_nxt;
	} while (l_iter != NULL);

	return blk;

chain_lvl_failure:
	_blk_free(state, blk);
	return NULL;
}

/**
 * XXX
 */
static struct bpf_blk *_gen_bpf_chain_lvl_res(struct bpf_state *state,
					      struct bpf_blk *blk)
{
	struct bpf_blk *b_new;
	unsigned int iter;

	/* convert TGT_PTR_DB references to TGT_PTR_BLK references */
	for (iter = 0; iter < blk->blk_cnt; iter++) {
		if (blk->blks[iter].jt.type == TGT_PTR_DB) {
			/* dive down the rabbit hole */
			b_new = _gen_bpf_chain(state, NULL,
					       blk->blks[iter].jt.tgt.ptr);
			if (b_new == NULL)
				return NULL;
			blk->blks[iter].jt = _BPF_JMP_BLK(b_new);
		}
		if (blk->blks[iter].jf.type == TGT_PTR_DB) {
			/* dive down the rabbit hole */
			b_new = _gen_bpf_chain(state, NULL,
					       blk->blks[iter].jf.tgt.ptr);
			if (b_new == NULL)
				return NULL;
			blk->blks[iter].jf = _BPF_JMP_BLK(b_new);
		}
	}

	return blk;
}

/**
 * XXX
 */
static struct bpf_blk *_gen_bpf_chain(struct bpf_state *state,
				      struct bpf_blk *blk,
				      const struct db_arg_chain_tree *c)
{
	blk = _gen_bpf_chain_lvl(state, blk, c);
	if (blk == NULL)
		return NULL;
	return _gen_bpf_chain_lvl_res(state, blk);
}

/**
 * XXX
 */
static int _gen_bpf_blk_hsh(struct bpf_state *state, struct bpf_blk **blk_p,
			    unsigned int *h_val_ret)
{
	int rc;
	int iter;
	struct bpf_instr *i_iter;
	struct bpf_blk *blk = *blk_p, *b_iter;
	unsigned int h_val;

	/* run through the block looking for jumps */
	for (iter = 0; iter < blk->blk_cnt; iter++) {
		i_iter = &blk->blks[iter];
		switch (i_iter->jt.type) {
		case TGT_NONE:
		case TGT_NXT:
		case TGT_IMM:
		case TGT_PTR_HSH:
			/* ignore these jump types */
			break;
		case TGT_PTR_BLK:
			/* start at the leaf nodes */
			b_iter = i_iter->jt.tgt.ptr;
			rc = _gen_bpf_blk_hsh(state, &b_iter, &h_val);
			if (rc < 0)
				return rc;
			i_iter->jt = _BPF_JMP_HSH(h_val);
			break;
		default:
			/* we should not be here */
			return -EFAULT;
		}
		switch (i_iter->jf.type) {
		case TGT_NONE:
		case TGT_NXT:
		case TGT_IMM:
		case TGT_PTR_HSH:
			/* ignore these jump types */
			break;
		case TGT_PTR_BLK:
			/* start at the leaf nodes */
			b_iter = i_iter->jf.tgt.ptr;
			rc = _gen_bpf_blk_hsh(state, &b_iter, &h_val);
			if (rc < 0)
				return rc;
			i_iter->jf = _BPF_JMP_HSH(h_val);
			break;
		default:
			/* we should not be here */
			return -EFAULT;
		}
	}

	/* insert the block into the hash table */
	rc = _hsh_add(state, &blk, 0, &h_val);
	if (rc < 0)
		return rc;
	*blk_p = blk;
	*h_val_ret = h_val;

	return 0;
}

/**
 * XXX
 */
static int _gen_bpf_syscall(struct bpf_state *state,
			    const struct db_sys_list *sys)
{
	int rc;
	struct bpf_instr instr;
	struct bpf_blk *blk_c, *blk_s;
	unsigned int h_val;

	/* we treat syscall block generation slightly different from the rest
	 * because we sort the list according to syscall number and not
	 * something useful like chain size/length */

	if (sys == NULL)
		return 0;

	/* generate the syscall and chain instruction block */

	/* generate the chains */
	blk_c = _gen_bpf_chain(state, NULL, sys->chains);
	if (blk_c == NULL)
		return -ENOMEM;

	/* add the chain to the hash table */
	/* XXX - we can probably move this down into the
	 *       _gen_bpf_chain_lvl_res() function with a little work
	 *       which would save us some time */
	rc = _gen_bpf_blk_hsh(state, &blk_c, &h_val);
	if (rc < 0)
		return rc;

	/* syscall check (syscall is still in the accumulator) */
	_BPF_INSTR(instr, BPF_JMP+BPF_JEQ,
		   _BPF_JMP_HSH(h_val), _BPF_JMP_NXT, sys->num);
	blk_s = _blk_append(state, NULL, &instr);
	if (blk_s == NULL)
		return -ENOMEM;
	rc = _hsh_add(state, &blk_s, 1, &h_val);
	if (rc < 0)
		return rc;

	/* add to the top level block group */
	return _grp_append(state, &(state->tg_chains), blk_s);
}

/**
 * XXX
 */
static int _gen_bpf_build_state(struct bpf_state *state,
				const struct db_filter *db)
{
	int rc;
	struct db_sys_list *s_iter;
	struct bpf_instr instr;

	/* default action */
	if (state->def_action == SCMP_ACT_ALLOW)
		_BPF_INSTR(instr, BPF_RET,
			   _BPF_JMP_NO, _BPF_JMP_NO, _BPF_ALLOW);
	else if (state->def_action == SCMP_ACT_DENY)
		_BPF_INSTR(instr, BPF_RET,
			   _BPF_JMP_NO, _BPF_JMP_NO, _BPF_DENY);
	else {
		rc = -EFAULT;
		goto build_state_failure;
	}
	state->def_blk = _blk_append(state, state->def_blk, &instr);
	if (state->def_blk == NULL) {
		rc = -ENOMEM;
		goto build_state_failure;
	}
	rc = _hsh_add(state, &state->def_blk, 1, &state->def_hsh);
	if (rc < 0)
		goto build_state_failure;

	/* run through all the syscall filters */
	db_list_foreach(s_iter, db->syscalls) {
		/* build the top level block groups */
		rc = _gen_bpf_syscall(state, s_iter);
		if (rc < 0)
			goto build_state_failure;
	}

	/* tack on a default action at the end */
	rc = _grp_append(state, &(state->tg_chains), state->def_blk);
	if (rc < 0)
		goto build_state_failure;

	return 0;

build_state_failure:
	_state_reset_all(state);
	return rc;
}

/**
 * XXX
 */
static int _gen_bpf_build_bpf(struct bpf_state *state)
{
	int rc;
	int iter;
	unsigned int h_val;
	unsigned int res_cnt;
	unsigned int jmp_len;
	struct bpf_instr instr;
	struct bpf_blk *b_head, *b_tail, *b_iter, *b_jmp;

	/* XXX - we use a very simplistic algorithm for "writing out" the
	 *       final bpf program, we should factor into account jump lengths
	 *       to minimize the total average jump length as well as other
	 *       possible heuristics to optimize the block placement within
	 *       the overall program */

	/* link all of the top level blocks together */
	b_head = state->tg_chains.grps[0];
	b_head->prev = NULL;
	b_head->next = NULL;
	b_iter = b_head;
	for (iter = 1; iter < state->tg_chains.grp_cnt; iter++) {
		b_iter->next = state->tg_chains.grps[iter];
		b_iter->next->prev = b_iter;
		b_iter->next->next = NULL;
		b_iter = b_iter->next;
		b_tail = b_iter;
	}

	/* resolve any TGT_NXT jumps to TGT_PTR_HSH jumps at the top level */
	b_iter = b_head;
	while (b_iter != NULL && b_iter->next != NULL) {
		b_jmp = b_iter->next;
		for (iter = 0; iter < b_iter->blk_cnt; iter++) {
			switch (b_iter->blks[iter].jt.type) {
			case TGT_NXT:
				b_iter->blks[iter].jt =
						      _BPF_JMP_HSH(b_jmp->hash);
			default:
				break;
			}
			switch (b_iter->blks[iter].jf.type) {
			case TGT_NXT:
				b_iter->blks[iter].jf =
						      _BPF_JMP_HSH(b_jmp->hash);
			default:
				break;
			}
		}
		b_iter = b_iter->next;
	}

	/* pull in all of the TGT_PTR_HSH jumps, one layer at a time */
	/* XXX - this is going to be _really_ slow */
	/* XXX - we really should make this more intelligent about ordering, it
	 *       shouldn't be terrible as-is but we can likely do much better
	 *       in the case of jumps spanning a top level (de-duped blocks)
	 *       and we can probably do a bit better even within the same
	 *       syscall */
	do {
		res_cnt = 0;
		while (b_tail->next != NULL)
			b_tail = b_tail->next;
		b_iter = b_tail;
		/* go through the block list backwards (no reverse jumps) */
		while (b_iter != NULL) {
			/* look for jumps - backwards (shorter jumps) */
			for (iter = b_iter->blk_cnt - 1; iter >= 0; iter--) {
				switch (b_iter->blks[iter].jt.type) {
				case TGT_NONE:
				case TGT_IMM:
					break;
				case TGT_PTR_HSH:
					b_jmp = _hsh_find_once(state,
						b_iter->blks[iter].jt.tgt.hash);
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
				switch (b_iter->blks[iter].jf.type) {
				case TGT_NONE:
				case TGT_IMM:
					break;
				case TGT_PTR_HSH:
					b_jmp = _hsh_find_once(state,
						b_iter->blks[iter].jf.tgt.hash);
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
	} while (res_cnt != 0);

	/* load the syscall into the accumulator */
	_BPF_INSTR(instr, BPF_LD+BPF_ABS,
		   _BPF_JMP_NO, _BPF_JMP_NO, _BPF_SYSCALL);
	rc = _bpf_append_instr(state->bpf, &instr);
	if (rc < 0)
		return rc;

	/* resolve the TGT_PTR_HSH jumps and build the single bpf program */
	b_iter = b_head;
	while (b_iter != NULL) {
		/* resolve the jumps */
		for (iter = 0; iter < b_iter->blk_cnt; iter++) {
			switch (b_iter->blks[iter].jt.type) {
			case TGT_NONE:
			case TGT_IMM:
				break;
			case TGT_PTR_HSH:
				h_val = b_iter->blks[iter].jt.tgt.hash;
				jmp_len = b_iter->blk_cnt - (iter + 1);
				b_jmp = b_iter->next;
				while (b_jmp != NULL && b_jmp->hash != h_val) {
					jmp_len += b_jmp->blk_cnt;
					b_jmp = b_jmp->next;
				}
				if (b_jmp == NULL)
					return -EFAULT;
				if (jmp_len > _BPF_JMP_MAX)
					/* XXX - we can fix this by inserting
					 *       long jumps */
					return -EFAULT;
				b_iter->blks[iter].jt = _BPF_JMP_IMM(jmp_len);
				break;
			default:
				/* fatal error */
				return -EFAULT;
			}
			switch (b_iter->blks[iter].jf.type) {
			case TGT_NONE:
			case TGT_IMM:
				break;
			case TGT_PTR_HSH:
				h_val = b_iter->blks[iter].jf.tgt.hash;
				jmp_len = b_iter->blk_cnt - (iter + 1);
				b_jmp = b_iter->next;
				while (b_jmp != NULL && b_jmp->hash != h_val) {
					jmp_len += b_jmp->blk_cnt;
					b_jmp = b_jmp->next;
				}
				if (b_jmp == NULL)
					return -EFAULT;
				if (jmp_len > _BPF_JMP_MAX)
					/* XXX - we can fix this by inserting
					 *       long jumps */
					return -EFAULT;
				b_iter->blks[iter].jf = _BPF_JMP_IMM(jmp_len);
				break;
			default:
				/* fatal error */
				return -EFAULT;
			}
		}
		/* build the bpf program */
		rc = _bpf_append_blk(state->bpf, b_iter);
		if (rc < 0)
			return rc;

		b_iter = b_iter->next;
	}

	/* XXX - we may need to add a default action if we don't have any
	 *       chains */

	return 0;
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

	rc = _gen_bpf_build_state(&state, db);
	if (rc < 0)
		goto bpf_generate_end;
	rc = _gen_bpf_build_bpf(&state);
	if (rc < 0)
		goto bpf_generate_end;

bpf_generate_end:
	if (rc < 0)
		_state_reset_all(&state);
	else
		_state_release(&state);
	return state.bpf;
}

/**
 * Free memory associated with a BPF representation
 * @param fprog the BPF representation
 *
 * Free the memory associated with a BPF representation generated by the
 * gen_bpf_generate().
 *
 */
void gen_bpf_destroy(struct bpf_program *program)
{
	_program_free(program);
}
