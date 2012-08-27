/**
 * Enhanced Seccomp Filter DB
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
 */

/*
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License as
 * published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses>.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <seccomp.h>

#include "arch.h"
#include "db.h"

/* state values */
#define _DB_STA_VALID			0xA1B2C3D4
#define _DB_STA_FREED			0x1A2B3C4D

/* the priority field is fairly simple - without any user hints, or in the case
 * of a hint "tie", we give higher priority to syscalls with less chain nodes
 * (filter is easier to evaluate) */
#define _DB_PRI_MASK_CHAIN		0x0000FFFF
#define _DB_PRI_MASK_USER		0x00FF0000
#define _DB_PRI_USER(x)			(((x) << 16) & _DB_PRI_MASK_USER)

static unsigned int _db_tree_free(struct db_arg_chain_tree *tree);

/**
 * Do not call this function directly, use _db_tree_free() instead
 */
static unsigned int __db_tree_free(struct db_arg_chain_tree *tree)
{
	int cnt;

	if (tree == NULL || --(tree->refcnt) > 0)
		return 0;

	/* we assume the caller has ensured that 'tree->lvl_prv == NULL' */
	cnt = __db_tree_free(tree->lvl_nxt);
	cnt += _db_tree_free(tree->nxt_t);
	cnt += _db_tree_free(tree->nxt_f);

	free(tree);
	return cnt + 1;
}

/**
 * Free a syscall filter argument chain tree
 * @param list the argument chain list
 *
 * This function frees a syscall argument chain list and returns the number of
 * nodes freed.
 *
 */
static unsigned int _db_tree_free(struct db_arg_chain_tree *tree)
{
	struct db_arg_chain_tree *iter;

	if (tree == NULL)
		return 0;

	iter = tree;
	while (iter->lvl_prv != NULL)
		iter = iter->lvl_prv;

	return __db_tree_free(iter);
}

/**
 * Remove a node from an argument chain tree
 * @param tree the pointer to the tree
 * @param node the node to remove
 * @param action_flg the replacement action flag
 * @param action the replacement action
 *
 * This function searches the tree looking for the node and removes it once
 * found.  The function also removes any other nodes that are no longer needed
 * as a result of removing the given node.  Returns the number of nodes freed.
 *
 */
static unsigned int _db_tree_remove(struct db_arg_chain_tree **tree,
				    struct db_arg_chain_tree *node,
				    unsigned int action_flg,
				    uint32_t action)
{
	int cnt = 0;
	struct db_arg_chain_tree *c_iter;

	if (tree == NULL || *tree == NULL || node == NULL)
		return 0;

	c_iter = *tree;
	while (c_iter->lvl_prv != NULL)
		c_iter = c_iter->lvl_prv;

	do {
		if (c_iter == node) {
			/* remove from the tree */
			if (c_iter == *tree) {
				if (c_iter->lvl_prv != NULL)
					*tree = c_iter->lvl_prv;
				else
					*tree = c_iter->lvl_nxt;
			}
			if (c_iter->lvl_prv != NULL)
				c_iter->lvl_prv->lvl_nxt = c_iter->lvl_nxt;
			if (c_iter->lvl_nxt != NULL)
				c_iter->lvl_nxt->lvl_prv = c_iter->lvl_prv;

			/* free and return */
			c_iter->lvl_prv = NULL;
			c_iter->lvl_nxt = NULL;
			cnt += _db_tree_free(c_iter);
			return cnt;
		}

		/* check the true/false sub-trees */
		cnt += _db_tree_remove(&(c_iter->nxt_t), node,
				       action_flg, action);
		cnt += _db_tree_remove(&(c_iter->nxt_f), node,
				       action_flg, action);

		c_iter = c_iter->lvl_nxt;
	} while (c_iter != NULL);

	return cnt;
}

/**
 * Traverse a tree checking the action values
 * @param tree the pointer to the tree
 * @param action the action
 *
 * Traverse the tree inspecting each action to see if it matches the given
 * action.  Returns zero if all actions match the given action, negative values
 * on failure.
 *
 */
static int _db_tree_act_check(struct db_arg_chain_tree *tree, uint32_t action)
{
	int rc;
	struct db_arg_chain_tree *c_iter;

	if (tree == NULL)
		return 0;

	c_iter = tree;
	while (c_iter->lvl_prv != NULL)
		c_iter = c_iter->lvl_prv;

	do {
		if (c_iter->act_t_flg && c_iter->act_t != action)
			return -EEXIST;
		if (c_iter->act_f_flg && c_iter->act_f != action)
			return -EEXIST;

		rc = _db_tree_act_check(c_iter->nxt_t, action);
		if (rc < 0)
			return rc;
		rc = _db_tree_act_check(c_iter->nxt_f, action);
		if (rc < 0)
			return rc;

		c_iter = c_iter->lvl_nxt;
	} while (c_iter != NULL);

	return 0;
}

/**
 * Checks for a sub-tree match in an existing tree and prunes the leaves
 * @param tree_head the head of the existing tree
 * @param tree_start the starting point into the existing tree
 * @param new_p pointer to the new tree
 * @param remove_flg removal flag, only valid on return if return >= 0
 *
 * This function searches the existing tree for an occurance of the new tree
 * and removes as much of it as possible.  Returns the number of nodes removed
 * from the tree on success, and negative values on failure.
 *
 */
static int _db_tree_sub_prune(struct db_arg_chain_tree **tree_head,
			      struct db_arg_chain_tree *tree_start,
			      struct db_arg_chain_tree *new,
			      unsigned int *remove_flg)
{
	int rc = 0;
	struct db_arg_chain_tree *c_iter = tree_start;

	*remove_flg = 0;

	if (new == NULL || c_iter == NULL)
		return 0;
	if (!db_chain_one_result(new))
		return 0;

	while (c_iter->lvl_prv != NULL)
		c_iter = c_iter->lvl_prv;

	do {
		if (c_iter->arg < new->arg) {
			if (c_iter->nxt_t != NULL) {
				rc = _db_tree_sub_prune(tree_head,
							c_iter->nxt_t, new,
							remove_flg);
				if (rc > 0)
					goto sub_prune_found_down;
			}
			if (c_iter->nxt_f != NULL) {
				rc = _db_tree_sub_prune(tree_head,
							c_iter->nxt_f, new,
							remove_flg);
				if (rc > 0)
					goto sub_prune_found_down;
			}
		} else if (db_chain_eq(c_iter, new)) {
			if (db_chain_leaf(new)) {
				if (!db_chain_one_result(c_iter)) {
					/* can't remove existing node */
					if (new->act_t_flg && c_iter->act_t_flg
					    && new->act_t == c_iter->act_t)
						c_iter->act_t_flg = 0;
					if (new->act_f_flg && c_iter->act_f_flg
					    && new->act_f == c_iter->act_f)
						c_iter->act_f_flg = 0;
					goto sub_prune_return;
				}
				if ((db_chain_eq_result(c_iter, new)) ||
				    ((new->act_t_flg && c_iter->nxt_t != NULL)||
				     (new->act_f_flg && c_iter->nxt_f != NULL)))
					/* exact or close match - remove node */
					goto sub_prune_remove;
				goto sub_prune_return;
			}
			if (new->nxt_t != NULL) {
				rc = _db_tree_sub_prune(tree_head,
							c_iter->nxt_t,
							new->nxt_t,
							remove_flg);
				if (rc > 0)
					goto sub_prune_found_down;
			}
			if (new->nxt_f != NULL) {
				rc = _db_tree_sub_prune(tree_head,
							c_iter->nxt_f,
							new->nxt_f,
							remove_flg);
				if (rc > 0)
					goto sub_prune_found_down;
			}
		} else if (db_chain_gt(c_iter, new))
			goto sub_prune_return;

		c_iter = c_iter->lvl_nxt;
	} while (c_iter != NULL);

	goto sub_prune_return;

sub_prune_found_down:
	if (db_chain_zombie(c_iter))
		goto sub_prune_remove;
sub_prune_return:
	*remove_flg = 0;
	return rc;
sub_prune_remove:
	rc += _db_tree_remove(tree_head, c_iter, 0, 0);
	*remove_flg = 1;
	return rc;
}

/**
 * Validate the seccomp action
 * @param action the seccomp action
 *
 * Verify that the given action is a valid seccomp action; return zero if
 * valid, -EINVAL if invalid.
 */
int db_action_valid(uint32_t action)
{
	if (action == SCMP_ACT_KILL)
		return 0;
	else if (action == SCMP_ACT_TRAP)
		return 0;
	else if (action == SCMP_ACT_ERRNO(action & 0x0000ffff))
		return 0;
	else if (action == SCMP_ACT_TRACE(action & 0x0000ffff))
		return 0;
	else if (action == SCMP_ACT_ALLOW)
		return 0;

	return -EINVAL;
}

/**
 * Free and reset the seccomp filter collection
 * @param col the seccomp filter collection
 * @param def_action the default filter action
 *
 * This function frees any existing filter DBs and resets the collection to a
 * default state.
 *
 */
void db_col_reset(struct db_filter_col *col, uint32_t def_action)
{
	unsigned int iter;

	if (col == NULL)
		return;

	/* free any filters */
	for (iter = 0; iter < col->filter_cnt; iter++)
		db_release(col->filters[iter]);
	col->filter_cnt = 0;
	free(col->filters);
	col->filters = NULL;

	/* set the default attribute values */
	col->attr.act_default = def_action;
	col->attr.act_badarch = SCMP_ACT_KILL;
	col->attr.nnp_enable = 1;

	/* set the state */
	col->state = _DB_STA_VALID;
}

/**
 * Intitalize a seccomp filter collection
 * @param def_action the default filter action
 *
 * This function initializes a seccomp filter collection and readies it for
 * use.  Returns a pointer to the collection on success, NULL on failure.
 *
 */
struct db_filter_col *db_col_init(uint32_t def_action)
{
	struct db_filter_col *col;

	col = malloc(sizeof(*col));
	if (col == NULL)
		return NULL;

	/* clear the buffer for the first time */
	memset(col, 0, sizeof(*col));

	/* reset the DB to a known state */
	db_col_reset(col, def_action);

	return col;
}

/**
 * Destroy a seccomp filter collection
 * @param col the seccomp filter collection
 *
 * This function destroys a seccomp filter collection.  After calling this
 * function, the filter should no longer be referenced.
 *
 */
void db_col_release(struct db_filter_col *col)
{
	if (col == NULL)
		return;

	/* set the state, just in case */
	col->state = _DB_STA_FREED;

	/* free and reset the DB */
	db_col_reset(col, 0);
	free(col);
}

/**
 * Validate a filter collection
 * @param col the seccomp filter collection
 *
 * This function validates a seccomp filter collection.  Returns zero if the
 * collection is valid, negative values on failure.
 *
 */
int db_col_valid(struct db_filter_col *col)
{
	if (col != NULL && col->state == _DB_STA_VALID)
		return 0;
	return -EINVAL;
}

/**
 * Get a filter attribute
 * @param col the seccomp filter collection
 * @param attr the filter attribute
 * @param value the filter attribute value
 *
 * Get the requested filter attribute and provide it via @value.  Returns zero
 * on success, negative values on failure.
 *
 */
int db_col_attr_get(const struct db_filter_col *col,
		    enum scmp_filter_attr attr, uint32_t *value)
{
	switch (attr) {
	case SCMP_FLTATR_ACT_DEFAULT:
		*value = col->attr.act_default;
		break;
	case SCMP_FLTATR_ACT_BADARCH:
		*value = col->attr.act_badarch;
		break;
	case SCMP_FLTATR_CTL_NNP:
		*value = col->attr.nnp_enable;
		break;
	default:
		return -EEXIST;
		break;
	}

	return 0;
}

/**
 * Set a filter attribute
 * @param db the seccomp filter collection
 * @param attr the filter attribute
 * @param value the filter attribute value
 *
 * Set the requested filter attribute with the given value.  Returns zero on
 * success, negative values on failure.
 *
 */
int db_col_attr_set(struct db_filter_col *col,
		    enum scmp_filter_attr attr, uint32_t value)
{
	switch (attr) {
	case SCMP_FLTATR_ACT_DEFAULT:
		/* read only */
		return -EACCES;
		break;
	case SCMP_FLTATR_ACT_BADARCH:
		if (db_action_valid(value) == 0)
			col->attr.act_badarch = value;
		else
			return -EINVAL;
		break;
	case SCMP_FLTATR_CTL_NNP:
		col->attr.nnp_enable = (value ? 1 : 0);
		break;
	default:
		return -EEXIST;
		break;
	}

	return 0;
}

/**
 * Add a new filter DB to a filter collection
 * @param col the seccomp filter collection
 * @param db the seccomp filter DB
 *
 * This function adds an existing seccomp filter DB to an existing seccomp
 * filter collection assuming there isn't a filter DB already present with the
 * same architecture.  Returns zero on success, negative values on failure.
 *
 */
int db_col_db_add(struct db_filter_col *col, struct db_filter *db)
{
	unsigned int iter;
	struct db_filter **dbs;

	for (iter = 0; iter < col->filter_cnt; iter++)
		if (col->filters[iter]->arch->token == db->arch->token)
			return -EEXIST;

	dbs = realloc(col->filters,
		      sizeof(struct db_filter *) * (col->filter_cnt + 1));
	if (dbs == NULL)
		return -ENOMEM;
	col->filters = dbs;
	col->filter_cnt++;
	col->filters[col->filter_cnt - 1] = db;

	return 0;
}

/**
 * Free and reset the seccomp filter DB
 * @param db the seccomp filter DB
 * @param def_action the default filter action
 *
 * This function frees any existing filters and resets the filter DB to a
 * default state; only the DB architecture is preserved.
 *
 */
void db_reset(struct db_filter *db)
{
	struct db_sys_list *s_iter;

	if (db == NULL)
		return;

	/* free any filters */
	if (db->syscalls != NULL) {
		s_iter = db->syscalls;
		while (s_iter != NULL) {
			db->syscalls = s_iter->next;
			_db_tree_free(s_iter->chains);
			free(s_iter);
			s_iter = db->syscalls;
		}
		db->syscalls = NULL;
	}
}

/**
 * Intitalize a seccomp filter DB
 * @param arch the architecture definition
 *
 * This function initializes a seccomp filter DB and readies it for use.
 * Returns a pointer to the DB on success, NULL on failure.
 *
 */
struct db_filter *db_init(const struct arch_def *arch)
{
	struct db_filter *db;

	db = malloc(sizeof(*db));
	if (db == NULL)
		return NULL;

	/* clear the buffer for the first time and set the arch */
	memset(db, 0, sizeof(*db));
	db->arch = arch;

	/* reset the DB to a known state */
	db_reset(db);

	return db;
}

/**
 * Destroy a seccomp filter DB
 * @param db the seccomp filter DB
 *
 * This function destroys a seccomp filter DB.  After calling this function,
 * the filter should no longer be referenced.
 *
 */
void db_release(struct db_filter *db)
{
	if (db == NULL)
		return;

	/* free and reset the DB */
	db_reset(db);
	free(db);
}

/**
 * Update the user specified portion of the syscall priority
 * @param db the seccomp filter db
 * @param syscall the syscall number
 * @param priority the syscall priority
 *
 * This function sets, or updates, the syscall priority; the highest priority
 * value between the existing and specified value becomes the new syscall
 * priority.  If the syscall entry does not already exist, a new phantom
 * syscall entry is created as a placeholder.  Returns zero on success,
 * negative values on failure.
 *
 */
int db_syscall_priority(struct db_filter *db,
			unsigned int syscall, uint8_t priority)
{
	unsigned int sys_pri = _DB_PRI_USER(priority);
	struct db_sys_list *s_new, *s_iter, *s_prev = NULL;

	assert(db != NULL);

	s_iter = db->syscalls;
	while (s_iter != NULL && s_iter->num < syscall) {
		s_prev = s_iter;
		s_iter = s_iter->next;
	}

	/* matched an existing syscall entry */
	if (s_iter != NULL && s_iter->num == syscall) {
		if (sys_pri > (s_iter->priority & _DB_PRI_MASK_USER)) {
			s_iter->priority &= (~_DB_PRI_MASK_USER);
			s_iter->priority |= sys_pri;
		}
		return 0;
	}

	/* no existing syscall entry - create a phantom entry */
	s_new = malloc(sizeof(*s_new));
	if (s_new == NULL)
		return -ENOMEM;
	memset(s_new, 0, sizeof(*s_new));
	s_new->num = syscall;
	s_new->priority = sys_pri;
	s_new->valid = 0;

	/* add it before s_iter */
	if (s_prev != NULL) {
		s_new->next = s_prev->next;
		s_prev->next = s_new;
	} else {
		s_new->next = db->syscalls;
		db->syscalls = s_new;
	}

	return 0;
}

/**
 * Fixup the node based on the op/mask
 * @param node the chain node
 *
 * Apply some simplifications based on the comparison op and mask value.
 *
 */
static void _db_node_mask_fixup(struct db_arg_chain_tree *node)
{
	if (node->op == SCMP_CMP_MASKED_EQ && node->mask == 0) {
		node->op = SCMP_CMP_EQ;
		node->mask = ARG_MASK_MAX;
		node->datum = 0;
	} else
		node->datum &= node->mask;
}

/**
 * Generate a new filter rule for a 64 bit system
 * @param arch the architecture definition
 * @param action the filter action
 * @param syscall the syscall number
 * @param chain argument filter chain
 *
 * This function generates a new syscall filter for a 64 bit system. Returns
 * zero on success, negative values on failure.
 *
 */
static struct db_sys_list *_db_rule_gen_64(const struct arch_def *arch,
					   uint32_t action,
					   unsigned int syscall,
					   struct db_api_arg *chain)
{
	unsigned int iter;
	int chain_len_max;
	struct db_sys_list *s_new;
	struct db_arg_chain_tree *c_iter_hi = NULL, *c_iter_lo = NULL;
	struct db_arg_chain_tree *c_prev_lo = NULL;
	unsigned int tf_flag;

	s_new = malloc(sizeof(*s_new));
	if (s_new == NULL)
		return NULL;
	memset(s_new, 0, sizeof(*s_new));
	s_new->num = syscall;
	s_new->valid = 1;
	/* run through the argument chain */
	chain_len_max = arch_arg_count_max(arch);
	for (iter = 0; iter < chain_len_max; iter++) {
		if (chain[iter].valid == 0)
			continue;

		c_iter_hi = malloc(sizeof(*c_iter_hi));
		if (c_iter_hi == NULL)
			goto gen_64_failure;
		memset(c_iter_hi, 0, sizeof(*c_iter_hi));
		c_iter_hi->refcnt = 1;
		c_iter_lo = malloc(sizeof(*c_iter_lo));
		if (c_iter_lo == NULL) {
			free(c_iter_hi);
			goto gen_64_failure;
		}
		memset(c_iter_lo, 0, sizeof(*c_iter_lo));
		c_iter_lo->refcnt = 1;

		/* link this level to the previous level */
		if (c_prev_lo != NULL) {
			if (tf_flag)
				c_prev_lo->nxt_t = c_iter_hi;
			else
				c_prev_lo->nxt_f = c_iter_hi;
		} else
			s_new->chains = c_iter_hi;
		s_new->node_cnt += 2;

		/* set the arg, op, and datum fields */
		c_iter_hi->arg = chain[iter].arg;
		c_iter_lo->arg = chain[iter].arg;
		c_iter_hi->arg_offset = arch_arg_offset_hi(arch,
							   c_iter_hi->arg);
		c_iter_lo->arg_offset = arch_arg_offset_lo(arch,
							   c_iter_lo->arg);
		switch (chain[iter].op) {
			case SCMP_CMP_GT:
				c_iter_hi->op = SCMP_CMP_GE;
				c_iter_lo->op = SCMP_CMP_GT;
				tf_flag = 1;
				break;
			case SCMP_CMP_NE:
				c_iter_hi->op = SCMP_CMP_EQ;
				c_iter_lo->op = SCMP_CMP_EQ;
				tf_flag = 0;
				break;
			case SCMP_CMP_LT:
				c_iter_hi->op = SCMP_CMP_GE;
				c_iter_lo->op = SCMP_CMP_GE;
				tf_flag = 0;
				break;
			case SCMP_CMP_LE:
				c_iter_hi->op = SCMP_CMP_GE;
				c_iter_lo->op = SCMP_CMP_GT;
				tf_flag = 0;
				break;
			default:
				c_iter_hi->op = chain[iter].op;
				c_iter_lo->op = chain[iter].op;
				tf_flag = 1;
		}
		c_iter_hi->mask = D64_HI(chain[iter].mask);
		c_iter_lo->mask = D64_LO(chain[iter].mask);
		c_iter_hi->datum = D64_HI(chain[iter].datum);
		c_iter_lo->datum = D64_LO(chain[iter].datum);

		/* fixup the mask/datum */
		_db_node_mask_fixup(c_iter_hi);
		_db_node_mask_fixup(c_iter_lo);

		/* link the hi and lo chain nodes */
		c_iter_hi->nxt_t = c_iter_lo;

		c_prev_lo = c_iter_lo;
	}
	if (c_iter_lo != NULL) {
		/* set the leaf node */
		if (tf_flag) {
			c_iter_lo->act_t_flg = 1;
			c_iter_lo->act_t = action;
		} else {
			c_iter_lo->act_f_flg = 1;
			c_iter_lo->act_f = action;
		}
	} else
		s_new->action = action;

	return s_new;

gen_64_failure:
	/* free the new chain and its syscall struct */
	_db_tree_free(s_new->chains);
	free(s_new);
	return NULL;
}

/**
 * Generate a new filter rule for a 32 bit system
 * @param arch the architecture definition
 * @param action the filter action
 * @param syscall the syscall number
 * @param chain argument filter chain
 *
 * This function generates a new syscall filter for a 32 bit system. Returns
 * zero on success, negative values on failure.
 *
 */
static struct db_sys_list *_db_rule_gen_32(const struct arch_def *arch,
					   uint32_t action,
					   unsigned int syscall,
					   struct db_api_arg *chain)
{
	unsigned int iter;
	int chain_len_max;
	struct db_sys_list *s_new;
	struct db_arg_chain_tree *c_iter = NULL, *c_prev = NULL;
	unsigned int tf_flag;

	s_new = malloc(sizeof(*s_new));
	if (s_new == NULL)
		return NULL;
	memset(s_new, 0, sizeof(*s_new));
	s_new->num = syscall;
	s_new->valid = 1;
	/* run through the argument chain */
	chain_len_max = arch_arg_count_max(arch);
	for (iter = 0; iter < chain_len_max; iter++) {
		if (chain[iter].valid == 0)
			continue;

		c_iter = malloc(sizeof(*c_iter));
		if (c_iter == NULL)
			goto gen_32_failure;
		memset(c_iter, 0, sizeof(*c_iter));
		c_iter->refcnt = 1;
		c_iter->arg = chain[iter].arg;
		c_iter->arg_offset = arch_arg_offset(c_iter->arg);
		c_iter->op = chain[iter].op;
		c_iter->mask = chain[iter].mask;
		c_iter->datum = chain[iter].datum;

		/* link in the new node and update the chain */
		if (c_prev != NULL) {
			if (tf_flag)
				c_prev->nxt_t = c_iter;
			else
				c_prev->nxt_f = c_iter;
		} else
			s_new->chains = c_iter;
		s_new->node_cnt++;

		/* rewrite the op to reduce the op/datum combos */
		switch (c_iter->op) {
			case SCMP_CMP_NE:
				c_iter->op = SCMP_CMP_EQ;
				tf_flag = 0;
				break;
			case SCMP_CMP_LT:
				c_iter->op = SCMP_CMP_GE;
				tf_flag = 0;
				break;
			case SCMP_CMP_LE:
				c_iter->op = SCMP_CMP_GT;
				tf_flag = 0;
				break;
			default:
				tf_flag = 1;
		}

		/* fixup the mask/datum */
		_db_node_mask_fixup(c_iter);

		c_prev = c_iter;
	}
	if (c_iter != NULL) {
		/* set the leaf node */
		if (tf_flag) {
			c_iter->act_t_flg = 1;
			c_iter->act_t = action;
		} else {
			c_iter->act_f_flg = 1;
			c_iter->act_f = action;
		}
	} else
		s_new->action = action;

	return s_new;

gen_32_failure:
	/* free the new chain and its syscall struct */
	_db_tree_free(s_new->chains);
	free(s_new);
	return NULL;
}

/**
 * Add a new rule to the seccomp filter DB
 * @param db the seccomp filter db
 * @param action the filter action
 * @param syscall the syscall number
 * @param chain argument filter chain
 *
 * This function adds a new syscall filter to the seccomp filter DB, adding to
 * the existing filters for the syscall, unless no argument specific filters
 * are present (filtering only on the syscall).  When adding new chains, the
 * shortest chain, or most inclusive filter match, will be entered into the
 * filter DB. Returns zero on success, negative values on failure.
 *
 */
int db_rule_add(struct db_filter *db, uint32_t action, unsigned int syscall,
		struct db_api_arg *chain)
{
	int rc = -ENOMEM;
	struct db_sys_list *s_new, *s_iter, *s_prev = NULL;
	struct db_arg_chain_tree *c_iter = NULL, *c_prev = NULL;
	struct db_arg_chain_tree *ec_iter, *ec_iter_b;
	unsigned int rm_flag = 0;
	unsigned int new_chain_cnt = 0;
	unsigned int n_cnt;

	assert(db != NULL);

	/* do all our possible memory allocation up front so we don't have to
	 * worry about failure once we get to the point where we start updating
	 * the filter db */
	if (db->arch->size == ARCH_SIZE_64)
		s_new = _db_rule_gen_64(db->arch, action, syscall, chain);
	else if (db->arch->size == ARCH_SIZE_32)
		s_new = _db_rule_gen_32(db->arch, action, syscall, chain);
	else
		return -EFAULT;
	if (s_new == NULL)
		return -ENOMEM;
	new_chain_cnt = s_new->node_cnt;

	/* no more failures allowed after this point that would result in the
	 * stored filter being in an inconsistent state */

	/* find a matching syscall/chain or insert a new one */
	s_iter = db->syscalls;
	while (s_iter != NULL && s_iter->num < syscall) {
		s_prev = s_iter;
		s_iter = s_iter->next;
	}
add_reset:
	s_new->node_cnt = new_chain_cnt;
	s_new->priority = _DB_PRI_MASK_CHAIN - s_new->node_cnt;
	c_prev = NULL;
	c_iter = s_new->chains;
	if (s_iter != NULL)
		ec_iter = s_iter->chains;
	else
		ec_iter = NULL;
	if (s_iter == NULL || s_iter->num != syscall) {
		/* new syscall, add before s_iter */
		if (s_prev != NULL) {
			s_new->next = s_prev->next;
			s_prev->next = s_new;
		} else {
			s_new->next = db->syscalls;
			db->syscalls = s_new;
		}
		return 0;
	} else if (s_iter->chains == NULL) {
		if (rm_flag || s_iter->valid == 0) {
			/* we are here because our previous pass cleared the
			 * entire syscall chain when searching for a subtree
			 * match or the existing syscall entry is a phantom,
			 * so either way add the new chain */
			s_iter->chains = s_new->chains;
			s_iter->action = s_new->action;
			s_iter->node_cnt = s_new->node_cnt;
			if (s_iter->valid == 1)
				s_iter->priority = s_new->priority;
			s_iter->valid = 1;
			free(s_new);
			rc = 0;
			goto add_priority_update;
		} else
			/* syscall exists without any chains - existing filter
			 * is at least as large as the new entry so cleanup and
			 * exit */
			goto add_free_ok;
	} else if (s_iter->chains != NULL && s_new->chains == NULL) {
		/* syscall exists with chains but the new filter has no chains
		 * so we need to clear the existing chains and exit */
		_db_tree_free(s_iter->chains);
		s_iter->chains = NULL;
		s_iter->node_cnt = 0;
		s_iter->action = action;
		goto add_free_ok;
	}
	/* syscall exists and has at least one existing chain - start at the
	 * top and walk the two chains */
	do {
		/* check for sub-tree matches in the existing tree */
		rc = _db_tree_sub_prune(&(s_iter->chains), ec_iter, c_iter,
					&rm_flag);
		if (rc > 0)
			s_iter->node_cnt -= rc;
		else if (rc < 0)
			goto add_free;
		if (rm_flag)
			goto add_reset;

		/* check for sub-tree matches in the new tree */
		ec_iter_b = ec_iter;
		while (ec_iter_b->lvl_prv != NULL)
			ec_iter_b = ec_iter_b->lvl_prv;
		do {
			rc = _db_tree_sub_prune(&(s_new->chains),
						c_iter, ec_iter_b, &rm_flag);
			ec_iter_b = ec_iter_b->lvl_nxt;
		} while (rc == 0 && ec_iter_b != NULL);
		if (rc > 0) {
			s_new->node_cnt -= rc;
			if (s_new->node_cnt > 0)
				/* XXX - are we ever going to hit this is a
				 *       normal use case?  pretty sure we can't
				 *       "reset" in this case ... */
				return -EFAULT;
			rc = 0;
			goto add_free;
		} else if (rc < 0)
			goto add_free;

		/* insert the new rule into the existing tree */
		if (db_chain_eq(c_iter, ec_iter)) {
			/* found a matching node on this chain level */
			if (db_chain_leaf(c_iter) && db_chain_leaf(ec_iter)) {
				/* both are leaf nodes */
				if (c_iter->act_t_flg && ec_iter->act_t_flg) {
					if (ec_iter->act_t != action)
						goto add_free_exist;
				} else if (c_iter->act_t_flg) {
					ec_iter->act_t_flg = 1;
					ec_iter->act_t = action;
				}
				if (c_iter->act_f_flg && ec_iter->act_f_flg) {
					if (ec_iter->act_f != action)
						goto add_free_exist;
				} else if (c_iter->act_f_flg) {
					ec_iter->act_f_flg = 1;
					ec_iter->act_f = action;
				}
				if (ec_iter->act_t_flg == ec_iter->act_f_flg &&
				    ec_iter->act_t == ec_iter->act_f) {
					n_cnt = _db_tree_remove(
							     &(s_iter->chains),
							     ec_iter,
							     1,
							     ec_iter->act_t);
					s_iter->node_cnt -= n_cnt;
				}
				goto add_free_ok;
			} else if (db_chain_leaf(c_iter)) {
				/* new is shorter */
				if (c_iter->act_t_flg) {
					rc = _db_tree_act_check(ec_iter->nxt_t,
								action);
					if (rc < 0)
						goto add_free;
					n_cnt = _db_tree_free(ec_iter->nxt_t);
					ec_iter->nxt_t = NULL;
					ec_iter->act_t_flg = 1;
					ec_iter->act_t = action;
				} else {
					rc = _db_tree_act_check(ec_iter->nxt_f,
								action);
					if (rc < 0)
						goto add_free;
					n_cnt = _db_tree_free(ec_iter->nxt_f);
					ec_iter->nxt_f = NULL;
					ec_iter->act_f_flg = 1;
					ec_iter->act_f = action;
				}
				s_iter->node_cnt -= n_cnt;
				goto add_free_ok;
			} else if (c_iter->nxt_t != NULL) {
				if (ec_iter->nxt_t != NULL) {
					/* jump to the next level */
					c_prev = c_iter;
					c_iter = c_iter->nxt_t;
					ec_iter = ec_iter->nxt_t;
					s_new->node_cnt--;
				} else if (ec_iter->act_t_flg) {
					/* existing is shorter */
					if (ec_iter->act_t == action)
						goto add_free_ok;
					goto add_free_exist;
				} else {
					/* add a new branch */
					c_prev = c_iter;
					ec_iter->nxt_t = c_iter->nxt_t;
					s_iter->node_cnt += (s_new->node_cnt-1);
					goto add_free_match;
				}
			} else if (c_iter->nxt_f != NULL) {
				if (ec_iter->nxt_f != NULL) {
					/* jump to the next level */
					c_prev = c_iter;
					c_iter = c_iter->nxt_f;
					ec_iter = ec_iter->nxt_f;
					s_new->node_cnt--;
				} else if (ec_iter->act_f_flg) {
					/* existing is shorter */
					if (ec_iter->act_f == action)
						goto add_free_ok;
					goto add_free_exist;
				} else {
					/* add a new branch */
					c_prev = c_iter;
					ec_iter->nxt_f = c_iter->nxt_f;
					s_iter->node_cnt += (s_new->node_cnt-1);
					goto add_free_match;
				}
			} else {
				/* we should never be here! */
				rc = -EFAULT;
				goto add_free;
			}
		} else {
			/* need to check other nodes on this level */
			if (db_chain_lt(c_iter, ec_iter)) {
				if (ec_iter->lvl_prv == NULL) {
					/* add to the start of the level */
					ec_iter->lvl_prv = c_iter;
					c_iter->lvl_nxt = ec_iter;
					if (ec_iter == s_iter->chains)
						s_iter->chains = c_iter;
					s_iter->node_cnt += s_new->node_cnt;
					goto add_free_match;
				} else
					ec_iter = ec_iter->lvl_prv;
			} else {
				if (ec_iter->lvl_nxt == NULL) {
					/* add to the end of the level */
					ec_iter->lvl_nxt = c_iter;
					c_iter->lvl_prv = ec_iter;
					s_iter->node_cnt += s_new->node_cnt;
					goto add_free_match;
				} else if (db_chain_lt(c_iter,
						       ec_iter->lvl_nxt)) {
					/* add new chain in between */
					c_iter->lvl_nxt = ec_iter->lvl_nxt;
					ec_iter->lvl_nxt->lvl_prv = c_iter;
					ec_iter->lvl_nxt = c_iter;
					c_iter->lvl_prv = ec_iter;
					s_iter->node_cnt += s_new->node_cnt;
					goto add_free_match;
				} else
					ec_iter = ec_iter->lvl_nxt;
			}
		}
	} while ((c_iter != NULL) && (ec_iter != NULL));

	/* we should never be here! */
	return -EFAULT;

add_free_exist:
	rc = -EEXIST;
	goto add_free;
add_free_ok:
	rc = 0;
add_free:
	/* free the new chain and its syscall struct */
	_db_tree_free(s_new->chains);
	free(s_new);
	goto add_priority_update;
add_free_match:
	/* free the matching portion of new chain */
	if (c_prev != NULL) {
		c_prev->nxt_t = NULL;
		c_prev->nxt_f = NULL;
		_db_tree_free(s_new->chains);
	}
	free(s_new);
	rc = 0;
add_priority_update:
	/* update the priority */
	if (s_iter != NULL) {
		s_iter->priority &= (~_DB_PRI_MASK_CHAIN);
		s_iter->priority |= (_DB_PRI_MASK_CHAIN - s_iter->node_cnt);
	}
	return rc;
}
