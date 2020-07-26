/**
 * Enhanced Seccomp Filter DB
 *
 * Copyright (c) 2012,2016,2018 Red Hat <pmoore@redhat.com>
 * Copyright (c) 2019 Cisco Systems, Inc. <pmoore2@cisco.com>
 * Author: Paul Moore <paul@paul-moore.com>
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
#include "system.h"
#include "helper.h"

/* state values */
#define _DB_STA_VALID			0xA1B2C3D4
#define _DB_STA_FREED			0x1A2B3C4D

/* the priority field is fairly simple - without any user hints, or in the case
 * of a hint "tie", we give higher priority to syscalls with less chain nodes
 * (filter is easier to evaluate) */
#define _DB_PRI_MASK_CHAIN		0x0000FFFF
#define _DB_PRI_MASK_USER		0x00FF0000
#define _DB_PRI_USER(x)			(((x) << 16) & _DB_PRI_MASK_USER)

/* prove information about the sub-tree check results */
struct db_iter_state {
#define _DB_IST_NONE			0x00000000
#define _DB_IST_MATCH			0x00000001
#define _DB_IST_MATCH_ONCE		0x00000002
#define _DB_IST_X_FINISHED		0x00000010
#define _DB_IST_N_FINISHED		0x00000020
#define _DB_IST_X_PREFIX		0x00000100
#define _DB_IST_N_PREFIX		0x00000200
#define _DB_IST_M_MATCHSET		(_DB_IST_MATCH|_DB_IST_MATCH_ONCE)
#define _DB_IST_M_REDUNDANT		(_DB_IST_MATCH| \
					 _DB_IST_X_FINISHED| \
					 _DB_IST_N_PREFIX)
	unsigned int flags;
	uint32_t action;
	struct db_sys_list *sx;
};

static unsigned int _db_node_put(struct db_arg_chain_tree **node);

/**
 * Define the syscall argument priority for nodes on the same level of the tree
 * @param a tree node
 *
 * Prioritize the syscall argument value, taking into account hi/lo words.
 * Should only ever really be called by _db_chain_{lt,eq}().  Returns an
 * arbitrary value indicating priority.
 *
 */
static unsigned int __db_chain_arg_priority(const struct db_arg_chain_tree *a)
{
	return (a->arg << 1) + (a->arg_h_flg ? 1 : 0);
}

/**
 * Define the "op" priority for nodes on the same level of the tree
 * @param op the argument operator
 *
 * Prioritize the syscall argument comparison operator.  Should only ever
 * really be called by _db_chain_{lt,eq}().  Returns an arbitrary value
 * indicating priority.
 *
 */
static unsigned int __db_chain_op_priority(enum scmp_compare op)
{
	/* the distinction between LT/LT and GT/GE is mostly to make the
	 * ordering as repeatable as possible regardless of the order in which
	 * the rules are added */
	switch (op) {
	case SCMP_CMP_MASKED_EQ:
	case SCMP_CMP_EQ:
	case SCMP_CMP_NE:
		return 3;
	case SCMP_CMP_LE:
	case SCMP_CMP_LT:
		return 2;
	case SCMP_CMP_GE:
	case SCMP_CMP_GT:
		return 1;
	default:
		return 0;
	}
}

/**
 * Determine if node "a" is less than node "b"
 * @param a tree node
 * @param b tree node
 *
 * The logic is best explained by looking at the comparison code in the
 * function.
 *
 */
static bool _db_chain_lt(const struct db_arg_chain_tree *a,
			 const struct db_arg_chain_tree *b)
{
	unsigned int a_arg, b_arg;
	unsigned int a_op, b_op;

	a_arg = __db_chain_arg_priority(a);
	b_arg = __db_chain_arg_priority(b);
	if (a_arg < b_arg)
		return true;
	else if (a_arg > b_arg)
		return false;

	a_op = __db_chain_op_priority(a->op_orig);
	b_op = __db_chain_op_priority(b->op_orig);
	if (a_op < b_op)
		return true;
	else if (a_op > b_op)
		return false;

	/* NOTE: at this point the arg and op priorities are equal */

	switch (a->op_orig) {
	case SCMP_CMP_LE:
	case SCMP_CMP_LT:
		/* in order to ensure proper ordering for LT/LE comparisons we
		 * need to invert the argument value so smaller values come
		 * first */
		if (a->datum > b->datum)
			return true;
		break;
	default:
		if (a->datum < b->datum)
			return true;
		break;
	}

	return false;
}

/**
 * Determine if two nodes have equal argument datum values
 * @param a tree node
 * @param b tree node
 *
 * In order to return true the nodes must have the same datum and mask for the
 * same argument.
 *
 */
static bool _db_chain_eq(const struct db_arg_chain_tree *a,
			 const struct db_arg_chain_tree *b)
{
	unsigned int a_arg, b_arg;

	a_arg = __db_chain_arg_priority(a);
	b_arg = __db_chain_arg_priority(b);

	return ((a_arg == b_arg) && (a->op == b->op) &&
		(a->datum == b->datum) && (a->mask == b->mask));
}

/**
 * Determine if a given tree node is a leaf node
 * @param iter the node to test
 *
 * A leaf node is a node with no other nodes beneath it.
 *
 */
static bool _db_chain_leaf(const struct db_arg_chain_tree *iter)
{
	return (iter->nxt_t == NULL && iter->nxt_f == NULL);
}

/**
 * Determine if a given tree node is a zombie node
 * @param iter the node to test
 *
 * A zombie node is a leaf node that also has no true or false actions.
 *
 */
static bool _db_chain_zombie(const struct db_arg_chain_tree *iter)
{
	return (_db_chain_leaf(iter) &&
		!(iter->act_t_flg) && !(iter->act_f_flg));
}

/**
 * Get a node reference
 * @param node pointer to a node
 *
 * This function gets a reference to an individual node.  Returns a pointer
 * to the node.
 *
 */
static struct db_arg_chain_tree *_db_node_get(struct db_arg_chain_tree *node)
{
	if (node != NULL)
		node->refcnt++;
	return node;
}

/**
 * Garbage collect a level of the tree
 * @param node tree node
 *
 * Check the entire level on which @node resides, if there is no other part of
 * the tree which points to a node on this level, remove the entire level.
 * Returns the number of nodes removed.
 *
 */
static unsigned int _db_level_clean(struct db_arg_chain_tree *node)
{
	int cnt = 0;
	unsigned int links;
	struct db_arg_chain_tree *n = node;
	struct db_arg_chain_tree *start;

	while (n->lvl_prv)
		n = n->lvl_prv;
	start = n;

	while (n != NULL) {
		links = 0;
		if (n->lvl_prv)
			links++;
		if (n->lvl_nxt)
			links++;

		if (n->refcnt > links)
			return cnt;

		n = n->lvl_nxt;
	}

	n = start;
	while (n != NULL)
		cnt += _db_node_put(&n);

	return cnt;
}

/**
 * Free a syscall filter argument chain tree
 * @param tree the argument chain list
 *
 * This function drops a reference to the tree pointed to by @tree and garbage
 * collects the top level.  Returns the number of nodes removed.
 *
 */
static unsigned int _db_tree_put(struct db_arg_chain_tree **tree)
{
	unsigned int cnt;

	cnt = _db_node_put(tree);
	if (*tree)
		cnt += _db_level_clean(*tree);

	return cnt;
}

/**
 * Release a node reference
 * @param node pointer to a node
 *
 * This function drops a reference to an individual node, unless this is the
 * last reference in which the entire sub-tree is affected.  Returns the number
 * of nodes freed.
 *
 */
static unsigned int _db_node_put(struct db_arg_chain_tree **node)
{
	unsigned int cnt = 0;
	struct db_arg_chain_tree *n = *node;
	struct db_arg_chain_tree *lvl_p, *lvl_n, *nxt_t, *nxt_f;

	if (n == NULL)
		return 0;

	if (--(n->refcnt) == 0) {
		lvl_p = n->lvl_prv;
		lvl_n = n->lvl_nxt;
		nxt_t = n->nxt_t;
		nxt_f = n->nxt_f;

		/* split the current level */
		/* NOTE: we still hold a ref for both lvl_p and lvl_n */
		if (lvl_p)
			lvl_p->lvl_nxt = NULL;
		if (lvl_n)
			lvl_n->lvl_prv = NULL;

		/* drop refcnts on the current level */
		if (lvl_p)
			cnt += _db_node_put(&lvl_p);
		if (lvl_n)
			cnt += _db_node_put(&lvl_n);

		/* re-link current level if it still exists */
		if (lvl_p)
			lvl_p->lvl_nxt = _db_node_get(lvl_n);
		if (lvl_n)
			lvl_n->lvl_prv = _db_node_get(lvl_p);

		/* update caller's pointer */
		if (lvl_p)
			*node = lvl_p;
		else if (lvl_n)
			*node = lvl_n;
		else
			*node = NULL;

		/* drop the next level(s) */
		cnt += _db_tree_put(&nxt_t);
		cnt += _db_tree_put(&nxt_f);

		/* cleanup and accounting */
		free(n);
		cnt++;
	}

	return cnt;
}

/**
 * Remove a node from an argument chain tree
 * @param tree the pointer to the tree
 * @param node the node to remove
 *
 * This function searches the tree looking for the node and removes it as well
 * as any sub-trees beneath it.  Returns the number of nodes freed.
 *
 */
static unsigned int _db_tree_remove(struct db_arg_chain_tree **tree,
				    struct db_arg_chain_tree *node)
{
	int cnt = 0;
	struct db_arg_chain_tree *c_iter;

	if (tree == NULL || *tree == NULL || node == NULL)
		return 0;

	c_iter = *tree;
	while (c_iter->lvl_prv != NULL)
		c_iter = c_iter->lvl_prv;

	do {
		/* current node? */
		if (c_iter == node)
			goto remove;

		/* check the sub-trees */
		cnt += _db_tree_remove(&(c_iter->nxt_t), node);
		cnt += _db_tree_remove(&(c_iter->nxt_f), node);

		/* check for empty/zombie nodes */
		if (_db_chain_zombie(c_iter))
			goto remove;

		/* next node on this level */
		c_iter = c_iter->lvl_nxt;
	} while (c_iter != NULL && cnt == 0);

	return cnt;

remove:
	/* reset the tree pointer if needed */
	if (c_iter == *tree) {
		if (c_iter->lvl_prv != NULL)
			*tree = c_iter->lvl_prv;
		else
			*tree = c_iter->lvl_nxt;
	}

	/* remove the node from the current level */
	if (c_iter->lvl_prv)
		c_iter->lvl_prv->lvl_nxt = c_iter->lvl_nxt;
	if (c_iter->lvl_nxt)
		c_iter->lvl_nxt->lvl_prv = c_iter->lvl_prv;
	c_iter->lvl_prv = NULL;
	c_iter->lvl_nxt = NULL;

	/* free the node and any sub-trees */
	cnt += _db_node_put(&c_iter);

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
 * Checks for a sub-tree match in an existing tree and prunes the tree
 * @param existing pointer to the existing tree
 * @param new pointer to the new tree
 * @param state pointer to a state structure
 *
 * This function searches the existing tree trying to prune it based on the
 * new tree.  Returns the number of nodes removed from the tree on success,
 * zero if no changes were made.
 *
 */
static int _db_tree_prune(struct db_arg_chain_tree **existing,
			  struct db_arg_chain_tree *new,
			  struct db_iter_state *state)
{
	int cnt = 0;
	struct db_iter_state state_nxt;
	struct db_iter_state state_new = *state;
	struct db_arg_chain_tree *x_iter_next;
	struct db_arg_chain_tree *x_iter = *existing;
	struct db_arg_chain_tree *n_iter = new;

	/* check if either tree is finished */
	if (n_iter == NULL || x_iter == NULL)
		goto prune_return;

	/* bail out if we have a broken match */
	if ((state->flags & _DB_IST_M_MATCHSET) == _DB_IST_MATCH_ONCE)
		goto prune_return;

	/* get to the start of the existing level */
	while (x_iter->lvl_prv)
		x_iter = x_iter->lvl_prv;

	/* NOTE: a few comments on the code below ...
	 * 1) we need to take a reference before we go down a level in case
	 *    we end up dropping the sub-tree (see the _db_node_get() calls)
	 * 2) since the new tree really only has one branch, we can only ever
	 *    match on one branch in the existing tree, if we "hit" then we
	 *    can bail on the other branches */

	do {
		/* store this now in case we remove x_iter */
		x_iter_next = x_iter->lvl_nxt;

		/* compare the two nodes */
		if (_db_chain_eq(x_iter, n_iter)) {
			/* we have a match */
			state_new.flags |= _DB_IST_M_MATCHSET;

			/* check if either tree is finished */
			if (_db_chain_leaf(n_iter))
				state_new.flags |= _DB_IST_N_FINISHED;
			if (_db_chain_leaf(x_iter))
				state_new.flags |= _DB_IST_X_FINISHED;

			/* don't remove nodes if we have more actions/levels */
			if ((x_iter->act_t_flg || x_iter->nxt_t) &&
			    !(n_iter->act_t_flg || n_iter->nxt_t))
				goto prune_return;
			if ((x_iter->act_f_flg || x_iter->nxt_f) &&
			    !(n_iter->act_f_flg || n_iter->nxt_f))
				goto prune_return;

			/* if finished, compare actions */
			if ((state_new.flags & _DB_IST_N_FINISHED) &&
			    (state_new.flags & _DB_IST_X_FINISHED)) {
				if (n_iter->act_t_flg != x_iter->act_t_flg)
					goto prune_return;
				if (n_iter->act_t != x_iter->act_t)
					goto prune_return;

				if (n_iter->act_f_flg != x_iter->act_f_flg)
					goto prune_return;
				if (n_iter->act_f != x_iter->act_f)
					goto prune_return;
			}

			/* check next level */
			if (n_iter->nxt_t) {
				_db_node_get(x_iter);
				state_nxt = *state;
				state_nxt.flags |= _DB_IST_M_MATCHSET;
				cnt += _db_tree_prune(&x_iter->nxt_t,
						      n_iter->nxt_t,
						      &state_nxt);
				cnt += _db_node_put(&x_iter);
				if (state_nxt.flags & _DB_IST_MATCH) {
					state_new.flags |= state_nxt.flags;
					/* don't return yet, we need to check
					 * the current node */
				}
				if (x_iter == NULL)
					goto prune_next_node;
			}
			if (n_iter->nxt_f) {
				_db_node_get(x_iter);
				state_nxt = *state;
				state_nxt.flags |= _DB_IST_M_MATCHSET;
				cnt += _db_tree_prune(&x_iter->nxt_f,
						      n_iter->nxt_f,
						      &state_nxt);
				cnt += _db_node_put(&x_iter);
				if (state_nxt.flags & _DB_IST_MATCH) {
					state_new.flags |= state_nxt.flags;
					/* don't return yet, we need to check
					 * the current node */
				}
				if (x_iter == NULL)
					goto prune_next_node;
			}

			/* remove the node? */
			if (!_db_tree_act_check(x_iter, state_new.action) &&
			    (state_new.flags & _DB_IST_MATCH) &&
			    (state_new.flags & _DB_IST_N_FINISHED) &&
			    (state_new.flags & _DB_IST_X_PREFIX)) {
				/* yes - the new tree is "shorter" */
				cnt += _db_tree_remove(&state->sx->chains,
						       x_iter);
				if (state->sx->chains == NULL)
					goto prune_return;
			} else if (!_db_tree_act_check(x_iter, state_new.action)
				   && (state_new.flags & _DB_IST_MATCH) &&
				   (state_new.flags & _DB_IST_X_FINISHED) &&
				   (state_new.flags & _DB_IST_N_PREFIX)) {
				/* no - the new tree is "longer" */
				goto prune_return;
			}
		} else if (_db_chain_lt(x_iter, n_iter)) {
			/* bail if we have a prefix on the new tree */
			if (state->flags & _DB_IST_N_PREFIX)
				goto prune_return;

			/* check the next level in the existing tree */
			if (x_iter->nxt_t) {
				_db_node_get(x_iter);
				state_nxt = *state;
				state_nxt.flags &= ~_DB_IST_MATCH;
				state_nxt.flags |= _DB_IST_X_PREFIX;
				cnt += _db_tree_prune(&x_iter->nxt_t, n_iter,
						      &state_nxt);
				cnt += _db_node_put(&x_iter);
				if (state_nxt.flags & _DB_IST_MATCH) {
					state_new.flags |= state_nxt.flags;
					goto prune_return;
				}
				if (x_iter == NULL)
					goto prune_next_node;
			}
			if (x_iter->nxt_f) {
				_db_node_get(x_iter);
				state_nxt = *state;
				state_nxt.flags &= ~_DB_IST_MATCH;
				state_nxt.flags |= _DB_IST_X_PREFIX;
				cnt += _db_tree_prune(&x_iter->nxt_f, n_iter,
						      &state_nxt);
				cnt += _db_node_put(&x_iter);
				if (state_nxt.flags & _DB_IST_MATCH) {
					state_new.flags |= state_nxt.flags;
					goto prune_return;
				}
				if (x_iter == NULL)
					goto prune_next_node;
			}
		} else {
			/* bail if we have a prefix on the existing tree */
			if (state->flags & _DB_IST_X_PREFIX)
				goto prune_return;

			/* check the next level in the new tree */
			if (n_iter->nxt_t) {
				_db_node_get(x_iter);
				state_nxt = *state;
				state_nxt.flags &= ~_DB_IST_MATCH;
				state_nxt.flags |= _DB_IST_N_PREFIX;
				cnt += _db_tree_prune(&x_iter, n_iter->nxt_t,
						      &state_nxt);
				cnt += _db_node_put(&x_iter);
				if (state_nxt.flags & _DB_IST_MATCH) {
					state_new.flags |= state_nxt.flags;
					goto prune_return;
				}
				if (x_iter == NULL)
					goto prune_next_node;
			}
			if (n_iter->nxt_f) {
				_db_node_get(x_iter);
				state_nxt = *state;
				state_nxt.flags &= ~_DB_IST_MATCH;
				state_nxt.flags |= _DB_IST_N_PREFIX;
				cnt += _db_tree_prune(&x_iter, n_iter->nxt_f,
						      &state_nxt);
				cnt += _db_node_put(&x_iter);
				if (state_nxt.flags & _DB_IST_MATCH) {
					state_new.flags |= state_nxt.flags;
					goto prune_return;
				}
				if (x_iter == NULL)
					goto prune_next_node;
			}
		}

prune_next_node:
		/* check next node on this level */
		x_iter = x_iter_next;
	} while (x_iter);

	// if we are falling through, we clearly didn't match on anything
	state_new.flags &= ~_DB_IST_MATCH;

prune_return:
	/* no more nodes on this level, return to the level above */
	if (state_new.flags & _DB_IST_MATCH)
		state->flags |= state_new.flags;
	else
		state->flags &= ~_DB_IST_MATCH;
	return cnt;
}

/**
 * Add a new tree into an existing tree
 * @param existing pointer to the existing tree
 * @param new pointer to the new tree
 * @param state pointer to a state structure
 *
 * This function adds the new tree into the existing tree, fetching additional
 * references as necessary.  Returns zero on success, negative values on
 * failure.
 *
 */
static int _db_tree_add(struct db_arg_chain_tree **existing,
			struct db_arg_chain_tree *new,
			struct db_iter_state *state)
{
	int rc;
	struct db_arg_chain_tree *x_iter = *existing;
	struct db_arg_chain_tree *n_iter = new;

	do {
		if (_db_chain_eq(x_iter, n_iter)) {
			if (n_iter->act_t_flg) {
				if (!x_iter->act_t_flg) {
					/* new node has a true action */

					/* do the actions match? */
					rc = _db_tree_act_check(x_iter->nxt_t,
								n_iter->act_t);
					if (rc != 0)
						return rc;

					/* update with the new action */
					rc = _db_node_put(&x_iter->nxt_t);
					x_iter->nxt_t = NULL;
					x_iter->act_t = n_iter->act_t;
					x_iter->act_t_flg = true;
					state->sx->node_cnt -= rc;
				} else if (n_iter->act_t != x_iter->act_t) {
					/* if we are dealing with a 64-bit
					 * comparison, we need to adjust our
					 * action based on the full 64-bit
					 * value to ensure we handle GT/GE
					 * comparisons correctly */
					if (n_iter->arg_h_flg &&
					    (n_iter->datum_full >
					     x_iter->datum_full))
						x_iter->act_t = n_iter->act_t;
					if (_db_chain_leaf(x_iter) ||
					    _db_chain_leaf(n_iter))
						return -EEXIST;
				}
			}
			if (n_iter->act_f_flg) {
				if (!x_iter->act_f_flg) {
					/* new node has a false action */

					/* do the actions match? */
					rc = _db_tree_act_check(x_iter->nxt_f,
								n_iter->act_f);
					if (rc != 0)
						return rc;

					/* update with the new action */
					rc = _db_node_put(&x_iter->nxt_f);
					x_iter->nxt_f = NULL;
					x_iter->act_f = n_iter->act_f;
					x_iter->act_f_flg = true;
					state->sx->node_cnt -= rc;
				} else if (n_iter->act_f != x_iter->act_f) {
					/* if we are dealing with a 64-bit
					 * comparison, we need to adjust our
					 * action based on the full 64-bit
					 * value to ensure we handle LT/LE
					 * comparisons correctly */
					if (n_iter->arg_h_flg &&
					    (n_iter->datum_full <
					     x_iter->datum_full))
						x_iter->act_t = n_iter->act_t;
					if (_db_chain_leaf(x_iter) ||
					    _db_chain_leaf(n_iter))
						return -EEXIST;
				}
			}

			if (n_iter->nxt_t) {
				if (x_iter->nxt_t) {
					/* compare the next level */
					rc = _db_tree_add(&x_iter->nxt_t,
							  n_iter->nxt_t,
							  state);
					if (rc != 0)
						return rc;
				} else if (!x_iter->act_t_flg) {
					/* add a new sub-tree */
					x_iter->nxt_t = _db_node_get(n_iter->nxt_t);
				} else
					/* done - existing tree is "shorter" */
					return 0;
			}
			if (n_iter->nxt_f) {
				if (x_iter->nxt_f) {
					/* compare the next level */
					rc = _db_tree_add(&x_iter->nxt_f,
							  n_iter->nxt_f,
							  state);
					if (rc != 0)
						return rc;
				} else if (!x_iter->act_f_flg) {
					/* add a new sub-tree */
					x_iter->nxt_f = _db_node_get(n_iter->nxt_f);
				} else
					/* done - existing tree is "shorter" */
					return 0;
			}

			return 0;
		} else if (!_db_chain_lt(x_iter, n_iter)) {
			/* try to move along the current level */
			if (x_iter->lvl_nxt == NULL) {
				/* add to the end of this level */
				n_iter->lvl_prv = _db_node_get(x_iter);
				x_iter->lvl_nxt = _db_node_get(n_iter);
				return 0;
			} else
				/* next */
				x_iter = x_iter->lvl_nxt;
		} else {
			/* add before the existing node on this level*/
			if (x_iter->lvl_prv != NULL) {
				x_iter->lvl_prv->lvl_nxt = _db_node_get(n_iter);
				n_iter->lvl_prv = x_iter->lvl_prv;
				x_iter->lvl_prv = _db_node_get(n_iter);
				n_iter->lvl_nxt = x_iter;
			} else {
				x_iter->lvl_prv = _db_node_get(n_iter);
				n_iter->lvl_nxt = _db_node_get(x_iter);
			}
			if (*existing == x_iter) {
				*existing = _db_node_get(n_iter);
				_db_node_put(&x_iter);
			}
			return 0;
		}
	} while (x_iter);

	return 0;
}

/**
 * Free and reset the seccomp filter DB
 * @param db the seccomp filter DB
 *
 * This function frees any existing filters and resets the filter DB to a
 * default state; only the DB architecture is preserved.
 *
 */
static void _db_reset(struct db_filter *db)
{
	struct db_sys_list *s_iter;
	struct db_api_rule_list *r_iter;

	if (db == NULL)
		return;

	/* free any filters */
	if (db->syscalls != NULL) {
		s_iter = db->syscalls;
		while (s_iter != NULL) {
			db->syscalls = s_iter->next;
			_db_tree_put(&s_iter->chains);
			free(s_iter);
			s_iter = db->syscalls;
		}
		db->syscalls = NULL;
	}
	db->syscall_cnt = 0;

	/* free any rules */
	if (db->rules != NULL) {
		/* split the loop first then loop and free */
		db->rules->prev->next = NULL;
		r_iter = db->rules;
		while (r_iter != NULL) {
			db->rules = r_iter->next;
			free(r_iter);
			r_iter = db->rules;
		}
		db->rules = NULL;
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
static struct db_filter *_db_init(const struct arch_def *arch)
{
	struct db_filter *db;

	db = zmalloc(sizeof(*db));
	if (db == NULL)
		return NULL;

	/* set the arch and reset the DB to a known state */
	db->arch = arch;
	_db_reset(db);

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
static void _db_release(struct db_filter *db)
{
	if (db == NULL)
		return;

	/* free and reset the DB */
	_db_reset(db);
	free(db);
}

/**
 * Destroy a seccomp filter snapshot
 * @param snap the seccomp filter snapshot
 *
 * This function destroys a seccomp filter snapshot.  After calling this
 * function, the snapshot should no longer be referenced.
 *
 */
static void _db_snap_release(struct db_filter_snap *snap)
{
	unsigned int iter;

	if (snap == NULL)
		return;

	if (snap->filter_cnt > 0) {
		for (iter = 0; iter < snap->filter_cnt; iter++) {
			if (snap->filters[iter])
				_db_release(snap->filters[iter]);
		}
		free(snap->filters);
	}
	free(snap);
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
static int _db_syscall_priority(struct db_filter *db,
				int syscall, uint8_t priority)
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
	s_new = zmalloc(sizeof(*s_new));
	if (s_new == NULL)
		return -ENOMEM;
	s_new->num = syscall;
	s_new->priority = sys_pri;
	s_new->valid = false;

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
 * Create a new rule
 * @param strict the strict value
 * @param action the rule's action
 * @param syscall the syscall number
 * @param chain the syscall argument filter
 *
 * This function creates a new rule structure based on the given arguments.
 * Returns a pointer to the new rule on success, NULL on failure.
 *
 */
static struct db_api_rule_list *_db_rule_new(bool strict,
					     uint32_t action, int syscall,
					     struct db_api_arg *chain)
{
	struct db_api_rule_list *rule;

	rule = zmalloc(sizeof(*rule));
	if (rule == NULL)
		return NULL;
	rule->action = action;
	rule->syscall = syscall;
	rule->strict = strict;
	memcpy(rule->args, chain, sizeof(*chain) * ARG_COUNT_MAX);

	return rule;
}

/**
 * Duplicate an existing filter rule
 * @param src the rule to duplicate
 *
 * This function makes an exact copy of the given rule, but does not add it
 * to any lists.  Returns a pointer to the new rule on success, NULL on
 * failure.
 *
 */
struct db_api_rule_list *db_rule_dup(const struct db_api_rule_list *src)
{
	struct db_api_rule_list *dest;

	dest = malloc(sizeof(*dest));
	if (dest == NULL)
		return NULL;
	memcpy(dest, src, sizeof(*dest));
	dest->prev = NULL;
	dest->next = NULL;

	return dest;
}

/**
 * Free and reset the seccomp filter collection
 * @param col the seccomp filter collection
 * @param def_action the default filter action
 *
 * This function frees any existing filter DBs and resets the collection to a
 * default state.  In the case of failure the filter collection may be in an
 * unknown state and should be released.  Returns zero on success, negative
 * values on failure.
 *
 */
int db_col_reset(struct db_filter_col *col, uint32_t def_action)
{
	unsigned int iter;
	struct db_filter *db;
	struct db_filter_snap *snap;

	if (col == NULL)
		return -EINVAL;

	/* free any filters */
	for (iter = 0; iter < col->filter_cnt; iter++)
		_db_release(col->filters[iter]);
	col->filter_cnt = 0;
	if (col->filters)
		free(col->filters);
	col->filters = NULL;

	/* set the endianess to undefined */
	col->endian = 0;

	/* set the default attribute values */
	col->attr.act_default = def_action;
	col->attr.act_badarch = SCMP_ACT_KILL;
	col->attr.nnp_enable = 1;
	col->attr.tsync_enable = 0;
	col->attr.api_tskip = 0;
	col->attr.log_enable = 0;
	col->attr.spec_allow = 0;
	col->attr.optimize = 1;
	col->attr.api_sysrawrc = 0;

	/* set the state */
	col->state = _DB_STA_VALID;
	if (def_action == SCMP_ACT_NOTIFY)
		col->notify_used = true;
	else
		col->notify_used = false;

	/* reset the initial db */
	db = _db_init(arch_def_native);
	if (db == NULL)
		return -ENOMEM;
	if (db_col_db_add(col, db) < 0) {
		_db_release(db);
		return -ENOMEM;
	}

	/* reset the transactions */
	while (col->snapshots) {
		snap = col->snapshots;
		col->snapshots = snap->next;
		for (iter = 0; iter < snap->filter_cnt; iter++)
			_db_release(snap->filters[iter]);
		free(snap->filters);
		free(snap);
	}

	return 0;
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

	col = zmalloc(sizeof(*col));
	if (col == NULL)
		return NULL;

	/* reset the DB to a known state */
	if (db_col_reset(col, def_action) < 0)
		goto init_failure;

	return col;

init_failure:
	db_col_release(col);
	return NULL;
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
	unsigned int iter;
	struct db_filter_snap *snap;

	if (col == NULL)
		return;

	/* set the state, just in case */
	col->state = _DB_STA_FREED;

	/* free any snapshots */
	while (col->snapshots != NULL) {
		snap = col->snapshots;
		col->snapshots = snap->next;
		_db_snap_release(snap);
	}

	/* free any filters */
	for (iter = 0; iter < col->filter_cnt; iter++)
		_db_release(col->filters[iter]);
	col->filter_cnt = 0;
	if (col->filters)
		free(col->filters);
	col->filters = NULL;

	/* free the collection */
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
	if (col != NULL && col->state == _DB_STA_VALID && col->filter_cnt > 0)
		return 0;
	return -EINVAL;
}

/**
 * Validate the seccomp action
 * @param col the seccomp filter collection
 * @param action the seccomp action
 *
 * Verify that the given action is a valid seccomp action; return zero if
 * valid, -EINVAL if invalid.
 */
int db_col_action_valid(const struct db_filter_col *col, uint32_t action)
{
	if (col != NULL) {
		/* NOTE: in some cases we don't have a filter collection yet,
		 *       but when we do we need to do the following checks */

		/* kernel disallows TSYNC and NOTIFY in one filter unless we
		 * have the TSYNC_ESRCH flag */
		if (sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC_ESRCH) < 1 &&
		    col->attr.tsync_enable && action == SCMP_ACT_NOTIFY)
			return -EINVAL;
	}

	if (sys_chk_seccomp_action(action) == 1)
		return 0;
	return -EINVAL;
}

/**
 * Merge two filter collections
 * @param col_dst the destination filter collection
 * @param col_src the source filter collection
 *
 * This function merges two filter collections into the given destination
 * collection.  The source filter collection is no longer valid if the function
 * returns successfully.  Returns zero on success, negative values on failure.
 *
 */
int db_col_merge(struct db_filter_col *col_dst, struct db_filter_col *col_src)
{
	unsigned int iter_a, iter_b;
	struct db_filter **dbs;

	/* verify that the endianess is a match */
	if (col_dst->endian != col_src->endian)
		return -EDOM;

	/* make sure we don't have any arch/filter collisions */
	for (iter_a = 0; iter_a < col_dst->filter_cnt; iter_a++) {
		for (iter_b = 0; iter_b < col_src->filter_cnt; iter_b++) {
			if (col_dst->filters[iter_a]->arch->token ==
			    col_src->filters[iter_b]->arch->token)
				return -EEXIST;
		}
	}

	/* expand the destination */
	dbs = realloc(col_dst->filters,
		      sizeof(struct db_filter *) *
		      (col_dst->filter_cnt + col_src->filter_cnt));
	if (dbs == NULL)
		return -ENOMEM;
	col_dst->filters = dbs;

	/* transfer the architecture filters */
	for (iter_a = col_dst->filter_cnt, iter_b = 0;
	     iter_b < col_src->filter_cnt; iter_a++, iter_b++) {
		col_dst->filters[iter_a] = col_src->filters[iter_b];
		col_dst->filter_cnt++;
	}

	/* free the source */
	col_src->filter_cnt = 0;
	db_col_release(col_src);

	return 0;
}

/**
 * Check to see if an architecture filter exists in the filter collection
 * @param col the seccomp filter collection
 * @param arch_token the architecture token
 *
 * Iterate through the given filter collection checking to see if a filter
 * exists for the specified architecture.  Returns -EEXIST if a filter is found,
 * zero if a matching filter does not exist.
 *
 */
int db_col_arch_exist(struct db_filter_col *col, uint32_t arch_token)
{
	unsigned int iter;

	for (iter = 0; iter < col->filter_cnt; iter++)
		if (col->filters[iter]->arch->token == arch_token)
			return -EEXIST;

	return 0;
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
	int rc = 0;

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
	case SCMP_FLTATR_CTL_TSYNC:
		*value = col->attr.tsync_enable;
		break;
	case SCMP_FLTATR_API_TSKIP:
		*value = col->attr.api_tskip;
		break;
	case SCMP_FLTATR_CTL_LOG:
		*value = col->attr.log_enable;
		break;
	case SCMP_FLTATR_CTL_SSB:
		*value = col->attr.spec_allow;
		break;
	case SCMP_FLTATR_CTL_OPTIMIZE:
		*value = col->attr.optimize;
		break;
	case SCMP_FLTATR_API_SYSRAWRC:
		*value = col->attr.api_sysrawrc;
		break;
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

/**
 * Get a filter attribute
 * @param col the seccomp filter collection
 * @param attr the filter attribute
 *
 * Returns the requested filter attribute value with zero on any error.
 * Special care must be given with this function as error conditions can be
 * hidden from the caller.
 *
 */
uint32_t db_col_attr_read(const struct db_filter_col *col,
			  enum scmp_filter_attr attr)
{
	uint32_t value = 0;

	db_col_attr_get(col, attr, &value);
	return value;
}

/**
 * Set a filter attribute
 * @param col the seccomp filter collection
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
	int rc = 0;

	switch (attr) {
	case SCMP_FLTATR_ACT_DEFAULT:
		/* read only */
		return -EACCES;
		break;
	case SCMP_FLTATR_ACT_BADARCH:
		if (db_col_action_valid(col, value) == 0)
			col->attr.act_badarch = value;
		else
			return -EINVAL;
		break;
	case SCMP_FLTATR_CTL_NNP:
		col->attr.nnp_enable = (value ? 1 : 0);
		break;
	case SCMP_FLTATR_CTL_TSYNC:
		rc = sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC);
		if (rc == 1) {
			/* supported */
			rc = 0;
			/* kernel disallows TSYNC and NOTIFY in one filter
			 * unless we have TSYNC_ESRCH */
			if (sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC_ESRCH) < 1 &&
			    value && col->notify_used)
				return -EINVAL;
			col->attr.tsync_enable = (value ? 1 : 0);
		} else if (rc == 0)
			/* unsupported */
			rc = -EOPNOTSUPP;
		break;
	case SCMP_FLTATR_API_TSKIP:
		col->attr.api_tskip = (value ? 1 : 0);
		break;
	case SCMP_FLTATR_CTL_LOG:
		rc = sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_LOG);
		if (rc == 1) {
			/* supported */
			rc = 0;
			col->attr.log_enable = (value ? 1 : 0);
		} else if (rc == 0) {
			/* unsupported */
			rc = -EOPNOTSUPP;
		}
		break;
	case SCMP_FLTATR_CTL_SSB:
		rc = sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_SPEC_ALLOW);
		if (rc == 1) {
			/* supported */
			rc = 0;
			col->attr.spec_allow = (value ? 1 : 0);
		} else if (rc == 0) {
			/* unsupported */
			rc = -EOPNOTSUPP;
		}
		break;
	case SCMP_FLTATR_CTL_OPTIMIZE:
		switch (value) {
		case 1:
		case 2:
			col->attr.optimize = value;
			break;
		default:
			rc = -EOPNOTSUPP;
			break;
		}
		break;
	case SCMP_FLTATR_API_SYSRAWRC:
		col->attr.api_sysrawrc = (value ? 1 : 0);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

/**
 * Add a new architecture filter to a filter collection
 * @param col the seccomp filter collection
 * @param arch the architecture
 *
 * This function adds a new architecture filter DB to an existing seccomp
 * filter collection assuming there isn't a filter DB already present with the
 * same architecture.  Returns zero on success, negative values on failure.
 *
 */
int db_col_db_new(struct db_filter_col *col, const struct arch_def *arch)
{
	int rc;
	struct db_filter *db;

	db = _db_init(arch);
	if (db == NULL)
		return -ENOMEM;
	rc = db_col_db_add(col, db);
	if (rc < 0)
		_db_release(db);

	return rc;
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
	struct db_filter **dbs;

	if (col->endian != 0 && col->endian != db->arch->endian)
		return -EDOM;

	if (db_col_arch_exist(col, db->arch->token))
		return -EEXIST;

	dbs = realloc(col->filters,
		      sizeof(struct db_filter *) * (col->filter_cnt + 1));
	if (dbs == NULL)
		return -ENOMEM;
	col->filters = dbs;
	col->filter_cnt++;
	col->filters[col->filter_cnt - 1] = db;
	if (col->endian == 0)
		col->endian = db->arch->endian;

	return 0;
}

/**
 * Remove a filter DB from a filter collection
 * @param col the seccomp filter collection
 * @param arch_token the architecture token
 *
 * This function removes an existing seccomp filter DB from an existing seccomp
 * filter collection.  Returns zero on success, negative values on failure.
 *
 */
int db_col_db_remove(struct db_filter_col *col, uint32_t arch_token)
{
	unsigned int iter;
	unsigned int found;
	struct db_filter **dbs;

	if ((col->filter_cnt <= 0) || (db_col_arch_exist(col, arch_token) == 0))
		return -EINVAL;

	for (found = 0, iter = 0; iter < col->filter_cnt; iter++) {
		if (found)
			col->filters[iter - 1] = col->filters[iter];
		else if (col->filters[iter]->arch->token == arch_token) {
			_db_release(col->filters[iter]);
			found = 1;
		}
	}
	col->filters[--col->filter_cnt] = NULL;

	if (col->filter_cnt > 0) {
		/* NOTE: if we can't do the realloc it isn't fatal, we just
		 *       have some extra space allocated */
		dbs = realloc(col->filters,
			      sizeof(struct db_filter *) * col->filter_cnt);
		if (dbs != NULL)
			col->filters = dbs;
	} else {
		/* this was the last filter so free all the associated memory
		 * and reset the endian token */
		free(col->filters);
		col->filters = NULL;
		col->endian = 0;
	}

	return 0;
}

/**
 * Test if the argument filter can be skipped because it's a tautology
 * @param arg argument filter
 *
 * If this argument filter applied to the lower 32 bit can be skipped this
 * function returns false.
 *
 */
static bool _db_arg_cmp_need_lo(const struct db_api_arg *arg)
{
	if (arg->op == SCMP_CMP_MASKED_EQ && D64_LO(arg->mask) == 0)
		return false;

	return true;
}

/**
 * Test if the argument filter can be skipped because it's a tautology
 * @param arg argument filter
 *
 * If this argument filter applied to the upper 32 bit can be skipped this
 * function returns false.
 *
 */
static bool _db_arg_cmp_need_hi(const struct db_api_arg *arg)
{
	if (arg->op == SCMP_CMP_MASKED_EQ && D64_HI(arg->mask) == 0)
		return false;

	return true;
}

/**
 * Fixup the node based on the op/mask
 * @param node the chain node
 *
 * Ensure the datum is masked as well.
 *
 */
static void _db_node_mask_fixup(struct db_arg_chain_tree *node)
{
	node->datum &= node->mask;
}

/**
 * Generate a new filter rule for a 64 bit system
 * @param arch the architecture definition
 * @param rule the new filter rule
 *
 * This function generates a new syscall filter for a 64 bit system. Returns
 * zero on success, negative values on failure.
 *
 */
static struct db_sys_list *_db_rule_gen_64(const struct arch_def *arch,
					   const struct db_api_rule_list *rule)
{
	unsigned int iter;
	struct db_sys_list *s_new;
	const struct db_api_arg *chain = rule->args;
	struct db_arg_chain_tree *c_iter[3] = { NULL, NULL, NULL };
	struct db_arg_chain_tree *c_prev[3] = { NULL, NULL, NULL };
	enum scmp_compare op_prev = _SCMP_CMP_MIN;
	unsigned int arg;
	scmp_datum_t mask;
	scmp_datum_t datum;

	s_new = zmalloc(sizeof(*s_new));
	if (s_new == NULL)
		return NULL;
	s_new->num = rule->syscall;
	s_new->valid = true;
	/* run through the argument chain */
	for (iter = 0; iter < ARG_COUNT_MAX; iter++) {
		if (chain[iter].valid == 0)
			continue;

		/* TODO: handle the case were either hi or lo isn't needed */

		/* skip generating instruction which are no-ops */
		if (!_db_arg_cmp_need_hi(&chain[iter]) &&
		    !_db_arg_cmp_need_lo(&chain[iter]))
			continue;

		c_iter[0] = zmalloc(sizeof(*c_iter[0]));
		if (c_iter[0] == NULL)
			goto gen_64_failure;
		c_iter[1] = zmalloc(sizeof(*c_iter[1]));
		if (c_iter[1] == NULL) {
			free(c_iter[0]);
			goto gen_64_failure;
		}
		c_iter[2] = NULL;

		arg = chain[iter].arg;
		mask = chain[iter].mask;
		datum = chain[iter].datum;

		/* NOTE: with the idea that a picture is worth a thousand
		 *       words, i'm presenting the following diagrams which
		 *       show how we should compare 64-bit syscall arguments
		 *       using 32-bit comparisons.
		 *
		 *       in the diagrams below "A(x)" is the syscall argument
		 *       being evaluated and "R(x)" is the syscall argument
		 *       value specified in the libseccomp rule.  the "ACCEPT"
		 *       verdict indicates a rule match and processing should
		 *       continue on to the rest of the rule, or the final rule
		 *       action should be triggered.  the "REJECT" verdict
		 *       indicates that the rule does not match and processing
		 *       should continue to the next rule or the default
		 *       action.
		 *
		 * SCMP_CMP_GT:
		 *                   +------------------+
		 *                +--|  Ah(x) >  Rh(x)  |------+
		 *                |  +------------------+      |
		 *              FALSE                         TRUE     A
		 *                |                            |       C
		 *                +-----------+                +---->  C
		 *                            v                +---->  E
		 *                   +------------------+      |       P
		 *                +--|  Ah(x) == Rh(x)  |--+   |       T
		 *        R       |  +------------------+  |   |
		 *        E     FALSE                     TRUE |
		 *        J  <----+                        |   |
		 *        E  <----+           +------------+   |
		 *        C     FALSE         v                |
		 *        T       |  +------------------+      |
		 *                +--|  Al(x) >  Rl(x)  |------+
		 *                   +------------------+
		 *
		 * SCMP_CMP_GE:
		 *                   +------------------+
		 *                +--|  Ah(x) >  Rh(x)  |------+
		 *                |  +------------------+      |
		 *              FALSE                         TRUE     A
		 *                |                            |       C
		 *                +-----------+                +---->  C
		 *                            v                +---->  E
		 *                   +------------------+      |       P
		 *                +--|  Ah(x) == Rh(x)  |--+   |       T
		 *        R       |  +------------------+  |   |
		 *        E     FALSE                     TRUE |
		 *        J  <----+                        |   |
		 *        E  <----+           +------------+   |
		 *        C     FALSE         v                |
		 *        T       |  +------------------+      |
		 *                +--|  Al(x) >= Rl(x)  |------+
		 *                   +------------------+
		 *
		 * SCMP_CMP_LT:
		 *                   +------------------+
		 *                +--|  Ah(x) >  Rh(x)  |------+
		 *                |  +------------------+      |
		 *              FALSE                         TRUE     R
		 *                |                            |       E
		 *                +-----------+                +---->  J
		 *                            v                +---->  E
		 *                   +------------------+      |       C
		 *                +--|  Ah(x) == Rh(x)  |--+   |       T
		 *        A       |  +------------------+  |   |
		 *        C     FALSE                     TRUE |
		 *        C  <----+                        |   |
		 *        E  <----+           +------------+   |
		 *        P     FALSE         v                |
		 *        T       |  +------------------+      |
		 *                +--|  Al(x) >= Rl(x)  |------+
		 *                   +------------------+
		 *
		 * SCMP_CMP_LE:
		 *                   +------------------+
		 *                +--|  Ah(x) >  Rh(x)  |------+
		 *                |  +------------------+      |
		 *              FALSE                         TRUE     R
		 *                |                            |       E
		 *                +-----------+                +---->  J
		 *                            v                +---->  E
		 *                   +------------------+      |       C
		 *                +--|  Ah(x) == Rh(x)  |--+   |       T
		 *        A       |  +------------------+  |   |
		 *        C     FALSE                     TRUE |
		 *        C  <----+                        |   |
		 *        E  <----+           +------------+   |
		 *        P     FALSE         v                |
		 *        T       |  +------------------+      |
		 *                +--|  Al(x) >  Rl(x)  |------+
		 *                   +------------------+
		 *
		 * SCMP_CMP_EQ:
		 *                   +------------------+
		 *                +--|  Ah(x) == Rh(x)  |--+
		 *        R       |  +------------------+  |           A
		 *        E     FALSE                     TRUE         C
		 *        J  <----+                        |           C
		 *        E  <----+           +------------+   +---->  E
		 *        C     FALSE         v                |       P
		 *        T       |  +------------------+      |       T
		 *                +--|  Al(x) == Rl(x)  |------+
		 *                   +------------------+
		 *
		 * SCMP_CMP_NE:
		 *                   +------------------+
		 *                +--|  Ah(x) == Rh(x)  |--+
		 *        A       |  +------------------+  |           R
		 *        C     FALSE                     TRUE         E
		 *        C  <----+                        |           J
		 *        E  <----+           +------------+   +---->  E
		 *        P     FALSE         v                |       C
		 *        T       |  +------------------+      |       T
		 *                +--|  Al(x) == Rl(x)  |------+
		 *                   +------------------+
		 *
		 */

		/* setup the level */
		switch (chain[iter].op) {
		case SCMP_CMP_GT:
		case SCMP_CMP_GE:
		case SCMP_CMP_LE:
		case SCMP_CMP_LT:
			c_iter[2] = zmalloc(sizeof(*c_iter[2]));
			if (c_iter[2] == NULL) {
				free(c_iter[0]);
				free(c_iter[1]);
				goto gen_64_failure;
			}

			c_iter[0]->arg = arg;
			c_iter[1]->arg = arg;
			c_iter[2]->arg = arg;
			c_iter[0]->arg_h_flg = true;
			c_iter[1]->arg_h_flg = true;
			c_iter[2]->arg_h_flg = false;
			c_iter[0]->arg_offset = arch_arg_offset_hi(arch, arg);
			c_iter[1]->arg_offset = arch_arg_offset_hi(arch, arg);
			c_iter[2]->arg_offset = arch_arg_offset_lo(arch, arg);

			c_iter[0]->mask = D64_HI(mask);
			c_iter[1]->mask = D64_HI(mask);
			c_iter[2]->mask = D64_LO(mask);
			c_iter[0]->datum = D64_HI(datum);
			c_iter[1]->datum = D64_HI(datum);
			c_iter[2]->datum = D64_LO(datum);
			c_iter[0]->datum_full = datum;
			c_iter[1]->datum_full = datum;
			c_iter[2]->datum_full = datum;

			_db_node_mask_fixup(c_iter[0]);
			_db_node_mask_fixup(c_iter[1]);
			_db_node_mask_fixup(c_iter[2]);

			c_iter[0]->op = SCMP_CMP_GT;
			c_iter[1]->op = SCMP_CMP_EQ;
			switch (chain[iter].op) {
			case SCMP_CMP_GT:
			case SCMP_CMP_LE:
				c_iter[2]->op = SCMP_CMP_GT;
				break;
			case SCMP_CMP_GE:
			case SCMP_CMP_LT:
				c_iter[2]->op = SCMP_CMP_GE;
				break;
			default:
				/* we should never get here */
				goto gen_64_failure;
			}
			c_iter[0]->op_orig = chain[iter].op;
			c_iter[1]->op_orig = chain[iter].op;
			c_iter[2]->op_orig = chain[iter].op;

			c_iter[0]->nxt_f = _db_node_get(c_iter[1]);
			c_iter[1]->nxt_t = _db_node_get(c_iter[2]);
			break;
		case SCMP_CMP_EQ:
		case SCMP_CMP_MASKED_EQ:
		case SCMP_CMP_NE:
			c_iter[0]->arg = arg;
			c_iter[1]->arg = arg;
			c_iter[0]->arg_h_flg = true;
			c_iter[1]->arg_h_flg = false;
			c_iter[0]->arg_offset = arch_arg_offset_hi(arch, arg);
			c_iter[1]->arg_offset = arch_arg_offset_lo(arch, arg);

			c_iter[0]->mask = D64_HI(mask);
			c_iter[1]->mask = D64_LO(mask);
			c_iter[0]->datum = D64_HI(datum);
			c_iter[1]->datum = D64_LO(datum);
			c_iter[0]->datum_full = datum;
			c_iter[1]->datum_full = datum;

			_db_node_mask_fixup(c_iter[0]);
			_db_node_mask_fixup(c_iter[1]);

			switch (chain[iter].op) {
			case SCMP_CMP_MASKED_EQ:
				c_iter[0]->op = SCMP_CMP_MASKED_EQ;
				c_iter[1]->op = SCMP_CMP_MASKED_EQ;
				break;
			default:
				c_iter[0]->op = SCMP_CMP_EQ;
				c_iter[1]->op = SCMP_CMP_EQ;
			}
			c_iter[0]->op_orig = chain[iter].op;
			c_iter[1]->op_orig = chain[iter].op;

			c_iter[0]->nxt_t = _db_node_get(c_iter[1]);
			break;
		default:
			/* we should never get here */
			goto gen_64_failure;
		}

		/* link this level to the previous level */
		if (c_prev[0] != NULL) {
			switch (op_prev) {
			case SCMP_CMP_GT:
			case SCMP_CMP_GE:
				c_prev[0]->nxt_t = _db_node_get(c_iter[0]);
				c_prev[2]->nxt_t = _db_node_get(c_iter[0]);
				break;
			case SCMP_CMP_EQ:
			case SCMP_CMP_MASKED_EQ:
				c_prev[1]->nxt_t = _db_node_get(c_iter[0]);
				break;
			case SCMP_CMP_LE:
			case SCMP_CMP_LT:
				c_prev[1]->nxt_f = _db_node_get(c_iter[0]);
				c_prev[2]->nxt_f = _db_node_get(c_iter[0]);
				break;
			case SCMP_CMP_NE:
				c_prev[0]->nxt_f = _db_node_get(c_iter[0]);
				c_prev[1]->nxt_f = _db_node_get(c_iter[0]);
				break;
			default:
				/* we should never get here */
				goto gen_64_failure;
			}
		} else
			s_new->chains = _db_node_get(c_iter[0]);

		/* update the node count */
		switch (chain[iter].op) {
		case SCMP_CMP_NE:
		case SCMP_CMP_EQ:
		case SCMP_CMP_MASKED_EQ:
			s_new->node_cnt += 2;
			break;
		default:
			s_new->node_cnt += 3;
		}

		/* keep pointers to this level */
		c_prev[0] = c_iter[0];
		c_prev[1] = c_iter[1];
		c_prev[2] = c_iter[2];
		op_prev = chain[iter].op;
	}
	if (c_iter[0] != NULL) {
		/* set the actions on the last layer */
		switch (op_prev) {
		case SCMP_CMP_GT:
		case SCMP_CMP_GE:
			c_iter[0]->act_t_flg = true;
			c_iter[0]->act_t = rule->action;
			c_iter[2]->act_t_flg = true;
			c_iter[2]->act_t = rule->action;
			break;
		case SCMP_CMP_LE:
		case SCMP_CMP_LT:
			c_iter[1]->act_f_flg = true;
			c_iter[1]->act_f = rule->action;
			c_iter[2]->act_f_flg = true;
			c_iter[2]->act_f = rule->action;
			break;
		case SCMP_CMP_EQ:
		case SCMP_CMP_MASKED_EQ:
			c_iter[1]->act_t_flg = true;
			c_iter[1]->act_t = rule->action;
			break;
		case SCMP_CMP_NE:
			c_iter[0]->act_f_flg = true;
			c_iter[0]->act_f = rule->action;
			c_iter[1]->act_f_flg = true;
			c_iter[1]->act_f = rule->action;
			break;
		default:
			/* we should never get here */
			goto gen_64_failure;
		}
	} else
		s_new->action = rule->action;

	return s_new;

gen_64_failure:
	/* free the new chain and its syscall struct */
	_db_tree_put(&s_new->chains);
	free(s_new);
	return NULL;
}

/**
 * Generate a new filter rule for a 32 bit system
 * @param arch the architecture definition
 * @param rule the new filter rule
 *
 * This function generates a new syscall filter for a 32 bit system. Returns
 * zero on success, negative values on failure.
 *
 */
static struct db_sys_list *_db_rule_gen_32(const struct arch_def *arch,
					   const struct db_api_rule_list *rule)
{
	unsigned int iter;
	struct db_sys_list *s_new;
	const struct db_api_arg *chain = rule->args;
	struct db_arg_chain_tree *c_iter = NULL, *c_prev = NULL;
	bool tf_flag;

	s_new = zmalloc(sizeof(*s_new));
	if (s_new == NULL)
		return NULL;
	s_new->num = rule->syscall;
	s_new->valid = true;
	/* run through the argument chain */
	for (iter = 0; iter < ARG_COUNT_MAX; iter++) {
		if (chain[iter].valid == 0)
			continue;

		/* skip generating instructions which are no-ops */
		if (!_db_arg_cmp_need_lo(&chain[iter]))
			continue;

		c_iter = zmalloc(sizeof(*c_iter));
		if (c_iter == NULL)
			goto gen_32_failure;
		c_iter->arg = chain[iter].arg;
		c_iter->arg_h_flg = false;
		c_iter->arg_offset = arch_arg_offset(arch, c_iter->arg);
		c_iter->op = chain[iter].op;
		c_iter->op_orig = chain[iter].op;
		/* implicitly strips off the upper 32 bit */
		c_iter->mask = chain[iter].mask;
		c_iter->datum = chain[iter].datum;
		c_iter->datum_full = chain[iter].datum;

		/* link in the new node and update the chain */
		if (c_prev != NULL) {
			if (tf_flag)
				c_prev->nxt_t = _db_node_get(c_iter);
			else
				c_prev->nxt_f = _db_node_get(c_iter);
		} else
			s_new->chains = _db_node_get(c_iter);
		s_new->node_cnt++;

		/* rewrite the op to reduce the op/datum combos */
		switch (c_iter->op) {
		case SCMP_CMP_NE:
			c_iter->op = SCMP_CMP_EQ;
			tf_flag = false;
			break;
		case SCMP_CMP_LT:
			c_iter->op = SCMP_CMP_GE;
			tf_flag = false;
			break;
		case SCMP_CMP_LE:
			c_iter->op = SCMP_CMP_GT;
			tf_flag = false;
			break;
		default:
			tf_flag = true;
		}

		/* fixup the mask/datum */
		_db_node_mask_fixup(c_iter);

		c_prev = c_iter;
	}
	if (c_iter != NULL) {
		/* set the leaf node */
		if (tf_flag) {
			c_iter->act_t_flg = true;
			c_iter->act_t = rule->action;
		} else {
			c_iter->act_f_flg = true;
			c_iter->act_f = rule->action;
		}
	} else
		s_new->action = rule->action;

	return s_new;

gen_32_failure:
	/* free the new chain and its syscall struct */
	_db_tree_put(&s_new->chains);
	free(s_new);
	return NULL;
}

/**
 * Add a new rule to the seccomp filter DB
 * @param db the seccomp filter db
 * @param rule the filter rule
 *
 * This function adds a new syscall filter to the seccomp filter DB, adding to
 * the existing filters for the syscall, unless no argument specific filters
 * are present (filtering only on the syscall).  When adding new chains, the
 * shortest chain, or most inclusive filter match, will be entered into the
 * filter DB. Returns zero on success, negative values on failure.
 *
 * It is important to note that in the case of failure the db may be corrupted,
 * the caller must use the transaction mechanism if the db integrity is
 * important.
 *
 */
int db_rule_add(struct db_filter *db, const struct db_api_rule_list *rule)
{
	int rc = -ENOMEM;
	struct db_sys_list *s_new, *s_iter, *s_prev = NULL;
	struct db_iter_state state;
	bool rm_flag = false;

	assert(db != NULL);

	/* do all our possible memory allocation up front so we don't have to
	 * worry about failure once we get to the point where we start updating
	 * the filter db */
	if (db->arch->size == ARCH_SIZE_64)
		s_new = _db_rule_gen_64(db->arch, rule);
	else if (db->arch->size == ARCH_SIZE_32)
		s_new = _db_rule_gen_32(db->arch, rule);
	else
		return -EFAULT;
	if (s_new == NULL)
		return -ENOMEM;

	/* find a matching syscall/chain or insert a new one */
	s_iter = db->syscalls;
	while (s_iter != NULL && s_iter->num < rule->syscall) {
		s_prev = s_iter;
		s_iter = s_iter->next;
	}
	s_new->priority = _DB_PRI_MASK_CHAIN - s_new->node_cnt;
add_reset:
	if (s_iter == NULL || s_iter->num != rule->syscall) {
		/* new syscall, add before s_iter */
		if (s_prev != NULL) {
			s_new->next = s_prev->next;
			s_prev->next = s_new;
		} else {
			s_new->next = db->syscalls;
			db->syscalls = s_new;
		}
		db->syscall_cnt++;
		return 0;
	} else if (s_iter->chains == NULL) {
		if (rm_flag || !s_iter->valid) {
			/* we are here because our previous pass cleared the
			 * entire syscall chain when searching for a subtree
			 * match or the existing syscall entry is a phantom,
			 * so either way add the new chain */
			s_iter->chains = s_new->chains;
			s_iter->action = s_new->action;
			s_iter->node_cnt = s_new->node_cnt;
			if (s_iter->valid)
				s_iter->priority = s_new->priority;
			s_iter->valid = true;
			free(s_new);
			rc = 0;
			goto add_priority_update;
		} else {
			/* syscall exists without any chains - existing filter
			 * is at least as large as the new entry so cleanup and
			 * exit */
			_db_tree_put(&s_new->chains);
			free(s_new);
			goto add_free_ok;
		}
	} else if (s_iter->chains != NULL && s_new->chains == NULL) {
		/* syscall exists with chains but the new filter has no chains
		 * so we need to clear the existing chains and exit */
		_db_tree_put(&s_iter->chains);
		s_iter->chains = NULL;
		s_iter->node_cnt = 0;
		s_iter->action = rule->action;

		/* cleanup the new tree and return */
		_db_tree_put(&s_new->chains);
		free(s_new);
		goto add_free_ok;
	}

	/* prune any sub-trees that are no longer required */
	memset(&state, 0, sizeof(state));
	state.sx = s_iter;
	state.action = rule->action;
	rc = _db_tree_prune(&s_iter->chains, s_new->chains, &state);
	if (rc > 0) {
		/* we pruned at least some of the existing tree */
		rm_flag = true;
		s_iter->node_cnt -= rc;
		if (s_iter->chains == NULL)
			/* we pruned the entire tree */
			goto add_reset;
	} else if ((state.flags & _DB_IST_M_REDUNDANT) == _DB_IST_M_REDUNDANT) {
		/* the existing tree is "shorter", drop the new one */
		_db_tree_put(&s_new->chains);
		free(s_new);
		goto add_free_ok;
	}

	/* add the new rule to the existing filter and cleanup */
	memset(&state, 0, sizeof(state));
	state.sx = s_iter;
	rc = _db_tree_add(&s_iter->chains, s_new->chains, &state);
	if (rc < 0)
		goto add_failure;
	s_iter->node_cnt += s_new->node_cnt;
	s_iter->node_cnt -= _db_tree_put(&s_new->chains);
	free(s_new);

add_free_ok:
	rc = 0;
add_priority_update:
	/* update the priority */
	if (s_iter != NULL) {
		s_iter->priority &= (~_DB_PRI_MASK_CHAIN);
		s_iter->priority |= (_DB_PRI_MASK_CHAIN - s_iter->node_cnt);
	}
	return rc;

add_failure:
	/* NOTE: another reminder that we don't do any db error recovery here,
	 * use the transaction mechanism as previously mentioned */
	_db_tree_put(&s_new->chains);
	free(s_new);
	return rc;
}

/**
 * Set the priority of a given syscall
 * @param col the filter collection
 * @param syscall the syscall number
 * @param priority priority value, higher value == higher priority
 *
 * This function sets the priority of the given syscall; this value is used
 * when generating the seccomp filter code such that higher priority syscalls
 * will incur less filter code overhead than the lower priority syscalls in the
 * filter.  Returns zero on success, negative values on failure.
 *
 */
int db_col_syscall_priority(struct db_filter_col *col,
			    int syscall, uint8_t priority)
{
	int rc = 0, rc_tmp;
	unsigned int iter;
	int sc_tmp;
	struct db_filter *filter;

	for (iter = 0; iter < col->filter_cnt; iter++) {
		filter = col->filters[iter];
		sc_tmp = syscall;

		rc_tmp = arch_syscall_translate(filter->arch, &sc_tmp);
		if (rc_tmp < 0)
			goto priority_failure;

		/* if this is a pseudo syscall then we need to rewrite the
		 * syscall for some arch specific reason, don't forget the
		 * special handling for syscall -1 */
		if (sc_tmp < -1) {
			/* we set this as a strict op - we don't really care
			 * since priorities are a "best effort" thing - as we
			 * want to catch the -EDOM error and bail on this
			 * architecture */
			rc_tmp = arch_syscall_rewrite(filter->arch, &sc_tmp);
			if (rc_tmp == -EDOM)
				continue;
			if (rc_tmp < 0)
				goto priority_failure;
		}

		rc_tmp = _db_syscall_priority(filter, sc_tmp, priority);

priority_failure:
		if (rc == 0 && rc_tmp < 0)
			rc = rc_tmp;
	}

	return rc;
}

/**
 * Add a new rule to a single filter
 * @param filter the filter
 * @param rule the filter rule
 *
 * This is a helper function for db_col_rule_add() and similar functions, it
 * isn't generally useful.  Returns zero on success, negative values on error.
 *
 */
static int _db_col_rule_add(struct db_filter *filter,
			    struct db_api_rule_list *rule)
{
	int rc;
	struct db_api_rule_list *iter;

	/* add the rule to the filter */
	rc = arch_filter_rule_add(filter, rule);
	if (rc != 0)
		return rc;

	/* insert the chain to the end of the rule list */
	iter = rule;
	while (iter->next)
		iter = iter->next;
	if (filter->rules != NULL) {
		rule->prev = filter->rules->prev;
		iter->next = filter->rules;
		filter->rules->prev->next = rule;
		filter->rules->prev = iter;
	} else {
		rule->prev = iter;
		iter->next = rule;
		filter->rules = rule;
	}

	return 0;
}

/**
 * Add a new rule to the current filter
 * @param col the filter collection
 * @param strict the strict flag
 * @param action the filter action
 * @param syscall the syscall number
 * @param arg_cnt the number of argument filters in the argument filter chain
 * @param arg_array the argument filter chain, (uint, enum scmp_compare, ulong)
 *
 * This function adds a new argument/comparison/value to the seccomp filter for
 * a syscall; multiple arguments can be specified and they will be chained
 * together (essentially AND'd together) in the filter.  When the strict flag
 * is true the function will fail if the exact rule can not be added to the
 * filter, if the strict flag is false the function will not fail if the
 * function needs to adjust the rule due to architecture specifics.  Returns
 * zero on success, negative values on failure.
 *
 */
int db_col_rule_add(struct db_filter_col *col,
		    bool strict, uint32_t action, int syscall,
		    unsigned int arg_cnt, const struct scmp_arg_cmp *arg_array)
{
	int rc = 0, rc_tmp;
	unsigned int iter;
	unsigned int arg_num;
	size_t chain_size;
	struct db_api_arg *chain = NULL;
	struct scmp_arg_cmp arg_data;
	struct db_api_rule_list *rule;
	struct db_filter *db;

	/* collect the arguments for the filter rule */
	chain_size = sizeof(*chain) * ARG_COUNT_MAX;
	chain = zmalloc(chain_size);
	if (chain == NULL)
		return -ENOMEM;
	for (iter = 0; iter < arg_cnt; iter++) {
		arg_data = arg_array[iter];
		arg_num = arg_data.arg;
		if (arg_num < ARG_COUNT_MAX && chain[arg_num].valid == 0) {
			chain[arg_num].valid = 1;
			chain[arg_num].arg = arg_num;
			chain[arg_num].op = arg_data.op;
			/* TODO: we should check datum/mask size against the
			 *	 arch definition, e.g. 64 bit datum on x86 */
			switch (chain[arg_num].op) {
			case SCMP_CMP_NE:
			case SCMP_CMP_LT:
			case SCMP_CMP_LE:
			case SCMP_CMP_EQ:
			case SCMP_CMP_GE:
			case SCMP_CMP_GT:
				chain[arg_num].mask = DATUM_MAX;
				chain[arg_num].datum = arg_data.datum_a;
				break;
			case SCMP_CMP_MASKED_EQ:
				chain[arg_num].mask = arg_data.datum_a;
				chain[arg_num].datum = arg_data.datum_b;
				break;
			default:
				rc = -EINVAL;
				goto add_return;
			}
		} else {
			rc = -EINVAL;
			goto add_return;
		}
	}

	/* create a checkpoint */
	rc = db_col_transaction_start(col);
	if (rc != 0)
		goto add_return;

	/* add the rule to the different filters in the collection */
	for (iter = 0; iter < col->filter_cnt; iter++) {
		db = col->filters[iter];

		/* create the rule */
		rule = _db_rule_new(strict, action, syscall, chain);
		if (rule == NULL) {
			rc_tmp = -ENOMEM;
			goto add_arch_fail;
		}

		/* add the rule */
		rc_tmp = _db_col_rule_add(db, rule);
		if (rc_tmp != 0)
			free(rule);

add_arch_fail:
		if (rc_tmp != 0 && rc == 0)
			rc = rc_tmp;
	}

	/* commit the transaction or abort */
	if (rc == 0)
		db_col_transaction_commit(col);
	else
		db_col_transaction_abort(col);

add_return:
	/* update the misc state */
	if (rc == 0 && action == SCMP_ACT_NOTIFY)
		col->notify_used = true;
	if (chain != NULL)
		free(chain);
	return rc;
}

/**
 * Start a new seccomp filter transaction
 * @param col the filter collection
 *
 * This function starts a new seccomp filter transaction for the given filter
 * collection.  Returns zero on success, negative values on failure.
 *
 */
int db_col_transaction_start(struct db_filter_col *col)
{
	int rc;
	unsigned int iter;
	struct db_filter_snap *snap;
	struct db_filter *filter_o, *filter_s;
	struct db_api_rule_list *rule_o, *rule_s = NULL;

	/* check to see if a shadow snapshot exists */
	if (col->snapshots && col->snapshots->shadow) {
		/* we have a shadow!  this will be easy */

		/* NOTE: we don't bother to do any verification of the shadow
		 *       because we start a new transaction every time we add
		 *       a new rule to the filter(s); if this ever changes we
		 *       will need to add a mechanism to verify that the shadow
		 *       transaction is current/correct */

		col->snapshots->shadow = false;
		return 0;
	}

	/* allocate the snapshot */
	snap = zmalloc(sizeof(*snap));
	if (snap == NULL)
		return -ENOMEM;
	snap->filters = zmalloc(sizeof(struct db_filter *) * col->filter_cnt);
	if (snap->filters == NULL) {
		free(snap);
		return -ENOMEM;
	}
	snap->filter_cnt = col->filter_cnt;
	for (iter = 0; iter < snap->filter_cnt; iter++)
		snap->filters[iter] = NULL;
	snap->next = NULL;

	/* create a snapshot of the current filter state */
	for (iter = 0; iter < col->filter_cnt; iter++) {
		/* allocate a new filter */
		filter_o = col->filters[iter];
		filter_s = _db_init(filter_o->arch);
		if (filter_s == NULL)
			goto trans_start_failure;
		snap->filters[iter] = filter_s;

		/* create a filter snapshot from existing rules */
		rule_o = filter_o->rules;
		if (rule_o == NULL)
			continue;
		do {
			/* duplicate the rule */
			rule_s = db_rule_dup(rule_o);
			if (rule_s == NULL)
				goto trans_start_failure;

			/* add the rule */
			rc = _db_col_rule_add(filter_s, rule_s);
			if (rc != 0)
				goto trans_start_failure;
			rule_s = NULL;

			/* next rule */
			rule_o = rule_o->next;
		} while (rule_o != filter_o->rules);
	}

	/* add the snapshot to the list */
	snap->next = col->snapshots;
	col->snapshots = snap;

	return 0;

trans_start_failure:
	if (rule_s != NULL)
		free(rule_s);
	_db_snap_release(snap);
	return -ENOMEM;
}

/**
 * Abort the top most seccomp filter transaction
 * @param col the filter collection
 *
 * This function aborts the most recent seccomp filter transaction.
 *
 */
void db_col_transaction_abort(struct db_filter_col *col)
{
	int iter;
	unsigned int filter_cnt;
	struct db_filter **filters;
	struct db_filter_snap *snap;

	if (col->snapshots == NULL)
		return;

	/* replace the current filter with the last snapshot */
	snap = col->snapshots;
	col->snapshots = snap->next;
	filter_cnt = col->filter_cnt;
	filters = col->filters;
	col->filter_cnt = snap->filter_cnt;
	col->filters = snap->filters;
	free(snap);

	/* free the filter we swapped out */
	for (iter = 0; iter < filter_cnt; iter++)
		_db_release(filters[iter]);
	free(filters);
}

/**
 * Commit the top most seccomp filter transaction
 * @param col the filter collection
 *
 * This function commits the most recent seccomp filter transaction and
 * attempts to create a shadow transaction that is a duplicate of the current
 * filter to speed up future transactions.
 *
 */
void db_col_transaction_commit(struct db_filter_col *col)
{
	int rc;
	unsigned int iter;
	struct db_filter_snap *snap;
	struct db_filter *filter_o, *filter_s;
	struct db_api_rule_list *rule_o, *rule_s;

	snap = col->snapshots;
	if (snap == NULL)
		return;

	/* check for a shadow set by a higher transaction commit */
	if (snap->shadow) {
		/* leave the shadow intact, but drop the next snapshot */
		if (snap->next) {
			snap->next = snap->next->next;
			_db_snap_release(snap->next);
		}
		return;
	}

	/* adjust the number of filters if needed */
	if (col->filter_cnt > snap->filter_cnt) {
		unsigned int tmp_i;
		struct db_filter **tmp_f;

		/* add filters */
		tmp_f = realloc(snap->filters,
				sizeof(struct db_filter *) * col->filter_cnt);
		if (tmp_f == NULL)
			goto shadow_err;
		snap->filters = tmp_f;
		do {
			tmp_i = snap->filter_cnt;
			snap->filters[tmp_i] =
				_db_init(col->filters[tmp_i]->arch);
			if (snap->filters[tmp_i] == NULL)
				goto shadow_err;
			snap->filter_cnt++;
		} while (snap->filter_cnt < col->filter_cnt);
	} else if (col->filter_cnt < snap->filter_cnt) {
		/* remove filters */

		/* NOTE: while we release the filters we no longer need, we
		 *       don't bother to resize the filter array, we just
		 *       adjust the filter counter, this *should* be harmless
		 *       at the cost of a not reaping all the memory possible */

		do {
			_db_release(snap->filters[snap->filter_cnt--]);
		} while (snap->filter_cnt > col->filter_cnt);
	}

	/* loop through each filter and update the rules on the snapshot */
	for (iter = 0; iter < col->filter_cnt; iter++) {
		filter_o = col->filters[iter];
		filter_s = snap->filters[iter];

		/* skip ahead to the new rule(s) */
		rule_o = filter_o->rules;
		rule_s = filter_s->rules;
		if (rule_o == NULL)
			/* nothing to shadow */
			continue;
		if (rule_s != NULL) {
			do {
				rule_o = rule_o->next;
				rule_s = rule_s->next;
			} while (rule_s != filter_s->rules);

			/* did we actually add any rules? */
			if (rule_o == filter_o->rules)
				/* no, we are done in this case */
				continue;
		}

		/* update the old snapshot to make it a shadow */
		do {
			/* duplicate the rule */
			rule_s = db_rule_dup(rule_o);
			if (rule_s == NULL)
				goto shadow_err;

			/* add the rule */
			rc = _db_col_rule_add(filter_s, rule_s);
			if (rc != 0) {
				free(rule_s);
				goto shadow_err;
			}

			/* next rule */
			rule_o = rule_o->next;
		} while (rule_o != filter_o->rules);
	}

	/* success, mark the snapshot as a shadow and return */
	snap->shadow = true;
	return;

shadow_err:
	/* we failed making a shadow, cleanup and return */
	col->snapshots = snap->next;
	_db_snap_release(snap);
	return;
}
