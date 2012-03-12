/**
 * Enhanced Seccomp Filter DB
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

#ifndef _FILTER_DB_H
#define _FILTER_DB_H

#include <seccomp.h>

#include "arch.h"

/* XXX - need to provide doxygen comments for the types here */

struct db_api_arg {
	unsigned int valid;

	unsigned int arg;
	unsigned int op;
	datum_t datum;
};

struct db_arg_chain_tree {
	/* argument number (a0 = 0, a1 = 1, etc.) */
	unsigned int arg;

	/* comparison operator */
	enum scmp_compare op;
	/* syscall argument value */
	datum_t datum;

	/* actions */
	unsigned int act_t_flg;
	uint32_t act_t;
	unsigned int act_f_flg;
	uint32_t act_f;

	/* list of nodes on this level */
	struct db_arg_chain_tree *lvl_prv, *lvl_nxt;

	/* next node in the chain */
	struct db_arg_chain_tree *nxt_t;
	struct db_arg_chain_tree *nxt_f;
};
#define db_chain_lt(x,y) \
	(((x)->arg < (y)->arg) || \
	 (((x)->arg == (y)->arg) && ((x)->op < (y)->op)))
#define db_chain_eq(x,y) \
	(((x)->arg == (y)->arg) && \
	 ((x)->op == (y)->op) && ((x)->datum == (y)->datum))
#define db_chain_leaf(x) \
	(((x)->act_t_flg != 0) || ((x)->act_t_flg != 0))

struct db_sys_list {
	/* native syscall number */
	unsigned int num;

	/* priority - higher is better */
	unsigned int priority;

	/* the argument chain heads */
	struct db_arg_chain_tree *chains;
	unsigned int node_cnt;

	/* action in the case of no argument chains */
	uint32_t action;

	struct db_sys_list *next;
};

struct db_filter {
	/* target architecture */
	const struct arch_def *arch;

	/* action to take if we don't match an explicit allow/deny */
	uint32_t def_action;

	/* syscall filters, kept as a sorted single-linked list */
	struct db_sys_list *syscalls;
};

/**
 * Iterate over each item in the DB list
 * @param iter the iterator
 * @param list the list
 *
 * This macro acts as for()/while() conditional and iterates the following
 * statement for each item in the given list.
 *
 */
#define db_list_foreach(iter,list) \
	for (iter = (list); iter != NULL; iter = iter->next)

struct db_filter *db_new(const struct arch_def *arch, uint32_t def_action);
void db_destroy(struct db_filter *db);

int db_add_syscall(struct db_filter *db, uint32_t action, unsigned int syscall,
		   struct db_api_arg *chain);

struct db_sys_list *db_find_syscall(const struct db_filter *db,
				    unsigned int syscall);

#endif
