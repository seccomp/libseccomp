/**
 * Enhanced Seccomp Filter DB
 *
 * Copyright (c) 2012,2016 Red Hat <pmoore@redhat.com>
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

#ifndef _FILTER_DB_H
#define _FILTER_DB_H

#include <inttypes.h>
#include <stdbool.h>

#include <seccomp.h>

#include "arch.h"

/* XXX - need to provide doxygen comments for the types here */

struct db_api_arg {
	unsigned int arg;
	enum scmp_compare op;
	scmp_datum_t mask;
	scmp_datum_t datum;

	bool valid;
};

struct db_api_rule_list {
	uint32_t action;
	int syscall;
	bool strict;
	struct db_api_arg args[ARG_COUNT_MAX];

	struct db_api_rule_list *prev, *next;
};

struct db_arg_chain_tree {
	/* argument number (a0 = 0, a1 = 1, etc.) */
	unsigned int arg;
	/* true to indicate this is the high 32-bit word of a 64-bit value */
	bool arg_h_flg;
	/* argument bpf offset */
	unsigned int arg_offset;

	/* comparison operator */
	enum scmp_compare op;
	enum scmp_compare op_orig;
	/* syscall argument value */
	uint32_t mask;
	uint32_t datum;
	scmp_datum_t datum_full;

	/* actions */
	bool act_t_flg;
	bool act_f_flg;
	uint32_t act_t;
	uint32_t act_f;

	/* list of nodes on this level */
	struct db_arg_chain_tree *lvl_prv, *lvl_nxt;

	/* next node in the chain */
	struct db_arg_chain_tree *nxt_t;
	struct db_arg_chain_tree *nxt_f;

	unsigned int refcnt;
};
#define ARG_MASK_MAX		((uint32_t)-1)

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
	/* temporary use only by the BPF generator */
	struct db_sys_list *pri_prv, *pri_nxt;

	bool valid;
};

struct db_filter_attr {
	/* action to take if we don't match an explicit allow/deny */
	uint32_t act_default;
	/* action to take if we don't match the architecture */
	uint32_t act_badarch;
	/* NO_NEW_PRIVS related attributes */
	uint32_t nnp_enable;
	/* SECCOMP_FILTER_FLAG_TSYNC related attributes */
	uint32_t tsync_enable;
	/* allow rules with a -1 syscall value */
	uint32_t api_tskip;
	/* SECCOMP_FILTER_FLAG_LOG related attributes */
	uint32_t log_enable;
	/* SPEC_ALLOW related attributes */
	uint32_t spec_allow;
	/* SCMP_FLTATR_CTL_OPTIMIZE related attributes */
	uint32_t optimize;
	/* return the raw system return codes */
	uint32_t api_sysrawrc;
};

struct db_filter {
	/* target architecture */
	const struct arch_def *arch;

	/* syscall filters, kept as a sorted single-linked list */
	struct db_sys_list *syscalls;
	unsigned int syscall_cnt;

	/* list of rules used to build the filters, kept in order */
	struct db_api_rule_list *rules;
};

struct db_filter_snap {
	/* individual filters */
	struct db_filter **filters;
	unsigned int filter_cnt;
	bool shadow;

	struct db_filter_snap *next;
};

struct db_filter_col {
	/* verification / state */
	int state;

	/* attributes */
	struct db_filter_attr attr;

	/* individual filters */
	int endian;
	struct db_filter **filters;
	unsigned int filter_cnt;

	/* transaction snapshots */
	struct db_filter_snap *snapshots;

	/* userspace notification */
	bool notify_used;
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

struct db_api_rule_list *db_rule_dup(const struct db_api_rule_list *src);

struct db_filter_col *db_col_init(uint32_t def_action);
int db_col_reset(struct db_filter_col *col, uint32_t def_action);
void db_col_release(struct db_filter_col *col);

int db_col_valid(struct db_filter_col *col);

int db_col_action_valid(const struct db_filter_col *col, uint32_t action);

int db_col_merge(struct db_filter_col *col_dst, struct db_filter_col *col_src);

int db_col_arch_exist(struct db_filter_col *col, uint32_t arch_token);

int db_col_attr_get(const struct db_filter_col *col,
		    enum scmp_filter_attr attr, uint32_t *value);
uint32_t db_col_attr_read(const struct db_filter_col *col,
			  enum scmp_filter_attr attr);
int db_col_attr_set(struct db_filter_col *col,
		    enum scmp_filter_attr attr, uint32_t value);

int db_col_db_new(struct db_filter_col *col, const struct arch_def *arch);
int db_col_db_add(struct db_filter_col *col, struct db_filter *db);
int db_col_db_remove(struct db_filter_col *col, uint32_t arch_token);

int db_col_rule_add(struct db_filter_col *col,
		    bool strict, uint32_t action, int syscall,
		    unsigned int arg_cnt, const struct scmp_arg_cmp *arg_array);

int db_col_syscall_priority(struct db_filter_col *col,
			    int syscall, uint8_t priority);

int db_col_transaction_start(struct db_filter_col *col);
void db_col_transaction_abort(struct db_filter_col *col);
void db_col_transaction_commit(struct db_filter_col *col);

int db_rule_add(struct db_filter *db, const struct db_api_rule_list *rule);

#endif
