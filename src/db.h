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

/* XXX - need to provide doxygen comments for the types here */

struct db_syscall_arg_val_list {
	/* comparison operator */
	enum scmp_compare op;
	/* syscall argument value */
	/* XXX - this could change, just need something big enough to hold any
	 *       syscall argument */
	unsigned long datum;

	struct db_syscall_arg_val_list *next;
};

struct db_syscall_arg_list {
	/* argument number (a0 = 0, a1 = 1, etc.) */
	unsigned int num;
	/* list of permissible values, kept as an unsorted single-linked list */
	struct db_syscall_arg_val_list *values;

	struct db_syscall_arg_list *next;
};

struct db_syscall_list {
	/* native syscall number */
	unsigned int num;
	/* list of args, kept as a sorted single-linked list (optional) */
	struct db_syscall_arg_list *args;

	struct db_syscall_list *next;
};

struct db_filter {
	/* action to take if we don't match an explicit allow/deny */
	enum scmp_flt_action def_action;

	/* syscall filters, kept as a sorted single-linked list */
	struct db_syscall_list *sys_allow;
	struct db_syscall_list *sys_deny;
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

struct db_filter *db_new(enum scmp_flt_action def_action);
void db_destroy(struct db_filter *db);

int db_add_syscall(struct db_filter *db,
		   enum scmp_flt_action action, unsigned int syscall,
		   unsigned int override);
int db_add_syscall_arg(struct db_filter *db,
		       enum scmp_flt_action action,
		       unsigned int syscall,
		       unsigned int arg,
		       enum scmp_compare op, unsigned long datum,
		       unsigned int override);

struct db_syscall_list *db_find_syscall(const struct db_filter *db,
					enum scmp_flt_action action,
					unsigned int syscall);
struct db_syscall_list *db_find_syscall_all(const struct db_filter *db,
					    unsigned int syscall);

#endif