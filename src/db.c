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

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <seccomp.h>

#include "db.h"

/**
 * Free each item in the DB list
 * @param iter the iterator
 * @param list the list
 * 
 * This macro acts as for()/while() conditional and iterates the following
 * statement before freeing the list item.
 * 
 */
#define _db_list_foreach_free(iter,list) \
	for (iter = (list); \
	     iter != NULL; \
	     (list) = iter->next, free(iter), iter = (list))

/**
 * Free a syscall filter argument chain list
 * @param list the argument chain list
 * 
 * This function frees a syscall argument chain list.
 * 
 */
static void _db_sys_arg_chain_list_free(struct db_syscall_arg_chain_list *list)
{
	struct db_syscall_arg_chain_list *c_iter;
	struct db_syscall_arg_list *a_iter;

	_db_list_foreach_free(c_iter, list) {
		_db_list_foreach_free(a_iter, c_iter->args);
	}
}

/**
 * Intitalize a seccomp filter DB
 * @param def_action the default filter action
 * 
 * This function initializes a seccomp filter DB and readies it for use.
 * Returns a pointer to the DB on success, NULL on failure.
 * 
 */
struct db_filter *db_new(enum scmp_flt_action def_action)
{
	struct db_filter *db;

	db = malloc(sizeof(*db));
	if (db) {
		memset(db, 0, sizeof(*db));
		db->def_action = def_action;
	}

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
void db_destroy(struct db_filter *db)
{
	struct db_syscall_list *s_iter;

	if (db == NULL)
		return;

	_db_list_foreach_free(s_iter, db->syscalls)
		_db_sys_arg_chain_list_free(s_iter->chains);
}

/**
 * Add a syscall filter with an optional argument chain
 * @param db the seccomp filter db
 * @param override override existing rules
 * @param action the filter action
 * @param syscall the syscall number
 * @param chain_len the number of argument filters in the argument filter chain
 * @param chain_list argument filter chain, (uint, enum scmp_compare, ulong)
 * 
 * This function adds a new syscall filter to the seccomp filter DB, adding to
 * the existing filters for the syscall, unless no argument specific filters
 * are present (filtering only on the syscall).  If override is true, then the
 * argument filter rule is added regardless of what is already present.
 * Returns zero on success, negative values on failure.
 * 
 */
int db_add_syscall(struct db_filter *db, unsigned int override,
		   enum scmp_flt_action action, unsigned int syscall,
		   unsigned int chain_len, va_list chain_list)
{
	int rc;
	unsigned int iter;
	struct db_syscall_list *sys;
	struct db_syscall_list *sys_prev = NULL;
	struct db_syscall_list *sys_new = NULL;
	struct db_syscall_arg_chain_list *c_new = NULL;
	struct db_syscall_arg_chain_list *c_iter;
	struct db_syscall_arg_list *s_arg_prev = NULL;
	struct db_syscall_arg_list *s_arg_new = NULL;

	assert(db != NULL);

	/* we can't easily (we could do it, but that would be painful) check
	 * to see if an existing argument chain matches the new addition so
	 * we always add the new chain to the end of the list - in the future
	 * we can try to be more clever about this - XXX */
	if (chain_len > 0) {
		c_new = malloc(sizeof(*c_new));
		if (c_new == NULL) {
			rc = -ENOMEM;
			goto db_add_syscall_args_failure;
		}
		memset(c_new, 0, sizeof(*c_new));
		for (iter = 0; iter < chain_len; iter++) {
			s_arg_new = malloc(sizeof(*s_arg_new));
			if (s_arg_new == NULL) {
				rc = -ENOMEM;
				goto db_add_syscall_args_failure;
			}
			memset(s_arg_new, 0, sizeof(*s_arg_new));

			s_arg_new->num = va_arg(chain_list, unsigned int);
			/* XXX - sanity check 's_arg_new->num' */
			s_arg_new->op = va_arg(chain_list, unsigned int);
			if (s_arg_new->op <= _SCMP_CMP_MIN ||
			s_arg_new->op >= _SCMP_CMP_MAX) {
				rc = -EINVAL;
				goto db_add_syscall_args_failure;
			}
			s_arg_new->datum = va_arg(chain_list, unsigned long);

			if (s_arg_prev == NULL)
				c_new->args = s_arg_new;
			else
				s_arg_prev->next = s_arg_new;
			s_arg_prev = s_arg_new;
		}
	} else
		c_new = NULL;

	/* XXX - this is where we could compare c_new against the existing
	 *       argument chains */

	/* find the syscall, or create one, and add the argument chain to it */
	sys = db->syscalls;
	while (sys != NULL && sys->num < syscall) {
		sys_prev = sys;
		sys = sys->next;
	}
	if (sys == NULL || sys->num != syscall) {
		sys_new = malloc(sizeof(*sys_new));
		if (sys_new == NULL) {
			rc = -ENOMEM;
			goto db_add_syscall_args_failure;
		}
		memset(sys_new, 0, sizeof(*sys_new));
		sys_new->num = syscall;
		sys_new->chains = c_new;

		if (sys_prev == NULL) {
			sys_new->next = sys;
			db->syscalls = sys_new;
		} else {
			sys_new->next = sys_prev->next;
			sys_prev->next = sys_new;
		}
	} else if (sys->chains != NULL) {
		c_iter = sys->chains;
		while (c_iter->next != NULL)
			c_iter = c_iter->next;
		c_iter->next = c_new;
	} else if (override) {
		/* if override is true, we add an argument filter if given */
		sys->chains = c_new;
	} else if (c_new != NULL) {
		/* if override is false, we don't want to restrict a syscall
		 * only filter (no arguments specified) so error out */
		rc = -EEXIST;
		goto db_add_syscall_args_failure;
	}

	return 0;

db_add_syscall_args_failure:
	if (c_new)
		_db_sys_arg_chain_list_free(c_new);
	if (sys_new)
		free(sys_new);
	va_end(chain_list);
	return rc;
}

/**
 * Find a syscall filter in the DB
 * @param db the seccomp filter DB
 * @param syscall the syscall number
 * 
 * This function searches the filter DB using the given syscall number and
 * returns a pointer to the syscall filter or NULL if no matching syscall
 * filter exists.
 * 
 */
struct db_syscall_list *db_find_syscall(const struct db_filter *db,
					unsigned int syscall)
{
	struct db_syscall_list *iter;

	assert(db != NULL);

	iter = db->syscalls;
	while (iter != NULL && iter->num < syscall)
		iter = iter->next;
	if (iter != NULL && iter->num == syscall)
		return iter;

	return NULL;
}
