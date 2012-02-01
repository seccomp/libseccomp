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

#include <seccomp.h>

#include "filter_db.h"

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
 * Free a syscall filter argument list
 * @param list the argument list
 * 
 * This function frees a syscall argument list.
 * 
 */
static void _db_sys_arg_list_free(struct db_syscall_arg_list *list)
{
	struct db_syscall_arg_list *a_iter;
	struct db_syscall_arg_val_list *v_iter;

	_db_list_foreach_free(a_iter, list) {
		_db_list_foreach_free(v_iter, a_iter->values);
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
struct db_filter *seccomp_db_new(enum scmp_flt_action def_action)
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
void seccomp_db_destroy(struct db_filter *db)
{
	struct db_syscall_list *s_iter;

	if (db == NULL)
		return;

	_db_list_foreach_free(s_iter, db->sys_allow)
		_db_sys_arg_list_free(s_iter->args);
	_db_list_foreach_free(s_iter, db->sys_deny)
		_db_sys_arg_list_free(s_iter->args);
}

/**
 * Add a syscall filter
 * @param db the seccomp filter db
 * @param action the filter action
 * @param syscall the syscall number
 * @param override override existing rules
 * 
 * This function adds a new syscall filter to the seccomp filter DB, and if
 * the override argument is true, any existing matching syscall rules are
 * reset/replaced.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_db_add_syscall(struct db_filter *db,
			   enum scmp_flt_action action, unsigned int syscall,
			   unsigned int override)
{
	struct db_syscall_list *sys;
	struct db_syscall_list *sys_prev = NULL;
	struct db_syscall_list *sys_new;

	assert(db != NULL);

	/* check the opposite action list first to prevent problems later */
	sys = (action == SCMP_ACT_ALLOW ? db->sys_deny : db->sys_allow);
	while (sys != NULL && sys->num < syscall)
		sys = sys->next;
	if (sys != NULL && sys->num == syscall)
		return -EEXIST;

	/* add the filter to the correct list if it isn't already present */
	sys = (action == SCMP_ACT_ALLOW ? db->sys_allow : db->sys_deny);
	while (sys != NULL && sys->num < syscall) {
		sys_prev = sys;
		sys = sys->next;
	}
	if (sys == NULL || sys->num != syscall) {
		sys_new = malloc(sizeof(*sys_new));
		if (sys_new == NULL)
			return -ENOMEM;
		memset(sys_new, 0, sizeof(*sys_new));
		sys_new->num = syscall;
		if (sys_prev == NULL) {
			sys_new->next = sys;
			if (action == SCMP_ACT_ALLOW)
				db->sys_allow = sys_new;
			else
				db->sys_deny = sys_new;
		} else {
			sys_new->next = sys_prev->next;
			sys_prev->next = sys_new;
		}
	} else if (override) {
		/* if the syscall is already present in the filter with the
		 * correct action we don't change it unless override is true */
		_db_sys_arg_list_free(sys->args);
		sys->args = NULL;
	}
	
	return 0;
}

/**
 * Add a syscall filter with an argument filter
 * @param db the seccomp filter db
 * @param action the filter action
 * @param syscall the syscall number
 * @param arg the argument number
 * @param datum the argument value
 * @param override override existing rules
 * 
 * This function adds a new syscall filter to the seccomp filter DB, adding to
 * the existing filters for the syscall, unless no argument specific filters
 * are present (filtering only on the syscall).  If override is true, then the
 * argument filter rule is added regardless of what is already present.
 * Returns zero on success, negative values on failure.
 * 
 */
int seccomp_db_add_syscall_arg(struct db_filter *db,
			       enum scmp_flt_action action,
			       unsigned int syscall,
			       unsigned int arg,
			       enum scmp_compare op, unsigned long datum,
			       unsigned int override)
{
	int rc;
	struct db_syscall_list *sys;
	struct db_syscall_list *sys_prev = NULL;
	struct db_syscall_list *sys_new = NULL;
	struct db_syscall_arg_list *s_arg;
	struct db_syscall_arg_list *s_arg_prev = NULL;
	struct db_syscall_arg_list *s_arg_new = NULL;
	struct db_syscall_arg_val_list *a_val;
	struct db_syscall_arg_val_list *a_val_prev=NULL;
	struct db_syscall_arg_val_list *a_val_new=NULL;

	assert(db != NULL);

	/* check the opposite action list first to prevent problems later */
	sys = (action == SCMP_ACT_ALLOW ? db->sys_deny : db->sys_allow);
	while (sys != NULL && sys->num < syscall)
		sys = sys->next;
	if (sys != NULL && sys->num == syscall)
		return -EEXIST;

	/* add the filter to the correct list if it isn't already present */

	/* find the syscall */
	sys = (action == SCMP_ACT_ALLOW ? db->sys_allow : db->sys_deny);
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
		sys = sys_new;
	} else if (!override && sys->args == NULL) {
		/* if override is false, we don't want to restrict a syscall
		 * only (no arguments specified) filter so fail out */
		rc = -EEXIST;
		goto db_add_syscall_args_failure;
	}
	/* find the argument */
	s_arg = sys->args;
	while (s_arg != NULL && s_arg->num < arg) {
		s_arg_prev = s_arg;
		s_arg = s_arg->next;
	}
	if (s_arg == NULL || s_arg->num != arg) {
		/* new argument filter */
		s_arg_new = malloc(sizeof(*s_arg_new));
		if (s_arg_new == NULL) {
			rc = -ENOMEM;
			goto db_add_syscall_args_failure;
		}
		memset(s_arg_new, 0, sizeof(*s_arg_new));
		s_arg_new->num = arg;
		a_val = malloc(sizeof(*a_val));
		if (a_val == NULL) {
			rc = -ENOMEM;
			goto db_add_syscall_args_failure;
		}
		memset(a_val, 0, sizeof(*a_val));
		a_val->op = op;
		a_val->datum = datum;
		s_arg_new->values = a_val;
		s_arg = s_arg_new;
	} else {
		/* existing argument filter */
		a_val = s_arg->values;
		while (a_val != NULL && a_val->datum != datum) {
			a_val_prev = a_val;
			a_val = a_val->next;
		}
		if (a_val == NULL) {
			/* new argument value */
			a_val_new = malloc(sizeof(*a_val_new));
			if (a_val_new == NULL) {
				rc = -ENOMEM;
				goto db_add_syscall_args_failure;
			}
			memset(a_val_new, 0, sizeof(*a_val_new));
			a_val_new->op = op;
			a_val_new->datum = datum;
		} else
			/* filter already exists, just return */
			return 0;
	}

	/* if necessary, add the new filter pieces to the filter db */
	if (a_val_new != NULL) {
		if (a_val_prev == NULL)
			s_arg->values = a_val_new;
		else
			a_val_prev->next = a_val_new;
	}
	if (s_arg_new != NULL) {
		if (s_arg_prev == NULL) {
			sys->args = s_arg_new;
		} else {
			s_arg_new->next = s_arg_prev->next;
			s_arg_prev->next = s_arg_new;
		}
	}
	if (sys_new != NULL) {
		if (sys_prev == NULL) {
			if (action == SCMP_ACT_ALLOW)
				db->sys_allow = sys_new;
			else
				db->sys_deny = sys_new;
		} else {
			sys_new->next = sys_prev->next;
			sys_prev->next = sys_new;
		}
	}

	return 0;

db_add_syscall_args_failure:
	if (a_val_new)
		free(a_val_new);
	if (s_arg_new)
		free(s_arg_new);
	if (sys_new)
		free(sys_new);
	return rc;
}

/**
 * Find a syscall filter in the DB
 * @param db the seccomp filter DB
 * @param action the matching filter action
 * @param syscall the syscall number
 * 
 * This function searches the filter DB using the given action and syscall
 * number and returns a pointer to the syscall filter or NULL if no matching
 * syscall filter exists.
 * 
 */
struct db_syscall_list *seccomp_db_find_syscall(const struct db_filter *db,
						enum scmp_flt_action action,
						unsigned int syscall)
{
	struct db_syscall_list *iter;

	assert(db != NULL);

	iter = (action == SCMP_ACT_ALLOW ? db->sys_allow : db->sys_deny);
	while (iter != NULL && iter->num < syscall)
		iter = iter->next;
	if (iter != NULL && iter->num == syscall)
		return iter;

	return NULL;
}

/**
 * Find a syscall filter in the DB
 * @param db the seccomp filter DB
 * @param syscall the syscall number
 * 
 * This function searches the filter DB for all possible actions using the
 * given syscall number and returns a pointer to the syscall filter or NULL if
 * no matching syscall filter exists.
 *
 */
struct db_syscall_list *seccomp_db_find_syscall_all(const struct db_filter *db,
						    unsigned int syscall)
{
	struct db_syscall_list *iter;

	assert(db != NULL);

	iter = seccomp_db_find_syscall(db, SCMP_ACT_ALLOW, syscall);
	if (iter != NULL)
		return iter;
	return seccomp_db_find_syscall(db, SCMP_ACT_DENY, syscall);
}
