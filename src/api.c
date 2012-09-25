/**
 * Seccomp Library API
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

#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

#include <seccomp.h>

#include "arch.h"
#include "db.h"
#include "gen_pfc.h"
#include "gen_bpf.h"
#include "system.h"

/**
 * Validate a filter context
 * @param ctx the filter context
 *
 * Attempt to validate the provided filter context.  Returns zero if the
 * context is valid, negative values on failure.
 *
 */
static int _ctx_valid(const scmp_filter_ctx *ctx)
{
	return db_col_valid((struct db_filter_col *)ctx);
}

/**
 * Validate a syscall number
 * @param syscall the syscall number
 *
 * Attempt to perform basic syscall number validation.  Returns zero of the
 * syscall appears valid, negative values on failure.
 *
 */
static int _syscall_valid(int syscall)
{
	if (syscall <= -1 && syscall >= -99)
		return -EINVAL;
	return 0;
}

/* NOTE - function header comment in include/seccomp.h */
scmp_filter_ctx seccomp_init(uint32_t def_action)
{
	struct db_filter_col *col;
	struct db_filter *db;

	if (db_action_valid(def_action) < 0)
		return NULL;

	col = db_col_init(def_action);
	if (col == NULL)
		return NULL;
	db = db_init(&arch_def_native);
	if (db == NULL)
		goto init_failure_col;

	if (db_col_db_add(col, db) < 0)
		goto init_failure_db;

	return col;

init_failure_db:
	db_release(db);
init_failure_col:
	db_col_release(col);
	return NULL;
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_reset(scmp_filter_ctx ctx, uint32_t def_action)
{
	int rc;
	struct db_filter_col *col = (struct db_filter_col *)ctx;
	struct db_filter *db;

	if (db_col_valid(col) || db_action_valid(def_action) < 0)
		return -EINVAL;

	db_col_reset(col, def_action);

	db = db_init(&arch_def_native);
	if (db == NULL)
		return -ENOMEM;
	rc = db_col_db_add(col, db);
	if (rc < 0)
		db_release(db);

	return rc;
}

/* NOTE - function header comment in include/seccomp.h */
void seccomp_release(scmp_filter_ctx ctx)
{
	if (_ctx_valid(ctx))
		return;

	db_col_release((struct db_filter_col *)ctx);
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_load(const scmp_filter_ctx ctx)
{
	int rc;
	struct db_filter_col *col;
	struct bpf_program *program;

	if (_ctx_valid(ctx))
		return -EINVAL;
	col = (struct db_filter_col *)ctx;

	program = gen_bpf_generate((struct db_filter_col *)ctx);
	if (program == NULL)
		return -ENOMEM;
	/* attempt to set NO_NEW_PRIVS */
	if (col->attr.nnp_enable) {
		rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		if (rc < 0)
			return -errno;
	}
	/* load the filter into the kernel */
	rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, program);
	gen_bpf_release(program);
	if (rc < 0)
		return -errno;

	return 0;
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_attr_get(const scmp_filter_ctx ctx,
		     enum scmp_filter_attr attr, uint32_t *value)
{
	if (_ctx_valid(ctx))
		return -EINVAL;

	return db_col_attr_get((const struct db_filter_col *)ctx, attr, value);
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_attr_set(scmp_filter_ctx ctx,
		     enum scmp_filter_attr attr, uint32_t value)
{
	if (_ctx_valid(ctx))
		return -EINVAL;

	return db_col_attr_set((struct db_filter_col *)ctx, attr, value);
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_syscall_resolve_name(const char *name)
{
	if (name == NULL)
		return -EINVAL;

	return arch_syscall_resolve_name(&arch_def_native, name);
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_syscall_priority(scmp_filter_ctx ctx, int syscall, uint8_t priority)
{
	int rc = 0, rc_tmp;
	unsigned int iter;
	int syscall_tmp;
	struct db_filter_col *col;
	struct db_filter *filter;

	if (_ctx_valid(ctx) || _syscall_valid(syscall))
		return -EINVAL;
	col = (struct db_filter_col *)ctx;

	for (iter = 0; iter < col->filter_cnt; iter++) {
		filter = col->filters[iter];
		syscall_tmp = syscall;

		rc_tmp = arch_syscall_translate(filter->arch, &syscall_tmp);
		if (rc_tmp < 0)
			goto syscall_priority_failure;

		/* if this is a pseudo syscall (syscall < 0) then we need to
		 * rewrite the syscall for some arch specific reason */
		if (syscall_tmp < 0) {
			rc_tmp = arch_syscall_rewrite(filter->arch,
						      &syscall_tmp);
			if (rc_tmp < 0)
				goto syscall_priority_failure;
		}

		rc_tmp = db_syscall_priority(filter, syscall_tmp, priority);

syscall_priority_failure:
		if (rc == 0 && rc_tmp < 0)
			rc = rc_tmp;
	}

	return rc;
}

/**
 * Add a new rule to the current filter
 * @param col the filter collection
 * @param strict the strict flag
 * @param action the filter action
 * @param syscall the syscall number
 * @param arg_cnt the number of argument filters in the argument filter chain
 * @param arg_list the argument filter chain, (uint, enum scmp_compare, ulong)
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
static int _seccomp_rule_add(struct db_filter_col *col,
			     unsigned int strict, uint32_t action, int syscall,
			     unsigned int arg_cnt, va_list arg_list)
{
	int rc = 0, rc_tmp;
	int syscall_tmp;
	unsigned int iter;
	unsigned int chain_len_max;
	unsigned int arg_num;
	struct db_filter *filter;
	struct db_api_arg *chain = NULL;
	struct scmp_arg_cmp arg_data;

	if (db_col_valid(col) || _syscall_valid(syscall))
		return -EINVAL;

	rc = db_action_valid(action);
	if (rc < 0)
		return rc;
	if (action == col->attr.act_default)
		return -EPERM;

	if (strict && col->filter_cnt > 1)
		return -EOPNOTSUPP;

	/* collect the arguments for the filter rule */
	chain_len_max = ARG_COUNT_MAX;
	chain = malloc(sizeof(*chain) * chain_len_max);
	if (chain == NULL)
		return -ENOMEM;
	memset(chain, 0, sizeof(*chain) * chain_len_max);
	for (iter = 0; iter < arg_cnt; iter++) {
		arg_data = va_arg(arg_list, struct scmp_arg_cmp);
		arg_num = arg_data.arg;
		if (arg_num < chain_len_max && chain[arg_num].valid == 0) {
			chain[arg_num].valid = 1;
			chain[arg_num].arg = arg_num;
			chain[arg_num].op = arg_data.op;
			/* XXX - we should check datum/mask size against the
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
				goto rule_add_return;
			}
		} else {
			rc = -EINVAL;
			goto rule_add_return;
		}
	}

	for (iter = 0; iter < col->filter_cnt; iter++) {
		filter = col->filters[iter];
		syscall_tmp = syscall;

		rc_tmp = arch_syscall_translate(filter->arch, &syscall_tmp);
		if (rc_tmp < 0)
			goto rule_add_failure;

		/* if this is a pseudo syscall (syscall < 0) then we need to
		 * rewrite the rule for some arch specific reason */
		if (syscall_tmp < 0) {
			rc_tmp = arch_filter_rewrite(filter->arch, strict,
						     &syscall_tmp, chain);
			if (rc_tmp < 0)
				goto rule_add_failure;
		}

		/* add the new rule to the existing filter */
		rc_tmp = db_rule_add(filter, action, syscall_tmp, chain);

rule_add_failure:
		if (rc == 0 && rc_tmp < 0)
			rc = rc_tmp;
	}

rule_add_return:
	if (chain != NULL)
		free(chain);
	return rc;
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_rule_add(scmp_filter_ctx ctx,
		     uint32_t action, int syscall, unsigned int arg_cnt, ...)
{
	int rc;
	va_list arg_list;

	va_start(arg_list, arg_cnt);
	rc = _seccomp_rule_add((struct db_filter_col *)ctx,
			       0, action, syscall, arg_cnt, arg_list);
	va_end(arg_list);

	return rc;
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_rule_add_exact(scmp_filter_ctx ctx, uint32_t action,
			   int syscall, unsigned int arg_cnt, ...)
{
	int rc;
	va_list arg_list;

	va_start(arg_list, arg_cnt);
	rc = _seccomp_rule_add((struct db_filter_col *)ctx,
			       1, action, syscall, arg_cnt, arg_list);
	va_end(arg_list);

	return rc;
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_export_pfc(const scmp_filter_ctx ctx, int fd)
{
	if (_ctx_valid(ctx))
		return -EINVAL;

	return gen_pfc_generate((struct db_filter_col *)ctx, fd);
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_export_bpf(const scmp_filter_ctx ctx, int fd)
{
	int rc;
	struct bpf_program *program;

	if (_ctx_valid(ctx))
		return -EINVAL;

	program = gen_bpf_generate((struct db_filter_col *)ctx);
	if (program == NULL)
		return -ENOMEM;
	rc = write(fd, program->blks, BPF_PGM_SIZE(program));
	gen_bpf_release(program);
	if (rc < 0)
		return -errno;

	return 0;
}
