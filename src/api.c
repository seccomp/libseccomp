/**
 * Seccomp Library API
 *
 * Copyright (c) 2012,2013 Red Hat <pmoore@redhat.com>
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

#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <seccomp.h>

#include "arch.h"
#include "db.h"
#include "gen_pfc.h"
#include "gen_bpf.h"
#include "system.h"

#define API	__attribute__((visibility("default")))

const struct scmp_version library_version = {
	.major = SCMP_VER_MAJOR,
	.minor = SCMP_VER_MINOR,
	.micro = SCMP_VER_MICRO,
};

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
API const struct scmp_version *seccomp_version(void)
{
	return &library_version;
}

/* NOTE - function header comment in include/seccomp.h */
API scmp_filter_ctx seccomp_init(uint32_t def_action)
{
	if (db_action_valid(def_action) < 0)
		return NULL;

	return db_col_init(def_action);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_reset(scmp_filter_ctx ctx, uint32_t def_action)
{
	struct db_filter_col *col = (struct db_filter_col *)ctx;

	if (ctx == NULL || db_action_valid(def_action) < 0)
		return -EINVAL;

	return db_col_reset(col, def_action);
}

/* NOTE - function header comment in include/seccomp.h */
API void seccomp_release(scmp_filter_ctx ctx)
{
	db_col_release((struct db_filter_col *)ctx);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_merge(scmp_filter_ctx ctx_dst,
		      scmp_filter_ctx ctx_src)
{
	struct db_filter_col *col_dst = (struct db_filter_col *)ctx_dst;
	struct db_filter_col *col_src = (struct db_filter_col *)ctx_src;

	if (db_col_valid(col_dst) || db_col_valid(col_src))
		return -EINVAL;

	/* NOTE: only the default action, NNP, and TSYNC settings must match */
	if ((col_dst->attr.act_default != col_src->attr.act_default) ||
	    (col_dst->attr.nnp_enable != col_src->attr.nnp_enable) ||
	    (col_dst->attr.tsync_enable != col_src->attr.tsync_enable))
		return -EINVAL;

	return db_col_merge(col_dst, col_src);
}

/* NOTE - function header comment in include/seccomp.h */
API uint32_t seccomp_arch_resolve_name(const char *arch_name)
{
	const struct arch_def *arch;

	if (arch_name == NULL)
		return 0;

	arch = arch_def_lookup_name(arch_name);
	if (arch == NULL)
		return 0;

	return arch->token;
}

/* NOTE - function header comment in include/seccomp.h */
API uint32_t seccomp_arch_native(void)
{
	return arch_def_native->token;
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_arch_exist(const scmp_filter_ctx ctx,
			   uint32_t arch_token)
{
	struct db_filter_col *col = (struct db_filter_col *)ctx;

	if (arch_token == 0)
		arch_token = arch_def_native->token;

	if (arch_valid(arch_token))
		return -EINVAL;

	return (db_col_arch_exist(col, arch_token) ? 0 : -EEXIST);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_arch_add(scmp_filter_ctx ctx, uint32_t arch_token)
{
	const struct arch_def *arch;
	struct db_filter_col *col = (struct db_filter_col *)ctx;

	if (arch_token == 0)
		arch_token = arch_def_native->token;

	if (arch_valid(arch_token))
		return -EINVAL;
	if (db_col_arch_exist(col, arch_token))
		return -EEXIST;

	arch = arch_def_lookup(arch_token);
	if (arch == NULL)
		return -EFAULT;
	return db_col_db_new(col, arch);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_arch_remove(scmp_filter_ctx ctx, uint32_t arch_token)
{
	struct db_filter_col *col = (struct db_filter_col *)ctx;

	if (arch_token == 0)
		arch_token = arch_def_native->token;

	if (arch_valid(arch_token))
		return -EINVAL;
	if (db_col_arch_exist(col, arch_token) != -EEXIST)
		return -EEXIST;

	return db_col_db_remove(col, arch_token);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_load(const scmp_filter_ctx ctx)
{
	struct db_filter_col *col;

	if (_ctx_valid(ctx))
		return -EINVAL;
	col = (struct db_filter_col *)ctx;

	return sys_filter_load(col);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_attr_get(const scmp_filter_ctx ctx,
			 enum scmp_filter_attr attr, uint32_t *value)
{
	if (_ctx_valid(ctx))
		return -EINVAL;

	return db_col_attr_get((const struct db_filter_col *)ctx, attr, value);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_attr_set(scmp_filter_ctx ctx,
			 enum scmp_filter_attr attr, uint32_t value)
{
	if (_ctx_valid(ctx))
		return -EINVAL;

	return db_col_attr_set((struct db_filter_col *)ctx, attr, value);
}

/* NOTE - function header comment in include/seccomp.h */
API char *seccomp_syscall_resolve_num_arch(uint32_t arch_token, int num)
{
	const struct arch_def *arch;
	const char *name;

	if (arch_token == 0)
		arch_token = arch_def_native->token;
	if (arch_valid(arch_token))
		return NULL;
	arch = arch_def_lookup(arch_token);
	if (arch == NULL)
		return NULL;

	name = arch_syscall_resolve_num(arch, num);
	if (name == NULL)
		return NULL;

	return strdup(name);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_syscall_resolve_name_arch(uint32_t arch_token, const char *name)
{
	const struct arch_def *arch;

	if (name == NULL)
		return __NR_SCMP_ERROR;

	if (arch_token == 0)
		arch_token = arch_def_native->token;
	if (arch_valid(arch_token))
		return __NR_SCMP_ERROR;
	arch = arch_def_lookup(arch_token);
	if (arch == NULL)
		return __NR_SCMP_ERROR;

	return arch_syscall_resolve_name(arch, name);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_syscall_resolve_name_rewrite(uint32_t arch_token,
					     const char *name)
{
	int rc;
	int syscall;
	const struct arch_def *arch;

	if (name == NULL)
		return __NR_SCMP_ERROR;

	if (arch_token == 0)
		arch_token = arch_def_native->token;
	if (arch_valid(arch_token))
		return __NR_SCMP_ERROR;
	arch = arch_def_lookup(arch_token);
	if (arch == NULL)
		return __NR_SCMP_ERROR;

	syscall = arch_syscall_resolve_name(arch, name);
	if (syscall == __NR_SCMP_ERROR)
		return __NR_SCMP_ERROR;
	rc = arch_syscall_rewrite(arch, &syscall);
	if (rc == -EDOM)
		/* if we can't rewrite the syscall, just pass it through */
		return syscall;
	else if (rc < 0)
		return __NR_SCMP_ERROR;

	return syscall;
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_syscall_resolve_name(const char *name)
{
	return seccomp_syscall_resolve_name_arch(SCMP_ARCH_NATIVE, name);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_syscall_priority(scmp_filter_ctx ctx,
				 int syscall, uint8_t priority)
{
	struct db_filter_col *col = (struct db_filter_col *)ctx;

	if (db_col_valid(col) || _syscall_valid(syscall))
		return -EINVAL;

	return db_col_syscall_priority(col, syscall, priority);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_rule_add_array(scmp_filter_ctx ctx,
			       uint32_t action, int syscall,
			       unsigned int arg_cnt,
			       const struct scmp_arg_cmp *arg_array)
{
	int rc;
	struct db_filter_col *col = (struct db_filter_col *)ctx;

	if (arg_cnt > ARG_COUNT_MAX)
		return -EINVAL;
	if (arg_cnt > 0 && arg_array == NULL)
		return -EINVAL;

	if (db_col_valid(col) || _syscall_valid(syscall))
		return -EINVAL;

	rc = db_action_valid(action);
	if (rc < 0)
		return rc;
	if (action == col->attr.act_default)
		return -EPERM;

	return db_col_rule_add(col, 0, action, syscall, arg_cnt, arg_array);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_rule_add(scmp_filter_ctx ctx,
			 uint32_t action, int syscall,
			 unsigned int arg_cnt, ...)
{
	int rc;
	int iter;
	struct scmp_arg_cmp arg_array[ARG_COUNT_MAX];
	va_list arg_list;

	/* arg_cnt is unsigned, so no need to check the lower bound */
	if (arg_cnt > ARG_COUNT_MAX)
		return -EINVAL;

	va_start(arg_list, arg_cnt);
	for (iter = 0; iter < arg_cnt; ++iter)
		arg_array[iter] = va_arg(arg_list, struct scmp_arg_cmp);
	rc = seccomp_rule_add_array(ctx, action, syscall, arg_cnt, arg_array);
	va_end(arg_list);

	return rc;
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_rule_add_exact_array(scmp_filter_ctx ctx,
				     uint32_t action, int syscall,
				     unsigned int arg_cnt,
				     const struct scmp_arg_cmp *arg_array)
{
	int rc;
	struct db_filter_col *col = (struct db_filter_col *)ctx;

	if (arg_cnt > ARG_COUNT_MAX)
		return -EINVAL;
	if (arg_cnt > 0 && arg_array == NULL)
		return -EINVAL;

	if (db_col_valid(col) || _syscall_valid(syscall))
		return -EINVAL;

	rc = db_action_valid(action);
	if (rc < 0)
		return rc;
	if (action == col->attr.act_default)
		return -EPERM;

	if (col->filter_cnt > 1)
		return -EOPNOTSUPP;

	return db_col_rule_add(col, 1, action, syscall, arg_cnt, arg_array);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_rule_add_exact(scmp_filter_ctx ctx,
			       uint32_t action, int syscall,
			       unsigned int arg_cnt, ...)
{
	int rc;
	int iter;
	struct scmp_arg_cmp arg_array[ARG_COUNT_MAX];
	va_list arg_list;

	/* arg_cnt is unsigned, so no need to check the lower bound */
	if (arg_cnt > ARG_COUNT_MAX)
		return -EINVAL;

	va_start(arg_list, arg_cnt);
	for (iter = 0; iter < arg_cnt; ++iter)
		arg_array[iter] = va_arg(arg_list, struct scmp_arg_cmp);
	rc = seccomp_rule_add_exact_array(ctx,
					  action, syscall, arg_cnt, arg_array);
	va_end(arg_list);

	return rc;
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_export_pfc(const scmp_filter_ctx ctx, int fd)
{
	if (_ctx_valid(ctx))
		return -EINVAL;

	return gen_pfc_generate((struct db_filter_col *)ctx, fd);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_export_bpf(const scmp_filter_ctx ctx, int fd)
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
