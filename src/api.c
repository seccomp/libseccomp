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
#include <sys/ioctl.h>

#include <seccomp.h>

#include "arch.h"
#include "db.h"
#include "gen_pfc.h"
#include "gen_bpf.h"
#include "helper.h"
#include "system.h"

#define API	__attribute__((visibility("default")))

const struct scmp_version library_version = {
	.major = SCMP_VER_MAJOR,
	.minor = SCMP_VER_MINOR,
	.micro = SCMP_VER_MICRO,
};

unsigned int seccomp_api_level = 0;

/**
 * Filter the error codes we send back to callers
 * @param err the error code
 *
 * We consider error codes part of our API so we want to make sure we don't
 * accidentally send an undocumented error code to our callers.  This function
 * helps with that.
 *
 */
static int _rc_filter(int err)
{
	/* pass through success values */
	if (err >= 0)
		return err;

	/* filter the error codes */
	switch (err) {
	case -EACCES:
	/* NOTE: operation is not permitted by libseccomp */
	case -ECANCELED:
	/* NOTE: kernel level error that is beyond the control of
	 *       libseccomp */
	case -EDOM:
	/* NOTE: failure due to arch/ABI */
	case -EEXIST:
	/* NOTE: operation failed due to existing rule or filter */
	case -EINVAL:
	/* NOTE: invalid input to the libseccomp API */
	case -ENOENT:
	/* NOTE: no matching entry found */
	case -ENOMEM:
	/* NOTE: unable to allocate enough memory to perform the
	 *       requested operation */
	case -EOPNOTSUPP:
	/* NOTE: operation is not supported */
	case -ESRCH:
		/* NOTE: operation failed due to multi-threading */
		return err;
	default:
		/* NOTE: this is the default "internal libseccomp error"
		 *       error code, it is our catch-all */
		return -EFAULT;
	}
}

/**
 * Filter the system error codes we send back to callers
 * @param col the filter collection
 * @param err the error code
 *
 * This is similar to _rc_filter(), but it first checks the filter attribute
 * to determine if we should be filtering the return codes.
 *
 */
static int _rc_filter_sys(struct db_filter_col *col, int err)
{
	/* pass through success values */
	if (err >= 0)
		return err;

	/* pass the return code if the SCMP_FLTATR_API_SYSRAWRC is true */
	if (db_col_attr_read(col, SCMP_FLTATR_API_SYSRAWRC))
		return err;
	return -ECANCELED;
}

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
static int _syscall_valid(const struct db_filter_col *col, int syscall)
{
	/* syscall -1 is used by tracers to skip the syscall */
	if (col->attr.api_tskip && syscall == -1)
		return 0;
	if (syscall <= -1 && syscall >= -99)
		return -EINVAL;
	return 0;
}

/**
 * Update the API level
 *
 * This function performs a series of tests to determine what functionality is
 * supported given the current running environment (kernel, etc.).  It is
 * important to note that this function only does meaningful checks the first
 * time it is run, the resulting API level is cached after this first run and
 * used for all subsequent calls.  The API level value is returned.
 *
 */
static unsigned int _seccomp_api_update(void)
{
	unsigned int level = 1;

	/* if seccomp_api_level > 0 then it's already been set, we're done */
	if (seccomp_api_level >= 1)
		return seccomp_api_level;

	/* NOTE: level 1 is the base level, start checking at 2 */

	if (sys_chk_seccomp_syscall() &&
	    sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC) == 1)
		level = 2;

	if (level == 2 &&
	    sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_LOG) == 1 &&
	    sys_chk_seccomp_action(SCMP_ACT_LOG) == 1 &&
	    sys_chk_seccomp_action(SCMP_ACT_KILL_PROCESS) == 1)
		level = 3;

	if (level == 3 &&
	    sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_SPEC_ALLOW) == 1)
		level = 4;

	if (level == 4 &&
	    sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_NEW_LISTENER) == 1 &&
	    sys_chk_seccomp_action(SCMP_ACT_NOTIFY) == 1)
		level = 5;

	if (level == 5 &&
	    sys_chk_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC_ESRCH) == 1)
		level = 6;

	/* update the stored api level and return */
	seccomp_api_level = level;
	return seccomp_api_level;
}

/* NOTE - function header comment in include/seccomp.h */
API const struct scmp_version *seccomp_version(void)
{
	return &library_version;
}

/* NOTE - function header comment in include/seccomp.h */
API unsigned int seccomp_api_get(void)
{
	/* update the api level, if needed */
	return _seccomp_api_update();
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_api_set(unsigned int level)
{
	switch (level) {
	case 1:
		sys_set_seccomp_syscall(false);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC, false);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_LOG, false);
		sys_set_seccomp_action(SCMP_ACT_LOG, false);
		sys_set_seccomp_action(SCMP_ACT_KILL_PROCESS, false);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_SPEC_ALLOW, false);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_NEW_LISTENER, false);
		sys_set_seccomp_action(SCMP_ACT_NOTIFY, false);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC_ESRCH, false);
		break;
	case 2:
		sys_set_seccomp_syscall(true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_LOG, false);
		sys_set_seccomp_action(SCMP_ACT_LOG, false);
		sys_set_seccomp_action(SCMP_ACT_KILL_PROCESS, false);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_SPEC_ALLOW, false);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_NEW_LISTENER, false);
		sys_set_seccomp_action(SCMP_ACT_NOTIFY, false);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC_ESRCH, false);
		break;
	case 3:
		sys_set_seccomp_syscall(true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_LOG, true);
		sys_set_seccomp_action(SCMP_ACT_LOG, true);
		sys_set_seccomp_action(SCMP_ACT_KILL_PROCESS, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_SPEC_ALLOW, false);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_NEW_LISTENER, false);
		sys_set_seccomp_action(SCMP_ACT_NOTIFY, false);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC_ESRCH, false);
		break;
	case 4:
		sys_set_seccomp_syscall(true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_LOG, true);
		sys_set_seccomp_action(SCMP_ACT_LOG, true);
		sys_set_seccomp_action(SCMP_ACT_KILL_PROCESS, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_SPEC_ALLOW, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_NEW_LISTENER, false);
		sys_set_seccomp_action(SCMP_ACT_NOTIFY, false);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC_ESRCH, false);
		break;
	case 5:
		sys_set_seccomp_syscall(true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_LOG, true);
		sys_set_seccomp_action(SCMP_ACT_LOG, true);
		sys_set_seccomp_action(SCMP_ACT_KILL_PROCESS, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_SPEC_ALLOW, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_NEW_LISTENER, true);
		sys_set_seccomp_action(SCMP_ACT_NOTIFY, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC_ESRCH, false);
		break;
	case 6:
		sys_set_seccomp_syscall(true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_LOG, true);
		sys_set_seccomp_action(SCMP_ACT_LOG, true);
		sys_set_seccomp_action(SCMP_ACT_KILL_PROCESS, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_SPEC_ALLOW, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_NEW_LISTENER, true);
		sys_set_seccomp_action(SCMP_ACT_NOTIFY, true);
		sys_set_seccomp_flag(SECCOMP_FILTER_FLAG_TSYNC_ESRCH, true);
		break;
	default:
		return _rc_filter(-EINVAL);
	}

	seccomp_api_level = level;
	return _rc_filter(0);
}

/* NOTE - function header comment in include/seccomp.h */
API scmp_filter_ctx seccomp_init(uint32_t def_action)
{
	/* force a runtime api level detection */
	_seccomp_api_update();

	if (db_col_action_valid(NULL, def_action) < 0)
		return NULL;

	return db_col_init(def_action);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_reset(scmp_filter_ctx ctx, uint32_t def_action)
{
	struct db_filter_col *col = (struct db_filter_col *)ctx;

	/* a NULL filter context indicates we are resetting the global state */
	if (ctx == NULL) {
		/* reset the global state and redetermine the api level */
		sys_reset_state();
		_seccomp_api_update();
		return _rc_filter(0);
	}
	/* ensure the default action is valid */
	if (db_col_action_valid(NULL, def_action) < 0)
		return _rc_filter(-EINVAL);

	/* reset the filter */
	return _rc_filter(db_col_reset(col, def_action));
}

/* NOTE - function header comment in include/seccomp.h */
API void seccomp_release(scmp_filter_ctx ctx)
{
	db_col_release((struct db_filter_col *)ctx);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_merge(scmp_filter_ctx ctx_dst, scmp_filter_ctx ctx_src)
{
	struct db_filter_col *col_dst = (struct db_filter_col *)ctx_dst;
	struct db_filter_col *col_src = (struct db_filter_col *)ctx_src;

	if (db_col_valid(col_dst) || db_col_valid(col_src))
		return _rc_filter(-EINVAL);

	/* NOTE: only the default action, NNP, and TSYNC settings must match */
	if ((col_dst->attr.act_default != col_src->attr.act_default) ||
	    (col_dst->attr.nnp_enable != col_src->attr.nnp_enable) ||
	    (col_dst->attr.tsync_enable != col_src->attr.tsync_enable))
		return _rc_filter(-EINVAL);

	return _rc_filter(db_col_merge(col_dst, col_src));
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
API int seccomp_arch_exist(const scmp_filter_ctx ctx, uint32_t arch_token)
{
	struct db_filter_col *col = (struct db_filter_col *)ctx;

	if (arch_token == 0)
		arch_token = arch_def_native->token;

	if (arch_valid(arch_token))
		return _rc_filter(-EINVAL);

	return _rc_filter((db_col_arch_exist(col, arch_token) ? 0 : -EEXIST));
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_arch_add(scmp_filter_ctx ctx, uint32_t arch_token)
{
	const struct arch_def *arch;
	struct db_filter_col *col = (struct db_filter_col *)ctx;

	if (arch_token == 0)
		arch_token = arch_def_native->token;

	arch = arch_def_lookup(arch_token);
	if (arch == NULL)
		return _rc_filter(-EINVAL);
	if (db_col_arch_exist(col, arch_token))
		return _rc_filter(-EEXIST);

	return _rc_filter(db_col_db_new(col, arch));
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_arch_remove(scmp_filter_ctx ctx, uint32_t arch_token)
{
	struct db_filter_col *col = (struct db_filter_col *)ctx;

	if (arch_token == 0)
		arch_token = arch_def_native->token;

	if (arch_valid(arch_token))
		return _rc_filter(-EINVAL);
	if (db_col_arch_exist(col, arch_token) != -EEXIST)
		return _rc_filter(-EEXIST);

	return _rc_filter(db_col_db_remove(col, arch_token));
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_load(const scmp_filter_ctx ctx)
{
	struct db_filter_col *col;
	bool rawrc;

	if (_ctx_valid(ctx))
		return _rc_filter(-EINVAL);
	col = (struct db_filter_col *)ctx;

	rawrc = db_col_attr_read(col, SCMP_FLTATR_API_SYSRAWRC);
	return _rc_filter(sys_filter_load(col, rawrc));
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_attr_get(const scmp_filter_ctx ctx,
			 enum scmp_filter_attr attr, uint32_t *value)
{
	if (_ctx_valid(ctx))
		return _rc_filter(-EINVAL);

	return _rc_filter(db_col_attr_get((const struct db_filter_col *)ctx,
					  attr, value));
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_attr_set(scmp_filter_ctx ctx,
			 enum scmp_filter_attr attr, uint32_t value)
{
	if (_ctx_valid(ctx))
		return _rc_filter(-EINVAL);

	return _rc_filter(db_col_attr_set((struct db_filter_col *)ctx,
					  attr, value));
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

	if (db_col_valid(col) || _syscall_valid(col, syscall))
		return _rc_filter(-EINVAL);

	return _rc_filter(db_col_syscall_priority(col, syscall, priority));
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
		return _rc_filter(-EINVAL);
	if (arg_cnt > 0 && arg_array == NULL)
		return _rc_filter(-EINVAL);

	if (db_col_valid(col) || _syscall_valid(col, syscall))
		return _rc_filter(-EINVAL);

	rc = db_col_action_valid(col, action);
	if (rc < 0)
		return _rc_filter(rc);
	if (action == col->attr.act_default)
		return _rc_filter(-EACCES);

	return _rc_filter(db_col_rule_add(col, 0, action,
					  syscall, arg_cnt, arg_array));
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
		return _rc_filter(-EINVAL);

	va_start(arg_list, arg_cnt);
	for (iter = 0; iter < arg_cnt; ++iter)
		arg_array[iter] = va_arg(arg_list, struct scmp_arg_cmp);
	rc = seccomp_rule_add_array(ctx, action, syscall, arg_cnt, arg_array);
	va_end(arg_list);

	return _rc_filter(rc);
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
		return _rc_filter(-EINVAL);
	if (arg_cnt > 0 && arg_array == NULL)
		return _rc_filter(-EINVAL);

	if (db_col_valid(col) || _syscall_valid(col, syscall))
		return _rc_filter(-EINVAL);

	rc = db_col_action_valid(col, action);
	if (rc < 0)
		return _rc_filter(rc);
	if (action == col->attr.act_default)
		return _rc_filter(-EACCES);

	if (col->filter_cnt > 1)
		return _rc_filter(-EOPNOTSUPP);

	return _rc_filter(db_col_rule_add(col, 1, action,
					  syscall, arg_cnt, arg_array));
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
		return _rc_filter(-EINVAL);

	va_start(arg_list, arg_cnt);
	for (iter = 0; iter < arg_cnt; ++iter)
		arg_array[iter] = va_arg(arg_list, struct scmp_arg_cmp);
	rc = seccomp_rule_add_exact_array(ctx,
					  action, syscall, arg_cnt, arg_array);
	va_end(arg_list);

	return _rc_filter(rc);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_notify_alloc(struct seccomp_notif **req,
			     struct seccomp_notif_resp **resp)
{
	/* force a runtime api level detection */
	_seccomp_api_update();

	return _rc_filter(sys_notify_alloc(req, resp));
}

/* NOTE - function header comment in include/seccomp.h */
API void seccomp_notify_free(struct seccomp_notif *req,
			     struct seccomp_notif_resp *resp)
{
	if (req)
		free(req);
	if (resp)
		free(resp);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_notify_receive(int fd, struct seccomp_notif *req)
{
	return _rc_filter(sys_notify_receive(fd, req));
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_notify_respond(int fd, struct seccomp_notif_resp *resp)
{
	return _rc_filter(sys_notify_respond(fd, resp));
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_notify_id_valid(int fd, uint64_t id)
{
	/* force a runtime api level detection */
	_seccomp_api_update();

	return _rc_filter(sys_notify_id_valid(fd, id));
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_notify_fd(const scmp_filter_ctx ctx)
{
	/* NOTE: for historical reasons, and possibly future use, we require a
	 * valid filter context even though we don't actual use it here; the
	 * api update is also not strictly necessary, but keep it for now */

	/* force a runtime api level detection */
	_seccomp_api_update();

	if (_ctx_valid(ctx))
		return _rc_filter(-EINVAL);

	return _rc_filter(sys_notify_fd());
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_export_pfc(const scmp_filter_ctx ctx, int fd)
{
	int rc;
	struct db_filter_col *col;

	if (_ctx_valid(ctx))
		return _rc_filter(-EINVAL);
	col = (struct db_filter_col *)ctx;

	rc = gen_pfc_generate(col, fd);
	return _rc_filter_sys(col, rc);
}

/* NOTE - function header comment in include/seccomp.h */
API int seccomp_export_bpf(const scmp_filter_ctx ctx, int fd)
{
	int rc;
	struct db_filter_col *col;
	struct bpf_program *program;

	if (_ctx_valid(ctx))
		return _rc_filter(-EINVAL);
	col = (struct db_filter_col *)ctx;

	rc = gen_bpf_generate(col, &program);
	if (rc < 0)
		return _rc_filter(rc);
	rc = write(fd, program->blks, BPF_PGM_SIZE(program));
	gen_bpf_release(program);
	if (rc < 0)
		return _rc_filter_sys(col, -errno);

	return 0;
}
