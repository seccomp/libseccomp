/**
 * Seccomp System Interfaces
 *
 * Copyright (c) 2014 Red Hat <pmoore@redhat.com>
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

#include <stdlib.h>
#include <errno.h>
#include <sys/prctl.h>

#define _GNU_SOURCE
#include <unistd.h>

#include "system.h"

#include <seccomp.h>

#include "arch.h"
#include "db.h"
#include "gen_bpf.h"
#include "helper.h"

/* NOTE: the seccomp syscall allowlist is currently disabled for testing
 *       purposes, but unless we can verify all of the supported ABIs before
 *       our next release we may have to enable the allowlist */
#define SYSCALL_ALLOWLIST_ENABLE	0

static int _nr_seccomp = -1;
static int _support_seccomp_syscall = -1;
static int _support_seccomp_flag_tsync = -1;
static int _support_seccomp_flag_log = -1;
static int _support_seccomp_action_log = -1;
static int _support_seccomp_kill_process = -1;
static int _support_seccomp_flag_spec_allow = -1;
static int _support_seccomp_flag_new_listener = -1;
static int _support_seccomp_user_notif = -1;

/**
 * Check to see if the seccomp() syscall is supported
 *
 * This function attempts to see if the system supports the seccomp() syscall.
 * Unfortunately, there are a few reasons why this check may fail, including
 * a previously loaded seccomp filter, so it is hard to say for certain.
 * Return one if the syscall is supported, zero otherwise.
 *
 */
int sys_chk_seccomp_syscall(void)
{
	int rc;
	int nr_seccomp;

	/* NOTE: it is reasonably safe to assume that we should be able to call
	 *       seccomp() when the caller first starts, but we can't rely on
	 *       it later so we need to cache our findings for use later */
	if (_support_seccomp_syscall >= 0)
		return _support_seccomp_syscall;

#if SYSCALL_ALLOWLIST_ENABLE
	/* architecture allowlist */
	switch (arch_def_native->token) {
	case SCMP_ARCH_X86_64:
	case SCMP_ARCH_ARM:
	case SCMP_ARCH_AARCH64:
	case SCMP_ARCH_PPC64:
	case SCMP_ARCH_PPC64LE:
	case SCMP_ARCH_S390:
	case SCMP_ARCH_S390X:
	case SCMP_ARCH_RISCV64:
		break;
	default:
		goto unsupported;
	}
#endif

	nr_seccomp = arch_syscall_resolve_name(arch_def_native, "seccomp");
	if (nr_seccomp < 0)
		goto unsupported;

	/* this is an invalid call because the second argument is non-zero, but
	 * depending on the errno value of ENOSYS or EINVAL we can guess if the
	 * seccomp() syscal is supported or not */
	rc = syscall(nr_seccomp, SECCOMP_SET_MODE_STRICT, 1, NULL);
	if (rc < 0 && errno == EINVAL)
		goto supported;

unsupported:
	_support_seccomp_syscall = 0;
	return 0;
supported:
	_nr_seccomp = nr_seccomp;
	_support_seccomp_syscall = 1;
	return 1;
}

/**
 * Force the seccomp() syscall support setting
 * @param enable the intended support state
 *
 * This function overrides the current seccomp() syscall support setting; this
 * is very much a "use at your own risk" function.
 *
 */
void sys_set_seccomp_syscall(bool enable)
{
	_support_seccomp_syscall = (enable ? 1 : 0);
}

/**
 * Check to see if a seccomp action is supported
 * @param action the seccomp action
 *
 * This function checks to see if a seccomp action is supported by the system.
 * Return one if the action is supported, zero otherwise.
 *
 */
int sys_chk_seccomp_action(uint32_t action)
{
	if (action == SCMP_ACT_KILL_PROCESS) {
		if (_support_seccomp_kill_process < 0) {
			if (sys_chk_seccomp_syscall() == 1 &&
			    syscall(_nr_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
				    &action) == 0)
				_support_seccomp_kill_process = 1;
			else
				_support_seccomp_kill_process = 0;
		}

		return _support_seccomp_kill_process;
	} else if (action == SCMP_ACT_KILL_THREAD) {
		return 1;
	} else if (action == SCMP_ACT_TRAP) {
		return 1;
	} else if ((action == SCMP_ACT_ERRNO(action & 0x0000ffff)) &&
		   ((action & 0x0000ffff) < MAX_ERRNO)) {
		return 1;
	} else if (action == SCMP_ACT_TRACE(action & 0x0000ffff)) {
		return 1;
	} else if (action == SCMP_ACT_LOG) {
		if (_support_seccomp_action_log < 0) {
			if (sys_chk_seccomp_syscall() == 1 &&
			    syscall(_nr_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
				    &action) == 0)
				_support_seccomp_action_log = 1;
			else
				_support_seccomp_action_log = 0;
		}

		return _support_seccomp_action_log;
	} else if (action == SCMP_ACT_ALLOW) {
		return 1;
	} else if (action == SCMP_ACT_NOTIFY) {
		if (_support_seccomp_user_notif < 0) {
			struct seccomp_notif_sizes sizes;
			if (sys_chk_seccomp_syscall() == 1 &&
			    syscall(_nr_seccomp, SECCOMP_GET_NOTIF_SIZES, 0,
				    &sizes) == 0)
				_support_seccomp_user_notif = 1;
			else
				_support_seccomp_user_notif = 0;
		}

		return _support_seccomp_user_notif;
	}

	return 0;
}

/**
 * Force a seccomp action support setting
 * @param action the seccomp action
 * @param enable the intended support state
 *
 * This function overrides the current seccomp action support setting; this
 * is very much a "use at your own risk" function.
 */
void sys_set_seccomp_action(uint32_t action, bool enable)
{
	switch (action) {
	case SCMP_ACT_LOG:
		_support_seccomp_action_log = (enable ? 1 : 0);
		break;
	case SCMP_ACT_KILL_PROCESS:
		_support_seccomp_kill_process = (enable ? 1 : 0);
		break;
	case SCMP_ACT_NOTIFY:
		_support_seccomp_user_notif = (enable ? 1 : 0);
		break;
	}
}

/**
 * Check to see if a seccomp() flag is supported by the kernel
 * @param flag the seccomp() flag
 *
 * This function checks to see if a seccomp() flag is supported by the kernel.
 * Return one if the flag is supported, zero otherwise.
 *
 */
static int _sys_chk_seccomp_flag_kernel(int flag)
{
	/* this is an invalid seccomp(2) call because the last argument
	 * is NULL, but depending on the errno value of EFAULT we can
	 * guess if the filter flag is supported or not */
	if (sys_chk_seccomp_syscall() == 1 &&
	    syscall(_nr_seccomp, SECCOMP_SET_MODE_FILTER, flag, NULL) == -1 &&
	    errno == EFAULT)
		return 1;

	return 0;
}

/**
 * Check to see if a seccomp() flag is supported
 * @param flag the seccomp() flag
 *
 * This function checks to see if a seccomp() flag is supported by the system.
 * Return one if the syscall is supported, zero if unsupported, negative values
 * on error.
 *
 */
int sys_chk_seccomp_flag(int flag)
{
	switch (flag) {
	case SECCOMP_FILTER_FLAG_TSYNC:
		if (_support_seccomp_flag_tsync < 0)
			_support_seccomp_flag_tsync = _sys_chk_seccomp_flag_kernel(flag);

		return _support_seccomp_flag_tsync;
	case SECCOMP_FILTER_FLAG_LOG:
		if (_support_seccomp_flag_log < 0)
			_support_seccomp_flag_log = _sys_chk_seccomp_flag_kernel(flag);

		return _support_seccomp_flag_log;
	case SECCOMP_FILTER_FLAG_SPEC_ALLOW:
		if (_support_seccomp_flag_spec_allow < 0)
			_support_seccomp_flag_spec_allow = _sys_chk_seccomp_flag_kernel(flag);

		return _support_seccomp_flag_spec_allow;
	case SECCOMP_FILTER_FLAG_NEW_LISTENER:
		if (_support_seccomp_flag_new_listener < 0)
			_support_seccomp_flag_new_listener = _sys_chk_seccomp_flag_kernel(flag);

		return _support_seccomp_flag_new_listener;
	}

	return -EOPNOTSUPP;
}

/**
 * Force a seccomp() syscall flag support setting
 * @param flag the seccomp() flag
 * @param enable the intended support state
 *
 * This function overrides the current seccomp() syscall support setting for a
 * given flag; this is very much a "use at your own risk" function.
 *
 */
void sys_set_seccomp_flag(int flag, bool enable)
{
	switch (flag) {
	case SECCOMP_FILTER_FLAG_TSYNC:
		_support_seccomp_flag_tsync = (enable ? 1 : 0);
		break;
	case SECCOMP_FILTER_FLAG_LOG:
		_support_seccomp_flag_log = (enable ? 1 : 0);
		break;
	case SECCOMP_FILTER_FLAG_SPEC_ALLOW:
		_support_seccomp_flag_spec_allow = (enable ? 1 : 0);
		break;
	case SECCOMP_FILTER_FLAG_NEW_LISTENER:
		_support_seccomp_flag_new_listener = (enable ? 1 : 0);
		break;
	}
}

/**
 * Loads the filter into the kernel
 * @param col the filter collection
 *
 * This function loads the given seccomp filter context into the kernel.  If
 * the filter was loaded correctly, the kernel will be enforcing the filter
 * when this function returns.  Returns zero on success, negative values on
 * error.
 *
 */
int sys_filter_load(struct db_filter_col *col)
{
	int rc;
	struct bpf_program *prgm = NULL;

	rc = gen_bpf_generate(col, &prgm);
	if (rc < 0)
		return rc;

	/* attempt to set NO_NEW_PRIVS */
	if (col->attr.nnp_enable) {
		rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		if (rc < 0)
			goto filter_load_out;
	}

	/* load the filter into the kernel */
	if (sys_chk_seccomp_syscall() == 1) {
		int flgs = 0;
		if (col->attr.tsync_enable)
			flgs |= SECCOMP_FILTER_FLAG_TSYNC;
		else if (_support_seccomp_user_notif > 0)
			flgs |= SECCOMP_FILTER_FLAG_NEW_LISTENER;
		if (col->attr.log_enable)
			flgs |= SECCOMP_FILTER_FLAG_LOG;
		if (col->attr.spec_allow)
			flgs |= SECCOMP_FILTER_FLAG_SPEC_ALLOW;
		rc = syscall(_nr_seccomp, SECCOMP_SET_MODE_FILTER, flgs, prgm);
		if (rc > 0 && col->attr.tsync_enable)
			/* always return -ESRCH if we fail to sync threads */
			rc = -ESRCH;
		if (rc > 0 && _support_seccomp_user_notif > 0) {
			/* return 0 on NEW_LISTENER success, but save the fd */
			col->notify_fd = rc;
			rc = 0;
		}
	} else
		rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prgm);

filter_load_out:
	/* cleanup and return */
	gen_bpf_release(prgm);
	if (rc == -ESRCH)
		return -ESRCH;
	if (rc < 0)
		return -ECANCELED;
	return rc;
}

int sys_notify_alloc(struct seccomp_notif **req,
		     struct seccomp_notif_resp **resp)
{
	int rc;
	static struct seccomp_notif_sizes sizes = { 0, 0, 0 };

	if (_support_seccomp_syscall <= 0)
		return -EOPNOTSUPP;

	if (sizes.seccomp_notif == 0 && sizes.seccomp_notif_resp == 0) {
		rc = syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes);
		if (rc < 0)
			return -ECANCELED;
	}
	if (sizes.seccomp_notif == 0 || sizes.seccomp_notif_resp == 0)
		return -EFAULT;

	if (req) {
		*req = zmalloc(sizes.seccomp_notif);
		if (!*req)
			return -ENOMEM;
	}

	if (resp) {
		*resp = zmalloc(sizes.seccomp_notif_resp);
		if (!*resp) {
			if (req)
				free(*req);
			return -ENOMEM;
		}
	}

	return 0;
}

int sys_notify_receive(int fd, struct seccomp_notif *req)
{
	if (_support_seccomp_user_notif <= 0)
		return -EOPNOTSUPP;

	if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0)
		return -ECANCELED;

	return 0;
}

int sys_notify_respond(int fd, struct seccomp_notif_resp *resp)
{
	if (_support_seccomp_user_notif <= 0)
		return -EOPNOTSUPP;

	if (ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0)
		return -ECANCELED;
	return 0;
}

int sys_notify_id_valid(int fd, uint64_t id)
{
	if (_support_seccomp_user_notif <= 0)
		return -EOPNOTSUPP;

	if (ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id) < 0)
		return -ENOENT;
	return 0;
}
