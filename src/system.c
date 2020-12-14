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

/* task global state */
struct task_state {
	/* seccomp(2) syscall */
	int nr_seccomp;

	/* userspace notification fd */
	int notify_fd;

	/* runtime support flags */
	int sup_syscall;
	int sup_flag_tsync;
	int sup_flag_log;
	int sup_action_log;
	int sup_kill_process;
	int sup_flag_spec_allow;
	int sup_flag_new_listener;
	int sup_user_notif;
	int sup_flag_tsync_esrch;
};
static struct task_state state = {
	.nr_seccomp = -1,

	.notify_fd = -1,

	.sup_syscall = -1,
	.sup_flag_tsync = -1,
	.sup_flag_log = -1,
	.sup_action_log = -1,
	.sup_kill_process = -1,
	.sup_flag_spec_allow = -1,
	.sup_flag_new_listener = -1,
	.sup_user_notif = -1,
	.sup_flag_tsync_esrch = -1,
};

/**
 * Reset the task state
 *
 * This function fully resets the library's global "system task state".
 *
 */
void sys_reset_state(void)
{
	state.nr_seccomp = -1;

	if (state.notify_fd > 0)
		close(state.notify_fd);
	state.notify_fd = -1;

	state.sup_syscall = -1;
	state.sup_flag_tsync = -1;
	state.sup_flag_log = -1;
	state.sup_action_log = -1;
	state.sup_kill_process = -1;
	state.sup_flag_spec_allow = -1;
	state.sup_flag_new_listener = -1;
	state.sup_user_notif = -1;
	state.sup_flag_tsync_esrch = -1;
}

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
	if (state.sup_syscall >= 0)
		return state.sup_syscall;

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
	 * seccomp() syscall is supported or not */
	rc = syscall(nr_seccomp, SECCOMP_SET_MODE_STRICT, 1, NULL);
	if (rc < 0 && errno == EINVAL)
		goto supported;

unsupported:
	state.sup_syscall = 0;
	return 0;
supported:
	state.nr_seccomp = nr_seccomp;
	state.sup_syscall = 1;
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
	state.sup_syscall = (enable ? 1 : 0);
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
		if (state.sup_kill_process < 0) {
			if (sys_chk_seccomp_syscall() == 1 &&
			    syscall(state.nr_seccomp,
				    SECCOMP_GET_ACTION_AVAIL, 0, &action) == 0)
				state.sup_kill_process = 1;
			else
				state.sup_kill_process = 0;
		}

		return state.sup_kill_process;
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
		if (state.sup_action_log < 0) {
			if (sys_chk_seccomp_syscall() == 1 &&
			    syscall(state.nr_seccomp,
				    SECCOMP_GET_ACTION_AVAIL, 0, &action) == 0)
				state.sup_action_log = 1;
			else
				state.sup_action_log = 0;
		}

		return state.sup_action_log;
	} else if (action == SCMP_ACT_ALLOW) {
		return 1;
	} else if (action == SCMP_ACT_NOTIFY) {
		if (state.sup_user_notif < 0) {
			struct seccomp_notif_sizes sizes;
			if (sys_chk_seccomp_syscall() == 1 &&
			    syscall(state.nr_seccomp,
				    SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == 0)
				state.sup_user_notif = 1;
			else
				state.sup_user_notif = 0;
		}

		return state.sup_user_notif;
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
		state.sup_action_log = (enable ? 1 : 0);
		break;
	case SCMP_ACT_KILL_PROCESS:
		state.sup_kill_process = (enable ? 1 : 0);
		break;
	case SCMP_ACT_NOTIFY:
		state.sup_user_notif = (enable ? 1 : 0);
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
static int _sys_chk_flag_kernel(int flag)
{
	/* this is an invalid seccomp(2) call because the last argument
	 * is NULL, but depending on the errno value of EFAULT we can
	 * guess if the filter flag is supported or not */
	if (sys_chk_seccomp_syscall() == 1 &&
	    syscall(state.nr_seccomp,
		    SECCOMP_SET_MODE_FILTER, flag, NULL) == -1 &&
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
		if (state.sup_flag_tsync < 0)
			state.sup_flag_tsync = _sys_chk_flag_kernel(flag);
		return state.sup_flag_tsync;
	case SECCOMP_FILTER_FLAG_LOG:
		if (state.sup_flag_log < 0)
			state.sup_flag_log = _sys_chk_flag_kernel(flag);
		return state.sup_flag_log;
	case SECCOMP_FILTER_FLAG_SPEC_ALLOW:
		if (state.sup_flag_spec_allow < 0)
			state.sup_flag_spec_allow = _sys_chk_flag_kernel(flag);
		return state.sup_flag_spec_allow;
	case SECCOMP_FILTER_FLAG_NEW_LISTENER:
		if (state.sup_flag_new_listener < 0)
			state.sup_flag_new_listener = _sys_chk_flag_kernel(flag);
		return state.sup_flag_new_listener;
	case SECCOMP_FILTER_FLAG_TSYNC_ESRCH:
		if (state.sup_flag_tsync_esrch < 0)
			state.sup_flag_tsync_esrch = _sys_chk_flag_kernel(flag);
		return state.sup_flag_tsync_esrch;
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
		state.sup_flag_tsync = (enable ? 1 : 0);
		break;
	case SECCOMP_FILTER_FLAG_LOG:
		state.sup_flag_log = (enable ? 1 : 0);
		break;
	case SECCOMP_FILTER_FLAG_SPEC_ALLOW:
		state.sup_flag_spec_allow = (enable ? 1 : 0);
		break;
	case SECCOMP_FILTER_FLAG_NEW_LISTENER:
		state.sup_flag_new_listener = (enable ? 1 : 0);
		break;
	case SECCOMP_FILTER_FLAG_TSYNC_ESRCH:
		state.sup_flag_tsync_esrch = (enable ? 1 : 0);
		break;
	}
}

/**
 * Loads the filter into the kernel
 * @param col the filter collection
 * @param rawrc pass the raw return code if true
 *
 * This function loads the given seccomp filter context into the kernel.  If
 * the filter was loaded correctly, the kernel will be enforcing the filter
 * when this function returns.  Returns zero on success, negative values on
 * error.
 *
 */
int sys_filter_load(struct db_filter_col *col, bool rawrc)
{
	int rc;
	bool tsync_notify;
	bool listener_req;
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

	tsync_notify = state.sup_flag_tsync_esrch > 0 && state.notify_fd == -1;
	listener_req = state.sup_user_notif > 0 && \
		       col->notify_used && state.notify_fd == -1;

	/* load the filter into the kernel */
	if (sys_chk_seccomp_syscall() == 1) {
		int flgs = 0;
		if (tsync_notify) {
			if (col->attr.tsync_enable)
				flgs |= SECCOMP_FILTER_FLAG_TSYNC | \
					SECCOMP_FILTER_FLAG_TSYNC_ESRCH;
			if (listener_req)
				flgs |= SECCOMP_FILTER_FLAG_NEW_LISTENER;
		} else if (col->attr.tsync_enable) {
			if (listener_req) {
				/* NOTE: we _should_ catch this in db.c */
				rc = -EFAULT;
				goto filter_load_out;
			}
			flgs |= SECCOMP_FILTER_FLAG_TSYNC;
		} else if (listener_req)
			flgs |= SECCOMP_FILTER_FLAG_NEW_LISTENER;
		if (col->attr.log_enable)
			flgs |= SECCOMP_FILTER_FLAG_LOG;
		if (col->attr.spec_allow)
			flgs |= SECCOMP_FILTER_FLAG_SPEC_ALLOW;
		rc = syscall(state.nr_seccomp,
			     SECCOMP_SET_MODE_FILTER, flgs, prgm);
		if (tsync_notify && rc > 0) {
			/* return 0 on NEW_LISTENER success, but save the fd */
			state.notify_fd = rc;
			rc = 0;
		} else if (rc > 0 && col->attr.tsync_enable) {
			/* always return -ESRCH if we fail to sync threads */
			errno = ESRCH;
			rc = -errno;
		} else if (rc > 0 && state.sup_user_notif > 0) {
			/* return 0 on NEW_LISTENER success, but save the fd */
			state.notify_fd = rc;
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
		return (rawrc ? -errno : -ECANCELED);
	return rc;
}

/**
 * Return the userspace notification fd
 *
 * This function returns the userspace notification fd from
 * SECCOMP_FILTER_FLAG_NEW_LISTENER.  If the notification fd has not yet been
 * set, or an error has occurred, -1 is returned.
 *
 */
int sys_notify_fd(void)
{
	return state.notify_fd;
}

/**
 * Allocate a pair of notification request/response structures
 * @param req the request location
 * @param resp the response location
 *
 * This function allocates a pair of request/response structure by computing
 * the correct sized based on the currently running kernel. It returns zero on
 * success, and negative values on failure.
 *
 */
int sys_notify_alloc(struct seccomp_notif **req,
		     struct seccomp_notif_resp **resp)
{
	int rc;
	static struct seccomp_notif_sizes sizes = { 0, 0, 0 };

	if (state.sup_syscall <= 0)
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

/**
 * Receive a notification from a seccomp notification fd
 * @param fd the notification fd
 * @param req the request buffer to save into
 *
 * Blocks waiting for a notification on this fd. This function is thread safe
 * (synchronization is performed in the kernel). Returns zero on success,
 * negative values on error.
 *
 */
int sys_notify_receive(int fd, struct seccomp_notif *req)
{
	if (state.sup_user_notif <= 0)
		return -EOPNOTSUPP;

	if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, req) < 0)
		return -ECANCELED;

	return 0;
}

/**
 * Send a notification response to a seccomp notification fd
 * @param fd the notification fd
 * @param resp the response buffer to use
 *
 * Sends a notification response on this fd. This function is thread safe
 * (synchronization is performed in the kernel). Returns zero on success,
 * negative values on error.
 *
 */
int sys_notify_respond(int fd, struct seccomp_notif_resp *resp)
{
	if (state.sup_user_notif <= 0)
		return -EOPNOTSUPP;

	if (ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, resp) < 0)
		return -ECANCELED;
	return 0;
}

/**
 * Check if a notification id is still valid
 * @param fd the notification fd
 * @param id the id to test
 *
 * Checks to see if a notification id is still valid. Returns 0 on success, and
 * negative values on failure.
 *
 */
int sys_notify_id_valid(int fd, uint64_t id)
{
	int rc;
	if (state.sup_user_notif <= 0)
		return -EOPNOTSUPP;

	rc = ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &id);
	if (rc < 0 && errno == EINVAL)
		/* It is possible that libseccomp was built against newer kernel
		 * headers than the kernel it is running on. If so, the older
		 * runtime kernel may not support the "fixed"
		 * SECCOMP_IOCTL_NOTIF_ID_VALID ioctl number which was introduced in
		 * kernel commit 47e33c05f9f0 ("seccomp: Fix ioctl number for
		 * SECCOMP_IOCTL_NOTIF_ID_VALID"). Try the old value. */
		rc = ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID_WRONG_DIR, &id);
	if (rc < 0)
		return -ENOENT;
	return 0;
}
