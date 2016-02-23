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

#include <seccomp.h>

#include "arch.h"
#include "db.h"
#include "gen_bpf.h"
#include "system.h"

/* NOTE: the seccomp syscall whitelist is currently disabled for testing
 *       purposes, but unless we can verify all of the supported ABIs before
 *       our next release we may have to enable the whitelist */
#define SYSCALL_WHITELIST_ENABLE	0

static int _nr_seccomp = -1;
static int _support_seccomp_syscall = -1;

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

#if SYSCALL_WHITELIST_ENABLE
	/* architecture whitelist */
	switch (arch_def_native->token) {
	case SCMP_ARCH_X86_64:
	case SCMP_ARCH_ARM:
	case SCMP_ARCH_AARCH64:
	case SCMP_ARCH_PPC64:
	case SCMP_ARCH_PPC64LE:
	case SCMP_ARCH_S390:
	case SCMP_ARCH_S390X:
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
 * Check to see if a seccomp() flag is supported
 * @param flag the seccomp() flag
 *
 * This function checks to see if a seccomp() flag is supported by the system.
 * If the flag is supported one is returned, zero if unsupported, negative
 * values on error.
 *
 */
int sys_chk_seccomp_flag(int flag)
{
	switch (flag) {
	case SECCOMP_FILTER_FLAG_TSYNC:
		return sys_chk_seccomp_syscall();
	}

	return -EOPNOTSUPP;
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
int sys_filter_load(const struct db_filter_col *col)
{
	int rc;
	struct bpf_program *prgm = NULL;

	prgm = gen_bpf_generate(col);
	if (prgm == NULL)
		return -ENOMEM;

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
			flgs = SECCOMP_FILTER_FLAG_TSYNC;
		rc = syscall(_nr_seccomp, SECCOMP_SET_MODE_FILTER, flgs, prgm);
		if (rc > 0 && col->attr.tsync_enable)
			/* always return -ESRCH if we fail to sync threads */
			errno = ESRCH;
	} else
		rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prgm);

filter_load_out:
	/* cleanup and return */
	gen_bpf_release(prgm);
	if (rc < 0)
		return -errno;
	return 0;
}
