/**
 * Seccomp Library test program
 *
 * Copyright (c) 2018-2020 Oracle and/or its affiliates.
 * Author: Tom Hromatka <tom.hromatka@oracle.com>
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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <seccomp.h>

#include "util.h"

#define ARG_COUNT_MAX 2

struct syscall_errno {
	int syscall;
	int error;
	int arg_cnt;
	/* To make the test more interesting, arguments are added to several
	 * syscalls.  To keep the test simple, the arguments always use
	 * SCMP_CMP_EQ.
	 */
	int args[ARG_COUNT_MAX];
};

struct syscall_errno table[] = {
	{ SCMP_SYS(read), 0, 0, { 0, 0 } },
	{ SCMP_SYS(write), 1, 0, { 0, 0 } },
	{ SCMP_SYS(open), 2, 0, { 0, 0 } },
	{ SCMP_SYS(close), 3, 2, { 100, 101 } },
	{ SCMP_SYS(stat), 4, 0, { 0, 0 } },
	{ SCMP_SYS(fstat), 5, 0, { 0, 0 } },
	{ SCMP_SYS(lstat), 6, 0, { 0, 0 } },
	{ SCMP_SYS(poll), 7, 1, { 102, 0 } },
	{ SCMP_SYS(lseek), 8, 2, { 103, 104 } },
	{ SCMP_SYS(mmap), 9, 0, { 0, 0 } },
	{ SCMP_SYS(mprotect), 10, 0, { 0, 0 } },
	{ SCMP_SYS(munmap), 11, 0, { 0, 0 } },
	{ SCMP_SYS(brk), 12, 0, { 0, 0 } },
	{ SCMP_SYS(rt_sigaction), 13, 0, { 0, 0 } },
	{ SCMP_SYS(rt_sigprocmask), 14, 0, { 0, 0 } },
	{ SCMP_SYS(rt_sigreturn), 15, 0, { 0, 0 } },
	{ SCMP_SYS(ioctl), 16, 0, { 0, 0 } },
	{ SCMP_SYS(pread64), 17, 1, { 105, 0 } },
	{ SCMP_SYS(pwrite64), 18, 0, { 0, 0 } },
	{ SCMP_SYS(readv), 19, 0, { 0, 0 } },
	{ SCMP_SYS(writev), 20, 0, { 0, 0 } },
	{ SCMP_SYS(access), 21, 0, { 0, 0 } },
	{ SCMP_SYS(pipe), 22, 0, { 0, 0 } },
	{ SCMP_SYS(select), 23, 2, { 106, 107 } },
	{ SCMP_SYS(sched_yield), 24, 0, { 0, 0 } },
	{ SCMP_SYS(mremap), 25, 2, { 108, 109 } },
	{ SCMP_SYS(msync), 26, 0, { 0, 0 } },
	{ SCMP_SYS(mincore), 27, 0, { 0, 0 } },
	{ SCMP_SYS(madvise), 28, 0, { 0, 0 } },
	{ SCMP_SYS(dup), 32, 1, { 112, 0 } },
	{ SCMP_SYS(dup2), 33, 0, { 0, 0 } },
	{ SCMP_SYS(pause), 34, 0, { 0, 0 } },
	{ SCMP_SYS(nanosleep), 35, 0, { 0, 0 } },
	{ SCMP_SYS(getitimer), 36, 0, { 0, 0 } },
	{ SCMP_SYS(alarm), 37, 0, { 0, 0 } },
};

const int table_size = sizeof(table) / sizeof(table[0]);

int main(int argc, char *argv[])
{
	int rc, i;
	struct util_options opts;
	scmp_filter_ctx ctx = NULL;

	rc = util_getopt(argc, argv, &opts);
	if (rc < 0)
		goto out;

	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL) {
		rc = ENOMEM;
		goto out;
	}

	rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	if (rc != 0)
		goto out;

	rc = seccomp_arch_add(ctx, SCMP_ARCH_AARCH64);
	if (rc != 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_PPC64LE);
	if (rc != 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
	if (rc != 0)
		goto out;

	rc = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_OPTIMIZE, 2);
	if (rc < 0)
		goto out;

	for (i = 0; i < table_size; i++) {
		switch (table[i].arg_cnt) {
		case 2:
			rc = seccomp_rule_add(ctx,
					      SCMP_ACT_ERRNO(table[i].error),
					      table[i].syscall, 2,
					      SCMP_A0(SCMP_CMP_EQ,
						      table[i].args[0]),
					      SCMP_A1(SCMP_CMP_EQ,
						      table[i].args[1]));
			break;
		case 1:
			rc = seccomp_rule_add(ctx,
					      SCMP_ACT_ERRNO(table[i].error),
					      table[i].syscall, 1,
					      SCMP_A0(SCMP_CMP_EQ,
						      table[i].args[0]));
			break;
		case 0:
		default:
			rc = seccomp_rule_add(ctx,
					      SCMP_ACT_ERRNO(table[i].error),
					      table[i].syscall, 0);
			break;
		}

		if (rc < 0)
			goto out;
	}

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
