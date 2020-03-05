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
	{ SCMP_SYS(read), 0, 2, { 100, 101 } },
	{ SCMP_SYS(write), 1, 1, { 102, 0 } },
	{ SCMP_SYS(open), 2, 0, { 0, 0 } },
	{ SCMP_SYS(close), 3, 0, { 0, 0 } },
	{ SCMP_SYS(stat), 4, 0, { 0, 0 } },
	{ SCMP_SYS(fstat), 5, 1, { 103, 0 } },
	{ SCMP_SYS(lstat), 6, 0, { 0, 0 } },
	{ SCMP_SYS(poll), 7, 0, { 0, 0 } },
	{ SCMP_SYS(lseek), 8, 1, { 104, 0 } },
	{ SCMP_SYS(mmap), 9, 0, { 0, 0 } },
	{ SCMP_SYS(mprotect), 10, 1, { 105, 0 } },
	{ SCMP_SYS(munmap), 11, 0, { 0, 0 } },
	{ SCMP_SYS(brk), 12, 0, { 0, 0 } },
	{ SCMP_SYS(rt_sigaction), 13, 0, { 0, 0 } },
	{ SCMP_SYS(rt_sigprocmask), 14, 0, { 0, 0 } },
	{ SCMP_SYS(rt_sigreturn), 15, 0, { 0, 0 } },
	{ SCMP_SYS(ioctl), 16, 0, { 0, 0 } },
	{ SCMP_SYS(pread64), 17, 1, { 106, 0 } },
	{ SCMP_SYS(pwrite64), 18, 2, { 107, 108 } },
};

const int table_size = sizeof(table) / sizeof(table[0]);

int main(int argc, char *argv[])
{
	int rc, fd, i;
	scmp_filter_ctx ctx = NULL;

	/* stdout */
	fd = 1;

	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL) {
		rc = ENOMEM;
		goto out;
	}

	rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_AARCH64);
	if (rc < 0)
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

	rc = seccomp_export_pfc(ctx, fd);
	if (rc < 0)
		goto out;

out:
	seccomp_release(ctx);
	close(fd);
	return (rc < 0 ? -rc : rc);
}
