/**
 * Seccomp Library test program
 *
 * Copyright (c) 2017 Red Hat <pmoore@redhat.com>
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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <seccomp.h>

#include "util.h"

int main(int argc, char *argv[])
{
	int rc;
	int fd;
	scmp_filter_ctx ctx = NULL;

	/* stdout */
	fd = 1;

	rc = seccomp_api_set(3);
	if (rc != 0)
		return EOPNOTSUPP;

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
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X32);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_ARM);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_AARCH64);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_MIPSEL);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_MIPSEL64);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_MIPSEL64N32);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_PPC64LE);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_RISCV64);
	if (rc < 0)
		goto out;

	/* NOTE: the syscalls and their arguments have been picked to achieve
	 *       the highest possible code coverage, this is not a useful
	 *       real world filter configuration */

	rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
	if (rc < 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(read), 4,
			      SCMP_A0(SCMP_CMP_EQ, 0),
			      SCMP_A1(SCMP_CMP_GE, 1),
			      SCMP_A2(SCMP_CMP_GT, 2),
			      SCMP_A3(SCMP_CMP_MASKED_EQ, 0x0f, 3));
	if (rc < 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_TRAP, SCMP_SYS(write), 3,
			      SCMP_A0(SCMP_CMP_NE, 0),
			      SCMP_A1(SCMP_CMP_LE, 1),
			      SCMP_A2(SCMP_CMP_LT, 2));
	if (rc < 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(1), SCMP_SYS(close), 0);
	if (rc < 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_TRACE(1), SCMP_SYS(exit), 0);
	if (rc < 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, SCMP_SYS(fstat), 0);
	if (rc < 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_LOG, SCMP_SYS(exit_group), 0);
	if (rc < 0)
		goto out;

	/* verify the prioritized, but no-rule, syscall */
	rc = seccomp_syscall_priority(ctx, SCMP_SYS(poll), 255);
	if (rc < 0)
		goto out;

	rc = seccomp_export_pfc(ctx, fd);
	if (rc < 0)
		goto out;

out:
	seccomp_release(ctx);
	close(fd);
	return (rc < 0 ? -rc : rc);
}
