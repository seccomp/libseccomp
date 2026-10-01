/**
 * Seccomp Library test program
 *
 * Copyright (c) 2026 Sascha Grunert <sgrunert@redhat.com>
 * Author: Sascha Grunert <sgrunert@redhat.com>
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
#include <unistd.h>

#include <seccomp.h>

#include "util.h"

int main(int argc, char *argv[])
{
	int rc;
	struct util_options opts;
	scmp_filter_ctx ctx = NULL;

	rc = util_getopt(argc, argv, &opts);
	if (rc < 0)
		goto out;

	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL)
		return ENOMEM;

	rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X32);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_AARCH64);
	if (rc < 0)
		goto out;

	/* a pseudo-syscall on every arch above, without conditions so that it
	 * sorts before the conditional rules and becomes the head of the
	 * syscall list, where it is omitted from the filter; x86 drops the
	 * rule when it is added, the others keep it */
	rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(arm_fadvise64_64), 0);
	if (rc < 0)
		goto out;

	/* the real rules must still be applied, which they are only if the
	 * filter loads the syscall number before testing them */
	rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(read), 1,
			      SCMP_A0(SCMP_CMP_EQ, 1));
	if (rc < 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), 1,
			      SCMP_A0(SCMP_CMP_EQ, 1));
	if (rc < 0)
		goto out;

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
