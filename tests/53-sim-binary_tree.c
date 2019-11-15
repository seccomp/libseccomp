/**
 * Seccomp Library test program
 *
 * Copyright (c) 2018 Oracle and/or its affiliates.  All rights reserved.
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

#define MAX_SYSCALL		(330)

#include <stdio.h>

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
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
	if (rc < 0)
		goto out;
	rc = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_OPTIMIZE, 2);
	if (rc < 0)
		goto out;

	/* NOTE: this test is entirely fabricated and should not be
	 * 	 replicated in the real world.
	 *
	 *	 The MAX_SYSCALL number (330) was chosen to force seccomp to
	 *	 build an unbalanced binary tree - and it happens to be less
	 *	 than the current syscall max.  The syscall numbers are
	 *	 hardcoded to simplify the test.  A few syscalls have
	 *	 argument chains to further complicate the filter.
	 */

	for (i = 0; i < MAX_SYSCALL; i++) {
		/* arbitrarily make the filter more complex by filtering
		 * on arguments for a few syscalls
		 */
		if (i == 10 || i == 53 || i == 61 || i == 255)
			rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(i), i, 1,
					      SCMP_A0(SCMP_CMP_EQ, i));
		else
			rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(i), i, 0);
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
