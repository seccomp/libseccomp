/**
 * Seccomp Library test program
 *
 * Copyright (c) 2025 Oracle and/or its affiliates.
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
#include <unistd.h>

#include <seccomp.h>

#include "util.h"

#include <stdio.h>
int main(int argc, char *argv[])
{
	int rc;
	struct util_options opts;
	scmp_filter_ctx ctx = NULL;

	rc = util_getopt(argc, argv, &opts);
	if (rc < 0)
		goto out;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		return ENOMEM;

	rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	if (rc != 0)
		goto out;

	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
	if (rc != 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X32);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_OPTIMIZE, 2);
	if (rc != 0)
		goto out;
	rc = seccomp_attr_set(ctx, SCMP_FLTATR_ACT_ENOSYS, SCMP_ACT_ERRNO(3));
	if (rc != 0)
		goto out;
	rc = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_KVERMAX, SCMP_KV_6_5);
	if (rc != 0)
		goto out;

	/* unknown action must be set before the kernel version is set */
	rc = seccomp_attr_set(ctx, SCMP_FLTATR_ACT_ENOSYS, SCMP_ACT_ERRNO(9));
	if (rc != -EINVAL)
		goto out;

	/*
	 * Attempt to add a rule after the maximum kernel version has been
	 * set.  This should fail because libseccomp currently does not
	 * support overwriting existing rules.
	 */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	if (rc != -EINVAL)
		goto out;

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
