/**
 * Seccomp Library test program
 *
 * Copyright (c) 2026 Microsoft Corporation <paulmoore@microsoft.com>
 * Copyright (c) 2026 Oracle and/or its affiliates.
 * Author: Paul Moore <paul@paul-moore.com>
 * Author: Tom Hromatka (Oracle) <tom.hromatka@gmail.com>
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

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		return ENOMEM;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 1,
			      SCMP_A0(SCMP_CMP_LT, 5));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getppid), 1,
			      SCMP_A0(SCMP_CMP_GT, 0x300000000ULL));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
			      SCMP_A0(SCMP_CMP_MASKED_EQ,
				      0x000000ff000000ffULL,
				      0x0000000100000001ULL));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
			      SCMP_A0(SCMP_CMP_MASKED_EQ,
				      0x000000ff000000ffULL,
				      0x0000000200000002ULL));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
			      SCMP_A0(SCMP_CMP_LT, 5),
			      SCMP_A1(SCMP_CMP_LT, 5));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
			      SCMP_A0(SCMP_CMP_GT, 0x300000000ULL));
	if (rc != 0)
		goto out;

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}

