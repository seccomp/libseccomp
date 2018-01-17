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
#include <limits.h>
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

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1001, 2,
				    SCMP_A0(SCMP_CMP_EQ, 1),
				    SCMP_A1(SCMP_CMP_EQ, 2));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1001, 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1002, 1,
				    SCMP_A0(SCMP_CMP_EQ, 1));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_TRAP, 1002, 1,
				    SCMP_A0(SCMP_CMP_EQ, 1));
	if (rc != -EEXIST) {
		rc = EEXIST;
		goto out;
	}

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1003, 1,
				    SCMP_A0(SCMP_CMP_NE, 1));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_TRAP, 1003, 1,
				    SCMP_A0(SCMP_CMP_EQ, 1));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1004, 1,
				    SCMP_A0(SCMP_CMP_EQ, 1));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_TRAP, 1004, 1,
				    SCMP_A0(SCMP_CMP_NE, 1));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1005, 1,
				    SCMP_A0(SCMP_CMP_EQ, 1));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1005, 1,
				    SCMP_A0(SCMP_CMP_NE, 1));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1006, 2,
				    SCMP_A0(SCMP_CMP_EQ, 1),
				    SCMP_A1(SCMP_CMP_EQ, 2));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1006, 1,
				    SCMP_A0(SCMP_CMP_EQ, 1));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1007, 1,
				    SCMP_A0(SCMP_CMP_EQ, 1));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1007, 2,
				    SCMP_A0(SCMP_CMP_EQ, 1),
				    SCMP_A1(SCMP_CMP_EQ, 2));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1008, 2,
				    SCMP_A0(SCMP_CMP_NE, 1),
				    SCMP_A1(SCMP_CMP_NE, 2));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1008, 3,
				    SCMP_A0(SCMP_CMP_NE, 1),
				    SCMP_A1(SCMP_CMP_NE, 2),
				    SCMP_A2(SCMP_CMP_NE, 3));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1009, 2,
				    SCMP_A0(SCMP_CMP_EQ, 1),
				    SCMP_A1(SCMP_CMP_NE, 2));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1009, 1,
				    SCMP_A0(SCMP_CMP_NE, 1));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1010, 2,
				    SCMP_A0(SCMP_CMP_NE, 1),
				    SCMP_A1(SCMP_CMP_EQ, 2));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1010, 1,
				    SCMP_A0(SCMP_CMP_EQ, 1));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1011, 1,
				    SCMP_A0(SCMP_CMP_EQ, 1));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1011, 2,
				    SCMP_A0(SCMP_CMP_NE, 1),
				    SCMP_A2(SCMP_CMP_EQ, 1));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1012, 1,
				    SCMP_A0(SCMP_CMP_MASKED_EQ, 0x0000, 1));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1013, 2,
				    SCMP_A0(SCMP_CMP_NE, 1),
				    SCMP_A1(SCMP_CMP_NE, 2));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1013, 2,
				    SCMP_A0(SCMP_CMP_LT, 1),
				    SCMP_A1(SCMP_CMP_NE, 2));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1014, 2,
				    SCMP_A3(SCMP_CMP_GE, 1),
				    SCMP_A4(SCMP_CMP_GE, 2));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1014, 2,
				    SCMP_A0(SCMP_CMP_NE, 1),
				    SCMP_A1(SCMP_CMP_NE, 2));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1015, 2,
				    SCMP_A0(SCMP_CMP_EQ, 4),
				    SCMP_A1(SCMP_CMP_EQ, 1));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1015, 2,
				    SCMP_A0(SCMP_CMP_EQ, 4),
				    SCMP_A1(SCMP_CMP_NE, 1));
	if (rc != 0)
		goto out;

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
