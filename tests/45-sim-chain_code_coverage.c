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
#include <unistd.h>
#include <stdbool.h>

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

	/* the syscall and argument numbers are all fake to make the test
	 * simpler */

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1008, 1,
				    SCMP_A0(SCMP_CMP_GE, 1));
	if (rc != 0)
		goto out;

	/* db_chain_lt() path #1 - due to "A1" > "A0" */
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1008, 1,
				    SCMP_A1(SCMP_CMP_GE, 2));
	if (rc != 0)
		goto out;

	/* db_chain_lt() path #2 - due to "GT" > "GE" */
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1008, 1,
				    SCMP_A0(SCMP_CMP_GT, 3));
	if (rc != 0)
		goto out;

	/* db_chain_lt() path #3 - due to the second mask (0xff) being greater
	 * than the first (0xf) */
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1008, 1,
				    SCMP_A2(SCMP_CMP_MASKED_EQ, 0xf, 4));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1008, 1,
				    SCMP_A2(SCMP_CMP_MASKED_EQ, 0xff, 5));
	if (rc != 0)
		goto out;

	/* db_chain_lt() path #4 - due to datum (6) > previous datum (5) */
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1008, 1,
				    SCMP_A2(SCMP_CMP_MASKED_EQ, 0xff, 6));
	if (rc != 0)
		goto out;

	/* attempt to hit some of the lvl_prv and lvl_nxt code in db.c */
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1008, 5,
				    SCMP_A0(SCMP_CMP_NE, 7),
				    SCMP_A1(SCMP_CMP_LT, 8),
				    SCMP_A2(SCMP_CMP_EQ, 9),
				    SCMP_A3(SCMP_CMP_GE, 10),
				    SCMP_A4(SCMP_CMP_GT, 11),
				    SCMP_A5(SCMP_CMP_MASKED_EQ, 0xffff, 12));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1008, 5,
				    SCMP_A0(SCMP_CMP_NE, 7),
				    SCMP_A1(SCMP_CMP_LT, 8),
				    SCMP_A2(SCMP_CMP_EQ, 9),
				    SCMP_A3(SCMP_CMP_GE, 10),
				    SCMP_A4(SCMP_CMP_GT, 11),
				    SCMP_A5(SCMP_CMP_MASKED_EQ, 0xffff, 13));
	if (rc != 0)
		goto out;

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
