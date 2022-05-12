/**
 * Seccomp Library test program
 *
 * Copyright (c) 2022 Canonical Ltd.
 * Author: James Henstridge <james.henstridge@canonical.com>
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
#include <inttypes.h>

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

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1001, 1,
				    SCMP_A0(SCMP_CMP_NE | SCMP_CMP_32BIT, 0x10));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1002, 1,
				    SCMP_A0(SCMP_CMP_LT | SCMP_CMP_32BIT, 0x10));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1003, 1,
				    SCMP_A0(SCMP_CMP_LE | SCMP_CMP_32BIT, 0x10));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1004, 1,
				    SCMP_A0(SCMP_CMP_EQ | SCMP_CMP_32BIT, 0x10));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1005, 1,
				    SCMP_A0(SCMP_CMP_GE | SCMP_CMP_32BIT, 0x10));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1006, 1,
				    SCMP_A0(SCMP_CMP_GT | SCMP_CMP_32BIT, 0x10));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1007, 1,
				    SCMP_A0(SCMP_CMP_MASKED_EQ | SCMP_CMP_32BIT, 0xff, 0x10));
	if (rc != 0)
		goto out;

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
