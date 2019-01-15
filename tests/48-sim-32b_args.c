/**
 * Seccomp Library test program
 *
 * Copyright (c) 2019 Cisco Systems, Inc. <pmoore2@cisco.com>
 * Author: Paul Moore <paul@paul-moore.com>
 * Additions: Michael Weiser <michael.weiser@gmx.de>
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
	struct args {
		uint32_t action;
		int syscall;
		struct scmp_arg_cmp cmp;
	} *a, f[] = {
		{SCMP_ACT_ALLOW, 2000, SCMP_A0(SCMP_CMP_EQ, -1)},
		{SCMP_ACT_ALLOW, 2064, SCMP_A0_64(SCMP_CMP_EQ, -1)},
		{SCMP_ACT_ALLOW, 2032, SCMP_A0_32(SCMP_CMP_EQ, -1)},
		{0},
	};

	rc = util_getopt(argc, argv, &opts);
	if (rc < 0)
		goto out;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		return ENOMEM;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1000, 1,
				    SCMP_A0(SCMP_CMP_EQ, -1));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1064, 1,
				    SCMP_A0_64(SCMP_CMP_EQ, -1));
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, 1032, 1,
				    SCMP_A0_32(SCMP_CMP_EQ, -1));
	if (rc != 0)
		goto out;

	for (a = f; a->syscall != 0; a++) {
		rc = seccomp_rule_add_exact(ctx, a->action, a->syscall, 1,
					    a->cmp);
		if (rc != 0)
			goto out;
	}

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
