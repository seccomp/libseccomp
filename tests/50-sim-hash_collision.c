/**
 * Seccomp Library test program
 *
 * Copyright (c) 2019 Oracle and/or its affiliates.  All rights reserved.
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

int main(int argc, char *argv[])
{
	int rc;
	struct util_options opts;
	scmp_filter_ctx ctx = NULL;

	rc = util_getopt(argc, argv, &opts);
	if (rc < 0)
		goto out;

	rc = seccomp_api_set(1);
	if (rc != 0)
		return -rc;

	ctx = seccomp_init(SCMP_ACT_ERRNO(100));
	if (ctx == NULL)
		return ENOMEM;

	rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	if (rc != 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
	if (rc != 0)
		goto out;

	/* libseccomp utilizes a hash table to manage BPF blocks.  It
	 * currently employs MurmurHash3 where the key is the hashed values
	 * of the BPF instruction blocks, the accumulator start, and the
	 * accumulator end.  Changes to the hash algorithm will likely affect
	 * this test.
	 */

	/* The following rules were derived from an issue reported by Tor:
	 * https://github.com/seccomp/libseccomp/issues/148
	 *
	 * In the steps below, syscall 1001 is configured similarly to how
	 * Tor configured socket.  The fairly complex rules below led to
	 * a hash collision with rt_sigaction (syscall 1000) in this test.
	 */

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, 1001, 3,
			      SCMP_A0(SCMP_CMP_EQ, 1),
			      SCMP_A1(SCMP_CMP_MASKED_EQ, 0xf, 2),
			      SCMP_A2(SCMP_CMP_EQ, 3));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, 1001, 2,
			      SCMP_A0(SCMP_CMP_EQ, 1),
			      SCMP_A1(SCMP_CMP_MASKED_EQ, 0xf, 1));
	if (rc != 0)
		goto out;


	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, 1000, 1,
			      SCMP_A0(SCMP_CMP_EQ, 2));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, 1000, 1,
			      SCMP_A0(SCMP_CMP_EQ, 1));
	if (rc != 0)
		goto out;

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
