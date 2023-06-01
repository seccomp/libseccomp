/**
 * Seccomp Library test program
 *
 * Copyright (c) 2015 Red Hat <pmoore@redhat.com>
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

	/* NOTE: we have to be careful here because some ABIs use syscall
	 *       offsets which could interfere with our test, x86 is safe */
	rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	if (rc < 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
	if (rc < 0)
		goto out;

	/* SCMP_SYS(sysmips) == 4294957190 (unsigned) */
	rc = seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(sysmips), 0);
	if (rc < 0)
		goto out;
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_KILL, SCMP_SYS(sysmips), 0);
	if (rc == 0)
		goto out;
	/* -10001 == 4294957295 (unsigned) */
	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_KILL, -10001, 0);
	if (rc == 0)
		goto out;

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
