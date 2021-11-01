/**
 * Seccomp Library test program
 *
 * Copyright (c) 2016 Red Hat <pmoore@redhat.com>
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

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		return ENOMEM;

	rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	if (rc != 0)
		goto out;

	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
	if (rc != 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
	if (rc != 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X32);
	if (rc != 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_PPC64LE);
	if (rc != 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_MIPSEL);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(listen), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpeername), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketpair), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(send), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recv), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(shutdown), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(setsockopt), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(accept4), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmmsg), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmmsg), 0);
	if (rc != 0)
		goto out;

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
