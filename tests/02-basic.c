/**
 * Seccomp Library test program
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
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

/*
 * Just like mode 1 seccomp we allow 4 syscalls:
 * read, write, exit, and rt_sigreturn
 */

#include <unistd.h>

#include <seccomp.h>

#include "util.h"

int main(int argc, char *argv[])
{
	int rc;
	int bpf;

	rc = util_getopt(argc, argv, &bpf);
	if (rc < 0)
		return rc;

	rc = seccomp_init(SCMP_ACT_KILL);
	if (rc != 0)
		return rc;


	rc = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
	if (rc != 0)
		return rc;

	rc = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	if (rc != 0)
		return rc;

	rc = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	if (rc != 0)
		return rc;

	rc = seccomp_rule_add_exact(SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
	if (rc != 0)
		return rc;

	if (bpf)
		rc = seccomp_gen_bpf(STDOUT_FILENO);
	else
		rc = seccomp_gen_pfc(STDOUT_FILENO);
	if (rc != 0)
		return rc;

	seccomp_release();
	return rc;
}
