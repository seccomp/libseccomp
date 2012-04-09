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

#include <limits.h>
#include <unistd.h>

#include <seccomp.h>

#include "util.h"

int main(int argc, char *argv[])
{
	int rc;
	int bpf;
	int iter;

	rc = util_getopt(argc, argv, &bpf);
	if (rc < 0)
		return rc;

	rc = seccomp_init(SCMP_ACT_KILL);
	if (rc != 0)
		return rc;

	/* NOTE - syscalls referenced by number to make the test simpler */

	rc = seccomp_rule_add_exact(SCMP_ACT_ALLOW, 1, 0);
	if (rc != 0)
		return rc;

	/* same syscall, many chains */
	for (iter = 0; iter < 600; iter++) {
		rc = seccomp_rule_add_exact(SCMP_ACT_ALLOW, 1000, 3,
					    SCMP_A0(SCMP_CMP_EQ, iter),
					    SCMP_A1(SCMP_CMP_NE, 0x0),
					    SCMP_A2(SCMP_CMP_LT, SSIZE_MAX));
		if (rc != 0)
			return rc;
	}

	/* many syscalls, same chain */
	for (iter = 100; iter < 700; iter++) {
		rc = seccomp_rule_add_exact(SCMP_ACT_ALLOW, iter, 1,
					    SCMP_A0(SCMP_CMP_NE, 0));
		if (rc != 0)
			return rc;
	}

	rc = seccomp_rule_add_exact(SCMP_ACT_ALLOW, 4, 0);
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
