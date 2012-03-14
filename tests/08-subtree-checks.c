/**
 * Seccomp Library test program
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
 */

/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <seccomp.h>

#include "util.h"

int main(int argc, char *argv[])
{
	int bpf;
	int rc;

	rc = util_getopt(argc, argv, &bpf);
	if (rc < 0)
		return rc;

	rc = seccomp_init(SCMP_ACT_KILL);
	if (rc != 0)
		return rc;

	/* the syscall and argument numbers are all fake to make the test
	 * simpler */

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1000, 2,
				 0, SCMP_CMP_EQ, 0UL,
				 1, SCMP_CMP_EQ, 1UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1000, 1,
				 1, SCMP_CMP_EQ, 1UL);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1001, 1,
				 1, SCMP_CMP_EQ, 1UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1001, 2,
				 0, SCMP_CMP_EQ, 0UL,
				 1, SCMP_CMP_EQ, 1UL);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1002, 4,
				 0, SCMP_CMP_EQ, 0UL,
				 1, SCMP_CMP_EQ, 1UL,
				 2, SCMP_CMP_EQ, 2UL,
				 3, SCMP_CMP_EQ, 3UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1002, 2,
				 1, SCMP_CMP_EQ, 1UL,
				 2, SCMP_CMP_EQ, 2UL);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1003, 2,
				 1, SCMP_CMP_EQ, 1UL,
				 2, SCMP_CMP_EQ, 2UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1003, 4,
				 0, SCMP_CMP_EQ, 0UL,
				 1, SCMP_CMP_EQ, 1UL,
				 2, SCMP_CMP_EQ, 2UL,
				 3, SCMP_CMP_EQ, 3UL);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1004, 4,
				 0, SCMP_CMP_EQ, 0UL,
				 1, SCMP_CMP_EQ, 1UL,
				 2, SCMP_CMP_EQ, 2UL,
				 3, SCMP_CMP_EQ, 3UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1004, 2,
				 0, SCMP_CMP_EQ, 0UL,
				 1, SCMP_CMP_EQ, 11UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1004, 4,
				 0, SCMP_CMP_EQ, 0UL,
				 1, SCMP_CMP_EQ, 1UL,
				 2, SCMP_CMP_EQ, 2UL,
				 3, SCMP_CMP_EQ, 33UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1004, 2,
				 1, SCMP_CMP_EQ, 1UL,
				 2, SCMP_CMP_EQ, 2UL);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1005, 2,
				 1, SCMP_CMP_EQ, 1UL,
				 2, SCMP_CMP_EQ, 2UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1005, 4,
				 0, SCMP_CMP_EQ, 0UL,
				 1, SCMP_CMP_EQ, 1UL,
				 2, SCMP_CMP_EQ, 2UL,
				 3, SCMP_CMP_EQ, 3UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1005, 2,
				 0, SCMP_CMP_EQ, 0UL,
				 1, SCMP_CMP_EQ, 11UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1005, 4,
				 0, SCMP_CMP_EQ, 0UL,
				 1, SCMP_CMP_EQ, 1UL,
				 2, SCMP_CMP_EQ, 2UL,
				 3, SCMP_CMP_EQ, 33UL);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1006, 2,
				 1, SCMP_CMP_NE, 1UL,
				 2, SCMP_CMP_EQ, 0UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1006, 2,
				 1, SCMP_CMP_EQ, 1UL,
				 2, SCMP_CMP_EQ, 2UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1006, 1,
				 1, SCMP_CMP_NE, 1UL);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_TRAP, 1007, 2,
				 2, SCMP_CMP_EQ, 1UL,
				 3, SCMP_CMP_EQ, 3UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1007, 2,
				 2, SCMP_CMP_EQ, 1UL,
				 3, SCMP_CMP_NE, 3UL);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, 1007, 1,
				 3, SCMP_CMP_NE, 3UL);
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
