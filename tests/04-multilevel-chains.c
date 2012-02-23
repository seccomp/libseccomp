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

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#include <seccomp.h>

int main(int argc, char *argv[])
{
	static int bpf = 0;
	int rc;

	while (1) {
		static struct option long_options[] = {
			{"bpf", no_argument, &bpf, 1},
			{"pfc", no_argument, &bpf, 0},
			{0,0,0,0},
		};
		int c, option_index = 0;

		c = getopt_long(argc, argv, "bp",
				long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 0:
			break;
		case 'b':
			bpf = 1;
			break;

		case 'p':
			bpf = 0;
			break;
		default:
			return -1;
		}
	}

	if (optind < argc) {
		printf("usage %s: [--bpf,-b] [--pfc,-p]\n", argv[0]);
		return -EINVAL;
	}

	rc = seccomp_init(SCMP_ACT_DENY);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, SCMP_SYS(read), 3,
				 0, SCMP_CMP_EQ, STDIN_FILENO,
				 1, SCMP_CMP_NE, NULL,
				 2, SCMP_CMP_LT, SSIZE_MAX);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
				 0, SCMP_CMP_EQ, STDOUT_FILENO,
				 1, SCMP_CMP_NE, NULL,
				 2, SCMP_CMP_LT, SSIZE_MAX);
	if (rc != 0)
		return rc;
	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
				 0, SCMP_CMP_EQ, STDERR_FILENO,
				 1, SCMP_CMP_NE, NULL,
				 2, SCMP_CMP_LT, SSIZE_MAX);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	if (rc != 0)
		return rc;

	rc = seccomp_add_syscall(SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
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
