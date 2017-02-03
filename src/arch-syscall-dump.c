/**
 * Enhanced Seccomp Architecture Sycall Checker
 *
 * Copyright (c) 2014 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <paul@paul-moore.com>
 *
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
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include <seccomp.h>

#include "arch.h"
#include "arch-x86.h"
#include "arch-x86_64.h"
#include "arch-x32.h"
#include "arch-arm.h"
#include "arch-mips.h"
#include "arch-mips64.h"
#include "arch-mips64n32.h"
#include "arch-aarch64.h"
#include "arch-ppc.h"
#include "arch-ppc64.h"
#include "arch-s390.h"
#include "arch-s390x.h"

/**
 * Print the usage information to stderr and exit
 * @param program the name of the current program being invoked
 *
 * Print the usage information and exit with EINVAL.
 *
 */
static void exit_usage(const char *program)
{
	fprintf(stderr, "usage: %s [-h] [-a <arch>] [-o <offset>]\n", program);
	exit(EINVAL);
}

/**
 * main
 */
int main(int argc, char *argv[])
{
	int opt;
	const struct arch_def *arch = arch_def_native;
	int offset = 0;
	int iter;
	const struct arch_syscall_def *sys;

	/* parse the command line */
	while ((opt = getopt(argc, argv, "a:o:h")) > 0) {
		switch (opt) {
		case 'a':
			arch = arch_def_lookup_name(optarg);
			if (arch == 0)
				exit_usage(argv[0]);
			break;
		case 'o':
			offset = atoi(optarg);
			break;
		case 'h':
		default:
			/* usage information */
			exit_usage(argv[0]);
		}
	}

	iter = 0;
	do {
		switch (arch->token) {
		case SCMP_ARCH_X86:
			sys = x86_syscall_iterate(iter);
			break;
		case SCMP_ARCH_X86_64:
			sys = x86_64_syscall_iterate(iter);
			break;
		case SCMP_ARCH_X32:
			sys = x32_syscall_iterate(iter);
			break;
		case SCMP_ARCH_ARM:
			sys = arm_syscall_iterate(iter);
			break;
		case SCMP_ARCH_AARCH64:
			sys = aarch64_syscall_iterate(iter);
			break;
		case SCMP_ARCH_MIPS:
		case SCMP_ARCH_MIPSEL:
			sys = mips_syscall_iterate(iter);
			break;
		case SCMP_ARCH_MIPS64:
		case SCMP_ARCH_MIPSEL64:
			sys = mips64_syscall_iterate(iter);
			break;
		case SCMP_ARCH_MIPS64N32:
		case SCMP_ARCH_MIPSEL64N32:
			sys = mips64n32_syscall_iterate(iter);
			break;
		case SCMP_ARCH_PPC:
			sys = ppc_syscall_iterate(iter);
			break;
		case SCMP_ARCH_PPC64:
		case SCMP_ARCH_PPC64LE:
			sys = ppc64_syscall_iterate(iter);
			break;
		case SCMP_ARCH_S390:
			sys = s390_syscall_iterate(iter);
			break;
		case SCMP_ARCH_S390X:
			sys = s390x_syscall_iterate(iter);
			break;
		default:
			/* invalid arch */
			exit_usage(argv[0]);
		}
		if (sys->name != NULL) {
			int sys_num = sys->num;

			if (offset > 0 && sys_num > 0)
				sys_num -= offset;

			/* output the results */
			printf("%s\t%d\n", sys->name, sys_num);

			/* next */
			iter++;
		}
	} while (sys->name != NULL);

	return 0;
}
