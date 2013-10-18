/**
 * Syscall resolver
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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include "../src/arch.h"
#include "../src/arch-x86.h"
#include "../src/arch-x86_64.h"
#include "../src/arch-x32.h"
#include "../src/arch-arm.h"

/**
 * Print the usage information to stderr and exit
 * @param program the name of the current program being invoked
 *
 * Print the usage information and exit with EINVAL.
 *
 */
static void exit_usage(const char *program)
{
	fprintf(stderr,
		"usage: %s [-h] [-a <arch>] [-t] <name>|<number>\n",
		program);
	exit(EINVAL);
}

/**
 * main
 */
int main(int argc, char *argv[])
{
	int opt;
	int translate = 0;
	const struct arch_def *arch = arch_def_native;
	int sys_num;
	const char *sys_name;

	/* parse the command line */
	while ((opt = getopt(argc, argv, "a:ht")) > 0) {
		switch (opt) {
		case 'a':
			if (strcmp(optarg, "x86") == 0)
				arch = &arch_def_x86;
			else if (strcmp(optarg, "x86_64") == 0)
				arch = &arch_def_x86_64;
			else if (strcmp(optarg, "x32") == 0)
				arch = &arch_def_x32;
			else if (strcmp(optarg, "arm") == 0)
				arch = &arch_def_arm;
			else
				exit_usage(argv[0]);
			break;
		case 't':
			translate = 1;
			break;
		case 'h':
		default:
			/* usage information */
			exit_usage(argv[0]);
		}
	}

	/* sanity checks */
	if (optind >= argc)
		exit_usage(argv[0]);

	/* perform the syscall lookup */
	if (isdigit(argv[optind][0]) || argv[optind][0] == '-') {
		sys_num = atoi(argv[optind]);
		sys_name = arch_syscall_resolve_num(arch, sys_num);
		printf("%s\n", sys_name);
	} else {
		sys_num = arch_syscall_resolve_name(arch, argv[optind]);
		if (translate != 0)
			/* ignore errors and just output the resolved number */
			arch_syscall_rewrite(arch, 0, &sys_num);
		printf("%d\n", sys_num);
	}

	return 0;
}
