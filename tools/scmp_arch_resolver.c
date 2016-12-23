/**
 * Architecture resolver
 *
 * Copyright (c) 2016 Canonical LTD.
 * Author: Tyler Hicks <tyhicks@canonical.com
 */

/**
 * Originally seccomp_sys_resolver.c:
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
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
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include <seccomp.h>

#include "util.h"

/**
 * Print the usage information to stderr and exit
 * @param program the name of the current program being invoked
 *
 * Print the usage information and exit with EINVAL.
 *
 */
static void exit_usage(const char *program)
{
	fprintf(stderr, "usage: %s [-h] <name>|<number>\n", program);
	exit(EINVAL);
}

/**
 * main
 */
int main(int argc, char *argv[])
{
	int opt;

	/* parse the command line */
	while ((opt = getopt(argc, argv, "h")) > 0) {
		switch (opt) {
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
		char *arch_name = arch_resolve_token(atoi(argv[optind]));

		printf("%s\n", (arch_name ? arch_name : "UNKNOWN"));
		free(arch_name);
	} else {
		uint32_t arch_num = seccomp_arch_resolve_name(argv[optind]);

		printf("%d\n", arch_num);
	}

	return 0;
}
