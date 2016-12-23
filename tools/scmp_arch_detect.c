/**
 * Architecture Detector
 *
 * Copyright (c) 2013 Red Hat <pmoore@redhat.com>
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
	fprintf(stderr,
		"usage: %s [-h] [-t]\n",
		program);
	exit(EINVAL);
}

/**
 * main
 */
int main(int argc, char *argv[])
{
	int opt;
	int token = 0;
	uint32_t arch;

	/* parse the command line */
	while ((opt = getopt(argc, argv, "ht")) > 0) {
		switch (opt) {
		case 't':
			token = 1;
			break;
		case 'h':
		default:
			/* usage information */
			exit_usage(argv[0]);
		}
	}

	arch = seccomp_arch_native();
	if (token == 0) {
		char *name = arch_resolve_token(arch);

		printf("%s\n", (name ? name : "unknown"));
		free(name);
	} else
		printf("%d\n", arch);

	return 0;
}
