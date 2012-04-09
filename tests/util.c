/**
 * Seccomp Library utility code for tests
 *
 * Copyright (c) 2012 Red Hat <eparis@redhat.com>
 * Author: Eric Paris <eparis@redhat.com>
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
#include <getopt.h>
#include <stdio.h>

#include "util.h"

/**
 * Parse the arguments passed to main
 * @param argc the argument count
 * @param argv the argument pointer
 * @param bpf indicates whether bpf or pfc should be generated for the test
 *
 * This function parses the arguments passed to main.  Returns zero on
 * success and negative values on failure.
 *
 */
int util_getopt(int argc, char *argv[], int *bpf)
{
	int rc = 0;

	*bpf = 0;
	while (1) {
		int c, option_index = 0;
		const struct option long_options[] = {
			{"bpf", no_argument, bpf, 1},
			{"pfc", no_argument, bpf, 0},
			{0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "bp",
				long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 0:
			break;
		case 'b':
			*bpf = 1;
			break;

		case 'p':
			*bpf = 0;
			break;
		default:
			rc = -EINVAL;
			break;
		}
	}

	if (rc == -EINVAL || optind < argc) {
		printf("usage %s: [--bpf,-b] [--pfc,-p]\n", argv[0]);
		rc = -EINVAL;
	}

	return rc;
}
