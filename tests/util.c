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
#include <string.h>
#include <unistd.h>

#include <seccomp.h>

#include "util.h"

/**
 * Parse the arguments passed to main
 * @param argc the argument count
 * @param argv the argument pointer
 * @param opts the options structure
 *
 * This function parses the arguments passed to the test from the command line.
 * Returns zero on success and negative values on failure.
 *
 */
int util_getopt(int argc, char *argv[], struct util_options *opts)
{
	int rc = 0;

	if (opts == NULL)
		return -EFAULT;

	memset(opts, 0, sizeof(*opts));
	while (1) {
		int c, option_index = 0;
		const struct option long_options[] = {
			{"bpf", no_argument, &(opts->bpf_flg), 1},
			{"pfc", no_argument, &(opts->bpf_flg), 0},
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
			opts->bpf_flg = 1;
			break;
		case 'p':
			opts->bpf_flg = 0;
			break;
		default:
			rc = -EINVAL;
			break;
		}
	}

	if (rc == -EINVAL || optind < argc) {
		fprintf(stderr, "usage %s: [--bpf,-b] [--pfc,-p]\n", argv[0]);
		rc = -EINVAL;
	}

	return rc;
}

/**
 * Output the filter in either BPF or PFC
 * @param opts the options structure
 * @param ctx the filter context
 *
 * This function outputs the seccomp filter to stdout in either BPF or PFC
 * format depending on the test paramaeters supplied by @opts.
 *
 */
int util_filter_output(const struct util_options *opts,
		       const scmp_filter_ctx ctx)
{
	int rc;

	if (opts == NULL)
		return -EFAULT;

	if (opts->bpf_flg)
		rc = seccomp_export_bpf(ctx, STDOUT_FILENO);
	else
		rc = seccomp_export_pfc(ctx, STDOUT_FILENO);

	return rc;
}
