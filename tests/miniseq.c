/**
 * Seccomp Library test support program
 *
 * Copyright (c) 2015 Mathias Krause <minipli@googlemail.com>
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

#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

static int get_number(char *str, uint64_t *res)
{
	char *end = str;

	errno = 0;
	*res = strtoull(str, &end, 0);
	if (errno || *end != '\0') {
		fprintf(stderr, "error: failed to convert '%s'\n", str);
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	uint64_t first, last, cur;

	if (argc != 3) {
		fprintf(stderr, "usage: %s FIRST LAST\n", argv[0]);
		return 1;
	}

	if (get_number(argv[1], &first) || get_number(argv[2], &last))
		return 1;

	for (cur = first; cur != last; cur++)
		printf("%" PRId64 "\n", cur);
	printf("%" PRId64 "\n", cur);

	return 0;
}
