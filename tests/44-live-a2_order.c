/**
 * Seccomp Library test program
 *
 * Copyright (c) 2018 Oracle and/or its affiliates.  All rights reserved.
 * Author: Tom Hromatka <tom.hromatka@oracle.com>
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
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <seccomp.h>

#include "util.h"

#define DEFAULT_ACTION_ERRNO	100
#define DEFAULT_ACTION		SCMP_ACT_ERRNO(DEFAULT_ACTION_ERRNO)

struct size_and_rc {
	int size;
	int expected_rc;
};

static const struct size_and_rc test_cases[] = {
	{1, 1},
	{10, 10},
	{50, 50},
	{100, -DEFAULT_ACTION_ERRNO},
	{200, -5},
	{256, -5},
	{257, -6},
	{400, -6},
	{800, -7},
	{1600, -8},
	{3200, -9},
	{4095, -9},
	{4096, -9},
	{4097, -10},
	{8000, -10},
	{8192, -10},
	{16383, -11},
	{16384, -11},
	{16385, -12},
	{35000, -12},
};

static int do_read(int sz, int expected_rc)
{
	char *buf = NULL;
	int rc = -1000, zero_fd = -1;

	zero_fd = open("/dev/zero", O_RDONLY);
	if (zero_fd <= 0)
		goto error;

	buf = malloc(sz);
	if (buf == NULL)
		goto error;

	rc = read(zero_fd, buf, sz);
	if(rc < 0) {
		if (expected_rc == -errno)
			rc = 0;
	} else {
		if (rc == expected_rc)
			rc = 0;
	}

error:
	if (zero_fd >= 0)
		close(zero_fd);
	if (buf)
		free(buf);
	return rc;
}

int main(int argc, char *argv[])
{
	int rc, i;
	scmp_filter_ctx ctx = NULL;

	ctx = seccomp_init(DEFAULT_ACTION);
	if (ctx == NULL)
		return ENOMEM;

	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
			      SCMP_A2(SCMP_CMP_LE, 64));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(5), SCMP_SYS(read), 1,
			      SCMP_A2(SCMP_CMP_GT, 128));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(6), SCMP_SYS(read), 1,
			      SCMP_A2(SCMP_CMP_GT, 256));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(7), SCMP_SYS(read), 1,
			      SCMP_A2(SCMP_CMP_GT, 512));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(8), SCMP_SYS(read), 1,
			      SCMP_A2(SCMP_CMP_GT, 1024));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(9), SCMP_SYS(read), 1,
			      SCMP_A2(SCMP_CMP_GT, 2048));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(10), SCMP_SYS(read), 1,
			      SCMP_A2(SCMP_CMP_GT, 4096));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(11), SCMP_SYS(read), 1,
			      SCMP_A2(SCMP_CMP_GT, 8192));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(12), SCMP_SYS(read), 1,
			      SCMP_A2(SCMP_CMP_GT, 16384));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_load(ctx);
	if (rc != 0)
		goto out;

	for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
		rc = do_read(test_cases[i].size,
			     test_cases[i].expected_rc);
		if (rc < 0)
			goto out;
	}

	rc = 160;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
