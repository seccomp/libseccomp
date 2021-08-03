/**
 * Seccomp Library test program
 *
 * Copyright (c) 2019 Cisco Systems, Inc. <pmoore2@cisco.com>
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
#include <unistd.h>

#include <seccomp.h>

#include "util.h"

int main(int argc, char *argv[])
{
	int rc;
	struct util_options opts;
	scmp_filter_ctx ctx = NULL;
	unsigned int api;

	rc = util_getopt(argc, argv, &opts);
	if (rc < 0)
		goto out;

	api = seccomp_api_get();
	if (api == 0) {
		rc = -EFAULT;
		goto out;
	}

	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL)
		return ENOMEM;

	if (api >= 2) {
		rc = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1);
		if (rc != 0)
			goto out;
	}
	if (api >= 3) {
		rc = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_LOG, 1);
		if (rc != 0)
			goto out;
	}
	if (api >= 4) {
		rc = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_SSB, 1);
		if (rc != 0)
			goto out;
	}

	rc = seccomp_load(ctx);

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
