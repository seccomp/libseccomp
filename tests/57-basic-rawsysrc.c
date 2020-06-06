/**
 * Seccomp Library test program
 *
 * Copyright (c) 2020 Cisco Systems, Inc. <pmoore2@cisco.com>
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
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <seccomp.h>

#include "util.h"

int main(int argc, char *argv[])
{
	int rc;
	int fd;
	scmp_filter_ctx ctx = NULL;

	rc = seccomp_api_set(3);
	if (rc != 0)
		return EOPNOTSUPP;

	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL) {
		rc = ENOMEM;
		goto out;
	}

	rc = seccomp_attr_set(ctx, SCMP_FLTATR_API_SYSRAWRC, 1);
	if (rc != 0)
		goto out;

	/* we must use a closed/invalid fd for this to work */
	fd = dup(2);
	close(fd);
	rc = seccomp_export_pfc(ctx, fd);
	if (rc == -EBADF)
		rc = 0;
	else
		rc = -1;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
