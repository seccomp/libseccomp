/**
 * Seccomp Library test program
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
#include <unistd.h>

#include <seccomp.h>

#include "util.h"

int main(int argc, char *argv[])
{
	int rc;
	uint32_t val = (uint32_t)-1;

	rc = seccomp_init(SCMP_ACT_ALLOW);
	if (rc != 0)
		goto out;

	rc = seccomp_attr_get(SCMP_FLTATR_ACT_DEFAULT, &val);
	if (rc != 0)
		goto out;
	if (val != SCMP_ACT_ALLOW) {
		rc = -1;
		goto out;
	}
	rc = seccomp_attr_set(SCMP_FLTATR_ACT_DEFAULT, val);
	if (rc != -EACCES) {
		rc = -1;
		goto out;
	}

	rc = seccomp_attr_set(SCMP_FLTATR_CTL_NNP_ON, 0);
	if (rc != 0)
		goto out;
	rc = seccomp_attr_get(SCMP_FLTATR_CTL_NNP_ON, &val);
	if (rc != 0)
		goto out;
	if (val != 0) {
		rc = -1;
		goto out;
	}

	rc = seccomp_attr_set(SCMP_FLTATR_CTL_NNP_ERR, 1);
	if (rc != 0)
		goto out;
	rc = seccomp_attr_get(SCMP_FLTATR_CTL_NNP_ERR, &val);
	if (rc != 0)
		goto out;
	if (val != 1) {
		rc = -1;
		goto out;
	}

	rc = 0;

out:
	seccomp_release();
	return (rc < 0 ? -rc : rc);
}
