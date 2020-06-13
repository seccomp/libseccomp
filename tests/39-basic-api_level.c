/**
 * Seccomp Library test program
 *
 * Copyright (c) 2017 Red Hat <pmoore@redhat.com>
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

int main(int argc, char *argv[])
{
	int rc;
	unsigned int api;

	api = seccomp_api_get();
	if (api < 1)
		return -1;

	rc = seccomp_api_set(1);
	if (rc != 0)
		return -2;
	api = seccomp_api_get();
	if (api != 1)
		return -3;

	rc = seccomp_api_set(2);
	if (rc != 0)
		return -4;
	api = seccomp_api_get();
	if (api != 2)
		return -5;

	rc = seccomp_api_set(3);
	if (rc != 0)
		return -6;
	api = seccomp_api_get();
	if (api != 3)
		return -7;

	rc = seccomp_api_set(4);
	if (rc != 0)
		return -8;
	api = seccomp_api_get();
	if (api != 4)
		return -9;

	rc = seccomp_api_set(5);
	if (rc != 0)
		return -10;
	api = seccomp_api_get();
	if (api != 5)
		return -11;

	rc = seccomp_api_set(6);
	if (rc != 0)
		return -12;
	api = seccomp_api_get();
	if (api != 6)
		return -13;

	/* Attempt to set a high, invalid API level */
	rc = seccomp_api_set(1024);
	if (rc != -EINVAL)
		return -1001;
	/* Ensure that the previously set API level didn't change */
	api = seccomp_api_get();
	if (api != 6)
		return -1002;

	return 0;
}
