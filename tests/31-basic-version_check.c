/**
 * Seccomp Library test program
 *
 * Copyright (c) 2016 Red Hat <pmoore@redhat.com>
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
	const struct scmp_version *ver;

	ver = seccomp_version();
	if (ver == NULL)
		return -1;

	if (ver->major != SCMP_VER_MAJOR ||
	    ver->minor != SCMP_VER_MINOR ||
	    ver->micro != SCMP_VER_MICRO)
		return -2;

	return 0;
}
