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
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <seccomp.h>

#include "util.h"


static const unsigned int allowlist[] = {
	SCMP_SYS(clone),
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
	SCMP_SYS(futex),
	SCMP_SYS(madvise),
	SCMP_SYS(mmap),
	SCMP_SYS(mprotect),
	SCMP_SYS(munmap),
	SCMP_SYS(nanosleep),
	SCMP_SYS(set_robust_list),
};

/**
 * Child thread created via pthread_create()
 *
 * This thread will call a disallowed syscall.  It should
 * cause the entire program to die (and not just this
 * thread.)
 */
void *child_start(void *param)
{
	int fd;

	/* make a disallowed syscall */
	fd = open("/dev/null", O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	/* we should never get here.  seccomp should kill the entire
	 * process when open() is called. */
	if (fd >= 0)
		close(fd);

	return NULL;
}

int main(int argc, char *argv[])
{
	int rc, i;
	scmp_filter_ctx ctx = NULL;
	pthread_t child_thread;

	ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
	if (ctx == NULL)
		return ENOMEM;

	for (i = 0; i < sizeof(allowlist) / sizeof(allowlist[0]); i++) {
		rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allowlist[i], 0);
		if (rc != 0)
			goto out;
	}

	rc = seccomp_load(ctx);
	if (rc != 0)
		goto out;

	rc = pthread_create(&child_thread, NULL, child_start, NULL);
	if (rc != 0)
		goto out;

	/* sleep for a bit to ensure that the child thread has time to run */
	sleep(1);

	/* we should never get here! */
	rc = -EACCES;
	goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
