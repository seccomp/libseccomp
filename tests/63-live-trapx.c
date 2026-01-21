/**
 * Seccomp Library test program
 *
 * Copyright (c) 2025 Oracle and/or its affiliates.
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

#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <seccomp.h>

#include "util.h"


#include <stdio.h>


#define EXPECTED_REASON 1234

static int trap_rc;

static void _trap_handler(int signal, siginfo_t *info, void *ctx)
{
	if (info->si_errno == EXPECTED_REASON)
		trap_rc = 0;
	else
		trap_rc = -EINVAL;
}

int trap_install(void)
{
	struct sigaction signal_handler;
	sigset_t signal_mask;

	trap_rc = -EBUSY;

	memset(&signal_handler, 0, sizeof(signal_handler));
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGSYS);

	signal_handler.sa_sigaction = &_trap_handler;
	signal_handler.sa_flags = SA_SIGINFO;
	if (sigaction(SIGSYS, &signal_handler, NULL) < 0)
		return -errno;
	if (sigprocmask(SIG_UNBLOCK, &signal_mask, NULL))
		return -errno;

	return 0;
}

int main(int argc, char *argv[])
{
	scmp_filter_ctx ctx = NULL;
	pid_t ppid;
	int cnt, rc;

	rc = trap_install();
	if (rc != 0)
		goto out;

	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL)
		return ENOMEM;

	rc = seccomp_rule_add(ctx, SCMP_ACT_TRAPX(EXPECTED_REASON),
			      SCMP_SYS(getppid), 0);
	if (rc != 0)
		goto out;

	rc = seccomp_load(ctx);
	if (rc != 0)
		goto out;

	ppid = getppid();
	(void)ppid;

	cnt = 0;
	while (trap_rc == -EBUSY) {
		sleep(1);
		cnt++;

		if (cnt > 5)
			break;
	}

	if (trap_rc == 0)
		rc = 161;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
