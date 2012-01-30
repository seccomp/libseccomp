/**
 * Seccomp Library
 * 
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
 */

/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SECCOMP_H
#define _SECCOMP_H

#include <asm/unistd.h>

/* XXX - see notes in seccomp_add_syscall() about pseudo syscalls, we'll need
 *       to define them here for the arch/platforms that require them */

#define SCMP_SYS(x)	__NR_##x

enum scmp_flt_action {
	SCMP_ACT_ALLOW = 0,
	SCMP_ACT_DENY,
};

enum scmp_compare {
	SCMP_CMP_NE = 0,	/* not equal */
	SCMP_CMP_LT,		/* less than */
	SCMP_CMP_LE,		/* less than or equal */
	SCMP_CMP_EQ,		/* equal */
	SCMP_CMP_GE,		/* greater than or equal */
	SCMP_CMP_GT,		/* greater than */
};

int seccomp_reset(enum scmp_flt_action def_action);
void seccomp_release(void);

int seccomp_enable(void);

int seccomp_add_syscall(enum scmp_flt_action action, int syscall);
int seccomp_add_syscall_arg(enum scmp_flt_action action, int syscall,
			    unsigned int arg,
			    enum scmp_compare op, unsigned long datum);

int seccomp_gen_pfc(int fd);
int seccomp_gen_bpf(int fd);

#endif
