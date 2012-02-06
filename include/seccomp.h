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

/* XXX - this should match the kernel's maximum syscall count */
/* XXX - we may want to make this arch dependent if it is in the kernel */
#define SCMP_ARG_MAX		6

#define SCMP_SYS(x)		__NR_##x

enum scmp_flt_action {
	_SCMP_ACT_MIN = 0,	/* sentinel */
	SCMP_ACT_ALLOW,
	SCMP_ACT_DENY,
	_SCMP_ACT_MAX,		/* sentinel */
};

enum scmp_compare {
	_SCMP_CMP_MIN = 0,	/* sentinel */
	SCMP_CMP_NE = 1,	/* not equal */
	SCMP_CMP_LT = 2,	/* less than */
	SCMP_CMP_LE = 3,	/* less than or equal */
	SCMP_CMP_EQ = 4,	/* equal */
	SCMP_CMP_GE = 5,	/* greater than or equal */
	SCMP_CMP_GT = 6,	/* greater than */
	SCMP_CMP_MASK = 7,	/* masked value equality */
	_SCMP_CMP_MAX,		/* sentinel */
};

int seccomp_init(enum scmp_flt_action def_action);
int seccomp_reset(enum scmp_flt_action def_action);
void seccomp_release(void);

int seccomp_enable(void);

int seccomp_add_syscall(enum scmp_flt_action action, int syscall,
			unsigned int chain_len, ...);

int seccomp_gen_pfc(int fd);
int seccomp_gen_bpf(int fd);

#endif
