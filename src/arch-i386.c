/**
 * Enhanced Seccomp i386 Specific Code
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

#include <stdlib.h>
#include <errno.h>

#include "arch.h"
#include "arch-i386.h"

/* i386 syscall numbers */
#define __i386_NR_socketcall		102
#define __i386_NR_ipc			117

/**
 * Rewrite a syscall value to match the architecture
 * @param arch the architecture definition
 * @param syscall the syscall number
 *
 * Syscalls can vary across different architectures so this function rewrites
 * the syscall into the correct value for the specified architecture.  Returns
 * zero on success, negative values on failure.
 *
 */
int i386_syscall_rewrite(const struct arch_def *arch, int *syscall)
{
	/* XXX - rewrite the value in @syscall here */
	return -1;
}

/**
 * Rewrite a filter rule to match the architecture specifics
 * @param arch the architecture definition
 * @param syscall the syscall number
 * @param chain the argument filter chain
 *
 * Syscalls can vary across different architectures so this function handles
 * the necessary seccomp rule rewrites to ensure the right thing is done
 * regardless of the rule or architecture.  Returns zero on success, negative
 * values on error.
 *
 */
int i386_filter_rewrite(const struct arch_def *arch,
			int *syscall, struct db_api_arg *chain)
{
	unsigned int iter;

	if ((*syscall) <= -100 && (*syscall) >= -117) {
		for (iter = 0; iter < i386_arg_count_max; iter++) {
			if (chain[iter].valid != 0)
				return -EINVAL;
		}
		*syscall = __i386_NR_socketcall;
		chain[0].arg = 0;
		chain[0].op = SCMP_CMP_EQ;
		chain[0].datum = abs((*syscall) % 100);
		chain[0].valid = 1;
	} else if ((*syscall) <= -200 && (*syscall) >= -211) {
		for (iter = 0; iter < i386_arg_count_max; iter++) {
			if (chain[iter].valid != 0)
				return -EINVAL;
		}
		*syscall = __i386_NR_ipc;
		chain[0].arg = 0;
		chain[0].op = SCMP_CMP_EQ;
		chain[0].datum = abs((*syscall) % 200);
		chain[0].valid = 1;
	} else if ((*syscall) < 0)
		return -EINVAL;

	return 0;
}
