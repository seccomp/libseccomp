/**
 * Enhanced Seccomp x32 Specific Code
 *
 * Copyright (c) 2013 Red Hat <pmoore@redhat.com>
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

#include <stdlib.h>
#include <errno.h>
#include <linux/audit.h>

#include "arch.h"
#include "arch-x32.h"
#include "syscalls.h"

/**
 * Resolve a syscall name to a number
 * @param arch the architecture definition
 * @param name the syscall name
 *
 * Resolve the given syscall name to the syscall number using the syscall table.
 * Returns the syscall number on success, including negative pseudo syscall
 * numbers; returns __NR_SCMP_ERROR on failure.
 *
 */
int x32_syscall_resolve_name_munge(const struct arch_def *arch,
				   const char *name)
{
	int sys;

	/* NOTE: we don't want to modify the pseudo-syscall numbers */
	sys = arch->syscall_resolve_name_raw(name);
	if (sys == __NR_SCMP_ERROR || sys < 0)
		return sys;

	return (sys | X32_SYSCALL_BIT);
}

/**
 * Resolve a syscall number to a name
 * @param arch the architecture definition
 * @param num the syscall number
 *
 * Resolve the given syscall number to the syscall name using the syscall table.
 * Returns a pointer to the syscall name string on success, including pseudo
 * syscall names; returns NULL on failure.
 *
 */
const char *x32_syscall_resolve_num_munge(const struct arch_def *arch,
					  int num)
{
	/* NOTE: we don't want to modify the pseudo-syscall numbers */
	if (num >= 0)
		num &= ~X32_SYSCALL_BIT;
	return arch->syscall_resolve_num_raw(num);
}

ARCH_DEF(x32)

const struct arch_def arch_def_x32 = {
	.token = SCMP_ARCH_X32,
	/* NOTE: this seems odd but the kernel treats x32 like x86_64 here */
	.token_bpf = AUDIT_ARCH_X86_64,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_LITTLE,
	.syscall_resolve_name = x32_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = x32_syscall_resolve_name,
	.syscall_resolve_num = x32_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = x32_syscall_resolve_num,
	.syscall_rewrite = NULL,
	.rule_add = NULL,
};
