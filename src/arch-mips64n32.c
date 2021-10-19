/**
 * Enhanced Seccomp MIPS Specific Code
 *
 * Copyright (c) 2014 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <paul@paul-moore.com>
 *
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
#include "arch-mips64n32.h"
#include "syscalls.h"

/* N32 ABI */
#define __SCMP_NR_BASE			6000

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
int mips64n32_syscall_resolve_name_munge(const struct arch_def *arch,
					 const char *name)
{
	int sys;

	/* NOTE: we don't want to modify the pseudo-syscall numbers */
	sys = mips64n32_syscall_resolve_name(name);
	if (sys == __NR_SCMP_ERROR || sys < 0)
		return sys;

	return sys + __SCMP_NR_BASE;
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
const char *mips64n32_syscall_resolve_num_munge(const struct arch_def *arch,
						int num)
{
	/* NOTE: we don't want to modify the pseudo-syscall numbers */
	if (num >= __SCMP_NR_BASE)
		num -= __SCMP_NR_BASE;
	return mips64n32_syscall_resolve_num(num);
}

ARCH_DEF(mips64n32)

const struct arch_def arch_def_mips64n32 = {
	.token = SCMP_ARCH_MIPS64N32,
	.token_bpf = AUDIT_ARCH_MIPS64N32,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_BIG,
	.syscall_resolve_name = mips64n32_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = mips64n32_syscall_resolve_name,
	.syscall_resolve_num = mips64n32_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = mips64n32_syscall_resolve_num,
	.syscall_rewrite = NULL,
	.rule_add = NULL,
};

const struct arch_def arch_def_mipsel64n32 = {
	.token = SCMP_ARCH_MIPSEL64N32,
	.token_bpf = AUDIT_ARCH_MIPSEL64N32,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_LITTLE,
	.syscall_resolve_name = mips64n32_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = mips64n32_syscall_resolve_name,
	.syscall_resolve_num = mips64n32_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = mips64n32_syscall_resolve_num,
	.syscall_rewrite = NULL,
	.rule_add = NULL,
};
