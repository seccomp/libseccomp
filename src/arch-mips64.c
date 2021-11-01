/**
 * Enhanced Seccomp MIPS64 Specific Code
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

#include <linux/audit.h>

#include "arch.h"
#include "arch-mips64.h"
#include "syscalls.h"

/* 64 ABI */
#define __SCMP_NR_BASE			5000

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
int mips64_syscall_resolve_name_munge(const struct arch_def *arch,
				      const char *name)
{
	int sys;

	/* NOTE: we don't want to modify the pseudo-syscall numbers */
	sys = arch->syscall_resolve_name_raw(name);
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
const char *mips64_syscall_resolve_num_munge(const struct arch_def *arch,
					     int num)
{
	/* NOTE: we don't want to modify the pseudo-syscall numbers */
	if (num >= __SCMP_NR_BASE)
		num -= __SCMP_NR_BASE;
	return arch->syscall_resolve_num_raw(num);
}

ARCH_DEF(mips64)

const struct arch_def arch_def_mips64 = {
	.token = SCMP_ARCH_MIPS64,
	.token_bpf = AUDIT_ARCH_MIPS64,
	.size = ARCH_SIZE_64,
	.endian = ARCH_ENDIAN_BIG,
	.syscall_resolve_name = mips64_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = mips64_syscall_resolve_name,
	.syscall_resolve_num = mips64_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = mips64_syscall_resolve_num,
	.syscall_rewrite = NULL,
	.rule_add = NULL,
};

const struct arch_def arch_def_mipsel64 = {
	.token = SCMP_ARCH_MIPSEL64,
	.token_bpf = AUDIT_ARCH_MIPSEL64,
	.size = ARCH_SIZE_64,
	.endian = ARCH_ENDIAN_LITTLE,
	.syscall_resolve_name = mips64_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = mips64_syscall_resolve_name,
	.syscall_resolve_num = mips64_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = mips64_syscall_resolve_num,
	.syscall_rewrite = NULL,
	.rule_add = NULL,
};
