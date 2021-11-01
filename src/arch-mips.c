/**
 * Enhanced Seccomp MIPS Specific Code
 *
 * Copyright (c) 2014 Imagination Technologies Ltd.
 * Author: Markos Chandras <markos.chandras@imgtec.com>
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
#include <string.h>
#include <linux/audit.h>

#include "db.h"
#include "syscalls.h"
#include "arch.h"
#include "arch-mips.h"

/* O32 ABI */
#define __SCMP_NR_BASE			4000

/* mips syscall numbers */
#define __mips_NR_socketcall		(__SCMP_NR_BASE + 102)
#define __mips_NR_ipc			(__SCMP_NR_BASE + 117)

/**
 * Resolve a syscall name to a number
 * @param name the syscall name
 *
 * Resolve the given syscall name to the syscall number using the syscall table.
 * Returns the syscall number on success, including negative pseudo syscall
 * numbers; returns __NR_SCMP_ERROR on failure.
 *
 */
int mips_syscall_resolve_name_raw(const char *name)
{
	int sys;

	/* NOTE: we don't want to modify the pseudo-syscall numbers */
	sys = mips_syscall_resolve_name(name);
	if (sys == __NR_SCMP_ERROR || sys < 0)
		return sys;

	return sys + __SCMP_NR_BASE;
}

/**
 * Resolve a syscall number to a name
 * @param num the syscall number
 *
 * Resolve the given syscall number to the syscall name using the syscall table.
 * Returns a pointer to the syscall name string on success, including pseudo
 * syscall names; returns NULL on failure.
 *
 */
const char *mips_syscall_resolve_num_raw(int num)
{
	/* NOTE: we don't want to modify the pseudo-syscall numbers */
	if (num >= __SCMP_NR_BASE)
		num -= __SCMP_NR_BASE;
	return mips_syscall_resolve_num(num);
}

ARCH_DEF(mips)

const struct arch_def arch_def_mips = {
	.token = SCMP_ARCH_MIPS,
	.token_bpf = AUDIT_ARCH_MIPS,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_BIG,
	.sys_socketcall = __mips_NR_socketcall,
	.sys_ipc = __mips_NR_ipc,
	.syscall_resolve_name = abi_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = mips_syscall_resolve_name_raw,
	.syscall_resolve_num = abi_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = mips_syscall_resolve_num_raw,
	.syscall_rewrite = abi_syscall_rewrite,
	.rule_add = abi_rule_add,
};

const struct arch_def arch_def_mipsel = {
	.token = SCMP_ARCH_MIPSEL,
	.token_bpf = AUDIT_ARCH_MIPSEL,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_LITTLE,
	.sys_socketcall = __mips_NR_socketcall,
	.sys_ipc = __mips_NR_ipc,
	.syscall_resolve_name = abi_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = mips_syscall_resolve_name_raw,
	.syscall_resolve_num = abi_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = mips_syscall_resolve_num_raw,
	.syscall_rewrite = abi_syscall_rewrite,
	.rule_add = abi_rule_add,
};
