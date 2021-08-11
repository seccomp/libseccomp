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

/* mips syscall numbers */
#define __mips_NR_socketcall		102
#define __mips_NR_ipc			117

const struct arch_def arch_def_mips = {
	.token = SCMP_ARCH_MIPS,
	.token_bpf = AUDIT_ARCH_MIPS,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_BIG,
	.sys_socketcall = __mips_NR_socketcall,
	.sys_ipc = __mips_NR_ipc,
	.syscall_resolve_name = abi_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = mips_syscall_resolve_name,
	.syscall_resolve_num = abi_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = mips_syscall_resolve_num,
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
	.syscall_resolve_name_raw = mips_syscall_resolve_name,
	.syscall_resolve_num = abi_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = mips_syscall_resolve_num,
	.syscall_rewrite = abi_syscall_rewrite,
	.rule_add = abi_rule_add,
};
