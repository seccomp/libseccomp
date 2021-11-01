/**
 * Enhanced Seccomp PPC64 Specific Code
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
#include <string.h>
#include <linux/audit.h>

#include "db.h"
#include "syscalls.h"
#include "arch.h"
#include "arch-ppc64.h"

/* ppc64 syscall numbers */
#define __ppc64_NR_socketcall		102
#define __ppc64_NR_ipc			117

ARCH_DEF(ppc64)

const struct arch_def arch_def_ppc64 = {
	.token = SCMP_ARCH_PPC64,
	.token_bpf = AUDIT_ARCH_PPC64,
	.size = ARCH_SIZE_64,
	.endian = ARCH_ENDIAN_BIG,
	.sys_socketcall = __ppc64_NR_socketcall,
	.sys_ipc = __ppc64_NR_ipc,
	.syscall_resolve_name = abi_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = ppc64_syscall_resolve_name,
	.syscall_resolve_num = abi_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = ppc64_syscall_resolve_num,
	.syscall_rewrite = abi_syscall_rewrite,
	.rule_add = abi_rule_add,
};

const struct arch_def arch_def_ppc64le = {
	.token = SCMP_ARCH_PPC64LE,
	.token_bpf = AUDIT_ARCH_PPC64LE,
	.size = ARCH_SIZE_64,
	.endian = ARCH_ENDIAN_LITTLE,
	.sys_socketcall = __ppc64_NR_socketcall,
	.sys_ipc = __ppc64_NR_ipc,
	.syscall_resolve_name = abi_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = ppc64_syscall_resolve_name,
	.syscall_resolve_num = abi_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = ppc64_syscall_resolve_num,
	.syscall_rewrite = abi_syscall_rewrite,
	.rule_add = abi_rule_add,
};
