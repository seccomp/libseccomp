/**
 * Enhanced Seccomp sparc64 Specific Code
 *
 * Copyright (c) 2015 Freescale <bogdan.purcareata@freescale.com>
 *               2025 John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
 * Author: Bogdan Purcareata <bogdan.purcareata@freescale.com>
 *         John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
 *
 * Derived from the PPC-specific code
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
#include "arch-sparc64.h"

/* sparc64 syscall numbers */
#define __sparc64_NR_socketcall		206
#define __sparc64_NR_ipc		215

ARCH_DEF(sparc64)

const struct arch_def arch_def_sparc64 = {
	.token = SCMP_ARCH_SPARC64,
	.token_bpf = AUDIT_ARCH_SPARC64,
	.size = ARCH_SIZE_64,
	.endian = ARCH_ENDIAN_BIG,
	.sys_socketcall = __sparc64_NR_socketcall,
	.sys_ipc = __sparc64_NR_ipc,
	.syscall_resolve_name = abi_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = sparc64_syscall_resolve_name,
	.syscall_resolve_num = abi_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = sparc64_syscall_resolve_num,
	.syscall_rewrite = abi_syscall_rewrite,
	.rule_add = abi_rule_add,
	.syscall_name_kver = sparc64_syscall_name_kver,
	.syscall_num_kver = sparc64_syscall_num_kver,
};
