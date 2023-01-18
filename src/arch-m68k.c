/**
 * Enhanced Seccomp m68k Specific Code
 *
 * Copyright (c) 2015 Freescale <bogdan.purcareata@freescale.com>
 *               2017-2023 John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
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
#include "arch-m68k.h"

/* m68k syscall numbers */
#define __m68k_NR_socketcall		102
#define __m68k_NR_ipc			117

ARCH_DEF(m68k)

const struct arch_def arch_def_m68k = {
	.token = SCMP_ARCH_M68K,
	.token_bpf = AUDIT_ARCH_M68K,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_BIG,
	.sys_socketcall = __m68k_NR_socketcall,
	.sys_ipc = __m68k_NR_ipc,
	.syscall_resolve_name = abi_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = m68k_syscall_resolve_name,
	.syscall_resolve_num = abi_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = m68k_syscall_resolve_num,
	.syscall_rewrite = abi_syscall_rewrite,
	.rule_add = abi_rule_add,
	.syscall_name_kver = m68k_syscall_name_kver,
	.syscall_num_kver = m68k_syscall_num_kver,
};
