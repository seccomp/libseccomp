/**
 * Enhanced Seccomp 64-bit LoongArch Syscall Table
 *
 * Copyright (c) 2021 Xiaotian Wu <wuxiaotian@loongson.cn>
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
#include "arch-loongarch64.h"
#include "syscalls.h"

ARCH_DEF(loongarch64)

const struct arch_def arch_def_loongarch64 = {
	.token = SCMP_ARCH_LOONGARCH64,
	.token_bpf = AUDIT_ARCH_LOONGARCH64,
	.size = ARCH_SIZE_64,
	.endian = ARCH_ENDIAN_LITTLE,
	.syscall_resolve_name_raw = loongarch64_syscall_resolve_name,
	.syscall_resolve_num_raw = loongarch64_syscall_resolve_num,
	.syscall_rewrite = NULL,
	.rule_add = NULL,
	.syscall_name_kver = loongarch64_syscall_name_kver,
	.syscall_num_kver = loongarch64_syscall_num_kver,
};
