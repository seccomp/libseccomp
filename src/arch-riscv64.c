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
#include "arch-riscv64.h"

const struct arch_def arch_def_riscv64 = {
	.token = SCMP_ARCH_RISCV64,
	.token_bpf = AUDIT_ARCH_RISCV64,
	.size = ARCH_SIZE_64,
	.endian = ARCH_ENDIAN_LITTLE,
	.syscall_resolve_name = riscv64_syscall_resolve_name,
	.syscall_resolve_num = riscv64_syscall_resolve_num,
	.syscall_rewrite = NULL,
	.rule_add = NULL,
};
