/*
 * Copyright (c) 2016 Helge Deller <deller@gmx.de>
 * Author: Helge Deller <deller@gmx.de>
 */

#include <stdlib.h>
#include <errno.h>
#include <linux/audit.h>

#include "arch.h"
#include "arch-parisc.h"
#include "syscalls.h"

ARCH_DEF(parisc)

const struct arch_def arch_def_parisc = {
	.token = SCMP_ARCH_PARISC,
	.token_bpf = AUDIT_ARCH_PARISC,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_BIG,
	.syscall_resolve_name_raw = parisc_syscall_resolve_name,
	.syscall_resolve_num_raw = parisc_syscall_resolve_num,
	.syscall_rewrite = NULL,
	.rule_add = NULL,
};
