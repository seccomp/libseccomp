/*
 * Copyright (c) 2016 Helge Deller <deller@gmx.de>
 * Author: Helge Deller <deller@gmx.de>
*/

#include <stdlib.h>
#include <errno.h>
#include <linux/audit.h>

#include "arch.h"
#include "arch-parisc64.h"

const struct arch_def arch_def_parisc64 = {
	.token = SCMP_ARCH_PARISC64,
	.token_bpf = AUDIT_ARCH_PARISC64,
	.size = ARCH_SIZE_64,
	.endian = ARCH_ENDIAN_BIG,
	.syscall_resolve_name = parisc64_syscall_resolve_name,
	.syscall_resolve_num = parisc64_syscall_resolve_num,
	.syscall_rewrite = NULL,
	.rule_add = NULL,
};
