/*
 * Copyright 2015 IBM
 * Author: Jan Willeke <willeke@linux.vnet.com.com>
 */

#include <stdlib.h>
#include <errno.h>
#include <linux/audit.h>

#include "arch.h"
#include "arch-s390x.h"

const struct arch_def arch_def_s390x = {
	.token = SCMP_ARCH_S390X,
	.token_bpf = AUDIT_ARCH_S390X,
	.size = ARCH_SIZE_64,
	.endian = ARCH_ENDIAN_BIG,
	.syscall_resolve_name = s390x_syscall_resolve_name,
	.syscall_resolve_num = s390x_syscall_resolve_num,
	.syscall_rewrite = NULL,
	.rule_add = NULL,
};
