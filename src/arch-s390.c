/*
 * Copyright 2015 IBM
 * Author: Jan Willeke <willeke@linux.vnet.com.com>
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <linux/audit.h>

#include "db.h"
#include "syscalls.h"
#include "arch.h"
#include "arch-s390.h"

/* s390 syscall numbers */
#define __s390_NR_socketcall		102
#define __s390_NR_ipc			117

ARCH_DEF(s390)

const struct arch_def arch_def_s390 = {
	.token = SCMP_ARCH_S390,
	.token_bpf = AUDIT_ARCH_S390,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_BIG,
	.sys_socketcall = __s390_NR_socketcall,
	.sys_ipc = __s390_NR_ipc,
	.syscall_resolve_name = abi_syscall_resolve_name_munge,
	.syscall_resolve_name_raw = s390_syscall_resolve_name,
	.syscall_resolve_num = abi_syscall_resolve_num_munge,
	.syscall_resolve_num_raw = s390_syscall_resolve_num,
	.syscall_rewrite = abi_syscall_rewrite,
	.rule_add = abi_rule_add,
};
