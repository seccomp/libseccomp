/*
 * Copyright 2015 IBM
 * Author: Jan Willeke <willeke@linux.vnet.com.com>
 */

#include <stdlib.h>
#include <errno.h>
#include <linux/audit.h>

#include "arch.h"
#include "arch-s390.h"

const struct arch_def arch_def_s390 = {
	.token = SCMP_ARCH_S390,
	.token_bpf = AUDIT_ARCH_S390,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_BIG,
};
