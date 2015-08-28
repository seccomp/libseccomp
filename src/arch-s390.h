/*
 * Copyright 2015 IBM
 * Author: Jan Willeke <willeke@linux.vnet.com.com>
 */

#ifndef _ARCH_s390_H
#define _ARCH_s390_H

#include <inttypes.h>

#include "arch.h"
#include "system.h"

#define s390_arg_count_max		6

extern const struct arch_def arch_def_s390;
#define s390_arg_offset(x)		(offsetof(struct seccomp_data, args[x]))

int s390_syscall_resolve_name(const char *name);
const char *s390_syscall_resolve_num(int num);
const char *s390_syscall_iterate_name(unsigned int spot);

#endif
