/*
 * Copyright 2015 IBM
 * Author: Jan Willeke <willeke@linux.vnet.com.com>
 */

#ifndef _ARCH_S390X_H
#define _ARCH_S390X_H

#include <inttypes.h>

#include "arch.h"
#include "db.h"
#include "system.h"

#define s390x_arg_count_max		6

extern const struct arch_def arch_def_s390x;
#define s390x_arg_offset(x)		(offsetof(struct seccomp_data, args[x]))

#define s390x_arg_offset_lo(x)		(s390x_arg_offset(x) + 4)
#define s390x_arg_offset_hi(x)		(s390x_arg_offset(x))

int s390x_syscall_resolve_name(const char *name);
const char *s390x_syscall_resolve_num(int num);

const char *s390x_syscall_iterate_name(unsigned int spot);

int s390x_syscall_rewrite(int *syscall);

int s390x_rule_add(struct db_filter_col *col, struct db_filter *db, bool strict,
		   struct db_api_rule_list *rule);

#endif
