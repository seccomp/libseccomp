/**
 * Enhanced Seccomp MIPS Specific Code
 *
 * Copyright (c) 2014 Imagination Technologies Ltd.
 * Author: Markos Chandras <markos.chandras@imgtec.com>
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

#ifndef _ARCH_MIPS_H
#define _ARCH_MIPS_H

#include <inttypes.h>

#include "arch.h"
#include "system.h"

#define mips_arg_count_max		6

extern const struct arch_def arch_def_mips;
extern const struct arch_def arch_def_mipsel;

#define mips_arg_offset(x)	(offsetof(struct seccomp_data, args[x]) + 4)
#define mipsel_arg_offset(x)	(offsetof(struct seccomp_data, args[x]))

int mips_syscall_resolve_name(const char *name);
const char *mips_syscall_resolve_num(int num);

#endif
