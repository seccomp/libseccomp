/**
 * Enhanced Seccomp i386 Specific Code
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
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

#ifndef _ARCH_i386_H
#define _ARCH_i386_H

#include "arch.h"
#include "db.h"
#include "system.h"

#define i386_arg_count_max		6

extern const struct arch_def arch_def_i386;
extern const struct arch_syscall_def i386_syscall_table[];

int i386_syscall_rewrite(const struct arch_def *arch, int *syscall);

int i386_filter_rewrite(const struct arch_def *arch,
			unsigned int strict,
			int *syscall, struct db_api_arg *chain);

#endif
