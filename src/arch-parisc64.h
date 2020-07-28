/**
 * Enhanced Seccomp PARISC64 Specific Code
 *
 * Copyright (c) 2020 Oracle and/or its affiliates.
 * Author: Tom Hromatka <tom.hromatka@oracle.com>
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

#ifndef _ARCH_PARISC64_H
#define _ARCH_PARISC64_H

#include <inttypes.h>

#include "arch.h"
#include "system.h"

extern const struct arch_def arch_def_parisc64;

int parisc64_syscall_resolve_name(const char *name);
const char *parisc64_syscall_resolve_num(int num);

const struct arch_syscall_def *parisc64_syscall_iterate(unsigned int spot);

#endif
