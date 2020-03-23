/**
 * Enhanced Seccomp x86_64 Syscall Table
 *
 * Copyright (c) 2012, 2020 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <paul@paul-moore.com>
 * gperf support: Giuseppe Scrivano <gscrivan@redhat.com>
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
#include <seccomp.h>
#include <string.h>

#include "arch.h"
#include "syscalls.h"

#define ARCH_DEF(NAME) \
	int NAME##_syscall_resolve_name(const char *name) \
	{ \
		return syscall_resolve_name(name, OFFSET_ARCH(NAME)); \
	} \
	const char *NAME##_syscall_resolve_num(int num) \
	{ \
		return syscall_resolve_num(num, OFFSET_ARCH(NAME)); \
	} \
	const struct arch_syscall_def *NAME##_syscall_iterate(unsigned int spot) \
	{ \
		return syscall_iterate(spot, OFFSET_ARCH(NAME)); \
	}

ARCH_DEF(x86_64)
ARCH_DEF(arm)
ARCH_DEF(aarch64)
ARCH_DEF(mips64n32)
ARCH_DEF(mips64)
ARCH_DEF(mips)
ARCH_DEF(parisc)
ARCH_DEF(parisc64)
ARCH_DEF(ppc64)
ARCH_DEF(ppc)
ARCH_DEF(s390)
ARCH_DEF(s390x)
ARCH_DEF(x32)
ARCH_DEF(x86)
ARCH_DEF(riscv64)
