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

#define SYSCALL_ARCH(NAME)                                                                   \
int NAME##_syscall_resolve_name(const char *name)                                            \
{                                                                                            \
	return syscall_resolve_name(name, OFFSET_ARCH(NAME));                                \
}                                                                                            \
                                                                                             \
const char *NAME##_syscall_resolve_num(int num)                                              \
{                                                                                            \
	return syscall_resolve_num(num, OFFSET_ARCH(NAME));                                  \
}                                                                                            \
                                                                                             \
const struct arch_syscall_def *NAME##_syscall_iterate(unsigned int spot)                     \
{                                                                                            \
	return syscall_iterate(spot, OFFSET_ARCH(NAME));                                     \
}

SYSCALL_ARCH(x86_64)
SYSCALL_ARCH(arm)
SYSCALL_ARCH(aarch64)
SYSCALL_ARCH(mips64n32)
SYSCALL_ARCH(mips64)
SYSCALL_ARCH(mips)
SYSCALL_ARCH(parisc)
SYSCALL_ARCH(ppc64)
SYSCALL_ARCH(ppc)
SYSCALL_ARCH(s390)
SYSCALL_ARCH(s390x)
SYSCALL_ARCH(x32)
SYSCALL_ARCH(x86)
SYSCALL_ARCH(riscv64)
