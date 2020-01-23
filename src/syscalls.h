/**
 * Enhanced Seccomp x86_64 Syscall Table
 *
 * Copyright (c) 2012, 2020 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <paul@paul-moore.com>
 * gperf support: Giuseppe Scrivano <gscrivan@redhat.com>
 */

#ifndef _SYSCALLS_H
#define _SYSCALLS_H

#include <stddef.h>

#include "arch-aarch64.h"
#include "arch-arm.h"
#include "arch.h"
#include "arch-mips64.h"
#include "arch-mips64n32.h"
#include "arch-mips.h"
#include "arch-parisc.h"
#include "arch-ppc64.h"
#include "arch-ppc.h"
#include "arch-s390.h"
#include "arch-s390x.h"
#include "arch-x32.h"
#include "arch-x86_64.h"
#include "arch-x86.h"
#include "arch-x86.h"
#include "arch-riscv64.h"

struct arch_syscall_def_internal {
	int name;
	/* Each arch listed here must be defined in syscalls.c  */
	int x86_64;
	int arm;
	int aarch64;
	int mips64n32;
	int mips64;
	int mips;
	int parisc;
	int ppc64;
	int ppc;
	int s390;
	int s390x;
	int x32;
	int x86;
	int riscv64;

	int index;
};

#define OFFSET_ARCH(NAME) offsetof(struct arch_syscall_def_internal, NAME)

/* Defined in syscalls.perf.template  */
int syscall_resolve_name(const char *name, int offset);
const char *syscall_resolve_num(int num, int offset);
const struct arch_syscall_def *syscall_iterate(unsigned int spot, int offset);

#endif
