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

/* NOTE: changes to the arch_syscall_table layout may require changes to the
 *       generate_syscalls_perf.sh and arch-syscall-validate scripts */
struct arch_syscall_table {
	int name;
	int index;

	/* each arch listed here must be defined in syscalls.c  */
	/* NOTE: see the warning above - BEWARE! */
	int x86;
	int x86_64;
	int x32;
	int arm;
	int aarch64;
	int mips;
	int mips64;
	int mips64n32;
	int parisc;
	int parisc64;
	int ppc;
	int ppc64;
	int riscv64;
	int s390;
	int s390x;
};
#define OFFSET_ARCH(NAME) offsetof(struct arch_syscall_table, NAME)

/* defined in syscalls.perf.template  */
int syscall_resolve_name(const char *name, int offset);
const char *syscall_resolve_num(int num, int offset);
const struct arch_syscall_def *syscall_iterate(unsigned int spot, int offset);

/* helper functions for multiplexed syscalls, e.g. socketcall(2) and ipc(2) */
int abi_syscall_resolve_name_munge(const struct arch_def *arch,
				   const char *name);
const char *abi_syscall_resolve_num_munge(const struct arch_def *arch, int num);
int abi_syscall_rewrite(const struct arch_def *arch, int *syscall);
int abi_rule_add(struct db_filter *db, struct db_api_rule_list *rule);


#endif
