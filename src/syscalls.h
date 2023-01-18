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
#include <seccomp.h>

#include "arch-aarch64.h"
#include "arch-arm.h"
#include "arch.h"
#include "arch-loongarch64.h"
#include "arch-m68k.h"
#include "arch-mips64.h"
#include "arch-mips64n32.h"
#include "arch-mips.h"
#include "arch-parisc.h"
#include "arch-ppc64.h"
#include "arch-ppc.h"
#include "arch-s390.h"
#include "arch-s390x.h"
#include "arch-sh.h"
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
	enum scmp_kver x86_kver;
	int x86_64;
	enum scmp_kver x86_64_kver;
	int x32;
	enum scmp_kver x32_kver;

	int arm;
	enum scmp_kver arm_kver;
	int aarch64;
	enum scmp_kver aarch64_kver;

	int loongarch64;
	enum scmp_kver loongarch64_kver;

	int m68k;
	enum scmp_kver m68k_kver;

	int mips;
	enum scmp_kver mips_kver;
	int mips64;
	enum scmp_kver mips64_kver;
	int mips64n32;
	enum scmp_kver mips64n32_kver;

	int parisc;
	enum scmp_kver parisc_kver;
	int parisc64;
	enum scmp_kver parisc64_kver;

	int ppc;
	enum scmp_kver ppc_kver;
	int ppc64;
	enum scmp_kver ppc64_kver;

	int riscv64;
	enum scmp_kver riscv64_kver;

	int s390;
	enum scmp_kver s390_kver;
	int s390x;
	enum scmp_kver s390x_kver;

	int sh;
	enum scmp_kver sh_kver;
};
#define SYSTBL_OFFSET(NAME) offsetof(struct arch_syscall_table, NAME)

/* defined in syscalls.perf.template  */
int syscall_resolve_name(const char *name, int offset);
const char *syscall_resolve_num(int num, int offset);
enum scmp_kver syscall_resolve_name_kver(const char *name, int offset_kver);
enum scmp_kver syscall_resolve_num_kver(int num,
					int offset_arch, int offset_kver);
const struct arch_syscall_def *syscall_iterate(unsigned int spot, int offset);

/* helper functions for multiplexed syscalls, e.g. socketcall(2) and ipc(2) */
int abi_syscall_resolve_name_munge(const struct arch_def *arch,
				   const char *name);
const char *abi_syscall_resolve_num_munge(const struct arch_def *arch, int num);
int abi_syscall_rewrite(const struct arch_def *arch, int *syscall);
int abi_rule_add(struct db_filter *db, struct db_api_rule_list *rule);


#endif
