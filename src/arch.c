/**
 * Enhanced Seccomp Architecture/Machine Specific Code
 *
 * Copyright (c) 2012,2018 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <paul@paul-moore.com>
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

#include <elf.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <asm/bitsperlong.h>
#include <linux/audit.h>
#include <stdbool.h>

#include <seccomp.h>

#include "arch.h"
#include "arch-x86.h"
#include "arch-x86_64.h"
#include "arch-x32.h"
#include "arch-arm.h"
#include "arch-aarch64.h"
#include "arch-mips.h"
#include "arch-mips64.h"
#include "arch-mips64n32.h"
#include "arch-parisc.h"
#include "arch-parisc64.h"
#include "arch-ppc.h"
#include "arch-ppc64.h"
#include "arch-riscv64.h"
#include "arch-s390.h"
#include "arch-s390x.h"
#include "db.h"
#include "system.h"

#define default_arg_offset(x)		(offsetof(struct seccomp_data, args[x]))

#if __i386__
const struct arch_def *arch_def_native = &arch_def_x86;
#elif __x86_64__
#ifdef __ILP32__
const struct arch_def *arch_def_native = &arch_def_x32;
#else
const struct arch_def *arch_def_native = &arch_def_x86_64;
#endif /* __ILP32__ */
#elif __arm__
const struct arch_def *arch_def_native = &arch_def_arm;
#elif __aarch64__
const struct arch_def *arch_def_native = &arch_def_aarch64;
#elif __mips__ && _MIPS_SIM == _MIPS_SIM_ABI32
#if __MIPSEB__
const struct arch_def *arch_def_native = &arch_def_mips;
#elif __MIPSEL__
const struct arch_def *arch_def_native = &arch_def_mipsel;
#endif /* _MIPS_SIM_ABI32 */
#elif __mips__ && _MIPS_SIM == _MIPS_SIM_ABI64
#if __MIPSEB__
const struct arch_def *arch_def_native = &arch_def_mips64;
#elif __MIPSEL__
const struct arch_def *arch_def_native = &arch_def_mipsel64;
#endif /* _MIPS_SIM_ABI64 */
#elif __mips__ && _MIPS_SIM == _MIPS_SIM_NABI32
#if __MIPSEB__
const struct arch_def *arch_def_native = &arch_def_mips64n32;
#elif __MIPSEL__
const struct arch_def *arch_def_native = &arch_def_mipsel64n32;
#endif /* _MIPS_SIM_NABI32 */
#elif __hppa64__ /* hppa64 must be checked before hppa */
const struct arch_def *arch_def_native = &arch_def_parisc64;
#elif __hppa__
const struct arch_def *arch_def_native = &arch_def_parisc;
#elif __PPC64__
#ifdef __BIG_ENDIAN__
const struct arch_def *arch_def_native = &arch_def_ppc64;
#else
const struct arch_def *arch_def_native = &arch_def_ppc64le;
#endif
#elif __PPC__
const struct arch_def *arch_def_native = &arch_def_ppc;
#elif __s390x__ /* s390x must be checked before s390 */
const struct arch_def *arch_def_native = &arch_def_s390x;
#elif __s390__
const struct arch_def *arch_def_native = &arch_def_s390;
#elif __riscv && __riscv_xlen == 64
const struct arch_def *arch_def_native = &arch_def_riscv64;
#else
#error the arch code needs to know about your machine type
#endif /* machine type guess */

/**
 * Validate the architecture token
 * @param arch the architecture token
 *
 * Verify the given architecture token; return zero if valid, -EINVAL if not.
 *
 */
int arch_valid(uint32_t arch)
{
	return (arch_def_lookup(arch) ? 0 : -EINVAL);
}

/**
 * Lookup the architecture definition
 * @param token the architecure token
 *
 * Return the matching architecture definition, returns NULL on failure.
 *
 */
const struct arch_def *arch_def_lookup(uint32_t token)
{
	switch (token) {
	case SCMP_ARCH_X86:
		return &arch_def_x86;
	case SCMP_ARCH_X86_64:
		return &arch_def_x86_64;
	case SCMP_ARCH_X32:
		return &arch_def_x32;
	case SCMP_ARCH_ARM:
		return &arch_def_arm;
	case SCMP_ARCH_AARCH64:
		return &arch_def_aarch64;
	case SCMP_ARCH_MIPS:
		return &arch_def_mips;
	case SCMP_ARCH_MIPSEL:
		return &arch_def_mipsel;
	case SCMP_ARCH_MIPS64:
		return &arch_def_mips64;
	case SCMP_ARCH_MIPSEL64:
		return &arch_def_mipsel64;
	case SCMP_ARCH_MIPS64N32:
		return &arch_def_mips64n32;
	case SCMP_ARCH_MIPSEL64N32:
		return &arch_def_mipsel64n32;
	case SCMP_ARCH_PARISC:
		return &arch_def_parisc;
	case SCMP_ARCH_PARISC64:
		return &arch_def_parisc64;
	case SCMP_ARCH_PPC:
		return &arch_def_ppc;
	case SCMP_ARCH_PPC64:
		return &arch_def_ppc64;
	case SCMP_ARCH_PPC64LE:
		return &arch_def_ppc64le;
	case SCMP_ARCH_S390:
		return &arch_def_s390;
	case SCMP_ARCH_S390X:
		return &arch_def_s390x;
	case SCMP_ARCH_RISCV64:
		return &arch_def_riscv64;
	}

	return NULL;
}

/**
 * Lookup the architecture definition by name
 * @param arch_name the architecure name
 *
 * Return the matching architecture definition, returns NULL on failure.
 *
 */
const struct arch_def *arch_def_lookup_name(const char *arch_name)
{
	if (strcmp(arch_name, "x86") == 0)
		return &arch_def_x86;
	else if (strcmp(arch_name, "x86_64") == 0)
		return &arch_def_x86_64;
	else if (strcmp(arch_name, "x32") == 0)
		return &arch_def_x32;
	else if (strcmp(arch_name, "arm") == 0)
		return &arch_def_arm;
	else if (strcmp(arch_name, "aarch64") == 0)
		return &arch_def_aarch64;
	else if (strcmp(arch_name, "mips") == 0)
		return &arch_def_mips;
	else if (strcmp(arch_name, "mipsel") == 0)
		return &arch_def_mipsel;
	else if (strcmp(arch_name, "mips64") == 0)
		return &arch_def_mips64;
	else if (strcmp(arch_name, "mipsel64") == 0)
		return &arch_def_mipsel64;
	else if (strcmp(arch_name, "mips64n32") == 0)
		return &arch_def_mips64n32;
	else if (strcmp(arch_name, "mipsel64n32") == 0)
		return &arch_def_mipsel64n32;
	else if (strcmp(arch_name, "parisc64") == 0)
		return &arch_def_parisc64;
	else if (strcmp(arch_name, "parisc") == 0)
		return &arch_def_parisc;
	else if (strcmp(arch_name, "ppc") == 0)
		return &arch_def_ppc;
	else if (strcmp(arch_name, "ppc64") == 0)
		return &arch_def_ppc64;
	else if (strcmp(arch_name, "ppc64le") == 0)
		return &arch_def_ppc64le;
	else if (strcmp(arch_name, "s390") == 0)
		return &arch_def_s390;
	else if (strcmp(arch_name, "s390x") == 0)
		return &arch_def_s390x;
	else if (strcmp(arch_name, "riscv64") == 0)
		return &arch_def_riscv64;

	return NULL;
}

/**
 * Determine the argument offset for the lower 32 bits
 * @param arch the architecture definition
 * @param arg the argument number
 *
 * Determine the correct offset for the low 32 bits of the given argument based
 * on the architecture definition.  Returns the offset on success, negative
 * values on failure.
 *
 */
int arch_arg_offset_lo(const struct arch_def *arch, unsigned int arg)
{
	if (arch_valid(arch->token) < 0)
		return -EDOM;

	switch (arch->endian) {
	case ARCH_ENDIAN_LITTLE:
		return default_arg_offset(arg);
		break;
	case ARCH_ENDIAN_BIG:
		return default_arg_offset(arg) + 4;
		break;
	default:
		return -EDOM;
	}
}

/**
 * Determine the argument offset for the high 32 bits
 * @param arch the architecture definition
 * @param arg the argument number
 *
 * Determine the correct offset for the high 32 bits of the given argument
 * based on the architecture definition.  Returns the offset on success,
 * negative values on failure.
 *
 */
int arch_arg_offset_hi(const struct arch_def *arch, unsigned int arg)
{
	if (arch_valid(arch->token) < 0 || arch->size != ARCH_SIZE_64)
		return -EDOM;

	switch (arch->endian) {
	case ARCH_ENDIAN_LITTLE:
		return default_arg_offset(arg) + 4;
		break;
	case ARCH_ENDIAN_BIG:
		return default_arg_offset(arg);
		break;
	default:
		return -EDOM;
	}
}

/**
 * Determine the argument offset
 * @param arch the architecture definition
 * @param arg the argument number
 *
 * Determine the correct offset for the given argument based on the
 * architecture definition.  Returns the offset on success, negative values on
 * failure.
 *
 */
int arch_arg_offset(const struct arch_def *arch, unsigned int arg)
{
	return arch_arg_offset_lo(arch, arg);
}

/**
 * Resolve a syscall name to a number
 * @param arch the architecture definition
 * @param name the syscall name
 *
 * Resolve the given syscall name to the syscall number based on the given
 * architecture.  Returns the syscall number on success, including negative
 * pseudo syscall numbers; returns __NR_SCMP_ERROR on failure.
 *
 */
int arch_syscall_resolve_name(const struct arch_def *arch, const char *name)
{
	if (arch->syscall_resolve_name)
		return (*arch->syscall_resolve_name)(arch, name);
	if (arch->syscall_resolve_name_raw)
		return (*arch->syscall_resolve_name_raw)(name);

	return __NR_SCMP_ERROR;
}

/**
 * Resolve a syscall number to a name
 * @param arch the architecture definition
 * @param num the syscall number
 *
 * Resolve the given syscall number to the syscall name based on the given
 * architecture.  Returns a pointer to the syscall name string on success,
 * including pseudo syscall names; returns NULL on failure.
 *
 */
const char *arch_syscall_resolve_num(const struct arch_def *arch, int num)
{
	if (arch->syscall_resolve_num)
		return (*arch->syscall_resolve_num)(arch, num);
	if (arch->syscall_resolve_num_raw)
		return (*arch->syscall_resolve_num_raw)(num);

	return NULL;
}

/**
 * Translate the syscall number
 * @param arch the architecture definition
 * @param syscall the syscall number
 *
 * Translate the syscall number, in the context of the native architecure, to
 * the provided architecure.  Returns zero on success, negative values on
 * failure.
 *
 */
int arch_syscall_translate(const struct arch_def *arch, int *syscall)
{
	int sc_num;
	const char *sc_name;

	/* special handling for syscall -1 */
	if (*syscall == -1)
		return 0;

	if (arch->token != arch_def_native->token) {
		sc_name = arch_syscall_resolve_num(arch_def_native, *syscall);
		if (sc_name == NULL)
			return -EFAULT;

		sc_num = arch_syscall_resolve_name(arch, sc_name);
		if (sc_num == __NR_SCMP_ERROR)
			return -EFAULT;

		*syscall = sc_num;
	}

	return 0;
}

/**
 * Rewrite a syscall value to match the architecture
 * @param arch the architecture definition
 * @param syscall the syscall number
 *
 * Syscalls can vary across different architectures so this function rewrites
 * the syscall into the correct value for the specified architecture. Returns
 * zero on success, -EDOM if the syscall is not defined for @arch, and negative
 * values on failure.
 *
 */
int arch_syscall_rewrite(const struct arch_def *arch, int *syscall)
{
	int sys = *syscall;

	if (sys >= -1) {
		/* we shouldn't be here - no rewrite needed */
		return 0;
	} else if (sys > -100) {
		/* -2 to -99 are reserved values */
		return -EINVAL;
	} else if (sys > -10000) {
		/* rewritable syscalls */
		if (arch->syscall_rewrite)
			(*arch->syscall_rewrite)(arch, syscall);
	}

	/* syscalls not defined on this architecture */
	if ((*syscall) < 0)
		return -EDOM;
	return 0;
}

/**
 * Add a new rule to the specified filter
 * @param db the seccomp filter db
 * @param strict the rule
 *
 * This function adds a new argument/comparison/value to the seccomp filter for
 * a syscall; multiple arguments can be specified and they will be chained
 * together (essentially AND'd together) in the filter.  When the strict flag
 * is true the function will fail if the exact rule can not be added to the
 * filter, if the strict flag is false the function will not fail if the
 * function needs to adjust the rule due to architecture specifics.  Returns
 * zero on success, negative values on failure.
 *
 * It is important to note that in the case of failure the db may be corrupted,
 * the caller must use the transaction mechanism if the db integrity is
 * important.
 *
 */
int arch_filter_rule_add(struct db_filter *db,
			 const struct db_api_rule_list *rule)
{
	int rc = 0;
	int syscall;
	struct db_api_rule_list *rule_dup = NULL;

	/* create our own rule that we can munge */
	rule_dup = db_rule_dup(rule);
	if (rule_dup == NULL)
		return -ENOMEM;

	/* translate the syscall */
	rc = arch_syscall_translate(db->arch, &rule_dup->syscall);
	if (rc < 0)
		goto rule_add_return;
	syscall = rule_dup->syscall;

	/* add the new rule to the existing filter */
	if (syscall == -1 || db->arch->rule_add == NULL) {
		/* syscalls < -1 require a db->arch->rule_add() function */
		if (syscall < -1 && rule_dup->strict) {
			rc = -EDOM;
			goto rule_add_return;
		}
		rc = db_rule_add(db, rule_dup);
	} else
		rc = (db->arch->rule_add)(db, rule_dup);

rule_add_return:
	/* NOTE: another reminder that we don't do any db error recovery here,
	 * use the transaction mechanism as previously mentioned */
	if (rule_dup != NULL)
		free(rule_dup);
	return rc;
}
