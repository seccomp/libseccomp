/**
 * Enhanced Seccomp Architecture/Machine Specific Code
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

#include <elf.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <asm/bitsperlong.h>
#include <linux/audit.h>

#include <seccomp.h>

#include "arch.h"
#include "arch-i386.h"
#include "arch-x86_64.h"
#include "arch-x32.h"
#include "arch-arm.h"
#include "system.h"

#if __i386__
const struct arch_def *arch_def_native = &arch_def_i386;
#elif __x86_64__
#ifdef __ILP32__
const struct arch_def *arch_def_native = &arch_def_x32;
#else
const struct arch_def *arch_def_native = &arch_def_x86_64;
#endif /* __ILP32__ */
#elif __arm__
const struct arch_def *arch_def_native = &arch_def_arm;
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
	switch (arch) {
	case SCMP_ARCH_X86:
	case SCMP_ARCH_X86_64:
	case SCMP_ARCH_X32:
	case SCMP_ARCH_ARM:
		return 0;
	}

	return -EINVAL;
}

/**
 * Lookup the syscall table for an architecture
 * @param token the architecure token
 *
 * Return the architecture's syscall table, returns NULL on failure.
 *
 */
static const struct arch_syscall_def *_arch_syscall_lookup(uint32_t token)
{
	switch (token) {
	case SCMP_ARCH_X86:
		return i386_syscall_table;
	case SCMP_ARCH_X86_64:
		return x86_64_syscall_table;
	case SCMP_ARCH_X32:
		return x32_syscall_table;
	case SCMP_ARCH_ARM:
		return arm_syscall_table;
	}

	return NULL;
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
		return &arch_def_i386;
	case SCMP_ARCH_X86_64:
		return &arch_def_x86_64;
	case SCMP_ARCH_X32:
		return &arch_def_x32;
	case SCMP_ARCH_ARM:
		return &arch_def_arm;
	}

	return NULL;
}

/**
 * Determine the maximum number of syscall arguments
 * @param arch the architecture definition
 *
 * Determine the maximum number of syscall arguments for the given architecture.
 * Returns the number of arguments on success, negative values on failure.
 *
 */
int arch_arg_count_max(const struct arch_def *arch)
{
	switch (arch->token) {
	case SCMP_ARCH_X86:
		return i386_arg_count_max;
	case SCMP_ARCH_X86_64:
		return x86_64_arg_count_max;
	case SCMP_ARCH_X32:
		return x32_arg_count_max;
	case SCMP_ARCH_ARM:
		return arm_arg_count_max;
	}

	return -EDOM;
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
	switch (arch->token) {
	case SCMP_ARCH_X86_64:
		return x86_64_arg_offset_lo(arg);
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
	switch (arch->token) {
	case SCMP_ARCH_X86_64:
		return x86_64_arg_offset_hi(arg);
	default:
		return -EDOM;
	}
}

/**
 * Resolve a syscall name to a number
 * @param arch the architecture definition
 * @param name the syscall name
 *
 * Resolve the given syscall name to the syscall number based on the given
 * architecture.  Returns the syscall number on success, including negative
 * pseudo syscall numbers; returns -1 on failure.
 *
 */
int arch_syscall_resolve_name(const struct arch_def *arch, const char *name)
{
	unsigned int iter;
	const struct arch_syscall_def *table;

	table = _arch_syscall_lookup(arch->token);
	if (table == NULL)
		return __NR_SCMP_ERROR;

	/* XXX - plenty of room for future improvement here */
	for (iter = 0; table[iter].name != NULL; iter++) {
		if (strcmp(name, table[iter].name) == 0)
			return table[iter].num;
	}

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
	unsigned int iter;
	const struct arch_syscall_def *table;

	table = _arch_syscall_lookup(arch->token);
	if (table == NULL)
		return NULL;

	/* XXX - plenty of room for future improvement here */
	for (iter = 0; table[iter].num != __NR_SCMP_ERROR; iter++) {
		if (num == table[iter].num)
			return table[iter].name;
	}

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
 * @param strict strict flag
 * @param syscall the syscall number
 *
 * Syscalls can vary across different architectures so this function rewrites
 * the syscall into the correct value for the specified architecture.  If
 * @strict is true then the function will fail if the syscall can not be
 * preservered, however, if @strict is false the function will do a "best
 * effort" rewrite and not fail. Returns zero on success, negative values on
 * failure.
 *
 */
int arch_syscall_rewrite(const struct arch_def *arch, unsigned int strict,
			 int *syscall)
{
	int sys = *syscall;

	if (sys >= 0) {
		/* we shouldn't be here - no rewrite needed */
		return 0;
	} else if (sys < 0 && sys > -100) {
		/* reserved values */
		return -EINVAL;
	} else if (sys <= -100 && sys > -10000) {
		/* rewritable syscalls */
		switch (arch->token) {
		case SCMP_ARCH_X86:
			return i386_syscall_rewrite(arch, strict, syscall);
		}
		/* NOTE: we fall through to the default handling (strict?) if
		 *       we don't support any rewriting for the architecture */
	}

	/* syscalls not defined on this architecture */
	if (strict)
		return -EDOM;
	return 0;
}

/**
 * Rewrite a filter rule to match the architecture specifics
 * @param arch the architecture definition
 * @param strict strict flag
 * @param syscall the syscall number
 * @param chain the argument filter chain
 *
 * Syscalls can vary across different architectures so this function handles
 * the necessary seccomp rule rewrites to ensure the right thing is done
 * regardless of the rule or architecture.  If @strict is true then the
 * function will fail if the entire filter can not be preservered, however,
 * if @strict is false the function will do a "best effort" rewrite and not
 * fail.  Returns zero on success, negative values on failure.
 *
 */
int arch_filter_rewrite(const struct arch_def *arch,
			unsigned int strict,
			int *syscall, struct db_api_arg *chain)
{
	int sys = *syscall;

	if (sys >= 0) {
		/* we shouldn't be here - no rewrite needed */
		return 0;
	} else if (sys < 0 && sys > -100) {
		/* reserved values */
		return -EINVAL;
	} else if (sys <= -100 && sys > -10000) {
		/* rewritable syscalls */
		switch (arch->token) {
		case SCMP_ARCH_X86:
			return i386_filter_rewrite(arch,
						   strict, syscall, chain);
		}
		/* NOTE: we fall through to the default handling (strict?) if
		 *       we don't support any rewriting for the architecture */
	}

	/* syscalls not defined on this architecture */
	if (strict)
		return -EDOM;
	return 0;
}
