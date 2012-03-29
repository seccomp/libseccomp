/**
 * Enhanced Seccomp Architecture/Machine Specific Code
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
 */

/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <stdlib.h>
#include <asm/bitsperlong.h>
#include <linux/audit.h>

#include "arch.h"
#include "arch-i386.h"
#include "arch-x86_64.h"

const struct arch_def arch_def_native = {
#if __i386__
	.token = AUDIT_ARCH_I386,
#elif __x86_64__
	.token = AUDIT_ARCH_X86_64,
#else
#error the arch code needs to know about your machine type
#endif /* machine type guess */

#if __BITS_PER_LONG == 32
	.size = ARCH_SIZE_32,
#elif __BITS_PER_LONG == 64
	.size = ARCH_SIZE_64,
#else
	.size = ARCH_SIZE_UNSPEC,
#endif /* BITS_PER_LONG */

#if __BYTE_ORDER == __LITTLE_ENDIAN
	.endian = ARCH_ENDIAN_LITTLE,
#elif __BYTE_ORDER == __BIG_ENDIAN
	.endian = ARCH_ENDIAN_BIG,
#else
	.endian = ARCH_ENDIAN_UNSPEC,
#endif /* __BYTE_ORDER */
};

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
	case AUDIT_ARCH_I386:
		return i386_arg_count_max;
	case AUDIT_ARCH_X86_64:
		return x86_64_arg_count_max;
	default:
		return -EDOM;
	}
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
	case AUDIT_ARCH_I386:
		return i386_arg_offset_lo(arg);
	case AUDIT_ARCH_X86_64:
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
	case AUDIT_ARCH_X86_64:
		return x86_64_arg_offset_hi(arg);
	default:
		return -EDOM;
	}
}

/**
 * Determine the argument offset
 * @param arch the architecture definition
 * @param arg the argument number
 *
 * Determine the correct offset of the given argument based on the architecture
 * definition.  Returns the offset on success, negative values on failure.
 *
 */
int arch_arg_offset(const struct arch_def *arch, unsigned int arg)
{
	switch (arch->token) {
	case AUDIT_ARCH_I386:
		return i386_arg_offset(arg);
	case AUDIT_ARCH_X86_64:
		return x86_64_arg_offset(arg);
	default:
		return -EDOM;
	}
}

/**
 * Rewrite a syscall value to match the architecture
 * @param arch the architecture definition
 * @param syscall the syscall number
 *
 * Syscalls can vary across different architectures so this function rewrites
 * the syscall into the correct value for the specified architecture.  Returns
 * zero on success, negative values on failure.
 *
 */
int arch_syscall_rewrite(const struct arch_def *arch, int *syscall)
{
	switch (arch->token) {
	case AUDIT_ARCH_I386:
		return i386_syscall_rewrite(arch, syscall);
	default:
		return -EDOM;
	}
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
	switch (arch->token) {
	case AUDIT_ARCH_I386:
		return i386_filter_rewrite(arch, strict, syscall, chain);
	default:
		return -EDOM;
	}
}
