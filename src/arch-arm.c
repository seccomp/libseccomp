/**
 * Enhanced Seccomp ARM Specific Code
 *
 * Copyright (c) 2013 Red Hat <pmoore@redhat.com>
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

#include <stdlib.h>
#include <errno.h>
#include <linux/audit.h>

#include "arch.h"
#include "arch-arm.h"

#define __SCMP_NR_OABI_SYSCALL_BASE     0x900000
#define __SCMP_ARM_NR_BASE              0x0f0000

/* NOTE: we currently only support the ARM EABI, more info at the URL below:
 *       -> http://wiki.embeddedarm.com/wiki/EABI_vs_OABI */
#if 1
#define __SCMP_NR_BASE                  0
#else
#define __SCMP_NR_BASE                  __SCMP_NR_OABI_SYSCALL_BASE
#endif

/**
 * Resolve a syscall name to a number
 * @param name the syscall name
 *
 * Resolve the given syscall name to the syscall number using the syscall table.
 * Returns the syscall number on success, including negative pseudo syscall
 * numbers; returns __NR_SCMP_ERROR on failure.
 *
 */
int arm_syscall_resolve_name_munge(const char *name)
{
	int sys;

	/* NOTE: we don't want to modify the pseudo-syscall numbers */
	sys = arm_syscall_resolve_name(name);
	if (sys == __NR_SCMP_ERROR || sys < 0)
		return sys;

	return (sys | __SCMP_NR_BASE);
}

/**
 * Resolve a syscall number to a name
 * @param num the syscall number
 *
 * Resolve the given syscall number to the syscall name using the syscall table.
 * Returns a pointer to the syscall name string on success, including pseudo
 * syscall names; returns NULL on failure.
 *
 */
const char *arm_syscall_resolve_num_munge(int num)
{
	/* NOTE: we don't want to modify the pseudo-syscall numbers */
	if (num >= 0)
		num &= ~__SCMP_NR_BASE;
	return arm_syscall_resolve_num(num);
}

const struct arch_def arch_def_arm = {
	.token = SCMP_ARCH_ARM,
	.token_bpf = AUDIT_ARCH_ARM,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_LITTLE,
	.syscall_resolve_name = arm_syscall_resolve_name_munge,
	.syscall_resolve_num = arm_syscall_resolve_num_munge,
	.syscall_rewrite = NULL,
	.rule_add = NULL,
};
