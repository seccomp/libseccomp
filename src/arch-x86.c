/**
 * Enhanced Seccomp x86 Specific Code
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

#include <stdlib.h>
#include <errno.h>
#include <linux/audit.h>

#include "arch.h"
#include "arch-x86.h"

/* x86 syscall numbers */
#define __x86_NR_socketcall		102
#define __x86_NR_ipc			117

const struct arch_def arch_def_x86 = {
	.token = SCMP_ARCH_X86,
	.token_bpf = AUDIT_ARCH_I386,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_LITTLE,
	.syscall_resolve_name = x86_syscall_resolve_name,
	.syscall_resolve_num = x86_syscall_resolve_num,
	.syscall_rewrite = x86_syscall_rewrite,
	.rule_add = x86_rule_add,
};

/**
 * Rewrite a syscall value to match the architecture
 * @param syscall the syscall number
 *
 * Syscalls can vary across different architectures so this function rewrites
 * the syscall into the correct value for the specified architecture.  Returns
 * zero on success, negative values on failure.
 *
 */
int x86_syscall_rewrite(int *syscall)
{
	int sys = *syscall;

	if (sys <= -100 && sys >= -117)
		*syscall = __x86_NR_socketcall;
	else if (sys <= -200 && sys >= -211)
		*syscall = __x86_NR_ipc;
	else if (sys < 0)
		return -EDOM;

	return 0;
}

/**
 * add a new rule to the x86 seccomp filter
 * @param db the seccomp filter db
 * @param strict the strict flag
 * @param rule the filter rule
 *
 * This function adds a new syscall filter to the seccomp filter db, making any
 * necessary adjustments for the x86 ABI.  Returns zero on success, negative
 * values on failure.
 *
 */
int x86_rule_add(struct db_filter *db, bool strict,
		 struct db_api_rule_list *rule)
{
	int rc;
	unsigned int iter;
	int sys = rule->syscall;

	if (sys >= 0) {
		/* normal syscall processing */
		rc = db_rule_add(db, rule);
		if (rc < 0)
			return rc;
	} else if (sys <= -100 && sys >= -117) {
		/* multiplexed socket syscalls */
		for (iter = 0; iter < ARG_COUNT_MAX; iter++) {
			if ((rule->args[iter].valid != 0) && (strict))
				return -EINVAL;
		}
		rule->args[0].arg = 0;
		rule->args[0].op = SCMP_CMP_EQ;
		rule->args[0].mask = DATUM_MAX;
		rule->args[0].datum = abs(sys) % 100;
		rule->args[0].valid = 1;
		rule->syscall = __x86_NR_socketcall;

		rc = db_rule_add(db, rule);
		if (rc < 0)
			return rc;
	} else if (sys <= -200 && sys >= -211) {
		/* multiplexed ipc syscalls */
		for (iter = 0; iter < ARG_COUNT_MAX; iter++) {
			if ((rule->args[iter].valid != 0) && (strict))
				return -EINVAL;
		}
		rule->args[0].arg = 0;
		rule->args[0].op = SCMP_CMP_EQ;
		rule->args[0].mask = DATUM_MAX;
		rule->args[0].datum = abs(sys) % 200;
		rule->args[0].valid = 1;
		rule->syscall = __x86_NR_ipc;

		rc = db_rule_add(db, rule);
		if (rc < 0)
			return rc;
	} else if (strict)
		return -EDOM;

	return 0;
}
