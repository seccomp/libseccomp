/*
 * Copyright 2015 IBM
 * Author: Jan Willeke <willeke@linux.vnet.com.com>
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <linux/audit.h>

#include "arch.h"
#include "arch-s390.h"

/* s390 syscall numbers */
#define __s390_NR_socketcall		102
#define __s390_NR_ipc			117

const struct arch_def arch_def_s390 = {
	.token = SCMP_ARCH_S390,
	.token_bpf = AUDIT_ARCH_S390,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_BIG,
	.syscall_resolve_name = s390_syscall_resolve_name,
	.syscall_resolve_num = s390_syscall_resolve_num,
	.syscall_rewrite = s390_syscall_rewrite,
	.rule_add = s390_rule_add,
};

/**
 * Convert a multiplexed pseudo socket syscall into a direct syscall
 * @param socketcall the multiplexed pseudo syscall number
 *
 * Return the related direct syscall number, __NR_SCMP_UNDEF is there is
 * no related syscall, or __NR_SCMP_ERROR otherwise.
 *
 */
int _s390_sock_demux(int socketcall)
{
	switch (socketcall) {
	case -101:
		/* socket */
		return 359;
	case -102:
		/* bind */
		return 361;
	case -103:
		/* connect */
		return 362;
	case -104:
		/* listen */
		return 363;
	case -105:
		/* accept - not defined */
		return __NR_SCMP_UNDEF;
	case -106:
		/* getsockname */
		return 367;
	case -107:
		/* getpeername */
		return 368;
	case -108:
		/* socketpair */
		return 360;
	case -109:
		/* send - not defined */
		return __NR_SCMP_UNDEF;
	case -110:
		/* recv - not defined */
		return __NR_SCMP_UNDEF;
	case -111:
		/* sendto */
		return 369;
	case -112:
		/* recvfrom */
		return 371;
	case -113:
		/* shutdown */
		return 373;
	case -114:
		/* setsockopt */
		return 366;
	case -115:
		/* getsockopt */
		return 365;
	case -116:
		/* sendmsg */
		return 370;
	case -117:
		/* recvmsg */
		return 372;
	case -118:
		/* accept4 */
		return 364;
	case -119:
		/* recvmmsg */
		return 337;
	case -120:
		/* sendmmsg */
		return 345;
	}

	return __NR_SCMP_ERROR;
}

/**
 * Convert a direct socket syscall into multiplexed pseudo socket syscall
 * @param syscall the direct syscall
 *
 * Return the related multiplexed pseduo syscall number, __NR_SCMP_UNDEF is
 * there is no related pseudo syscall, or __NR_SCMP_ERROR otherwise.
 *
 */
int _s390_sock_mux(int syscall)
{
	switch (syscall) {
	case 337:
		/* recvmmsg */
		return -119;
	case 345:
		/* sendmmsg */
		return -120;
	case 359:
		/* socket */
		return -101;
	case 360:
		/* socketpair */
		return -108;
	case 361:
		/* bind */
		return -102;
	case 362:
		/* connect */
		return -103;
	case 363:
		/* listen */
		return -104;
	case 364:
		/* accept4 */
		return -118;
	case 365:
		/* getsockopt */
		return -115;
	case 366:
		/* setsockopt */
		return -114;
	case 367:
		/* getsockname */
		return -106;
	case 368:
		/* getpeername */
		return -107;
	case 369:
		/* sendto */
		return -111;
	case 370:
		/* sendmsg */
		return -116;
	case 371:
		/* recvfrom */
		return -112;
	case 372:
		/* recvmsg */
		return -117;
	case 373:
		/* shutdown */
		return -113;
	}

	return __NR_SCMP_ERROR;
}

/**
 * Rewrite a syscall value to match the architecture
 * @param syscall the syscall number
 *
 * Syscalls can vary across different architectures so this function rewrites
 * the syscall into the correct value for the specified architecture.  Returns
 * zero on success, negative values on failure.
 *
 */
int s390_syscall_rewrite(int *syscall)
{
	int sys = *syscall;

	if (sys <= -100 && sys >= -120)
		*syscall = __s390_NR_socketcall;
	else if (sys <= -200 && sys >= -224)
		*syscall = __s390_NR_ipc;
	else if (sys < 0)
		return -EDOM;

	return 0;
}

/**
 * add a new rule to the s390 seccomp filter
 * @param col the filter collection
 * @param db the seccomp filter db
 * @param strict the strict flag
 * @param rule the filter rule
 *
 * This function adds a new syscall filter to the seccomp filter db, making any
 * necessary adjustments for the s390 ABI.  Returns zero on success, negative
 * values on failure.
 *
 */
int s390_rule_add(struct db_filter_col *col, struct db_filter *db, bool strict,
		  struct db_api_rule_list *rule)
{
	int rc;
	unsigned int iter;
	int sys = rule->syscall;
	int sys_a, sys_b;
	struct db_api_rule_list *rule_a, *rule_b;

	if ((sys <= -100 && sys >= -120) || (sys >= 359 && sys <= 373)) {
		/* (-100 to -120) : multiplexed socket syscalls
		   (359 to 373)   : direct socket syscalls, Linux 4.3+ */

		/* strict check for the multiplexed socket syscalls */
		for (iter = 0; iter < ARG_COUNT_MAX; iter++) {
			if ((rule->args[iter].valid != 0) && (strict))
				return -EINVAL;
		}

		/* determine both the muxed and direct syscall numbers */
		if (sys > 0) {
			sys_a = _s390_sock_mux(sys);
			if (sys_a == __NR_SCMP_ERROR)
				return __NR_SCMP_ERROR;
			sys_b = sys;
		} else {
			sys_a = sys;
			sys_b = _s390_sock_demux(sys);
			if (sys_b == __NR_SCMP_ERROR)
				return __NR_SCMP_ERROR;
		}

		/* use rule_a for the multiplexed syscall and use rule_b for
		 * the direct wired syscall */

		if (sys_a == __NR_SCMP_UNDEF) {
			rule_a = NULL;
			rule_b = rule;
		} else if (sys_b == __NR_SCMP_UNDEF) {
			rule_a = rule;
			rule_b = NULL;
		} else {
			/* need two rules, dup the first and link together */
			rule_a = rule;
			rule_b = db_rule_dup(rule_a);
			if (rule_b == NULL)
				return -ENOMEM;
			rule_b->prev = rule_a;
			rule_b->next = NULL;
			rule_a->next = rule_b;
		}

		/* multiplexed socket syscalls */
		if (rule_a != NULL) {
			rule_a->syscall = __s390_NR_socketcall;
			rule_a->args[0].arg = 0;
			rule_a->args[0].op = SCMP_CMP_EQ;
			rule_a->args[0].mask = DATUM_MAX;
			rule_a->args[0].datum = (-sys_a) % 100;
			rule_a->args[0].valid = 1;
		}

		/* direct wired socket syscalls */
		if (rule_b != NULL)
			rule_b->syscall = sys_b;

		/* add the rules as a single transaction */
		rc = db_col_transaction_start(col);
		if (rc < 0)
			return rc;
		if (rule_a != NULL) {
			rc = db_rule_add(db, rule_a);
			if (rc < 0)
				goto fail_transaction;
		}
		if (rule_b != NULL) {
			rc = db_rule_add(db, rule_b);
			if (rc < 0)
				goto fail_transaction;
		}
		db_col_transaction_commit(col);
	} else if (sys <= -200 && sys >= -224) {
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
		rule->syscall = __s390_NR_ipc;

		rc = db_rule_add(db, rule);
		if (rc < 0)
			return rc;
	} else if (sys >= 0) {
		/* normal syscall processing */
		rc = db_rule_add(db, rule);
		if (rc < 0)
			return rc;
	} else if (strict)
		return -EDOM;

	return 0;

fail_transaction:
	db_col_transaction_abort(col);
	return rc;
}
