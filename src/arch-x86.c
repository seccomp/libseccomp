/**
 * Enhanced Seccomp x86 Specific Code
 *
 * Copyright (c) 2012,2016 Red Hat <pmoore@redhat.com>
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
#include <string.h>
#include <linux/audit.h>

#include "db.h"
#include "syscalls.h"
#include "arch.h"
#include "arch-x86.h"

/* x86 syscall numbers */
#define __x86_NR_socketcall		102
#define __x86_NR_ipc			117

/**
 * Resolve a syscall name to a number
 * @param name the syscall name
 *
 * Resolve the given syscall name to the syscall number using the syscall table.
 * Returns the syscall number on success, including negative pseudo syscall
 * numbers; returns __NR_SCMP_ERROR on failure.
 *
 */
int x86_syscall_resolve_name_munge(const char *name)
{
	if (strcmp(name, "accept") == 0)
		return __PNR_accept;
	else if (strcmp(name, "accept4") == 0)
		return __PNR_accept4;
	else if (strcmp(name, "bind") == 0)
		return __PNR_bind;
	else if (strcmp(name, "connect") == 0)
		return __PNR_connect;
	else if (strcmp(name, "getpeername") == 0)
		return __PNR_getpeername;
	else if (strcmp(name, "getsockname") == 0)
		return __PNR_getsockname;
	else if (strcmp(name, "getsockopt") == 0)
		return __PNR_getsockopt;
	else if (strcmp(name, "listen") == 0)
		return __PNR_listen;
	else if (strcmp(name, "recv") == 0)
		return __PNR_recv;
	else if (strcmp(name, "recvfrom") == 0)
		return __PNR_recvfrom;
	else if (strcmp(name, "recvmsg") == 0)
		return __PNR_recvmsg;
	else if (strcmp(name, "recvmmsg") == 0)
		return __PNR_recvmmsg;
	else if (strcmp(name, "send") == 0)
		return __PNR_send;
	else if (strcmp(name, "sendmsg") == 0)
		return __PNR_sendmsg;
	else if (strcmp(name, "sendmmsg") == 0)
		return __PNR_sendmmsg;
	else if (strcmp(name, "sendto") == 0)
		return __PNR_sendto;
	else if (strcmp(name, "setsockopt") == 0)
		return __PNR_setsockopt;
	else if (strcmp(name, "shutdown") == 0)
		return __PNR_shutdown;
	else if (strcmp(name, "socket") == 0)
		return __PNR_socket;
	else if (strcmp(name, "socketpair") == 0)
		return __PNR_socketpair;

	if (strcmp(name, "semop") == 0)
		return __PNR_semop;
	else if (strcmp(name, "semget") == 0)
		return __PNR_semget;
	else if (strcmp(name, "semctl") == 0)
		return __PNR_semctl;
	else if (strcmp(name, "semtimedop") == 0)
		return __PNR_semtimedop;
	else if (strcmp(name, "msgsnd") == 0)
		return __PNR_msgsnd;
	else if (strcmp(name, "msgrcv") == 0)
		return __PNR_msgrcv;
	else if (strcmp(name, "msgget") == 0)
		return __PNR_msgget;
	else if (strcmp(name, "msgctl") == 0)
		return __PNR_msgctl;
	else if (strcmp(name, "shmat") == 0)
		return __PNR_shmat;
	else if (strcmp(name, "shmdt") == 0)
		return __PNR_shmdt;
	else if (strcmp(name, "shmget") == 0)
		return __PNR_shmget;
	else if (strcmp(name, "shmctl") == 0)
		return __PNR_shmctl;

	return x86_syscall_resolve_name(name);
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
const char *x86_syscall_resolve_num_munge(int num)
{
	if (num == __PNR_accept)
		return "accept";
	else if (num == __PNR_accept4)
		return "accept4";
	else if (num == __PNR_bind)
		return "bind";
	else if (num == __PNR_connect)
		return "connect";
	else if (num == __PNR_getpeername)
		return "getpeername";
	else if (num == __PNR_getsockname)
		return "getsockname";
	else if (num == __PNR_getsockopt)
		return "getsockopt";
	else if (num == __PNR_listen)
		return "listen";
	else if (num == __PNR_recv)
		return "recv";
	else if (num == __PNR_recvfrom)
		return "recvfrom";
	else if (num == __PNR_recvmsg)
		return "recvmsg";
	else if (num == __PNR_recvmmsg)
		return "recvmmsg";
	else if (num == __PNR_send)
		return "send";
	else if (num == __PNR_sendmsg)
		return "sendmsg";
	else if (num == __PNR_sendmmsg)
		return "sendmmsg";
	else if (num == __PNR_sendto)
		return "sendto";
	else if (num == __PNR_setsockopt)
		return "setsockopt";
	else if (num == __PNR_shutdown)
		return "shutdown";
	else if (num == __PNR_socket)
		return "socket";
	else if (num == __PNR_socketpair)
		return "socketpair";

	if (num == __PNR_semop)
		return "semop";
	else if (num == __PNR_semget)
		return "semget";
	else if (num == __PNR_semctl)
		return "semctl";
	else if (num == __PNR_semtimedop)
		return "semtimedop";
	else if (num == __PNR_msgsnd)
		return "msgsnd";
	else if (num == __PNR_msgrcv)
		return "msgrcv";
	else if (num == __PNR_msgget)
		return "msgget";
	else if (num == __PNR_msgctl)
		return "msgctl";
	else if (num == __PNR_shmat)
		return "shmat";
	else if (num == __PNR_shmdt)
		return "shmdt";
	else if (num == __PNR_shmget)
		return "shmget";
	else if (num == __PNR_shmctl)
		return "shmctl";

	return x86_syscall_resolve_num(num);
}

/**
 * Convert a multiplexed pseudo syscall into a direct syscall
 * @param syscall the multiplexed pseudo syscall number
 *
 * Return the related direct syscall number, __NR_SCMP_UNDEF is there is
 * no related syscall, or __NR_SCMP_ERROR otherwise.
 *
 */
static int _x86_syscall_demux(int syscall)
{
	switch (syscall) {
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
	case -201:
		/* semop - not defined */
		return __NR_SCMP_UNDEF;
	case -202:
		/* semget */
		return 393;
	case -203:
		/* semctl */
		return 394;
	case -204:
		/* semtimedop - not defined */
		return __NR_SCMP_UNDEF;
	case -211:
		/* msgsnd */
		return 400;
	case -212:
		/* msgrcv */
		return 401;
	case -213:
		/* msgget */
		return 399;
	case -214:
		/* msgctl */
		return 402;
	case -221:
		/* shmat */
		return 397;
	case -222:
		/* shmdt */
		return 398;
	case -223:
		/* shmget */
		return 395;
	case -224:
		/* shmctl */
		return 396;
	}

	return __NR_SCMP_ERROR;
}

/**
 * Convert a direct syscall into multiplexed pseudo socket syscall
 * @param syscall the direct syscall
 *
 * Return the related multiplexed pseduo syscall number, __NR_SCMP_UNDEF is
 * there is no related pseudo syscall, or __NR_SCMP_ERROR otherwise.
 *
 */
static int _x86_syscall_mux(int syscall)
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
	case 393:
		/* semget */
		return -202;
	case 394:
		/* semctl */
		return -203;
	case 400:
		/* msgsnd */
		return -211;
	case 401:
		/* msgrcv */
		return -212;
	case 399:
		/* msgget */
		return -213;
	case 402:
		/* msgctl */
		return -214;
	case 397:
		/* shmat */
		return -221;
	case 398:
		/* shmdt */
		return -222;
	case 395:
		/* shmget */
		return -223;
	case 396:
		/* shmctl */
		return -224;
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
int x86_syscall_rewrite(int *syscall)
{
	int sys = *syscall;

	if (sys <= -100 && sys >= -120)
		*syscall = __x86_NR_socketcall;
	else if (sys <= -200 && sys >= -224)
		*syscall = __x86_NR_ipc;
	else if (sys < 0)
		return -EDOM;

	return 0;
}

/**
 * add a new rule to the x86 seccomp filter
 * @param db the seccomp filter db
 * @param rule the filter rule
 *
 * This function adds a new syscall filter to the seccomp filter db, making any
 * necessary adjustments for the x86 ABI.  Returns zero on success, negative
 * values on failure.
 *
 * It is important to note that in the case of failure the db may be corrupted,
 * the caller must use the transaction mechanism if the db integrity is
 * important.
 *
 */
int x86_rule_add(struct db_filter *db, struct db_api_rule_list *rule)
{
	int rc = 0;
	unsigned int iter;
	int sys = rule->syscall;
	int sys_a, sys_b;
	struct db_api_rule_list *rule_a, *rule_b, *rule_dup = NULL;

	if ((sys <= -100 && sys >= -120) || (sys >= 359 && sys <= 373)) {
		/* (-100 to -120) : multiplexed socket syscalls
		   (359 to 373)   : direct socket syscalls, Linux 4.3+ */

		/* strict check for the multiplexed socket syscalls */
		for (iter = 0; iter < ARG_COUNT_MAX; iter++) {
			if ((rule->args[iter].valid != 0) && (rule->strict)) {
				rc = -EINVAL;
				goto add_return;
			}
		}

		/* determine both the muxed and direct syscall numbers */
		if (sys > 0) {
			sys_a = _x86_syscall_mux(sys);
			if (sys_a == __NR_SCMP_ERROR) {
				rc = __NR_SCMP_ERROR;
				goto add_return;
			}
			sys_b = sys;
		} else {
			sys_a = sys;
			sys_b = _x86_syscall_demux(sys);
			if (sys_b == __NR_SCMP_ERROR) {
				rc = __NR_SCMP_ERROR;
				goto add_return;
			}
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
			rule_dup = db_rule_dup(rule_a);
			rule_b = rule_dup;
			if (rule_b == NULL)
				goto add_return;
			rule_b->prev = rule_a;
			rule_b->next = NULL;
			rule_a->next = rule_b;
		}

		/* multiplexed socket syscalls */
		if (rule_a != NULL) {
			rule_a->syscall = __x86_NR_socketcall;
			rule_a->args[0].arg = 0;
			rule_a->args[0].op = SCMP_CMP_EQ;
			rule_a->args[0].mask = DATUM_MAX;
			rule_a->args[0].datum = (-sys_a) % 100;
			rule_a->args[0].valid = 1;
		}

		/* direct wired socket syscalls */
		if (rule_b != NULL)
			rule_b->syscall = sys_b;

		/* we should be protected by a transaction checkpoint */
		if (rule_a != NULL) {
			rc = db_rule_add(db, rule_a);
			if (rc < 0)
				goto add_return;
		}
		if (rule_b != NULL) {
			rc = db_rule_add(db, rule_b);
			if (rc < 0)
				goto add_return;
		}
	} else if ((sys <= -200 && sys >= -224) || (sys >= 393 && sys <= 402)) {
		/* (-200 to -224) : multiplexed ipc syscalls
		   (393 to 402) : direct ipc syscalls */

		/* strict check for the multiplexed socket syscalls */
		for (iter = 0; iter < ARG_COUNT_MAX; iter++) {
			if ((rule->args[iter].valid != 0) && (rule->strict)) {
				rc = -EINVAL;
				goto add_return;
			}
		}

		/* determine both the muxed and direct syscall numbers */
		if (sys > 0) {
			sys_a = _x86_syscall_mux(sys);
			if (sys_a == __NR_SCMP_ERROR) {
				rc = __NR_SCMP_ERROR;
				goto add_return;
			}
			sys_b = sys;
		} else {
			sys_a = sys;
			sys_b = _x86_syscall_demux(sys);
			if (sys_b == __NR_SCMP_ERROR) {
				rc = __NR_SCMP_ERROR;
				goto add_return;
			}
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
			rule_dup = db_rule_dup(rule_a);
			rule_b = rule_dup;
			if (rule_b == NULL)
				goto add_return;
			rule_b->prev = rule_a;
			rule_b->next = NULL;
			rule_a->next = rule_b;
		}

		/* multiplexed socket syscalls */
		if (rule_a != NULL) {
			rule_a->syscall = __x86_NR_ipc;
			rule_a->args[0].arg = 0;
			rule_a->args[0].op = SCMP_CMP_EQ;
			rule_a->args[0].mask = DATUM_MAX;
			rule_a->args[0].datum = (-sys_a) % 200;
			rule_a->args[0].valid = 1;
		}

		/* direct wired socket syscalls */
		if (rule_b != NULL)
			rule_b->syscall = sys_b;

		/* we should be protected by a transaction checkpoint */
		if (rule_a != NULL) {
			rc = db_rule_add(db, rule_a);
			if (rc < 0)
				goto add_return;
		}
		if (rule_b != NULL) {
			rc = db_rule_add(db, rule_b);
			if (rc < 0)
				goto add_return;
		}
	} else if (sys >= 0) {
		/* normal syscall processing */
		rc = db_rule_add(db, rule);
		if (rc < 0)
			goto add_return;
	} else if (rule->strict) {
		rc = -EDOM;
		goto add_return;
	}

add_return:
	if (rule_dup != NULL)
		free(rule_dup);
	return rc;
}

const struct arch_def arch_def_x86 = {
	.token = SCMP_ARCH_X86,
	.token_bpf = AUDIT_ARCH_I386,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_LITTLE,
	.syscall_resolve_name = x86_syscall_resolve_name_munge,
	.syscall_resolve_num = x86_syscall_resolve_num_munge,
	.syscall_rewrite = x86_syscall_rewrite,
	.rule_add = x86_rule_add,
};
