/**
 * Enhanced Seccomp Syscall Table Functions
 *
 * Copyright (c) 2012, 2020 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <paul@paul-moore.com>
 * gperf support: Giuseppe Scrivano <gscrivan@redhat.com>
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
#include <seccomp.h>

#include "db.h"
#include "arch.h"
#include "syscalls.h"

/**
 * Resolve a syscall name to a number
 * @param arch the arch definition
 * @param name the syscall name
 *
 * Resolve the given syscall name to the syscall number using the syscall table.
 * Returns the syscall number on success, including negative pseudo syscall
 * numbers; returns __NR_SCMP_ERROR on failure.
 *
 */
int abi_syscall_resolve_name_munge(const struct arch_def *arch,
				   const char *name)
{

#define _ABI_SYSCALL_RES_NAME_CHK(NAME) \
	if (!strcmp(name, #NAME)) return __PNR_##NAME;

	_ABI_SYSCALL_RES_NAME_CHK(socket)
	_ABI_SYSCALL_RES_NAME_CHK(bind)
	_ABI_SYSCALL_RES_NAME_CHK(connect)
	_ABI_SYSCALL_RES_NAME_CHK(listen)
	_ABI_SYSCALL_RES_NAME_CHK(accept)
	_ABI_SYSCALL_RES_NAME_CHK(getsockname)
	_ABI_SYSCALL_RES_NAME_CHK(getpeername)
	_ABI_SYSCALL_RES_NAME_CHK(socketpair)
	_ABI_SYSCALL_RES_NAME_CHK(send)
	_ABI_SYSCALL_RES_NAME_CHK(recv)
	_ABI_SYSCALL_RES_NAME_CHK(sendto)
	_ABI_SYSCALL_RES_NAME_CHK(recvfrom)
	_ABI_SYSCALL_RES_NAME_CHK(shutdown)
	_ABI_SYSCALL_RES_NAME_CHK(setsockopt)
	_ABI_SYSCALL_RES_NAME_CHK(getsockopt)
	_ABI_SYSCALL_RES_NAME_CHK(sendmsg)
	_ABI_SYSCALL_RES_NAME_CHK(recvmsg)
	_ABI_SYSCALL_RES_NAME_CHK(accept4)
	_ABI_SYSCALL_RES_NAME_CHK(recvmmsg)
	_ABI_SYSCALL_RES_NAME_CHK(sendmmsg)
	_ABI_SYSCALL_RES_NAME_CHK(semop)
	_ABI_SYSCALL_RES_NAME_CHK(semget)
	_ABI_SYSCALL_RES_NAME_CHK(semctl)
	_ABI_SYSCALL_RES_NAME_CHK(semtimedop)
	_ABI_SYSCALL_RES_NAME_CHK(msgsnd)
	_ABI_SYSCALL_RES_NAME_CHK(msgrcv)
	_ABI_SYSCALL_RES_NAME_CHK(msgget)
	_ABI_SYSCALL_RES_NAME_CHK(msgctl)
	_ABI_SYSCALL_RES_NAME_CHK(shmat)
	_ABI_SYSCALL_RES_NAME_CHK(shmdt)
	_ABI_SYSCALL_RES_NAME_CHK(shmget)
	_ABI_SYSCALL_RES_NAME_CHK(shmctl)

	return arch->syscall_resolve_name_raw(name);
}

/**
 * Resolve a syscall number to a name
 * @param arch the arch definition
 * @param num the syscall number
 *
 * Resolve the given syscall number to the syscall name using the syscall table.
 * Returns a pointer to the syscall name string on success, including pseudo
 * syscall names; returns NULL on failure.
 *
 */
const char *abi_syscall_resolve_num_munge(const struct arch_def *arch, int num)
{

#define _ABI_SYSCALL_RES_NUM_CHK(NAME) \
	if (num == __PNR_##NAME) return #NAME;

	_ABI_SYSCALL_RES_NUM_CHK(socket)
	_ABI_SYSCALL_RES_NUM_CHK(bind)
	_ABI_SYSCALL_RES_NUM_CHK(connect)
	_ABI_SYSCALL_RES_NUM_CHK(listen)
	_ABI_SYSCALL_RES_NUM_CHK(accept)
	_ABI_SYSCALL_RES_NUM_CHK(getsockname)
	_ABI_SYSCALL_RES_NUM_CHK(getpeername)
	_ABI_SYSCALL_RES_NUM_CHK(socketpair)
	_ABI_SYSCALL_RES_NUM_CHK(send)
	_ABI_SYSCALL_RES_NUM_CHK(recv)
	_ABI_SYSCALL_RES_NUM_CHK(sendto)
	_ABI_SYSCALL_RES_NUM_CHK(recvfrom)
	_ABI_SYSCALL_RES_NUM_CHK(shutdown)
	_ABI_SYSCALL_RES_NUM_CHK(setsockopt)
	_ABI_SYSCALL_RES_NUM_CHK(getsockopt)
	_ABI_SYSCALL_RES_NUM_CHK(sendmsg)
	_ABI_SYSCALL_RES_NUM_CHK(recvmsg)
	_ABI_SYSCALL_RES_NUM_CHK(accept4)
	_ABI_SYSCALL_RES_NUM_CHK(recvmmsg)
	_ABI_SYSCALL_RES_NUM_CHK(sendmmsg)
	_ABI_SYSCALL_RES_NUM_CHK(semop)
	_ABI_SYSCALL_RES_NUM_CHK(semget)
	_ABI_SYSCALL_RES_NUM_CHK(semctl)
	_ABI_SYSCALL_RES_NUM_CHK(semtimedop)
	_ABI_SYSCALL_RES_NUM_CHK(msgsnd)
	_ABI_SYSCALL_RES_NUM_CHK(msgrcv)
	_ABI_SYSCALL_RES_NUM_CHK(msgget)
	_ABI_SYSCALL_RES_NUM_CHK(msgctl)
	_ABI_SYSCALL_RES_NUM_CHK(shmat)
	_ABI_SYSCALL_RES_NUM_CHK(shmdt)
	_ABI_SYSCALL_RES_NUM_CHK(shmget)
	_ABI_SYSCALL_RES_NUM_CHK(shmctl)

	return arch->syscall_resolve_num_raw(num);
}

/**
 * Check if a syscall is a socket syscall
 * @param arch the arch definition
 * @param sys the syscall number
 *
 * Returns true if the syscall is a socket related syscall, false otherwise.
 *
 */
static bool _abi_syscall_socket_test(const struct arch_def *arch, int sys)
{
	const char *name;

	/* multiplexed pseduo-syscalls */
	if (sys <= -100 && sys >= -120)
		return true;

	name = arch->syscall_resolve_num_raw(sys);
	if (!name)
		return false;

#define _ABI_SYSCALL_SOCK_CHK(NAME) \
	if (!strcmp(name, #NAME)) return true;

	_ABI_SYSCALL_SOCK_CHK(socket)
	_ABI_SYSCALL_SOCK_CHK(bind)
	_ABI_SYSCALL_SOCK_CHK(connect)
	_ABI_SYSCALL_SOCK_CHK(listen)
	_ABI_SYSCALL_SOCK_CHK(accept)
	_ABI_SYSCALL_SOCK_CHK(getsockname)
	_ABI_SYSCALL_SOCK_CHK(getpeername)
	_ABI_SYSCALL_SOCK_CHK(socketpair)
	_ABI_SYSCALL_SOCK_CHK(send)
	_ABI_SYSCALL_SOCK_CHK(recv)
	_ABI_SYSCALL_SOCK_CHK(sendto)
	_ABI_SYSCALL_SOCK_CHK(recvfrom)
	_ABI_SYSCALL_SOCK_CHK(shutdown)
	_ABI_SYSCALL_SOCK_CHK(setsockopt)
	_ABI_SYSCALL_SOCK_CHK(getsockopt)
	_ABI_SYSCALL_SOCK_CHK(sendmsg)
	_ABI_SYSCALL_SOCK_CHK(recvmsg)
	_ABI_SYSCALL_SOCK_CHK(accept4)
	_ABI_SYSCALL_SOCK_CHK(recvmmsg)
	_ABI_SYSCALL_SOCK_CHK(sendmmsg)

	return false;
}

/**
 * Check if a syscall is an ipc syscall
 * @param arch the arch definition
 * @param sys the syscall number
 *
 * Returns true if the syscall is an ipc related syscall, false otherwise.
 *
 */
static bool _abi_syscall_ipc_test(const struct arch_def *arch, int sys)
{
	const char *name;

	/* multiplexed pseduo-syscalls */
	if (sys <= -200 && sys >= -224)
		return true;

	name = arch->syscall_resolve_num_raw(sys);
	if (!name)
		return false;

#define _ABI_SYSCALL_IPC_CHK(NAME) \
	if (!strcmp(name, #NAME)) return true;

	_ABI_SYSCALL_IPC_CHK(semop)
	_ABI_SYSCALL_IPC_CHK(semget)
	_ABI_SYSCALL_IPC_CHK(semctl)
	_ABI_SYSCALL_IPC_CHK(semtimedop)
	_ABI_SYSCALL_IPC_CHK(msgsnd)
	_ABI_SYSCALL_IPC_CHK(msgrcv)
	_ABI_SYSCALL_IPC_CHK(msgget)
	_ABI_SYSCALL_IPC_CHK(msgctl)
	_ABI_SYSCALL_IPC_CHK(shmat)
	_ABI_SYSCALL_IPC_CHK(shmdt)
	_ABI_SYSCALL_IPC_CHK(shmget)
	_ABI_SYSCALL_IPC_CHK(shmctl)

	return false;
}

/**
 * Convert a multiplexed pseudo syscall into a direct syscall
 * @param arch the arch definition
 * @param syscall the multiplexed pseudo syscall number
 *
 * Return the related direct syscall number, __NR_SCMP_UNDEF is there is
 * no related syscall, or __NR_SCMP_ERROR otherwise.
 *
 */
static int _abi_syscall_demux(const struct arch_def *arch, int syscall)
{
	int sys = __NR_SCMP_UNDEF;

#define _ABI_SYSCALL_DEMUX_CHK(NAME) \
case __PNR_##NAME: \
	sys = arch->syscall_resolve_name_raw(#NAME); break;

	switch (syscall) {
		_ABI_SYSCALL_DEMUX_CHK(socket)
		_ABI_SYSCALL_DEMUX_CHK(bind)
		_ABI_SYSCALL_DEMUX_CHK(connect)
		_ABI_SYSCALL_DEMUX_CHK(listen)
		_ABI_SYSCALL_DEMUX_CHK(accept)
		_ABI_SYSCALL_DEMUX_CHK(getsockname)
		_ABI_SYSCALL_DEMUX_CHK(getpeername)
		_ABI_SYSCALL_DEMUX_CHK(socketpair)
		_ABI_SYSCALL_DEMUX_CHK(send)
		_ABI_SYSCALL_DEMUX_CHK(recv)
		_ABI_SYSCALL_DEMUX_CHK(sendto)
		_ABI_SYSCALL_DEMUX_CHK(recvfrom)
		_ABI_SYSCALL_DEMUX_CHK(shutdown)
		_ABI_SYSCALL_DEMUX_CHK(setsockopt)
		_ABI_SYSCALL_DEMUX_CHK(getsockopt)
		_ABI_SYSCALL_DEMUX_CHK(sendmsg)
		_ABI_SYSCALL_DEMUX_CHK(recvmsg)
		_ABI_SYSCALL_DEMUX_CHK(accept4)
		_ABI_SYSCALL_DEMUX_CHK(recvmmsg)
		_ABI_SYSCALL_DEMUX_CHK(sendmmsg)
		_ABI_SYSCALL_DEMUX_CHK(semop)
		_ABI_SYSCALL_DEMUX_CHK(semget)
		_ABI_SYSCALL_DEMUX_CHK(semctl)
		_ABI_SYSCALL_DEMUX_CHK(semtimedop)
		_ABI_SYSCALL_DEMUX_CHK(msgsnd)
		_ABI_SYSCALL_DEMUX_CHK(msgrcv)
		_ABI_SYSCALL_DEMUX_CHK(msgget)
		_ABI_SYSCALL_DEMUX_CHK(msgctl)
		_ABI_SYSCALL_DEMUX_CHK(shmat)
		_ABI_SYSCALL_DEMUX_CHK(shmdt)
		_ABI_SYSCALL_DEMUX_CHK(shmget)
		_ABI_SYSCALL_DEMUX_CHK(shmctl)
	}

	/* this looks odd because the arch resolver returns _ERROR if it can't
	 * resolve the syscall, but we want to use _UNDEF for that, so we set
	 * 'sys' to a sentinel value of _UNDEF and if it is error here we know
	 * the resolve failed to find a match */
	if (sys == __NR_SCMP_UNDEF)
		sys = __NR_SCMP_ERROR;
	else if (sys == __NR_SCMP_ERROR)
		sys = __NR_SCMP_UNDEF;

	return sys;
}

/**
 * Convert a direct syscall into multiplexed pseudo socket syscall
 * @param arch the arch definition
 * @param syscall the direct syscall
 *
 * Return the related multiplexed pseduo syscall number, __NR_SCMP_UNDEF is
 * there is no related pseudo syscall, or __NR_SCMP_ERROR otherwise.
 *
 */
static int _abi_syscall_mux(const struct arch_def *arch, int syscall)
{
	const char *sys;

	sys = arch->syscall_resolve_num_raw(syscall);
	if (!sys)
		return __NR_SCMP_ERROR;

#define _ABI_SYSCALL_MUX_CHK(NAME) \
	if (!strcmp(sys, #NAME)) return __PNR_##NAME;

	_ABI_SYSCALL_MUX_CHK(socket)
	_ABI_SYSCALL_MUX_CHK(bind)
	_ABI_SYSCALL_MUX_CHK(connect)
	_ABI_SYSCALL_MUX_CHK(listen)
	_ABI_SYSCALL_MUX_CHK(accept)
	_ABI_SYSCALL_MUX_CHK(getsockname)
	_ABI_SYSCALL_MUX_CHK(getpeername)
	_ABI_SYSCALL_MUX_CHK(socketpair)
	_ABI_SYSCALL_MUX_CHK(send)
	_ABI_SYSCALL_MUX_CHK(recv)
	_ABI_SYSCALL_MUX_CHK(sendto)
	_ABI_SYSCALL_MUX_CHK(recvfrom)
	_ABI_SYSCALL_MUX_CHK(shutdown)
	_ABI_SYSCALL_MUX_CHK(setsockopt)
	_ABI_SYSCALL_MUX_CHK(getsockopt)
	_ABI_SYSCALL_MUX_CHK(sendmsg)
	_ABI_SYSCALL_MUX_CHK(recvmsg)
	_ABI_SYSCALL_MUX_CHK(accept4)
	_ABI_SYSCALL_MUX_CHK(recvmmsg)
	_ABI_SYSCALL_MUX_CHK(sendmmsg)
	_ABI_SYSCALL_MUX_CHK(semop)
	_ABI_SYSCALL_MUX_CHK(semget)
	_ABI_SYSCALL_MUX_CHK(semctl)
	_ABI_SYSCALL_MUX_CHK(semtimedop)
	_ABI_SYSCALL_MUX_CHK(msgsnd)
	_ABI_SYSCALL_MUX_CHK(msgrcv)
	_ABI_SYSCALL_MUX_CHK(msgget)
	_ABI_SYSCALL_MUX_CHK(msgctl)
	_ABI_SYSCALL_MUX_CHK(shmat)
	_ABI_SYSCALL_MUX_CHK(shmdt)
	_ABI_SYSCALL_MUX_CHK(shmget)
	_ABI_SYSCALL_MUX_CHK(shmctl)

	return __NR_SCMP_ERROR;
}

/**
 * Rewrite a syscall value to match the architecture
 * @param arch the arch definition
 * @param syscall the syscall number
 *
 * Syscalls can vary across different architectures so this function rewrites
 * the syscall into the correct value for the specified architecture.  Returns
 * zero on success, negative values on failure.
 *
 */
int abi_syscall_rewrite(const struct arch_def *arch, int *syscall)
{
	int sys = *syscall;

	if (sys <= -100 && sys >= -120)
		*syscall = arch->sys_socketcall;
	else if (sys <= -200 && sys >= -224)
		*syscall = arch->sys_ipc;
	else if (sys < 0)
		return -EDOM;

	return 0;
}

/**
 * add a new rule to the abi seccomp filter
 * @param db the seccomp filter db
 * @param rule the filter rule
 *
 * This function adds a new syscall filter to the seccomp filter db, making any
 * necessary adjustments for the abi ABI.  Returns zero on success, negative
 * values on failure.
 *
 * It is important to note that in the case of failure the db may be corrupted,
 * the caller must use the transaction mechanism if the db integrity is
 * important.
 *
 */
int abi_rule_add(struct db_filter *db, struct db_api_rule_list *rule)
{
	int rc = 0;
	unsigned int iter;
	int sys = rule->syscall;
	int sys_a, sys_b;
	struct db_api_rule_list *rule_a, *rule_b, *rule_dup = NULL;

	if (_abi_syscall_socket_test(db->arch, sys)) {
		/* socket syscalls */

		/* strict check for the multiplexed socket syscalls */
		for (iter = 0; iter < ARG_COUNT_MAX; iter++) {
			if ((rule->args[iter].valid != 0) && (rule->strict)) {
				rc = -EINVAL;
				goto add_return;
			}
		}

		/* determine both the muxed and direct syscall numbers */
		if (sys > 0) {
			sys_a = _abi_syscall_mux(db->arch, sys);
			if (sys_a == __NR_SCMP_ERROR) {
				rc = __NR_SCMP_ERROR;
				goto add_return;
			}
			sys_b = sys;
		} else {
			sys_a = sys;
			sys_b = _abi_syscall_demux(db->arch, sys);
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
			rule_a->syscall = db->arch->sys_socketcall;
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
	} else if (_abi_syscall_ipc_test(db->arch, sys)) {
		/* ipc syscalls */

		/* strict check for the multiplexed socket syscalls */
		for (iter = 0; iter < ARG_COUNT_MAX; iter++) {
			if ((rule->args[iter].valid != 0) && (rule->strict)) {
				rc = -EINVAL;
				goto add_return;
			}
		}

		/* determine both the muxed and direct syscall numbers */
		if (sys > 0) {
			sys_a = _abi_syscall_mux(db->arch, sys);
			if (sys_a == __NR_SCMP_ERROR) {
				rc = __NR_SCMP_ERROR;
				goto add_return;
			}
			sys_b = sys;
		} else {
			sys_a = sys;
			sys_b = _abi_syscall_demux(db->arch, sys);
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
			rule_a->syscall = db->arch->sys_ipc;
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
