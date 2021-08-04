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
#include "arch-sh.h"

/* sh syscall numbers */
#define __sh_NR_socketcall		102
#define __sh_NR_ipc			117

/**
 * Resolve a syscall name to a number
 * @param name the syscall name
 *
 * Resolve the given syscall name to the syscall number using the syscall table.
 * Returns the syscall number on success, including negative pseudo syscall
 * numbers; returns __NR_SCMP_ERROR on failure.
 *
 */
int sh_syscall_resolve_name_munge(const char *name)
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

	return sh_syscall_resolve_name(name);
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
const char *sh_syscall_resolve_num_munge(int num)
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

	return sh_syscall_resolve_num(num);
}

/**
 * Check if a syscall is a socket syscall
 * @param sys the syscall number
 *
 * Returns true if the syscall is a socket related syscall, false otherwise.
 *
 */
static bool _sh_syscall_socket_test(int sys)
{
	const char *name;

	/* multiplexed pseduo-syscalls */
	if (sys <= -100 && sys >= -120)
		return true;

	name = sh_syscall_resolve_num(sys);
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
 * @param sys the syscall number
 *
 * Returns true if the syscall is an ipc related syscall, false otherwise.
 *
 */
static bool _sh_syscall_ipc_test(int sys)
{
	const char *name;

	/* multiplexed pseduo-syscalls */
	if (sys <= -200 && sys >= -224)
		return true;

	name = sh_syscall_resolve_num(sys);
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
 * @param syscall the multiplexed pseudo syscall number
 *
 * Return the related direct syscall number, __NR_SCMP_UNDEF is there is
 * no related syscall, or __NR_SCMP_ERROR otherwise.
 *
 */
static int _sh_syscall_demux(int syscall)
{
	int sys = __NR_SCMP_UNDEF;

#define _ABI_SYSCALL_DEMUX_CHK(NAME) \
case __PNR_##NAME: \
	sys = sh_syscall_resolve_name(#NAME); break;

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
 * @param syscall the direct syscall
 *
 * Return the related multiplexed pseduo syscall number, __NR_SCMP_UNDEF is
 * there is no related pseudo syscall, or __NR_SCMP_ERROR otherwise.
 *
 */
static int _sh_syscall_mux(int syscall)
{
	const char *sys;

	sys = sh_syscall_resolve_num(syscall);
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
 * @param syscall the syscall number
 *
 * Syscalls can vary across different architectures so this function rewrites
 * the syscall into the correct value for the specified architecture.  Returns
 * zero on success, negative values on failure.
 *
 */
int sh_syscall_rewrite(int *syscall)
{
	int sys = *syscall;

	if (sys <= -100 && sys >= -120)
		*syscall = __sh_NR_socketcall;
	else if (sys <= -200 && sys >= -224)
		*syscall = __sh_NR_ipc;
	else if (sys < 0)
		return -EDOM;

	return 0;
}

/**
 * add a new rule to the sh seccomp filter
 * @param db the seccomp filter db
 * @param rule the filter rule
 *
 * This function adds a new syscall filter to the seccomp filter db, making any
 * necessary adjustments for the sh ABI.  Returns zero on success, negative
 * values on failure.
 *
 * It is important to note that in the case of failure the db may be corrupted,
 * the caller must use the transaction mechanism if the db integrity is
 * important.
 *
 */
int sh_rule_add(struct db_filter *db, struct db_api_rule_list *rule)
{
	int rc = 0;
	unsigned int iter;
	int sys = rule->syscall;
	int sys_a, sys_b;
	struct db_api_rule_list *rule_a, *rule_b, *rule_dup = NULL;

	if (_sh_syscall_socket_test(sys)) {
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
			sys_a = _sh_syscall_mux(sys);
			if (sys_a == __NR_SCMP_ERROR) {
				rc = __NR_SCMP_ERROR;
				goto add_return;
			}
			sys_b = sys;
		} else {
			sys_a = sys;
			sys_b = _sh_syscall_demux(sys);
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
			rule_a->syscall = __sh_NR_socketcall;
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
	} else if (_sh_syscall_ipc_test(sys)) {
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
			sys_a = _sh_syscall_mux(sys);
			if (sys_a == __NR_SCMP_ERROR) {
				rc = __NR_SCMP_ERROR;
				goto add_return;
			}
			sys_b = sys;
		} else {
			sys_a = sys;
			sys_b = _sh_syscall_demux(sys);
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
			rule_a->syscall = __sh_NR_ipc;
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

const struct arch_def arch_def_sheb = {
	.token = SCMP_ARCH_SHEB,
	.token_bpf = AUDIT_ARCH_SH,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_BIG,
	.syscall_resolve_name = sh_syscall_resolve_name_munge,
	.syscall_resolve_num = sh_syscall_resolve_num_munge,
	.syscall_rewrite = sh_syscall_rewrite,
	.rule_add = sh_rule_add,
};

const struct arch_def arch_def_sh = {
	.token = SCMP_ARCH_SH,
	.token_bpf = AUDIT_ARCH_SHEL,
	.size = ARCH_SIZE_32,
	.endian = ARCH_ENDIAN_LITTLE,
	.syscall_resolve_name = sh_syscall_resolve_name_munge,
	.syscall_resolve_num = sh_syscall_resolve_num_munge,
	.syscall_rewrite = sh_syscall_rewrite,
	.rule_add = sh_rule_add,
};
