/**
 * Seccomp Library
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

#ifndef _SECCOMP_H
#define _SECCOMP_H

#include <inttypes.h>
#include <asm/unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * types
 */

/**
 * Filter context/handle
 */
typedef void * scmp_filter_ctx;

/**
 * Filter attributes
 */
enum scmp_filter_attr {
	_SCMP_FLTATR_MIN = 0,
	SCMP_FLTATR_ACT_DEFAULT = 1,	/**< default filter action */
	SCMP_FLTATR_ACT_BADARCH = 2,	/**< bad architecture action */
	SCMP_FLTATR_CTL_NNP = 3,	/**< set NO_NEW_PRIVS on filter load */
	_SCMP_FLTATR_MAX,
};

/**
 * Comparison operators
 */
enum scmp_compare {
	_SCMP_CMP_MIN = 0,
	SCMP_CMP_NE = 1,		/**< not equal */
	SCMP_CMP_LT = 2,		/**< less than */
	SCMP_CMP_LE = 3,		/**< less than or equal */
	SCMP_CMP_EQ = 4,		/**< equal */
	SCMP_CMP_GE = 5,		/**< greater than or equal */
	SCMP_CMP_GT = 6,		/**< greater than */
	SCMP_CMP_MASKED_EQ = 7,		/**< masked equality */
	_SCMP_CMP_MAX,
};

/**
 * Argument datum
 */
typedef uint64_t scmp_datum_t;

/**
 * Argument / Value comparison definition
 */
struct scmp_arg_cmp {
	unsigned int arg;	/**< argument number, starting at 0 */
	enum scmp_compare op;	/**< the comparison op, e.g. SCMP_CMP_* */
	scmp_datum_t datum_a;
	scmp_datum_t datum_b;
};

/*
 * macros/defines
 */

/**
 * Convert a syscall name into the associated syscall number
 * @param x the syscall name
 */
#define SCMP_SYS(x)		__NR_##x

/**
 * Specify an argument comparison struct for use in declaring rules
 * @param arg the argument number, starting at 0
 * @param op the comparison operator, e.g. SCMP_CMP_*
 * @param datum_a dependent on comparison
 * @param datum_b dependent on comparison, optional
 */
#define SCMP_CMP(...)		((struct scmp_arg_cmp){__VA_ARGS__})

/**
 * Specify an argument comparison struct for argument 0
 */
#define SCMP_A0(...)		SCMP_CMP(0, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 1
 */
#define SCMP_A1(...)		SCMP_CMP(1, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 2
 */
#define SCMP_A2(...)		SCMP_CMP(2, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 3
 */
#define SCMP_A3(...)		SCMP_CMP(3, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 4
 */
#define SCMP_A4(...)		SCMP_CMP(4, __VA_ARGS__)

/**
 * Specify an argument comparison struct for argument 5
 */
#define SCMP_A5(...)		SCMP_CMP(5, __VA_ARGS__)

/*
 * seccomp actions
 */

/**
 * Kill the process
 */
#define SCMP_ACT_KILL		0x00000000U
/**
 * Throw a SIGSYS signal
 */
#define SCMP_ACT_TRAP		0x00030000U
/**
 * Return the specified error code
 */
#define SCMP_ACT_ERRNO(x)	(0x00050000U | ((x) & 0x0000ffffU))
/**
 * Notify a tracing process with the specified value
 */
#define SCMP_ACT_TRACE(x)	(0x7ff00000U | ((x) & 0x0000ffffU))
/**
 * Allow the syscall to be executed
 */
#define SCMP_ACT_ALLOW		0x7fff0000U

/*
 * functions
 */

/**
 * Initialize the filter state
 * @param def_action the default filter action
 *
 * This function initializes the internal seccomp filter state and should
 * be called before any other functions in this library to ensure the filter
 * state is initialized.  Returns a filter context on success, NULL on failure.
 *
 */
scmp_filter_ctx seccomp_init(uint32_t def_action);

/**
 * Reset the current filter state
 * @param ctx the filter context
 * @param def_action the default filter action
 *
 * This function resets the given seccomp filter state and ensures the
 * filter state is reinitialized.  This function does not reset any seccomp
 * filters already loaded into the kernel.  Returns zero on success, negative
 * values on failure.
 *
 */
int seccomp_reset(scmp_filter_ctx ctx, uint32_t def_action);

/**
 * Destroys the current filter state and releases any resources
 * @param ctx the filter context
 *
 * This functions destroys the given seccomp filter state and releases any
 * resources, including memory, associated with the filter state.  This
 * function does not reset any seccomp filters already loaded into the kernel.
 * The filter context can no longer be used after calling this function.
 *
 */
void seccomp_release(scmp_filter_ctx ctx);

/**
 * Loads the current filter into the kernel
 * @param ctx the filter context
 *
 * This function loads the given seccomp filter context into the kernel.  If
 * the filter was loaded correctly, the kernel will be enforcing the filter
 * when this function returns.  Returns zero on success, negative values on
 * error.
 *
 */
int seccomp_load(const scmp_filter_ctx ctx);

/**
 * Get the value of a filter attribute
 * @param ctx the filter context
 * @param attr the filter attribute name
 * @param value the filter attribute value
 *
 * This function fetches the value of the given attribute name and returns it
 * via @value.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_attr_get(const scmp_filter_ctx ctx,
		     enum scmp_filter_attr attr, uint32_t *value);

/**
 * Set the value of a filter attribute
 * @param ctx the filter context
 * @param attr the filter attribute name
 * @param value the filter attribute value
 *
 * This function sets the value of the given attribute.  Returns zero on
 * success, negative values on failure.
 *
 */
int seccomp_attr_set(scmp_filter_ctx ctx,
		     enum scmp_filter_attr attr, uint32_t value);

/**
 * Set the priority of a given syscall
 * @param ctx the filter context
 * @param syscall the syscall number
 * @param priority priority value, higher value == higher priority
 *
 * This function sets the priority of the given syscall; this value is used
 * when generating the seccomp filter code such that higher priority syscalls
 * will incur less filter code overhead than the lower priority syscalls in the
 * filter.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_syscall_priority(scmp_filter_ctx ctx,
			     int syscall, uint8_t priority);

/**
 * Add a new rule to the current filter
 * @param ctx the filter context
 * @param action the filter action
 * @param syscall the syscall number
 * @param arg_cnt the number of argument filters in the argument filter chain
 * @param ... scmp_arg_cmp structs (use of SCMP_ARG_CMP() recommended)
 *
 * This function adds a series of new argument/value checks to the seccomp
 * filter for the given syscall; multiple argument/value checks can be
 * specified and they will be chained together (AND'd together) in the filter.
 * If the specified rule needs to be adjusted due to architecture specifics it
 * will be adjusted without notification.  Returns zero on success, negative
 * values on failure.
 *
 */
int seccomp_rule_add(scmp_filter_ctx ctx,
		     uint32_t action, int syscall, unsigned int arg_cnt, ...);

/**
 * Add a new rule to the current filter
 * @param ctx the filter context
 * @param action the filter action
 * @param syscall the syscall number
 * @param arg_cnt the number of argument filters in the argument filter chain
 * @param ... scmp_arg_cmp structs (use of SCMP_ARG_CMP() recommended)
 *
 * This function adds a series of new argument/value checks to the seccomp
 * filter for the given syscall; multiple argument/value checks can be
 * specified and they will be chained together (AND'd together) in the filter.
 * If the specified rule can not be represented on the architecture the
 * function will fail.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_rule_add_exact(scmp_filter_ctx ctx, uint32_t action,
			   int syscall, unsigned int arg_cnt, ...);

/**
 * Generate seccomp Pseudo Filter Code (PFC) and export it to a file
 * @param ctx the filter context
 * @param fd the destination fd
 *
 * This function generates seccomp Pseudo Filter Code (PFC) and writes it to
 * the given fd.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_export_pfc(const scmp_filter_ctx ctx, int fd);

/**
 * Generate seccomp Berkley Packet Filter (BPF) code and export it to a file
 * @param ctx the filter context
 * @param fd the destination fd
 *
 * This function generates seccomp Berkley Packer Filter (BPF) code and writes
 * it to the given fd.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_export_bpf(const scmp_filter_ctx ctx, int fd);

/*
 * pseudo syscall definitions
 */

/* NOTE - pseudo syscall values {-1..-99} are reserved */

#define __PNR_socket		-100
#ifndef __NR_socket
#define __NR_socket		__PNR_socket
#endif /* __NR_socket */

#define __PNR_bind		-101
#ifndef __NR_bind
#define __NR_bind		__PNR_bind
#endif /* __NR_bind */

#define __PNR_connect		-102
#ifndef __NR_connect
#define __NR_connect		__PNR_connect
#endif /* __NR_connect */

#define __PNR_listen		-103
#ifndef __NR_listen
#define __NR_listen		__PNR_listen
#endif /* __NR_listen */

#define __PNR_accept		-104
#ifndef __NR_accept
#define __NR_accept		__PNR_accept
#endif /* __NR_accept */

#define __PNR_getsockname	-105
#ifndef __NR_getsockname
#define __NR_getsockname	__PNR_getsockname
#endif /* __NR_getsockname */

#define __PNR_getpeername	-106
#ifndef __NR_getpeername
#define __NR_getpeername	__PNR_getpeername
#endif /* __NR_getpeername */

#define __PNR_socketpair	-107
#ifndef __NR_socketpair
#define __NR_socketpair		__PNR_socketpair
#endif /* __NR_socketpair */

#define __PNR_send		-108
#ifndef __NR_send
#define __NR_send		__PNR_send
#endif /* __NR_send */

#define __PNR_recv		-109
#ifndef __NR_recv
#define __NR_recv		__PNR_recv
#endif /* __NR_recv */

#define __PNR_sendto		-110
#ifndef __NR_sendto
#define __NR_sendto		__PNR_sendto
#endif /* __NR_sendto */

#define __PNR_recvfrom		-111
#ifndef __NR_recvfrom
#define __NR_recvfrom		__PNR_recvfrom
#endif /* __NR_recvfrom */

#define __PNR_shutdown		-112
#ifndef __NR_shutdown
#define __NR_shutdown		__PNR_shutdown
#endif /* __NR_shutdown */

#define __PNR_getsockopt	-113
#ifndef __NR_getsockopt
#define __NR_getsockopt		__PNR_getsockopt
#endif /* __NR_getsockopt */

#define __PNR_sendmsg		-114
#ifndef __NR_sendmsg
#define __NR_sendmsg		__PNR_sendmsg
#endif /* __NR_sendmsg */

#define __PNR_recvmsg		-115
#ifndef __NR_recvmsg
#define __NR_recvmsg		__PNR_recvmsg
#endif /* __NR_recvmsg */

#define __PNR_recvmmsg		-116
#ifndef __NR_recvmmsg
#define __NR_recvmmsg		__PNR_recvmmsg
#endif /* __NR_recvmmsg */

#define __PNR_sendmmsg		-117
#ifndef __NR_sendmmsg
#define __NR_sendmmsg		__PNR_sendmmsg
#endif /* __NR_sendmmsg */


#define __PNR_semop		-200
#ifndef __NR_semop
#define __NR_semop		__PNR_semop
#endif /* __NR_semop */

#define __PNR_semget		-201
#ifndef __NR_semget
#define __NR_semget		__PNR_semget
#endif /* __NR_semget */

#define __PNR_semctl		-202
#ifndef __NR_semctl
#define __NR_semctl		__PNR_semctl
#endif /* __NR_semctl */

#define __PNR_semtimedop	-203
#ifndef __NR_semtimedop
#define __NR_semtimedop		__PNR_semtimedop
#endif /* __NR_semtime */

#define __PNR_msgsnd		-204
#ifndef __NR_msgsnd
#define __NR_msgsnd		__PNR_msgsnd
#endif /* __NR_msgsnd */

#define __PNR_msgrcv		-205
#ifndef __NR_msgrcv
#define __NR_msgrcv		__PNR_msgrcv
#endif /* __NR_msgrcv */

#define __PNR_msgget		-206
#ifndef __NR_msgget
#define __NR_msgget		__PNR_msgget
#endif /* __NR_msgget */

#define __PNR_msgctl		-207
#ifndef __NR_msgctl
#define __NR_msgctl		__PNR_msgctl
#endif /* __NR_msgctl */

#define __PNR_shmat		-208
#ifndef __NR_shmat
#define __NR_shmat		__PNR_shmat
#endif /* __NR_shmat */

#define __PNR_shmdt		-209
#ifndef __NR_shmdt
#define __NR_shmdt		__PNR_shmdt
#endif /* __NR_shmdt */

#define __PNR_shmget		-210
#ifndef __NR_shmget
#define __NR_shmget		__PNR_shmget
#endif /* __NR_shmget */

#define __PNR_shmctl		-211
#ifndef __NR_shmctl
#define __NR_shmctl		__PNR_shmctl
#endif /* __NR_shmctl */

#ifdef __cplusplus
}
#endif

#endif
