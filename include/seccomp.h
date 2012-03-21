/**
 * Seccomp Library
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

#ifndef _SECCOMP_H
#define _SECCOMP_H

#include <inttypes.h>
#include <asm/unistd.h>

/*
 * macros/defines
 */

/**
 * Convert a syscall name into the associated syscall number
 * @param x the syscall name
 */
#define SCMP_SYS(x)		__NR_##x

/*
 * seccomp actions
 */

/* XXX - the values used here should be replaced with the system #defines */

/**
 * Kill the process
 */
#define SCMP_ACT_KILL		0x00000000U
/**
 * Throw a SIGSYS signal
 */
#define SCMP_ACT_TRAP		0x00020000U
/**
 * Return the specified error code
 */
#define SCMP_ACT_ERRNO(x)	(0x00030000U | ((x) & 0x0000ffff))
/**
 * Notify a tracing process with the specified value
 */
#define SCMP_ACT_TRACE(x)	(0x7ff00000U | ((x) & 0x0000ffff))
/**
 * Allow the syscall to be executed
 */
#define SCMP_ACT_ALLOW		0x7fff0000U

/*
 * types
 */

/**
 * Comparison operators
 */
enum scmp_compare {
	_SCMP_CMP_MIN = 0,
	SCMP_CMP_NE = 1,	/**< not equal */
	SCMP_CMP_LT = 2,	/**< less than */
	SCMP_CMP_LE = 3,	/**< less than or equal */
	SCMP_CMP_EQ = 4,	/**< equal */
	SCMP_CMP_GE = 5,	/**< greater than or equal */
	SCMP_CMP_GT = 6,	/**< greater than */
	SCMP_CMP_MASK = 7,	/**< masked equality */
	_SCMP_CMP_MAX,
};

/*
 * functions
 */

/**
 * Initialize the filter state
 * @param def_action the default filter action
 *
 * This function initializes the internal seccomp filter state and should
 * be called before any other functions in this library to ensure the filter
 * state is initialized.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_init(uint32_t def_action);

/**
 * Reset the current filter state
 * @param def_action the default filter action
 *
 * This function resets the internal seccomp filter state and ensures the
 * filter state is reinitialized.  This function does not reset any seccomp
 * filters already loaded into the kernel.  Returns zero on success, negative
 * values on failure.
 *
 */
int seccomp_reset(uint32_t def_action);

/**
 * Destroys the current filter state and releases any resources
 *
 * This functions destroys the internal seccomp filter state and releases any
 * resources, including memory, associated with the filter state.  This
 * function does not reset any seccomp filters already loaded into the kernel.
 * The function seccomp_reset() must be called before the filter can be
 * reconfigured after calling this function.
 *
 */
void seccomp_release(void);

/**
 * Loads the current filter into the kernel
 *
 * This function loads the currently configured seccomp filter into the kernel.
 * If the filter was loaded correctly, the kernel will be enforcing the filter
 * when this function returns.  Returns zero on success, negative values on
 * error.
 *
 */
int seccomp_load(void);

/**
 * Set the priority of a given syscall
 * @param syscall the syscall number
 * @param priority priority value, higher value == higher priority
 *
 * This function sets the priority of the given syscall; this value is used
 * when generating the seccomp filter code such that higher priority syscalls
 * will incur less filter code overhead than the lower priority syscalls in the
 * filter.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_syscall_priority(int syscall, uint8_t priority);

/**
 * Add a new rule to the current filter
 * @param action the filter action
 * @param syscall the syscall number
 * @param arg_cnt the number of argument filters in the argument filter chain
 * @param ... the argument filter chain, (uint, enum scmp_compare, ulong)
 *
 * This function adds a new argument/comparison/value to the seccomp filter for
 * a syscall; multiple arguments can be specified and they will be chained
 * together (essentially AND'd together) in the filter.  Returns zero on
 * success, negative values on failure.
 *
 */
int seccomp_rule_add(uint32_t action, int syscall, unsigned int arg_cnt, ...);

/**
 * Generate seccomp Pseudo Filter Code (PFC)
 * @param fd the destination fd
 *
 * This function generates seccomp Pseudo Filter Code (PFC) and writes it to
 * the given fd.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_gen_pfc(int fd);

/**
 * Generate seccomp Berkley Packet Filter (BPF) code
 * @param fd the destination fd
 *
 * This function generates seccomp Berkley Packer Filter (BPF) code and writes
 * it to the given fd.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_gen_bpf(int fd);

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

#endif
