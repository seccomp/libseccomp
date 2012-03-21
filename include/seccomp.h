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
 * macros
 */

#define SCMP_SYS(x)		__NR_##x

/* XXX - the constants here should be replaced with the seccomp #defines */
#define SCMP_ACT_KILL		0x00000000U
#define SCMP_ACT_TRAP		0x00020000U
#define SCMP_ACT_ERRNO(x)	(0x00030000U | ((x) & 0x0000ffff))
#define SCMP_ACT_TRACE(x)	(0x7ff00000U | ((x) & 0x0000ffff))
#define SCMP_ACT_ALLOW		0x7fff0000U

/*
 * types
 */

enum scmp_compare {
	_SCMP_CMP_MIN = 0,	/* sentinel */
	SCMP_CMP_NE = 1,	/* not equal */
	SCMP_CMP_LT = 2,	/* less than */
	SCMP_CMP_LE = 3,	/* less than or equal */
	SCMP_CMP_EQ = 4,	/* equal */
	SCMP_CMP_GE = 5,	/* greater than or equal */
	SCMP_CMP_GT = 6,	/* greater than */
	SCMP_CMP_MASK = 7,	/* masked value equality */
	_SCMP_CMP_MAX,		/* sentinel */
};

/*
 * functions
 */

int seccomp_init(uint32_t def_action);
int seccomp_reset(uint32_t def_action);
void seccomp_release(void);

int seccomp_load(void);

int seccomp_rule_add(uint32_t action, int syscall, unsigned int arg_cnt, ...);

int seccomp_gen_pfc(int fd);
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
