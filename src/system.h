/**
 * Seccomp System Interfaces
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
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

#ifndef _SYSTEM_H
#define _SYSTEM_H

#include <inttypes.h>
#include <stdbool.h>
#include <linux/filter.h>
#include <linux/types.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include "configure.h"

/* NOTE: this was taken from the Linux Kernel sources */
#define MAX_ERRNO		4095

struct db_filter_col;

#ifdef HAVE_LINUX_SECCOMP_H

/* system header file */
#include <linux/seccomp.h>

#else

/* NOTE: the definitions below were taken from the Linux Kernel sources */

/* Valid values for seccomp.mode and prctl(PR_SET_SECCOMP, <mode>) */
#define SECCOMP_MODE_DISABLED	0 /* seccomp is not in use. */
#define SECCOMP_MODE_STRICT	1 /* uses hard-coded filter. */
#define SECCOMP_MODE_FILTER	2 /* uses user-supplied filter. */

/*
 * All BPF programs must return a 32-bit value.
 * The bottom 16-bits are for optional return data.
 * The upper 16-bits are ordered from least permissive values to most.
 *
 * The ordering ensures that a min_t() over composed return values always
 * selects the least permissive choice.
 */
#define SECCOMP_RET_KILL_PROCESS 0x80000000U /* kill the process immediately */
#define SECCOMP_RET_KILL_THREAD	0x00000000U /* kill the thread immediately */
#define SECCOMP_RET_KILL	SECCOMP_RET_KILL_THREAD /* default to killing the thread */
#define SECCOMP_RET_TRAP	0x00030000U /* disallow and force a SIGSYS */
#define SECCOMP_RET_ERRNO	0x00050000U /* returns an errno */
#define SECCOMP_RET_USER_NOTIF	0x7fc00000U /* notifies userspace */
#define SECCOMP_RET_TRACE	0x7ff00000U /* pass to a tracer or disallow */
#define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */

/* Masks for the return value sections. */
#define SECCOMP_RET_ACTION	0x7fff0000U
#define SECCOMP_RET_DATA	0x0000ffffU

/**
 * struct seccomp_data - the format the BPF program executes over.
 * @nr: the system call number
 * @arch: indicates system call convention as an AUDIT_ARCH_* value
 *        as defined in <linux/audit.h>.
 * @instruction_pointer: at the time of the system call.
 * @args: up to 6 system call arguments always stored as 64-bit values
 *        regardless of the architecture.
 */
struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};

#endif /* HAVE_LINUX_SECCOMP_H */

/* rename some of the socket filter types to make more sense */
typedef struct sock_filter bpf_instr_raw;

/* no new privs defintions */
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS		38
#endif

#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS		39
#endif

/* operations for the seccomp() syscall */
#ifndef SECCOMP_SET_MODE_STRICT
#define SECCOMP_SET_MODE_STRICT		0
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER		1
#endif
#ifndef SECCOMP_GET_ACTION_AVAIL
#define SECCOMP_GET_ACTION_AVAIL	2
#endif
#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES		3
#endif

/* flags for the seccomp() syscall */
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC		(1UL << 0)
#endif
#ifndef SECCOMP_FILTER_FLAG_LOG
#define SECCOMP_FILTER_FLAG_LOG			(1UL << 1)
#endif
#ifndef SECCOMP_FILTER_FLAG_SPEC_ALLOW
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW		(1UL << 2)
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER	(1UL << 3)
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC_ESRCH
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH		(1UL << 4)
#endif

#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG			0x7ffc0000U /* allow after logging */
#endif

/* SECCOMP_RET_ACTION_FULL was added in kernel v4.14. */
#ifndef SECCOMP_RET_ACTION_FULL
#define SECCOMP_RET_ACTION_FULL		0xffff0000U
#endif

/* SECCOMP_RET_LOG was added in kernel v4.14. */
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG			0x7fc00000U
#endif

/* SECCOMP_RET_USER_NOTIF was added in kernel v5.0. */
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF	 	0x7fc00000U

struct seccomp_notif_sizes {
	__u16 seccomp_notif;
	__u16 seccomp_notif_resp;
	__u16 seccomp_data;
};

struct seccomp_notif {
	__u64 id;
	__u32 pid;
	__u32 flags;
	struct seccomp_data data;
};

struct seccomp_notif_resp {
	__u64 id;
	__s64 val;
	__s32 error;
	__u32 flags;
};

#define SECCOMP_IOC_MAGIC               '!'
#define SECCOMP_IO(nr)                  _IO(SECCOMP_IOC_MAGIC, nr)
#define SECCOMP_IOR(nr, type)           _IOR(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOW(nr, type)           _IOW(SECCOMP_IOC_MAGIC, nr, type)
#define SECCOMP_IOWR(nr, type)          _IOWR(SECCOMP_IOC_MAGIC, nr, type)

/* flags for seccomp notification fd ioctl */
#define SECCOMP_IOCTL_NOTIF_RECV        SECCOMP_IOWR(0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND        SECCOMP_IOWR(1, \
						     struct seccomp_notif_resp)
#define SECCOMP_IOCTL_NOTIF_ID_VALID    SECCOMP_IOW(2, __u64)
#endif /* SECCOMP_RET_USER_NOTIF */

/* non-public ioctl number for backwards compat (see system.c) */
#define SECCOMP_IOCTL_NOTIF_ID_VALID_WRONG_DIR SECCOMP_IOR(2, __u64)

void sys_reset_state(void);

int sys_chk_seccomp_syscall(void);
void sys_set_seccomp_syscall(bool enable);

int sys_chk_seccomp_action(uint32_t action);
void sys_set_seccomp_action(uint32_t action, bool enable);

int sys_chk_seccomp_flag(int flag);
void sys_set_seccomp_flag(int flag, bool enable);

int sys_filter_load(struct db_filter_col *col, bool rawrc);

int sys_notify_fd(void);
int sys_notify_alloc(struct seccomp_notif **req,
		     struct seccomp_notif_resp **resp);
int sys_notify_receive(int fd, struct seccomp_notif *req);
int sys_notify_respond(int fd, struct seccomp_notif_resp *resp);
int sys_notify_id_valid(int fd, uint64_t id);
#endif
