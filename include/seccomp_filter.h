/*
 * Secomp-based system call filtering data structures and definitions.
 *
 * Copyright (C) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License v.2.
 *
 */

#ifndef __LINUX_SECCOMP_FILTER_H__
#define __LINUX_SECCOMP_FILTER_H__

/* XXX - needed for early development only */

#ifndef PR_ATTACH_SECCOMP_FILTER
#define PR_ATTACH_SECCOMP_FILTER	37
#endif

#include <asm/byteorder.h>
#include <linux/types.h>

/*
 *	Keep the contents of this file similar to linux/filter.h:
 *	  struct sock_filter and sock_fprog and versions.
 *	Custom naming exists solely if divergence is ever needed.
 */

/*
 * Current version of the filter code architecture.
 */
#define SECCOMP_BPF_MAJOR_VERSION 1
#define SECCOMP_BPF_MINOR_VERSION 1

struct seccomp_filter_block {	/* Filter block */
	__u16	code;   /* Actual filter code */
	__u8	jt;	/* Jump true */
	__u8	jf;	/* Jump false */
	__u32	k;      /* Generic multiuse field */
};

struct seccomp_fprog {	/* Required for SO_ATTACH_FILTER. */
	unsigned short		len;	/* Number of filter blocks */
	struct seccomp_filter_block *filter;
};

/* Ensure the u32 ordering is consistent with platform byte order. */
#if defined(__LITTLE_ENDIAN)
#define SECCOMP_ENDIAN_SWAP(x, y) x, y
#elif defined(__BIG_ENDIAN)
#define SECCOMP_ENDIAN_SWAP(x, y) y, x
#else
#error edit for your odd arch byteorder.
#endif

/* System call argument layout for the filter data. */
union seccomp_filter_arg {
	struct {
		__u32 SECCOMP_ENDIAN_SWAP(lo32, hi32);
	};
	__u64 u64;
};

/*
 *	Expected data the BPF program will execute over.
 *	Endianness will be arch specific, but the values will be
 *	swapped, as above, to allow for consistent BPF programs.
 */
struct seccomp_filter_data {
	int syscall_nr;
	__u32 __reserved;
	union seccomp_filter_arg args[6];
};

#undef SECCOMP_ENDIAN_SWAP

/*
 * Defined valid return values for the BPF program.
 */
#define SECCOMP_BPF_ALLOW	0xFFFFFFFF
#define SECCOMP_BPF_DENY	0

#endif /* __LINUX_SECCOMP_FILTER_H__ */
