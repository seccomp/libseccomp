/**
 * Tool utility functions
 *
 * Copyright (c) 2014 Red Hat <pmoore@redhat.com>
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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/audit.h>

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <endian.h>

#include <seccomp.h>

#include "util.h"

/* determine the native architecture */
#if __i386__
#define ARCH_NATIVE		AUDIT_ARCH_I386
#elif __x86_64__
#ifdef __ILP32__
#define ARCH_NATIVE		AUDIT_ARCH_X86_64
#else
#define ARCH_NATIVE		AUDIT_ARCH_X86_64
#endif /* __ILP32__ */
#elif __arm__
#define ARCH_NATIVE		AUDIT_ARCH_ARM
#elif __aarch64__
#define ARCH_NATIVE		AUDIT_ARCH_AARCH64
#elif __mips__ && _MIPS_SIM == _MIPS_SIM_ABI32
#if __MIPSEB__
#define ARCH_NATIVE		AUDIT_ARCH_MIPS
#elif __MIPSEL__
#define ARCH_NATIVE		AUDIT_ARCH_MIPSEL
#endif /* _MIPS_SIM_ABI32 */
#elif __mips__ && _MIPS_SIM == _MIPS_SIM_ABI64
#if __MIPSEB__
#define ARCH_NATIVE		AUDIT_ARCH_MIPS64
#elif __MIPSEL__
#define ARCH_NATIVE		AUDIT_ARCH_MIPSEL64
#endif /* _MIPS_SIM_ABI64 */
#elif __mips__ && _MIPS_SIM == _MIPS_SIM_NABI32
#if __MIPSEB__
#define ARCH_NATIVE		AUDIT_ARCH_MIPS64N32
#elif __MIPSEL__
#define ARCH_NATIVE		AUDIT_ARCH_MIPSEL64N32
#endif /* _MIPS_SIM_NABI32 */
#elif __hppa64__
#define ARCH_NATIVE		AUDIT_ARCH_PARISC64
#elif __hppa__
#define ARCH_NATIVE		AUDIT_ARCH_PARISC
#elif __PPC64__
#ifdef __BIG_ENDIAN__
#define ARCH_NATIVE		AUDIT_ARCH_PPC64
#else
#define ARCH_NATIVE		AUDIT_ARCH_PPC64LE
#endif
#elif __PPC__
#define ARCH_NATIVE		AUDIT_ARCH_PPC
#elif __s390x__ /* s390x must be checked before s390 */
#define ARCH_NATIVE		AUDIT_ARCH_S390X
#elif __s390__
#define ARCH_NATIVE		AUDIT_ARCH_S390
#else
#error the simulator code needs to know about your machine type
#endif

/* default to the native arch */
uint32_t arch = ARCH_NATIVE;

/**
 * Convert a 16-bit target integer into the host's endianess
 * @param arch the architecture token
 * @param val the 16-bit integer
 *
 * Convert the endianess of the supplied value and return it to the caller.
 *
 */
uint16_t ttoh16(uint32_t arch, uint16_t val)
{
	if (arch & __AUDIT_ARCH_LE)
		return le16toh(val);
	else
		return be16toh(val);
}

/**
 * Convert a 32-bit target integer into the host's endianess
 * @param arch the architecture token
 * @param val the 32-bit integer
 *
 * Convert the endianess of the supplied value and return it to the caller.
 *
 */
uint32_t ttoh32(uint32_t arch, uint32_t val)
{
	if (arch & __AUDIT_ARCH_LE)
		return le32toh(val);
	else
		return be32toh(val);
}

/**
 * Convert a 32-bit host integer into the target's endianess
 * @param arch the architecture token
 * @param val the 32-bit integer
 *
 * Convert the endianess of the supplied value and return it to the caller.
 *
 */
uint32_t htot32(uint32_t arch, uint32_t val)
{
	if (arch & __AUDIT_ARCH_LE)
		return htole32(val);
	else
		return htobe32(val);
}

/**
 * Convert a 64-bit host integer into the target's endianess
 * @param arch the architecture token
 * @param val the 64-bit integer
 *
 * Convert the endianess of the supplied value and return it to the caller.
 *
 */
uint64_t htot64(uint32_t arch, uint64_t val)
{
	if (arch & __AUDIT_ARCH_LE)
		return htole64(val);
	else
		return htobe64(val);
}

/**
 * Resolve arch token to a name
 * @param arch_token the architecture token, e.g. SCMP_ARCH_*
 *
 * Resolve the given architecture token to the architecture name; it is up to
 * the caller to free the returned string. Returns the architecture name on
 * success, NULL on failure.
 *
 */
char *arch_resolve_token(uint32_t arch_token)
{
	const char *name;

	switch (arch_token) {
	case SCMP_ARCH_X86:
		name = "x86";
		break;
	case SCMP_ARCH_X86_64:
		name = "x86_64";
		break;
	case SCMP_ARCH_X32:
		name = "x32";
		break;
	case SCMP_ARCH_ARM:
		name = "arm";
		break;
	case SCMP_ARCH_AARCH64:
		name = "aarch64";
		break;
	case SCMP_ARCH_MIPS:
		name = "mips";
		break;
	case SCMP_ARCH_MIPSEL:
		name = "mipsel";
		break;
	case SCMP_ARCH_MIPS64:
		name = "mips64";
		break;
	case SCMP_ARCH_MIPSEL64:
		name = "mipsel64";
		break;
	case SCMP_ARCH_MIPS64N32:
		name = "mips64n32";
		break;
	case SCMP_ARCH_MIPSEL64N32:
		name = "mipsel64n32";
		break;
	case SCMP_ARCH_PARISC:
		name = "parisc";
		break;
	case SCMP_ARCH_PARISC64:
		name = "parisc64";
		break;
	case SCMP_ARCH_PPC:
		name = "ppc";
		break;
	case SCMP_ARCH_PPC64:
		name = "ppc64";
		break;
	case SCMP_ARCH_PPC64LE:
		name = "ppc64le";
		break;
	case SCMP_ARCH_S390:
		name = "s390";
		break;
	case SCMP_ARCH_S390X:
		name = "s390x";
		break;
	default:
		name = NULL;
	}

	return name ? strdup(name) : NULL;
}
