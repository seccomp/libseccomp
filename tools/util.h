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

#ifndef _UTIL_H
#define _UTIL_H

#include <elf.h>
#include <inttypes.h>
#include <linux/audit.h>

/**
 * The ARM architecture tokens
 */
/* AArch64 support for audit was merged in 3.17-rc1 */
#ifndef AUDIT_ARCH_AARCH64
#ifndef EM_AARCH64
#define EM_AARCH64		183
#endif /* EM_AARCH64 */
#define AUDIT_ARCH_AARCH64	(EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#endif /* AUDIT_ARCH_AARCH64 */

/**
 * The MIPS architecture tokens
 */
#ifndef __AUDIT_ARCH_CONVENTION_MIPS64_N32
#define __AUDIT_ARCH_CONVENTION_MIPS64_N32	0x20000000
#endif
#ifndef EM_MIPS
#define EM_MIPS			8
#endif
#ifndef AUDIT_ARCH_MIPS
#define AUDIT_ARCH_MIPS		(EM_MIPS)
#endif
#ifndef AUDIT_ARCH_MIPS64
#define AUDIT_ARCH_MIPS64	(EM_MIPS|__AUDIT_ARCH_64BIT)
#endif
/* MIPS64N32 support was merged in 3.15 */
#ifndef AUDIT_ARCH_MIPS64N32
#define AUDIT_ARCH_MIPS64N32	(EM_MIPS|__AUDIT_ARCH_64BIT|\
				 __AUDIT_ARCH_CONVENTION_MIPS64_N32)
#endif
/* MIPSEL64N32 support was merged in 3.15 */
#ifndef AUDIT_ARCH_MIPSEL64N32
#define AUDIT_ARCH_MIPSEL64N32	(EM_MIPS|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE|\
				 __AUDIT_ARCH_CONVENTION_MIPS64_N32)
#endif

#ifndef AUDIT_ARCH_AARCH64
/* AArch64 support for audit was merged in 3.17-rc1 */
#define AUDIT_ARCH_AARCH64	(EM_AARCH64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#endif

#ifndef AUDIT_ARCH_PPC64LE
#define AUDIT_ARCH_PPC64LE	(EM_PPC64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#endif

extern uint32_t arch;

uint16_t ttoh16(uint32_t arch, uint16_t val);
uint32_t ttoh32(uint32_t arch, uint32_t val);

uint32_t htot32(uint32_t arch, uint32_t val);
uint64_t htot64(uint32_t arch, uint64_t val);

#endif
