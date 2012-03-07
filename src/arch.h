/**
 * Enhanced Seccomp Architecture/Machine Specific Code
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

#ifndef _ARCH_H
#define _ARCH_H

#include <inttypes.h>

struct arch_def {
	uint32_t token;
	enum {
		ARCH_SIZE_UNSPEC = 0,
		ARCH_SIZE_32 = 32,
		ARCH_SIZE_64 = 64,
	} size;
	enum {
		ARCH_ENDIAN_UNSPEC = 0,
		ARCH_ENDIAN_LITTLE,
		ARCH_ENDIAN_BIG,
	} endian;
};

/* arch_def for the current process */
extern const struct arch_def arch_def_native;

/* syscall argument datum type */
/* NOTE - see the comment in db.c:db_add_syscall() about possibile va_arg()
 *	  limitations on datum size */
typedef uint64_t datum_t;
#define D64_LO(x)	((uint32_t)((uint64_t)(x) & 0x00000000ffffffff))
#define D64_HI(x)	((uint32_t)((uint64_t)(x) >> 32))

int arch_arg_offset(const struct arch_def *arch, unsigned int arg);
int arch_arg_offset_lo(const struct arch_def *arch, unsigned int arg);
int arch_arg_offset_hi(const struct arch_def *arch, unsigned int arg);

#endif
