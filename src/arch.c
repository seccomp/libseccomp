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

#include <stdlib.h>
#include <asm/bitsperlong.h>

#include "arch.h"

const struct arch_def arch_def_native = {
	.token = 0,
#if __BITS_PER_LONG == 32
	.size = ARCH_SIZE_32,
#elif __BITS_PER_LONG == 64
	.size = ARCH_SIZE_64,
#else
	.size = ARCH_SIZE_UNSPEC,
#endif /* BITS_PER_LONG */
#if __BYTE_ORDER == __LITTLE_ENDIAN
	.endian = ARCH_ENDIAN_LITTLE,
#elif __BYTE_ORDER == __BIG_ENDIAN
	.endian = ARCH_ENDIAN_BIG,
#else
	.endian = ARCH_ENDIAN_UNSPEC,
#endif /* __BYTE_ORDER */
};
