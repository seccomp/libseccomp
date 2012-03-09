/**
 * Enhanced Seccomp x86_64 Specific Code
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

#ifndef _ARCH_x86_64_H
#define _ARCH_x86_64_H

#include <inttypes.h>

#include "arch.h"

#define x86_64_arg_count_max		6

#define x86_64_arg_offset(x)		(8 + ((x) * 8))
#define x86_64_arg_offset_lo(x)		(x86_64_arg_offset(x))
#define x86_64_arg_offset_hi(x)		(x86_64_arg_offset(x) + 4)

#endif
