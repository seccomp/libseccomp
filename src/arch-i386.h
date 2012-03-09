/**
 * Enhanced Seccomp i386 Specific Code
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

#ifndef _ARCH_i386_H
#define _ARCH_i386_H

#include "arch.h"
#include "db.h"

#define i386_arg_count_max		6

#define i386_arg_offset(x)		(8 + ((x) * 4))
#define i386_arg_offset_lo(x)		(i386_arg_offset(x))

int i386_filter_rewrite(const struct arch_def *arch,
			int *syscall, struct db_api_arg *chain);

#endif
