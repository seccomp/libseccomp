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

#include <stdlib.h>

#include "arch.h"
#include "arch-i386.h"

/**
 * Determine the argument offset for the lower 32 bits
 * @param arch the architecture definition
 * @param arg the argument number
 *
 * Determine the correct offset for the low 32 bits of the given argument based
 * on the architecture definition.  Returns the offset on success, negative
 * values on failure.
 *
 */
int i386_arg_offset_lo(const struct arch_def *arch, unsigned int arg)
{
	return i386_arg_offset(arch, arg);
}

/**
 * Determine the argument offset
 * @param arch the architecture definition
 * @param arg the argument number
 *
 * Determine the correct offset of the given argument based on the architecture
 * definition.  Returns the offset on success, negative values on failure.
 *
 */
int i386_arg_offset(const struct arch_def *arch, unsigned int arg)
{
	return 8 + (arg * 4);
}
