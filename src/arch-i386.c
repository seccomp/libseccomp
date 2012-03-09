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
 * Rewrite a filter rule to match the architecture specifics
 * @param arch the architecture definition
 * @param syscall the syscall number
 * @param chain the argument filter chain
 *
 * Syscalls can vary across different architectures so this function handles
 * the necessary seccomp rule rewrites to ensure the right thing is done
 * regardless of the rule or architecture.  Returns zero on success, negative
 * values on error.
 *
 */
int i386_filter_rewrite(const struct arch_def *arch,
			int *syscall, struct db_api_arg *chain)
{
	/* XXX - rewrite the values in @syscall and @chain here */
	return -1;
}
