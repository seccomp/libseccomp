/**
 * Enhanced Seccomp Architecture Sycall Checker
 *
 * Copyright (c) 2014 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
 *
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "arch.h"
#include "arch-x86.h"
#include "arch-x86_64.h"
#include "arch-arm.h"
#include "arch-mips.h"

void syscall_check(char *str_miss, const char *syscall,
		   const char *arch_name, const char *arch_sys)
{
	if (strcmp(syscall, arch_sys)) {
		if (str_miss[0] != '\0')
			strcat(str_miss, ",");
		strcat(str_miss, arch_name);
	}
}

int main(int argc, char *argv[])
{
	int i_x86 = 0;
	int i_x86_64 = 0;
	int i_arm = 0;
	int i_mips = 0;
	const char *sys_name, *tmp;
	char str_miss[256];

	do {
		str_miss[0] = '\0';
		tmp = x86_syscall_iterate_name(i_x86);
		if (tmp)
			sys_name = tmp;

		/* check each arch using x86 as the reference */
		syscall_check(str_miss, sys_name,
			      "x86_64", x86_64_syscall_iterate_name(i_x86_64));
		syscall_check(str_miss, sys_name,
			      "arm", arm_syscall_iterate_name(i_arm));
		syscall_check(str_miss, sys_name,
			      "mips", mips_syscall_iterate_name(i_mips));

		/* output the results */
		printf("%s: ", sys_name);
		if (str_miss[0] != '\0') {
			printf("MISS(%s)\n", str_miss);
			return 1;
		} else
			printf("OK\n");

		/* next */
		if (x86_syscall_iterate_name(i_x86 + 1))
			i_x86++;
		if (!x86_64_syscall_iterate_name(++i_x86_64))
			i_x86_64 = -1;
		if (!arm_syscall_iterate_name(++i_arm))
			i_arm = -1;
		if (!mips_syscall_iterate_name(++i_mips))
			i_mips = -1;
	} while (i_x86_64 >= 0 && i_arm >= 0 && i_mips >= 0);

	/* check for any leftovers */
	tmp = x86_syscall_iterate_name(i_x86 + 1);
	if (tmp) {
		printf("%s: ERROR, x86 has additional syscalls\n", tmp);
		return 1;
	}
	if (i_x86_64 >= 0) {
		printf("%s: ERROR, x86_64 has additional syscalls\n",
		       x86_64_syscall_iterate_name(i_x86_64));
		return 1;
	}
	if (i_arm >= 0) {
		printf("%s: ERROR, arm has additional syscalls\n",
			arm_syscall_iterate_name(i_arm));
		return 1;
	}
	if (i_mips >= 0) {
		printf("%s: ERROR, mips has additional syscalls\n",
		       mips_syscall_iterate_name(i_mips));
		return 1;
	}

	/* if we made it here, all is good */
	return 0;
}
