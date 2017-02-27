/**
 * Enhanced Seccomp Architecture Sycall Checker
 *
 * Copyright (c) 2014 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <paul@paul-moore.com>
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
#include "arch-x32.h"
#include "arch-arm.h"
#include "arch-aarch64.h"
#include "arch-mips.h"
#include "arch-mips64.h"
#include "arch-mips64n32.h"
#include "arch-ppc.h"
#include "arch-ppc64.h"
#include "arch-s390.h"
#include "arch-s390x.h"

/**
 * compare the syscall values
 * @param str_miss the other bad architectures
 * @param syscall the syscall string to compare against
 * @param arch_name the name of the arch being tested
 * @param arch_sys the syscall name to compare
 *
 * Compare the syscall names and update @str_miss if necessary.
 *
 */
void syscall_check(char *str_miss, const char *syscall,
		   const char *arch_name, const struct arch_syscall_def *sys)
{
	if (strcmp(syscall, sys->name)) {
		if (str_miss[0] != '\0')
			strcat(str_miss, ",");
		strcat(str_miss, arch_name);
	}
}

/**
 * main
 */
int main(int argc, char *argv[])
{
	int i_x86 = 0;
	int i_x86_64 = 0;
	int i_x32 = 0;
	int i_arm = 0;
	int i_aarch64 = 0;
	int i_mips = 0;
	int i_mips64 = 0;
	int i_mips64n32 = 0;
	int i_ppc = 0;
	int i_ppc64 = 0;
	int i_s390 = 0;
	int i_s390x = 0;
	char str_miss[256];
	const char *sys_name;
	const struct arch_syscall_def *sys;

	do {
		str_miss[0] = '\0';
		sys = x86_syscall_iterate(i_x86);
		if (sys == NULL || sys->name == NULL) {
			printf("FAULT\n");
			return 1;
		}
		sys_name = sys->name;

		/* check each arch using x86 as the reference */
		syscall_check(str_miss, sys_name, "x86_64",
			      x86_64_syscall_iterate(i_x86_64));
		syscall_check(str_miss, sys_name, "x32",
			      x32_syscall_iterate(i_x32));
		syscall_check(str_miss, sys_name, "arm",
			      arm_syscall_iterate(i_arm));
		syscall_check(str_miss, sys_name, "aarch64",
			      aarch64_syscall_iterate(i_aarch64));
		syscall_check(str_miss, sys_name, "mips",
			      mips_syscall_iterate(i_mips));
		syscall_check(str_miss, sys_name, "mips64",
			      mips64_syscall_iterate(i_mips64));
		syscall_check(str_miss, sys_name, "mips64n32",
			      mips64n32_syscall_iterate(i_mips64n32));
		syscall_check(str_miss, sys_name, "ppc",
			      ppc_syscall_iterate(i_ppc));
		syscall_check(str_miss, sys_name, "ppc64",
			      ppc64_syscall_iterate(i_ppc64));
		syscall_check(str_miss, sys_name, "s390",
			      s390_syscall_iterate(i_s390));
		syscall_check(str_miss, sys_name, "s390x",
			      s390x_syscall_iterate(i_s390x));

		/* output the results */
		printf("%s: ", sys_name);
		if (str_miss[0] != '\0') {
			printf("MISS(%s)\n", str_miss);
			return 1;
		} else
			printf("OK\n");

		/* next */
		if (x86_syscall_iterate(i_x86 + 1)->name)
			i_x86++;
		if (!x86_64_syscall_iterate(++i_x86_64)->name)
			i_x86_64 = -1;
		if (!x32_syscall_iterate(++i_x32)->name)
			i_x32 = -1;
		if (!arm_syscall_iterate(++i_arm)->name)
			i_arm = -1;
		if (!aarch64_syscall_iterate(++i_aarch64)->name)
			i_aarch64 = -1;
		if (!mips_syscall_iterate(++i_mips)->name)
			i_mips = -1;
		if (!mips64_syscall_iterate(++i_mips64)->name)
			i_mips64 = -1;
		if (!mips64n32_syscall_iterate(++i_mips64n32)->name)
			i_mips64n32 = -1;
		if (!ppc_syscall_iterate(++i_ppc)->name)
			i_ppc = -1;
		if (!ppc64_syscall_iterate(++i_ppc64)->name)
			i_ppc64 = -1;
		if (!s390_syscall_iterate(++i_s390)->name)
			i_s390 = -1;
		if (!s390x_syscall_iterate(++i_s390x)->name)
			i_s390x = -1;
	} while (i_x86_64 >= 0 && i_x32 >= 0 &&
		 i_arm >= 0 && i_aarch64 >= 0 &&
		 i_mips >= 0 && i_mips64 >= 0 && i_mips64n32 >= 0 &&
		 i_ppc >= 0 && i_ppc64 >= 0 &&
		 i_s390 >= 0 && i_s390x >= 0);

	/* check for any leftovers */
	sys = x86_syscall_iterate(i_x86 + 1);
	if (sys->name) {
		printf("ERROR, x86 has additional syscalls\n");
		return 1;
	}
	if (i_x86_64 >= 0) {
		printf("ERROR, x86_64 has additional syscalls\n");
		return 1;
	}
	if (i_x32 >= 0) {
		printf("ERROR, x32 has additional syscalls\n");
		return 1;
	}
	if (i_arm >= 0) {
		printf("ERROR, arm has additional syscalls\n");
		return 1;
	}
	if (i_aarch64 >= 0) {
		printf("ERROR, aarch64 has additional syscalls\n");
		return 1;
	}
	if (i_mips >= 0) {
		printf("ERROR, mips has additional syscalls\n");
		return 1;
	}
	if (i_mips64 >= 0) {
		printf("ERROR, mips64 has additional syscalls\n");
		return 1;
	}
	if (i_mips64n32 >= 0) {
		printf("ERROR, mips64n32 has additional syscalls\n");
		return 1;
	}
	if (i_ppc >= 0) {
		printf("ERROR, ppc has additional syscalls\n");
		return 1;
	}
	if (i_ppc64 >= 0) {
		printf("ERROR, ppc64 has additional syscalls\n");
		return 1;
	}
	if (i_s390 >= 0) {
		printf("ERROR, s390 has additional syscalls\n");
		return 1;
	}
	if (i_s390x >= 0) {
		printf("ERROR, s390x has additional syscalls\n");
		return 1;
	}

	/* if we made it here, all is good */
	return 0;
}
