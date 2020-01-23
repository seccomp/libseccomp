/**
 * Seccomp Library test program
 *
 * Copyright (c) 2020 Red Hat <gscrivan@redhat.com>
 * Author: Giuseppe Scrivano <gscrivan@redhat.com>
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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <seccomp.h>

unsigned int arch_list[] = {
	SCMP_ARCH_NATIVE,
	SCMP_ARCH_X86,
	SCMP_ARCH_X86_64,
	SCMP_ARCH_X32,
	SCMP_ARCH_ARM,
	SCMP_ARCH_AARCH64,
	SCMP_ARCH_MIPS,
	SCMP_ARCH_MIPS64,
	SCMP_ARCH_MIPS64N32,
	SCMP_ARCH_MIPSEL,
	SCMP_ARCH_MIPSEL64,
	SCMP_ARCH_MIPSEL64N32,
	SCMP_ARCH_PPC,
	SCMP_ARCH_PPC64,
	SCMP_ARCH_PPC64LE,
	SCMP_ARCH_S390,
	SCMP_ARCH_S390X,
	SCMP_ARCH_PARISC,
	SCMP_ARCH_PARISC64,
	SCMP_ARCH_RISCV64,
	-1
};

static int test_arch(int arch, int init)
{
	int n, iter = 0;

	for (iter = init; iter < init + 1000; iter++) {
		char *name;

		name = seccomp_syscall_resolve_num_arch(arch, iter);
		if (name == NULL)
			continue;

		n = seccomp_syscall_resolve_name_arch(arch, name);
		if (n != iter)
			return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int iter = 0;

	for (iter = 0; arch_list[iter] != -1; iter++) {
		int init = 0;
		if (arch_list[iter] == SCMP_ARCH_X32)
			init = 0x40000000;
		else if (arch_list[iter] == SCMP_ARCH_MIPS)
			init = 4000;
		else if (arch_list[iter] == SCMP_ARCH_MIPS64)
			init = 5000;
		else if (arch_list[iter] == SCMP_ARCH_MIPS64N32)
			init = 6000;
		if (test_arch(arch_list[iter], init) < 0)
			return 1;
	}

	return 0;
}
