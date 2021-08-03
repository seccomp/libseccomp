/**
 * Seccomp Library test program
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
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

#include <errno.h>
#include <string.h>
#include <stdlib.h>

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

int main(int argc, char *argv[])
{
	int rc;
	int iter = 0;
	unsigned int arch;
	char *name = NULL;

	if (seccomp_syscall_resolve_name("open") != __SNR_open)
		goto fail;
	if (seccomp_syscall_resolve_name("read") != __SNR_read)
		goto fail;
	if (seccomp_syscall_resolve_name("INVALID") != __NR_SCMP_ERROR)
		goto fail;

	rc = seccomp_syscall_resolve_name_rewrite(SCMP_ARCH_NATIVE, "openat");
	if (rc != __SNR_openat)
		goto fail;

	while ((arch = arch_list[iter++]) != -1) {
		int sys;
		int nr_open;
		int nr_read;
		int nr_socket;
		int nr_shmctl;

		if (seccomp_syscall_resolve_name_arch(arch,
						      "INVALID") != __NR_SCMP_ERROR)
			goto fail;
		name = seccomp_syscall_resolve_num_arch(arch, __NR_SCMP_ERROR);
		if (name != NULL)
			goto fail;

		nr_open = seccomp_syscall_resolve_name_arch(arch, "open");
		if (nr_open == __NR_SCMP_ERROR)
			goto fail;
		nr_read = seccomp_syscall_resolve_name_arch(arch, "read");
		if (nr_read == __NR_SCMP_ERROR)
			goto fail;
		nr_socket = seccomp_syscall_resolve_name_rewrite(arch, "socket");
		if (nr_socket == __NR_SCMP_ERROR)
			goto fail;
		nr_shmctl = seccomp_syscall_resolve_name_rewrite(arch, "shmctl");
		if (nr_shmctl == __NR_SCMP_ERROR)
			goto fail;

		name = seccomp_syscall_resolve_num_arch(arch, nr_open);
		if (name == NULL || strcmp(name, "open") != 0)
			goto fail;
		free(name);
		name = NULL;

		name = seccomp_syscall_resolve_num_arch(arch, nr_read);
		if (name == NULL || strcmp(name, "read") != 0)
			goto fail;
		free(name);
		name = NULL;

		name = seccomp_syscall_resolve_num_arch(arch, nr_socket);
		if (name == NULL ||
		    (strcmp(name, "socket") != 0 &&
		     strcmp(name, "socketcall") != 0))
			goto fail;
		free(name);
		name = NULL;

		name = seccomp_syscall_resolve_num_arch(arch, nr_shmctl);
		if (name == NULL ||
		    (strcmp(name, "shmctl") != 0 && strcmp(name, "ipc") != 0))
			goto fail;
		free(name);
		name = NULL;

		/* socket pseudo-syscalls */
		if (seccomp_syscall_resolve_name_arch(arch, "socketcall") > 0) {
			for (sys = -101; sys >= -120; sys--) {
				name = seccomp_syscall_resolve_num_arch(arch,
									sys);
				if (name == NULL)
					goto fail;
				free(name);
				name = NULL;
			}
		}
		/* ipc pseudo-syscalls */
		if (seccomp_syscall_resolve_name_arch(arch, "ipc") > 0) {
			for (sys = -201; sys >= -204; sys--) {
				name = seccomp_syscall_resolve_num_arch(arch,
									sys);
				if (name == NULL)
					goto fail;
				free(name);
				name = NULL;
			}
			for (sys = -211; sys >= -214; sys--) {
				name = seccomp_syscall_resolve_num_arch(arch,
									sys);
				if (name == NULL)
					goto fail;
				free(name);
				name = NULL;
			}
			for (sys = -221; sys >= -224; sys--) {
				name = seccomp_syscall_resolve_num_arch(arch,
									sys);
				if (name == NULL)
					goto fail;
				free(name);
				name = NULL;
			}
		}
	}

	return 0;

fail:
	if (name != NULL)
		free(name);
	return 1;
}
