/**
 * Seccomp Library test program
 *
 * Copyright (c) 2025 Paul Moore <paul@paul-moore.com>
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

#include <seccomp.h>

#include "util.h"

int main(int argc, char *argv[])
{
	int rc = 0;
	uint32_t token;
	const char *name;

	/*
	 * Verify round-trip: seccomp_arch_resolve_name() then
	 * seccomp_arch_name() must return the original name for every
	 * known architecture.
	 */
#define CHECK_ARCH(str, tok) \
	do { \
		token = seccomp_arch_resolve_name(str); \
		if (token != (tok)) { \
			rc = -1; \
			goto out; \
		} \
		name = seccomp_arch_name(token); \
		if (name == NULL || strcmp(name, (str)) != 0) { \
			rc = -1; \
			goto out; \
		} \
	} while (0)

	CHECK_ARCH("x86",          SCMP_ARCH_X86);
	CHECK_ARCH("x86_64",       SCMP_ARCH_X86_64);
	CHECK_ARCH("x32",          SCMP_ARCH_X32);
	CHECK_ARCH("arm",          SCMP_ARCH_ARM);
	CHECK_ARCH("aarch64",      SCMP_ARCH_AARCH64);
	CHECK_ARCH("loongarch64",  SCMP_ARCH_LOONGARCH64);
	CHECK_ARCH("m68k",         SCMP_ARCH_M68K);
	CHECK_ARCH("mips",         SCMP_ARCH_MIPS);
	CHECK_ARCH("mipsel",       SCMP_ARCH_MIPSEL);
	CHECK_ARCH("mips64",       SCMP_ARCH_MIPS64);
	CHECK_ARCH("mipsel64",     SCMP_ARCH_MIPSEL64);
	CHECK_ARCH("mips64n32",    SCMP_ARCH_MIPS64N32);
	CHECK_ARCH("mipsel64n32",  SCMP_ARCH_MIPSEL64N32);
	CHECK_ARCH("parisc",       SCMP_ARCH_PARISC);
	CHECK_ARCH("parisc64",     SCMP_ARCH_PARISC64);
	CHECK_ARCH("ppc",          SCMP_ARCH_PPC);
	CHECK_ARCH("ppc64",        SCMP_ARCH_PPC64);
	CHECK_ARCH("ppc64le",      SCMP_ARCH_PPC64LE);
	CHECK_ARCH("s390",         SCMP_ARCH_S390);
	CHECK_ARCH("s390x",        SCMP_ARCH_S390X);
	CHECK_ARCH("riscv64",      SCMP_ARCH_RISCV64);
	CHECK_ARCH("sheb",         SCMP_ARCH_SHEB);
	CHECK_ARCH("sh",           SCMP_ARCH_SH);
#undef CHECK_ARCH

	/* SCMP_ARCH_NATIVE must resolve to the native arch's name */
	name = seccomp_arch_name(SCMP_ARCH_NATIVE);
	if (name == NULL) {
		rc = -1;
		goto out;
	}
	token = seccomp_arch_resolve_name(name);
	if (token != seccomp_arch_native()) {
		rc = -1;
		goto out;
	}

	/* invalid token must return NULL */
	name = seccomp_arch_name(0xdeadbeef);
	if (name != NULL) {
		rc = -1;
		goto out;
	}

out:
	return (rc < 0 ? EOPNOTSUPP : 0);
}
