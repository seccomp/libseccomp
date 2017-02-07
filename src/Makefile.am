####
# Seccomp Library Source Files
#

#
# This library is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, see <http://www.gnu.org/licenses>.
#

SUBDIRS = .
if ENABLE_PYTHON
SUBDIRS += python
endif

SOURCES_ALL = \
	api.c system.h system.c \
	gen_pfc.h gen_pfc.c gen_bpf.h gen_bpf.c \
	hash.h hash.c \
	db.h db.c \
	arch.c arch.h \
	arch-x86.h arch-x86.c arch-x86-syscalls.c \
	arch-x86_64.h arch-x86_64.c arch-x86_64-syscalls.c \
	arch-x32.h arch-x32.c arch-x32-syscalls.c \
	arch-arm.h arch-arm.c arch-arm-syscalls.c \
	arch-aarch64.h arch-aarch64.c arch-aarch64-syscalls.c \
	arch-mips.h arch-mips.c arch-mips-syscalls.c \
	arch-mips64.h arch-mips64.c arch-mips64-syscalls.c \
	arch-mips64n32.h arch-mips64n32.c arch-mips64n32-syscalls.c \
	arch-ppc.h arch-ppc.c arch-ppc-syscalls.c \
	arch-ppc64.h arch-ppc64.c arch-ppc64-syscalls.c \
	arch-s390.h arch-s390.c arch-s390-syscalls.c \
	arch-s390x.h arch-s390x.c arch-s390x-syscalls.c

EXTRA_DIST = arch-syscall-validate

TESTS = arch-syscall-check

check_PROGRAMS = arch-syscall-check arch-syscall-dump

lib_LTLIBRARIES = libseccomp.la

arch_syscall_dump_SOURCES = arch-syscall-dump.c ${SOURCES_ALL}

arch_syscall_check_SOURCES = arch-syscall-check.c ${SOURCES_ALL}

libseccomp_la_SOURCES = ${SOURCES_ALL}
libseccomp_la_CPPFLAGS = ${AM_CPPFLAGS} ${CODE_COVERAGE_CPPFLAGS} \
	-I${top_builddir}/include
libseccomp_la_CFLAGS = ${AM_CFLAGS} ${CODE_COVERAGE_CFLAGS} ${CFLAGS} \
	-fPIC -DPIC -fvisibility=hidden
libseccomp_la_LDFLAGS = ${AM_LDFLAGS} ${CODE_COVERAGE_LDFLAGS} ${LDFLAGS} \
	-version-number ${VERSION_MAJOR}:${VERSION_MINOR}:${VERSION_MICRO}

check-build:
	${MAKE} ${AM_MAKEFLAGS} ${check_PROGRAMS}
