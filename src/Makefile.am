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

@CODE_COVERAGE_RULES@

CODE_COVERAGE_IGNORE_PATTERN = /usr/include/bits/* */arch-syscall-check.c

SUBDIRS = .
if ENABLE_PYTHON
SUBDIRS += python
endif

SOURCES_ALL = \
	api.c system.h system.c helper.h helper.c \
	gen_pfc.h gen_pfc.c gen_bpf.h gen_bpf.c \
	hash.h hash.c \
	db.h db.c \
	arch.c arch.h \
	arch-x86.h arch-x86.c \
	arch-x86_64.h arch-x86_64.c \
	arch-x32.h arch-x32.c \
	arch-arm.h arch-arm.c \
	arch-aarch64.h arch-aarch64.c \
	arch-mips.h arch-mips.c \
	arch-mips64.h arch-mips64.c \
	arch-mips64n32.h arch-mips64n32.c \
	arch-parisc.h arch-parisc.c \
	arch-parisc64.h arch-parisc64.c \
	arch-ppc.h arch-ppc.c \
	arch-ppc64.h arch-ppc64.c \
	arch-riscv64.h arch-riscv64.c \
	arch-s390.h arch-s390.c \
	arch-s390x.h arch-s390x.c \
	syscalls.h syscalls.c syscalls.perf.c

EXTRA_DIST = \
	arch-syscall-validate arch-gperf-generate \
	syscalls.csv syscalls.perf.template

TESTS = arch-syscall-check

check_PROGRAMS = arch-syscall-check arch-syscall-dump

lib_LTLIBRARIES = libseccomp.la

arch_syscall_dump_SOURCES = arch-syscall-dump.c ${SOURCES_ALL}

arch_syscall_check_SOURCES = arch-syscall-check.c ${SOURCES_ALL}
arch_syscall_check_CFLAGS = ${AM_CFLAGS} ${CODE_COVERAGE_CFLAGS}
arch_syscall_check_LDFLAGS = ${CODE_COVERAGE_LDFLAGS}

libseccomp_la_SOURCES = ${SOURCES_ALL}
libseccomp_la_CPPFLAGS = ${AM_CPPFLAGS} ${CODE_COVERAGE_CPPFLAGS}
libseccomp_la_CFLAGS = ${AM_CFLAGS} ${CODE_COVERAGE_CFLAGS} ${CFLAGS} \
	-fPIC -DPIC -fvisibility=hidden
libseccomp_la_LDFLAGS = ${AM_LDFLAGS} ${CODE_COVERAGE_LDFLAGS} ${LDFLAGS} \
	-version-number ${VERSION_MAJOR}:${VERSION_MINOR}:${VERSION_MICRO}

EXTRA_DIST += syscalls.perf.c syscalls.perf
CLEANFILES = syscalls.perf.c syscalls.perf

syscalls.perf: syscalls.csv syscalls.perf.template
	${AM_V_GEN} ${srcdir}/arch-gperf-generate \
		${srcdir}/syscalls.csv ${srcdir}/syscalls.perf.template

syscalls.perf.c: syscalls.perf
	${GPERF} -m 100 --null-strings --pic -tCEG -T -S1 $< > $@

check-build:
	${MAKE} ${AM_MAKEFLAGS} ${check_PROGRAMS}
