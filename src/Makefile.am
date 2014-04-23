# -*- Makefile -*-

SUBDIRS = .
if ENABLE_PYTHON
SUBDIRS += python
endif

SOURCES = \
	api.c arch.c db.c gen_pfc.c gen_bpf.c hash.c \
	arch-x86.c arch-x86-syscalls.c \
	arch-x86_64.c arch-x86_64-syscalls.c \
	arch-x32.c arch-x32-syscalls.c \
	arch-arm.c arch-arm-syscalls.c \
	arch-mips.c arch-mips-syscalls.c \
	\
	arch.h db.h gen_bpf.h gen_pfc.h hash.h system.h \
	arch-x86.h arch-x86_64.h arch-x32.h\
	arch-arm.h \
	arch-mips.h

noinst_LTLIBRARIES = libseccomp-internal.la

libseccomp_internal_la_SOURCES = ${SOURCES}

lib_LTLIBRARIES = libseccomp.la

libseccomp_la_SOURCES = ${SOURCES}
libseccomp_la_CFLAGS = -fvisibility=hidden
libseccomp_la_LDFLAGS = \
	-version-number ${VERSION_MAJOR}:${VERSION_MINOR}:${VERSION_MICRO}

