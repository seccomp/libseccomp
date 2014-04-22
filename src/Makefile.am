# -*- Makefile -*-

SUBDIRS = .
if ENABLE_PYTHON
SUBDIRS += python
endif

lib_LTLIBRARIES = libseccomp.la

libseccomp_la_SOURCES = api.c arch.c arch-x86.c arch-x86-syscalls.c \
	arch-x86_64.c arch-x86_64-syscalls.c arch-x32.c arch-x32-syscalls.c \
	arch-arm.c arch-arm-syscalls.c arch-mips.c arch-mips-syscalls.c \
	db.c hash.c gen_pfc.c gen_bpf.c \
	\
	arch-mips.h arch-arm.h arch-x32.h arch-x86.h arch-x86_64.h arch.h \
	db.h gen_bpf.h gen_pfc.h hash.h system.h
libseccomp_la_LDFLAGS = \
	-version-number ${VERSION_MAJOR}:${VERSION_MINOR}:${VERSION_MICRO}
