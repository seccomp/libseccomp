# -*- Makefile -*-

ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src tools tests

pkgconfdir = ${libdir}/pkgconfig
pkgconf_DATA = libseccomp.pc

nodist_include_HEADERS = include/seccomp.h

dist_man_MANS = \
	doc/man/man1/scmp_sys_resolver.1 \
	doc/man/man3/seccomp_arch_add.3 \
	doc/man/man3/seccomp_arch_exist.3 \
	doc/man/man3/seccomp_arch_native.3 \
	doc/man/man3/seccomp_arch_remove.3 \
	doc/man/man3/seccomp_attr_get.3 \
	doc/man/man3/seccomp_attr_set.3 \
	doc/man/man3/seccomp_export_bpf.3 \
	doc/man/man3/seccomp_export_pfc.3 \
	doc/man/man3/seccomp_init.3 \
	doc/man/man3/seccomp_load.3 \
	doc/man/man3/seccomp_merge.3 \
	doc/man/man3/seccomp_release.3 \
	doc/man/man3/seccomp_reset.3 \
	doc/man/man3/seccomp_rule_add.3 \
	doc/man/man3/seccomp_rule_add_exact.3 \
	doc/man/man3/seccomp_syscall_priority.3 \
	doc/man/man3/seccomp_syscall_resolve_name.3 \
	doc/man/man3/seccomp_syscall_resolve_name_arch.3 \
	doc/man/man3/seccomp_syscall_resolve_num_arch.3
