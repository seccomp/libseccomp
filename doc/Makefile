#
# Enhanced Seccomp Library Makefile
#
# Copyright (c) 2012 Red Hat <pmoore@redhat.com>
# Author: Paul Moore <pmoore@redhat.com>
#

#
# This library is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License as
# published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, see <http://www.gnu.org/licenses>.
#

#
# macros
#

include ../macros.mk

#
# configuration
#

include $(TOPDIR)/version_info.mk
include $(TOPDIR)/configure.mk
include $(TOPDIR)/install.mk

MAN1 = \
	man/man1/scmp_sys_resolver.1

MAN3 = \
	man/man3/seccomp_init.3 \
	man/man3/seccomp_load.3 \
	man/man3/seccomp_release.3 \
	man/man3/seccomp_reset.3 \
	man/man3/seccomp_rule_add.3 \
	man/man3/seccomp_rule_add_exact.3 \
	man/man3/seccomp_syscall_priority.3 \
	man/man3/seccomp_syscall_resolve_name.3 \
	man/man3/seccomp_syscall_resolve_name_arch.3 \
	man/man3/seccomp_syscall_resolve_num_arch.3 \
	man/man3/seccomp_export_bpf.3 \
	man/man3/seccomp_export_pfc.3 \
	man/man3/seccomp_attr_set.3 \
	man/man3/seccomp_attr_get.3 \
	man/man3/seccomp_arch_add.3 \
	man/man3/seccomp_arch_exist.3 \
	man/man3/seccomp_arch_native.3 \
	man/man3/seccomp_arch_remove.3 \
	man/man3/seccomp_merge.3

#
# targets
#

.PHONY: all install install_man1 install_man3

all:

install: install_man1 install_man3

install_man1: $(MAN1)
	$(INSTALL_MAN1_MACRO)

install_man3: $(MAN3)
	$(INSTALL_MAN3_MACRO)
