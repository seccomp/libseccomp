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

include $(TOPDIR)/configure.mk
include $(TOPDIR)/install.mk

LDFLAGS := ../src/libseccomp.a

TOOLS = scmp_bpf_disasm \
	scmp_bpf_sim \
	scmp_sys_resolver \
	scmp_arch_detect

TOOLS_INSTALL = scmp_sys_resolver

DEPS = $(TOOLS:%=%.d)

#
# targets
#

.PHONY: install clean

all: $(TOOLS)

-include $(DEPS)

$(DEPS):
	$(MAKEDEP_EXEC)

$(TOOLS):
	$(COMPILE_EXEC)

install: $(TOOLS_INSTALL)
	$(INSTALL_BIN_MACRO)

clean:
	$(RM) $(DEPS) $(TOOLS)
