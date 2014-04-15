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

OBJS = util.o

LIBFLAGS := ../src/libseccomp.a $(OBJS)

TOOLS = scmp_bpf_disasm \
	scmp_bpf_sim \
	scmp_sys_resolver \
	scmp_arch_detect

TOOLS_INSTALL = scmp_sys_resolver

DEPS_OBJS = $(OBJS:%.o=%.d)
DEPS_TOOLS = $(TOOLS:%=%.d)

#
# targets
#

.PHONY: install clean

all: $(TOOLS) $(OBJS)

-include $(DEPS_TOOLS) $(DEPS_OBJS)

$(DEPS_TOOLS):
	$(MAKEDEP_EXEC)
	$(ADDDEP) $@ $(OBJS)

$(TOOLS):
	$(COMPILE_EXEC)

install: $(TOOLS_INSTALL)
	$(INSTALL_BIN_MACRO)

clean:
	$(RM) $(DEPS_TOOLS) $(DEPS_OBJS) $(TOOLS)
