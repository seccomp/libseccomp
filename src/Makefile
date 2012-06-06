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

LIB_STATIC = libseccomp.a
LIB_SHARED = libseccomp.so.$(VERSION_RELEASE)

OBJS = \
	api.o db.o \
	arch.o arch-i386.o \
	hash.o \
	gen_pfc.o gen_bpf.o

DEPS = $(OBJS:%.o=%.d)

#
# targets
#

.PHONY: all install clean

all: $(LIB_STATIC) $(LIB_SHARED)

-include $(DEPS)

$(LIB_STATIC): $(OBJS)
	$(ARCHIVE)

$(LIB_SHARED): $(OBJS)
	$(LINK_LIB)

install: $(LIB_SHARED)
	$(INSTALL_LIB_MACRO)

clean:
	$(RM) -f $(DEPS) $(OBJS) $(LIB_STATIC) $(LIB_SHARED)
