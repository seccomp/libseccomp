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
	api.o db.o arch.o \
	arch-x86.o arch-x86-syscalls.o \
	arch-x86_64.o arch-x86_64-syscalls.o \
	arch-x32.o arch-x32-syscalls.o \
	arch-arm.o arch-arm-syscalls.o \
	hash.o \
	gen_pfc.o gen_bpf.o

DEPS = $(OBJS:%.o=%.d)

#
# bindings configuration
#

BINDINGS =

ifeq ($(CONF_BINDINGS_PYTHON), 1)
	BINDINGS += python
endif

#
# targets
#

.PHONY: all install clean python

all: $(LIB_STATIC) $(LIB_SHARED) $(BINDINGS)

-include $(DEPS)

$(LIB_STATIC): $(OBJS)
	$(ARCHIVE)

$(LIB_SHARED): $(OBJS)
	$(LINK_LIB)

python: $(LIB_STATIC)
	@$(ECHO_INFO) "building in directory $@/ ..."
	@$(MAKE) -C $@

install: $(LIB_SHARED)
	$(INSTALL_LIB_MACRO)
	@for dir in $(BINDINGS); do \
		$(ECHO) ">> INFO: installing from $$dir/"; \
		$(MAKE) -C $$dir install; \
	done

clean:
	$(RM) $(DEPS) $(OBJS) $(LIB_STATIC) libseccomp.so.*
	@for dir in python; do \
		$(MAKE) -C $$dir clean; \
	done

