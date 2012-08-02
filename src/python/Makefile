#
# Enhanced Seccomp Library Python Bindings Makefile
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

include ../../macros.mk

#
# configuration
#

include $(TOPDIR)/version_info.mk
include $(TOPDIR)/configure.mk
include $(TOPDIR)/install.mk

LIB_STATIC = ../libseccomp.a

#
# targets
#

.PHONY: all install clean

all: build

build: $(LIB_STATIC) libseccomp.pxd seccomp.pyx
	@$(RM) seccomp.c
	$(PY_BUILD) && touch build

install: build
	$(PY_INSTALL) install --prefix=$(DESTDIR)/$(INSTALL_PREFIX)

clean:
	$(RM) -rf build seccomp.c
