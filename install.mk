#
# Enhanced Seccomp Library Installation Defaults
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

INSTALL_PREFIX ?= $(CONF_INSTALL_PREFIX)

INSTALL_SBIN_DIR ?= $(DESTDIR)/$(INSTALL_PREFIX)/sbin
INSTALL_BIN_DIR ?= $(DESTDIR)/$(INSTALL_PREFIX)/bin
INSTALL_LIB_DIR ?= $(DESTDIR)/$(CONF_INSTALL_LIBDIR)
INSTALL_INC_DIR ?= $(DESTDIR)/$(INSTALL_PREFIX)/include
INSTALL_MAN_DIR ?= $(DESTDIR)/$(INSTALL_PREFIX)/share/man

INSTALL_OWNER ?= $$(id -u)
INSTALL_GROUP ?= $$(id -g)
