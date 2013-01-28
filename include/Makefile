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

HDR_BUILD = seccomp.h

#
# targets
#

.PHONY: all install clean

all: $(HDR_BUILD)

install: $(HDR_BUILD)
	$(INSTALL_INC_MACRO)

seccomp.h: seccomp.h.in
	@$(ECHO) " GEN $@"
	$(CAT) $< | \
	$(SED) -e 's/%%VERSION_MAJOR%%/$(VERSION_MAJOR)/g' | \
	$(SED) -e 's/%%VERSION_MINOR%%/$(VERSION_MINOR)/g' | \
	$(SED) -e 's/%%VERSION_MICRO%%/$(VERSION_MICRO)/g' > $@

clean:
	@$(RM) $(HDR_BUILD)
