#
# Enhanced Seccomp Library Build Macros
#
# Copyright (c) 2012 Red Hat <pmoore@redhat.com>
# Author: Paul Moore <pmoore@redhat.com>
#

#
# This program is free software: you can redistribute it and/or modify
# it under the terms of version 2 of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

SHELL = /bin/bash

#
# simple /bin/bash script to find the top of the tree
#

TOPDIR = $$(\
	ftd() { \
		cd $$1; \
		if [[ -r "macros.mk" ]]; then \
			pwd; \
		else \
			ftd "../"; \
		 fi \
	}; \
	ftd .)

#
# build configuration
#

INCFLAGS = -I$(TOPDIR) -I$(TOPDIR)/include
LIBFLAGS =

CFLAGS  ?= -fPIC -Wl,-z,relro -Wall -O0 -g
LDFLAGS ?= -z relro -g

#
# build tools
#

MV ?= mv
CAT ?= cat
ECHO ?= echo

SED ?= sed

# we require gcc specific functionality
GCC ?= gcc

INSTALL ?= install

#
# auto dependencies
#

MAKEDEP = @$(GCC) $(INCFLAGS) -MM -MF $(patsubst %.o,%.d,$@) $<;
MAKEDEP_EXEC = \
	@$(GCC) $(INCFLAGS) -MM -MT $(patsubst %.d,%,$@) \
		-MF $@ $(patsubst %.d,%.c,$@);

ADDDEP = \
	@adep() { \
		$(MV) $$1 $$1.dtmp; \
		$(CAT) $$1.dtmp | $(SED) -e 's/\([^\]\)$$/\1 \\/' | \
			( $(CAT) - && $(ECHO) " $$2" ) > $$1; \
		$(RM) -f $@.dtmp; \
	}; \
	adep

#
# build constants
#

VERSION_HDR = version.h

#
# build macros
#

ARCHIVE = @echo " AR $@ (add/update: $?)"; $(AR) -cru $@ $?;
COMPILE = @echo " CC $@"; $(GCC) $(CFLAGS) $(INCFLAGS) -o $@ -c $<;
COMPILE_EXEC = @echo " CC $@"; $(GCC) $(CFLAGS) $(INCFLAGS) -o $@ $< $(LDFLAGS);
LINK_EXEC = @echo " LD $@"; $(GCC) $(LDFLAGS) -o $@ $^ $(LIBFLAGS);
LINK_LIB  = @echo " LD $@"; $(GCC) $(LDFLAGS) -o $@ $^ -shared -Wl,-soname=$@;

#
# install macros
#

INSTALL_MACRO = \
	@install_func() { \
		dir="$(INSTALL_PREFIX)"/"$$1"; \
		if [[ -n "$$2" ]]; then \
			$(ECHO) " INSTALL $$2"; \
		else \
			$(ECHO) " INSTALL $^ ($$dir/$^)"; \
		fi; \
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) \
			-d "$$dir"; \
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) \
			$^ "$$dir"; \
	}; \
	install_func

#
# default build targets
#

%.o: %.c
	$(MAKEDEP)
	$(COMPILE)
