#
# Enhanced Seccomp Library Build Macros
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
	@adddep_func() { \
		$(MV) $$1 $$1.dtmp; \
		$(CAT) $$1.dtmp | $(SED) -e 's/\([^\]\)$$/\1 \\/' | \
			( $(CAT) - && $(ECHO) " $$2" ) > $$1; \
		$(RM) -f $@.dtmp; \
	}; \
	adddep_func

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
LINK_LIB = \
	@link_lib_func() { \
		name=$${1//.so.*/.so}; \
		echo " LD $$name ($$1)"; \
		$(GCC) $(LDFLAGS) -o $@ $^ -shared -Wl,-soname=$$name; \
	}; \
	link_lib_func $@;

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
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) -m 0644 \
			$^ "$$dir"; \
	}; \
	install_func

INSTALL_SBIN_MACRO = \
	@install_sbin_func() { \
		dir="$(INSTALL_SBIN_DIR)"; \
		if [[ -n "$$2" ]]; then \
			$(ECHO) " INSTALL $$2"; \
		else \
			$(ECHO) " INSTALL $^ ($$dir/$^)"; \
		fi; \
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) \
			-d "$$dir"; \
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) -m 0644 \
			$^ "$$dir"; \
	}; \
	install_sbin_func

INSTALL_BIN_MACRO = \
	@install_bin_func() { \
		dir="$(INSTALL_BIN_DIR)"; \
		if [[ -n "$$2" ]]; then \
			$(ECHO) " INSTALL $$2"; \
		else \
			$(ECHO) " INSTALL $^ ($$dir/$^)"; \
		fi; \
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) \
			-d "$$dir"; \
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) -m 0644 \
			$^ "$$dir"; \
	}; \
	install_bin_func

INSTALL_LIB_MACRO = \
	@install_lib_func() { \
		dir="$(INSTALL_LIB_DIR)"; \
		if [[ -n "$$2" ]]; then \
			$(ECHO) " INSTALL $$2"; \
		else \
			$(ECHO) " INSTALL $^ ($$dir/$^)"; \
		fi; \
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) \
			-d "$$dir"; \
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) -m 0644 \
			$^ "$$dir"; \
	}; \
	install_lib_func

INSTALL_INC_MACRO = \
	@install_inc_func() { \
		dir="$(INSTALL_INC_DIR)"; \
		if [[ -n "$$2" ]]; then \
			$(ECHO) " INSTALL $$2"; \
		else \
			$(ECHO) " INSTALL $^ ($$dir/$^)"; \
		fi; \
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) \
			-d "$$dir"; \
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) -m 0644 \
			$^ "$$dir"; \
	}; \
	install_inc_func

INSTALL_MAN_MACRO = \
	@install_man_func() { \
		dir="$(INSTALL_MAN_DIR)"/"$$1"; \
		if [[ -n "$$2" ]]; then \
			$(ECHO) " INSTALL $$2"; \
		else \
			$(ECHO) " INSTALL $^ ($$dir/$^)"; \
		fi; \
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) \
			-d "$$dir"; \
		$(INSTALL) -o $(INSTALL_OWNER) -g $(INSTALL_GROUP) -m 0644 \
			$^ "$$dir"; \
	}; \
	install_man_func

#
# default build targets
#

%.o: %.c
	$(MAKEDEP)
	$(COMPILE)
