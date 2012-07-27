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

include macros.mk

#
# configuration
#

-include version_info.mk
-include configure.mk
include install.mk

#
# targets
#

CONFIGS = configure.mk configure.h version_info.mk libseccomp.pc
SUBDIRS_BUILD = src tests tools
SUBDIRS_INSTALL = src include doc

.PHONY: tarball install ctags cstags clean dist-clean $(SUBDIRS_BUILD)

all: $(SUBDIRS_BUILD)

$(CONFIGS): version_info
	@$(ECHO) "INFO: automatically generating configuration ..."
	@./configure

tarball: clean
	@ver=$(VERSION_RELEASE); \
	tarball=libseccomp-$$ver.tar.gz; \
	$(ECHO) "INFO: creating the tarball ../$$tarball"; \
	tmp_dir=$$(mktemp -d /tmp/libseccomp.XXXXX); \
	rel_dir=$$tmp_dir/libseccomp-$$ver; \
	$(MKDIR) $$rel_dir; \
	$(TAR) cf - --exclude=*~ --exclude=.git* --exclude=.stgit* . | \
		(cd $$rel_dir; tar xf -); \
	(cd $$tmp_dir; $(TAR) zcf $$tarball libseccomp-$$ver); \
	$(MV) $$tmp_dir/$$tarball ..; \
	$(RM) -rf $$tmp_dir;

$(VERSION_HDR): version_info.mk
	@$(ECHO) "INFO: creating the version header file"
	@hdr="$(VERSION_HDR)"; \
	$(ECHO) "/* automatically generated - do not edit */" > $$hdr; \
	$(ECHO) "#ifndef _VERSION_H" >> $$hdr; \
	$(ECHO) "#define _VERSION_H" >> $$hdr; \
	$(ECHO) "#define VERSION_RELEASE \"$(VERSION_RELEASE)\"" >> $$hdr; \
	$(ECHO) "#endif" >> $$hdr;

src: $(VERSION_HDR) $(CONFIGS)
	@$(ECHO) "INFO: building in directory $@/ ..."
	@$(MAKE) -C $@

tests: src
	@$(ECHO) "INFO: building in directory $@/ ..."
	@$(MAKE) -C $@

tools: src
	@$(ECHO) "INFO: building in directory $@/ ..."
	@$(MAKE) -C $@

install: $(SUBDIRS_BUILD)
	@$(ECHO) "INFO: installing in $(INSTALL_PREFIX) ..."
	$(INSTALL_PC_MACRO) libseccomp.pc
	@for dir in $(SUBDIRS_INSTALL); do \
		$(ECHO) "INFO: installing from $$dir/"; \
		$(MAKE) -C $$dir install; \
	done

ctags:
	@$(ECHO) "INFO: generating ctags for the project ..."
	@ctags -R *

cstags:
	@$(ECHO) "INFO: generating cscope tags for the project ..."
	@find -iname *.[ch] > cscope.files
	@cscope -b -q -k

clean:
	@$(ECHO) "INFO: cleaning up libseccomp"
	@for dir in $(SUBDIRS_BUILD); do \
		$(MAKE) -C $$dir clean; \
	done

dist-clean: clean
	@$(ECHO) "INFO: removing the configuration files"
	@$(RM) $(CONFIGS)
