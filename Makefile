#
# Enhanced Seccomp Library Makefile
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

#
# macros
#

include macros.mk

#
# configuration
#

INSTALL_PREFIX ?= /usr/local

INSTALL_SBIN_DIR ?= $(INSTALL_PREFIX)/sbin
INSTALL_BIN_DIR ?= $(INSTALL_PREFIX)/bin
INSTALL_LIB_DIR ?= $(INSTALL_PREFIX)/lib
INSTALL_MAN_DIR ?= $(INSTALL_PREFIX)/share/man

INSTALL_OWNER ?= root
INSTALL_GROUP ?= root

#
# targets
#

SUBDIRS = src tests tools

.PHONY: tarball install ctags cstags clean $(SUBDIRS)

all: $(SUBDIRS)

tarball: clean
	@ver=$$(source ./version_info; echo $$VERSION_RELEASE); \
	tarball=libseccomp-$$ver.tar.gz; \
	echo "INFO: creating the tarball ../$$tarball"; \
	tmp_dir=$$(mktemp -d /tmp/libseccomp.XXXXX); \
	rel_dir=$$tmp_dir/libseccomp-$$ver; \
	mkdir $$rel_dir; \
	tar cf - --exclude=.svn . | (cd $$rel_dir; tar xf -); \
	(cd $$tmp_dir; tar zcf $$tarball libseccomp-$$ver); \
	mv $$tmp_dir/$$tarball ..; \
	rm -rf $$tmp_dir;

install: $(SUBDIRS)
	@echo "INFO: installing files in $(INSTALL_PREFIX)"
	@echo "- XXX - TBD"

$(VERSION_HDR): version_info
	@echo "INFO: creating the version header file"
	@hdr="$(VERSION_HDR)"; \
	source ./version_info; \
	echo "/* automatically generated - do not edit */" > $$hdr; \
	echo "#ifndef _VERSION_H" >> $$hdr; \
	echo "#define _VERSION_H" >> $$hdr; \
	echo "#define VERSION_RELEASE \"$$VERSION_RELEASE\"" >> $$hdr; \
	echo "#endif" >> $$hdr;

$(SUBDIRS): $(VERSION_HDR)
	@echo "INFO: entering directory $@/ ..."
	@$(MAKE) -s -C $@

ctags:
	@echo "INFO: generating ctags for the project ..."
	@ctags -R *

cstags:
	@echo "INFO: generating cscope tags for the project ..."
	@find -iname *.[ch] > cscope.files
	@cscope -b -q -k

clean:
	@echo "INFO: removing the version header file"; \
	rm -f $(VERSION_HDR)
	@for dir in $(SUBDIRS); do \
		echo "INFO: cleaning in $$dir/"; \
		$(MAKE) -s -C $$dir clean; \
	done
