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

include ../macros.mk

#
# configuration
#

include ../version_info

LIB_STATIC = libseccomp.a
LIB_SHARED = libseccomp.so.$(VERSION_RELEASE)

OBJS =  api.o db.o \
	arch.o arch-i386.o arch-x86_64.o \
	hash.o \
	gen_pfc.o gen_bpf.o

DEPS = $(OBJS:%.o=%.d)

#
# targets
#

.PHONY: all clean

all: $(LIB_STATIC)

-include $(DEPS)

$(LIB_STATIC): $(OBJS)
	$(ARCHIVE)

clean:
	$(RM) -f $(DEPS) $(OBJS) $(LIB_STATIC) $(LIB_SHARED)
