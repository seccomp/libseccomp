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

-include ../configure.mk
include ../version_info

OBJS = util.o

LDFLAGS := ../src/libseccomp.a $(OBJS)

TESTS = 01-allow \
	02-basic \
	03-basic-chains \
	04-multilevel-chains \
	05-long-jumps \
	06-actions \
	07-db-bug-looping \
	08-subtree-checks \
	09-syscall-priority-pre \
	10-syscall-priority-post

DEPS_OBJS = $(OBJS:%.o=%.d)
DEPS_TESTS = $(TESTS:%=%.d)

#
# targets
#

.PHONY: clean

all: $(TESTS) $(OBJS)

-include $(DEPS_TESTS) $(DEPS_OBJS)

$(DEPS_TESTS):
	$(MAKEDEP_EXEC)
	$(ADDDEP) $@ ../src/libseccomp.a
	$(ADDDEP) $@ $(OBJS)

$(TESTS):
	$(COMPILE_EXEC)

clean:
	$(RM) -f $(DEPS_TESTS) $(DEPS_OBJS) $(TESTS) $(OBJS)
