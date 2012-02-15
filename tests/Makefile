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

#
# macros
#

include ../macros.mk

#
# configuration
#

include ../version_info

INCFLAGS := $(INCFLAGS) -I../include
LDFLAGS := ../src/libseccomp.a

TESTS = 01-basic \
	02-basic-pfc \
	03-chains-pfc \
	04-chains-bpf

#
# targets
#

.PHONY: clean

all: $(TESTS)

# XXX - find a better way to do this using $(TESTS)

01-basic: 01-basic.c
	$(COMPILE_EXEC)

02-basic-pfc: 02-basic-pfc.c
	$(COMPILE_EXEC)

03-chains-pfc: 03-chains-pfc.c
	$(COMPILE_EXEC)

04-chains-bpf: 04-chains-bpf.c
	$(COMPILE_EXEC)

clean:
	$(RM) -f $(TESTS)
