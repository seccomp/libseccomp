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

TOOLS = bpf_disasm

#
# targets
#

.PHONY: clean

all: $(TOOLS)

# XXX - find a better way to do this using $(TOOLS)

bpf_disasm: bpf_disasm.c
	$(COMPILE_EXEC)

clean:
	$(RM) -f $(TOOLS)
