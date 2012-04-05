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

include ../configure.mk
include ../install.mk
include ../version_info

MAN3 = \
	man/man3/seccomp_init.3 \
	man/man3/seccomp_load.3 \
	man/man3/seccomp_release.3 \
	man/man3/seccomp_reset.3 \
	man/man3/seccomp_rule_add.3 \
	man/man3/seccomp_rule_add_exact.3 \
	man/man3/seccomp_syscall_priority.3 \

#
# targets
#

.PHONY: all install install_man3

all:

install: install_man3

install_man3: $(MAN3)
	$(INSTALL_MACRO) share/man/man3 "manpages"
