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

OBJS = util.o

LDFLAGS := ../src/libseccomp.a $(OBJS)

TEST_PRIVATE = 00-test

TESTS = 01-sim-allow \
	02-sim-basic \
	03-sim-basic_chains \
	04-sim-multilevel_chains \
	05-sim-long_jumps \
	06-sim-actions \
	07-sim-db_bug_looping \
	08-sim-subtree_checks \
	09-sim-syscall_priority_pre \
	10-sim-syscall_priority_post \
	11-basic-basic_errors \
	12-sim-basic_masked_ops \
	13-basic-attrs \
	14-sim-reset \
	15-basic-resolver \
	16-sim-arch_basic \
	17-sim-arch_merge \
	18-sim-basic_whitelist \
	19-sim-missing_syscalls \
	20-live-basic_die \
	21-live-basic_allow \
	22-sim-basic_chains_array \
	23-sim-arch_all_basic \
	24-live-arg_allow \
	25-sim-multilevel_chains_adv

DEPS_OBJS = $(OBJS:%.o=%.d)
DEPS_TESTS = $(TESTS:%=%.d)

#
# targets
#

.PHONY: check clean

all: $(TESTS) $(OBJS)

-include $(DEPS_TESTS) $(DEPS_OBJS)

$(DEPS_TESTS):
	$(MAKEDEP_EXEC)
	$(ADDDEP) $@ ../src/libseccomp.a
	$(ADDDEP) $@ $(OBJS)

$(TESTS):
	$(COMPILE_EXEC)

$(TEST_PRIVATE): 00-test.c $(OBJS) ../src/libseccomp.a
	$(COMPILE_EXEC)

check: $(TESTS)
	./regression

clean:
	$(RM) $(DEPS_TESTS) $(DEPS_OBJS) $(TESTS) $(TEST_PRIVATE) $(OBJS) *.pyc
