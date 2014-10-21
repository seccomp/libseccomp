####
# Seccomp Library Tests
#

#
# This library is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, see <http://www.gnu.org/licenses>.
#

AM_LDFLAGS = -static
LDADD = util.la ../src/libseccomp.la

check_LTLIBRARIES = util.la
util_la_SOURCES = util.c util.h
util_la_LDFLAGS = -module

TESTS = regression

check_PROGRAMS = \
	01-sim-allow \
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
	23-sim-arch_all_le_basic \
	24-live-arg_allow \
	25-sim-multilevel_chains_adv \
	26-sim-arch_all_be_basic

EXTRA_PROGRAMS = 00-test

check-build:
	${MAKE} ${AM_MAKEFLAGS} ${check_PROGRAMS}

clean-local:
	${RM} -f 00-test *.pyc
