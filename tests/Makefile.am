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

if CODE_COVERAGE_ENABLED
DBG_STATIC =
else
DBG_STATIC = -static
endif

AM_LDFLAGS = ${DBG_STATIC} -lpthread

LDADD = util.la ../src/libseccomp.la ${CODE_COVERAGE_LIBS}

check_LTLIBRARIES = util.la
util_la_SOURCES = util.c util.h
util_la_LDFLAGS = -module

miniseq_LDADD =

TESTS = regression

check_PROGRAMS = \
	miniseq \
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
	18-sim-basic_allowlist \
	19-sim-missing_syscalls \
	20-live-basic_die \
	21-live-basic_allow \
	22-sim-basic_chains_array \
	23-sim-arch_all_le_basic \
	24-live-arg_allow \
	25-sim-multilevel_chains_adv \
	26-sim-arch_all_be_basic \
	27-sim-bpf_blk_state \
	28-sim-arch_x86 \
	29-sim-pseudo_syscall \
	30-sim-socket_syscalls \
	31-basic-version_check \
	32-live-tsync_allow \
	33-sim-socket_syscalls_be \
	34-sim-basic_denylist \
	35-sim-negative_one \
	36-sim-ipc_syscalls \
	37-sim-ipc_syscalls_be \
	38-basic-pfc_coverage \
	39-basic-api_level \
	40-sim-log \
	41-sim-syscall_priority_arch \
	42-sim-adv_chains \
	43-sim-a2_order \
	44-live-a2_order \
	45-sim-chain_code_coverage \
	46-sim-kill_process \
	47-live-kill_process \
	48-sim-32b_args \
	49-sim-64b_comparisons \
	50-sim-hash_collision \
	51-live-user_notification \
	52-basic-load \
	53-sim-binary_tree \
	54-live-binary_tree \
	55-basic-pfc_binary_tree \
	56-basic-iterate_syscalls \
	57-basic-rawsysrc \
	58-live-tsync_notify \
	59-basic-empty_binary_tree

EXTRA_DIST_TESTPYTHON = \
	util.py \
	01-sim-allow.py \
	02-sim-basic.py \
	03-sim-basic_chains.py \
	04-sim-multilevel_chains.py \
	05-sim-long_jumps.py \
	06-sim-actions.py \
	07-sim-db_bug_looping.py \
	08-sim-subtree_checks.py \
	09-sim-syscall_priority_pre.py \
	10-sim-syscall_priority_post.py \
	11-basic-basic_errors.py \
	12-sim-basic_masked_ops.py \
	13-basic-attrs.py \
	14-sim-reset.py \
	15-basic-resolver.py \
	16-sim-arch_basic.py \
	17-sim-arch_merge.py \
	18-sim-basic_allowlist.py \
	19-sim-missing_syscalls.py \
	20-live-basic_die.py \
	21-live-basic_allow.py \
	22-sim-basic_chains_array.py \
	23-sim-arch_all_le_basic.py \
	24-live-arg_allow.py \
	25-sim-multilevel_chains_adv.py \
	26-sim-arch_all_be_basic.py \
	27-sim-bpf_blk_state.py \
	28-sim-arch_x86.py \
	29-sim-pseudo_syscall.py \
	30-sim-socket_syscalls.py \
	31-basic-version_check.py \
	32-live-tsync_allow.py \
	33-sim-socket_syscalls_be.py \
	34-sim-basic_denylist.py \
	35-sim-negative_one.py \
	36-sim-ipc_syscalls.py \
	37-sim-ipc_syscalls_be.py \
	39-basic-api_level.py \
	40-sim-log.py \
	41-sim-syscall_priority_arch.py \
	42-sim-adv_chains.py \
	43-sim-a2_order.py \
	44-live-a2_order.py \
	45-sim-chain_code_coverage.py \
	46-sim-kill_process.py \
	47-live-kill_process.py \
	48-sim-32b_args.py \
	49-sim-64b_comparisons.py \
	50-sim-hash_collision.py \
	51-live-user_notification.py \
	52-basic-load.py \
	53-sim-binary_tree.py \
	54-live-binary_tree.py \
	56-basic-iterate_syscalls.py \
	57-basic-rawsysrc.py \
	58-live-tsync_notify.py \
	59-basic-empty_binary_tree.py

EXTRA_DIST_TESTCFGS = \
	01-sim-allow.tests \
	02-sim-basic.tests \
	03-sim-basic_chains.tests \
	04-sim-multilevel_chains.tests \
	05-sim-long_jumps.tests \
	06-sim-actions.tests \
	07-sim-db_bug_looping.tests \
	08-sim-subtree_checks.tests \
	09-sim-syscall_priority_pre.tests \
	10-sim-syscall_priority_post.tests \
	11-basic-basic_errors.tests \
	12-sim-basic_masked_ops.tests \
	13-basic-attrs.tests \
	14-sim-reset.tests \
	15-basic-resolver.tests \
	16-sim-arch_basic.tests \
	17-sim-arch_merge.tests \
	18-sim-basic_allowlist.tests \
	19-sim-missing_syscalls.tests \
	20-live-basic_die.tests \
	21-live-basic_allow.tests \
	22-sim-basic_chains_array.tests \
	23-sim-arch_all_le_basic.tests \
	24-live-arg_allow.tests \
	25-sim-multilevel_chains_adv.tests \
	26-sim-arch_all_be_basic.tests \
	27-sim-bpf_blk_state.tests \
	28-sim-arch_x86.tests \
	29-sim-pseudo_syscall.tests \
	30-sim-socket_syscalls.tests \
	31-basic-version_check.tests \
	32-live-tsync_allow.tests \
	33-sim-socket_syscalls_be.tests \
	34-sim-basic_denylist.tests \
	35-sim-negative_one.tests \
	36-sim-ipc_syscalls.tests \
	37-sim-ipc_syscalls_be.tests \
	38-basic-pfc_coverage.tests \
	39-basic-api_level.tests \
	40-sim-log.tests \
	41-sim-syscall_priority_arch.tests \
	42-sim-adv_chains.tests \
	43-sim-a2_order.tests \
	44-live-a2_order.tests \
	45-sim-chain_code_coverage.tests \
	46-sim-kill_process.tests \
	47-live-kill_process.tests \
	48-sim-32b_args.tests \
	49-sim-64b_comparisons.tests \
	50-sim-hash_collision.tests \
	51-live-user_notification.tests \
	52-basic-load.tests \
	53-sim-binary_tree.tests \
	54-live-binary_tree.tests \
	55-basic-pfc_binary_tree.tests \
	56-basic-iterate_syscalls.tests \
	57-basic-rawsysrc.tests \
	58-live-tsync_notify.tests \
	59-basic-empty_binary_tree.tests

EXTRA_DIST_TESTSCRIPTS = \
	38-basic-pfc_coverage.sh 38-basic-pfc_coverage.pfc \
	55-basic-pfc_binary_tree.sh 55-basic-pfc_binary_tree.pfc

EXTRA_DIST_TESTTOOLS = regression testdiff testgen

EXTRA_DIST_TESTVALGRIND = valgrind_test.supp

EXTRA_DIST = \
	${EXTRA_DIST_TESTCFGS} \
	${EXTRA_DIST_TESTPYTHON} \
	${EXTRA_DIST_TESTSCRIPTS} \
	${EXTRA_DIST_TESTTOOLS} \
	${EXTRA_DIST_TESTVALGRIND}

nodist_00_test_SOURCES = 00-test.c
EXTRA_PROGRAMS = 00-test

check-build:
	${MAKE} ${AM_MAKEFLAGS} ${check_PROGRAMS}

clean-local:
	${RM} -f 00-test *.pyc
