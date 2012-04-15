/**
 * Seccomp Library API
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
 */

/*
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License as
 * published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses>.
 */

#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>

#include <seccomp.h>

#include "arch.h"
#include "db.h"
#include "gen_pfc.h"
#include "gen_bpf.h"
#include "system.h"

/* the underlying code supports multiple simultaneous seccomp filters, but in
 * practice we really only need one per-process right now, and this is it */
static struct db_filter *filter = NULL;

/* NOTE - function header comment in include/seccomp.h */
int seccomp_init(uint32_t def_action)
{
	int rc;

	rc = db_action_valid(def_action);
	if (rc < 0)
		return rc;

	if (filter != NULL)
		return -EEXIST;
	filter = db_init(&arch_def_native, def_action);

	return (filter ? 0 : -ENOMEM);
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_reset(uint32_t def_action)
{
	if (filter != NULL)
		db_release(filter);

	return seccomp_init(def_action);
}

/* NOTE - function header comment in include/seccomp.h */
void seccomp_release(void)
{
	if (filter == NULL)
		return;

	db_release(filter);
	filter = NULL;
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_load(void)
{
	int rc;
	struct bpf_program *program;

	if (filter == NULL)
		return -EFAULT;

	program = gen_bpf_generate(filter);
	if (program == NULL)
		return -ENOMEM;
	/* attempt to set NO_NEW_PRIVS but don't fail if it doesn't work */
	if (filter->attr.nnp_enable) {
		rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		if (rc < 0)
			return -errno;
	}
	/* load the filter into the kernel */
	rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, program);
	gen_bpf_release(program);
	if (rc < 0)
		return -errno;

	return 0;
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_attr_get(enum scmp_filter_attr attr, uint32_t *value)
{
	if (filter == NULL)
		return -EFAULT;

	return db_attr_get(filter, attr, value);
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_attr_set(enum scmp_filter_attr attr, uint32_t value)
{
	if (filter == NULL)
		return -EFAULT;

	return db_attr_set(filter, attr, value);
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_syscall_priority(int syscall, uint8_t priority)
{
	int rc;

	if (filter == NULL)
		return -EFAULT;

	/* if this is a pseudo syscall (syscall < 0) then we need to rewrite
	 * the syscall for some arch specific reason */
	if (syscall < 0) {
		rc = arch_syscall_rewrite(filter->arch, &syscall);
		if (rc < 0)
			return rc;
	}

	return db_syscall_priority(filter, syscall, priority);
}

/**
 * Add a new rule to the current filter
 * @param strict the strict flag
 * @param action the filter action
 * @param syscall the syscall number
 * @param arg_cnt the number of argument filters in the argument filter chain
 * @param arg_list the argument filter chain, (uint, enum scmp_compare, ulong)
 *
 * This function adds a new argument/comparison/value to the seccomp filter for
 * a syscall; multiple arguments can be specified and they will be chained
 * together (essentially AND'd together) in the filter.  When the strict flag
 * is true the function will fail if the exact rule can not be added to the
 * filter, if the strict flag is false the function will not fail if the
 * function needs to adjust the rule due to architecture specifics.  Returns
 * zero on success, negative values on failure.
 *
 */
static int _seccomp_rule_add(unsigned int strict, uint32_t action, int syscall,
			     unsigned int arg_cnt, va_list arg_list)
{
	int rc;
	unsigned int iter;
	unsigned int chain_len_max;
	unsigned int arg_num;
	struct db_api_arg *chain = NULL;
	struct scmp_arg_cmp arg_data;

	if (filter == NULL)
		return -EFAULT;

	rc = db_action_valid(action);
	if (rc < 0)
		return rc;
	if (action == filter->attr.act_default)
		return -EPERM;

	/* collect the arguments for the filter rule */
	chain_len_max = arch_arg_count_max(filter->arch);
	chain = malloc(sizeof(*chain) * chain_len_max);
	if (chain == NULL)
		return -ENOMEM;
	memset(chain, 0, sizeof(*chain) * chain_len_max);
	for (iter = 0; iter < arg_cnt; iter++) {
		arg_data = va_arg(arg_list, struct scmp_arg_cmp);
		arg_num = arg_data.arg;
		if (arg_num < chain_len_max && chain[arg_num].valid == 0) {
			chain[arg_num].valid = 1;
			chain[arg_num].arg = arg_num;
			chain[arg_num].op = arg_data.op;
			/* XXX - we should check datum/mask size against the
			 *	 arch definition, e.g. 64 bit datum on x86 */
			switch (chain[arg_num].op) {
			case SCMP_CMP_NE:
			case SCMP_CMP_LT:
			case SCMP_CMP_LE:
			case SCMP_CMP_EQ:
			case SCMP_CMP_GE:
			case SCMP_CMP_GT:
				chain[arg_num].mask = DATUM_MAX;
				chain[arg_num].datum = arg_data.datum_a;
				break;
			case SCMP_CMP_MASKED_EQ:
				chain[arg_num].mask = arg_data.datum_a;
				chain[arg_num].datum = arg_data.datum_b;
				break;
			default:
				rc = -EINVAL;
				goto rule_add_return;
			}
		} else {
			rc = -EINVAL;
			goto rule_add_return;
		}
	}

	/* if this is a pseudo syscall (syscall < 0) then we need to rewrite
	 * the rule for some arch specific reason */
	if (syscall < 0) {
		rc = arch_filter_rewrite(filter->arch, strict, &syscall, chain);
		if (rc < 0)
			goto rule_add_return;
	}

	/* add the new rule to the existing filter */
	rc = db_rule_add(filter, action, syscall, chain);

rule_add_return:
	if (chain != NULL)
		free(chain);
	return rc;
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_rule_add(uint32_t action, int syscall, unsigned int arg_cnt, ...)
{
	int rc;
	va_list arg_list;

	va_start(arg_list, arg_cnt);
	rc = _seccomp_rule_add(0, action, syscall, arg_cnt, arg_list);
	va_end(arg_list);

	return rc;
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_rule_add_exact(uint32_t action,
			   int syscall, unsigned int arg_cnt, ...)
{
	int rc;
	va_list arg_list;

	va_start(arg_list, arg_cnt);
	rc = _seccomp_rule_add(1, action, syscall, arg_cnt, arg_list);
	va_end(arg_list);

	return rc;
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_gen_pfc(int fd)
{
	if (filter == NULL)
		return -EFAULT;

	return gen_pfc_generate(filter, fd);
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_gen_bpf(int fd)
{
	int rc;
	struct bpf_program *program;

	if (filter == NULL)
		return -EFAULT;

	program = gen_bpf_generate(filter);
	if (program == NULL)
		return -ENOMEM;
	rc = write(fd, program->blks, BPF_PGM_SIZE(program));
	gen_bpf_release(program);
	if (rc < 0)
		return -errno;

	return 0;
}
