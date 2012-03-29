/**
 * Seccomp Library API
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <pmoore@redhat.com>
 */

/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

/* this is for systems that don't yet have this magic value defined */
#ifndef PR_ATTACH_SECCOMP_FILTER
#define PR_ATTACH_SECCOMP_FILTER	37
#endif

/* the underlying code supports multiple simultaneous seccomp filters, but in
 * practice we really only need one per-process right now, and this is it */
static struct db_filter *filter = NULL;

/**
 * Validate the seccomp action
 * @param action the seccomp action
 *
 * Verify that the given action is a valid seccomp action; return zero if
 * valid, -EINVAL if invalid.
 */
static int _seccomp_action_valid(uint32_t action)
{
	if (action == SCMP_ACT_KILL)
		return 0;
	else if (action == SCMP_ACT_TRAP)
		return 0;
	else if (action == SCMP_ACT_ERRNO(action & 0x0000ffff))
		return 0;
	else if (action == SCMP_ACT_TRACE(action & 0x0000ffff))
		return 0;
	else if (action == SCMP_ACT_ALLOW)
		return 0;

	return -EINVAL;
}

/* NOTE - function header comment in include/seccomp.h */
int seccomp_init(uint32_t def_action)
{
	int rc;

	rc = _seccomp_action_valid(def_action);
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
	rc = prctl(PR_ATTACH_SECCOMP_FILTER, program);
	gen_bpf_release(program);
	if (rc < 0)
		return errno;

	return 0;
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

/* NOTE - function header comment in include/seccomp.h */
int seccomp_rule_add(uint32_t action, int syscall, unsigned int arg_cnt, ...)
{
	int rc;
	unsigned int iter;
	unsigned int chain_len_max;
	va_list arg_list;
	struct db_api_arg *chain = NULL;
	unsigned int arg_num;

	if (filter == NULL)
		return -EFAULT;

	rc = _seccomp_action_valid(action);
	if (rc < 0)
		return rc;
	if (action == filter->def_action)
		return -EPERM;

	/* collect the arguments for the filter rule */
	chain_len_max = arch_arg_count_max(filter->arch);
	chain = malloc(sizeof(*chain) * chain_len_max);
	if (chain == NULL)
		return -ENOMEM;
	memset(chain, 0, sizeof(*chain) * chain_len_max);
	va_start(arg_list, arg_cnt);
	for (iter = 0; iter < arg_cnt; iter++) {
		arg_num = va_arg(arg_list, unsigned int);
		if (arg_num < chain_len_max && chain[arg_num].valid == 0) {
			chain[arg_num].valid = 1;
			chain[arg_num].arg = arg_num;
			chain[arg_num].op = va_arg(arg_list, unsigned int);
			if (chain[arg_num].op <= _SCMP_CMP_MIN ||
			    chain[arg_num].op >= _SCMP_CMP_MAX) {
				rc = -EINVAL;
				goto rule_add_return;
			}
			/* NOTE - basic testing indicates we can't pick a type
			 *	  larger than the system's 'unsigned long' */
			chain[arg_num].datum = va_arg(arg_list, unsigned long);
		} else {
			rc = -EINVAL;
			goto rule_add_return;
		}
	}

	/* if this is a pseudo syscall (syscall < 0) then we need to rewrite
	 * the rule for some arch specific reason */
	if (syscall < 0) {
		rc = arch_filter_rewrite(filter->arch, 1, &syscall, chain);
		if (rc < 0)
			goto rule_add_return;
	}

	/* add the new rule to the existing filter */
	rc = db_rule_add(filter, action, syscall, chain);

rule_add_return:
	va_end(arg_list);
	if (chain != NULL)
		free(chain);
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
		return errno;

	return 0;
}
