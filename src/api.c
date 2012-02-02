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

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/prctl.h>

#include <seccomp.h>

#include "db.h"
#include "gen_pfc.h"
#include "gen_bpf.h"

/* XXX - we need a way to handle things like socketcall() so devs don't have
 *       to worry about underlying arch/platform oddities */

/* the underlying code supports multiple simultaneous seccomp filters, but in
 * practice we really only need one per-process right now, and this is it */
static struct db_filter *filter = NULL;

/**
 * Initialize the filter state
 * @param def_action the default filter action
 *
 * This function initializes the internal seccomp filter state and should
 * be called before any other functions in this library to ensure the filter
 * state is initialized.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_init(enum scmp_flt_action def_action)
{
	if (def_action <= _SCMP_ACT_MIN || def_action >= _SCMP_ACT_MAX)
		return -EINVAL;

	if (filter != NULL)
		return -EEXIST;
	filter = db_new(def_action);

	return (filter ? 0 : -ENOMEM);
}

/**
 * Reset the filter state
 * @param def_action the default filter action
 *
 * This function resets the internal seccomp filter state and ensures the
 * filter state is reinitialized.  This function does not reset any seccomp
 * filters already loaded into the kernel.  Returns zero on success, negative
 * values on failure.
 *
 */
int seccomp_reset(enum scmp_flt_action def_action)
{
	if (def_action != SCMP_ACT_ALLOW && def_action != SCMP_ACT_DENY)
		return -EINVAL;

	if (filter != NULL)
		db_destroy(filter);
	filter = db_new(def_action);

	return (filter ? 0 : -ENOMEM);
}

/**
 * Destroys the filter state and releases any resources
 * 
 * This functions destroys the internal seccomp filter state and releases any
 * resources, including memory, associated with the filter state.  This
 * function does not reset any seccomp filters already loaded into the kernel.
 * The function seccomp_reset() must be called before the filter can be
 * reconfigured after calling this function.
 * 
 */
void seccomp_release(void)
{
	if (filter == NULL)
		return;

	db_destroy(filter);
	filter = NULL;
}

/**
 * Enables the currently configured seccomp filter
 * 
 * This function loads the currently configured seccomp filter into the kernel.
 * If the filter was loaded correctly, the kernel will be enforcing the filter
 * when this function returns.  Returns zero on success, negative values on
 * error.
 *
 */
int seccomp_enable(void)
{
	int rc;
	struct seccomp_fprog *fprog;

	if (filter == NULL)
		return -EFAULT;

	fprog = gen_bpf_generate(filter);
	if (fprog == NULL)
		return -ENOMEM;
	rc = prctl(PR_ATTACH_SECCOMP_FILTER, fprog);
	gen_bpf_destroy(fprog);
	if (rc < 0)
		return errno;

	return 0;
}

/**
 * Add a syscall and an optional argument chain to the existing filter
 * @param action the filter action
 * @param syscall the syscall number
 * @param chain_len the number of argument filters in the argument filter chain
 * @param ... the argument filter chain, (uint, enum scmp_compare, ulong)
 * 
 * This function adds a new argument/comparison/value to the seccomp filter for
 * a syscall; multiple arguments can be specified and they will be chained
 * together (essentially AND'd together) in the filter.  Returns zero on
 * success, negative values on failure.
 * 
 */
int seccomp_add_syscall(enum scmp_flt_action action, int syscall,
			unsigned int chain_len, ...)
{
	int rc;
	va_list chain_list;

	if (filter == NULL)
		return -EFAULT;

	/* XXX - not sure it still makes sense to have the action as a
	 *       parameter, but it does help reinforce what should happen
	 *       when reading the app code which calls us */
	if (action == filter->def_action)
		return -EPERM;

	/* XXX - we should cap the maximum syscall argument? is there one? */

	/* XXX - negative syscall values are going to be considered "special",
	 *       e.g. all the socketcall() syscalls on x86 will be represented
	 *       with negative syscall numbers - we need a thin shim layer
	 *       here to convert these pseudo syscalls into real filters (check
	 * 	 the a0 value, etc.) */

	va_start(chain_list, chain_len);
	rc = db_add_syscall(filter, 0, action, syscall,	chain_len, chain_list);
	va_end(chain_list);

	return rc;
}

/**
 * Generate seccomp pseudo filter code
 * @param fd the destination fd
 * 
 * This function generates seccomp pseudo filter code and writes it to the
 * given fd.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_gen_pfc(int fd)
{
	if (filter == NULL)
		return -EFAULT;

	return gen_pfc_generate(filter, fd);
}

/**
 * Generate seccomp Berkley Packet Filter code
 * @param fd the destination fd
 * 
 * This function generates seccomp Berkley Packer Filter (BPF) code and writes
 * it to the given fd.  Returns zero on success, negative values on failure.
 *
 */
int seccomp_gen_bpf(int fd)
{
	int rc;
	struct seccomp_fprog *fprog;

	if (filter == NULL)
		return -EFAULT;

	fprog = gen_bpf_generate(filter);
	if (fprog == NULL)
		return -ENOMEM;
	rc = write(fd, fprog->filter, fprog->len * sizeof(fprog->filter[0]));
	gen_bpf_destroy(fprog);
	if (rc < 0)
		return errno;

	return 0;
}
