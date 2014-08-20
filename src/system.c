/**
 * Seccomp System Interfaces
 *
 * Copyright (c) 2014 Red Hat <pmoore@redhat.com>
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

#include <stdlib.h>
#include <errno.h>
#include <sys/prctl.h>

#include <seccomp.h>

#include "db.h"
#include "gen_bpf.h"
#include "system.h"

/**
 * Loads the filter into the kernel
 * @param col the filter collection
 *
 * This function loads the given seccomp filter context into the kernel.  If
 * the filter was loaded correctly, the kernel will be enforcing the filter
 * when this function returns.  Returns zero on success, negative values on
 * error.
 *
 */
int sys_filter_load(const struct db_filter_col *col)
{
	int rc;
	struct bpf_program *program = NULL;

	program = gen_bpf_generate(col);
	if (program == NULL)
		return -ENOMEM;

	/* attempt to set NO_NEW_PRIVS */
	if (col->attr.nnp_enable) {
		rc = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		if (rc < 0)
			goto filter_load_out;
	}

	/* load the filter into the kernel */
#ifdef HAVE_SECCOMP
	rc = seccomp(SECCOMP_SET_MODE_FILTER, flags, program);
#else
	rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, program);
#endif /* HAVE_SECCOMP */

filter_load_out:
	/* cleanup and return */
	gen_bpf_release(program);
	if (rc < 0)
		return -errno;
	return 0;
}
