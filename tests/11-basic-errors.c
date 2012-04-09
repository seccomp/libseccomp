/**
 * Seccomp Library test program
 *
 * Copyright IBM Corp. 2012
 * Author: Corey Bryant <coreyb@linux.vnet.ibm.com>
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

#include <unistd.h>
#include <errno.h>

#include <seccomp.h>

int main(int argc, char *argv[])
{
	int rc;

	/* seccomp_init errors */
	rc = seccomp_init(SCMP_ACT_ALLOW+1);
	if (rc != -EINVAL)
		return -1;

	rc = seccomp_init(SCMP_ACT_ALLOW);
	if (rc != 0)
		return rc;
	else {
		rc = seccomp_init(SCMP_ACT_KILL);
		if (rc != -EEXIST)
			return -1;
	}
	seccomp_release();

	/* seccomp_reset error */
	rc = seccomp_reset(SCMP_ACT_KILL+1);
	if (rc != -EINVAL)
		return -1;

	/* seccomp_load error */
	rc = seccomp_load();
	if (rc != -EFAULT)
		return -1;

	/* seccomp_syscall_priority errors */
	rc = seccomp_syscall_priority(SCMP_SYS(read), 1);
	if (rc != -EFAULT)
		return -1;

	rc = seccomp_init(SCMP_ACT_ALLOW);
	if (rc != 0)
		return rc;
	else {
		rc = seccomp_syscall_priority(-1000, 1);
#if __i386__
		if (rc != -EINVAL)
			return -1;
#else
		if (rc != -EDOM)
			return -1;
#endif
	}
	seccomp_release();

	/* seccomp_rule_add errors */
	rc = seccomp_rule_add(SCMP_ACT_ALLOW, SCMP_SYS(read), 1,
			      SCMP_A0(SCMP_CMP_EQ, 0));
	if (rc != -EFAULT)
		return -1;

	rc = seccomp_init(SCMP_ACT_ALLOW);
	if (rc != 0)
		return rc;
	else {
		rc = seccomp_rule_add(SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
		if (rc != -EPERM)
			return -1;
		rc = seccomp_rule_add(SCMP_ACT_KILL-1, SCMP_SYS(read), 0);
		if (rc != -EINVAL)
			return -1;
		rc = seccomp_rule_add(SCMP_ACT_KILL, SCMP_SYS(read), 6);
		if (rc != -EINVAL)
			return -1;
		rc = seccomp_rule_add(SCMP_ACT_KILL, SCMP_SYS(read), 7,
				      SCMP_A0(SCMP_CMP_EQ, 0),
				      SCMP_A1(SCMP_CMP_EQ, 0),
				      SCMP_A2(SCMP_CMP_EQ, 0),
				      SCMP_A3(SCMP_CMP_EQ, 0),
				      SCMP_A4(SCMP_CMP_EQ, 0),
				      SCMP_A5(SCMP_CMP_EQ, 0),
				      SCMP_CMP(6, SCMP_CMP_EQ, 0));
		if (rc != -EINVAL)
			return -1;
		rc = seccomp_rule_add(SCMP_ACT_KILL, SCMP_SYS(read), 1,
				      SCMP_A0(_SCMP_CMP_MIN, 0));
		if (rc != -EINVAL)
			return -1;
		rc = seccomp_rule_add(SCMP_ACT_KILL, SCMP_SYS(read), 1,
				      SCMP_A0(_SCMP_CMP_MAX, 0));
		if (rc != -EINVAL)
			return -1;
#if __i386__
		rc = seccomp_rule_add(SCMP_ACT_KILL, -1001, 0);
		if (rc != -EINVAL)
			return -1;
#endif
	}
	seccomp_release();

	/* seccomp_rule_add_exact error */
	rc = seccomp_init(SCMP_ACT_ALLOW);
	if (rc != 0)
		return rc;
	else {
#if __i386__
		rc = seccomp_rule_add_exact(SCMP_ACT_KILL, SCMP_SYS(socket), 1,
					    SCMP_A0(SCMP_CMP_EQ, 2));
		if (rc != -EINVAL)
			return -1;
#endif
	}
	seccomp_release();

	/* seccomp_gen_pfc errors */
	rc = seccomp_gen_pfc(STDOUT_FILENO);
	if (rc != -EFAULT)
		return -1;

	rc = seccomp_init(SCMP_ACT_ALLOW);
	if (rc != 0)
		return rc;
	else {
		rc = seccomp_gen_pfc(sysconf(_SC_OPEN_MAX)-1);
		if (rc != EBADF)
			return -1;
	}
	seccomp_release();

	/* seccomp_gen_bpf errors */
	rc = seccomp_gen_bpf(STDOUT_FILENO);
	if (rc != -EFAULT)
		return -1;

	rc = seccomp_init(SCMP_ACT_ALLOW);
	if (rc != 0)
		return rc;
	else {
		rc = seccomp_gen_bpf(sysconf(_SC_OPEN_MAX)-1);
		if (rc != EBADF)
			return -1;
	}
	seccomp_release();

	return 0;
}
