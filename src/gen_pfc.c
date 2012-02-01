/**
 * Seccomp Pseudo Filter Code (PFC) Generator
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
#include <stdio.h>

#include <seccomp.h>

#include "db.h"
#include "gen_pfc.h"

/* XXX - we should check the fprintf() return values */

/**
 * Display a string representation of the filter action
 * @param action the action
 */
#define _gen_pfc_action(action) \
	((action) == SCMP_ACT_ALLOW ? "ALLOW" : "DENY")

/**
 * Generate pseudo filter code for a syscall
 * @param act the filter action
 * @param sys the syscall filter
 * @param fds the file stream to send the output
 * 
 * This function generates a pseduo filter code representation of the given
 * syscall filter and writes it to the given fd.  Returns zero on success,
 * negative values on failure.
 * 
 */
static int _gen_pfc_syscall(enum scmp_flt_action act,
			    const struct db_syscall_list *sys, FILE *fds)
{
	unsigned int sys_num = sys->num;
	struct db_syscall_arg_list *a_iter;
	struct db_syscall_arg_val_list *v_iter;
	char *op_str;

	char op_str_ne[] = "!=";
	char op_str_lt[] = "<";
	char op_str_le[] = "<=";
	char op_str_eq[] = "==";
	char op_str_ge[] = ">=";
	char op_str_gt[] = ">";
	char op_str_un[] = "??";

	fprintf(fds, "# filter code for syscall #%d\n", sys_num);
	fprintf(fds, " if (syscall != %d) goto syscall_%d_end;\n",
		sys_num, sys_num);
	if (sys->args != NULL) {
		db_list_foreach(a_iter, sys->args) {
			db_list_foreach(v_iter, a_iter->values) {
				switch (v_iter->op) {
					case SCMP_CMP_NE:
						op_str = op_str_ne;
						break;
					case SCMP_CMP_LT:
						op_str = op_str_lt;
						break;
					case SCMP_CMP_LE:
						op_str = op_str_le;
						break;
					case SCMP_CMP_EQ:
						op_str = op_str_eq;
						break;
					case SCMP_CMP_GE:
						op_str = op_str_ge;
						break;
					case SCMP_CMP_GT:
						op_str = op_str_gt;
						break;
					default:
						op_str = op_str_un;
				}
				fprintf(fds, " if (a%d %s 0x%lx) "
					     "goto syscall_%d_a%d_next;\n",
					a_iter->num,
					op_str,
					v_iter->datum,
					sys_num,
					a_iter->num);
			}
			fprintf(fds, " syscall_%d_a%d_next:\n",
				sys_num, a_iter->num);
		}
	}
	fprintf(fds, " action %s;\n", _gen_pfc_action(act));
	fprintf(fds, " syscall_%d_end:\n", sys_num);

	return 0;
}

/**
 * Generate a pseudo filter code string representation
 * @param db the seccomp filter DB
 * @param fd the fd to send the output
 * 
 * This function generates a pseudo filter code representation of the given
 * filter DB and writes it to the given fd.  Returns zero on success, negative
 * values on failure.
 * 
 */
int gen_pfc_generate(const struct db_filter *db, int fd)
{
	FILE *fds;
	struct db_syscall_list *iter;

	fds = fdopen(fd, "a+");
	if (fds == NULL)
		return errno;

	fprintf(fds, "#\n");
	fprintf(fds, "# filter pseudo code start\n");
	fprintf(fds, "#\n");
	db_list_foreach(iter, db->sys_deny)
		_gen_pfc_syscall(SCMP_ACT_DENY, iter, fds);
	db_list_foreach(iter, db->sys_allow)
		_gen_pfc_syscall(SCMP_ACT_ALLOW, iter, fds);
	fprintf(fds, "# default action\n");
	fprintf(fds, " action %s;\n", _gen_pfc_action(db->def_action));
	fprintf(fds, "#\n");
	fprintf(fds, "# filter pseudo code end\n");
	fprintf(fds, "#\n");

	fflush(fds);
	return 0;
}
