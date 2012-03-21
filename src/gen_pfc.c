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
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <asm/bitsperlong.h>

#include <seccomp.h>

#include "db.h"
#include "gen_pfc.h"

/* XXX - we should check the fprintf() return values */

/**
 * Display a string representation of the filter action
 * @param fds the file stream to send the output
 * @param action the action
 */
static void _pfc_action(FILE *fds, uint32_t action)
{
	switch (action & 0xffff0000) {
	case SCMP_ACT_KILL:
		fprintf(fds, " action KILL;\n");
		break;
	case SCMP_ACT_TRAP:
		fprintf(fds, " action TRAP;\n");
		break;
	case SCMP_ACT_ERRNO(0):
		fprintf(fds, " action ERRNO(%u);\n", (action & 0x0000ffff));
		break;
	case SCMP_ACT_TRACE(0):
		fprintf(fds, " action TRACE(%u);\n", (action & 0x0000ffff));
		break;
	case SCMP_ACT_ALLOW:
		fprintf(fds, " action ALLOW;\n");
		break;
	default:
		fprintf(fds, " action 0x%x;\n", action);
	}
}

/**
 * Indent the output stream
 * @param fds the file stream to send the output
 * @param lvl the indentation level
 *
 * This function indents the output stream with whitespace based on the
 * requested indentation level.
 */
static void _indent(FILE *fds, unsigned int lvl)
{
	while (lvl-- > 0)
		fprintf(fds, " ");
}

/**
 * Generate the pseudo filter code for an argument chain
 * @param node the head of the argument chain
 * @param lvl the indentation level
 * @param fds the file stream to send the output
 *
 * This function generates the pseudo filter code representation of the given
 * argument chain and writes it to the given output stream.
 *
 */
static void _gen_pfc_chain(const struct db_arg_chain_tree *node,
			   unsigned int lvl, FILE *fds)
{
	const struct db_arg_chain_tree *c_iter;

	/* get to the start */
	c_iter = node;
	while (c_iter->lvl_prv != NULL)
		c_iter = c_iter->lvl_prv;

	while (c_iter != NULL) {
		/* comparison operation */
		_indent(fds, lvl);
		switch (c_iter->op) {
			case SCMP_CMP_NE:
				fprintf(fds, " if ($a%d != %"PRIu64")\n",
					c_iter->arg,
					c_iter->datum);
				break;
			case SCMP_CMP_LT:
				fprintf(fds, " if ($a%d < %"PRIu64")\n",
					c_iter->arg,
					c_iter->datum);
				break;
			case SCMP_CMP_LE:
				fprintf(fds, " if ($a%d <= %"PRIu64")\n",
					c_iter->arg,
					c_iter->datum);
				break;
			case SCMP_CMP_EQ:
				fprintf(fds, " if ($a%d == %"PRIu64")\n",
					c_iter->arg,
					c_iter->datum);
				break;
			case SCMP_CMP_GE:
				fprintf(fds, " if ($a%d >= %"PRIu64")\n",
					c_iter->arg,
					c_iter->datum);
				break;
			case SCMP_CMP_GT:
				fprintf(fds, " if ($a%d > %"PRIu64")\n",
					c_iter->arg,
					c_iter->datum);
				break;
			default:
				fprintf(fds, " if ($a%d ??? %"PRIu64")\n",
					c_iter->arg, c_iter->datum);
		}

		/* true result */
		if (c_iter->act_t_flg) {
			_indent(fds, lvl + 1);
			_pfc_action(fds, c_iter->act_t);
		} else if (c_iter->nxt_t != NULL)
			_gen_pfc_chain(c_iter->nxt_t, lvl + 1, fds);

		/* false result */
		if (c_iter->act_f_flg) {
			_indent(fds, lvl);
			fprintf(fds, " else\n");
			_indent(fds, lvl + 1);
			_pfc_action(fds, c_iter->act_f);
		} else if (c_iter->nxt_f != NULL) {
			_indent(fds, lvl);
			fprintf(fds, " else\n");
			_gen_pfc_chain(c_iter->nxt_f, lvl + 1, fds);
		}

		c_iter = c_iter->lvl_nxt;
	}
}

/**
 * Generate pseudo filter code for a syscall
 * @param sys the syscall filter
 * @param fds the file stream to send the output
 *
 * This function generates a pseduo filter code representation of the given
 * syscall filter and writes it to the given output stream.
 *
 */
static void _gen_pfc_syscall(const struct db_sys_list *sys, FILE *fds)
{
	unsigned int sys_num = sys->num;

	fprintf(fds, "# filter code for syscall #%d\n", sys_num);
	if (sys->chains != NULL) {
		fprintf(fds, " if ($syscall != %d) goto syscal_%d_end;\n",
			sys_num, sys_num);
		_gen_pfc_chain(sys->chains, 0, fds);
		fprintf(fds, " syscall_%d_end:\n", sys_num);
	} else {
		fprintf(fds, " if ($syscall == %d)", sys_num);
		_pfc_action(fds, sys->action);
	}
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
	int newfd;
	FILE *fds;
	struct db_sys_list *s_iter;

	newfd = dup(fd);
	if (newfd < 0)
		return errno;
	fds = fdopen(newfd, "a");
	if (fds == NULL) {
		close(newfd);
		return errno;
	}

	fprintf(fds, "#\n");
	fprintf(fds, "# pseudo filter code start\n");
	fprintf(fds, "#\n");
	db_list_foreach(s_iter, db->syscalls)
		_gen_pfc_syscall(s_iter, fds);
	fprintf(fds, "# default action\n");
	_pfc_action(fds, db->def_action);
	fprintf(fds, "#\n");
	fprintf(fds, "# pseudo filter code end\n");
	fprintf(fds, "#\n");

	fflush(fds);
	fclose(fds);
	return 0;
}
