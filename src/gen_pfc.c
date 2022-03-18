/**
 * Seccomp Pseudo Filter Code (PFC) Generator
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <paul@paul-moore.com>
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

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* NOTE: needed for the arch->token decoding in _pfc_arch() */
#include <linux/audit.h>

#include <seccomp.h>

#include "arch.h"
#include "db.h"
#include "gen_pfc.h"
#include "helper.h"
#include "system.h"

struct pfc_sys_list {
	struct db_sys_list *sys;
	struct pfc_sys_list *next;
};

/* XXX - we should check the fprintf() return values */

/**
 * Display a string representation of the architecture
 * @param arch the architecture definition
 */
static const char *_pfc_arch(const struct arch_def *arch)
{
	switch (arch->token) {
	case SCMP_ARCH_X86:
		return "x86";
	case SCMP_ARCH_X86_64:
		return "x86_64";
	case SCMP_ARCH_X32:
		return "x32";
	case SCMP_ARCH_ARM:
		return "arm";
	case SCMP_ARCH_AARCH64:
		return "aarch64";
	case SCMP_ARCH_MIPS:
		return "mips";
	case SCMP_ARCH_MIPSEL:
		return "mipsel";
	case SCMP_ARCH_MIPS64:
		return "mips64";
	case SCMP_ARCH_MIPSEL64:
		return "mipsel64";
	case SCMP_ARCH_MIPS64N32:
		return "mips64n32";
	case SCMP_ARCH_MIPSEL64N32:
		return "mipsel64n32";
	case SCMP_ARCH_PARISC:
		return "parisc";
	case SCMP_ARCH_PARISC64:
		return "parisc64";
	case SCMP_ARCH_PPC64:
		return "ppc64";
	case SCMP_ARCH_PPC64LE:
		return "ppc64le";
	case SCMP_ARCH_PPC:
		return "ppc";
	case SCMP_ARCH_S390X:
		return "s390x";
	case SCMP_ARCH_S390:
		return "s390";
	case SCMP_ARCH_RISCV64:
		return "riscv64";
	default:
		return "UNKNOWN";
	}
}

/**
 * Display a string representation of the node argument
 * @param fds the file stream to send the output
 * @param arch the architecture definition
 * @param node the node
 */
static void _pfc_arg(FILE *fds,
		     const struct arch_def *arch,
		     const struct db_arg_chain_tree *node)
{
	if (arch->size == ARCH_SIZE_64) {
		if (arch_arg_offset_hi(arch, node->arg) == node->arg_offset)
			fprintf(fds, "$a%d.hi32", node->arg);
		else
			fprintf(fds, "$a%d.lo32", node->arg);
	} else
		fprintf(fds, "$a%d", node->arg);
}

/**
 * Display a string representation of the filter action
 * @param fds the file stream to send the output
 * @param action the action
 */
static void _pfc_action(FILE *fds, uint32_t action)
{
	switch (action & SECCOMP_RET_ACTION_FULL) {
	case SCMP_ACT_KILL_PROCESS:
		fprintf(fds, "action KILL_PROCESS;\n");
		break;
	case SCMP_ACT_KILL_THREAD:
		fprintf(fds, "action KILL;\n");
		break;
	case SCMP_ACT_TRAP:
		fprintf(fds, "action TRAP;\n");
		break;
	case SCMP_ACT_ERRNO(0):
		fprintf(fds, "action ERRNO(%u);\n", (action & 0x0000ffff));
		break;
	case SCMP_ACT_TRACE(0):
		fprintf(fds, "action TRACE(%u);\n", (action & 0x0000ffff));
		break;
	case SCMP_ACT_LOG:
		fprintf(fds, "action LOG;\n");
		break;
	case SCMP_ACT_ALLOW:
		fprintf(fds, "action ALLOW;\n");
		break;
	default:
		fprintf(fds, "action 0x%x;\n", action);
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
		fprintf(fds, "  ");
}

/**
 * Generate the pseudo filter code for an argument chain
 * @param arch the architecture definition
 * @param node the head of the argument chain
 * @param lvl the indentation level
 * @param fds the file stream to send the output
 *
 * This function generates the pseudo filter code representation of the given
 * argument chain and writes it to the given output stream.
 *
 */
static void _gen_pfc_chain(const struct arch_def *arch,
			   const struct db_arg_chain_tree *node,
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
		fprintf(fds, "if (");
		_pfc_arg(fds, arch, c_iter);
		switch (c_iter->op) {
		case SCMP_CMP_EQ:
			fprintf(fds, " == ");
			break;
		case SCMP_CMP_GE:
			fprintf(fds, " >= ");
			break;
		case SCMP_CMP_GT:
			fprintf(fds, " > ");
			break;
		case SCMP_CMP_MASKED_EQ:
			fprintf(fds, " & 0x%.8x == ", c_iter->mask);
			break;
		case SCMP_CMP_NE:
		case SCMP_CMP_LT:
		case SCMP_CMP_LE:
		default:
			fprintf(fds, " ??? ");
		}
		fprintf(fds, "%u)\n", c_iter->datum);

		/* true result */
		if (c_iter->act_t_flg) {
			_indent(fds, lvl + 1);
			_pfc_action(fds, c_iter->act_t);
		} else if (c_iter->nxt_t != NULL)
			_gen_pfc_chain(arch, c_iter->nxt_t, lvl + 1, fds);

		/* false result */
		if (c_iter->act_f_flg) {
			_indent(fds, lvl);
			fprintf(fds, "else\n");
			_indent(fds, lvl + 1);
			_pfc_action(fds, c_iter->act_f);
		} else if (c_iter->nxt_f != NULL) {
			_indent(fds, lvl);
			fprintf(fds, "else\n");
			_gen_pfc_chain(arch, c_iter->nxt_f, lvl + 1, fds);
		}

		c_iter = c_iter->lvl_nxt;
	}
}

/**
 * Generate pseudo filter code for a syscall
 * @param arch the architecture definition
 * @param sys the syscall filter
 * @param fds the file stream to send the output
 *
 * This function generates a pseduo filter code representation of the given
 * syscall filter and writes it to the given output stream.
 *
 */
static void _gen_pfc_syscall(const struct arch_def *arch,
			     const struct db_sys_list *sys, FILE *fds,
			     int lvl)
{
	unsigned int sys_num = sys->num;
	const char *sys_name = arch_syscall_resolve_num(arch, sys_num);

	_indent(fds, lvl);
	fprintf(fds, "# filter for syscall \"%s\" (%u) [priority: %d]\n",
		(sys_name ? sys_name : "UNKNOWN"), sys_num, sys->priority);
	_indent(fds, lvl);
	fprintf(fds, "if ($syscall == %u)\n", sys_num);
	if (sys->chains == NULL) {
		_indent(fds, lvl + 1);
		_pfc_action(fds, sys->action);
	} else
		_gen_pfc_chain(arch, sys->chains, lvl + 1, fds);
}

#define SYSCALLS_PER_NODE		(4)
static int _get_bintree_levels(unsigned int syscall_cnt,
			       uint32_t optimize)
{
	unsigned int i = 0, max_level;

	if (optimize != 2)
		/* Only use a binary tree if requested */
		return 0;

	if (syscall_cnt == 0)
		return 0;

	do {
		max_level = SYSCALLS_PER_NODE << i;
		i++;
	} while(max_level < syscall_cnt);

	return i;
}

static int _get_bintree_syscall_num(const struct pfc_sys_list *cur,
				    int lookahead_cnt,
				    int *const num)
{
	while (lookahead_cnt > 0 && cur != NULL) {
		cur = cur->next;
		lookahead_cnt--;
	}

	if (cur == NULL)
		return -EFAULT;

	*num = cur->sys->num;
	return 0;
}

static int _sys_num_sort(struct db_sys_list *syscalls,
			 struct pfc_sys_list **p_head)
{
	struct pfc_sys_list *p_iter = NULL, *p_new, *p_prev;
	struct db_sys_list *s_iter;

	db_list_foreach(s_iter, syscalls) {
		p_new = zmalloc(sizeof(*p_new));
		if (p_new == NULL) {
			return -ENOMEM;
		}
		p_new->sys = s_iter;

		p_prev = NULL;
		p_iter = *p_head;
		while (p_iter != NULL &&
		       s_iter->num < p_iter->sys->num) {
			p_prev = p_iter;
			p_iter = p_iter->next;
		}
		if (*p_head == NULL)
			*p_head = p_new;
		else if (p_prev == NULL) {
			p_new->next = *p_head;
			*p_head = p_new;
		} else {
			p_new->next = p_iter;
			p_prev->next = p_new;
		}
	}

	return 0;
}

static int _sys_priority_sort(struct db_sys_list *syscalls,
			      struct pfc_sys_list **p_head)
{
	struct pfc_sys_list *p_iter = NULL, *p_new, *p_prev;
	struct db_sys_list *s_iter;

	db_list_foreach(s_iter, syscalls) {
		p_new = zmalloc(sizeof(*p_new));
		if (p_new == NULL) {
			return -ENOMEM;
		}
		p_new->sys = s_iter;

		p_prev = NULL;
		p_iter = *p_head;
		while (p_iter != NULL &&
		       s_iter->priority < p_iter->sys->priority) {
			p_prev = p_iter;
			p_iter = p_iter->next;
		}
		if (*p_head == NULL)
			*p_head = p_new;
		else if (p_prev == NULL) {
			p_new->next = *p_head;
			*p_head = p_new;
		} else {
			p_new->next = p_iter;
			p_prev->next = p_new;
		}
	}

	return 0;
}

static int _sys_sort(struct db_sys_list *syscalls,
		     struct pfc_sys_list **p_head,
		     uint32_t optimize)
{
	if (optimize != 2)
		return _sys_priority_sort(syscalls, p_head);
	else
		/* sort by number for the binary tree */
		return _sys_num_sort(syscalls, p_head);
}

/**
 * Generate pseudo filter code for an architecture
 * @param col the seccomp filter collection
 * @param db the single seccomp filter
 * @param fds the file stream to send the output
 *
 * This function generates a pseudo filter code representation of the given
 * filter DB and writes it to the given output stream.  Returns zero on
 * success, negative values on failure.
 *
 */
static int _gen_pfc_arch(const struct db_filter_col *col,
			 const struct db_filter *db, FILE *fds,
			 uint32_t optimize)
{
	int rc = 0, i = 0, lookahead_num;
	unsigned int syscall_cnt = 0, bintree_levels, level, indent = 1;
	struct pfc_sys_list *p_iter = NULL, *p_head = NULL;

	/* sort the syscall list */
	rc = _sys_sort(db->syscalls, &p_head, optimize);
	if (rc < 0)
		goto arch_return;

	bintree_levels = _get_bintree_levels(db->syscall_cnt, optimize);

	fprintf(fds, "# filter for arch %s (%u)\n",
		_pfc_arch(db->arch), db->arch->token_bpf);
	fprintf(fds, "if ($arch == %u)\n", db->arch->token_bpf);
	p_iter = p_head;
	while (p_iter != NULL) {
		if (!p_iter->sys->valid) {
			p_iter = p_iter->next;
			continue;
		}

		for (i = bintree_levels - 1; i > 0; i--) {
			level = SYSCALLS_PER_NODE << i;

			if (syscall_cnt == 0 || (syscall_cnt % level) == 0) {
				rc = _get_bintree_syscall_num(p_iter, level / 2,
							      &lookahead_num);
				if (rc < 0)
					/* We have reached the end of the bintree.
					 * There aren't enough syscalls to construct
					 * any more if-elses.
					 */
					continue;
				_indent(fds, indent);
				fprintf(fds, "if ($syscall > %u)\n", lookahead_num);
				indent++;
			} else if ((syscall_cnt % (level / 2)) == 0) {
				lookahead_num = p_iter->sys->num;
				_indent(fds, indent - 1);
				fprintf(fds, "else # ($syscall <= %u)\n",
					p_iter->sys->num);
			}

		}

		_gen_pfc_syscall(db->arch, p_iter->sys, fds, indent);
		syscall_cnt++;
		p_iter = p_iter->next;

		/* undo the indentations as the else statements complete */
		for (i = 0; i < bintree_levels; i++) {
			if (syscall_cnt % ((SYSCALLS_PER_NODE * 2) << i) == 0)
				indent--;
		}
	}
	_indent(fds, 1);
	fprintf(fds, "# default action\n");
	_indent(fds, 1);
	_pfc_action(fds, col->attr.act_default);

arch_return:
	while (p_head != NULL) {
		p_iter = p_head;
		p_head = p_head->next;
		free(p_iter);
	}
	return rc;
}
/**
 * Generate a pseudo filter code string representation
 * @param col the seccomp filter collection
 * @param fd the fd to send the output
 *
 * This function generates a pseudo filter code representation of the given
 * filter collection and writes it to the given fd.  Returns zero on success,
 * negative errno values on failure.
 *
 */
int gen_pfc_generate(const struct db_filter_col *col, int fd)
{
	int newfd;
	unsigned int iter;
	FILE *fds;

	newfd = dup(fd);
	if (newfd < 0)
		return -errno;
	fds = fdopen(newfd, "a");
	if (fds == NULL) {
		close(newfd);
		return -errno;
	}

	/* generate the pfc */
	fprintf(fds, "#\n");
	fprintf(fds, "# pseudo filter code start\n");
	fprintf(fds, "#\n");

	for (iter = 0; iter < col->filter_cnt; iter++)
		_gen_pfc_arch(col, col->filters[iter], fds,
			      col->attr.optimize);

	fprintf(fds, "# invalid architecture action\n");
	_pfc_action(fds, col->attr.act_badarch);
	fprintf(fds, "#\n");
	fprintf(fds, "# pseudo filter code end\n");
	fprintf(fds, "#\n");

	fflush(fds);
	fclose(fds);

	return 0;
}
