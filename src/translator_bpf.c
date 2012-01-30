/**
 * Seccomp BPF Translator
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

/* XXX - this file is a quick n' dirty hack that hasn't really been verified,
 *       it is almost certainly broken; even if it does work, it needs some
 *       serious cleanup */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <seccomp.h>

#include "translator_bpf.h"
#include "bpf_helper.h"
#include "filter_db.h"

#if 1
/* XXX - provide our own macros for the following BPF statements, we probably
 *       want to just fixup the stuff in bpf_helper.h */
#define _JUMP(labels, label) \
	BPF_JUMP(BPF_JMP+BPF_JA, _FIND_LABEL(labels, label), JUMP_JT, JUMP_JF)
#define _LABEL(labels, label) \
	BPF_JUMP(BPF_JMP+BPF_JA, _FIND_LABEL(labels, label), LABEL_JT, LABEL_JF)
#define _FIND_LABEL(labels, label) seccomp_bpf_label(labels, label)
#define _SYSCALL(nr, jt) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, nr, 1, 0), \
	jt
#endif

/* allocation increment size */
#define BPF_INCR	(128 * sizeof(struct seccomp_filter_block))

struct bpf_filter {
	struct seccomp_fprog *prog;
	size_t alloc_len;
	struct bpf_labels lbls;
};

#define _bpf_blk_len(x) \
	(sizeof(x) / sizeof(x[0]))

#define _bpf_next(x) \
	((x)->prog->filter[(x)->prog->len])

/**
 * Append a new block of instructions to the BPF
 * @param x pointer to a bpf_filter struct
 * @param y new instruction block
 */
#define _bpf_append(x,y) \
	do { \
		memcpy(&_bpf_next(x), &(y), sizeof(y)); \
		(x)->prog->len += _bpf_blk_len(y); \
	} while (0)

/**
 * Grow the maximum BPF filter program size
 * @param bpf the bpf_filter struct
 * @param len the requested length
 * 
 * This functions checks to see if the BPF filter program space needs to be
 * expanded to meet the requested size and realloc's the space if needed.
 * Returns zero on success, negative values on failure.
 * 
 */
static int _seccomp_bpf_grow(struct bpf_filter *bpf, size_t len)
{
	void *buf;
	size_t buf_len = bpf->alloc_len + (BPF_INCR > len ? BPF_INCR : len);

	if (bpf->prog->len + len <= bpf->alloc_len)
		return 0;

	/* XXX - check to make sure the size isn't getting too large */
	/* XXX - is there a size limit? */

	buf = realloc(bpf->prog->filter, buf_len);
	if (buf == NULL) {
		free(bpf->prog->filter);
		bpf->prog->filter = NULL;
		bpf->prog->len = 0;
		bpf->alloc_len = 0;
		return -ENOMEM;
	}
	bpf->prog->filter = buf;
	bpf->alloc_len = buf_len;
	return 0;
}

/**
 * Append BPF instructions to the main BPF program
 * @param bpf the bpf_filter struct
 * @param blk the new BPF instruction block
 * @param blk_len length of the new BPF instruction block
 * 
 * This function appends the given set of BPF instructions to the main BPF
 * program, growing the allocated size if necessary.  Returns zero on success,
 * negative values on error.
 *
 */
static int _seccomp_bpf_append(struct bpf_filter *bpf,
			       const struct seccomp_filter_block *blk,
			       size_t blk_len)
{
	int rc = _seccomp_bpf_grow(bpf, blk_len);
	if (rc < 0)
		return rc;
	_bpf_append(bpf, blk);
	return 0;
}

/**
 * Generate BPF for the syscall argument
 * @param sys_num the syscall number
 * @param arg the syscall argument
 * @param bpf the bpf_filter struct
 *
 * This function generates BPF for the given syscall argument and action.
 * Returns zero on success, negative values on failure.
 *
 */
static int _seccomp_pbf_syscall_arg(unsigned int sys_num,
				    struct db_syscall_arg_list *arg,
				    struct bpf_filter *bpf)
{
	int rc;
	char lbl_end[256]; /* XXX - ungh */
	struct db_syscall_arg_val_list *v_iter;

	/* XXX - note the current limit on labels in bpf_helper.{c,h} */
	snprintf(lbl_end, 256, "syscall_%d_a%d_next", sys_num, arg->num);

	/* load the argument */
	{
		struct seccomp_filter_block blk[] = {
			ARG(arg->num),
		};
		rc = _seccomp_bpf_append(bpf, blk, _bpf_blk_len(blk));
		if (rc == 0)
			return -ENOMEM;
	}

	/* check against our argument value list */
	db_list_foreach(v_iter, arg->values) {
		if (v_iter->op == SCMP_CMP_NE) {
			struct seccomp_filter_block blk[] = {
				JNE(v_iter->datum, _JUMP(&bpf->lbls, lbl_end)),
			};
			rc = _seccomp_bpf_append(bpf, blk,
						 _bpf_blk_len(blk));
			if (rc == 0)
				return -ENOMEM;
		} else if (v_iter->op == SCMP_CMP_LT) {
			struct seccomp_filter_block blk[] = {
				JLT(v_iter->datum, _JUMP(&bpf->lbls, lbl_end)),
			};
			rc = _seccomp_bpf_append(bpf, blk,
						 _bpf_blk_len(blk));
			if (rc == 0)
				return -ENOMEM;
		} else if (v_iter->op == SCMP_CMP_LE) {
			struct seccomp_filter_block blk[] = {
				JLE(v_iter->datum, _JUMP(&bpf->lbls, lbl_end)),
			};
			rc = _seccomp_bpf_append(bpf, blk,
						 _bpf_blk_len(blk));
			if (rc == 0)
				return -ENOMEM;
		} else if (v_iter->op == SCMP_CMP_EQ) {
			struct seccomp_filter_block blk[] = {
				JEQ(v_iter->datum, _JUMP(&bpf->lbls, lbl_end)),
			};
			rc = _seccomp_bpf_append(bpf, blk,
						 _bpf_blk_len(blk));
			if (rc == 0)
				return -ENOMEM;
		} else if (v_iter->op == SCMP_CMP_GE) {
			struct seccomp_filter_block blk[] = {
				JGE(v_iter->datum, _JUMP(&bpf->lbls, lbl_end)),
			};
			rc = _seccomp_bpf_append(bpf, blk,
						 _bpf_blk_len(blk));
			if (rc == 0)
				return -ENOMEM;
		} else if (v_iter->op == SCMP_CMP_GT) {
			struct seccomp_filter_block blk[] = {
				JGT(v_iter->datum, _JUMP(&bpf->lbls, lbl_end)),
			};
			rc = _seccomp_bpf_append(bpf, blk,
						 _bpf_blk_len(blk));
			if (rc == 0)
				return -ENOMEM;
		} else
			return -EFAULT;
	}

	/* jump label for next argument block */
	{
		struct seccomp_filter_block blk[] = {
			_LABEL(&bpf->lbls, lbl_end),
		};
		rc = _seccomp_bpf_append(bpf, blk, _bpf_blk_len(blk));
		if (rc == 0)
			return -ENOMEM;
	}

	return 0;
}

/**
 * Generate BPF for a syscall filter
 * @param act the filter action
 * @param sys the system call filter
 * @param bpf the bpf_filter struct
 * 
 * This function generates BPF for the given syscall filter and action.
 * Returns zero on success, negative values on failure.
 *
 */
static int _seccomp_bpf_syscall(enum scmp_flt_action act,
				const struct db_syscall_list *sys,
				struct bpf_filter *bpf)
{
	int rc;
	char lbl_end[256]; /* XXX - ungh */
	struct db_syscall_arg_list *a_iter;

	/* XXX - note the current limit on labels in bpf_helper.{c,h} */
	snprintf(lbl_end, 256, "syscall_%d_end", sys->num); /* XXX - ungh^2 */

	if (sys->args == NULL) {
		if (act == SCMP_ACT_ALLOW) {
			struct seccomp_filter_block blk[] = {
				_SYSCALL(sys->num, _JUMP(&bpf->lbls, lbl_end)),
				ALLOW,
				_LABEL(&bpf->lbls, lbl_end),
			};
			rc = _seccomp_bpf_append(bpf, blk, _bpf_blk_len(blk));
			if (rc == 0)
				return -ENOMEM;
		} else {
			struct seccomp_filter_block blk[] = {
				_SYSCALL(sys->num, _JUMP(&bpf->lbls, lbl_end)),
				DENY,
				_LABEL(&bpf->lbls, lbl_end),
			};
			rc = _seccomp_bpf_append(bpf, blk, _bpf_blk_len(blk));
			if (rc == 0)
				return -ENOMEM;
		}
	} else {
		{
			struct seccomp_filter_block blk[] = {
				_SYSCALL(sys->num, _JUMP(&bpf->lbls, lbl_end)),
			};
			rc = _seccomp_bpf_append(bpf, blk, _bpf_blk_len(blk));
			if (rc == 0)
				return -ENOMEM;
		}

		/* iterate over the arguments */
		db_list_foreach(a_iter, sys->args) {
			rc = _seccomp_pbf_syscall_arg(sys->num, a_iter, bpf);
			if (rc < 0)
				return rc;
		}

		/* argument action and jump label for next arg block */
		if (act == SCMP_ACT_ALLOW) {
			struct seccomp_filter_block blk[] = {
				ALLOW,
				_LABEL(&bpf->lbls, lbl_end),
			};
			rc = _seccomp_bpf_append(bpf, blk, _bpf_blk_len(blk));
			if (rc == 0)
				return -ENOMEM;
		} else {
			struct seccomp_filter_block blk[] = {
				DENY,
				_LABEL(&bpf->lbls, lbl_end),
			};
			rc = _seccomp_bpf_append(bpf, blk, _bpf_blk_len(blk));
			if (rc == 0)
				return -ENOMEM;
		}
	}

	return 0;
}

/**
 * Generate a BPF representation of the filter DB
 * @param db the seccomp filter DB
 * 
 * This function generates a BPF representation of the given filter DB.
 * Returns a pointer to a valid seccomp_fprog on success, NULL on failure.
 *
 */
struct seccomp_fprog *seccomp_bpf_generate(const struct db_filter *db)
{
	int rc;
	struct bpf_filter bpf;
	struct db_syscall_list *iter;

	memset(&bpf, 0, sizeof(bpf));

	bpf.prog = malloc(sizeof(*bpf.prog));
	if (bpf.prog == NULL)
		return NULL;
	memset(&bpf.prog, 0, sizeof(*bpf.prog));

	/* XXX - assume we can get away with LOAD_SYSCALL_NR just at the top,
	 *       which may be wrong */
	/* load the syscall */
	{
		struct seccomp_filter_block blk[] = {
			LOAD_SYSCALL_NR,
		};
		rc = _seccomp_bpf_append(&bpf, blk, _bpf_blk_len(blk));
		if (rc == 0)
			goto bpf_generate_failure;
	}

	db_list_foreach(iter, db->sys_deny)
		_seccomp_bpf_syscall(SCMP_ACT_DENY, iter, &bpf);
	db_list_foreach(iter, db->sys_deny)
		_seccomp_bpf_syscall(SCMP_ACT_ALLOW, iter, &bpf);

	/* default action */
	if (db->def_action == SCMP_ACT_ALLOW) {
		struct seccomp_filter_block blk[] = {
			ALLOW,
		};
		rc = _seccomp_bpf_append(&bpf, blk, _bpf_blk_len(blk));
		if (rc == 0)
			goto bpf_generate_failure;
	} else {
		struct seccomp_filter_block blk[] = {
			DENY,
		};
		rc = _seccomp_bpf_append(&bpf, blk, _bpf_blk_len(blk));
		if (rc == 0)
			goto bpf_generate_failure;
	}

	/* resolve the labels/jumps */
	rc = bpf_resolve_jumps(&bpf.lbls,
			       bpf.prog->filter,
			       _bpf_blk_len(bpf.prog->filter));
	if (rc != 0)
		goto bpf_generate_failure;

	return bpf.prog;

bpf_generate_failure:
	free(bpf.prog);
	return NULL;
}