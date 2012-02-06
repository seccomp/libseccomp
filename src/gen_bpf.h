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

#ifndef _TRANSLATOR_BPF_H
#define _TRANSLATOR_BPF_H

#include <inttypes.h>

#include "db.h"

/* XXX - should we just use "sock_filter" in linux/filter.h? the name is
 *       awkward, but using the standard struct might be a good idea */
struct bpf_instr_raw {
	uint16_t op;
	uint8_t	jt;
	uint8_t	jf;
	uint32_t k;
} __attribute__ ((packed));

struct bpf_program {
	uint16_t blk_cnt;
	struct bpf_instr_raw *blks;
};
#define BPF_PGM_SIZE(x) \
	((x)->blk_cnt * sizeof(*((x)->blks)))

struct bpf_program *gen_bpf_generate(const struct db_filter *db);
void gen_bpf_destroy(struct bpf_program *program);

#endif
