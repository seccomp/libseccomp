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

#include "arch.h"
#include "db.h"
#include "system.h"

struct bpf_program {
	uint16_t blk_cnt;
	bpf_instr_raw *blks;
};
#define BPF_PGM_SIZE(x) \
	((x)->blk_cnt * sizeof(*((x)->blks)))

struct bpf_program *gen_bpf_generate(const struct db_filter *db);
void gen_bpf_release(struct bpf_program *program);

#endif
