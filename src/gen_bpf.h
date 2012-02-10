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

#if 0
#include <linux/seccomp_filter.h>
#else
/* XXX - needed for early development only */
#include <seccomp_filter.h>
#endif

#include "db.h"

struct seccomp_fprog *gen_bpf_generate(const struct db_filter *db);
void gen_bpf_destroy(struct seccomp_fprog *fprog);

#endif
