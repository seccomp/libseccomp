/**
 * Enhanced Seccomp Architecture/Machine Specific Code
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

#ifndef _ARCH_H
#define _ARCH_H

#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>

#include <seccomp.h>

#include "system.h"

struct db_filter;
struct db_api_arg;
struct db_api_rule_list;

struct arch_def {
	/* arch definition */
	uint32_t token;
	uint32_t token_bpf;
	enum {
		ARCH_SIZE_UNSPEC = 0,
		ARCH_SIZE_32 = 32,
		ARCH_SIZE_64 = 64,
	} size;
	enum {
		ARCH_ENDIAN_UNSPEC = 0,
		ARCH_ENDIAN_LITTLE,
		ARCH_ENDIAN_BIG,
	} endian;

	/* arch specific constants */
	int sys_socketcall;
	int sys_ipc;

	/* arch specific functions */
	int (*syscall_resolve_name)(const struct arch_def *arch,
				    const char *name);
	int (*syscall_resolve_name_raw)(const char *name);
	const char *(*syscall_resolve_num)(const struct arch_def *arch,
					   int num);
	const char *(*syscall_resolve_num_raw)(int num);
	int (*syscall_rewrite)(const struct arch_def *arch, int *syscall);
	int (*rule_add)(struct db_filter *db, struct db_api_rule_list *rule);
};

/* arch_def for the current architecture */
extern const struct arch_def *arch_def_native;

/* macro to declare the arch specific structures and functions */
#define ARCH_DECL(NAME) \
	extern const struct arch_def arch_def_##NAME; \
	int NAME##_syscall_resolve_name(const char *name); \
	const char *NAME##_syscall_resolve_num(int num); \
	const struct arch_syscall_def *NAME##_syscall_iterate(unsigned int spot);

/* macro to define the arch specific structures and functions */
#define ARCH_DEF(NAME) \
	int NAME##_syscall_resolve_name(const char *name) \
	{ \
		return syscall_resolve_name(name, OFFSET_ARCH(NAME)); \
	} \
	const char *NAME##_syscall_resolve_num(int num) \
	{ \
		return syscall_resolve_num(num, OFFSET_ARCH(NAME)); \
	} \
	const struct arch_syscall_def *NAME##_syscall_iterate(unsigned int spot) \
	{ \
		return syscall_iterate(spot, OFFSET_ARCH(NAME)); \
	}

/* syscall name/num mapping */
struct arch_syscall_def {
	const char *name;
	unsigned int num;
};

#define DATUM_MAX	((scmp_datum_t)-1)
#define D64_LO(x)	((uint32_t)((uint64_t)(x) & 0x00000000ffffffff))
#define D64_HI(x)	((uint32_t)((uint64_t)(x) >> 32))

#define ARG_COUNT_MAX	6

int arch_valid(uint32_t arch);

const struct arch_def *arch_def_lookup(uint32_t token);
const struct arch_def *arch_def_lookup_name(const char *arch_name);

int arch_arg_offset_lo(const struct arch_def *arch, unsigned int arg);
int arch_arg_offset_hi(const struct arch_def *arch, unsigned int arg);
int arch_arg_offset(const struct arch_def *arch, unsigned int arg);

int arch_syscall_resolve_name(const struct arch_def *arch, const char *name);
const char *arch_syscall_resolve_num(const struct arch_def *arch, int num);

int arch_syscall_translate(const struct arch_def *arch, int *syscall);
int arch_syscall_rewrite(const struct arch_def *arch, int *syscall);

int arch_filter_rule_add(struct db_filter *db,
			 const struct db_api_rule_list *rule);

#endif
