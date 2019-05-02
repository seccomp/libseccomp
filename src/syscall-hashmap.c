/**
 * Seccomp Library syscall hash map code
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

#include <string.h>

#include "arch.h"
#include "hash.h"

struct syscall_hashmap_entry {
	/* Both structures are combined into one to simplify usage */
	struct {
		uint32_t value;
		int record_idx;
	} hash;

	struct {
		struct arch_syscall_def syscall;
		int next_record_idx;
	} record;
};

/**
 * Hashes a syscall name
 * @param syscall_name the syscall name (cannot be NULL)
 */
inline static uint32_t syscall_hashmap_hasher(const char *syscall_name)
{
	return hash(syscall_name, strlen(syscall_name));
}

/**
 * Builds a syscall hashmap (name to number) structure
 * @param syscall_table architecture syscall table
 * @param entries hashmap entries
 * @param eno number of valid entries in @p syscall_table and the size of
 *        @p entries
 */
void build_syscall_hashmap(const struct arch_syscall_def *syscall_table,
                           struct syscall_hashmap_entry *entries, unsigned eno)
{
	/* First count how many times each hash occurs */
	for (unsigned i = 0; i < eno; ++i) {
		entries[i].hash.record_idx = 0;
		entries[i].record.next_record_idx = i + 1;
	}

	for (unsigned i = 0; i < eno; ++i) {
		uint32_t hash = syscall_hashmap_hasher(syscall_table[i].name) % eno;
		++entries[hash].hash.record_idx;
	}

	/* Fill the hashtable - it is separated into two stages to improve memory
	 * layout */
	unsigned sum = 0;
	for (unsigned i = 0; i < eno; ++i) {
		if (entries[i].hash.record_idx == 0) {
			entries[i].hash.record_idx = -1;
			continue;
		}

		sum = entries[i].hash.record_idx += sum;
		entries[sum - 1].record.next_record_idx = -1;
	}

	for (unsigned i = 0; i < eno; ++i) {
		uint32_t hash = syscall_hashmap_hasher(syscall_table[i].name) % eno;
		unsigned rid = --entries[hash].hash.record_idx;
		entries[rid].record.syscall = syscall_table[i];
	}
}

int syscall_hashmap_resolve(struct syscall_hashmap_entry *entries, unsigned eno,
                            const char *name)
{
	uint32_t hash = syscall_hashmap_hasher(name) % eno;
	unsigned rid = entries[hash].hash.record_idx;
	while (rid != -1) {
		struct syscall_hashmap_entry *entry = entries + rid;
		if (strcmp(name, entry->record.syscall.name) == 0)
			return entry->record.syscall.num;
		rid = entry->record.next_record_idx;
	}

	return __NR_SCMP_ERROR;
}
