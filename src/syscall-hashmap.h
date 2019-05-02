/**
 * Seccomp Library syscall hash map code
 *
 * See syscall-hashmap.c for information on the implementation.
 *
 */

#include "arch.h"

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

void build_syscall_hashmap(const struct arch_syscall_def *syscall_table,
                           struct syscall_hashmap_entry *entries, unsigned eno);

int syscall_hashmap_resolve(struct syscall_hashmap_entry *entries, unsigned eno,
                            const char *name);