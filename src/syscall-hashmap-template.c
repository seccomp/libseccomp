#include <inttypes.h>
#include <stdio.h>

#include "hash.c"
#include "syscall-hashmap.c"

#define concat2(a, b) a ## b
#define concat(a, b) concat2(a, b)
#define syscall_table concat(ARCH, _syscall_table)
#define ARR_LEN(arr) (sizeof(arr) / sizeof(*arr))

int main() {
	struct syscall_hashmap_entry hmap[ARR_LEN(syscall_table) - 1];
	const int eno = ARR_LEN(syscall_table) - 1;
	build_syscall_hashmap(syscall_table, hmap, eno);

	for (int i = 0; i < eno; ++i) {
		struct syscall_hashmap_entry *hmi = hmap + i;
		printf("{ { %"PRIu32", %i }, { { \"%s\", %u }, %i } },\n", hmi->hash.value,
			hmi->hash.record_idx, hmi->record.syscall.name,
			hmi->record.syscall.num, hmi->record.next_record_idx);
	}

	return 0;
}
