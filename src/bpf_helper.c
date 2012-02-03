/*
 * Seccomp BPF helper functions
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Author: Will Drewry <wad@chromium.org>
 *
 * The code may be used by anyone for any purpose,
 * and can serve as a starting point for developing
 * applications using prctl(PR_ATTACH_SECCOMP_FILTER).
 */

#include <stdio.h>
#include <string.h>

#include "bpf_helper.h"

int bpf_resolve_jumps(struct bpf_labels *labels,
		      struct seccomp_filter_block *filter, size_t count)
{
	struct seccomp_filter_block *begin = filter;
	__u8 insn = count - 1;

	if (count < 1)
		return -1;
	/*
	* Walk it once, backwards, to build the label table and do fixups.
	* Since backward jumps are disallowed by BPF, this is easy.
	*/
	filter += insn;
	for (; filter >= begin; --insn, --filter) {
		if (filter->code != (BPF_JMP+BPF_JA))
			continue;
		switch ((filter->jt<<8)|filter->jf) {
		case (JUMP_JT<<8)|JUMP_JF:
			if (labels->labels[filter->k].location == 0xffffffff) {
				fprintf(stderr, "Unresolved label: '%s'\n",
					labels->labels[filter->k].label);
				return 1;
			}
			filter->k = labels->labels[filter->k].location -
				    (insn + 1);
			filter->jt = 0;
			filter->jf = 0;
			continue;
		case (LABEL_JT<<8)|LABEL_JF:
			if (labels->labels[filter->k].location != 0xffffffff) {
				fprintf(stderr, "Duplicate label use: '%s'\n",
					labels->labels[filter->k].label);
				return 1;
			}
			labels->labels[filter->k].location = insn;
			filter->k = 0; /* fall through */
			filter->jt = 0;
			filter->jf = 0;
			continue;
		}
	}
	return 0;
}

/* Simple lookup table for labels. */
__u32 seccomp_bpf_label(struct bpf_labels *labels, const char *label)
{
	struct __bpf_label *begin = labels->labels, *end;
	int id;
	if (labels->count == 0) {
		begin->label = label;
		begin->location = 0xffffffff;
		labels->count++;
		return 0;
	}
	end = begin + labels->count;
	for (id = 0; begin < end; ++begin, ++id) {
		if (!strcmp(label, begin->label))
			return id;
	}
	begin->label = label;
	begin->location = 0xffffffff;
	labels->count++;
	return id;
}

void seccomp_bpf_print(FILE *file, struct seccomp_filter_block *filter,
			size_t count)
{
	int i;
	struct seccomp_filter_block *end = filter + count;

	for (i = 0 ; filter < end; ++filter, i++) {
		fprintf(file, "%04d: { code=%-3u,jt=%-4u,jf=%-4u,k=%-10u }, ",
			i, filter->code, filter->jt, filter->jf, filter->k);

#if __BITS_PER_LONG == 32

		switch (filter->code) {
		case BPF_LD+BPF_W+BPF_ABS:
			if (filter->k == offsetof(struct seccomp_filter_data,
						syscall_nr))
				fprintf(file, "%s\n", "LOAD NR");
			else
				fprintf(file, "%s%d\n", "LOAD ARG", filter->k /
					offsetof(struct seccomp_filter_data,
					args[0].lo32) - 1);
			break;
		case BPF_JMP+BPF_JA:
			if (filter->k > 1)
				fprintf(file, "%s %d (line %d)\n", "JA",
						filter->k, filter->k + i + 1);
			else
				fprintf(file, "%s %d\n", "JA", filter->k);
			break;
		case BPF_JMP+BPF_JEQ+BPF_K:
			fprintf(file, "%s %d ? %d : %d\n", "JEQ",
					filter->k, filter->jt, filter->jf);
			break;
		case BPF_JMP+BPF_JGE+BPF_K:
			fprintf(file, "%s %d ? %d : %d\n", "JGE",
					filter->k, filter->jt, filter->jf);
			break;
		case BPF_JMP+BPF_JGT+BPF_K:
			fprintf(file, "%s %d ? %d : %d\n", "JGT",
					filter->k, filter->jt, filter->jf);
			break;
		case BPF_RET+BPF_K:
			if (filter->k == 0xFFFFFFFF)
				fprintf(file, "%s", "ALLOW\n");
			else if (filter->k == 0)
				fprintf(file, "%s", "DENY\n");
			break;
		default:
			fprintf(file, "\n");
			break;
		}

#elif __BITS_PER_LONG == 64
		fprintf(file, "\n");
#endif

	}
}
