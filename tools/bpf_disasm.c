/**
 * BPF Disassembler
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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "bpf.h"

#define _OP_FMT			"%-3s"

/**
 * Decode the BPF operand
 * @param bpf the BPF instruction
 *
 * Decode the BPF operand and print it to stdout.
 *
 */
void bpf_decode_op(const struct bpf_instr *bpf)
{
	switch (bpf->op) {
		case BPF_LD+BPF_W+BPF_IMM:
		case BPF_LD+BPF_W+BPF_ABS:
		case BPF_LD+BPF_W+BPF_IND:
		case BPF_LD+BPF_W+BPF_MEM:
		case BPF_LD+BPF_W+BPF_LEN:
		case BPF_LD+BPF_W+BPF_MSH:
			printf(_OP_FMT, "ld");
			break;
		case BPF_LD+BPF_H+BPF_IMM:
		case BPF_LD+BPF_H+BPF_ABS:
		case BPF_LD+BPF_H+BPF_IND:
		case BPF_LD+BPF_H+BPF_MEM:
		case BPF_LD+BPF_H+BPF_LEN:
		case BPF_LD+BPF_H+BPF_MSH:
			printf(_OP_FMT, "ldh");
			break;
		case BPF_LD+BPF_B+BPF_IMM:
		case BPF_LD+BPF_B+BPF_ABS:
		case BPF_LD+BPF_B+BPF_IND:
		case BPF_LD+BPF_B+BPF_MEM:
		case BPF_LD+BPF_B+BPF_LEN:
		case BPF_LD+BPF_B+BPF_MSH:
			printf(_OP_FMT, "ldb");
			break;
		case BPF_LDX+BPF_W+BPF_IMM:
		case BPF_LDX+BPF_W+BPF_ABS:
		case BPF_LDX+BPF_W+BPF_IND:
		case BPF_LDX+BPF_W+BPF_MEM:
		case BPF_LDX+BPF_W+BPF_LEN:
		case BPF_LDX+BPF_W+BPF_MSH:
		case BPF_LDX+BPF_H+BPF_IMM:
		case BPF_LDX+BPF_H+BPF_ABS:
		case BPF_LDX+BPF_H+BPF_IND:
		case BPF_LDX+BPF_H+BPF_MEM:
		case BPF_LDX+BPF_H+BPF_LEN:
		case BPF_LDX+BPF_H+BPF_MSH:
		case BPF_LDX+BPF_B+BPF_IMM:
		case BPF_LDX+BPF_B+BPF_ABS:
		case BPF_LDX+BPF_B+BPF_IND:
		case BPF_LDX+BPF_B+BPF_MEM:
		case BPF_LDX+BPF_B+BPF_LEN:
		case BPF_LDX+BPF_B+BPF_MSH:
			printf(_OP_FMT, "ldx");
			break;
		case BPF_ST:
			printf(_OP_FMT, "st");
			break;
		case BPF_STX:
			printf(_OP_FMT, "stx");
			break;
		case BPF_ALU+BPF_ADD+BPF_K:
		case BPF_ALU+BPF_ADD+BPF_X:
			printf(_OP_FMT, "add");
			break;
		case BPF_ALU+BPF_SUB+BPF_K:
		case BPF_ALU+BPF_SUB+BPF_X:
			printf(_OP_FMT, "sub");
			break;
		case BPF_ALU+BPF_MUL+BPF_K:
		case BPF_ALU+BPF_MUL+BPF_X:
			printf(_OP_FMT, "mul");
			break;
		case BPF_ALU+BPF_DIV+BPF_K:
		case BPF_ALU+BPF_DIV+BPF_X:
			printf(_OP_FMT, "div");
			break;
		case BPF_ALU+BPF_OR+BPF_K:
		case BPF_ALU+BPF_OR+BPF_X:
			printf(_OP_FMT, "or");
			break;
		case BPF_ALU+BPF_AND+BPF_K:
		case BPF_ALU+BPF_AND+BPF_X:
			printf(_OP_FMT, "and");
			break;
		case BPF_ALU+BPF_LSH+BPF_K:
		case BPF_ALU+BPF_LSH+BPF_X:
			printf(_OP_FMT, "lsh");
			break;
		case BPF_ALU+BPF_RSH+BPF_K:
		case BPF_ALU+BPF_RSH+BPF_X:
			printf(_OP_FMT, "rsh");
			break;
		case BPF_ALU+BPF_NEG+BPF_K:
		case BPF_ALU+BPF_NEG+BPF_X:
			printf(_OP_FMT, "neg");
			break;
		case BPF_JMP+BPF_JA+BPF_K:
		case BPF_JMP+BPF_JA+BPF_X:
			printf(_OP_FMT, "jmp");
			break;
		case BPF_JMP+BPF_JEQ+BPF_K:
		case BPF_JMP+BPF_JEQ+BPF_X:
			printf(_OP_FMT, "jeq");
			break;
		case BPF_JMP+BPF_JGT+BPF_K:
		case BPF_JMP+BPF_JGT+BPF_X:
			printf(_OP_FMT, "jgt");
			break;
		case BPF_JMP+BPF_JGE+BPF_K:
		case BPF_JMP+BPF_JGE+BPF_X:
			printf(_OP_FMT, "jge");
			break;
		case BPF_JMP+BPF_JSET+BPF_K:
		case BPF_JMP+BPF_JSET+BPF_X:
			printf(_OP_FMT, "jset");
			break;
		case BPF_RET+BPF_K:
		case BPF_RET+BPF_X:
		case BPF_RET+BPF_A:
			printf(_OP_FMT, "ret");
			break;
		case BPF_MISC+BPF_TAX:
			printf(_OP_FMT, "tax");
			break;
		case BPF_MISC+BPF_TXA:
			printf(_OP_FMT, "txa");
			break;
		default:
			printf(_OP_FMT, "???");
	}
}

/**
 * Decode the BPF arguments (JT, JF, and K)
 * @param bpf the BPF instruction
 * @param line the current line number
 *
 * Decode the BPF arguments (JT, JF, and K) and print the relevant information
 * to stdout based on the operand.
 *
 */
void bpf_decode_args(const struct bpf_instr *bpf, unsigned int line)
{
	switch (BPF_CLASS(bpf->op)) {
		case BPF_LD:
		case BPF_LDX:
			switch (BPF_MODE(bpf->op)) {
				case BPF_ABS:
					printf("$data[%u]", bpf->k);
					break;
				case BPF_MEM:
					printf("$temp[%u]", bpf->k);
					break;
			}
			break;
		case BPF_ST:
		case BPF_STX:
			printf("$temp[%d]", bpf->k);
			break;
		case BPF_ALU:
			printf("%u", bpf->k);
			break;
		case BPF_JMP:
			if (BPF_OP(bpf->op) == BPF_JA) {
				printf("%.4u", (line + 1) + bpf->k);
			} else {
				printf("%u, true:%.4u false:%.4u",
				       bpf->k,
				       (line + 1) + bpf->jt,
				       (line + 1) + bpf->jf);
			}
			break;
		case BPF_RET:
			if (BPF_RVAL(bpf->op) == BPF_A) {
				/* XXX - accumulator? */
				printf("$acc");
			} else if (BPF_SRC(bpf->op) == BPF_K) {
				if (bpf->k == 0)
					printf("DENY");
				else if (bpf->k == 0xffffffff)
					printf("ALLOW");
				else
					printf("0x%.8x", bpf->k);
			} else if (BPF_SRC(bpf->op) == BPF_X) {
				/* XXX - any idea? */
				printf("???");
			}
			break;
		case BPF_MISC:
			break;
		default:
			printf("???");
	}
}

/**
 * Perform a simple decoding of the BPF program
 * @param fd the BPF program
 *
 * Read the BPF program and display the instructions.  Returns zero on success,
 * negative values on failure.
 *
 */
int bpf_decode(int fd)
{
	unsigned int line = 0;
	size_t len;
	struct bpf_instr bpf;

	/* header */
	printf(" line  OP   JT   JF   K\n");
	printf("=================================\n");

	do {
		/* XXX - need to account for partial reads */
		len = read(fd, &bpf, sizeof(bpf));
		if (len < sizeof(bpf))
			return (errno == EOF ? 0 : errno);

		printf(" %.4u: 0x%.2x 0x%.2x 0x%.2x 0x%.8x",
		       line, bpf.op, bpf.jt, bpf.jf, bpf.k);

		printf("   ");
		bpf_decode_op(&bpf);
		printf(" ");
		bpf_decode_args(&bpf, line);
		printf("\n");

		line++;
	} while(len > 0);

	return 0;
}

/**
 * main
 */
int main(int argc, char *argv[])
{
	int rc;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <bpf_file>\n", argv[0]);
		return EINVAL;
	}

	fd = open(argv[1], 0);
	if (fd < 0) {
		fprintf(stderr, "error: unable to open \"%s\"\n", argv[1]);
		return errno;
	}
	rc = bpf_decode(fd);
	close(fd);

	return rc;
}

