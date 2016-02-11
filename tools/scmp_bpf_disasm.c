/**
 * BPF Disassembler
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

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/audit.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "bpf.h"
#include "util.h"

#define _OP_FMT			"%-3s"

/**
 * Print the usage information to stderr and exit
 * @param program the name of the current program being invoked
 *
 * Print the usage information and exit with EINVAL.
 *
 */
static void exit_usage(const char *program)
{
	fprintf(stderr, "usage: %s -a <arch> [-d] [-h]\n", program);
	exit(EINVAL);
}

/**
 * Decode the BPF operand
 * @param bpf the BPF instruction
 *
 * Decode the BPF operand and print it to stdout.
 *
 */
static const char *bpf_decode_op(const bpf_instr_raw *bpf)
{
	switch (bpf->code) {
	case BPF_LD+BPF_W+BPF_IMM:
	case BPF_LD+BPF_W+BPF_ABS:
	case BPF_LD+BPF_W+BPF_IND:
	case BPF_LD+BPF_W+BPF_MEM:
	case BPF_LD+BPF_W+BPF_LEN:
	case BPF_LD+BPF_W+BPF_MSH:
		return "ld";
	case BPF_LD+BPF_H+BPF_IMM:
	case BPF_LD+BPF_H+BPF_ABS:
	case BPF_LD+BPF_H+BPF_IND:
	case BPF_LD+BPF_H+BPF_MEM:
	case BPF_LD+BPF_H+BPF_LEN:
	case BPF_LD+BPF_H+BPF_MSH:
		return "ldh";
	case BPF_LD+BPF_B+BPF_IMM:
	case BPF_LD+BPF_B+BPF_ABS:
	case BPF_LD+BPF_B+BPF_IND:
	case BPF_LD+BPF_B+BPF_MEM:
	case BPF_LD+BPF_B+BPF_LEN:
	case BPF_LD+BPF_B+BPF_MSH:
		return "ldb";
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
		return "ldx";
	case BPF_ST:
		return "st";
	case BPF_STX:
		return "stx";
	case BPF_ALU+BPF_ADD+BPF_K:
	case BPF_ALU+BPF_ADD+BPF_X:
		return "add";
	case BPF_ALU+BPF_SUB+BPF_K:
	case BPF_ALU+BPF_SUB+BPF_X:
		return "sub";
	case BPF_ALU+BPF_MUL+BPF_K:
	case BPF_ALU+BPF_MUL+BPF_X:
		return "mul";
	case BPF_ALU+BPF_DIV+BPF_K:
	case BPF_ALU+BPF_DIV+BPF_X:
		return "div";
	case BPF_ALU+BPF_OR+BPF_K:
	case BPF_ALU+BPF_OR+BPF_X:
		return "or";
	case BPF_ALU+BPF_AND+BPF_K:
	case BPF_ALU+BPF_AND+BPF_X:
		return "and";
	case BPF_ALU+BPF_LSH+BPF_K:
	case BPF_ALU+BPF_LSH+BPF_X:
		return "lsh";
	case BPF_ALU+BPF_RSH+BPF_K:
	case BPF_ALU+BPF_RSH+BPF_X:
		return "rsh";
	case BPF_ALU+BPF_NEG+BPF_K:
	case BPF_ALU+BPF_NEG+BPF_X:
		return "neg";
	case BPF_JMP+BPF_JA+BPF_K:
	case BPF_JMP+BPF_JA+BPF_X:
		return "jmp";
	case BPF_JMP+BPF_JEQ+BPF_K:
	case BPF_JMP+BPF_JEQ+BPF_X:
		return "jeq";
	case BPF_JMP+BPF_JGT+BPF_K:
	case BPF_JMP+BPF_JGT+BPF_X:
		return "jgt";
	case BPF_JMP+BPF_JGE+BPF_K:
	case BPF_JMP+BPF_JGE+BPF_X:
		return "jge";
	case BPF_JMP+BPF_JSET+BPF_K:
	case BPF_JMP+BPF_JSET+BPF_X:
		return "jset";
	case BPF_RET+BPF_K:
	case BPF_RET+BPF_X:
	case BPF_RET+BPF_A:
		return "ret";
	case BPF_MISC+BPF_TAX:
		return "tax";
	case BPF_MISC+BPF_TXA:
		return "txa";
	}
	return "???";
}

/**
 * Decode a RET action
 * @param k the return action
 *
 * Decode the action and print it to stdout.
 *
 */
static void bpf_decode_action(uint32_t k)
{
	uint32_t act = k & SECCOMP_RET_ACTION;
	uint32_t data = k & SECCOMP_RET_DATA;

	switch (act) {
	case SECCOMP_RET_KILL:
		printf("KILL");
		break;
	case SECCOMP_RET_TRAP:
		printf("TRAP");
		break;
	case SECCOMP_RET_ERRNO:
		printf("ERRNO(%u)", data);
		break;
	case SECCOMP_RET_TRACE:
		printf("TRACE(%u)", data);
		break;
	case SECCOMP_RET_ALLOW:
		printf("ALLOW");
		break;
	default:
		printf("0x%.8x", k);
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
static void bpf_decode_args(const bpf_instr_raw *bpf, unsigned int line)
{
	switch (BPF_CLASS(bpf->code)) {
	case BPF_LD:
	case BPF_LDX:
		switch (BPF_MODE(bpf->code)) {
		case BPF_ABS:
			printf("$data[%u]", bpf->k);
			break;
		case BPF_MEM:
			printf("$temp[%u]", bpf->k);
			break;
		case BPF_IMM:
			printf("%u", bpf->k);
			break;
		case BPF_IND:
			printf("$data[X + %u]", bpf->k);
			break;
		case BPF_LEN:
			printf("len($data)");
			break;
		case BPF_MSH:
			printf("4 * $data[%u] & 0x0f", bpf->k);
			break;
		}
		break;
	case BPF_ST:
	case BPF_STX:
		printf("$temp[%u]", bpf->k);
		break;
	case BPF_ALU:
		if (BPF_SRC(bpf->code) == BPF_K) {
			switch (BPF_OP(bpf->code)) {
			case BPF_OR:
			case BPF_AND:
				printf("0x%.8x", bpf->k);
				break;
			default:
				printf("%u", bpf->k);
			}
		} else
			printf("%u", bpf->k);
		break;
	case BPF_JMP:
		if (BPF_OP(bpf->code) == BPF_JA) {
			printf("%.4u", (line + 1) + bpf->k);
		} else {
			printf("%-4u true:%.4u false:%.4u",
			       bpf->k,
			       (line + 1) + bpf->jt,
			       (line + 1) + bpf->jf);
		}
		break;
	case BPF_RET:
		if (BPF_RVAL(bpf->code) == BPF_A) {
			/* XXX - accumulator? */
			printf("$acc");
		} else if (BPF_SRC(bpf->code) == BPF_K) {
			bpf_decode_action(bpf->k);
		} else if (BPF_SRC(bpf->code) == BPF_X) {
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
 * @param file the BPF program
 *
 * Read the BPF program and display the instructions.  Returns zero on success,
 * negative values on failure.
 *
 */
static int bpf_decode(FILE *file)
{
	unsigned int line = 0;
	size_t len;
	bpf_instr_raw bpf;

	/* header */
	printf(" line  OP   JT   JF   K\n");
	printf("=================================\n");

	while ((len = fread(&bpf, sizeof(bpf), 1, file))) {
		/* convert the bpf statement */
		bpf.code = ttoh16(arch, bpf.code);
		bpf.k = ttoh32(arch, bpf.k);

		/* display a hex dump */
		printf(" %.4u: 0x%.2x 0x%.2x 0x%.2x 0x%.8x",
		       line, bpf.code, bpf.jt, bpf.jf, bpf.k);

		/* display the assembler statements */
		printf("   ");
		printf(_OP_FMT, bpf_decode_op(&bpf));
		printf(" ");
		bpf_decode_args(&bpf, line);
		printf("\n");

		line++;
	}

	if (ferror(file))
		return errno;
	return 0;
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
static void bpf_dot_decode_args(const bpf_instr_raw *bpf, unsigned int line)
{
	const char *op = bpf_decode_op(bpf);

	printf("\tline%d[label=\"%s", line, op);
	switch (BPF_CLASS(bpf->code)) {
	case BPF_LD:
	case BPF_LDX:
		switch (BPF_MODE(bpf->code)) {
		case BPF_ABS:
			printf(" $data[%u]\",shape=parallelogram]\n", bpf->k);
			break;
		case BPF_MEM:
			printf(" $temp[%u]\",shape=parallelogram]\n", bpf->k);
			break;
		case BPF_IMM:
			printf(" %u\",shape=parallelogram]\n", bpf->k);
			break;
		case BPF_IND:
			printf(" $data[X + %u]\",shape=parallelogram]\n", bpf->k);
			break;
		case BPF_LEN:
			printf(" len($data)\",shape=parallelogram]\n");
			break;
		case BPF_MSH:
			printf(" 4 * $data[%u] & 0x0f\",shape=parallelogram]\n", bpf->k);
			break;
		}
		break;
	case BPF_ST:
	case BPF_STX:
		printf(" $temp[%u]\",shape=parallelogram]\n",
		       bpf->k);
		break;
	case BPF_ALU:
		if (BPF_SRC(bpf->code) == BPF_K) {
			switch (BPF_OP(bpf->code)) {
			case BPF_OR:
			case BPF_AND:
				printf(" 0x%.8x\",shape=rectangle]\n", bpf->k);
				break;
			default:
				printf(" %u\",shape=rectangle]\n", bpf->k);
			}
		} else
			printf(" %u\",shape=rectangle]\n", bpf->k);
		break;
	case BPF_JMP:
		if (BPF_OP(bpf->code) == BPF_JA) {
			printf("\",shape=hexagon]\n");
			printf("\tline%d -> line%d\n",
			       line, (line + 1) + bpf->k);
		} else {
			printf(" %-4u", bpf->k);
			/* Heuristic: if k > 256, also emit hex version */
			if (bpf->k > 256)
				printf("\\n(0x%.8x)", bpf->k);
			printf("\",shape=diamond]\n");
			printf("\tline%d -> line%d [label=\"true\"]\n",
			       line, (line + 1) + bpf->jt);
			printf("\tline%d -> line%d [label=\"false\"]\n",
			       line, (line + 1) + bpf->jf);
		}
		break;
	case BPF_RET:
		if (BPF_RVAL(bpf->code) == BPF_A) {
			/* XXX - accumulator? */
			printf(" $acc\", shape=\"box\", style=rounded]\n");
		} else if (BPF_SRC(bpf->code) == BPF_K) {
			printf(" ");
			bpf_decode_action(bpf->k);
			printf("\", shape=\"box\", style=rounded]\n");
		} else if (BPF_SRC(bpf->code) == BPF_X) {
			/* XXX - any idea? */
			printf(" ???\", shape=\"box\", style=rounded]\n");
		}
		break;
	case BPF_MISC:
		printf("\"]\n");
		break;
	default:
		printf(" ???\"]\n");
	}
}

/**
 * Perform a simple decoding of the BPF program to a dot graph
 * @param file the BPF program
 *
 * Read the BPF program and display the instructions.  Returns zero on success,
 * negative values on failure.
 *
 */
static int bpf_dot_decode(FILE *file)
{
	unsigned int line = 0;
	size_t len;
	bpf_instr_raw bpf;
	int prev_class = 0;

	/* header */
	printf("digraph {\n");
	printf("\tstart[shape=\"box\", style=rounded];\n");

	while ((len = fread(&bpf, sizeof(bpf), 1, file))) {
		/* convert the bpf statement */
		bpf.code = ttoh16(arch, bpf.code);
		bpf.k = ttoh32(arch, bpf.k);

		/* display the statement */
		bpf_dot_decode_args(&bpf, line);

		/* if previous line wasn't RET/JMP, link it to this line */
		if (line == 0)
			printf("\tstart -> line%d\n", line);
		else if ((prev_class != BPF_JMP) && (prev_class != BPF_RET))
			printf("\tline%d -> line%d\n", line - 1, line);
		prev_class = BPF_CLASS(bpf.code);

		line++;
	}
	printf("}\n");

	if (ferror(file))
		return errno;
	return 0;
}

/**
 * main
 */
int main(int argc, char *argv[])
{
	int rc;
	int opt;
	bool dot_out = false;
	FILE *file;

	/* parse the command line */
	while ((opt = getopt(argc, argv, "a:dh")) > 0) {
		switch (opt) {
		case 'a':
			if (strcmp(optarg, "x86") == 0)
				arch = AUDIT_ARCH_I386;
			else if (strcmp(optarg, "x86_64") == 0)
				arch = AUDIT_ARCH_X86_64;
			else if (strcmp(optarg, "x32") == 0)
				arch = AUDIT_ARCH_X86_64;
			else if (strcmp(optarg, "arm") == 0)
				arch = AUDIT_ARCH_ARM;
			else if (strcmp(optarg, "aarch64") == 0)
				arch = AUDIT_ARCH_AARCH64;
			else if (strcmp(optarg, "mips") == 0)
				arch = AUDIT_ARCH_MIPS;
			else if (strcmp(optarg, "mipsel") == 0)
				arch = AUDIT_ARCH_MIPSEL;
			else if (strcmp(optarg, "mips64") == 0)
				arch = AUDIT_ARCH_MIPS64;
			else if (strcmp(optarg, "mipsel64") == 0)
				arch = AUDIT_ARCH_MIPSEL64;
			else if (strcmp(optarg, "mips64n32") == 0)
				arch = AUDIT_ARCH_MIPS64N32;
			else if (strcmp(optarg, "mipsel64n32") == 0)
				arch = AUDIT_ARCH_MIPSEL64N32;
			else if (strcmp(optarg, "ppc64") == 0)
				arch = AUDIT_ARCH_PPC64;
			else if (strcmp(optarg, "ppc64le") == 0)
				arch = AUDIT_ARCH_PPC64LE;
			else if (strcmp(optarg, "ppc") == 0)
				arch = AUDIT_ARCH_PPC;
			else if (strcmp(optarg, "s390") == 0)
				arch = AUDIT_ARCH_S390;
			else if (strcmp(optarg, "s390x") == 0)
				arch = AUDIT_ARCH_S390X;
			else
				exit_usage(argv[0]);
			break;
		case 'd':
			dot_out = true;
			break;
		default:
			/* usage information */
			exit_usage(argv[0]);
		}
	}

	if ((optind > 1) && (optind < argc)) {
		int opt_file = optind - 1 ;
		file = fopen(argv[opt_file], "r");
		if (file == NULL) {
			fprintf(stderr, "error: unable to open \"%s\" (%s)\n",
				argv[opt_file], strerror(errno));
			return errno;
		}
	} else
		file = stdin;

	if (dot_out)
		rc = bpf_dot_decode(file);
	else
		rc = bpf_decode(file);
	fclose(file);

	return rc;
}
