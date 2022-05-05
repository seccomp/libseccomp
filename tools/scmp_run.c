/**
 * run a command with a given BPF profile
 *
 * Copyright (c) 2022 Maciej Borzecki <maciej.zenon.borzecki@canonical.com>
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
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAX_BPF_SIZE (12 * 1024)

static void exit_usage(const char *program)
{
	fprintf(stderr, "usage: %s -f <profile> -- <cmd...>\n", program);
	exit(EINVAL);
}

static int seccomp(unsigned int operation, unsigned int flags, void *args)
{
	errno = 0;
	return syscall(SYS_seccomp, operation, flags, args);
}

static size_t load_profile_or_die(const char *from, char *buf, size_t buf_size)
{
	FILE *f = fopen(from, "rb");
	if (f == NULL) {
		perror("cannot open profile file");
		exit(EINVAL);
	}
	size_t num_read = fread(buf, 1, buf_size - 1, f);
	buf[num_read] = 0;
	if (ferror(f) != 0) {
		perror("cannot read");
		fclose(f);
		exit(EINVAL);
	}
	if (feof(f) == 0) {
		fprintf(stderr, "cannot load BPF profile larger than %lu\n", buf_size - 1);
		fclose(f);
		exit(EINVAL);
	}
	fclose(f);
	return num_read;
}

int main(int argc, char *argv[])
{
	int opt = 0;
	const char *bpf_profile_path = NULL;
	char bpf_profile[MAX_BPF_SIZE] = {0};

	while ((opt = getopt(argc, argv, "f:h")) > 0) {
		switch (opt) {
		case 'f':
			bpf_profile_path = optarg;
			break;
		default:
			exit_usage(argv[0]);
			break;
		}
	}

	if (bpf_profile_path == NULL) {
		fprintf(stderr, "no BPF profile\n");
		exit_usage(argv[0]);
	}

	if (optind == argc) {
		fprintf(stderr, "no command\n");
		exit_usage(argv[0]);
	}

	const char *argv0 = argv[optind];
	const char **argv0_plus = (const char **)&argv[optind];

	int prof_size =
		load_profile_or_die(bpf_profile_path, bpf_profile, sizeof(bpf_profile));

	struct sock_fprog prog = {
		.len = prof_size / sizeof(struct sock_filter),
		.filter = (struct sock_filter *)bpf_profile,
	};
	/* this is intended to be used primarily as a debugging tool, so log all
	   disallowed actions */
	int err = seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG, &prog);
	/* TODO fallback to prctl if syscall fails? */
	if (err != 0) {
		perror("cannot load BPF profile");
		exit(EINVAL);
	}

	if (execv(argv0, (char *const *)argv0_plus) != 0) {
		perror("cannot exec");
		exit(EINVAL);
	}
	return 0;
}
