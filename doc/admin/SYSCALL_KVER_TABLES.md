Generating the Syscall Kernel Version Tables
===============================================================================
https://github.com/seccomp/libseccomp

The `*_kver` columns in `src/syscalls.csv` record the first kernel version in
which each syscall was available on each architecture.  They are generated from
per-kernel-version syscall tables, which are built from the kernel sources using
the [syscalls-table](https://github.com/hrw/syscalls-table) project.  The syscall
numbers in `src/syscalls.csv` are not taken from these tables; they are
maintained using `src/arch-syscall-validate`, which preserves the kernel version
columns.

This document describes how to regenerate the kernel version columns from
scratch, and how to update them for new kernel versions.

### Requirements

* A clone of the Linux kernel git repository with the release tags.  The scripts
  check out each kernel version being processed, so do not use a tree with any
  work in progress.

		# git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git

* A clone of the syscalls-table repository.  Its `data/` directory is modified
  while the tables are built.

		# git clone https://github.com/hrw/syscalls-table.git

* A toolchain able to build the kernel headers for each kernel version being
  processed, and the glibc i386 and x32 headers.

Modern toolchains are not able to build the host tools of old kernels; for
example, kernels v3.0 and v3.15 fail with GCC 16.  Some distributions, e.g.
Fedora, do not ship the glibc x32 headers.  `src/arch-build-kver-tables.py`
checks for both problems and fails if it detects any of them.

### Building the Toolchain Container

The easiest way to get a suitable toolchain is to use a container based on an
older distribution; the one below was tested with kernels v3.0 to v7.2:

	# podman build -t libseccomp-kver - <<'EOF'
	FROM docker.io/library/ubuntu:20.04
	RUN apt-get update && \
	    DEBIAN_FRONTEND=noninteractive apt-get install -y \
	        --no-install-recommends make gcc libc6-dev libc6-dev-i386 \
	        libc6-dev-x32 perl rsync python3 git ca-certificates bc && \
	    rm -rf /var/lib/apt/lists/*
	EOF

The same command works with Docker, just replace `podman` with `docker`.

### Building the Tables

Building the tables for all kernel versions known to the scripts takes about a
minute per kernel version.  The tables are written to the `tables-<version>`
subdirectories of the current directory.

	# KERNEL=/path/to/linux
	# SCTABLE=/path/to/syscalls-table
	# TABLES=/path/to/tables
	# LIBSECCOMP=/path/to/libseccomp
	# mkdir -p $TABLES
	# podman run --rm --userns=keep-id --security-opt label=disable \
	      -v $KERNEL:$KERNEL -v $SCTABLE:$SCTABLE -v $TABLES:$TABLES \
	      -v $LIBSECCOMP:$LIBSECCOMP:ro -w $TABLES libseccomp-kver \
	      python3 $LIBSECCOMP/src/arch-build-kver-tables.py \
	          -d $SCTABLE -k $KERNEL

With Docker, replace `--userns=keep-id` with `--user $(id -u):$(id -g)`.  If the
kernel tree is a git worktree, the repository it belongs to must be mounted as
well.

To only build the tables for some kernel versions, use the `-V` option, e.g.
`-V 7.1,7.2`.

### Filling In the Kernel Versions

Once the tables are built, fill in the kernel versions in the CSV file from the
libseccomp source directory (this does not require the container):

	# ./src/arch-update-syscalls-csv.py -d $TABLES -c src/syscalls.csv \
	      -V $(ls $TABLES | sed 's/^tables-//' | paste -sd,)

This only sets the kernel versions which are `SCMP_KV_UNDEF`, so to regenerate
them from scratch, reset them first:

	# sed -i 's/SCMP_KV_[0-9][0-9_]*/SCMP_KV_UNDEF/g' src/syscalls.csv

The syscalls-table project does not generate the s390 (31-bit) tables, so the
s390 kernel versions remain `SCMP_KV_UNDEF`.

### Adding New Kernel Versions

There is no need to rebuild the tables for all kernel versions when a new
kernel is released.  To add a new kernel version, e.g. v7.3:

1. Add the `SCMP_KV_7_3` value to the `scmp_kver` enumeration in
   `include/seccomp-kvers.h`, and to the Python bindings in
   `src/python/libseccomp.pxd` and `src/python/seccomp.pyx`.

2. Add the new version to the `kernel_versions` list in
   `src/arch-build-kver-tables.py`.

3. Update the syscall numbers in the CSV file (this requires libseccomp to be
   built first); the syscalls new to this kernel version get `SCMP_KV_UNDEF`
   as their kernel version:

		# cd src; ./arch-syscall-validate -c syscalls.csv $KERNEL; cd ..

4. Build the tables for the new kernel version as described above, adding
   `-V 7.3`.  A recent toolchain is fine for recent kernels, so the container
   is only needed if the host lacks the glibc x32 headers.  If the container's
   toolchain becomes too old for new kernels, update its base image.

5. Fill in the kernel versions of the new syscalls:

		# ./src/arch-update-syscalls-csv.py -d $TABLES -c src/syscalls.csv \
		      -V 7.3
