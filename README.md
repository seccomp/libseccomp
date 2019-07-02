![Enhanced Seccomp Helper Library](https://github.com/seccomp/libseccomp-artwork/blob/master/logo/libseccomp-color_text.png)
===============================================================================
https://github.com/seccomp/libseccomp

[![CII Best Practices](https://bestpractices.coreinfrastructure.org/projects/608/badge)](https://bestpractices.coreinfrastructure.org/projects/608)
[![Build Status](https://img.shields.io/travis/seccomp/libseccomp/master.svg)](https://travis-ci.org/seccomp/libseccomp)
[![Coverage Status](https://img.shields.io/coveralls/github/seccomp/libseccomp/master.svg)](https://coveralls.io/github/seccomp/libseccomp?branch=master)

The libseccomp library provides an easy to use, platform independent, interface
to the Linux Kernel's syscall filtering mechanism.  The libseccomp API is
designed to abstract away the underlying BPF based syscall filter language and
present a more conventional function-call based filtering interface that should
be familiar to, and easily adopted by, application developers.

## Online Resources

The library source repository currently lives on GitHub at the following URL:

* https://github.com/seccomp/libseccomp

The Go language bindings repository currently lives on GitHub at the following
URL:

* https://github.com/seccomp/libseccomp-golang

The project mailing list is currently hosted on Google Groups at the URL below,
please note that a Google account is not required to subscribe to the mailing
list.

* https://groups.google.com/forum/#!forum/libseccomp
* https://groups.google.com/forum/#!forum/libseccomp/join

## Supported Architectures

The libseccomp library currently supports the architectures listed below:

* 32-bit x86 (x86)
* 64-bit x86 (x86_64)
* 64-bit x86 x32 ABI (x32)
* 32-bit ARM EABI (arm)
* 64-bit ARM (aarch64)
* 32-bit MIPS (mips)
* 32-bit MIPS little endian (mipsel)
* 64-bit MIPS (mips64)
* 64-bit MIPS little endian (mipsel64)
* 64-bit MIPS n32 ABI (mips64n32)
* 64-bit MIPS n32 ABI little endian (mipsel64n32)
* 32-bit PA-RISC (parisc)
* 64-bit PA-RISC (parisc64)
* 32-bit PowerPC (ppc)
* 64-bit PowerPC (ppc64)
* 64-bit PowerPC little endian (ppc64le)
* 32-bit s390 (s390)
* 64-bit s390x (s390x)

## Documentation

The "doc/" directory contains all of the currently available documentation,
mostly in the form of manpages.  The top level directory also contains a README
file (this file) as well as the LICENSE, CREDITS, CONTRIBUTING, and
CHANGELOG files.

Those who are interested in contributing to the the project are encouraged to
read the CONTRIBUTING in the top level directory.

## Building and Installing the Library

If you are building the libseccomp library from an official release tarball,
you should follow the familiar three step process used by most autotools based
applications:

	# ./configure
	# make [V=0|1]
	# make install

However, if you are building the library from sources retrieved from the source
repository you may need to run the autogen.sh script before running configure.
In both cases, running "./configure -h" will display a list of build-time
configuration options.

## Testing the Library

There are a number of tests located in the "tests/" directory and a make target
which can be used to help automate their execution.  If you want to run the
standard regression tests you can execute the following after building the
library:

	# make check

These tests can be safely run on any Linux system, even those where the kernel
does not support seccomp-bpf (seccomp mode 2).  However, be warned that the
test run can take a while to run and produces a lot of output.

The generated seccomp-bpf filters can be tested on a live system using the
"live" tests; they can be executed using the following commands:

	# make check-build
	# (cd tests; ./regression -T live)

These tests will fail if the running Linux Kernel does not provide the
necessary support.

## Developer Tools

The "tools/" directory includes a number of tools which may be helpful in the
development of the library, or applications using the library.  Not all of
these tools are installed by default.

## Bug and Vulnerability Reporting

Problems with the libseccomp library can be reported using the GitHub issue
tracking system or the mailing list.  Those who wish to privately report
potential vulnerabilities should follow the directions in SECURITY.md.
