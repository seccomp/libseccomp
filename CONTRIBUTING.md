How to Contribute to the libseccomp Project
===============================================================================
https://github.com/seccomp/libseccomp

This document is intended to act as a guide to help you contribute to the
libseccomp project.  It is not perfect, and there will always be exceptions
to the rules described here, but by following the instructions below you
should have a much easier time getting your work merged with the upstream
project.

## Interacting with the Community

> "Be excellent to each other." - *Bill S. Preston, Esq.*

The libseccomp project aims to be a welcoming place and we ask that anyone who
interacts with the project, and the greater community, treat each other with
dignity and respect.  Individuals who do not behave in such a manner will be
warned and asked to adjust their behavior; in extreme cases the individual
may be blocked from the project.

Examples of inappropriate behavior includes: profane, abusive, or prejudicial
language directed at another person, vandalism (e.g. GitHub issue/PR "litter"),
or spam.

## Test Your Code Using Existing Tests

There are three possible tests you can run to verify your code.  The first
test is used to check the formatting and coding style of your changes, you
can run the test with the following command:

	# make check-syntax

... if there are any problems with your changes a diff/patch will be shown
which indicates the problems and how to fix them.

The second possible test is used to ensure that the different internal syscall
tables are consistent and to test your changes against the automated test
suite.  You can run the test with the following command:

	# make check

... if there are any faults or errors they will be displayed; beware that the
tests can run for some time and produce a lot of output.

The third possible test is used to validate libseccomp against a live, running
system using some simple regression tests.  After ensuring that your system
supports seccomp filters you can run the live tests with the following
command:

	# make check-build
	# (cd tests; ./regression -T live)

... if there are any faults or errors they will be displayed.

## Add New Tests for New Functionality

The libseccomp code includes a fairly extensive test suite and any submissions
which add functionality, or significantly change the existing code, should
include additional tests to verify the proper operation of the proposed
changes.

Code coverage analysis tools have been integrated into the libseccomp code
base, and can be enabled via the "--enable-code-coverage" configure flag and
the "check-code-coverage" make target.  Additional details on generating code
coverage information can be found in the .travis.yml file.

## How to Update the syscalls.csv Table

*** NOTE - This currently can only be done on Ubuntu ***

1. Install dependencies

   In addition to the normal libseccomp package dependencies, the following
   packages must also be installed:
   ```
   apt install libc6-dev-x32
   ```

1. Download source packages

   Download the following source packages:
   ```
   git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
   git clone https://github.com/hrw/syscalls-table.git
   git clone git@github.com:<yourrepo>/libseccomp.git
   ```

1. Add new kernel version enumerations

   The first line of [src/syscalls.csv](https://github.com/seccomp/libseccomp/blob/main/src/syscalls.csv)
   contains the newest kernel version known by libseccomp.  Add new kernel
   version enumerations to the end of the `enum scmp_kver` enumeration in
   [seccomp-kvers.h](https://github.com/seccomp/libseccomp/blob/main/include/seccomp-kvers.h).
   
   Optional - Add new kernel versions to the `kernel_versions` list in
   [arch-build-kver-tables.py](https://github.com/seccomp/libseccomp/blob/main/src/arch-build-kver-tables.py).

1. Build the table(s) of architectures, syscalls, and syscall numbers

   Using the [syscalls-table](https://github.com/hrw/syscalls-table) tool,
   build the tables of architectures, syscalls, and syscall numbers for the
   new kernel versions.

   ```
   cd libseccomp
   ./src/arch-build-kver-tables.py -d ../syscalls-table -k ../linux -V [Kernel Version(s)]

   # example:
   ./src/arch-build-kver-tables.py -d ../syscalls-table -k ../linux -V 6.14,6.15,6.16,6.17,6.18,6.19,7.0-rc7
   ```

1. Add the tables to syscalls.csv

   Parse the tables generated in the previous step and add the data to
   syscalls.csv.

   ```
   ./src/arch-update-syscalls-csv.py -a -d ./ -k ../linux -c src/syscalls.csv -V [Kernel Version(s)]

   # example
   ./src/arch-update-syscalls-csv.py -a -d ./ -k ../linux -c src/syscalls.csv -V 6.14,6.15,6.16,6.17,6.18,6.19,7.0-rc7
   ```

1. Update seccomp-syscalls.h with new syscalls

   Run `cd src && ./arch-syscall-check` to determine if any new syscalls were
   added and if they require __PNR and/or __SNR definitions.  If this tool
   identifies missing definitions, add them to
   [include/seccomp-syscalls.h](https://github.com/seccomp/libseccomp/blob/main/include/seccomp-syscalls.h).  [Here](https://github.com/seccomp/libseccomp/commit/f01e67509e45c672f4bdd643d94d90867cc19d90)
    is an example of the syscalls that were added to kernel version v6.12.


1. Build the legacy syscalls.csv table (optional but recommended)

   Prior to tracking the kernel version where syscalls were added, libseccomp
   employed internal tools to build the syscalls.csv table.  These tools can
   be used to validate the syscall numbers and their architectures.  Note that
   they cannot be used to validate the kernel version number.
   
   ```
   ./autogen.sh && ./configure --enable-python && make check-build
   
   cd src
   make arch-syscall-dump
   ./arch-syscall-validate -c syscalls-prev.csv ../../linux/
   ```

1. Compare CSVs

   Compare the checked-in (HEAD) CSV with the newly-generated syscalls.csv.
   Verify the following:
   * All new syscall names were properly added
   * If a syscall number changed, it should only have transitioned from `PNR`
     to a valid number.  If a number changed for an architecture, verify that
     its associated kernel version is correct
   * No syscall rows were deleted
   
   If you built `syscalls-prev.csv` in the previous step, do the same comparisons
   as outlined above.  Again, note that `syscalls-prev.csv` does not contain
   kernel version information, so only the syscall names, syscall numbers, and
   architectures can be verified.
   
   There are many tools to compare CSVs.  This [tool](https://www.textcompare.org/csv/)
   has been especially useful.

## Explain Your Work

At the top of every patch you should include a description of the problem you
are trying to solve, how you solved it, and why you chose the solution you
implemented.  If you are submitting a bug fix, it is also incredibly helpful
if you can describe/include a reproducer for the problem in the description as
well as instructions on how to test for the bug and verify that it has been
fixed.

## Sign Your Work

The sign-off is a simple line at the end of the patch description, which
certifies that you wrote it or otherwise have the right to pass it on as an
open-source patch.  The "Developer's Certificate of Origin" pledge is taken
from the Linux Kernel and the rules are pretty simple:

	Developer's Certificate of Origin 1.1

	By making a contribution to this project, I certify that:

	(a) The contribution was created in whole or in part by me and I
	    have the right to submit it under the open source license
	    indicated in the file; or

	(b) The contribution is based upon previous work that, to the best
	    of my knowledge, is covered under an appropriate open source
	    license and I have the right under that license to submit that
	    work with modifications, whether created in whole or in part
	    by me, under the same open source license (unless I am
	    permitted to submit under a different license), as indicated
	    in the file; or

	(c) The contribution was provided directly to me by some other
	    person who certified (a), (b) or (c) and I have not modified
	    it.

	(d) I understand and agree that this project and the contribution
	    are public and that a record of the contribution (including all
	    personal information I submit with it, including my sign-off) is
	    maintained indefinitely and may be redistributed consistent with
	    this project or the open source license(s) involved.

... then you just add a line to the bottom of your patch description, with
your real name, saying:

	Signed-off-by: Random J Developer <random@developer.example.org>

You can add this to your commit description in `git` with `git commit -s`

## Post Your Patches to GitHub

The libseccomp project accepts new patches via GitHub pull requests, if you
are not familiar with GitHub pull requests please see
[this guide](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request).
