How to Submit Patches to the libseccomp Project
===============================================================================
https://github.com/seccomp/libseccomp

This document is intended to act as a guide to help you contribute to the
libseccomp project.  It is not perfect, and there will always be exceptions
to the rules described here, but by following the instructions below you
should have a much easier time getting your work merged with the upstream
project.

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
