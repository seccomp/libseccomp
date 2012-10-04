#
# Seccomp Library utility code for tests
#
# Copyright (c) 2012 Red Hat <pmoore@redhat.com>
# Author: Paul Moore <pmoore@redhat.com>
#

#
# This library is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License as
# published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, see <http://www.gnu.org/licenses>.
#

""" Python utility code for the libseccomp test suite """

import argparse
import sys

def get_opt():
    """ Parse the arguments passed to main

    Description:
    Parse the arguments passed to the test from the command line.  Returns
    a parsed argparse object.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bpf", action="store_true")
    parser.add_argument("-p", "--pfc", action="store_true")
    return parser.parse_args()

def filter_output(args, ctx):
    """ Output the filter in either BPF or PFC

    Arguments:
    args - an argparse object from UtilGetOpt()
    ctx - a seccomp SyscallFilter object

    Description:
    Output the SyscallFilter to stdout in either BPF or PFC format depending
    on the test's command line arguments.
    """
    if (args.bpf):
        ctx.export_bpf(sys.stdout)
    else:
        ctx.export_pfc(sys.stdout)

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
