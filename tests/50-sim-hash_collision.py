#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2019 Oracle and/or its affiliates.  All rights reserved.
# Author: Tom Hromatka <tom.hromatka@oracle.com>
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

import argparse
import sys

import util

from seccomp import *

def test(args):
    set_api(1)
    f = SyscallFilter(ERRNO(100))
    f.remove_arch(Arch())
    f.add_arch(Arch("x86_64"))

    # libseccomp utilizes a hash table to manage BPF blocks.  It currently
    # employs MurmurHash3 where the key is the hashed values of the BPF
    # instruction blocks, the accumulator start, and the accumulator end.
    # Changes to the hash algorithm will likely affect this test.

    # The following rules were derived from an issue reported by Tor:
    # https://github.com/seccomp/libseccomp/issues/148
    #
    # In the steps below, syscall 1001 is configured similarly to how
    # Tor configured socket.  The fairly complex rules below led to
    # a hash collision with rt_sigaction (syscall 1000) in this test.

    f.add_rule_exactly(ALLOW, 1001, Arg(0, EQ, 1), Arg(1, MASKED_EQ, 0xf, 2),
                       Arg(2, EQ, 3))
    f.add_rule_exactly(ALLOW, 1001, Arg(0, EQ, 1), Arg(1, MASKED_EQ, 0xf, 1))
    f.add_rule_exactly(ALLOW, 1000, Arg(0, EQ, 2))
    f.add_rule_exactly(ALLOW, 1000, Arg(0, EQ, 1))
    return f

args = util.get_opt()
ctx = test(args)
util.filter_output(args, ctx)

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
