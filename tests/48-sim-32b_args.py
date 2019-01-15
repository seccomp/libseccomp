#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2019 Cisco Systems, Inc. <pmoore2@cisco.com>
# Author: Paul Moore <paul@paul-moore.com>
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
    f = SyscallFilter(KILL)
    # NOTE: this test is different from the native/c test as the bindings don't
    #       allow negative numbers (which is a good thing here)
    f.add_rule_exactly(ALLOW, 1000, Arg(0, EQ, 0xffffffffffffffff))
    f.add_rule_exactly(ALLOW, 1064, Arg(0, EQ, 0xffffffffffffffff))
    f.add_rule_exactly(ALLOW, 1032, Arg(0, EQ, 0xffffffff))
    # here we do not have static initializers to test but need to keep
    # behaviour in sync with the native test
    f.add_rule_exactly(ALLOW, 2000, Arg(0, EQ, 0xffffffffffffffff))
    f.add_rule_exactly(ALLOW, 2064, Arg(0, EQ, 0xffffffffffffffff))
    f.add_rule_exactly(ALLOW, 2032, Arg(0, EQ, 0xffffffff))
    return f

args = util.get_opt()
ctx = test(args)
util.filter_output(args, ctx)

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
