#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2022 Canonical Ltd.
# Author: James Henstridge <james.henstridge@canonical.com>
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
    f.add_rule_exactly(ALLOW, 1001, Arg(0, NE | CMP_32BIT, 0x10))
    f.add_rule_exactly(ALLOW, 1002, Arg(0, LT | CMP_32BIT, 0x10))
    f.add_rule_exactly(ALLOW, 1003, Arg(0, LE | CMP_32BIT, 0x10))
    f.add_rule_exactly(ALLOW, 1004, Arg(0, EQ | CMP_32BIT, 0x10))
    f.add_rule_exactly(ALLOW, 1005, Arg(0, GE | CMP_32BIT, 0x10))
    f.add_rule_exactly(ALLOW, 1006, Arg(0, GT | CMP_32BIT, 0x10))
    f.add_rule_exactly(ALLOW, 1007, Arg(0, MASKED_EQ | CMP_32BIT, 0xff, 0x10))
    return f

args = util.get_opt()
ctx = test(args)
util.filter_output(args, ctx)

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
