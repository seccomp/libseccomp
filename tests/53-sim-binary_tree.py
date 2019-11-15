#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2018 Oracle and/or its affiliates.  All rights reserved.
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
    f = SyscallFilter(ALLOW)

    f.remove_arch(Arch())
    f.add_arch(Arch("x86_64"))
    f.add_arch(Arch("x86"))
    f.set_attr(Attr.CTL_OPTIMIZE, 2)

    for i in range(330):
        if (i == 10 or i == 53 or i == 61 or i == 255):
            f.add_rule(ERRNO(i), i, Arg(0, EQ, i))
        else:
            f.add_rule(ERRNO(i), i)

    return f

args = util.get_opt()
ctx = test(args)
util.filter_output(args, ctx)

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
