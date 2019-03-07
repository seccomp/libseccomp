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
import errno
import sys

import util

from seccomp import *

def test(args):
    set_api(3)

    f = SyscallFilter(KILL)
    f.add_rule(ALLOW, "read", Arg(2, LE, 64))
    f.add_rule(ERRNO(5), "read", Arg(2, GT, 128))
    f.add_rule(ERRNO(6), "read", Arg(2, GT, 256))
    f.add_rule(ERRNO(7), "read", Arg(2, GT, 512))
    f.add_rule(ERRNO(8), "read", Arg(2, GT, 1024))
    f.add_rule(ERRNO(9), "read", Arg(2, GT, 2048))
    f.add_rule(ERRNO(10), "read", Arg(2, GT, 4096))
    f.add_rule(ERRNO(11), "read", Arg(2, GT, 8192))
    f.add_rule(ERRNO(12), "read", Arg(2, GT, 16384))
    f.add_rule(ALLOW, "write", Arg(2, GE, 32768))
    f.add_rule(ERRNO(5), "write", Arg(2, LT, 128))
    f.add_rule(ERRNO(6), "write", Arg(2, LT, 256))
    f.add_rule(ERRNO(7), "write", Arg(2, LT, 512))
    f.add_rule(ERRNO(8), "write", Arg(2, LT, 1024))
    f.add_rule(ERRNO(9), "write", Arg(2, LT, 2048))
    f.add_rule(ERRNO(10), "write", Arg(2, LT, 4096))
    f.add_rule(ERRNO(11), "write", Arg(2, LT, 8192))
    f.add_rule(ERRNO(12), "write", Arg(2, LT, 16384))

    return f

args = util.get_opt()
ctx = test(args)
util.filter_output(args, ctx)

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
