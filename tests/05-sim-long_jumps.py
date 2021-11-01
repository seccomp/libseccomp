#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2012 Red Hat <pmoore@redhat.com>
# Copyright (c) 2021 Microsoft Corporation <paulmoore@microsoft.com>
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
    f.add_rule(ALLOW, "brk")
    i = 0
    while i < 100:
        f.add_rule(ALLOW, "chdir",
                   Arg(0, EQ, i),
                   Arg(1, NE, 0),
                   Arg(2, LT, sys.maxsize))
        i += 1
    i = 0
    ctr = 0
    while i < 10000 and ctr < 100:
        sc = i
        i += 1
        if sc == resolve_syscall(Arch(), "chdir"):
            continue
        try:
            resolve_syscall(Arch(), sc)
        except ValueError:
            continue
        f.add_rule(ALLOW, sc, Arg(0, NE, 0))
        ctr += 1
    f.add_rule(ALLOW, "close")
    return f

args = util.get_opt()
ctx = test(args)
util.filter_output(args, ctx)

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;

