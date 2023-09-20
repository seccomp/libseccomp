#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2023 Microsoft Corporation <paulmoore@microsoft.com>
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
    f = SyscallFilter(ALLOW)
    f.start_transaction()
    f.add_rule_exactly(KILL, 1000)
    f.commit_transaction()
    f.add_rule_exactly(KILL, 1001)

    f.start_transaction()
    for i in range(1, 11):
        for j in range(0, i + 1):
            f.start_transaction()
        f.add_rule_exactly(KILL, 1100 + i)
        if (i % 5):
            for j in range(0, i + 1):
                f.commit_transaction()
        else:
            for j in range(0, i + 1):
                f.reject_transaction()
    f.commit_transaction()

    f.start_transaction()
    for i in range(1, 11):
        for j in range(0, i + 1):
            f.start_transaction()
        f.add_rule_exactly(KILL, 1200 + i)
        if (i % 5):
            for j in range(0, i + 1):
                f.commit_transaction()
        else:
            for j in range(0, i + 1):
                f.reject_transaction()
    f.reject_transaction()

    f.start_transaction()
    f.add_rule_exactly(KILL, 1002)
    f.commit_transaction()
    f.add_rule_exactly(KILL, 1003)
    return f

args = util.get_opt()
ctx = test(args)
util.filter_output(args, ctx)

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
