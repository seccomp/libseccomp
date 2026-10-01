#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2026 Sascha Grunert <sgrunert@redhat.com>
# Author: Sascha Grunert <sgrunert@redhat.com>
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
    f.add_arch(Arch("x86"))
    f.add_arch(Arch("x86_64"))
    f.add_arch(Arch("x32"))
    f.add_arch(Arch("aarch64"))
    # a pseudo-syscall on every arch above, without conditions so that it
    # sorts before the conditional rules and becomes the head of the syscall
    # list, where it is omitted from the filter; x86 drops the rule when it
    # is added, the others keep it
    f.add_rule(KILL, "arm_fadvise64_64")
    # the real rules must still be applied, which they are only if the
    # filter loads the syscall number before testing them
    f.add_rule(KILL, "read", Arg(0, EQ, 1))
    f.add_rule(KILL, "write", Arg(0, EQ, 1))
    return f

args = util.get_opt()
ctx = test(args)
util.filter_output(args, ctx)

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
