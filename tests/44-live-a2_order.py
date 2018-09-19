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
import os
import sys

import util

from seccomp import *

DEFAULT_ACTION_ERRNO = 100
DEFAULT_ACTION = ERRNO(DEFAULT_ACTION_ERRNO)

test_cases = [
    {'sz': 1, 'exp_rc': 1},
    {'sz': 10, 'exp_rc': 10},
    {'sz': 50, 'exp_rc': 50},
    {'sz': 100, 'exp_rc': -DEFAULT_ACTION_ERRNO},
    {'sz': 200, 'exp_rc': -5},
    {'sz': 256, 'exp_rc': -5},
    {'sz': 257, 'exp_rc': -6},
    {'sz': 400, 'exp_rc': -6},
    {'sz': 800, 'exp_rc': -7},
    {'sz': 1600, 'exp_rc': -8},
    {'sz': 3200, 'exp_rc': -9},
    {'sz': 4095, 'exp_rc': -9},
    {'sz': 4096, 'exp_rc': -9},
    {'sz': 4097, 'exp_rc': -10},
    {'sz': 8000, 'exp_rc': -10},
    {'sz': 8192, 'exp_rc': -10},
    {'sz': 16383, 'exp_rc': -11},
    {'sz': 16384, 'exp_rc': -11},
    {'sz': 16385, 'exp_rc': -12},
    {'sz': 35000, 'exp_rc': -12},
]

def do_read():
    fd = os.open("/dev/zero", os.O_RDONLY)
    for x in test_cases:
        try:
            os.read(fd, x['sz'])
            if x['exp_rc'] < 0:
                os.close(fd)
                raise IOError("Erroneously read %d bytes.  Expected rc = %d" %
                    (x['sz'], x['exp_rc']))
        except OSError as ex:
            if -ex.errno != x['exp_rc']:
                os.close(fd)
                raise IOError("Expected errno %d but os.read(%d bytes) caused errno %d" %
                    (-x['exp_rc'], x['sz'], ex.errno))
    os.close(fd)

def test():
    f = SyscallFilter(DEFAULT_ACTION)
    f.add_rule(ALLOW, "read", Arg(2, LE, 64))
    f.add_rule(ERRNO(5), "read", Arg(2, GT, 128))
    f.add_rule(ERRNO(6), "read", Arg(2, GT, 256))
    f.add_rule(ERRNO(7), "read", Arg(2, GT, 512))
    f.add_rule(ERRNO(8), "read", Arg(2, GT, 1024))
    f.add_rule(ERRNO(9), "read", Arg(2, GT, 2048))
    f.add_rule(ERRNO(10), "read", Arg(2, GT, 4096))
    f.add_rule(ERRNO(11), "read", Arg(2, GT, 8192))
    f.add_rule(ERRNO(12), "read", Arg(2, GT, 16384))
    # NOTE: additional syscalls required for python
    f.add_rule(ALLOW, "close")
    f.add_rule(ALLOW, "rt_sigaction")
    f.add_rule(ALLOW, "rt_sigreturn")
    f.add_rule(ALLOW, "sigaltstack")
    f.add_rule(ALLOW, "exit_group")
    f.add_rule(ALLOW, "exit")
    f.add_rule(ALLOW, "brk")
    f.add_rule(ALLOW, "open")
    f.add_rule(ALLOW, "openat")
    f.add_rule(ALLOW, "stat")
    f.add_rule(ALLOW, "write")
    f.load()

    do_read()

    # all reads behaved as expected
    quit(160)

test()

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
