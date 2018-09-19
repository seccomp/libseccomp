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
import threading
import time

import util

from seccomp import *

def child_start(param):
    param = 1

    try:
        fd = os.open("/dev/null", os.O_WRONLY)
    except IOError as ex:
        param = ex.errno
        quit(ex.errno)

def test():
    f = SyscallFilter(KILL_PROCESS)
    f.add_rule(ALLOW, "clone")
    f.add_rule(ALLOW, "exit")
    f.add_rule(ALLOW, "exit_group")
    f.add_rule(ALLOW, "futex")
    f.add_rule(ALLOW, "madvise")
    f.add_rule(ALLOW, "mmap")
    f.add_rule(ALLOW, "mprotect")
    f.add_rule(ALLOW, "munmap")
    f.add_rule(ALLOW, "nanosleep")
    f.add_rule(ALLOW, "set_robust_list")
    f.load()

    param = 0
    threading.Thread(target = child_start, args = (param, ))
    thread.start()

    time.sleep(1)

    quit(-errno.EACCES)

test()

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
