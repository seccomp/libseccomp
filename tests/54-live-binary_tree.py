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

denylist = [
    "times",
    "ptrace",
    "getuid",
    "syslog",
    "getgid",
    "setuid",
    "setgid",
    "geteuid",
    "getegid",
    "setpgid",
    "getppid",
    "getpgrp",
    "setsid",
    "setreuid",
    "setregid",
    "getgroups",
    "setgroups",
    "setresuid",
    "getresuid",
    "setresgid",
    "getresgid",
    "getpgid",
    "setfsuid",
    "setfsgid",
]

def test():
    action = util.parse_action(sys.argv[1])
    if not action == ALLOW:
        quit(1)
    util.install_trap()
    f = SyscallFilter(TRAP)
    f.set_attr(Attr.CTL_TSYNC, 1)
    f.set_attr(Attr.CTL_OPTIMIZE, 2)
    # NOTE: additional syscalls required for python
    f.add_rule(ALLOW, "stat")
    f.add_rule(ALLOW, "fstat")
    f.add_rule(ALLOW, "open")
    f.add_rule(ALLOW, "openat")
    f.add_rule(ALLOW, "mmap")
    f.add_rule(ALLOW, "munmap")
    f.add_rule(ALLOW, "read")
    f.add_rule(ALLOW, "write")
    f.add_rule(ALLOW, "close")
    f.add_rule(ALLOW, "rt_sigaction")
    f.add_rule(ALLOW, "rt_sigreturn")
    f.add_rule(ALLOW, "sigreturn")
    f.add_rule(ALLOW, "sigaltstack")
    f.add_rule(ALLOW, "brk")
    f.add_rule(ALLOW, "exit_group")

    for syscall in denylist:
        f.add_rule(KILL, syscall)

    f.load()
    try:
        util.write_file("/dev/null")
    except OSError as ex:
        quit(ex.errno)
    quit(160)

test()

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
