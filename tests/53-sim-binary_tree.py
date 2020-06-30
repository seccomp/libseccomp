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

table = [
    {"syscall": "read", "error": 0, "arg_cnt": 0 },
    {"syscall": "write", "error": 1, "arg_cnt": 0 },
    {"syscall": "open", "error": 2, "arg_cnt": 0 },
    {"syscall": "close", "error": 3, "arg_cnt": 2, "arg1": 100, "arg2": 101 },
    {"syscall": "stat", "error": 4, "arg_cnt": 0 },
    {"syscall": "fstat", "error": 5, "arg_cnt": 0 },
    {"syscall": "lstat", "error": 6, "arg_cnt": 0 },
    {"syscall": "poll", "error": 7, "arg_cnt": 1, "arg1": 102 },
    {"syscall": "lseek", "error": 8, "arg_cnt": 2, "arg1": 103, "arg2": 104 },
    {"syscall": "mmap", "error": 9, "arg_cnt": 0 },
    {"syscall": "mprotect", "error": 10, "arg_cnt": 0 },
    {"syscall": "munmap", "error": 11, "arg_cnt": 0 },
    {"syscall": "brk", "error": 12, "arg_cnt": 0 },
    {"syscall": "rt_sigaction", "error": 13, "arg_cnt": 0 },
    {"syscall": "rt_sigprocmask", "error": 14, "arg_cnt": 0 },
    {"syscall": "rt_sigreturn", "error": 15, "arg_cnt": 0 },
    {"syscall": "ioctl", "error": 16, "arg_cnt": 0 },
    {"syscall": "pread64", "error": 17, "arg_cnt": 1, "arg1": 105 },
    {"syscall": "pwrite64", "error": 18, "arg_cnt": 0 },
    {"syscall": "readv", "error": 19, "arg_cnt": 0 },
    {"syscall": "writev", "error": 20, "arg_cnt": 0 },
    {"syscall": "access", "error": 21, "arg_cnt": 0 },
    {"syscall": "pipe", "error": 22, "arg_cnt": 0 },
    {"syscall": "select", "error": 23, "arg_cnt": 2, "arg1": 106, "arg2": 107 },
    {"syscall": "sched_yield", "error": 24, "arg_cnt": 0 },
    {"syscall": "mremap", "error": 25, "arg_cnt": 2, "arg1": 108, "arg2": 109 },
    {"syscall": "msync", "error": 26, "arg_cnt": 0 },
    {"syscall": "mincore", "error": 27, "arg_cnt": 0 },
    {"syscall": "madvise", "error": 28, "arg_cnt": 0 },
    {"syscall": "dup", "error": 32, "arg_cnt": 1, "arg1": 112 },
    {"syscall": "dup2", "error": 33, "arg_cnt": 0 },
    {"syscall": "pause", "error": 34, "arg_cnt": 0 },
    {"syscall": "nanosleep", "error": 35, "arg_cnt": 0 },
    {"syscall": "getitimer", "error": 36, "arg_cnt": 0 },
    {"syscall": "alarm", "error": 37, "arg_cnt": 0 },
]

def test(args):
    f = SyscallFilter(ALLOW)

    f.remove_arch(Arch())
    f.add_arch(Arch("aarch64"))
    f.add_arch(Arch("ppc64le"))
    f.add_arch(Arch("x86_64"))

    for entry in table:
        if entry["arg_cnt"] == 2:
            f.add_rule(ERRNO(entry["error"]), entry["syscall"],
                       Arg(0, EQ, entry["arg1"]),
                       Arg(1, EQ, entry["arg2"]))
        elif entry["arg_cnt"] == 1:
            f.add_rule(ERRNO(entry["error"]), entry["syscall"],
                       Arg(0, EQ, entry["arg1"]))
        else:
            f.add_rule(ERRNO(entry["error"]), entry["syscall"])

    return f

args = util.get_opt()
ctx = test(args)
util.filter_output(args, ctx)

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
