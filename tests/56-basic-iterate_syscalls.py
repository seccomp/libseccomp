#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2020 Red Hat <gscrivan@redhat.com>
# Author: Giuseppe Scrivano <gscrivan@redhat.com>
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

arch_list = ["x86",
             "x86_64",
             "x32",
             "arm",
             "aarch64",
             "mipsel",
             "mipsel64",
             "mipsel64n32",
             "ppc64le",
             "riscv64"]

def test_arch(arch, init):
    for i in range(init, init + 1000):
        sys_name = resolve_syscall(arch, i)
        if sys_name is None:
            continue
        n = resolve_syscall(i, sys_name)
        if i != n:
            raise RuntimeError("Test failure")

def test():
    for i in arch_list:
        init = 0
        if i == "x32":
            init = 0x40000000
        elif i == "mipsel":
            init = 4000
        elif i == "mipsel64":
            init = 5000
        elif i == "mipsel64n32":
            init = 6000
        test_arch(Arch(i), init)

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
