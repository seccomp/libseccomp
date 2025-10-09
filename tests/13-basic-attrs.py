#!/usr/bin/env/python3

#
# Seccomp Library test program
#
# Copyright (c) 2012 Red Hat <pmoore@redhat.com>
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

def test():
    set_api(5)

    f = SyscallFilter(ALLOW)
    if f.get_attr(Attr.ACT_DEFAULT) != ALLOW:
        raise RuntimeError("Failed getting Attr.ACT_DEFAULT")
    try:
        f.set_attr(Attr.ACT_DEFAULT, ALLOW)
    except RuntimeError:
        pass
    f.set_attr(Attr.ACT_BADARCH, ALLOW)
    if f.get_attr(Attr.ACT_BADARCH) != ALLOW:
        raise RuntimeError("Failed getting Attr.ACT_BADARCH")
    f.set_attr(Attr.CTL_NNP, 0)
    if f.get_attr(Attr.CTL_NNP) != 0:
        raise RuntimeError("Failed getting Attr.CTL_NNP")
    if f.get_attr(Attr.CTL_TSYNC) != 0:
        raise RuntimeError("Failed getting Attr.CTL_TSYNC")
    f.set_attr(Attr.API_TSKIP, 0)
    if f.get_attr(Attr.API_TSKIP) != 0:
        raise RuntimeError("Failed getting Attr.API_TSKIP")
    f.set_attr(Attr.CTL_LOG, 1)
    if f.get_attr(Attr.CTL_LOG) != 1:
        raise RuntimeError("Failed getting Attr.CTL_LOG")
    f.set_attr(Attr.CTL_SSB, 1)
    if f.get_attr(Attr.CTL_SSB) != 1:
        raise RuntimeError("Failed getting Attr.CTL_SSB")
    f.set_attr(Attr.CTL_OPTIMIZE, 2)
    if f.get_attr(Attr.CTL_OPTIMIZE) != 2:
        raise RuntimeError("Failed getting Attr.CTL_OPTIMIZE")
    f.set_attr(Attr.API_SYSRAWRC, 1)
    if f.get_attr(Attr.API_SYSRAWRC) != 1:
        raise RuntimeError("Failed getting Attr.API_SYSRAWRC")
    f.set_attr(Attr.CTL_WAITKILL, 1)
    if f.get_attr(Attr.CTL_WAITKILL) != 1:
        raise RuntimeError("Failed getting Attr.CTL_WAITKILL")

test()

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
