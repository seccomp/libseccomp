#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2019 Cisco Systems, Inc. <pmoore2@cisco.com>
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
import os
import signal
import sys

import util

from seccomp import *

def test():
    magic = os.getuid() + 1
    f = SyscallFilter(ALLOW)
    f.set_attr(Attr.CTL_TSYNC, 1)
    f.add_rule(NOTIFY, "getuid")
    f.load()
    pid = os.fork()
    if pid == 0:
        val = os.getuid()
        if val != magic:
            raise RuntimeError("Response return value failed")
            quit(1)
        quit(0)
    else:
        notify = f.receive_notify()
        if notify.syscall != resolve_syscall(Arch(), "getuid"):
            raise RuntimeError("Notification failed")
        f.respond_notify(NotificationResponse(notify, magic, 0, 0))
        wpid, rc = os.waitpid(pid, 0)
        if os.WIFEXITED(rc) == 0:
            raise RuntimeError("Child process error")
        if os.WEXITSTATUS(rc) != 0:
            raise RuntimeError("Child process error")
        quit(160)

test()

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
