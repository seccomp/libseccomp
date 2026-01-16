#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2025 Microsoft Corporation <sudpandit@microsoft.com>
# Author: Sudipta Pandit <sudpandit@microsoft.com>


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
import ctypes
import ctypes.util
import os
import struct
import socket

import util

from seccomp import *


def send_fd(sock: socket.socket, fd: int):
    sock.sendmsg([b' '], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('i', fd))])

def recv_fd(sock: socket.socket):
    _msg, ancdata, _flags, _addr = sock.recvmsg(1, socket.CMSG_LEN(struct.calcsize('i')))
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            return struct.unpack('i', cmsg_data)[0]
    return None

def test():
    f = SyscallFilter(ALLOW)
    f.add_rule(NOTIFY, "openat")
    
    # Socketpair for sending file descriptors
    p_socket, c_socket = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

    pid = os.fork()
    if pid == 0:
        # load seccomp filter
        f.load()
        notify_fd = f.get_notify_fd()
        send_fd(c_socket, notify_fd)

        ret_fd = os.open("/etc/hostname", os.O_RDONLY)
        if ret_fd < 0:
            quit(ret_fd)

        ret_bytes = os.read(ret_fd, 128)
        os.close(ret_fd)
        if len(ret_bytes) != 0:
            # Expect zero bytes since the fd now points to /dev/null
            quit(1)

        os.close(notify_fd)
        c_socket.close()
        quit(0)
    else:
        # get the notification fd from child
        notify_fd = recv_fd(p_socket)
        notify = f.receive_notify(fd=notify_fd)
       
        if notify.syscall != resolve_syscall(Arch(), "openat"):
            raise RuntimeError("Notification failed")
        
        new_fd = os.open("/dev/null", os.O_RDONLY)
        installed_fd = f.notify_addfd(NotificationAddfd(notify, 0, new_fd), fd=notify_fd)
        f.respond_notify(NotificationResponse(notify, installed_fd, 0, 0), fd=notify_fd)

        # No longer need the fds
        os.close(new_fd)
        os.close(notify_fd)
        p_socket.close()

        wpid, rc = os.waitpid(pid, 0)
        if os.WIFEXITED(rc) == 0:
            raise RuntimeError("Child process error")
        if os.WEXITSTATUS(rc) != 0:
            raise RuntimeError("Child process error")
       
        quit(160)

test()

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
