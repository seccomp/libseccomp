#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2016 Red Hat <pmoore@redhat.com>
# Copyright (c) 2017 Canonical Ltd.
# Authors: Paul Moore <paul@paul-moore.com>
#          Tyler Hicks <tyhicks@canonical.com>
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
    api = get_api()
    if (api < 1):
        raise RuntimeError("Failed getting initial API level")

    set_api(1)
    api = get_api()
    if api != 1:
        raise RuntimeError("Failed getting API level 1")

    set_api(2)
    api = get_api()
    if api != 2:
        raise RuntimeError("Failed getting API level 2")

    set_api(3)
    api = get_api()
    if api != 3:
        raise RuntimeError("Failed getting API level 3")

    set_api(4)
    api = get_api()
    if api != 4:
        raise RuntimeError("Failed getting API level 4")

    set_api(5)
    api = get_api()
    if api != 5:
        raise RuntimeError("Failed getting API level 5")

    set_api(6)
    api = get_api()
    if api != 6:
        raise RuntimeError("Failed getting API level 6")

    # Attempt to set a high, invalid API level
    try:
        set_api(1024)
    except ValueError:
        pass
    else:
        raise RuntimeError("Missing failure when setting invalid API level")
    # Ensure that the previously set API level didn't change
    api = get_api()
    if api != 6:
        raise RuntimeError("Failed getting old API level after setting an invalid API level")

test()

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
