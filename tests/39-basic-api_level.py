#!/usr/bin/env python

#
# Seccomp Library test program
#
# Copyright (c) 2016 Red Hat <pmoore@redhat.com>
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

# NOTE: this is a NULL test since we don't support the seccomp_version() API
#       via the libseccomp python bindings

# kate: syntax python;
# kate: indent-mode python; space-indent on; indent-width 4; mixedindent off;
