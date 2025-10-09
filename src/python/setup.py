#!/usr/bin/env python3

#
# Enhanced Seccomp Library Python Module Build Script
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

import os

from setuptools import setup
from setuptools.extension import Extension
from Cython.Build import cythonize

setup(
	name = "seccomp",
	version = os.environ["VERSION_RELEASE"],
	description = "Python binding for libseccomp",
	long_description = "Python API for the Linux Kernel's syscall filtering capability, seccomp.",
	url = "https://github.com/seccomp/libseccomp",
	maintainer = "Paul Moore",
	maintainer_email = "paul@paul-moore.com",
	license = "LGPLv2.1",
	platforms = "Linux",
	ext_modules = cythonize([
		Extension("seccomp", ["seccomp.pyx"],
			# unable to handle libtool libraries directly
			extra_objects=["../.libs/libseccomp.a"]),
	])
)
