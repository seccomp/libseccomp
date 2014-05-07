####
# Seccomp Library
#

#
# This library is free software; you can redistribute it and/or modify it
# under the terms of version 2.1 of the GNU Lesser General Public License
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
# General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this library; if not, see <http://www.gnu.org/licenses>.
#

ACLOCAL_AMFLAGS = -I m4
SUBDIRS = include src tools tests doc

pkgconfdir = ${libdir}/pkgconfig
pkgconf_DATA = libseccomp.pc

# support silent builds
AM_MAKEFLAGS_0 = --quiet --no-print-directory
AM_MAKEFLAGS_1 =
AM_MAKEFLAGS_ = ${AM_MAKEFLAGS_0}
AM_MAKEFLAGS = ${AM_MAKEFLAGS_@AM_V@}

check-build: all
	${MAKE} ${AM_MAKEFLAGS} -C tests check-build

check-syntax:
	@./tools/check-syntax
