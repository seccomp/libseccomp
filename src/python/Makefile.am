####
# Seccomp Library Python Bindings
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

PY_DISTUTILS = \
	VERSION_RELEASE="@PACKAGE_VERSION@" \
	CPPFLAGS="-I\${top_srcdir}/include ${AM_CPPFLAGS} ${CPPFLAGS}" \
	CFLAGS="${AM_CFLAGS} ${CFLAGS}" \
	LDFLAGS="${AM_LDFLAGS} ${LDFLAGS}" \
	${PYTHON} ${srcdir}/setup.py

# support silent builds
PY_BUILD_0 = @echo "  PYTHON  " $@; ${PY_DISTUTILS} -q build
PY_BUILD_1 = ${PY_DISTUTILS} build
PY_BUILD_ = ${PY_BUILD_0}
PY_BUILD = ${PY_BUILD_@AM_V@}

# Build a wheel via PEP 517 (python -m build --no-isolation) to avoid the
# deprecated "setup.py install" invocation.  The --no-isolation flag reuses
# the in-tree build environment rather than creating an isolated venv.
PY_BDIST_WHEEL = \
	VERSION_RELEASE="@PACKAGE_VERSION@" \
	CPPFLAGS="-I\${top_srcdir}/include ${AM_CPPFLAGS} ${CPPFLAGS}" \
	CFLAGS="${AM_CFLAGS} ${CFLAGS}" \
	LDFLAGS="${AM_LDFLAGS} ${LDFLAGS}" \
	${PYTHON} -m build --wheel --no-isolation

EXTRA_DIST = libseccomp.pxd seccomp.pyx setup.py

all-local: build

build: ../libseccomp.la libseccomp.pxd seccomp.pyx setup.py
	[ -f ${builddir}/seccomp.pyx ] || cp ${srcdir}/seccomp.pyx ${builddir}
	${PY_BUILD} && touch build

install-exec-local: build
	${PY_BDIST_WHEEL}
	${PYTHON} -m installer \
		--destdir=${DESTDIR}/ \
		--prefix=${prefix} \
		dist/seccomp-*.whl

uninstall-local:
	${PYTHON} -m pip uninstall --yes seccomp

clean-local:
	[ ${srcdir} = ${builddir} ] || ${RM} -f ${builddir}/seccomp.pyx
	${RM} -rf seccomp.c build dist seccomp.egg-info
