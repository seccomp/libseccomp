# -*- Makefile -*-

PYTHON = /usr/bin/env python

PY_DISTUTILS = \
	VERSION_RELEASE="@PACKAGE_VERSION@" \
	CFLAGS="-I\${top_srcdir}/include ${CFLAGS} ${CPPFLAGS}" \
	LDFLAGS="${LDFLAGS}" \
	${PYTHON} ./setup.py

# support silent builds
PY_BUILD_0 = @echo "  PYTHON  " $@; ${PY_DISTUTILS} -q build
PY_BUILD_1 = ${PY_DISTUTILS} build
PY_BUILD_ = ${PY_BUILD_0}
PY_BUILD = ${PY_BUILD_@AM_V@}

PY_INSTALL = ${PY_DISTUTILS} install

all-local: build

build: ../libseccomp.la libseccomp.pxd seccomp.pyx
	${PY_BUILD} && touch build

install-exec-local: build
	${PY_INSTALL} --prefix=${DESTDIR}/${prefix}

clean-local:
	${RM} -rf seccomp.c build/
