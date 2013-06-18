# -*- Makefile -*-

PYTHON = /usr/bin/env python
pyverbose_0 = -q
pyverbose_ = ${pyverbose_0}

PY_DISTUTILS = \
	VERSION_RELEASE="${VERSION_RELEASE}" \
	CFLAGS="-I\${top_srcdir}/include ${CFLAGS} ${CPPFLAGS}" \
	LDFLAGS="${LDFLAGS}" \
	${PYTHON} ./setup.py
PY_BUILD = ${PY_DISTUTILS} build ${pyverbose_${V}}
PY_INSTALL = ${PY_DISTUTILS} install ${pyverbose_${V}}

all-local: python-build

python-build: ../libseccomp.la libseccomp.pxd seccomp.pyx
	${AM_V_GEN}${PY_DISTUTILS} build && touch $@

install-exec-local:
	${PY_DISTUTILS} install --prefix=${DESTDIR}/${prefix}

clean-local:
	rm -Rf python-build seccomp.c
