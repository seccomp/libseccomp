AC_INIT([libseccomp], [2.1.0])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([configure.h])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects tar-pax no-dist-gzip dist-xz])
AC_PROG_CC
AM_PROG_CC_C_O
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_DISABLE_STATIC
LT_INIT

AC_CHECK_HEADER([linux/seccomp.h])

AM_CPPFLAGS="-I\${top_srcdir}/include"
AM_CFLAGS="-Wall"
AM_LDFLAGS="-Wl,-z -Wl,relro"
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

VERSION_MAJOR="${VERSION%%.*}"
VERSION_MINOR="${VERSION#*.}"
VERSION_MICRO="${VERSION_MINOR#*.}"
VERSION_MINOR="${VERSION_MINOR%%.*}"
VERSION_MICRO="${VERSION_MICRO%%.*}"
AC_SUBST([VERSION_MAJOR])
AC_SUBST([VERSION_MINOR])
AC_SUBST([VERSION_MICRO])

dnl ####
dnl cython checks
dnl ####
AC_CHECK_PROG(have_cython, cython, "yes", "no")
AS_IF([test "$have_cython" = yes], [
	AS_ECHO("checking cython version... $(cython -V 2>&1 | cut -d' ' -f 3)")
	CYTHON_VER_MAJ=$(cython -V 2>&1 | cut -d' ' -f 3 | cut -d'.' -f 1);
	CYTHON_VER_MIN=$(cython -V 2>&1 | cut -d' ' -f 3 | cut -d'.' -f 2);
],[
	CYTHON_VER_MAJ=0
	CYTHON_VER_MIN=0
])

dnl ####
dnl python binding checks
dnl ####
AC_ARG_ENABLE([python],
	[AS_HELP_STRING([--enable-python],
	[build the python bindings, requires cython])])
AS_IF([test "$enable_python" = yes], [
	# cython version check
	AS_IF([test "$CYTHON_VER_MAJ" -eq 0 -a "$CYTHON_VER_MIN" -lt 16], [
		AC_MSG_ERROR([python bindings require cython 0.16 or higher])
	])
])
AM_CONDITIONAL([ENABLE_PYTHON], [test "$enable_python" = yes])
AC_DEFINE_UNQUOTED([ENABLE_PYTHON],
	[$(test "$enable_python" == yes && echo 1 || echo 0)],
	[Python bindings build flag.])

AC_CONFIG_FILES([Makefile src/Makefile src/python/Makefile tools/Makefile
	tests/Makefile include/seccomp.h libseccomp.pc])
AC_OUTPUT
