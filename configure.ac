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

dnl AC_ARG_ENABLE([python],
dnl	[AS_HELP_STRING([--enable-python], [build the python bindings, requires cython])])
enable_python=no
AM_CONDITIONAL([ENABLE_PYTHON], [test "$enable_python" = yes])
cython_ver=$(which cython >/dev/null 2>/dev/null && cython -V 2>&1 | cut -d' ' -f3)
cython_maj=$(echo "$cython_ver" | cut -d'.' -f1)
cython_min=$(echo "$cython_ver" | cut -d'.' -f2)
AS_IF([test "$enable_python" = yes], [
	recent=""
	AS_IF([test -n "$cython_maj" -a -n "$cython_min" &&
	  ! test "$cython_maj" -eq 0 -a "$cython_min" -lt 16], [recent=yes])
	AS_IF([test -z "$recent"], [
		AC_MSG_ERROR([python bindings require cython 0.16 or higher])
	])
])

AC_CONFIG_FILES([Makefile src/Makefile src/python/Makefile tools/Makefile
	tests/Makefile include/seccomp.h libseccomp.pc])
AC_OUTPUT
