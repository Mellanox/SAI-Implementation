
dnl Process this file with autoconf to produce a configure script.
AC_INIT([mlnx_sai], [3.0.0000])
AC_CONFIG_SRCDIR([])

dnl use local config dir for extras
AC_CONFIG_AUX_DIR(config)

dnl we use auto cheader
AM_CONFIG_HEADER(config.h)

dnl Defines the Language - we need gcc linker ...
AC_LANG_C

dnl Auto make
AM_INIT_AUTOMAKE

dnl Provides control over re-making of all auto files
AM_MAINTAINER_MODE

dnl Required for cases make defines a MAKE=make ??? Why
AC_PROG_MAKE_SET

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_CC

dnl We will use libtool for making ...
AC_PROG_LIBTOOL

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/types.h stdio.h stdlib.h string.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE

AM_INIT_AUTOMAKE([foreign subdir-objects])

dnl Checks for library functions.
#AC_CHECK_FUNCS([strchr strstr strtol strtoull regcomp regexec])

dnl Define an input config option to control syslog support
AC_ARG_ENABLE(syslog,
[  --enable-syslog    Turn on syslog],
[case "${enableval}" in
	yes) syslog=true ;;
	no)  syslog=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-syslog) ;;
esac],[syslog=false])
AM_CONDITIONAL(CONFIG_SYSLOG, test x$syslog = xtrue)

dnl Define an input config option to control debug compile
AC_ARG_ENABLE(debug,
[  --enable-debug    Turn on debugging],
[case "${enableval}" in
	yes) debug=true ;;
	no)  debug=false ;;
	*) AC_MSG_ERROR(bad value ${enableval} for --enable-debug) ;;
esac],[debug=false])
AM_CONDITIONAL(DEBUG, test x$debug = xtrue)

AC_ARG_ENABLE([simx],
  [AS_HELP_STRING([--enable-simx],
  [Notify that device is simix])],
  [simx=$enableval],
  [simx=no])

if test "x$simx" = xyes; then
  AC_DEFINE(IS_SIMX, 1, [Notify that device is simix])
fi

AC_ARG_ENABLE([maxrifs],
  [AS_HELP_STRING([--enable-maxrifs],
  [Notify that SPC4 max RIFs feature is enabled])],
  [maxrifs=$enableval],
  [maxrifs=no])

if test "x$maxrifs" = xyes; then
  AC_DEFINE(SPC4_MAX_RIFS, 1, [Notify that SPC4 max RIFs feature is enabled])
fi

AC_ARG_ENABLE([maxlags],
  [AS_HELP_STRING([--enable-maxlags],
  [Notify that SPC4 max LAGs feature is enabled])],
  [maxlags=$enableval],
  [maxlags=no])

if test "x$maxlags" = xyes; then
  AC_DEFINE(SPC4_MAX_LAGS_CONFIG, 1, [Notify that SPC4 max LAGs feature is enabled])
fi

dnl Define an input config option to control complib path
AC_ARG_WITH(sxcomplib,
[  --with-sxcomplib=<dir> define SwitchX compatibility library directory],
AC_MSG_NOTICE(Using SwitchX compatibility library from:$with_sxcomplib),
with_sxcomplib="none")
SX_COMPLIB_PATH=/usr/local
if test "x$with_sxcomplib" != xnone; then
  SX_COMPLIB_PATH=$with_sxcomplib
fi
AC_SUBST(SX_COMPLIB_PATH)

dnl Define an input config option to control sxd lib path
AC_ARG_WITH(sxdlibs,
[  --with-sxdlibs=<dir> define SwitchX Driver libraries directory],
AC_MSG_NOTICE(Using SwitchX Driver libraries from:$with_sxdlibs),
with_sxdlibs="none")
SXD_LIBS_PATH=/usr/local
if test "x$with_sxdlibs" != xnone; then
  SXD_LIBS_PATH=$with_sxdlibs
fi
AC_SUBST(SXD_LIBS_PATH)

dnl Define an input config option to control applibs path
AC_ARG_WITH(applibs,
[  --with-applibs=<dir> define SwitchX Application libraries directory],
AC_MSG_NOTICE(Using SwitchX Application libraries from:$with_applibs),
with_applibs="none")
APP_LIB_PATH=/usr/local
if test "x$with_applibs" != xnone; then
  APP_LIB_PATH=$with_applibs
fi
AC_SUBST(APP_LIB_PATH)

dnl Define an input config option to control applibs path
AC_ARG_WITH(xml2,
[  --with-xml2=<dir> define xml2 libraries directory],
AC_MSG_NOTICE(Using xml2 libraries from:$with_xml2),
with_xml2="none")
XML2_LIB_PATH=/usr
if test "x$with_xml2" != xnone; then
  XML2_LIB_PATH=$with_xml2
fi
AC_SUBST(XML2_LIB_PATH)

dnl Define an input config option to control python scripts path
AC_ARG_WITH(pydir,
[  --with-pydir=<dir> define python scripts directory],
AC_MSG_NOTICE(Using python scripts from:$with_pydir),
with_pydir="none")
APP_PY_PATH=/usr/bin
if test "x$with_pydir" != xnone; then
  APP_PY_PATH=$with_pydir
fi
AC_SUBST(APP_PY_PATH)

dnl Define an ELDK5 xml2 la libdir setting work around condition
AM_CONDITIONAL(XML2_ELDK5_LA_WA, test x`echo $with_xml2 | grep powerpc-4xx` != x)


CFLAGS_SAI_INTERFACE_COMMON="-Wall -Wswitch -Wunused -Werror -fPIC -fno-strict-aliasing -Wextra -Wno-unused-parameter -Wdate-time -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Werror=format-security -Wno-psabi"
AC_SUBST(CFLAGS_SAI_INTERFACE_COMMON)

dnl Create the following Makefiles
AC_OUTPUT([Makefile src/Makefile etc/sai.pc etc/Makefile])
