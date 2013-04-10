dnl Configure script for NBD system
dnl (c) 1998 Martin Mares <mj@ucw.cz>, (c) 2000 Pavel Machek <pavel@ucw.cz>,
dnl (c) 2003-2006 Wouter Verhelst <wouter@debian.org>
AC_INIT([nbd],[3.3],[wouter@debian.org])
AM_INIT_AUTOMAKE(foreign dist-bzip2)
AM_MAINTAINER_MODE

AC_ARG_ENABLE(
  lfs,
  AC_HELP_STRING(--disable-lfs,Disable Large File Support (default on)),
  [
    if test "x$enableval" = "xyes" ; then
      NBD_LFS=1
    else
      NBD_LFS=0
    fi
  ],
  [NBD_LFS=1]
)
AC_MSG_CHECKING([whether Large File Support should be enabled])
if test $NBD_LFS -eq 1; then
  AC_DEFINE(NBD_LFS,1, [Define to 1 if Large File Support should be enabled])
  AC_MSG_RESULT([yes])
else
  AC_DEFINE(NBD_LFS,0)
  AC_MSG_RESULT([no])
fi

AC_ARG_ENABLE(
  syslog,
  AC_HELP_STRING(--enable-syslog,Enable Syslog logging),
  [
    if test "x$enableval" = "xyes" ; then
      ISSERVER=1
    else
      ISSERVER=0
    fi
  ],
  [ISSERVER=0]
)

AC_MSG_CHECKING([whether syslog logging is requested])
if test $ISSERVER -eq 1; then
  AC_DEFINE(ISSERVER,1, [Define to 1 if you want nbd-server to log through syslog])
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi

AC_ARG_ENABLE(
  debug,
  AC_HELP_STRING(--enable-debug,Build a debugging version of the server),
  [
    if test "x$enableval" = "xyes"; then
      DODBG=1
    else
      DODBG=0
    fi
  ],
  [DODBG=0]
)

AC_MSG_CHECKING([whether a debugging version is requested])
if test $DODBG -eq 1; then
  AC_MSG_RESULT([yes])
  if test $ISSERVER -eq 1; then
    AC_MSG_ERROR([You requested both syslog logging and a debugging version of the server. Bad idea!])
  fi
  AC_DEFINE(DODBG,1,[Define if you want a debugging version of nbd-server (lots of copious output)])
  AC_DEFINE(NOFORK,1,[Define if you don't want the nbd-server to fork()])
else
  AC_MSG_RESULT([no])
fi

AC_ARG_ENABLE(
  sdp,
  AC_HELP_STRING(--enable-sdp,Build a version of nbd-server with support for the Socket Direct Protocol (SDP). Requires you to build and install a kernel with the InfiniBand patches (default disabled)),
  [
    if test "x$enableval" = "xyes"; then
      AC_DEFINE(WITH_SDP, 1, [Define to 1 if you have and want support for the Socket Direct Protocol])
    fi
  ]
)

AC_PROG_CC_C99
AC_PROG_CPP
AC_PROG_INSTALL
AC_CANONICAL_HOST
AC_C_BIGENDIAN
AC_C_INLINE
AC_C_CONST
AC_CHECK_SIZEOF(unsigned short int)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long int)
AC_CHECK_SIZEOF(unsigned long long int)
AC_CHECK_FUNCS([llseek alarm gethostbyname inet_ntoa memset socket strerror strstr mkstemp fdatasync])
AC_CHECK_HEADERS([linux/falloc.h])
HAVE_FL_PH=no
if test "x$ac_cv_header_linux_falloc_h" = "xyes"
then
	AC_CHECK_DECL(FALLOC_FL_PUNCH_HOLE, [HAVE_FL_PH=yes], [HAVE_FL_PH=no], [[#include <linux/falloc.h>]])
fi

AC_MSG_CHECKING([for FALLOC_FL_PUNCH_HOLE support])
if test "x$HAVE_FL_PH" = "xyes"
then
	AC_DEFINE(HAVE_FALLOC_PH, 1, [Define to 1 if you have FALLOC_FL_PUNCH_HOLE])
	AC_MSG_RESULT([yes])
else
	AC_DEFINE(HAVE_FALLOC_PH, 0, [Define to 1 if you have FALLOC_FL_PUNCH_HOLE])
	AC_MSG_RESULT([no])
fi
AC_COMPILE_IFELSE
AC_CHECK_FUNC([sync_file_range],
	[AC_DEFINE([HAVE_SYNC_FILE_RANGE], [sync_file_range(2) is not supported], [sync_file_range(2) is supported])],
        [])
AC_FUNC_FORK
AC_FUNC_SETVBUF_REVERSED
AC_MSG_CHECKING(whether client should be built)
case $host_os in
	linux*) NBD_CLIENT_NAME="nbd-client"
		AC_MSG_RESULT(yes)
		;;
	*)	NBD_CLIENT_NAME=""
		AC_MSG_RESULT(no)
		;;
esac
AC_SUBST(NBD_CLIENT_NAME)
AC_SEARCH_LIBS(bind, socket,, AC_MSG_ERROR([Could not find an implementation of the bind() system call]))
AC_SEARCH_LIBS(inet_ntoa, nsl,, AC_MSG_ERROR([Could not find an implementation of the inet_ntoa() system call]))
AC_SEARCH_LIBS(daemon, resolv,, AC_MSG_ERROR([Could not find an implementation of the daemon() system call]))
AC_CHECK_HEADERS([sys/mount.h],,,
[[#include <sys/param.h>
]])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h sys/ioctl.h sys/socket.h syslog.h linux/types.h])
AM_PATH_GLIB_2_0(2.26.0, [HAVE_GLIB=yes], AC_MSG_ERROR([Missing glib]))
AC_HEADER_SYS_WAIT
AC_TYPE_OFF_T
AC_TYPE_PID_T
nbd_server_CPPFLAGS=$nbd_server_CPPFLAGS" -DSYSCONFDIR='\"$sysconfdir\"'"
AC_SUBST(nbd_server_CPPFLAGS)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile doc/Doxyfile doc/Makefile man/Makefile man/nbd-client.8.sh man/nbd-server.5.sh man/nbd-server.1.sh man/nbd-trdump.1.sh])
AC_OUTPUT

