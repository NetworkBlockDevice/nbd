dnl Configure script for NBD system
dnl (c) 1998 Martin Mares <mj@ucw.cz>, (c) 2000 Pavel Machek <pavel@ucw.cz>,
dnl (c) 2003-2004 Wouter Verhelst <wouter@debian.org>
AC_INIT([nbd],[SVN],[wouter@debian.org])
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

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_C_BIGENDIAN
AC_C_INLINE
AC_C_CONST
AC_CHECK_SIZEOF(unsigned short int)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long int)
AC_CHECK_SIZEOF(unsigned long long int)
AC_CHECK_FUNCS([llseek alarm gethostbyname inet_ntoa memset socket strerror strstr])
AC_FUNC_FORK
AC_FUNC_SETVBUF_REVERSED
AC_MSG_CHECKING(whether client should be built)
case "`uname`" in
     *Linux*) sbin_PROGRAMS=nbd-client
	      AC_MSG_RESULT(yes)
              ;;
     *) AC_MSG_RESULT(no) ;;
esac
AC_MSG_CHECKING(where to find a working nbd.h)
AC_TRY_COMPILE([#define u32 int
#define u64 int
#define __be32 int
#define __be64 int
#include "nbd.h"
],
[int foo=NBD_CMD_DISC], 
  [AC_DEFINE(NBD_H_LOCAL, 1, Set to 1 if a (2.6) nbd.h can be found in the current directory)
    NBD_H='"nbd.h"'],
  AC_TRY_COMPILE([#define u32 int
#define u64 int
#define __be32 int
#define __be64 int
#include <linux/nbd.h>
  ],
[int foo=NBD_CMD_DISC],
    [AC_DEFINE(NBD_H_LINUX, 1, Set to 1 if a (2.6) nbd.h can be found in the linux directory in the search path)
      NBD_H='<linux/nbd.h>'],
    AC_MSG_ERROR(Could not find an nbd.h from 2.6 or above.)
  )
)
if test -f nbd.h
then
  if test $NBD_H='<linux/nbd.h>'
  then
    AC_MSG_WARN([there is a local nbd.h, but it is from the 2.4-series of kernels. Using the system-provided, working, nbd.h])
  fi
fi
AC_MSG_RESULT($NBD_H)
AC_CHECK_HEADERS([sys/mount.h],,,
[[#include <sys/param.h>
]])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h sys/ioctl.h sys/socket.h syslog.h])
AM_PATH_GLIB_2_0(2.6.0, [HAVE_GLIB=yes], AC_MSG_ERROR([Missing glib]))
AC_HEADER_SYS_WAIT
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_SUBST(sbin_PROGRAMS)
nbd_server_CPPFLAGS=$nbd_server_CPPFLAGS" -DSYSCONFDIR='\"$sysconfdir\"'"
AC_SUBST(nbd_server_CPPFLAGS)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile Doxyfile nbd-server.1 nbd-server.5])
AC_OUTPUT

