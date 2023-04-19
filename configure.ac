dnl Configure script for NBD system
dnl (c) 1998 Martin Mares <mj@ucw.cz>, (c) 2000 Pavel Machek <pavel@ucw.cz>,
dnl (c) 2003-2006 Wouter Verhelst <wouter@debian.org>
AC_INIT([nbd],
  m4_esyscmd(support/genver.sh | tr -d '\n'),
  [nbd@other.debian.org],,
  [http://nbd.sourceforge.net/])
m4_define([serial_tests], [
  m4_esyscmd([automake --version |
              head -1 |
              awk '{split ($NF,a,"."); if (a[1] == 1 && a[2] >= 12) { print "serial-tests" }}'
  ])
])
AM_INIT_AUTOMAKE(foreign dist-xz serial_tests subdir-objects)
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])
AC_CONFIG_MACRO_DIR([support])
LT_INIT

AC_ARG_ENABLE(
  lfs,
  AS_HELP_STRING([--disable-lfs],[Disable Large File Support (default on)]),
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
  AS_HELP_STRING([--enable-syslog],[Enable Syslog logging]),
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
  AS_HELP_STRING([--enable-debug],[Build a debugging version of the server]),
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
  AC_DEFINE(NOFORK,1,[Define if you do not want the nbd-server to fork()])
else
  AC_MSG_RESULT([no])
fi

AC_ARG_ENABLE(
  [gznbd],
  [AS_HELP_STRING([--enable-gznbd],[Build gznbd too (nbd server with on-the-fly decompression of images. NOTE: no support for newstyle protocol.)])],
  [
    AS_IF(
      [test "x$enableval" = "xyes"],
      [ENABLE_GZNBD=yes],
      [ENABLE_GZNBD=no]
    )
  ],
  [ENABLE_GZNBD=no]
)

AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AM_PROG_LEX(noyywrap)
m4_ifdef([AX_PROG_BISON],,
 [m4_fatal([The m4 macro AX_PROG_BISON has not been defined. Please install the autoconf-archive package.])])
AX_PROG_BISON([],AC_MSG_ERROR([bison is required]))
PKG_PROG_PKG_CONFIG
AC_CANONICAL_HOST
AC_C_BIGENDIAN
AC_C_INLINE
AC_C_CONST
AC_CHECK_SIZEOF(unsigned short int)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned long int)
AC_CHECK_SIZEOF(unsigned long long int)
AC_STRUCT_DIRENT_D_TYPE
AC_CHECK_FUNCS([llseek alarm gethostbyname inet_ntoa memset socket strerror strstr mkstemp fdatasync])
HAVE_FL_PH=no

AC_CHECK_FUNC(fallocate,
  [
    AC_CHECK_HEADERS([linux/falloc.h])
    if test "x$ac_cv_header_linux_falloc_h" = "xyes"
    then
      AC_CHECK_DECL(FALLOC_FL_PUNCH_HOLE, [HAVE_FL_PH=yes], [HAVE_FL_PH=no], [[#include <linux/falloc.h>]])
    fi
  ]
)

AC_MSG_CHECKING([for FALLOC_FL_PUNCH_HOLE support])
if test "x$HAVE_FL_PH" = "xyes"
then
	AC_DEFINE(HAVE_FALLOC_PH, 1, [Define to 1 if you have FALLOC_FL_PUNCH_HOLE])
	AC_MSG_RESULT([yes])
else
	AC_DEFINE(HAVE_FALLOC_PH, 0, [Define to 1 if you have FALLOC_FL_PUNCH_HOLE])
	AC_MSG_RESULT([no])
fi

AC_CHECK_DECL([BLKDISCARD], AC_DEFINE(HAVE_BLKDISCARD, 1, [Define to 1 if you have the BLKDISCARD ioctl]), AC_DEFINE(HAVE_BLKDISCARD, 0), [#include <linux/fs.h>])

AC_CHECK_FUNC(splice, [HAVE_SPLICE=yes], [HAVE_SPLICE=no])
if test "$HAVE_SPLICE" = "yes"
then
	HAVE_SETPIPE_SZ=no
	AC_CHECK_DECL(F_SETPIPE_SZ, [HAVE_SETPIPE_SZ=yes],
		[
			unset ac_cv_have_decl_F_SETPIPE_SZ
			AC_CHECK_HEADERS([linux/fcntl.h])
			if test "$ac_cv_header_linux_fcntl_h" = "yes"
			then
				AC_CHECK_DECL(F_SETPIPE_SZ, [HAVE_SETPIPE_SZ=define], [HAVE_SETPIPE_SZ=no], [[#include <linux/fcntl.h>]])
			fi
		],
		[[
			#define _GNU_SOURCE
			#include <fcntl.h>
		]]
	)
	AC_MSG_CHECKING([for F_SETPIPE_SZ support])
	case $HAVE_SETPIPE_SZ in
		yes)
			AC_DEFINE(HAVE_SPLICE, 1, [Define to 1 if we have splice support])
			AC_MSG_RESULT([yes])
		;;
		define)
			AC_DEFINE(HAVE_SPLICE, 1, [Define to 1 if we have splice support])
			AC_DEFINE(F_SETPIPE_SZ, 1031, [Define to 1031 if we have kernel support but no userspace support])
			AC_MSG_RESULT([yes])
		;;
		no)
			AC_MSG_RESULT([missing, disabling splice support])
		;;
	esac
fi

m4_ifndef([PKG_CHECK_MODULES], [m4_fatal([Missing pkg-config M4 macros. Please ensure that pkg-config is installed.])])

dnl AC_MSG_CHECKING([where to puth systemd unit files])
dnl AC_ARG_WITH(
dnl   systemd,
dnl   AS_HELP_STRING([--with-systemd=loc|pkgconfig],[Install systemd files in loc; if passing pkgconfig, use pkg-config to detect the correct location and install there.])
dnl   [
dnl     if test "x$enableval" = "xyes"; then
dnl       ENABLE_SYSTEMD=yes
dnl     else
dnl       ENABLE_SYSTEMD=no
dnl     fi
dnl   ],[]
dnl )
dnl 
dnl if test "x$ENABLE_SYSTEMD" != "xno"; then
dnl 	PKG_CHECK_VAR([SYSTEMDUNIT],[systemd],systemdsystemunitdir],[AC_SUBST([SYSTEMDLOC], [$SYSTEMDUNIT])])
dnl fi
dnl AM_CONDITIONAL(SYSTEMD, [test ! -z "$SYSTEMDUNIT"])
dnl if test ! -z $SYSTEMDUNIT; then
dnl 	AC_MSG_RESULT([$SYSTEMDUNIT])
dnl else
dnl 	case $ENABLE_SYSTEMD in
dnl 		no)
dnl 			AC_MSG_RESULT([disabled])
dnl 		;;
dnl 		yes)
dnl 			AC_MSG_ERROR([systemd not found])
dnl 		;;
dnl 		*)
dnl 			AC_MSG_RESULT([not found])
dnl 		;;
dnl 	esac
dnl fi

AC_ARG_WITH([gnutls],
	[AS_HELP_STRING([--without-gnutls],
		[do not use gnutls])],
	[],
	[with_gnutls=check]
)
if test "x$with_gnutls" != "xno"; then
	PKG_CHECK_MODULES(GnuTLS, [gnutls >= 2.12.0],
		[HAVE_GNUTLS=1
		AC_DEFINE(HAVE_GNUTLS, 1, [Define to 1 if you have a GnuTLS version of 2.12 or above])],
		[if test "x$with_gnutls" = "xyes"; then
			AC_MSG_ERROR([--with-gnutls given but cannot find gnutls])
		else
			HAVE_GNUTLS=0
			AC_DEFINE(HAVE_GNUTLS, 0)
		fi]
	)
else
	HAVE_GNUTLS=0
	AC_DEFINE(HAVE_GNUTLS, 0)
fi
AM_CONDITIONAL([GNUTLS], [test "x$HAVE_GNUTLS" = "x1"])

AC_CHECK_HEADERS([winioctl.h], [], [],
[#include <io.h>
#include <windef.h>
#include <winbase.h>
])
HAVE_FSCTL_SET_ZERO_DATA=no
if test "x$ac_cv_header_winioctl_h" = "xyes"
then
        AC_CHECK_DECL(FSCTL_SET_ZERO_DATA, [HAVE_FSCTL_SET_ZERO_DATA=yes], [HAVE_FSCTL_SET_ZERO_DATA=no],
        [#include <windef.h>
        #include <winbase.h>
        #include <winioctl.h>
        ])
fi
if test "x$HAVE_FSCTL_SET_ZERO_DATA" = "xyes"
then
        AC_DEFINE(HAVE_FSCTL_SET_ZERO_DATA, 1, [Define to 1 if you have FSCTL_SET_ZERO_DATA])
else
        AC_DEFINE(HAVE_FSCTL_SET_ZERO_DATA, 0, [Define to 1 if you have FSCTL_SET_ZERO_DATA])
fi

AC_CHECK_FUNC([sync_file_range],
	[AC_DEFINE([HAVE_SYNC_FILE_RANGE], [sync_file_range(2) is not supported], [sync_file_range(2) is supported])],
        [])
AC_FUNC_FORK
AC_MSG_CHECKING(whether client should be built)
AS_CASE([$host_os],
  [linux*], [NBD_CLIENT_NAME="nbd-client"; AC_MSG_RESULT(yes)],
  [NBD_CLIENT_NAME=""; AC_MSG_RESULT(no)]
)
AC_MSG_CHECKING(whether to expect tlshuge test to fail)
AS_CASE([$host_os],
  [darwin*], [RUN_XFAIL=tlshuge; AC_MSG_RESULT(yes)],
  [RUN_XFAIL=""; AC_MSG_RESULT(no)]
)
AC_SUBST([RUN_XFAIL])
AM_CONDITIONAL(CLIENT, [test ! -z "$NBD_CLIENT_NAME"])
AC_SEARCH_LIBS(bind, socket,, AC_MSG_ERROR([Could not find an implementation of the bind() system call]))
AC_SEARCH_LIBS(inet_ntoa, nsl,, AC_MSG_ERROR([Could not find an implementation of the inet_ntoa() system call]))
AC_SEARCH_LIBS(daemon, resolv,, AC_MSG_ERROR([Could not find an implementation of the daemon() system call]))
AC_CHECK_HEADERS([sys/mount.h],,,
[[#include <sys/param.h>
]])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h sys/ioctl.h sys/socket.h syslog.h linux/types.h sys/dirent.h sys/uio.h])
PKG_CHECK_MODULES(GLIB, [glib-2.0 >= 2.32.0 gthread-2.0 >= 2.32.0], [HAVE_GLIB=yes], AC_MSG_ERROR([Missing glib]))
PKG_CHECK_MODULES(SW, [socket_wrapper], [HAVE_SW=yes], [HAVE_SW=no])
PKG_CHECK_MODULES(NW, [nss_wrapper], [HAVE_NW=yes], [HAVE_NW=no])
AM_CONDITIONAL(CWRAP, test "$HAVE_SW" = "yes" -a "$HAVE_NW" = "yes")

my_save_cflags="$CFLAGS"
my_save_libs="$LIBS"
CFLAGS="-Wdeprecated-declarations -Werror $GLIB_CFLAGS"
LIBS="$GLIB_LIBS"
dnl g_memdup2 added in glib-2.68
AC_CHECK_FUNCS([g_memdup2])
CFLAGS="$my_save_cflags"
LIBS="$my_save_libs"

AC_MSG_CHECKING([whether _BSD_SOURCE needs to be defined for DT_* macros])
AC_PREPROC_IFELSE(
	[AC_LANG_PROGRAM([[#include <dirent.h>]],
			 [[#ifndef DT_UNKNOWN
#error nope
#endif]])],
	[AC_MSG_RESULT([no]); NEED_BSD_SOURCE=0],
	[AC_MSG_RESULT([yes]); NEED_BSD_SOURCE=1])
AC_DEFINE([NEED_BSD_SOURCE], $NEED_BSD_SOURCE, [Define to 1 if _BSD_SOURCE needs to be defined before certain inclusions])

AC_ARG_WITH([libnl],
	[AS_HELP_STRING([--without-libnl],
		[do not use libnl])],
	[],
	[with_libnl=check]
)
if test "x$with_libnl" != "xno"; then
	PKG_CHECK_MODULES(LIBNL3, libnl-genl-3.0 >= 3.1,
		[HAVE_NETLINK=1
		AC_DEFINE(HAVE_NETLINK, 1, [Define to 1 if we have netlink support])
		CFLAGS="$CFLAGS $LIBNL3_CFLAGS"
		LIBS="$LIBS $LIBNL3_LIBS"],
		[if test "x$with_libnl" = "xyes"; then
			AC_MSG_ERROR([--with-libnl given but cannot find libnl])
		else
			HAVE_NETLINK=0
			AC_DEFINE(HAVE_NETLINK, 0)
		fi]
	)
else
	HAVE_NETLINK=0
	AC_DEFINE(HAVE_NETLINK, 0, [Define to 1 if we have netlink support])
fi

AC_ARG_ENABLE([manpages],
	AS_HELP_STRING([--disable-manpages], [Do not install man pages]))
AM_CONDITIONAL(MANPAGES, test "x$enable_manpages" != "xno")
AS_IF([test "x$enable_manpages" != "xno"], [
	AC_SUBST([MAN_CONFIG_FILES],["\
		man/nbd-client.8.sh \
		man/nbd-server.5.sh \
		man/nbd-server.1.sh \
		man/nbd-trdump.1.sh \
		man/nbd-trplay.1.sh \
		man/nbdtab.5.sh \
		"])
	])

AC_HEADER_SYS_WAIT
AC_TYPE_OFF_T
AC_TYPE_PID_T
AM_CPPFLAGS=$AM_CPPFLAGS" -DSYSCONFDIR='\"$sysconfdir\"'"
AC_SUBST(AM_CPPFLAGS)
AM_CONDITIONAL(GZNBD, [test "x$ENABLE_GZNBD" = "xyes"])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_LINKS([tests/run/buffer.c:buffer.c
		 tests/run/crypto-gnutls.c:crypto-gnutls.c
		 tests/run/cliserv.c:cliserv.c])
AC_CONFIG_FILES([Makefile
		 doc/Doxyfile
		 doc/Makefile
		 man/Makefile
		 gznbd/Makefile
		 tests/Makefile
		 tests/code/Makefile
		 tests/run/Makefile
		 tests/parse/Makefile
                 man/nbd-client.8.sh
                 man/nbd-server.5.sh
                 man/nbd-server.1.sh
                 man/nbd-trdump.1.sh
                 man/nbd-trplay.1.sh
                 man/nbdtab.5.sh
		 systemd/Makefile
		 systemd/nbd@.service.sh
		])
AC_OUTPUT

