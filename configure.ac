dnl Configure script for NBD system
dnl (c) 1998 Martin Mares <mj@ucw.cz>, (c) 2000 Pavel Machek <pavel@ucw.cz>,
dnl (c) 2003-2004 Wouter Verhelst
AC_INIT([nbd],[2.7.2],[wouter@debian.org])
AM_INIT_AUTOMAKE()

AC_ARG_ENABLE(
  lfs, 
  AC_HELP_STRING([--enable-lfs],[Enable Large File Support]),
  [
     if test "x$enableval" = "xyes" ; then
        NBD_LFS=1
     else
        NBD_LFS=0
     fi
  ],
  [NBD_LFS=0]
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
   AC_HELP_STRING([--enable-syslog],[Enable Syslog logging]),
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
AC_MSG_CHECKING(whether warnings should be enabled)
if test -n "$GCC" ; then
  AC_MSG_RESULT(yes)
  #CFLAGS="$CFLAGS -Wall -W -Wno-parentheses -Wstrict-prototypes -Wno-unused"
else
  AC_MSG_RESULT(no)
fi
#AC_PROG_INSTALL
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
AC_MSG_CHECKING(whether there is a local nbd.h)
if test -f nbd.h; then
  AC_DEFINE(HAVE_LOCAL_NBD_H,1, [Define to 1 if you want to use a local nbd.h (not provided, must be supplied by you)])
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi
AC_CHECK_HEADERS([linux/nbd.h],,,
[[#define u32 unsigned int
#define u64 unsigned long int
]])
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h sys/ioctl.h sys/mount.h sys/socket.h syslog.h])
AC_HEADER_SYS_WAIT
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_SUBST(sbin_PROGRAMS)
AM_CONFIG_HEADER(config.h)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

