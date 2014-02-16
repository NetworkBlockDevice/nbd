# nbdkit
# Copyright (C) 2013-2014 Red Hat Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# * Neither the name of Red Hat nor the names of its contributors may be
# used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY RED HAT AND CONTRIBUTORS ''AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL RED HAT OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

AC_INIT([nbdkit], [1.1.6])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

dnl NB: Do not [quote] this parameter.
AM_INIT_AUTOMAKE(foreign)
LT_INIT

dnl Check for basic C environment.
AC_PROG_CC_STDC
AC_PROG_INSTALL
AC_PROG_CPP

AC_C_PROTOTYPES
test "x$U" != "x" && AC_MSG_ERROR([Compiler not ANSI compliant])

AM_PROG_CC_C_O

AC_ARG_ENABLE([gcc-warnings],
    [AS_HELP_STRING([--enable-gcc-warnings],
                    [turn on lots of GCC warnings (for developers)])],
     [case $enableval in
      yes|no) ;;
      *)      AC_MSG_ERROR([bad value $enableval for gcc-warnings option]) ;;
      esac
      gcc_warnings=$enableval],
      [gcc_warnings=no]
)
if test "x$gcc_warnings" = "xyes"; then
    WARNINGS_CFLAGS="-Wall -Werror"
    AC_SUBST([WARNINGS_CFLAGS])
fi

dnl Check if libc has program_invocation_short_name.
AC_CHECK_DECLS([program_invocation_short_name], [], [], [#include <errno.h>])

dnl Check if __attribute__((cleanup(...))) works.
dnl XXX It would be nice to use AC_COMPILE_IFELSE here, but gcc just
dnl emits a warning for attributes that it doesn't understand.
AC_MSG_CHECKING([if __attribute__((cleanup(...))) works with this compiler])
AC_RUN_IFELSE([
AC_LANG_SOURCE([[
#include <stdio.h>
#include <stdlib.h>

void
freep (void *ptr)
{
  exit (EXIT_SUCCESS);
}

void
test (void)
{
  __attribute__((cleanup(freep))) char *ptr = malloc (100);
}

int
main (int argc, char *argv[])
{
  test ();
  exit (EXIT_FAILURE);
}
]])
    ],[
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_ATTRIBUTE_CLEANUP],[1],[Define to 1 if '__attribute__((cleanup(...)))' works with this compiler.])
    ],[
    AC_MSG_WARN(
['__attribute__((cleanup(...)))' does not work.

You may not be using a sufficiently recent version of GCC or CLANG, or
you may be using a C compiler which does not support this attribute,
or the configure test may be wrong.

The code will still compile, but is likely to leak memory and other
resources when it runs.])])

dnl Check for Perl POD.
AC_CHECK_PROG([POD2MAN], [pod2man], [pod2man], [no])
AM_CONDITIONAL([HAVE_POD2MAN], [test "x$POD2MAN" != "xno"])

dnl Check for Perl, for embedding in the perl plugin.
AC_CHECK_PROG([PERL],[perl],[perl],[no])
AC_ARG_ENABLE([perl],
    AS_HELP_STRING([--disable-perl], [disable Perl embed plugin]),
    [],
    [enable_perl=yes])
AS_IF([test "x$PERL" != "xno" && test "x$enable_perl" != "xno"],[
    dnl Check for Perl archlib.
    AC_MSG_CHECKING([for Perl embed archlib])
    PERL_ARCHLIB="$($PERL -MConfig -e 'print $Config{archlib}')"
    AS_IF([ test -n "$PERL_ARCHLIB" ],[
        AC_MSG_RESULT([$PERL_ARCHLIB])
    ],[
        AC_MSG_NOTICE([Perl embed module disabled])
        enable_perl=no
    ])

    dnl Check for Perl CFLAGS.
    AC_MSG_CHECKING([for Perl embed CFLAGS])
    PERL_CFLAGS="$($PERL -MExtUtils::Embed -e 'ccflags')"
    AS_IF([ test -n "$PERL_CFLAGS" ],[
        AC_MSG_RESULT([$PERL_CFLAGS])
    ],[
        AC_MSG_NOTICE([Perl embed module disabled])
        enable_perl=no
    ])

    dnl Check for Perl LDOPTS.
    AC_MSG_CHECKING([for Perl embed LDOPTS])
    PERL_LDOPTS="$($PERL -MExtUtils::Embed -e 'ldopts')"

    dnl XXX Could check these actually work.
])
AM_CONDITIONAL([HAVE_PERL],[test "x$enable_perl" != "xno" && test "x$PERL" != "xno"])
AC_SUBST([PERL_ARCHLIB])
AC_SUBST([PERL_CFLAGS])
AC_SUBST([PERL_LDOPTS])

dnl Check for Python, for embedding in the python plugin.
AC_CHECK_PROG([PYTHON],[python],[python],[no])
AC_ARG_ENABLE([python],
    AS_HELP_STRING([--disable-python], [disable Python embed plugin]),
    [],
    [enable_python=yes])
AS_IF([test "x$PYTHON" != "xno" && test "x$enable_python" != "xno"],[
    AC_MSG_CHECKING([version of $PYTHON])
    PYTHON_VERSION_MAJOR=`$PYTHON -c "import sys; print (sys.version_info@<:@0@:>@)"`
    PYTHON_VERSION_MINOR=`$PYTHON -c "import sys; print (sys.version_info@<:@1@:>@)"`
    PYTHON_VERSION="$PYTHON_VERSION_MAJOR.$PYTHON_VERSION_MINOR"
    AS_IF([test -n "$PYTHON_VERSION"],[
        AC_MSG_RESULT([$PYTHON_VERSION])
    ],[
        AC_MSG_NOTICE([Python embed module disabled])
        enable_python=no
    ])

    dnl Check for Python CFLAGS, libraries.
    dnl On Debian: python-X.Y.pc
    PKG_CHECK_MODULES([PYTHON], [python-"$PYTHON_VERSION"], [
        AC_SUBST([PYTHON_CFLAGS])
        AC_SUBST([PYTHON_LIBS])
        AC_SUBST([PYTHON_VERSION])
        AC_DEFINE([HAVE_PYTHON],[1],[Python library found at compile time])
    ],[
        dnl On Fedora: python.pc
        PKG_CHECK_MODULES([PYTHON], [python], [
            AC_SUBST([PYTHON_CFLAGS])
            AC_SUBST([PYTHON_LIBS])
            AC_SUBST([PYTHON_VERSION])
            AC_DEFINE([HAVE_PYTHON],[1],[Python library found at compile time])
        ],[
            AC_MSG_WARN([python $PYTHON_VERSION not found])
            enable_python=no
        ])
    ])

    dnl XXX Could check these actually work.
])
AM_CONDITIONAL([HAVE_PYTHON],[test "x$enable_python" != "xno" && test "x$PYTHON" != "xno"])
AC_SUBST([PYTHON_CFLAGS])
AC_SUBST([PYTHON_LIBS])
AC_SUBST([PYTHON_LDFLAGS])

dnl Check for libvirt (only if you want to compile the libvirt plugin).
AC_ARG_WITH([libvirt],[
    AS_HELP_STRING([--without-libvirt],
                   [disable libvirt plugin @<:@default=check@:>@])],
    [],
    [with_libvirt=check])
AS_IF([test "$with_libvirt" != "no"],[
    PKG_CHECK_MODULES([LIBVIRT], [libvirt],[
        AC_SUBST([LIBVIRT_CFLAGS])
        AC_SUBST([LIBVIRT_LIBS])
        AC_DEFINE([HAVE_LIBVIRT],[1],[libvirt found at compile time.])
    ],
    [AC_MSG_WARN([libvirt not found, libvirt plugin will be disabled])])
])
AM_CONDITIONAL([HAVE_LIBVIRT],[test "x$LIBVIRT_LIBS" != "x"])

dnl Check for zlib (only if you want to compile the gzip plugin).
AC_ARG_WITH([zlib],[
    AS_HELP_STRING([--without-zlib],
                   [disable gzip plugin @<:@default=check@:>@])],
    [],
    [with_zlib=check])
AS_IF([test "$with_zlib" != "no"],[
    PKG_CHECK_MODULES([ZLIB], [zlib],[
        AC_SUBST([ZLIB_CFLAGS])
        AC_SUBST([ZLIB_LIBS])
        AC_DEFINE([HAVE_ZLIB],[1],[zlib found at compile time.])
    ],
    [AC_MSG_WARN([zlib not found, gzip plugin will be disabled])])
])
AM_CONDITIONAL([HAVE_ZLIB],[test "x$ZLIB_LIBS" != "x"])

dnl Check for liblzma (only if you want to compile the xz plugin).
AC_ARG_WITH([liblzma],[
    AS_HELP_STRING([--without-liblzma],
                   [disable xz plugin @<:@default=check@:>@])],
    [],
    [with_liblzma=check])
AS_IF([test "$with_liblzma" != "no"],[
    PKG_CHECK_MODULES([LIBLZMA], [liblzma],[
        AC_SUBST([LIBLZMA_CFLAGS])
        AC_SUBST([LIBLZMA_LIBS])
        AC_DEFINE([HAVE_LIBLZMA],[1],[liblzma found at compile time.])
    ],
    [AC_MSG_WARN([liblzma not found, xz plugin will be disabled])])
])
AM_CONDITIONAL([HAVE_LIBLZMA],[test "x$LIBLZMA_LIBS" != "x"])

dnl Check for libguestfs (only for the guestfs plugin and the test suite).
AC_ARG_WITH([libguestfs],[
    AS_HELP_STRING([--without-libguestfs],
                   [disable guestfs plugin and tests @<:@default=check@:>@])],
    [],
    [with_libguestfs=check])
AS_IF([test "$with_libguestfs" != "no"],[
    PKG_CHECK_MODULES([LIBGUESTFS], [libguestfs],[
        AC_SUBST([LIBGUESTFS_CFLAGS])
        AC_SUBST([LIBGUESTFS_LIBS])
        AC_DEFINE([HAVE_LIBGUESTFS],[1],[libguestfs found at compile time.])
    ],
    [AC_MSG_WARN([libguestfs not found, guestfs plugin and tests will be disabled])])
])
AM_CONDITIONAL([HAVE_LIBGUESTFS],[test "x$LIBGUESTFS_LIBS" != "x"])

dnl Check for guestfish (only needed for some of the tests).
AC_CHECK_PROG([GUESTFISH], [guestfish], [guestfish], [no])
AM_CONDITIONAL([HAVE_GUESTFISH], [test "x$GUESTFISH" != "xno"])

dnl See plugins/vddk/README.VDDK.
AC_CHECK_SIZEOF([size_t])
AS_IF([test "x$ac_cv_sizeof_size_t" = "x4"],[bits=32],[bits=64])
AC_ARG_WITH([vddk],[
    AS_HELP_STRING([--with-vddk],
                   [enable VMware VDDK plugin @<:@default=no@:>@])],
    [],
    [with_vddk=no])
AS_IF([test "$with_vddk" = "yes"],[
    VDDK_CFLAGS=
    VDDK_LIBS="-lvixDiskLib"
    # XXX Warning: stupid VMware API.
    VDDK_LIBDIR="$libdir/vmware-vix-disklib"
    ],[
    AS_IF([test "$with_vddk" != "no"], [
        VDDK_CFLAGS="-I$with_vddk/include"
        VDDK_LIBS="-L$with_vddk/lib$bits -lvixDiskLib"
        VDDK_LIBDIR="$with_vddk"
        ],
        [AC_MSG_NOTICE([VDDK plugin disabled])
    ])
])
AC_SUBST([VDDK_CFLAGS])
AC_SUBST([VDDK_LIBS])
AC_DEFINE_UNQUOTED([VDDK_LIBDIR],["$VDDK_LIBDIR"],[VDDK 'libDir'.])
AM_CONDITIONAL([HAVE_VDDK],[test "x$VDDK_LIBS" != "x"])

dnl Produce output files.
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile
                 docs/Makefile
                 include/Makefile
                 plugins/Makefile
                 plugins/example1/Makefile
                 plugins/example2/Makefile
                 plugins/example3/Makefile
                 plugins/file/Makefile
                 plugins/guestfs/Makefile
                 plugins/gzip/Makefile
                 plugins/libvirt/Makefile
                 plugins/perl/Makefile
                 plugins/python/Makefile
                 plugins/vddk/Makefile
                 plugins/xz/Makefile
                 src/Makefile
                 tests/Makefile])

AC_OUTPUT
