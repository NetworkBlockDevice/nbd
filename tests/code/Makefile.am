TESTS = clientacl dup mask size trim args_test
check_PROGRAMS = clientacl dup mask size trim args_test
EXTRA_DIST = macro.h

AM_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
AM_CPPFLAGS = -I$(top_srcdir)

clientacl_SOURCES = clientacl.c punchdummy.c
clientacl_LDADD = $(top_builddir)/libnbdsrv.la $(top_builddir)/libcliserv.la @GLIB_LIBS@

dup_SOURCES = dup.c punchdummy.c
dup_LDADD = $(top_builddir)/libnbdsrv.la $(top_builddir)/libcliserv.la @GLIB_LIBS@

mask_SOURCES = mask.c punchdummy.c
mask_LDADD = $(top_builddir)/libnbdsrv.la $(top_builddir)/libcliserv.la @GLIB_LIBS@

size_SOURCES = size.c punchdummy.c
size_LDADD = $(top_builddir)/libnbdsrv.la $(top_builddir)/libcliserv.la @GLIB_LIBS@

trim_SOURCES = trim.c
trim_LDADD = $(top_builddir)/libnbdsrv.la $(top_builddir)/libcliserv.la @GLIB_LIBS@

args_test_SOURCES = args_test.c ../../args.c
args_test_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/tests/code
args_test_LDADD = @GLIB_LIBS@
