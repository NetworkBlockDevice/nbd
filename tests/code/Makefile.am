TESTS = clientacl dup mask size trim
check_PROGRAMS = clientacl dup mask size trim
EXTRA_DIST = macro.h

AM_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
AM_CPPFLAGS = -I$(top_srcdir)

clientacl_SOURCES = clientacl.c punchdummy.c
clientacl_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@

dup_SOURCES = dup.c punchdummy.c
dup_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@

append_SOURCES = append.c punchdummy.c
append_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@

mask_SOURCES = mask.c punchdummy.c
mask_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@

size_SOURCES = size.c punchdummy.c
size_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@

trim_SOURCES = trim.c
trim_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@
