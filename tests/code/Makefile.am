TESTS = clientacl dup mask size
check_PROGRAMS = clientacl dup mask size
EXTRA_DIST = macro.h

AM_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
AM_CPPFLAGS = -I$(top_srcdir)

clientacl_SOURCES = clientacl.c
clientacl_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@

dup_SOURCES = dup.c
dup_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@

append_SOURCES = append.c
append_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@

mask_SOURCES = mask.c
mask_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@

size_SOURCES = size.c
size_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@
