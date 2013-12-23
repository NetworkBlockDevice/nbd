TESTS = clientacl dup append
check_PROGRAMS = clientacl dup append
EXTRA_DIST = macro.h

AM_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
AM_CPPFLAGS = -I$(top_srcdir)

clientacl_SOURCES = clientacl.c
clientacl_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@

dup_SOURCES = dup.c
dup_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@

append_SOURCES = append.c
append_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@
