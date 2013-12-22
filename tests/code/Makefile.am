TESTS = clientacl dup
check_PROGRAMS = clientacl dup

AM_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
AM_CPPFLAGS = -I$(top_srcdir)

clientacl_SOURCES = clientacl.c
clientacl_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@

dup_SOURCES = dup.c
dup_LDADD = $(top_builddir)/libnbdsrv.la @GLIB_LIBS@
