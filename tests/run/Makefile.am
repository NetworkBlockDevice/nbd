TESTS_ENVIRONMENT=$(srcdir)/simple_test
TESTS = cmd cfg1 cfgmulti cfgnew cfgsize write flush integrity dirconfig list # integrityhuge
check_PROGRAMS = nbd-tester-client
nbd_tester_client_SOURCES = nbd-tester-client.c $(top_srcdir)/cliserv.h $(top_srcdir)/netdb-compat.h
nbd_tester_client_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_tester_client_CPPFLAGS = -I$(top_srcdir)
nbd_tester_client_LDADD = @GLIB_LIBS@
EXTRA_DIST = integrity-test.tr integrityhuge-test.tr simple_test
cmd:
cfg1:
cfgmulti:
cfgnew:
cfgsize:
write:
flush:
integrity:
integrityhuge:
dirconfig:
list:
