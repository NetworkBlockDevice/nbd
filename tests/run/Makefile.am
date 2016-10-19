TESTS_ENVIRONMENT=$(srcdir)/simple_test
TESTS = cfg1 cfgmulti cfgnew cfgsize write flush integrity dirconfig list rowrite tree rotree unix integrityhuge
check_PROGRAMS = nbd-tester-client
## Various Automake versions don't play nice with files in parent
## directories, so instead work with a local copy
cliserv.c:
	rm -f cliserv.c
	ln -s $(top_srcdir)/cliserv.c cliserv.c
nbd_tester_client_SOURCES = nbd-tester-client.c cliserv.c
nbd_tester_client_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_tester_client_CPPFLAGS = -I$(top_srcdir)
nbd_tester_client_LDADD = @GLIB_LIBS@
EXTRA_DIST = integrity-test.tr integrityhuge-test.tr simple_test
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
rowrite:
tree:
rotree:
unix:
