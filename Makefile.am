SUBDIRS = man
bin_PROGRAMS = nbd-server
sbin_PROGRAMS = @NBD_CLIENT_NAME@
EXTRA_PROGRAMS = nbd-client knbd-client
TESTS_ENVIRONMENT=$(srcdir)/simple_test
TESTS = cmd cfg1 cfgmulti cfgnew cfgsize write
check_PROGRAMS = nbd-tester-client
knbd_client_SOURCES = nbd-client.c cliserv.h
nbd_client_SOURCES = nbd-client.c cliserv.h
nbd_server_SOURCES = nbd-server.c cliserv.h lfs.h nbd.h
nbd_tester_client_SOURCES = nbd-tester-client.c cliserv.h
nbd_server_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_tester_client_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_server_LDADD = @GLIB_LIBS@
nbd_tester_client_LDADD = @GLIB_LIBS@
EXTRA_DIST = gznbd simple_test
dist-hook:
	rm -Rf `find $(distdir) -name '.svn' -type d -print`
cmd:
cfg1:
cfgmulti:
cfgnew:
cfgsize:
write:
