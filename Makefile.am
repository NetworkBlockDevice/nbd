bin_PROGRAMS = nbd-server
EXTRA_PROGRAMS = nbd-client knbd-client
TESTS_ENVIRONMENT=$(srcdir)/simple_test
TESTS = cmd cfg1 cfgmulti
check_PROGRAMS = nbd-tester-client
knbd_client_SOURCES = nbd-client.c cliserv.h
nbd_client_SOURCES = nbd-client.c cliserv.h
nbd_server_SOURCES = nbd-server.c cliserv.h lfs.h nbd-server.h
EXTRA_nbd_server_SOURCES = backend-read-write.c backend-sendfile-freebsd.c backend-sendfile-linux.c
nbd_tester_client_SOURCES = nbd-tester-client.c cliserv.h
nbd_server_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_tester_client_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_server_LDADD = @GLIB_LIBS@ $(BACKEND)
nbd_server_DEPENDENCIES = $(BACKEND)
nbd_tester_client_LDADD = @GLIB_LIBS@
man_MANS = nbd-server.1 nbd-server.5 nbd-client.8
EXTRA_DIST = nbd-client.8.sgml nbd-server.1.sgml nbd-server.5.sgml gznbd simple_test
MAINTAINERCLEANFILES = nbd-client.8 nbd-server.1 nbd-server.5
nbd-server.1.in: $(srcdir)/nbd-server.1.sgml
	LC_ALL=C docbook2man nbd-server.1.sgml
	mv NBD-SERVER.1 nbd-server.1.in
nbd-client.8.in: $(srcdir)/nbd-client.8.sgml
	LC_ALL=C docbook2man nbd-client.8.sgml
	mv NBD-CLIENT.8 nbd-client.8.in
nbd-server.5.in: $(srcdir)/nbd-server.5.sgml
	LC_ALL=C docbook2man nbd-server.5.sgml
	mv NBD-SERVER.5 nbd-server.5.in
dist-hook:
	rm -Rf `find $(distdir) -name '.svn' -type d -print`
cmd:
cfg1:
cfgmulti:
