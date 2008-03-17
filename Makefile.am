bin_PROGRAMS = nbd-server
EXTRA_PROGRAMS = nbd-client knbd-client
TESTS = $(srcdir)/simple_test
check_PROGRAMS = nbd-tester-client
knbd_client_SOURCES = nbd-client.c cliserv.h
nbd_client_SOURCES = nbd-client.c cliserv.h
nbd_server_SOURCES = nbd-server.c cliserv.h
nbd_tester_client_SOURCES = nbd-tester-client.c cliserv.h
nbd_server_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_tester_client_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_server_LDADD = @GLIB_LIBS@
nbd_tester_client_LDADD = @GLIB_LIBS@
man_MANS = nbd-server.1 nbd-server.5 nbd-client.8
EXTRA_DIST = nbd-client.8.sgml nbd-server.1.sgml nbd-server.5.sgml gznbd winnbd lfs.h nbd-client.8 CodingStyle simple_test INSTALL
MAINTAINERCLEANFILES = nbd-client.8 nbd-server.1
nbd-server.1.in: nbd-server.1.sgml
	docbook2man nbd-server.1.sgml
	mv NBD-SERVER.1 nbd-server.1.in
nbd-client.8: nbd-client.8.sgml
	docbook2man nbd-client.8.sgml
	mv NBD-CLIENT.8 nbd-client.8
nbd-server.5.in: nbd-server.5.sgml
	docbook2man nbd-server.5.sgml
	mv NBD-SERVER.5 nbd-server.5.in
dist-hook:
	rm -Rf `find $(distdir) -name '.svn' -type d -print`
knbd_client-nbd-client.o: nbd-client.c
	$(KLCC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(knbd_client_CPPFLAGS) $(CPPFLAGS) $(knbd_client_CFLAGS) $(CFLAGS) -c -o knbd_client-nbd-client.o nbd-client.c
knbd-client$(EXEEXT): knbd_client-nbd-client.o $(knbd_client_DEPENDENCIES)
	@rm -f knbd-client$(EXEEXT)
	$(LINK) $(knbd_client_LDFLAGS) knbd_client-nbd-client.o $(knbd_client_LDADD) $(LIBS)
