bin_PROGRAMS = nbd-server
EXTRA_PROGRAMS = nbd-client
nbd_client_SOURCES = nbd-client.c cliserv.h
nbd_server_SOURCES = nbd-server.c cliserv.h
nbd_server_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_server_LDADD = @GLIB_LIBS@
man1_MANS = nbd-server.1
EXTRA_MANS = nbd-client.8
EXTRA_DIST = nbd-client.8.sgml nbd-server.1.sgml gznbd winnbd lfs.h nbd-client.8 nbd-server.1
MAINTAINERCLEANFILES = nbd-client.8 nbd-server.1
nbd-server.1: nbd-server.1.sgml
	docbook2man nbd-server.1.sgml
	mv NBD-SERVER.1 nbd-server.1
nbd-client.8: nbd-client.8.sgml
	docbook2man nbd-client.8.sgml
	mv NBD-CLIENT.8 nbd-client.8
dist-hook:
	rm -Rf `find $(distdir) -name 'CVS' -type d -print`
