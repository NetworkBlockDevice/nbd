bin_PROGRAMS = nbd-server
EXTRA_PROGRAMS = nbd-client
nbd_client_SOURCES = nbd-client.c cliserv.h
nbd_server_SOURCES = nbd-server.c cliserv.h
nbd_server_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_server_LDADD = @GLIB_LIBS@
man1_MANS = nbd-server.1
man8_MANS = nbd-client.8
EXTRA_DIST = nbd-client.8.sgml nbd-server.1.sgml gznbd winnbd
DISTCLEANFILES = nbd-client.8 nbd-server.1
nbd-server.1: nbd-server.1.sgml
	docbook-to-man nbd-server.1.sgml > nbd-server.1
nbd-client.8: nbd-client.8.sgml
	docbook-to-man nbd-client.8.sgml > nbd-client.8
dist-hook:
	rm -Rf `find $(distdir) -name 'CVS' -type d -print`
