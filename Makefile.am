ACLOCAL_AMFLAGS = -I support
SUBDIRS = . man doc tests systemd gznbd
bin_PROGRAMS = nbd-server nbd-trdump nbd-trplay
EXTRA_PROGRAMS = nbd-client make-integrityhuge
noinst_LTLIBRARIES = libnbdsrv.la libcliserv.la libnbdclt.la
libcliserv_la_SOURCES = cliserv.h cliserv.c
libcliserv_la_CFLAGS = @CFLAGS@
client_srcs = nbd-client.c cliserv.h nbd-netlink.h
nbd_server_SOURCES = nbd-server.c cliserv.h lfs.h nbd.h nbdsrv.h backend.h \
	netdb-compat.h nbd-helper.h
nbd_trdump_SOURCES = nbd-trdump.c cliserv.h nbd.h
nbd_trplay_SOURCES = nbd-trplay.c cliserv.h nbd.h
client_flags = @CFLAGS@
nbd_server_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_trdump_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_trplay_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
libnbdsrv_la_SOURCES = nbdsrv.c nbdsrv.h treefiles.c treefiles.h
libnbdsrv_la_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
client_libs = libcliserv.la libnbdclt.la
nbd_server_LDADD = @GLIB_LIBS@ libnbdsrv.la libcliserv.la
nbd_trdump_LDADD = libcliserv.la
nbd_trplay_LDADD = libcliserv.la
make_integrityhuge_SOURCES = make-integrityhuge.c cliserv.h nbd.h nbd-debug.h
EXTRA_DIST = maketr CodingStyle autogen.sh README.md support/genver.sh
if GNUTLS
nbd_server_CFLAGS += @GnuTLS_CFLAGS@
nbd_server_LDADD += @GnuTLS_LIBS@
endif
if CLIENT
sbin_PROGRAMS = nbd-client
if GNUTLS
sbin_PROGRAMS += min-nbd-client
min_nbd_client_SOURCES = $(client_srcs)
min_nbd_client_CFLAGS = $(client_flags) -DNOTLS -DPROG_NAME='"min-nbd-client"'
min_nbd_client_LDADD = $(client_libs)
nbd_client_SOURCES = $(client_srcs) crypto-gnutls.c crypto-gnutls.h buffer.c buffer.h
nbd_client_CFLAGS = $(client_flags) @GnuTLS_CFLAGS@ -DPROG_NAME='"nbd-client"'
nbd_client_LDADD = $(client_libs) @GnuTLS_LIBS@
else
nbd_client_SOURCES = $(client_srcs)
nbd_client_CFLAGS = $(client_flags) -DNOTLS -DPROG_NAME='"nbd-client"'
nbd_client_LDADD = $(client_libs)
endif
endif

libnbdclt_la_SOURCES = nbdtab_parser.tab.h nbdtab_parser.y nbdtab_lexer.l nbdclt.h
BUILT_SOURCES = nbdtab_parser.tab.h

nbd-client.c: $(builddir)/nbdtab_parser.tab.h
nbdtab_parser.tab.h: $(srcdir)/nbdtab_parser.y
	bison -d $^ > $@

AM_DISTCHECK_CONFIGURE_FLAGS=--enable-syslog
