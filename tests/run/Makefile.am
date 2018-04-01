if GNUTLS
TLSSRC = $(top_srcdir)/crypto-gnutls.c $(top_srcdir)/crypto-gnutls.h $(top_srcdir)/buffer.c $(top_srcdir)/buffer.h
else
TLSSRC =
endif
TESTS_ENVIRONMENT=$(srcdir)/simple_test
TESTS = cfg1 cfgmulti cfgnew cfgsize write flush integrity dirconfig list inetd \
	rowrite tree rotree unix integrityhuge handshake tls tlshuge tlswrongcert
check_PROGRAMS = nbd-tester-client
## Various Automake versions don't play nice with files in parent
## directories, so instead work with a local copy
cliserv.c:
	rm -f cliserv.c
	ln -s $(top_srcdir)/cliserv.c cliserv.c
buffer.c:
	rm -f buffer.c
	ln -s $(top_srcdir)/buffer.c buffer.c
crypto-gnutls.c:
	rm -f crypto-gnutls.c
	ln -s $(top_srcdir)/crypto-gnutls.c crypto-gnutls.c
nbd_tester_client_SOURCES = nbd-tester-client.c
nodist_nbd_tester_client_SOURCES = cliserv.c
nbd_tester_client_CFLAGS = @CFLAGS@ @GLIB_CFLAGS@
nbd_tester_client_CPPFLAGS = -I$(top_srcdir)
nbd_tester_client_LDADD = @GLIB_LIBS@
if GNUTLS
nodist_nbd_tester_client_SOURCES += buffer.c crypto-gnutls.c
nbd_tester_client_CFLAGS += @GnuTLS_CFLAGS@
nbd_tester_client_LDADD += @GnuTLS_LIBS@
endif
CLEANFILES = buffer.c crypto-gnutls.c cliserv.c
EXTRA_DIST = integrity-test.tr integrityhuge-test.tr simple_test certs/client-key.pem certs/client-cert.pem certs/server-cert.pem certs/ca-cert.pem certs/ca.info certs/client.info certs/server-key.pem certs/ca-key.pem certs/server.info certs/README.md certs/selfsigned-cert.pem certs/selfsigned-key.pem
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
inetd:
handshake:
tls:
tlshuge:
tlswrongcert:
