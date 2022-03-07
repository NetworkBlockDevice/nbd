if GNUTLS
TLSSRC = $(top_srcdir)/crypto-gnutls.c $(top_srcdir)/crypto-gnutls.h $(top_srcdir)/buffer.c $(top_srcdir)/buffer.h
else
TLSSRC =
endif
if CWRAP
TESTS_ENVIRONMENT=$(srcdir)/cwrap_test
else
TESTS_ENVIRONMENT=$(srcdir)/simple_test
endif
TESTS = cfg1 cfgmulti cfgnew cfgsize write flush integrity dirconfig list inetd \
	rowrite tree rotree unix integrityhuge handshake tls tlswrongcert tlshuge
XFAIL_TESTS=@RUN_XFAIL@
check_PROGRAMS = nbd-tester-client
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
EXTRA_DIST = integrity-test.tr integrityhuge-test.tr simple_test cwrap_test certs/client-key.pem certs/client-cert.pem certs/server-cert.pem certs/ca-cert.pem certs/ca.info certs/client.info certs/server-key.pem certs/ca-key.pem certs/server.info certs/README.md certs/selfsigned-cert.pem certs/selfsigned-key.pem
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
