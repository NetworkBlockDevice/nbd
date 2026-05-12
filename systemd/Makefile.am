#if SYSTEMD
#systemdunitdir = $(DESTDIR)/$(SYSTEMDLOC)
#systemdunit_DATA = nbd@.service
#endif

noinst_DATA = nbd@.service
DISTCLEANFILES = nbd@.service
EXTRA_DIST=nbd@.service.tmpl sh.tmpl

nbd@.service: nbd@.service.sh
	sh nbd@.service.sh > nbd@.service

nbd@.service.sh.in: nbd@.service.tmpl sh.tmpl
	cat sh.tmpl nbd@.service.tmpl > nbd@.service.sh.in
	echo EOF >> nbd@.service.sh.in
