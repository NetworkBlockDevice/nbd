#if SYSTEMD
#systemdunitdir = $(DESTDIR)/$(SYSTEMDLOC)
#systemdunit_DATA = nbd@.service
#endif

noinst_DATA = nbd@.service nbd-server.service
DISTCLEANFILES = nbd@.service nbd-server.service
EXTRA_DIST=nbd@.service.tmpl nbd-server.service.tmpl

nbd@.service: nbd@.service.sh
	sh nbd@.service.sh > nbd@.service

nbd@.service.sh.in: nbd@.service.tmpl ../man/sh.tmpl
	cat ../man/sh.tmpl nbd@.service.tmpl > nbd@.service.sh.in
	echo EOF >> nbd@.service.sh.in

nbd-server.service.sh.in: nbd-server.service.tmpl ../man/sh.tmpl
	cat ../man/sh.tmpl nbd-server.service.tmpl >> nbd-server.service.sh.in
	echo EOF >> nbd-server.service.sh.in

nbd-server.service: nbd-server.service.sh
	sh nbd-server.service.sh > nbd-server.service
