#if SYSTEMD
#systemdunitdir = $(DESTDIR)/$(SYSTEMDLOC)
#systemdunit_DATA = nbd@.service
#endif

nbd@.service: nbd@.service.sh
	sh nbd@.service.sh > nbd@.service

nbd@.service.sh.in: nbd@.service.tmpl ../man/sh.tmpl
	cat ../man/sh.tmpl nbd@.service.tmpl > nbd@.service.sh.in
	echo EOF >> nbd@.service.sh.in
