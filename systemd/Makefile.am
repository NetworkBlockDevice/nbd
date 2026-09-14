noinst_DATA = nbd@.service
DISTCLEANFILES = nbd@.service
EXTRA_DIST=nbd@.service.tmpl sh.tmpl nbd-server.service

nbd@.service: nbd@.service.sh
	sh nbd@.service.sh > nbd@.service
