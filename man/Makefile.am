if MANPAGES
man_MANS = nbd-server.1 nbd-server.5 nbd-client.8 nbd-trdump.1 nbd-trplay.1 nbdtab.5
CLEANFILES = manpage.links manpage.refs
DISTCLEANFILES = nbd-server.1 nbd-server.1.sgml nbd-client.8 nbd-client.8.sgml nbd-server.5 nbd-server.5.sgml nbd-trdump.1 nbd-trdump.1.sgml nbd-trplay.1 nbd-trplay.1.sgml nbdtab.5 nbdtab.5.sgml
EXTRA_DIST = nbd-server.1.sgml.in nbd-client.8.sgml.in nbd-server.5.sgml.in nbd-trdump.1.sgml.in nbd-trplay.1.sgml.in nbdtab.5.sgml.in

%: %.sgml
	docbook2man $<
endif
