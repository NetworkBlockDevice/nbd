man_MANS = nbd-server.1 nbd-server.5 nbd-client.8
CLEANFILES = manpage.links manpage.refs
MAINTAINERCLEANFILES = nbd-server.1 nbd-client.8 nbd-server.5
EXTRA_DIST = nbd-server.1.in.sgml nbd-client.8.in.sgml nbd-server.5.in.sgml

infiles: nbd-server.1.in nbd-client.8.in nbd-server.5.in

nbd-server.1.in: nbd-server.1.in.sgml
	LC_ALL=C docbook2man nbd-server.1.in.sgml
	mv NBD-SERVER.1 nbd-server.1.in
nbd-client.8.in: nbd-client.8.in.sgml
	LC_ALL=C docbook2man nbd-client.8.in.sgml
	mv NBD-CLIENT.8 nbd-client.8.in
nbd-server.5.in: nbd-server.5.in.sgml
	LC_ALL=C docbook2man nbd-server.5.in.sgml
	mv NBD-SERVER.5 nbd-server.5.in
