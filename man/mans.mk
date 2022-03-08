nbd-server.1: nbd-server.1.sh
	sh nbd-server.1.sh > nbd-server.1
nbd-server.5: nbd-server.5.sh
	sh nbd-server.5.sh > nbd-server.5
nbd-client.8: nbd-client.8.sh
	sh nbd-client.8.sh > nbd-client.8
nbd-trdump.1: nbd-trdump.1.sh
	sh nbd-trdump.1.sh > nbd-trdump.1
nbd-trplay.1: nbd-trplay.1.sh
	sh nbd-trplay.1.sh > nbd-trplay.1
nbdtab.5: nbdtab.5.sh
	sh nbdtab.5.sh > nbdtab.5
nbd-server.1.sh.in: nbd-server.1.in.sgml sh.tmpl
	LC_ALL=C docbook2man nbd-server.1.in.sgml
	cat sh.tmpl > nbd-server.1.sh.in
	cat NBD-SERVER.1 >> nbd-server.1.sh.in
	echo "EOF" >> nbd-server.1.sh.in
	rm NBD-SERVER.1
nbd-client.8.sh.in: nbd-client.8.in.sgml sh.tmpl
	LC_ALL=C docbook2man nbd-client.8.in.sgml
	cat sh.tmpl > nbd-client.8.sh.in
	cat NBD-CLIENT.8 >> nbd-client.8.sh.in
	echo "EOF" >> nbd-client.8.sh.in
	rm NBD-CLIENT.8
nbd-server.5.sh.in: nbd-server.5.in.sgml sh.tmpl
	LC_ALL=C docbook2man nbd-server.5.in.sgml
	cat sh.tmpl > nbd-server.5.sh.in
	cat NBD-SERVER.5 >> nbd-server.5.sh.in
	echo "EOF" >> nbd-server.5.sh.in
	rm NBD-SERVER.5
nbd-trdump.1.sh.in: nbd-trdump.1.in.sgml sh.tmpl
	LC_ALL=C docbook2man nbd-trdump.1.in.sgml
	cat sh.tmpl > nbd-trdump.1.sh.in
	cat NBD-TRDUMP.1 >> nbd-trdump.1.sh.in
	echo "EOF" >> nbd-trdump.1.sh.in
	rm NBD-TRDUMP.1
nbd-trplay.1.sh.in: nbd-trplay.1.in.sgml sh.tmpl
	LC_ALL=C docbook2man nbd-trplay.1.in.sgml
	cat sh.tmpl > nbd-trplay.1.sh.in
	cat NBD-TRPLAY.1 >> nbd-trplay.1.sh.in
	echo "EOF" >> nbd-trplay.1.sh.in
	rm NBD-TRPLAY.1
nbdtab.5.sh.in: nbdtab.5.in.sgml sh.tmpl
	LC_ALL=C docbook2man nbdtab.5.in.sgml
	cat sh.tmpl > nbdtab.5.sh.in
	cat NBDTAB.5 >> nbdtab.5.sh.in
	echo "EOF" >> nbdtab.5.sh.in
	rm NBDTAB.5
