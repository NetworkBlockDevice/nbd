#!/bin/sh
set -ex
if [ -z "$(type -p docbook2man)" ]; then
	if [ -z "$NO_MANPAGES" ]; then
		echo "E: docbook2man not found. Set NO_MANPAGES to a nonzero value to build without man pages"
		exit 1
	fi
	echo "W: docbook2man not found. You cannot distribute a tarball from this build, but we'll allow you to build without manpages."
	cd man
	touch nbd-server.1.sh.in nbd-server.5.sh.in nbd-client.8.sh.in nbd-trdump.1.sh.in nbd-trplay.1.sh.in nbdtab.5.sh.in
else
	make -C man -f mans.mk nbd-server.1.sh.in nbd-server.5.sh.in nbd-client.8.sh.in nbd-trdump.1.sh.in nbd-trplay.1.sh.in nbdtab.5.sh.in
fi
make -C systemd -f Makefile.am nbd@.service.sh.in
exec autoreconf -f -i
