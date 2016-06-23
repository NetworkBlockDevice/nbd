#!/bin/sh
set -ex
make -C man -f Makefile.am nbd-server.1.sh.in nbd-server.5.sh.in nbd-client.8.sh.in nbd-trdump.1.sh.in nbdtab.5.sh.in
make -C systemd -f Makefile.am nbd@.service.sh.in
exec autoreconf -f -i
