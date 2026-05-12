#!/bin/sh
set -ex
make -C systemd -f Makefile.am nbd@.service.sh.in nbd-server.service.sh.in
exec autoreconf -f -i
