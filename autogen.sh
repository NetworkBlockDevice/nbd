#!/bin/sh
set -ex
make -C man -f Makefile.am nbd-server.1.sh.in nbd-server.5.sh.in nbd-client.8.sh.in nbd-trdump.1.sh.in
exec autoreconf -f -i
