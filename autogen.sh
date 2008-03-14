#!/bin/sh
set -ex
make -f Makefile.am nbd-server.1.in nbd-server.5.in
exec autoreconf -f -i
