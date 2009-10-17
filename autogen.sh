#!/bin/sh
set -ex
srcdir=. make -f Makefile.am nbd-server.1.in nbd-server.5.in
exec autoreconf -f -i
