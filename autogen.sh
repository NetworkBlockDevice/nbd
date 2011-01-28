#!/bin/sh
set -ex
make -C man -f Makefile.am infiles
exec autoreconf -f -i
