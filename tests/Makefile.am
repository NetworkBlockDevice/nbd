# nbdkit
# Copyright (C) 2013 Red Hat Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# * Neither the name of Red Hat nor the names of its contributors may be
# used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY RED HAT AND CONTRIBUTORS ''AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL RED HAT OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

# Tests need libguestfs, since that is a convenient way to drive qemu.
if HAVE_LIBGUESTFS

TESTS_ENVIRONMENT = LIBGUESTFS_ATTACH_METHOD=appliance

# Common test library.
noinst_LTLIBRARIES = libtest.la
libtest_la_SOURCES = test.c test.h
libtest_la_CFLAGS = $(WARNINGS_CFLAGS)

# Basic connection test.
check_PROGRAMS = test-connect
TESTS = test-connect
noinst_DATA =

test_connect_SOURCES = test-connect.c test.h
test_connect_CFLAGS = $(WARNINGS_CFLAGS) $(LIBGUESTFS_CFLAGS)
test_connect_LDADD = libtest.la $(LIBGUESTFS_LIBS)

# gzip plugin test.
if HAVE_ZLIB
if HAVE_GUESTFISH

check_PROGRAMS += test-gzip
TESTS += test-gzip
noinst_DATA += disk.gz

test_gzip_SOURCES = test-gzip.c test.h
test_gzip_CFLAGS = $(WARNINGS_CFLAGS) $(LIBGUESTFS_CFLAGS)
test_gzip_LDADD = libtest.la $(LIBGUESTFS_LIBS)

disk.gz:
	rm -f $@ test1.img disk
	guestfish -N fs -m /dev/sda1 write /hello.txt "hello,world"
	mv test1.img disk
	gzip -9 disk

endif
endif

endif

CLEANFILES = *~
