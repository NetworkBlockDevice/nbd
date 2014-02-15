# nbdkit
# Copyright (C) 2013-2014 Red Hat Inc.
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

CLEANFILES = *~
MAINTAINERCLEANFILES =

EXTRA_DIST = test.pl test.py

# Tests need libguestfs, since that is a convenient way to drive qemu.
if HAVE_LIBGUESTFS

TESTS_ENVIRONMENT = LIBGUESTFS_ATTACH_METHOD=appliance

# Common test library.
check_LTLIBRARIES = libtest.la
libtest_la_SOURCES = test.c test.h
libtest_la_CFLAGS = $(WARNINGS_CFLAGS)

# Basic connection test.
check_PROGRAMS = test-connect
TESTS = test-connect
check_DATA =

test_connect_SOURCES = test-connect.c test.h
test_connect_CFLAGS = $(WARNINGS_CFLAGS) $(LIBGUESTFS_CFLAGS)
test_connect_LDADD = libtest.la $(LIBGUESTFS_LIBS)

# file plugin test.
check_PROGRAMS += test-file
TESTS += test-file
check_DATA += file-data
MAINTAINERCLEANFILES += file-data

test_file_SOURCES = test-file.c test.h
test_file_CFLAGS = $(WARNINGS_CFLAGS) $(LIBGUESTFS_CFLAGS)
test_file_LDADD = libtest.la $(LIBGUESTFS_LIBS)

file-data:
	rm -f $@ $@-t
	for f in `seq 1 512`; do echo -ne '\x01\x02\x03\x04\x05\x06\x07\x08'; done > $@-t
	mv $@-t $@

# gzip plugin test.
if HAVE_ZLIB
if HAVE_GUESTFISH

check_PROGRAMS += test-gzip
TESTS += test-gzip
check_DATA += disk disk.gz
MAINTAINERCLEANFILES += disk disk.gz

test_gzip_SOURCES = test-gzip.c test.h
test_gzip_CFLAGS = $(WARNINGS_CFLAGS) $(LIBGUESTFS_CFLAGS)
test_gzip_LDADD = libtest.la $(LIBGUESTFS_LIBS)

disk:
	rm -f $@ test1.img
	guestfish -N fs -m /dev/sda1 write /hello.txt "hello,world"
	mv test1.img disk

disk.gz: disk
	rm -f $@
	gzip -9 -c disk > $@

endif
endif

# xz plugin test.
if HAVE_LIBLZMA
if HAVE_GUESTFISH

check_PROGRAMS += test-xz
TESTS += test-xz
check_DATA += disk.xz
MAINTAINERCLEANFILES += disk.xz

test_xz_SOURCES = test-xz.c test.h
test_xz_CFLAGS = $(WARNINGS_CFLAGS) $(LIBGUESTFS_CFLAGS)
test_xz_LDADD = libtest.la $(LIBGUESTFS_LIBS)

disk.xz: disk
	rm -f $@
	xz --best -c disk > $@

endif
endif

# perl plugin test.
if HAVE_PERL

check_PROGRAMS += test-perl
TESTS += test-perl

test_perl_SOURCES = test-lang-plugins.c test.h
test_perl_CFLAGS = \
	-DLANG='"perl"' -DSCRIPT='"test.pl"' \
	$(WARNINGS_CFLAGS) $(LIBGUESTFS_CFLAGS)
test_perl_LDADD = libtest.la $(LIBGUESTFS_LIBS)

endif

# python plugin test.
if HAVE_PYTHON

check_PROGRAMS += test-python
TESTS += test-python

test_python_SOURCES = test-lang-plugins.c test.h
test_python_CFLAGS = \
	-DLANG='"python"' -DSCRIPT='"test.py"' \
	$(WARNINGS_CFLAGS) $(LIBGUESTFS_CFLAGS)
test_python_LDADD = libtest.la $(LIBGUESTFS_LIBS)

endif

endif
