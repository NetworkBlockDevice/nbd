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

EXTRA_DIST = libnbdkit-libvirt-plugin.pod

plugindir = $(libdir)/nbdkit/plugins

if HAVE_LIBVIRT

plugin_LTLIBRARIES = libnbdkit-libvirt-plugin.la

libnbdkit_libvirt_plugin_la_SOURCES = \
	libvirt-plugin.c \
	$(top_srcdir)/include/nbdkit-plugin.h

libnbdkit_libvirt_plugin_la_CPPFLAGS = \
	-I$(top_srcdir)/include
libnbdkit_libvirt_plugin_la_CFLAGS = \
	$(WARNINGS_CFLAGS) \
	$(LIBVIRT_CFLAGS)
libnbdkit_libvirt_plugin_la_LIBADD = \
	$(LIBVIRT_LIBS)
libnbdkit_libvirt_plugin_la_LDFLAGS = \
	-avoid-version -shared

if HAVE_POD2MAN

man_MANS = libnbdkit-libvirt-plugin.1

libnbdkit-libvirt-plugin.1: libnbdkit-libvirt-plugin.pod
	$(POD2MAN) -u --stderr --section=1 --center=nbdkit --release=nbdkit --name=libnbdkit-libvirt-plugin $< $@

endif

endif

CLEANFILES = *~
