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

plugindir = $(libdir)/nbdkit/plugins

sbin_PROGRAMS = nbdkit

nbdkit_SOURCES = \
	cleanup.c \
	connections.c \
	errors.c \
	internal.h \
	main.c \
	plugins.c \
	protocol.h \
	sockets.c \
	tls.c \
	utils.c \
	$(top_srcdir)/include/nbdkit-plugin.h

nbdkit_CPPFLAGS = \
	-Dbindir=\"$(bindir)\" \
	-Dlibdir=\"$(libdir)\" \
	-Dplugindir=\"$(plugindir)\" \
	-Dsbindir=\"$(sbindir)\" \
	-Dsysconfdir=\"$(sysconfdir)\" \
	-I$(top_srcdir)/include
nbdkit_CFLAGS = \
	-pthread \
	$(WARNINGS_CFLAGS)
nbdkit_LDADD = \
	-ldl
nbdkit_LDFLAGS = \
	-rdynamic

CLEANFILES = *~
