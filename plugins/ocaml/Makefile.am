# nbdkit
# Copyright (C) 2014 Red Hat Inc.
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

EXTRA_DIST = \
	NBDKit.mli \
	NBDKit.ml \
	nbdkit-ocaml-plugin.pod

plugindir = $(libdir)/nbdkit/plugins

if HAVE_OCAML

ocamllibdir = $(OCAMLLIB)
ocamllib_DATA = NBDKit.mli NBDKit.cmi NBDKit.cmx NBDKit.o

NBDKit.cmi: NBDKit.mli
	$(OCAMLC) -c $<

NBDKit.cmx NBDKit.o: NBDKit.ml
	$(OCAMLOPT) $(OCAMLOPTFLAGS) -c $<

# NB: nbdkit-ocaml-plugin is not a self-contained plugin.  It's a
# static library that you have to link in to the OCaml plugins that
# you write.  Hence this builds 'nbdkit-ocaml-plugin.a'.  See
# nbdkit-ocaml-plugin(3) for more details.

plugin_LTLIBRARIES = nbdkit-ocaml-plugin.la

nbdkit_ocaml_plugin_la_SOURCES = \
	ocaml.c \
	$(top_srcdir)/include/nbdkit-plugin.h

nbdkit_ocaml_plugin_la_CPPFLAGS = \
	-I$(OCAMLLIB) \
	-I$(top_srcdir)/include
nbdkit_ocaml_plugin_la_CFLAGS = \
	$(WARNINGS_CFLAGS) \
	-fPIC
nbdkit_ocaml_plugin_la_LDFLAGS = \
	-module -avoid-version -static

if HAVE_POD2MAN

man_MANS = nbdkit-ocaml-plugin.3

nbdkit-ocaml-plugin.3: nbdkit-ocaml-plugin.pod
	$(POD2MAN) -u --stderr --section=3 --center=nbdkit --release=nbdkit --name=`basename $@ .3` $< $@

endif

endif

CLEANFILES = *~ *.cmi *.cmx

