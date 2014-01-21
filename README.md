NBD README
==========

<a href="https://scan.coverity.com/projects/1243">
  <img alt="Coverity Scan Build Status"
         src="https://scan.coverity.com/projects/1243/badge.svg"/>
</a>

Welcome to the NBD userland support files!

This package contains nbd-server and nbd-client.

To install the package, do the normal `configure`/`make`/`make install`
dance. You'll need to install it on both the client and the server.

Using NBD is quite easy. First, on the client, you need to create the
device nodes:

    # cd /dev
    # ./MAKEDEV nbd0

(if you need more than one NBD device, repeat the above command for nbd1,
nbd2, ...)

Since there's a problem with nbd and the (default) cfq I/O scheduler,
you may want to set it to deadline:

    echo 'deadline' > /sys/block/nbd0/queue/scheduler

Note that this is done by default on recent kernels.

(again, repeat the above for nbd1, nbd2, etc, if you need more than one
device)

Next, start the server. You can use a file or a block device for that:

    nbd-server <port> <filename>

e.g.,

    nbd-server 1234 /home/wouter/nbd-export

Note that the filename must be an absolute path; i.e., something like
`/path/to/file`, not `../file`. See the nbd-server manpage for details
on any available options.

Finally, you'll be able to start the client:

    nbd-client <hostname> <port> <nbd device>

e.g.,

    nbd-client 10.0.0.1 1234 /dev/nbd0

`nbd-client` must be ran as root; the same is not true for nbd-server
(but do make sure that /var/run is writeable by the server that
`nbd-server` runs as; otherwise, you won't get a PID file, though the
server will keep running).

Starting with NBD 2.9, there is also support for a configuration file.
This configuration file is expected to be found at
`<sysconfdir>/nbd-server/config`, and should look something like this:

    # This is a comment
    [generic]
 	   # The [generic] section is required, even if nothing is specified
    	# there.
    	# When either of these options are specified, nbd-server drops
    	# privileges to the given user and group after opening ports, but
    	# _before_ opening files.
    	user = nbd
    	group = nbd
    	# Since version 2.9.17, nbd-server will do exports on a name
    	# basis (the used name is the name of the section in which the
    	# export is specified). This however required an incompatible
    	# protocol change. To enable backwards-compatible port-based
    	# exports, uncomment the following line:
    	# oldstyle = true
    [export1]
    	exportname = /export/nbd/export1-file
    	# The following line will be ignored unless the 
    	# "oldstyle = true" line in the generic section above is
    	# enabled.
    	port = 12345
    	authfile = /export/nbd/export1-authfile
    	timeout = 30
    	filesize = 10000000
    	readonly = false
    	multifile = false
    	copyonwrite = false
    	prerun = dd if=/dev/zero of=%s bs=1k count=500
    	postrun = rm -f %s
    [otherexport]
    	exportname = /export/nbd/experiment
    	# The other options are all optional, except this one in case
    	# the oldstyle option is used in [generic]:
    	# port = 12346

The configuration file is parsed with GLib's GKeyFile, which parses key
files as they are specified in the Freedesktop.org Desktop Entry
Specification, as can be found at
<http://freedesktop.org/Standards/desktop-entry-spec>. While this format
was not intended to be used for configuration files, the glib API is
flexible enough for it to be used as such.

The old command-line syntax is still supported, however.

There are packages (or similar) available for the following operating
systems:

- Debian (and derivatives, like Ubuntu): `nbd-client` and `nbd-server`,
  since Debian woody.
- Gentoo: the `nbd` ebuild in the `sys-block` category, available in
  Portage since 2002.
- FreeBSD: `net/nbd-server`, available in the ports tree since 2003.
  FreeBSD doesn't have kernel support for NBD, so obviously the client
  isn't built there.
- SuSE: `nbd`, in SuSE 10.0
- Fedora: `nbd`, since Fedora 7
- uClibc's `buildroot` script also seems to have support for NBD.

If you're packaging NBD for a different operating system that isn't in
the above list, I'd like to know about it.
