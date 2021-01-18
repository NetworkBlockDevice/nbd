NBD README
==========

Welcome to the NBD userland support files!

This package contains nbd-server and nbd-client.

To install the package, download the source and do the normal
`configure`/`make`/`make install` dance. You'll need to install it on both the
client and the server. Note that released nbd tarballs are found on
[sourceforge](http://sourceforge.net/projects/nbd/files/nbd/).

For compiling from git, do a checkout, install the SGML tools
(docbook2man), and then run './autogen.sh' while inside your checkout.
Then, see above.

Contributing
------------

If you want to send a patch, please do not open a pull request; instead, send
it to the
[mailinglist](https://lists.debian.org/nbd)

Using NBD
---------

NBD is quite easy to use. First, on the client, you need to load the module
and, if you're not using udev, to create the device nodes:

    # modprobe nbd
    # cd /dev
    # ./MAKEDEV nbd0

(if you need more than one NBD device, repeat the above command for nbd1,
nbd2, ...)

Next, write a configuration file for the server. An example looks like
this:

    # This is a comment
    [generic]
        # The [generic] section is required, even if nothing is specified
        # there.
        # When either of these options are specified, nbd-server drops
        # privileges to the given user and group after opening ports, but
        # _before_ opening files.
        user = nbd
        group = nbd
    [export1]
        exportname = /export/nbd/export1-file
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
        # The other options are all optional

The configuration file is parsed with GLib's GKeyFile, which parses key
files as they are specified in the Freedesktop.org Desktop Entry
Specification, as can be found at
<http://freedesktop.org/Standards/desktop-entry-spec>. While this format
was not intended to be used for configuration files, the glib API is
flexible enough for it to be used as such.

Now start the server:

    nbd-server -C /path/to/configfile

Note that the filename must be an absolute path; i.e., something like
`/path/to/file`, not `../file`. See the nbd-server manpage for details
on any available options.

Finally, you'll be able to start the client:

    nbd-client <hostname> -N <export name> <nbd device>

e.g.,

    nbd-client 10.0.0.1 -N otherexport /dev/nbd0

will use the second export in the above example (the one that exports
`/export/nbd/experiment`)

`nbd-client` must be ran as root; the same is not true for nbd-server
(but do make sure that /var/run is writeable by the server that
`nbd-server` runs as; otherwise, you won't get a PID file, though the
server will keep running).

There are packages (or similar) available for most current operating
systems; see the "Packaging status" badge below for details.

For questions, please use the [nbd@other.debian.org](mailto:nbd@other.debian.org) mailinglist.

Badges
======

[![Download Network Block Device](https://img.shields.io/sourceforge/dm/nbd.svg)](https://sourceforge.net/projects/nbd/files/latest/download)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/1243/badge.svg)](https://scan.coverity.com/projects/1243)
[![CII badge](https://bestpractices.coreinfrastructure.org/projects/281/badge)](https://bestpractices.coreinfrastructure.org/projects/281)
[![Travis](https://img.shields.io/travis/NetworkBlockDevice/nbd.svg)](https://travis-ci.org/NetworkBlockDevice/nbd)

[![Packaging status](https://repology.org/badge/vertical-allrepos/nbd.svg)](https://repology.org/metapackage/nbd)
