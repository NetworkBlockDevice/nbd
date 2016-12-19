This directory contains test certificates used for NBD's test suite.

They are:

* `client-key.pem` - client private key
* `client-cert.pem` - client public key
* `server-key.pem` - server private key
* `server-cert.pem` - server public key
* `ca-key.pem` - certificate authority private key
* `ca-cert.pem` - certificate authority public key

The `*.info` files are generated using the procedure below.

Certificates can be made using the procedure at: https://qemu.weilnetz.de/qemu-doc.html
using GnuTLS's certtool tool.

Here's how:

First make a CA:

    # certtool --generate-privkey > ca-key.pem

And give it a public key:

    # cat > ca.info <<EOF
    cn = Name of your organization
    ca
    cert_signing_key
    EOF
    # certtool --generate-self-signed --load-privkey ca-key.pem --template ca.info --outfile ca-cert.pem

Next issue a server certificate:

    # cat > server.info <<EOF
    organization = Name of your organization
    cn = server.foo.example.com
    tls_www_server
    encryption_key
    signing_key
    EOF
    # certtool --generate-privkey > server-key.pem
    # certtool --generate-certificate --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --load-privkey server-key.pem --template server.info --outfile server-cert.pem

Note the `cn` needs to match the hostname that nbd-client uses to connect (or the hostname specified with `-H` on the command line).

And finally issue a client certificate:

    # cat > client.info <<EOF
    country = GB
    state = London
    locality = London
    organization = Name of your organization
    cn = client.foo.example.com
    tls_www_client
    encryption_key
    signing_key
    EOF
    # certtool --generate-privkey > client-key.pem
    # certtool --generate-certificate --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --load-privkey client-key.pem --template client.info --outfile client-cert.pem


In contrast to the other files in this repository, the contents of this directory
are not licensed under the GPLv2. To the extent possible by applicable law, I
hereby waive all copyright and related or neighboring rights to the files in this
directory and release them into the public domain.

The purpose of releasing this into the public domain is to allow
competing implementations of the NBD protocol without those
implementations being considered derivative implementations.
