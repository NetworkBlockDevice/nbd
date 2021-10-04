# The NBD Uniform Resource Indicator (URI) format

## Introduction

This document describes the standard URI format that clients may use
to refer to an export located on an NBD server.

## Convention

"NBD" stands for Network Block Device and refers to the protocol
described in the adjacent protocol document also available online at
<https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md#the-nbd-protocol>

"URI" stands for Uniform Resource Indicator and refers to the standard
introduced in [RFC 3986](https://www.ietf.org/rfc/rfc3986.txt) and
subsequent IETF standards.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL",
"SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).
The same words in lower case carry their natural meaning.

## Related standards

All NBD URIs MUST also be valid URIs as described in
[RFC 3986](https://www.ietf.org/rfc/rfc3986.txt) and any subsequent
IETF standards describing URIs.  This means that any parsing, quoting
or encoding issues that may arise when making or parsing an NBD URI
must be answered by consulting IETF standards.

This standard defers any question about how the NBD protocol works to
the NBD protocol document available online at
<https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md#the-nbd-protocol>

## NBD URI components

An NBD URI consists of the following components:

     +------- Scheme (required)
     |
     |            +------- Authority (optional)
     |            |
     |            |           +------- Export name (optional)
     |            |           |
     v            v           v
    nbd://example.com:10809/export
    
    nbd+unix:///export?socket=nbd.sock
                           ^
                           |
                           +---- Query parameters

## NBD URI scheme

One of the following scheme names SHOULD be used to indicate an NBD URI:

* `nbd`: NBD over an unencrypted or opportunistically TLS encrypted
  TCP/IP connection.

* `nbds`: NBD over a TLS encrypted TCP/IP connection.  If encryption
  cannot be negotiated then the connection MUST fail.

* `nbd+unix`: NBD over a Unix domain socket.  The query parameters
  MUST include a parameter called `socket` which refers to the name of
  the Unix domain socket.

* `nbds+unix`: NBD over a TLS encrypted Unix domain socket.  If
  encryption cannot be negotiated then the connection MUST fail.  The
  query parameters MUST include a parameter called `socket` which
  refers to the name of the Unix domain socket.

Other URI scheme names MAY be used but not all NBD clients will
understand them or even recognize that they refer to NBD.

Note that using opportunistically encrypted connections (via the `nbd`
or `nbd+unix` scheme) risks a protocol downgrade attack; whereas
requests for a secure connection (via the `nbds` or `nbds+unix`
scheme) MUST use TLS to connect.  For more details, see
<https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md#security-considerations>

## NBD URI authority

The authority field SHOULD be used for TCP/IP connections and SHOULD
NOT be used for Unix domain socket connections.

The authority field MAY contain the `userinfo`, `host` and/or `port`
fields as defined in [RFC 3986](https://www.ietf.org/rfc/rfc3986.txt)
section 3.2.

The `host` field may be a host name or IP address.  Literal IPv6
addresses MUST be formatted in the way specified by
[RFC 2732](https://www.ietf.org/rfc/rfc2732.txt).

If the `port` field is not present then it MUST default to the NBD
port number assigned by IANA (10809).

The `userinfo` field is used to supply a username for certain less
common sorts of TLS authentication.  If the `userinfo` field is not
present but is needed by the client for TLS authentication then it
SHOULD default to a local operating system credential if one is
available.

It is up to the NBD client what should happen if the authority field
is not present for TCP/IP connections, or present for Unix domain
socket connections.  Options might include failing with an error,
ignoring it, or using defaults.

## NBD URI export name

If the version of the NBD protocol in use needs an export name, then
the path part of the URI except for the leading `/` character MUST be
passed to the server as the export name.

For example:

    NBD URI                          Export name
    ----------------------------------------------------
    nbd://example.com/disk           disk
    nbd+unix:///disk?socket=sock     disk
    nbd://example.com/               (empty string)
    nbd://example.com                (empty string)
    nbd://example.com//disk          /disk
    nbd://example.com/hello%20world  hello world

Note that export names are not usually paths, they are free text
strings.  In particular they do not usually start with a `/`
character, they may be an empty string, and they may contain any
Unicode character except NUL.

## NBD URI socket parameter

If the scheme name indicates a Unix domain socket then the query
parameters MUST include a `socket` key, referring to the Unix domain
socket which on Unix-like systems is usually a special file on the
local disk.

On platforms which support Unix domain sockets in the abstract
namespace, and if the client supports this, the `socket` parameter MAY
begin with an ASCII NUL character.  When the URI is properly encoded
it will look like this:

    nbd+unix:///?socket=%00/abstract

## NBD URI query parameters related to TLS

If TLS encryption is to be negotiated then the following query
parameters MAY be present:

* `tls-type`: Possible values include `anon`, `x509` or `psk`.  This
  specifies the desired TLS authentication method.

* `tls-hostname`: The optional TLS hostname to use for certificate
  verification.  This can be used when connecting over a Unix domain
  socket since there is no hostname available in the URI authority
  field; or when DNS does not properly resolve the server's hostname.

* `tls-verify-peer`: This optional parameter may be `0` or `1` to
  control whether the client verifies the server's identity.  By
  default clients SHOULD verify the server's identity if TLS is
  negotiated and if a suitable Certificate Authority is available.

## Other NBD URI query parameters

Clients SHOULD prefix experimental query parameters using `x-`.  This
SHOULD NOT be used for query parameters which are expected to be
widely used.

Any other query parameters which the client does not understand SHOULD
be diagnosed by the parser.

## Clients which do not support TLS

Wherever this document refers to encryption, authentication and TLS,
clients which do not support TLS SHOULD give an error when
encountering an NBD URI that requires TLS (such as one with a scheme
name `nbds` or `nbds+unix`).
