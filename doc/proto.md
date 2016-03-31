# The NBD protocol

## Introduction

The Network Block Device is a Linux-originated lightweight block access
protocol that allows one to export a block device to a client. While the
name of the protocol specifically references the concept of block
devices, there is nothing inherent in the *protocol* which requires that
exports are, in fact, block devices; the protocol only concerns itself
with a range of bytes, and several operations of particular lengths at
particular offsets within that range of bytes.

For matters of clarity, in this document we will refer to an export from
a server as a block device, even though the actual backing on the server
need not be an actual block device; it may be a block device, a regular
file, or a more complex configuration involving several files. That is
an implementational detail of the server.

## Conventions

In the below protocol descriptions, the label 'C:' is used for messages
sent by the client, whereas 'S:' is used for messages sent by the
server).  `monotype text` is for literal character data or (when used in
comments) constant names, `0xdeadbeef` is used for literal hex numbers
(which are always sent in network byte order), and (brackets) are used
for comments. Anything else is a description of the data that is sent.

## Protocol phases

The NBD protocol has two phases: the handshake and the transmission. During the
handshake, a connection is established and an exported NBD device along other
protocol parameters are negotiated between the client and the server. After a
successful handshake, the client and the server proceed to the transmission
phase in which the export is read from and written to.

On the client side under Linux, the handshake is implemented in
userspace, while the transmission phase is implemented in kernel space.
To get from the handshake to the transmission phase, the client performs

    ioctl(nbd, NBD_SET_SOCK, sock)
    ioctl(nbd, NBD_DO_IT)

with `nbd` in the above being a file descriptor for an open `/dev/nbdX`
device node, and `sock` being the socket to the server. The second of
the above two calls does not return until the client disconnects.

Note that there are other `ioctl` calls available, that are used by the
client to communicate the options to the kernel which were negotiated
with the server during the handshake. This document does not describe
those.

### Handshake

The handshake is the first phase of the protocol. Its main purpose is to
provide means for both the client and the server to negotiate which
export they are going to use and how.

There are three versions of the negotiation. They are referred to as
"oldstyle", "newstyle", and "fixed newstyle" negotiation. Oldstyle was
the only version of the negotiation until nbd 2.9.16; newstyle was
introduced for nbd 2.9.17. A short while later, it was discovered that
newstyle was insufficiently structured to allow protocol options to be
added while retaining backwards compatibility. The minor changes
introduced to fix this problem are, where necessary, referred to as
"fixed newstyle" to differentiate from the original version of the
newstyle negotiation.

#### Oldstyle negotiation

S: 64 bits, `NBDMAGIC` (also known as the `INIT_PASSWD`)  
S: 64 bits, `0x00420281861253` (`cliserv_magic`, a magic number)  
S: 64 bits, size of the export in bytes (unsigned)  
S: 32 bits, flags  
S: 124 bytes, zeroes (reserved).  

As can be seen, this isn't exactly a negotiation; it's just a matter of
the server sending a bunch of data to the client. If the client is
unhappy with what he receives, he should disconnect and not look back.

The fact that the size of the export was specified before the flags were
sent, made it impossible for the protocol to be changed in a
backwards-compatible manner to allow for named exports without ugliness.
As a result, the old style negotiation is now no longer developed;
starting with version 3.10 of the reference implementation, it is also
no longer supported.

#### Newstyle negotiation

A client who wants to use the new style negotiation SHOULD connect on
the IANA-reserved port for NBD, 10809. The server MAY listen on other
ports as well, but it SHOULD use the old style handshake on those. The
server SHOULD refuse to allow oldstyle negotiations on the newstyle
port. For debugging purposes, the server MAY change the port on which to
listen for newstyle negotiation, but this should not happen for
production purposes.

The initial few exchanges in newstyle negotiation look as follows:

S: 64 bits, `NBDMAGIC` (as in the old style handshake)  
S: 64 bits, `0x49484156454F5054` (note different magic number)  
S: 16 bits, handshake flags  
C: 32 bits, flags  

This completes the initial phase of negotiation; the client and server
now both know they understand the first version of the newstyle
handshake, with no options. The client SHOULD ignore any handshake flags
it does not recognize, while the server MUST close the connection if
it does not recognize the client's flags.  What follows is a repeating
group of options. In non-fixed newstyle only one option can be set
(`NBD_OPT_EXPORT_NAME`), and it is not optional.

At this point, we move on to option haggling, during which point the
client can send one or (in fixed newstyle) more options to the server.
The generic format of setting an option is as follows:

C: 64 bits, `0x49484156454F5054` (note same newstyle handshake's magic number)  
C: 32 bits, option  
C: 32 bits, length of option data (unsigned)  
C: any data needed for the chosen option, of length as specified above.  

The presence of the option length in every option allows the server
to skip any options presented by the client that it does not
understand.

If the value of the option field is `NBD_OPT_EXPORT_NAME` and the server
is willing to allow the export, the server replies with information
about the used export:

S: 64 bits, size of the export in bytes (unsigned)  
S: 16 bits, transmission flags  
S: 124 bytes, zeroes (reserved) (unless `NBD_FLAG_C_NO_ZEROES` was
   negotiated by the client)  

If the server is unwilling to allow the export, it should close the
connection.

The reason that the flags field is 16 bits large and not 32 as in the
oldstyle negotiation is that there are now 16 bits of transmission flags,
and 16 bits of handshake flags. Concatenated together, this results in
32 bits, which allows for using a common set of macros for both. If we
ever run out of flags, the server will set the most significant flag
bit, signalling that an extra flag field will follow, to which the
client will have to reply with a flag field of its own before the extra
flags are sent. This is not yet implemented.

#### Fixed newstyle negotiation

Unfortunately, due to a mistake, the server would immediately close the
connection when it saw an option it did not understand, rather than
signalling this fact to the client, which would've allowed it to retry;
and replies from the server were not structured either, which meant that
if the server were to send something the client did not understand, it
would have to abort negotiation as well.

To fix these two issues, the following changes were implemented:

- The server will set the handshake flag `NBD_FLAG_FIXED_NEWSTYLE`, to
  signal that it supports fixed newstyle negotiation
- The client should reply with `NBD_FLAG_C_FIXED_NEWSTYLE` set in its flags
  field too, though its side of the protocol does not change incompatibly.
- The client may now send other options to the server as appropriate, in
  the generic format for sending an option as described above.
- The server will reply to any option apart from `NBD_OPT_EXPORT_NAME`
  with reply packets in the following format:

S: 64 bits, `0x3e889045565a9` (magic number for replies)  
S: 32 bits, the option as sent by the client to which this is a reply  
S: 32 bits, reply type (e.g., `NBD_REP_ACK` for successful completion,
   or `NBD_REP_ERR_UNSUP` to mark use of an option not known by this
   server  
S: 32 bits, length of the reply. This may be zero for some replies, in
   which case the next field is not sent  
S: any data as required by the reply (e.g., an export name in the case
   of `NBD_REP_SERVER`)  

As there is no unique number for client requests, clients who want to
differentiate between answers to two instances of the same option during
any negotiation must make sure they've seen the answer to an outstanding
request before sending the next one of the same type. The server MAY
send replies in the order that the requests were received, but is not
required to.

### Transmission

There are two message types in the transmission phase: the request, and
the response.

The request message, sent by the client, looks as follows:

C: 32 bits, 0x25609513, magic (`NBD_REQUEST_MAGIC`)  
C: 16 bits, command flags  
C: 16 bits, type  
C: 64 bits, handle  
C: 64 bits, offset (unsigned)  
C: 32 bits, length (unsigned)  
C: (*length* bytes of data if the request is of type `NBD_CMD_WRITE`)  

The server replies with:

S: 32 bits, 0x67446698, magic (`NBD_REPLY_MAGIC`)  
S: 32 bits, error  
S: 64 bits, handle  
S: (*length* bytes of data if the request is of type `NBD_CMD_READ`)  

Replies need not be sent in the same order as requests (i.e., requests
may be handled by the server asynchronously).  Clients SHOULD use a
handle that is distinct from all other currently pending transactions,
but MAY reuse handles that are no longer in flight; handles need not
be consecutive.  In each reply, the server MUST use the same value for
handle as was sent by the client in the corresponding request.  In
this way, the client can correlate which request is receiving a
response.

## Values

This section describes the value and meaning of constants (other than
magic numbers) in the protocol.

When flags fields are specified, they are numbered in network byte
order.

### Handshake phase

#### Flag fields

##### Handshake flags

This field of 16 bits is sent by the server after the `INIT_PASSWD` and
the first magic number.

- bit 0, `NBD_FLAG_FIXED_NEWSTYLE`; should be set by servers that
  support the fixed newstyle protocol
- bit 1, `NBD_FLAG_NO_ZEROES`; if set, and if the client replies with
  `NBD_FLAG_C_NO_ZEROES` in the client flags field, the server MUST NOT
  send the 124 bytes of zero at the end of the negotiation.

The server MUST NOT set any other flags, and SHOULD NOT change behaviour
unless the client responds with a corresponding flag.  The server MUST
NOT set any of these flags during oldstyle negotiation.

##### Transmission flags

This field of 16 bits is sent by the server after option haggling, or
immediately after the handshake flags field in oldstyle negotiation:

- bit 0, `NBD_FLAG_HAS_FLAGS`; should always be 1
- bit 1, `NBD_FLAG_READ_ONLY`; should be set to 1 if the export is
  read-only
- bit 2, `NBD_FLAG_SEND_FLUSH`; should be set to 1 if the server
  supports `NBD_CMD_FLUSH` commands
- bit 3, `NBD_FLAG_SEND_FUA`; should be set to 1 if the server supports
  the `NBD_CMD_FLAG_FUA` flag
- bit 4, `NBD_FLAG_ROTATIONAL`; should be set to 1 to let the client
  schedule I/O accesses as for a rotational medium
- bit 5, `NBD_FLAG_SEND_TRIM`; should be set to 1 if the server supports
  `NBD_CMD_TRIM` commands

Clients SHOULD ignore unknown flags.

##### Client flags

This field of 32 bits is sent after initial connection and after
receiving the handshake flags from the server.

- bit 0, `NBD_FLAG_C_FIXED_NEWSTYLE`; SHOULD be set by clients that
  support the fixed newstyle protocol. Servers MAY choose to honour
  fixed newstyle from clients that didn't set this bit, but relying on
  this isn't recommended.
- bit 1, `NBD_FLAG_C_NO_ZEROES`; MUST NOT be set if the server did not
  set `NBD_FLAG_NO_ZEROES`. If set, the server MUST NOT send the 124
  bytes of zeroes at the end of the negotiation.

Clients SHOULD NOT set any other flags; the server MUST drop the
connection if the client sets an unknown flag, or a flag that does
not match something advertised by the server.

#### Option types

These values are used in the "option" field during the option haggling
of the newstyle negotiation.

- `NBD_OPT_EXPORT_NAME` (1)

    Choose the export which the client would like to use, end option
    haggling, and proceed to the transmission phase. Data: name of the
    export, free-form UTF8 text (subject to limitations by server
    implementation). If the chosen export does not exist or requirements
    for the chosen export are not met (e.g., the client did not
    negotiate TLS for an export where the server requires it), the
    server should close the connection.

    A special, "empty", name (i.e., the length field is zero and no name
    is specified), is reserved for a "default" export, to be used in cases
    where explicitly specifying an export name makes no sense.

    This is the only valid option in nonfixed newstyle negotiation. A
    server which wishes to use any other option MUST support fixed
    newstyle.

    A major problem of this option is that it does not support the
    return of error messages to the client in case of problems. To
    remedy this, the experimental `SELECT` extension has been
    introduced; see below.

- `NBD_OPT_ABORT` (2)

    The client desires to abort the negotiation and close the
    connection.

- `NBD_OPT_LIST` (3)

    Return a number of `NBD_REP_SERVER` replies, one for each export,
    followed by `NBD_REP_ACK`.

- `NBD_OPT_PEEK_EXPORT` (4)

    Was defined by the (withdrawn) experimental `PEEK_EXPORT` extension;
    not in use.

- `NBD_OPT_STARTTLS` (5)

    The client wishes to initiate TLS. If the server replies with
    `NBD_REP_ACK`, then the client should immediately initiate a TLS
    handshake and continue the negotiation in the encrypted channel. If
    the server is unwilling to perform TLS, it should reply with
    `NBD_REP_ERR_POLICY`. For backwards compatibility, a client should
    also be prepared to handle `NBD_REP_ERR_UNSUP`. If the client sent
    along any data with the request, the server should send back
    `NBD_REP_ERR_INVALID`.

    This functionality has not yet been implemented by the reference
    implementation, but was implemented by qemu so has been moved out of
    the "experimental" section.

- `NBD_OPT_SELECT` (6)

    Defined by the experimental `SELECT` extension; see below.

- `NBD_OPT_GO` (7)

    Defined by the experimental `SELECT` extension; see below.

#### Option reply types

These values are used in the "reply type" field, sent by the server
during option haggling in the fixed newstyle negotiation.

- `NBD_REP_ACK` (1)

    Will be sent by the server when it accepts the option and no further
    information is available, or when sending data related to the option
    (in the case of `NBD_OPT_LIST`) has finished. No data.

* `NBD_REP_SERVER` (2)

    A description of an export. Data:

    - 32 bits, length of name (unsigned)
    - Name of the export, as expected by `NBD_OPT_EXPORT_NAME`
    - If length of name < (length of reply as sent in the reply packet
      header - 4), then the rest of the data contains some undefined
      implementation-specific details about the export. This is not
      currently implemented, but future versions of nbd-server may send
      along some details about the export. If the client did not
      explicitly request otherwise, these details are defined to be
      UTF-8 encoded data suitable for direct display to a human being.
    - The experimental `SELECT` extension (see below) adds extra data to
      the end of this request.

There are a number of error reply types, all of which are denoted by
having bit 31 set. All error replies MAY have some data set, in which
case that data is an error message suitable for display to the user.

* `NBD_REP_ERR_UNSUP` (2^31 + 1)

    The option sent by the client is unknown by this server
    implementation (e.g., because the server is too old, or from another
    source).

* `NBD_REP_ERR_POLICY` (2^31 + 2)

    The option sent by the client is known by this server and
    syntactically valid, but server-side policy forbids the server to
    allow the option (e.g., the client sent `NBD_OPT_LIST` but server
    configuration has that disabled)

* `NBD_REP_ERR_INVALID` (2^31 + 3)

    The option sent by the client is known by this server, but was
    determined by the server to be syntactically invalid. For instance,
    the client sent an `NBD_OPT_LIST` with nonzero data length.

* `NBD_REP_ERR_PLATFORM` (2^31 + 4)

    The option sent by the client is not supported on the platform on
    which the server is running. Not currently used.

* `NBD_REP_ERR_TLS_REQD` (2^31 + 5)

    The server is unwilling to continue negotiation unless TLS is
    negotiated first. A server MUST NOT send this error if it has one or
    more exports that do not require TLS; not even if the client indicated
    interest (by way of `NBD_OPT_PEEK_EXPORT`) in an export which requires
    TLS.

    If this reply is used, servers SHOULD send it in reply to each and every
    unencrypted `NBD_OPT_*` message (apart from `NBD_OPT_STARTTLS`).

    This functionality has not yet been implemented by the reference
    implementation, but was implemented by qemu so has been moved out of
    the "experimental" section.

    The experimental `SELECT` extension makes small but compatible
    changes to the semantics of this error message; see below.

* `NBD_REP_ERR_UNKNOWN` (2^31 + 6)

    defined by the experimental `SELECT` extension; see below.

### Transmission phase

#### Command flags

This field of 16 bits is sent by the client with every request and provides
additional information to the server to execute the command. Refer to
the "Request types" section below for more details about how a given flag
affects a particular command.  Clients MUST NOT set a command flag bit
that is not documented for the particular command; and whether a flag is
valid may depend on negotiation during the handshake phase.

- bit 0, `NBD_CMD_FLAG_FUA`; valid during `NBD_CMD_WRITE`.  SHOULD be
  set to 1 if the client requires "Force Unit Access" mode of
  operation.  MUST NOT be set unless transmission flags included
  `NBD_FLAG_SEND_FUA`.

#### Request types

The following request types exist:

* `NBD_CMD_READ` (0)

    A read request. Length and offset define the data to be read. The
    server MUST reply with a reply header, followed immediately by len
    bytes of data, read offset bytes into the file, unless an error
    condition has occurred.

    If an error occurs, the server SHOULD set the appropriate error code
    in the error field. The server MUST then either close the
    connection, or send *length* bytes of data (which MAY be invalid).

    If an error occurs while reading after the server has already sent
    out the reply header with an error field set to zero (i.e.,
    signalling no error), the server MUST immediately close the
    connection; it MUST NOT send any further data to the client.

* `NBD_CMD_WRITE` (1)

    A write request. Length and offset define the location and amount of
    data to be written. The client MUST follow the request header with
    *length* number of bytes to be written to the device.

    The server MUST write the data to disk, and then send the reply
    message. The server MAY send the reply message before the data has
    reached permanent storage.

    If the `NBD_FLAG_SEND_FUA` flag ("Force Unit Access") was set in the
    transmission flags field, the client MAY set the flag `NBD_CMD_FLAG_FUA` in
    the command flags field. If this flag was set, the server MUST NOT send
    the reply until it has ensured that the newly-written data has reached
    permanent storage.

    If an error occurs, the server SHOULD set the appropriate error code
    in the error field. The server MAY then close the connection.

* `NBD_CMD_DISC` (2)

    A disconnect request. The server MUST handle all outstanding
    requests, and then close the connection.  A client MUST NOT send
    anything to the server after sending an `NBD_CMD_DISC` command.

    The values of the length and offset fields in a disconnect request
    are not defined.

* `NBD_CMD_FLUSH` (3)

    A flush request; a write barrier. The server MUST NOT send a
    successful reply header for this request before all write requests
    for which a reply has already been sent to the client have reached
    permanent storage (using fsync() or similar).

    A client MUST NOT send a flush request unless `NBD_FLAG_SEND_FLUSH`
    was set in the transmission flags field.

    For a flush request, *length* and *offset* are reserved, and MUST be
    set to all-zero.

* `NBD_CMD_TRIM` (4)

    A hint to the server that the data defined by len and offset is no
    longer needed. A server MAY discard len bytes starting at offset, but
    is not required to.

    After issuing this command, a client MUST NOT make any assumptions
    about the contents of the export affected by this command, until
    overwriting it again with `NBD_CMD_WRITE`.

    A client MUST NOT send a trim request unless `NBD_FLAG_SEND_TRIM`
    was set in the transmission flags field.

* Other requests

    Some third-party implementations may require additional protocol
    messages which are not described in this document. In the interest of
    interoperability, authors of such implementations SHOULD contact the
    maintainer of this document, so that these messages can be listed here
    to avoid conflicting implementations.

    Currently one such message is known: `NBD_CMD_CACHE`, with type set to
    5, implemented by xnbd.

#### Error values

The error values are used for the error field in the reply message.
Originally, error messages were defined as the value of `errno` on the
system running the server; however, although they happen to have similar
values on most systems, these values are in fact not well-defined, and
therefore not entirely portable.

Therefore, the allowed values for the error field have been restricted
to set of possibilities. To remain intelligible with older clients, the
most common values of `errno` for that particular error has been chosen
as the value for an error.

The following error values are defined:

* `EPERM` (1), Operation not permitted.
* `EIO` (5), Input/output error.
* `ENOMEM` (12), Cannot allocate memory.
* `EINVAL` (22), Invalid argument.
* `ENOSPC` (28), No space left on device.

The server SHOULD return `ENOSPC` if it receives a write request
including one or more sectors beyond the size of the device.  It SHOULD
return `EINVAL` if it receives a read or trim request including one or
more sectors beyond the size of the device.  It also SHOULD map the
`EDQUOT` and `EFBIG` errors to `ENOSPC`.  Finally, it SHOULD return
`EPERM` if it receives a write or trim request on a read-only export.

The server SHOULD return `EINVAL` if it receives an unknown command.

The server SHOULD return `EINVAL` if it receives an unknown command flag. It
also SHOULD return `EINVAL` if it receives a request with a flag not explicitly
documented as applicable to the given request.

Which error to return in any other case is not specified by the NBD
protocol.

The server SHOULD AVOID returning ENOMEM if at all possible.

## Experimental extensions

The specifications in this section are non-normative and experimental.
They are not currently implemented by any known version of the nbd
protocol; a first implementation may require changes to the
specifications in this section, or may cause the specifications here to
be withdrawn altogether.

Therefore, implementors are strongly suggested to contact the
[mailinglist](mailto:nbd-general@lists.sourceforge.net) in order to help
fine-tune the specifications in this section before committing to a particular
implementation.

### `SELECT` extension

A major downside of the `NBD_OPT_EXPORT_NAME` option is that it does not
allow for an error message to be returned by the server (or, in fact,
any structured message). This is a result of a (misguided) attempt to
keep backwards compatibility with non-fixed newstyle negotiation.

To remedy this, a `SELECT` extension is envisioned. This extension adds
two option requests and one error reply type, and extends one existing
option reply type.

* `NBD_OPT_SELECT`

    The client wishes to select the export with the given name for use
    in the transmission phase, but does not yet want to move to the
    transmission phase.

    Data:

    - 32 bits, length of name (unsigned)
    - Name of the export

    The server replies with one of the following:

    - `NBD_REP_ERR_UNKNOWN`: The chosen export does not exist on this
      server.
    - `NBD_REP_ERR_TLS_REQD`: The server does not wish to export this
      block device unless the client negotiates TLS first.
    - `NBD_REP_SERVER`: The server accepts the chosen export. In this
      case, the `NBD_REP_SERVER` message's data contains the following
      fields:

      - 32 bits, length of name (unsigned)
      - Name of the export. This name MAY be different from the one
	given in the `NBD_OPT_SELECT` option in case the server has
	multiple alternate names for a single export.
      - 64 bits, size of the export in bytes (unsigned)
      - 16 bits, transmission flags

      That is, the `NBD_REP_SERVER` message is extended to also include
      the data sent in reply to the `NBD_OPT_EXPORT_NAME` option.
    - For backwards compatibility, clients should be prepared to also
      handle `NBD_REP_ERR_UNSUP`. In this case, they should fall back to
      using `NBD_OPT_EXPORT_NAME`.

* `NBD_OPT_GO`

    The client wishes to terminate the negotiation phase and progress to
    the transmission phase. Possible replies from the server include:

    - `NBD_REP_ACK`: The server acknowledges. After receiving this
      reply, the client and the server have both moved to the
      transmission phase.
    - `NBD_REP_ERR_INVALID`: No `NBD_OPT_SELECT` command was
      previously issued during this negotiation (there is no default);
      or, the most recent `NBD_OPT_SELECT` command resulted in an error
      reply (selecting a different export clears the currently selected
      export, even if the new export does not exist on the server); or,
      the most recent `NBD_OPT_SELECT` command issued during this
      negotiation occurred before TLS was successfully negotiated
      (negotiating TLS clears the selected export).
    - Servers MAY also choose to send `NBD_REP_ERR_TLS_REQD` rather than
      `NBD_REP_ERR_INVALID` if no non-TLS exports are supported.
    - Servers MUST NOT send `NBD_REP_ERR_UNSUP` as a reply to this
      message if they do not also send it as a reply to the
      `NBD_OPT_SELECT` message.

## About this file

This file tries to document the NBD protocol as it is currently
implemented in the Linux kernel and in the reference implementation. The
purpose of this file is to allow people to understand the protocol
without having to read the code. However, the description above does not
come with any form of warranty; while every effort has been taken to
avoid them, mistakes are possible.

In contrast to the other files in this repository, this file is not
licensed under the GPLv2. To the extent possible by applicable law, I
hereby waive all copyright and related or neighboring rights to this
file and release it into the public domain.

The purpose of releasing this into the public domain is to allow
competing implementations of the NBD protocol without those
implementations being considered derivative implementations; but please
note that changing this document, while allowed by its public domain
status, does not make an incompatible implementation suddenly speak the
NBD protocol.
