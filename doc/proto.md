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

S: 64 bits, `0x4e42444d41474943` (ASCII '`NBDMAGIC`') (also known as
   the `INIT_PASSWD`)  
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

S: 64 bits, `0x4e42444d41474943` (ASCII '`NBDMAGIC`') (as in the old
   style handshake)  
S: 64 bits, `0x49484156454F5054` (ASCII '`IHAVEOPT`') (note different
   magic number)  
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

C: 64 bits, `0x49484156454F5054` (ASCII '`IHAVEOPT`') (note same
   newstyle handshake's magic number)  
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
  signal that it supports fixed newstyle negotiation.
- The client should reply with `NBD_FLAG_C_FIXED_NEWSTYLE` set in its flags
  field too, though its side of the protocol does not change incompatibly.
- The client may now send other options to the server as appropriate, in
  the generic format for sending an option as described above.
- The server MUST NOT send a response to `NBD_OPT_EXPORT_NAME` until all
  other pending option requests have had their final reply.
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

There are three message types in the transmission phase: the request,
the simple reply, and the experimental structured reply chunk.  The
transmission phase consists of a series of transactions, where the
client submits requests and the server sends corresponding replies
with either a single simple reply or a series of one or more
structured reply chunks per request.  The phase continues until either
side closes the connection.

Note that without client negotiation, the server MUST use only simple
replies, and that it is impossible to tell by reading the server
traffic in isolation whether a data field will be present; the simple
reply is also problematic for error handling of the `NBD_CMD_READ`
request.  Therefore, the experimental `STRUCTURED_REPLY` extension
creates a context-free server stream by introducing the use of
structured reply chunks; see below.

Replies need not be sent in the same order as requests (i.e., requests
may be handled by the server asynchronously), and structured reply
chunks from one request may be interleaved with reply messages from
other requests; however, there may be constraints that prevent
arbitrary reordering of structured reply chunks within a given reply.
Clients SHOULD use a handle that is distinct from all other currently
pending transactions, but MAY reuse handles that are no longer in
flight; handles need not be consecutive.  In each reply message
(whether simple or structured), the server MUST use the same value for
handle as was sent by the client in the corresponding request.  In
this way, the client can correlate which request is receiving a
response.

#### Ordering of messages and writes

The server MAY process commands out of order, and MAY reply out of
order, except that:

* All write commands (that includes `NBD_CMD_WRITE`,
  `NBD_WRITE_ZEROES` and `NBD_CMD_TRIM`) that the server
  completes (i.e. replies to) prior to processing to a
  `NBD_CMD_FLUSH` MUST be written to non-volatile
  storage prior to replying to that `NBD_CMD_FLUSH`. This
  paragraph only applies if `NBD_FLAG_SEND_FLUSH` is set within
  the transmission flags, as otherwise `NBD_CMD_FLUSH` will never
  be sent by the client to the server.

* A server MUST NOT reply to a command that has `NBD_CMD_FLAG_FUA` set
  in its command flags until the data (if any) written by that command
  is persisted to non-volatile storage. This only applies if
  `NBD_FLAG_SEND_FUA` is set within the transmission flags, as otherwise
  `NBD_CMD_FLAG_FUA` will not be set on any commands sent to the server
  by the client.

`NBD_CMD_FLUSH` is modelled on the Linux kernel empty bio with
`REQ_FLUSH` set. `NBD_CMD_FLAG_FUA` is modelled on the Linux
kernel bio with `REQ_FUA` set. In case of ambiguity in this
specification, the
[kernel documentation](https://www.kernel.org/doc/Documentation/block/writeback_cache_control.txt)
may be useful.

#### Request message

The request message, sent by the client, looks as follows:

C: 32 bits, 0x25609513, magic (`NBD_REQUEST_MAGIC`)  
C: 16 bits, command flags  
C: 16 bits, type  
C: 64 bits, handle  
C: 64 bits, offset (unsigned)  
C: 32 bits, length (unsigned)  
C: (*length* bytes of data if the request is of type `NBD_CMD_WRITE`)  

#### Simple reply message

The simple reply message MUST be sent by the server in response to all
requests if the experimental `STRUCTURED_REPLY` extension was not
negotiated.  If structured replies have been negotiated, a simple
reply MAY be used as a reply to any request other than `NBD_CMD_READ`,
but only if the reply has no data payload.  The message looks as
follows:

S: 32 bits, 0x67446698, magic (`NBD_SIMPLE_REPLY_MAGIC`; used to be
   `NBD_REPLY_MAGIC`)  
S: 32 bits, error (MAY be zero)  
S: 64 bits, handle  
S: (*length* bytes of data if the request is of type `NBD_CMD_READ`)  

#### Structured reply chunk message

This reply type MUST NOT be used except as documented by the
experimental `STRUCTURED_REPLY` extension; see below.

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
- bit 6, `NBD_FLAG_SEND_WRITE_ZEROES`; defined by the experimental
  `WRITE_ZEROES` extension; see below.
- bit 7, `NBD_FLAG_SEND_DF`; defined by the experimental `STRUCTURED_REPLY`
  extension; see below.

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

Clients MUST NOT set any other flags; the server MUST drop the
connection if the client sets an unknown flag, or a flag that does
not match something advertised by the server.

#### Option types

These values are used in the "option" field during the option haggling
of the newstyle negotiation.

- `NBD_OPT_EXPORT_NAME` (1)

    Choose the export which the client would like to use, end option
    haggling, and proceed to the transmission phase. Data: name of the
    export, free-form UTF-8 text (subject to limitations by server
    implementation). The length of the name is determined from the
    option header. The name is not NUL terminated, and may not
    contain embedded NUL characters. If the
    chosen export does not exist or requirements for the chosen export
    are not met (e.g., the client did not negotiate TLS for an export
    where the server requires it), the server should close the
    connection.

    A special, "empty", name (i.e., the length field is zero and no name
    is specified), is reserved for a "default" export, to be used in cases
    where explicitly specifying an export name makes no sense.

    This is the only valid option in nonfixed newstyle negotiation. A
    server which wishes to use any other option MUST support fixed
    newstyle.

    A major problem of this option is that it does not support the
    return of error messages to the client in case of problems. To
    remedy this, the experimental `INFO` extension has been
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
    `NBD_REP_ERR_INVALID`. The client MUST NOT send this option if
    it has already negotiated TLS; if the server receives
    `NBD_OPT_STARTTLS` when TLS has already been negotiated, the server
    MUST send back `NBD_REP_ERR_INVALID`.

    This functionality has not yet been implemented by the reference
    implementation, but was implemented by qemu so has been moved out of
    the "experimental" section.

- `NBD_OPT_INFO` (6)

    Defined by the experimental `INFO` extension; see below.

- `NBD_OPT_GO` (7)

    Defined by the experimental `INFO` extension; see below.

- `NBD_OPT_STRUCTURED_REPLY` (8)

    Defined by the experimental `STRUCTURED_REPLY` extension; see below.

#### Option reply types

These values are used in the "reply type" field, sent by the server
during option haggling in the fixed newstyle negotiation.

- `NBD_REP_ACK` (1)

    Will be sent by the server when it accepts the option and no further
    information is available, or when sending data related to the option
    (in the case of `NBD_OPT_LIST`) has finished. No data.

* `NBD_REP_SERVER` (2)

    A description of an export. Data:

    - 32 bits, length of name (unsigned); MUST be no larger than the
      reply packet header length - 4
    - Name of the export, as expected by `NBD_OPT_EXPORT_NAME` (note
      that the length of name does NOT include a NUL terminator)
    - If length of name < (reply packet header length - 4), then the
      rest of the data contains some implementation-specific details
      about the export. This is not currently implemented, but future
      versions of nbd-server may send along some details about the
      export. Therefore, unless explicitly documented otherwise by a
      particular client request, this field is defined to be UTF-8
      encoded data suitable for direct display to a human being; with
      no embedded or terminating NUL characters.

    The experimental `INFO` extension (see below) adds two client
    option requests where the extra data has a definition other than a
    UTF-8 message.

There are a number of error reply types, all of which are denoted by
having bit 31 set. All error replies MAY have some data set, in which
case that data is an error message in UTF-8 encoding suitable for
display to the user, with no embedded or terminating NUL characters.

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

    The experimental `INFO` extension makes small but compatible
    changes to the semantics of this error message; see below.

* `NBD_REP_ERR_UNKNOWN` (2^31 + 6)

    defined by the experimental `INFO` extension; see below.

### Transmission phase

#### Command flags

This field of 16 bits is sent by the client with every request and provides
additional information to the server to execute the command. Refer to
the "Request types" section below for more details about how a given flag
affects a particular command.  Clients MUST NOT set a command flag bit
that is not documented for the particular command; and whether a flag is
valid may depend on negotiation during the handshake phase.

- bit 0, `NBD_CMD_FLAG_FUA`; This flag is valid for all commands, provided
  `NBD_FLAG_SEND_FUA` has been negotiated, in which case the server MUST
  accept all commands with this bit set (even by ignoring the bit). The
  client SHOULD NOT set this bit unless the command has the potential of
  writing data (current commands are `NBD_CMD_WRITE`, `NBD_CMD_WRITE_ZEROES`
  and `NBD_CMD_TRIM`), however note that existing clients are known to set this
  bit on other commands. Subject to that, and provided `NBD_FLAG_SEND_FUA`
  is negotiated, the client MAY set this bit on all, no or some commands
  as it wishes (see the section on Ordering of messages and writes for
  details). If the server receives a command with `NBD_CMD_FLAG_FUA`
  set it MUST NOT send its reply to that command until all write
  operations (if any) associated with that command have been
  completed and persisted to non-volatile storage. If the command does
  not in fact write data (for instance on an `NBD_CMD_TRIM` in a situation
  where the command as a whole is ignored), the server MAY ignore this bit
  being set on such a command.
- bit 1, `NBD_CMD_FLAG_NO_HOLE`; defined by the experimental `WRITE_ZEROES`
  extension; see below.
- bit 2, `NBD_CMD_FLAG_DF`; defined by the experimental `STRUCTURED_REPLY`
  extension; see below

#### Request types

The following request types exist:

* `NBD_CMD_READ` (0)

    A read request. Length and offset define the data to be read. The
    server MUST reply with either a simple reply or a structured
    reply, according to whether the experimental `STRUCTURED_REPLY`
    extension was negotiated.

    If structured replies were not negotiated, the server MUST reply
    with a simple reply header, followed immediately by *length* bytes
    of data, read from *offset* bytes into the file, unless an error
    condition has occurred.

    If an error occurs, the server SHOULD set the appropriate error
    code in the error field. The server MUST then either close the
    connection, or send *length* bytes of data (these bytes MAY be
    invalid, in which case they SHOULD be zero); this is true even if
    the error is `EINVAL` for bad flags detected before even
    attempting to read.

    If an error occurs while reading after the server has already sent
    out the reply header with an error field set to zero (i.e.,
    signalling no error), the server MUST immediately close the
    connection; it MUST NOT send any further data to the client.

    The experimental `STRUCTURED_REPLY` extension changes the reply
    from a simple reply to a structured reply, in part to allow
    recovery after a partial read and more efficient reads of sparse
    files; see below.

* `NBD_CMD_WRITE` (1)

    A write request. Length and offset define the location and amount of
    data to be written. The client MUST follow the request header with
    *length* number of bytes to be written to the device.

    The server MUST write the data to disk, and then send the reply
    message. The server MAY send the reply message before the data has
    reached permanent storage.

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
    overwriting it again with `NBD_CMD_WRITE` or `NBD_CMD_WRITE_ZEROES`.

    A client MUST NOT send a trim request unless `NBD_FLAG_SEND_TRIM`
    was set in the transmission flags field.

* `NBD_CMD_WRITE_ZEROES` (6)

    Defined by the experimental `WRITE_ZEROES` extension; see below.

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
* `EOVERFLOW` (75), Value too large; SHOULD NOT be sent outside of the
  experimental `STRUCTURED_REPLY` extension; see below.

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

### `INFO` extension

A major downside of the `NBD_OPT_EXPORT_NAME` option is that it does not
allow for an error message to be returned by the server (or, in fact,
any structured message). This is a result of a (misguided) attempt to
keep backwards compatibility with non-fixed newstyle negotiation.

To remedy this, an `INFO` extension is envisioned. This extension adds
two option requests and one error reply type, and extends one existing
option reply type.

Both options have identical formats for requests and replies. The
only difference is that after a successful reply to `NBD_OPT_GO`
(i.e. an `NBD_REP_SERVER`), transmission mode is entered immediately.
Therefore these commands share common documentation.

* `NBD_OPT_INFO` and `NBD_OPT_GO`

    `NBD_OPT_INFO`: The client wishes to get details about an export
    with the given name for use in the transmission phase, but does
    not yet want to move to the transmission phase.  When successful,
    this option provides more details than `NBD_OPT_LIST`, but only
    for a single export name.

    `NBD_OPT_GO`: The client wishes to terminate the handshake phase
    and progress to the transmission phase. This client MAY issue this
    command after an `NBD_OPT_INFO`, or MAY issue it without a
    previous `NBD_OPT_INFO`.  `NBD_OPT_GO` can thus be used as an
    improved version of `NBD_OPT_EXPORT_NAME` that is capable of
    returning errors.

    Data (both commands):

    - Name of the export (as with `NBD_OPT_EXPORT_NAME`, the length
      comes from the option header).

    If no name is specified (i.e. a zero length string is provided),
    this specifies the default export (if any), as with
    `NBD_OPT_EXPORT_NAME`.

    The server replies with one of the following:

    - `NBD_REP_ERR_UNKNOWN`: The chosen export does not exist on this
      server.
    - `NBD_REP_ERR_TLS_REQD`: The server does not wish to export this
      block device unless the client negotiates TLS first.
    - `NBD_REP_SERVER`: The server accepts the chosen export.

    Additionally, if TLS has not been negotiated, the server MAY reply
    with `NBD_REP_ERR_TLS_REQD` (instead of `NBD_REP_ERR_UNKNOWN`)
    to requests for exports that are unknown. This is so that clients
    that have not negotiated TLS cannot enumerate exports.

    In the case of `NBD_REP_SERVER`, the message's data takes on a different
    interpretation than the default (so as to provide additional
    binary information normally sent in reply to `NBD_OPT_EXPORT_NAME`,
    in place of the default UTF-8 free-form string). The option reply length
    MUST be *length of name* + 14, and the option data has the following layout:

    - 64 bits, size of the export in bytes (unsigned)
    - 16 bits, transmission flags.
    - 32 bits, length of name (unsigned)
    - Name of the export. This name MAY be different from the one
      given in the `NBD_OPT_INFO` or `NBD_OPT_GO` option in case the
      server has multiple alternate names for a single export, or a
      default export was specified.

    The server MUST NOT fail an NDB_OPT_GO sent with the same parameters
    as a previous NBD_OPT_INFO which returned successfully (i.e. with
    `NBD_REP_SERVER`) unless in the intervening time the client has
    negotiated other options. The server MUST return the same transmission
    flags with NDB_OPT_GO as a previous NDB_OPT_INFO unless in the
    intervening time the client has negotiated other options.
    The values of the transmission flags MAY differ from what was sent
    earlier in response to an earlier `NBD_OPT_INFO` (if any), and/or
    the server MAY fail the request, based on other options that were
    negotiated in the meantime.

    For backwards compatibility, clients should be prepared to also
    handle `NBD_REP_ERR_UNSUP`. In this case, they should fall back to
    using `NBD_OPT_EXPORT_NAME`.

    The reply to an `NBD_OPT_GO` is identical to the reply to `NBD_OPT_INFO`
    save that if the reply indicates success (i.e. is `NBD_REP_SERVER`),
    the client and the server both immediately enter the transmission
    phase. The server MUST NOT send any zero padding bytes after the
    `NBD_REP_SERVER` data, whether or not the client negotiated the
    `NBD_FLAG_C_NO_ZEROES` flag. After sending this reply the server MUST
    immediately move to the transmission phase, and after receiving this
    reply, the client MUST immediately move to the transmission phase;
    therefore, the server MUST NOT send this particular reply until all
    other pending option replies have been sent by the server.

### `WRITE_ZEROES` extension

There exist some cases when a client knows that the data it is going to write
is all zeroes. Such cases include mirroring or backing up a device implemented
by a sparse file. With current NBD command set, the client has to issue
`NBD_CMD_WRITE` command with zeroed payload and transfer these zero bytes
through the wire. The server has to write the data onto disk, effectively
losing the sparseness.

To remedy this, a `WRITE_ZEROES` extension is envisioned. This
extension adds one new transmission flag, one new command, and one new
command flag.

* `NBD_FLAG_SEND_WRITE_ZEROES`

    The server SHOULD set this transmission flag to 1 if the
    `NBD_CMD_WRITE_ZEROES` request is supported.

* `NBD_CMD_WRITE_ZEROES`

    A write request with no payload. Length and offset define the location
    and amount of data to be zeroed.

    The server MUST zero out the data on disk, and then send the reply
    message. The server MAY send the reply message before the data has
    reached permanent storage.

    A client MUST NOT send a write zeroes request unless
    `NBD_FLAG_SEND_WRITE_ZEROES` was set in the transmission flags field.

    By default, the server MAY use trimming to zero out the area, even
    if it did not advertise `NBD_FLAG_SEND_TRIM`; but it MUST ensure
    that the data reads back as zero.  However, the client MAY set the
    command flag `NBD_CMD_FLAG_NO_HOLE` to inform the server that the
    area MUST be fully provisioned, ensuring that future writes to the
    same area will not cause fragmentation or cause failure due to
    insufficient space.

    If an error occurs, the server SHOULD set the appropriate error code
    in the error field. The server MAY then close the connection.

The server SHOULD return `ENOSPC` if it receives a write zeroes request
including one or more sectors beyond the size of the device. It SHOULD
return `EPERM` if it receives a write zeroes request on a read-only export.

The extension adds the following new command flag:

- `NBD_CMD_FLAG_NO_HOLE`; valid during `NBD_CMD_WRITE_ZEROES`.
  SHOULD be set to 1 if the client wants to ensure that the server does
  not create a hole. The client MAY send `NBD_CMD_FLAG_NO_HOLE` even
  if `NBD_FLAG_SEND_TRIM` was not set in the transmission flags field.
  The server MUST support the use of this flag if it advertises
  `NBD_FLAG_SEND_WRITE_ZEROES`.

### `STRUCTURED_REPLY` extension

Some of the major downsides of the default simple reply to
`NBD_CMD_READ` are as follows.  First, it is not possible to support
partial reads or early errors (the command must succeed or fail as a
whole, and either len bytes of data must be sent or the connection
must be closed, even if the failure is `EINVAL` due to bad flags).
Second, there is no way to efficiently skip over portions of a sparse
file that are known to contain all zeroes.  Finally, it is not
possible to reliably decode the server traffic without also having
context of what pending read requests were sent by the client.

To remedy this, a `STRUCTURED_REPLY` extension is envisioned. This
extension adds a new transmission phase message type, a new option
request, a new transmission flag, a new command flag, a new command
error, and alters the reply to the `NBD_CMD_READ` request.

* Transmission phase

    A structured reply in the transmission phase consists of one or
    more structured reply chunk messages.  The server MUST NOT send
    this reply type unless the client has successfully negotiated
    structured replies via `NBD_OPT_STRUCTURED_REPLY`.  Conversely, if
    structured replies are negotiated, the server MUST use a
    structured reply for any response with a payload, and MUST NOT use
    a simple reply for `NBD_CMD_READ` (even for the case of an early
    `EINVAL` due to bad flags), but MAY use either a simple reply or a
    structured reply to all other requests.  The server SHOULD prefer
    sending errors via a structured reply, as the error can then be
    accompanied by a UTF-8 text payload to present to a human user.

    A structured reply MAY occupy multiple structured chunk messages
    (all with the same value for "handle"), and the
    `NBD_REPLY_FLAG_DONE` reply flag is used to identify the final
    chunk.  Unless further documented by individual requests below,
    the chunks MAY be sent in any order, except that the chunk with
    the flag `NBD_REPLY_FLAG_DONE` MUST be sent last.  Even when a
    command documents further constraints between chunks of one reply,
    it is always safe to interleave chunks of that reply with messages
    related to other requests.  A server SHOULD try to minimize the
    number of chunks sent in a reply, but MUST NOT mark a chunk as
    final if there is still a possibility of detecting an error before
    transmission of that chunk completes.  A structured reply is
    considered successful only if it did not contain any error chunks,
    although the client MAY be able to determine partial success based
    on the chunks received.

    A structured reply chunk message looks as follows:

    S: 32 bits, 0x668e33ef, magic (`NBD_STRUCTURED_REPLY_MAGIC`)  
    S: 16 bits, flags  
    S: 16 bits, type  
    S: 64 bits, handle  
    S: 32 bits, length of payload (unsigned)  
    S: *length* bytes of payload data (if *length* is non-zero)  

    The use of *length* in the reply allows context-free division of
    the overall server traffic into individual reply messages; the
    *type* field describes how to further interpret the payload.

  * Structured reply flags

    This field of 16 bits is sent by the server as part of every
    structured reply.

    - bit 0, `NBD_REPLY_FLAG_DONE`; the server MUST clear this bit if
      more structured reply chunks will be sent for the same client
      request, and MUST set this bit if this is the final reply.  This
      bit MUST always be set for the `NBD_REPLY_TYPE_NONE` chunk,
      although any other chunk type can also be used as the final
      chunk.

    The server MUST NOT set any other flags without first negotiating
    the extension with the client, unless the client can usefully
    react to the response without interpreting the flag (for instance
    if the flag is some form of hint).  Clients MUST ignore
    unrecognized flags.

  * Structured Reply types

    These values are used in the "type" field of a structured reply.
    Some chunk types can additionally be categorized by role, such as
    *error chunks* or *content chunks*.  Each type determines how to
    interpret the "length" bytes of payload.  If the client receives
    an unknown or unexpected type, it MUST close the connection.

    - `NBD_REPLY_TYPE_NONE` (0)

      *length* MUST be 0 (and the payload field omitted).  This chunk
      type MUST always be used with the `NBD_REPLY_FLAG_DONE` bit set
      (that is, it may appear at most once in a structured reply, and
      is only useful as the final reply chunk).  If no earlier error
      chunks were sent, then this type implies that the overall client
      request is successful.  Valid as a reply to any request.

    - `NBD_REPLY_TYPE_ERROR` (1)

      This chunk type is in the error chunk category.  *length* MUST
      be at least 4.  This chunk represents that an error occurred,
      and the client MAY NOT make any assumptions about partial
      success. This type SHOULD NOT be used more than once in a
      structured reply.  Valid as a reply to any request.

      The payload is structured as:

      32 bits: error (MUST be nonzero)  
      *length - 4* bytes: (optional UTF-8 encoded data suitable for
         direct display to a human being, with no embedded or
         terminating NUL characters)  

    - `NBD_REPLY_TYPE_ERROR_OFFSET` (2)

      This chunk type is in the error chunk category.  *length* MUST
      be at least 12.  This reply represents that an error occurred at
      a given offset, which MUST lie within the original offset and
      length of the request; the client can use this offset to
      determine if request had any partial success.  This chunk type
      MAY appear multiple times in a structured reply, although the
      same offset SHOULD NOT be repeated.  Likewise, if content chunks
      were sent earlier in the structured reply, the server SHOULD NOT
      send multiple distinct offsets that lie within the bounds of a
      single content chunk.  Valid as a reply to `NBD_CMD_READ`,
      `NBD_CMD_WRITE`, `NBD_CMD_WRITE_ZEROES`, and `NBD_CMD_TRIM`.

      The payload is structured as:

      32 bits: error (MUST be nonzero)  
      64 bits: offset (unsigned)  
      *length - 12* bytes: (optional UTF-8 encoded data suitable for
         direct display to a human being, with no embedded or
         terminating NUL characters)  

    - `NBD_REPLY_TYPE_OFFSET_DATA` (3)

      This chunk type is in the content chunk category.  *length* MUST
      be at least 9.  It represents the contents of *length - 8* bytes
      of the file, starting at *offset*.  The data MUST lie within the
      bounds of the original offset and length of the client's
      request, and MUST NOT overlap with the bounds of any earlier
      content chunk or error chunk in the same reply.  This chunk may
      be used more than once in a reply, unless the `NBD_CMD_FLAG_DF`
      flag was set.  Valid as a reply to `NBD_CMD_READ`.

      The payload is structured as:

      64 bits: offset (unsigned)  
      *length - 8* bytes: data  

    - `NBD_REPLY_TYPE_OFFSET_HOLE` (4)

      This chunk type is in the content chunk category.  *length* MUST
      be exactly 12.  It represents that the contents of *hole size*
      bytes starting at *offset* read as all zeroes.  The hole MUST
      lie within the bounds of the original offset and length of the
      client's request, and MUST NOT overlap with the bounds of any
      earlier content chunk or error chunk in the same reply.  This
      chunk may be used more than once in a reply, unless the
      `NBD_CMD_FLAG_DF` flag was set.  Valid as a reply to
      `NBD_CMD_READ`.

      The payload is structured as:

      64 bits: offset (unsigned)  
      32 bits: hole size (unsigned, MUST be nonzero)  

* `NBD_OPT_STRUCTURED_REPLY`

    The client wishes to use structured replies during the
    transmission phase.  The option request has no additional data.

    The server replies with the following:

    - `NBD_REP_ACK`: Structured replies have been negotiated; the
      server MUST use structured replies to the `NBD_CMD_READ`
      transmission request.  Other extensions that require structured
      replies may now be negotiated.
    - For backwards compatibility, clients should be prepared to also
      handle `NBD_REP_ERR_UNSUP`; in this case, no structured replies
      will be sent.

    It is envisioned that future extensions will add other new
    requests that may require a data payload in the reply.  A server
    that supports such extensions SHOULD NOT advertise those
    extensions until the client negotiates structured replies; and a
    client MUST NOT make use of those extensions without first
    enabling the `NBD_OPT_STRUCTURED_REPLY` extension.

* `NBD_FLAG_SEND_DF`

    The server MUST set this transmission flag to 1 if the
    `NBD_CMD_READ` request supports the `NBD_CMD_FLAG_DF` flag, and
    MUST leave this flag clear if structured replies have not been
    negotiated. Clients MUST NOT set the `NBD_CMD_FLAG_DF` request
    flag unless this transmission flag is set.

* `NBD_CMD_FLAG_DF`

    The "don't fragment" flag, valid during `NBD_CMD_READ`.  SHOULD be
    set to 1 if the client requires the server to send at most one
    content chunk in reply.  MUST NOT be set unless the transmission
    flags include `NBD_FLAG_SEND_DF`.  Use of this flag MAY trigger an
    `EOVERFLOW` error chunk, if the request length is too large.

* `EOVERFLOW`

    The server SHOULD return `EOVERFLOW`, rather than `EINVAL`, when a
    client has requested `NBD_CMD_FLAG_DF` for a length that is too
    large to read without fragmentation.  The server MUST NOT return
    this error if the read request did not exceed 65,536 bytes, and
    SHOULD NOT return this error if `NBD_CMD_FLAG_DF` is not set.

* `NBD_CMD_READ`

    If structured replies were not negotiated, then a read request
    MUST always be answered by a simple reply, as documented above
    (using magic 0x67446698 `NBD_SIMPLE_REPLY_MAGIC`, and containing
    length bytes of data according to the client's request, although
    those bytes MAY be invalid if an error is returned, and the
    connection MUST be closed if an error occurs after a header
    claiming no error).

    If structured replies are negotiated, then a read request MUST
    result in a structured reply with one or more chunks (each using
    magic 0x668e33ef `NBD_STRUCTURED_REPLY_MAGIC`), where the final
    chunk has the flag `NBD_REPLY_FLAG_DONE`, and with the following
    additional constraints.

    The server MAY split the reply into any number of content chunks;
    each chunk MUST describe at least one byte, although to minimize
    overhead, the server SHOULD use chunks with lengths and offsets as
    an integer multiple of 512 bytes, where possible (the first and
    last chunk of an unaligned read being the most obvious places for
    an exception).  The server MUST NOT send content chunks that
    overlap with any earlier content or error chunk, and MUST NOT send
    chunks that describe data outside the offset and length of the
    request, but MAY send the content chunks in any order (the client
    MUST reassemble content chunks into the correct order), and MAY
    send additional content chunks even after reporting an error chunk.
    Note that a request for more than 2^32 - 8 bytes MUST be split
    into at least two chunks, so as not to overflow the length field
    of a reply while still allowing space for the offset of each
    chunk.  When no error is detected, the server MUST send enough
    data chunks to cover the entire region described by the offset and
    length of the client's request.

    To minimize traffic, the server MAY use a content or error chunk
    as the final chunk by setting the `NBD_REPLY_FLAG_DONE` flag, but
    MUST NOT do so for a content chunk if it would still be possible
    to detect an error while transmitting the chunk.  The
    `NBD_REPLY_TYPE_NONE` chunk is always acceptable as the final
    chunk.

    If an error is detected, the server MUST still complete the
    transmission of any current chunk (it MUST use padding bytes which
    SHOULD be zero, for any remaining data portion of a chunk with
    type `NBD_REPLY_TYPE_OFFSET_DATA`), but MAY omit further content
    chunks.  The server MUST include an error chunk as one of the
    subsequent chunks, but MAY defer the error reporting behind other
    queued chunks.  An error chunk of type `NBD_REPLY_TYPE_ERROR`
    implies that the client MAY NOT make any assumptions about
    validity of data chunks (whether sent before or after the error
    chunk), and if used, SHOULD be the only error chunk in the reply.
    On the other hand, an error chunk of type
    `NBD_REPLY_TYPE_ERROR_OFFSET` gives fine-grained information about
    which earlier data chunk(s) encountered a failure; as such, a
    server MAY still usefully follow it with further non-overlapping
    content chunks or with error offsets for other content chunks.
    The server MAY send an error chunk with no corresponding content
    chunk, but MUST ensure that the content chunk is sent first if a
    content and error chunk cover the same offset.  Generally, a
    server SHOULD NOT mix errors with offsets with a generic error.
    As long as all errors are accompanied by offsets, the client MAY
    assume that any data chunks with no subsequent error offset are
    valid, that chunks with an overlapping error offset errors are
    valid up until the reported offset, and that portions of the read
    that do not have a corresponding content chunk are not valid.

    A client MAY close the connection if it detects that the server
    has sent invalid chunks (such as overlapping data, or not enough
    data before claiming success).

    In order to avoid the burden of reassembly, the client MAY set the
    `NBD_CMD_FLAG_DF` flag ("don't fragment").  If this flag is set,
    the server MUST send at most one content chunk, although it MAY
    still send multiple chunks (the remaining chunks would be error
    chunks or a final type of `NBD_REPLY_TYPE_NONE`).  If the area
    being read contains both data and a hole, the server MUST use
    `NBD_REPLY_TYPE_OFFSET_DATA` with the zeroes explicitly present.
    A server MAY reject a client's request with the error `EOVERFLOW`
    if the length is too large to send without fragmentation, in which
    case it MUST NOT send a content chunk; however, the server MUST
    support unfragmented reads in which the client's request length
    does not exceed 65,536 bytes.

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
