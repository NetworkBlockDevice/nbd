# The NBD protocol

The NBD protocol has two phases: the handshake (in which the connection
is established, an exported NBD device is negotiated between the client
and the server, and protocol options are negotiated), and the data
pushing phase (in which the client and server are communicating between
eachother).

On the client side under Linux, the handshake is implemented in
userspace, while the data pushing phase is implemented in kernel space.
To get from the handshake to the data pushing phase, the client performs

    ioctl(nbd, NBD_SET_SOCK, sock)
    ioctl(nbd, NBD_DO_IT)

with `nbd` in the above ioctl being a file descriptor for an open
`/dev/nbdX` device node, and `sock` being the socket to the server. The
second of the two above ioctls does not return until the client
disconnects.

Note that there are other `ioctl`s available, that are used by the client
to communicate the options to the kernel which were negotiated with the
server during the handshake.

There are two message types in the data pushing phase: the request, and
the response.

There are five request types in the data pushing phase: `NBD_CMD_READ`,
`NBD_CMD_WRITE`, `NBD_CMD_DISC` (disconnect), `NBD_CMD_FLUSH`, `NBD_CMD_TRIM`.

The request is sent by the client; the response by the server. A request
header consists a 32 bit magic number (magic), a 32 bit field denoting
the request type (see below; 'type'), a 64 bit handle ('handle'), a 64
bit data offset ('from'), and a 32 bit length ('len'). In case of a
write request, the header is immediately followed by 'len' bytes of
data. In the case of `NBD_CMD_FLUSH`, the offset and length should
be zero (meaning "flush entire device"); other values are reserved
for future use (e.g. for flushing specific areas without a write).

Bits 16 and above of the commands are reserved for flags.  Right
now, the only flag is `NBD_CMD_FLAG_FUA` (bit 16), "Force unit access".

The reply contains three fields: a 32 bit magic number ('magic'), a 32
bit error code ('error'; 0, unless an error occurred in which case it is
one of the error values documented below), and the same 64 bit handle
that the corresponding request had in its 'handle' field. In case the
reply is sent in response to a read request and the error field is 0
(zero), the reply header is immediately followed by request.len bytes of
data.

In case of a disconnect request, the server will immediately close the
connection. Requests are currently handled synchronously; when (not if)
we change that to asynchronous handling, handling the disconnect request
will probably be postponed until there are no other outstanding
requests.

A flush request will not be sent unless `NBD_FLAG_SEND_FLUSH` is set,
and indicates the backing file should be fdatasync()'d to disk.

The top 16 bits of the request are flags. `NBD_CMD_FLAG_FUA` implies
a force unit access, and can currently only be usefully combined
with `NBD_CMD_WRITE`. This is implemented using sync_file_range
if present, else by fdatasync() of that file (note not all files
in a multifile environment). `NBD_CMD_FLAG_FUA` will not be set
unless `NBD_FLAG_SEND_FUA` is set.

## Error values

The following error values are defined:

    Integer value    Short name     Description
    -------------------------------------------------------------
       1             EPERM          Operation not permitted
       5             EIO            Input/output error
      12             ENOMEM         Cannot allocate memory
      22             EINVAL         Invalid argument
      28             ENOSPC         No space left on device

The server should return `ENOSPC` if it receives a write request including
one or more sectors beyond the size of the device.  It should return
`EINVAL` if it receives a read or trim request including one or more
sectors beyond the size of the device.  It also should map the `EDQUOT`
and `EFBIG` errors to `ENOSPC`.  Finally, it should return `EPERM` if it
receives a write or trim request on a read-only export.  Which error to
return in any other case is not specified by the NBD protocol.

## Negotiation

There are two versions of the negotiation: the 'old' style (nbd <=
2.9.16) and the 'new' style (nbd >= 2.9.17, though due to a bug it does
not work with anything below 2.9.18). What follows is a description of
both cases (in the below description, the label 'C:' is used for
messages sent by the client, whereas 'S:' is used for messages sent by
the server). "quoted text" is for literal character data, '0xdeadbeaf'
is used for literal hex numbers (which are always sent in network byte
order), and (brackets) are used for comments. Anything else is a
description of the data that is sent.

### 'old' style handshake

S: "NBDMAGIC" (the `INIT_PASSWD` in the code)  
S: 0x00420281861253 (`cliserv_magic`, a magic number)  
S: size of the export in bytes, 64 bit unsigned int  
S: flags, 4 bytes  
S: 124 bytes of zeroes (registered for future use, yes this is
   excessive).

As can be seen, this isn't exactly a negotiation; it's just the server
sending a bunch of data to the client. If the client is unhappy with
what he receives, he's supposed to disconnect and not look back.

The fact that the size of the export was specified before the flags were
sent, made it impossible for the protocol to be changed in a
backwards-compatible manner to allow for named exports without ugliness.
As a result, the old style negotiation is now no longer developed, and
only still supported for backwards compatibility.

### 'new' style handshake

A client who wants to use the new style negotiation should connect on
the IANA-reserved port for NBD, 10809. The server may listen on other
ports as well, but it will use the old style handshake on those. The
server will refuse to allow old-style negotiations on the new-style
port. For debugging purposes, the server may change the port on which to
listen for new-style negotiation, but this should not happen for
production purposes.

S: "NBDMAGIC" (as in the old style handshake)
S: 0x49484156454F5054 (note different magic number)
S: 16 bits of zero (bits 1-15 reserved for future use; bit 0 in use to
   signal fixed newstyle (see below))
C: 32 bits of zero (reserved for future use)

This completes the initial phase of negotiation; the client and server
now both know they understand the first version of the new-style
handshake, with no options. What follows is a repeating group of
options. Currently only one option can be set (the name of the export to
be used), and it is not optional; but future protocol extensions may add
other options that may or may not be optional. Once extra protocol
options have been added, the order in which these options are set will
not be significant.

The generic format of setting an option is as follows:

C: 0x49484156454F5054 (note same new-style handshake's magic number)  
C: 32 bits denoting the chosen option (`NBD_OPT_EXPORT_NAME` is the only
   possible value in this version of the protocol)  
C: unsigned 32 bit length of option data  
C: (any data needed for the chosen option)  

The presence of the option length in every option allows the server
to skip any options presented by the client that it does not
understand.

The data needed for the `NBD_OPT_EXPORT_NAME` option is:

C: name of the export (character string of length as specified,
   not terminated by any NUL bytes or similar)

Once all options are set, the server replies with information about the
used export:

S: size of the export in bytes, 64 bit unsigned int  
S: flags (16 bits unsigned int)  
S: 124 bytes of zeroes (forgot to remove that, oops)  

The reason that the flags field is 16 bits large and not 32 as in the
old style of the protocol is that there are now 16 bits of per-export
flags, and 16 bits of per-server flags. Concatenated together, this
results in 32 bits, which allows for using a common set of macros for
both; indeed, the code masks away the upper or lower bits of a 32 bit
"flags" field when performing the new-style handshake. If we ever run
out of flags, the server will set the most significant flag bit,
signalling that an extra flag field will follow, to which the client
will have to reply with a flag field of its own before the extra flags
are sent. This is not yet implemented.

### Fixed 'new' style handshake

Unfortunately, due to a mistake on my end, the server would immediately
close the connection when it saw an option it did not understand, rather
than signalling this fact to the client, which would've allowed it to
retry; and replies from the server were not structured either, which
meant that if the server were to send something the client did not
understand, it would have to abort negotiation as well.

To fix these two issues, the handshake has been extended once more:

- The server will set bit 0 of its first set of reserved flags, to
  signal that it supports this version of the protocol.
- The client should reply with bit 0 set in its reserved field too,
  though its side of the protocol does not change incompatibly.
- The client may now send other options to the server as appropriate, in
  the generic format for sending an option as described above.
- The server will reply to any option apart from `NBD_OPT_EXPORT_NAME`
  with reply packets in the following format:

S: 64 bits, `0x3e889045565a9` (magic number for replies)  
S: 32 bits, the option as sent by the client to which this is a reply
   packet.  
S: 32 bits, denoting reply type (e.g., `NBD_REP_ACK` to denote successful
   completion, or `NBD_REP_ERR_UNSUP` to denote use of an option not known
   by this server  
S: 32 bits, length of the reply. This may be zero for some replies, in
   which case the next field is not sent  
S: any data as required by the reply (e.g., an export name in the case
   of `NBD_REP_SERVER`

As there is no unique number for client requests, clients who want to
differentiate between answers to two instances of the same option during
any negotiation must make sure they've seen the answer to an outstanding
request before sending the next one of the same type.

## Values

This section describes the meaning of constants (other than magic
numbers) in the protocol handshake.

### Flag bits

* Per-export (16 bits, sent after option haggling, or immediately after
  the global flag field in oldstyle negotiation):

    bit 0 - `NBD_FLAG_HAS_FLAGS`

    should always be 1

    bit 1 - `NBD_FLAG_READ_ONLY`

    should be set to 1 if the export is read-only

    bit 2 - `NBD_FLAG_SEND_FLUSH`

    should be set to 1 if the server supports `NBD_CMD_FLUSH` commands

    bit 3 - `NBD_FLAG_SEND_FUA`

    should be set to 1 if the server supports the `NBD_CMD_FLAG_FUA` flag

    bit 4 - `NBD_FLAG_ROTATIONAL`

    should be set to 1 to let the client schedule I/O accesses as for a
    rotational medium

    bit 5 - `NBD_FLAG_SEND_TRIM`

    should be set to 1 if the server supports `NBD_CMD_TRIM` commands

* Global flag bits (16 bits, after initial connection):

    bit 0 - `NBD_FLAG_FIXED_NEWSTYLE`

    should be set by servers that support the fixed newstyle protocol

    bit 1 - `NBD_FLAG_NO_ZEROES`

    If set, and if the client sets `NBD_FLAG_C_NO_ZEROES`, then the 124
    bytes of zero at the end of the negotiation will not be sent by the
    server.

* Client (after initial connection and after receiving flags from
  server):

    bit 0 - `NBD_FLAG_C_FIXED_NEWSTYLE`
    Should be set by clients that support the fixed newstyle protocol.
    Servers may choose to honour fixed newstyle from clients that didn't
    set this bit, but relying on this isn't recommended.

    bit 1 - `NBD_FLAG_C_NO_ZEROES`
    MUST only be set if the server also sets `NBD_FLAG_NO_ZEROES`. If set,
    the server MUST NOT send the 124 bytes of zeroes at the end of the
    negotiation.

### Option types

- `NBD_OPT_EXPORT_NAME` (1)

    Choose the export which the client would like to use, and end option
    haggling. Data: name of the export, free-form UTF8 text (subject to
    limitations by server implementation). If the chosen export does not
    exist or requirements for the chosen export are not met (e.g., the
    client did not negotiate TLS for an export where the server requires
    it), the server should close the connection.

    A special, "empty", name (i.e., the length field is zero and no name
    is specified), is reserved for a "default" export, to be used in cases
    where explicitly specifying an export name makes no sense.

- `NBD_OPT_ABORT` (2)

    Abort negotiation and close the connection. Optional.

- `NBD_OPT_LIST` (3)

    Returns a number of `NBD_REP_SERVER` replies, one for each export,
    followed by an `NBD_REP_ACK`. No flags should be sent.

- `NBD_OPT_PEEK_EXPORT` (4)

    defined by the experimental `PEEK_EXPORT` extension; see below.

- `NBD_OPT_STARTTLS` (5)

    defined by the experimental STARTTLS extension; see below.

### Reply types

- `NBD_REP_ACK` (1)

    Will be sent by the server when it accepts the option, or when sending
    data related to the option (in the case of `NBD_OPT_LIST`) has finished.
    No data.

* `NBD_REP_SERVER` (2)

    A description of an export. Data:

    - 32 bits, length of name
    - Name of the export, as expected by `NBD_OPT_EXPORT_NAME`
    - If length of name < (length of reply as sent in the reply packet
      header - 4), then the rest of the data contains some undefined
      implementation-specific details about the export. This is not
      currently implemented, but future versions of nbd-server may send
      along some details about the export. If the client did not
      explicitly request otherwise, these details are defined to be UTF-8
      encoded data suitable for direct display to a human being.
    - The experimental `PEEK_EXPORT` extension (see below) will add extra
      data to the end of this request.

* `NBD_REP_STARTTLS` (3)

    defined by the experimental STARTTLS extension; see below.

There are a number of error reply types, all of which are denoted by
having bit 31 set. All error replies may have some data set, in which
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

    The option sent by the client is know by this server, but was
    determined by the server to be syntactically invalid. For instance,
    the client sent an `NBD_OPT_LIST` with nonzero data length.

* `NBD_REP_ERR_PLATFORM` (2^31 + 4)

    The option sent by the client is not supported on the platform on
    which the server is running. Not currently used.

* `NBD_REP_ERR_TLS_REQD` (2^31 + 5)

    defined by the experimental `STARTTLS` extension; see below.

### Request types

The following request types exist:

* `NBD_CMD_READ` (0)

    A read request. Length and offset define the data to be read. The
    server MUST reply with a reply header, followed immediately by len
    bytes of data, read offset bytes into the file, unless an error
    condition has occurred.

* `NBD_CMD_WRITE` (1)

    A write request. Length and offset define the location and amount of
    data to be written. The server should write the data to disk, and then
    send the reply header. However, the server does not need to ensure
    that all data has hit the disk, unless the `NBD_CMD_FLAG_FUA` flag is
    set (bit 16).

* `NBD_CMD_DISC` (2)

    A disconnect request. The server MUST handle all outstanding
    requests, and then close the connection.
    A client MUST NOT send anything to the server after sending an
    `NBD_CMD_DISC` command.

* `NBD_CMD_FLUSH` (3)

    A flush request; a write barrier. The server MUST NOT send a successful
    reply header for this request before all write requests that were
    completed before this command have hit the disk (using fsync() or similar).
    In this command, "len" and "offset" are reserved, and should be set to
    all-zero.

* `NBD_CMD_TRIM` (4)

    A hint to the server that the data defined by len and offset is no
    longer needed. A server MAY discard len bytes starting at offset, but
    is not required to.

    After issuing this command, a client MUST NOT make any assumptions
    about the contents of the export affected by this command, until
    overwriting it again with `NBD_CMD_WRITE`.

* `NBD_CMD_CACHE` (5)

    This command is defined by xnbd.

## Experimental extensions

The specifications in this section are non-normative and experimental.
They are not currently implemented by any known version of the nbd
protocol; a first implementation may require changes to the
specifications in this section.

Therefore, implementors are strongly suggested to contact the
mailinglist in order to help fine-tune the specifications in this
section before committing to a particular implementation.

### `PEEK_EXPORT` extension

The STARTTLS extension (see below) needed a way to figure out whether an
export requires TLS. For that, we need a generic way to request
information on an export.

This extension adds one option request, and extends one option reply

* `NBD_OPT_PEEK_EXPORT`

    Request one `NBD_REP_SERVER` packet with flags. The server SHOULD NOT
    finish with an `NBD_REP_ACK` packet.

* `NBD_REP_SERVER`

    If this was sent in reply to an `NBD_OPT_PEEK_EXPORT` command, then the
    name of the export is followed by a 32-bit "flags" field, describing
    properties about the export:

    - `NBD_F_EXP_RO` (0): if set, this export is read-only
    - `NBD_F_EXP_COW` (1): if set, the export has copy-on-write semantics;
      writes are lost after disconnect, and writes to this device will
      not be seen by other clients. SHOULD NOT be set if `NBD_F_EXP_RO` is
      set.
    - `NBD_F_EXP_TLS_OK` (2): if set, the export allows TLS.
    - `NBD_F_EXP_TLS_REQ` (3): if set, the export requires TLS. MUST NOT
      be set unless `NBD_F_EXP_TLS_OK` is also set. If this flag is set, a
      server MAY vary the state of the other flags in this flags field
      depending on whether TLS is enabled; a client SHOULD NOT assume
      that the other data is correct until TLS has been negotiated and
      this command re-issued.

    It follows that an `NBD_REP_SERVER` packet with flags should have
    the "length of name" field be equal to "length of reply - 8".

### `STARTTLS` extension

To implement secure NBD connections, a STARTTLS extension is envisioned.
This extension adds one option request, one option reply, and one error
type.

* `NBD_OPT_STARTTLS` (5)

    The client wishes to initiate TLS. If the server replies
    with `NBD_REP_STARTTLS`, then the client should immediately initiate a
    TLS handshake and continue the negotiation in the encrypted channel.
    If the server is unwilling to perform TLS, it should reply with
    `NBD_REP_ERR_POLICY`. For backwards compatibility, a client should also
    be prepared to handle `NBD_REP_ERR_UNSUP`. If the client sent along any
    data with the request, the server should send back
    `NBD_REP_ERR_INVALID`.

* `NBD_REP_STARTTLS` (3)

    An affirmative reply to `NBD_OPT_STARTTLS`. Length should be zero. The
    very next byte read from the client should be assumed to be the first
    byte in a TLS handshake.

* `NBD_REP_ERR_TLS_REQD`

    The server is unwilling to continue negotiation unless TLS is
    negotiated first. A server MUST NOT send this error if it has one or
    more exports that do not require TLS; not even if the client indicated
    interest (by way of `NBD_OPT_PEEK_EXPORT`) in an export which requires
    TLS.

    If this reply is used, servers SHOULD send it in reply to each and every
    unencrypted `NBD_OPT_*` message (apart from `NBD_OPT_STARTTLS`).

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
