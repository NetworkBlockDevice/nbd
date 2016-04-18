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
an implementation detail of the server.

## Conventions

In the below protocol descriptions, the label 'C:' is used for messages
sent by the client, whereas 'S:' is used for messages sent by the
server).  `monotype text` is for literal character data or (when used in
comments) constant names, `0xdeadbeef` is used for literal hex numbers
(which are always sent in network byte order), and (brackets) are used
for comments. Anything else is a description of the data that is sent.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL",
"SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt).
The same words in lower case carry their natural meaning.

Where this document refers to a string, then unless otherwise stated,
that string is a sequence of UTF-8 code points, which is not `NUL`
terminated, MUST NOT contain `NUL` characters, SHOULD be no longer than
256 bytes and MUST be no longer than 4096 bytes. This applies
to export names and error messages (amongst others). The length of a
string is always available through information sent earlier in the same
message, although it may require some computation based on the size of
other data also present in the same message.

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
listen for newstyle negotiation, but this SHOULD NOT happen for
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
it does not recognize, while the server MUST close the TCP connection if
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

If the server is unwilling to allow the export, it MUST terminate
the session.

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
- The client SHOULD reply with `NBD_FLAG_C_FIXED_NEWSTYLE` set in its flags
  field too, though its side of the protocol does not change incompatibly.
- The client MAY now send other options to the server as appropriate, in
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
S: 32 bits, length of the reply. This MAY be zero for some replies, in
   which case the next field is not sent  
S: any data as required by the reply (e.g., an export name in the case
   of `NBD_REP_SERVER`)  

As there is no unique number for client requests, clients who want to
differentiate between answers to two instances of the same option during
any negotiation must make sure they've seen the answer to an outstanding
request before sending the next one of the same type. The server MAY
send replies in the order that the requests were received, but is not
required to.

#### Termination of the session during option haggling

There are three possible mechanisms to end option haggling:

* Transmission mode can be entered (by the client sending
  `NBD_OPT_EXPORT_NAME` or by the server responding to an
  `NBD_OPT_GO` with `NBD_REP_ACK`). This is documented
  elsewhere.

* The client can send (and the server can reply to) an
  `NBD_OPT_ABORT`. This MUST be followed by the client
  shutting down TLS (if it is running), and the client
  dropping the connection. This is referred to as
  'initiating a soft disconnect'; soft disconnects can
  only be initiated by the client.

* The client or the server can disconnect the TCP session
  without activity at the NBD protocol level. If TLS is
  negotiated, the party initiating the transaction SHOULD
  shutdown TLS first if it is running. This is referred
  to as 'initiating a hard disconnect'.

This section concerns the second and third of these, together
called 'terminating the session', and under which circumstances
they are valid.

If either the client or the server detects a violation of a
mandatory condition ('MUST' etc.) by the other party, it MAY
initiate a hard disconnect.

A client MAY use a soft disconnect to terminate the session
whenever it wishes.

A party that is mandated by this document to terminate the
session MUST initiate a hard disconnect if it is not possible
to use a soft disconnect. Such circumstances include: where
that party is the server and it cannot return an error
(e.g. after an `NBD_OPT_EXPORT_NAME` it cannot satisfy),
and where that party is the client following a failed TLS
negotiation.

A party MUST NOT initiate a hard disconnect save where set out
in this section. Therefore, unless a client's situation falls
within the provisions of the previous paragraph or the
client detects a breach of a mandatory condition, it MUST NOT
use a hard disconnect, and hence its only option to terminate
the session is via a soft disconnect.

There is no requirement for the client or server to complete a
negotiation if it does not wish to do so. Either end MAY simply
terminate the session. In the client's case, if it wishes to
do so it MUST use soft disconnect.

In the server's case it MUST (save where set out above) simply
error inbound options until the client gets the hint that it is
unwelcome, except that if a server believes a client's behaviour
constitutes a denial of service, it MAY initiate a hard disconnect.
If the server is in the process of being shut down it MAY
error inflight options and SHOULD error further options received
(other than an `NBD_OPT_ABORT`) with `NBD_REP_ERR_SHUTDOWN`.

If the client receives `NBD_REP_ERR_SHUTDOWN` it MUST initiate
a soft disconnect.

### Transmission

There are two message types in the transmission phase: the request,
and the reply.  The
transmission phase consists of a series of transactions, where the
client submits requests and the server sends corresponding replies.
The phase continues until
either side terminates transmission; this can be performed cleanly
only by the client.

Replies need not be sent in the same order as requests (i.e., requests
may be handled by the server asynchronously).
Clients SHOULD use a handle that is distinct from all other currently
pending transactions, but MAY reuse handles that are no longer in
flight; handles need not be consecutive.  In each reply message
the server MUST use the same value for
handle as was sent by the client in the corresponding request.  In
this way, the client can correlate which request is receiving a
response.

#### Ordering of messages and writes

The server MAY process commands out of order, and MAY reply out of
order, except that:

* All write commands (that includes `NBD_CMD_WRITE`,
  and `NBD_CMD_TRIM`) that the server
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

#### Reply message

The reply message MUST be sent by the server in response to all
requests (save for `NBD_CMD_DISC`). The message looks as
follows:

S: 32 bits, 0x67446698, magic (`NBD_REPLY_MAGIC`)  
S: 32 bits, error (MAY be zero)  
S: 64 bits, handle  
S: (*length* bytes of data if the request is of type `NBD_CMD_READ`)  

#### Terminating the transmission phase

There are two methods of terminating the transmission phase:

* The client sends `NBD_CMD_DISC` whereupon the server MUST
  close down the TLS session (if one is running) and then
  close the TCP connection. This is referred to as 'initiating
  a soft disconnect'. Soft disconnects can only be
  initiated by the client.

* The client or the server drops the TCP session (in which
  case it SHOULD shut down the TLS session first). This is
  referred to as 'initiating a hard disconnect'.

Together these are referred to as 'terminating transmission'.

Either side MAY initiate a hard disconnect if it detects
a violation by the other party of a mandatory condition
within this document.

On a server shutdown, the server SHOULD wait for inflight
requests to be serviced prior to initiating a hard disconnect.
A server MAY speed this process up by issuing error replies.
The error value issued in respect of these requests and
any subsequently received requests SHOULD be `ESHUTDOWN`.

If the client receives an `ESHUTDOWN` error it MUST initiate
a soft disconnect.

The client MAY issue a soft disconnect at any time, but
SHOULD wait until there are no inflight requests first.

The client and the server MUST NOT initiate any form
of disconnect other than in one of the above circumstances.

## TLS support

The NBD protocol supports Transport Layer Security (TLS) (see
[RFC5246](https://tools.ietf.org/html/rfc5246)
as updated by
[RFC6176](https://tools.ietf.org/html/rfc6176)
).

TLS is negotiated with the `NBD_OPT_STARTTLS`
option. This is performed as an in-session upgrade. Below the term
'negotiation' is used to refer to the sending and receiving of
NBD options and option replies, and the term 'initiation' of TLS
is used to refer to the actual upgrade to TLS.

### Certificates, authentication and authorisation

This standard does not specify what encryption, certification
and signature algorithms are used. This standard does not
specify authentication and authorisation (for instance
whether client and/or server certificates are required and
what they should contain); this is implementation dependent.

TLS requires fixed newstyle negotiation to have completed.

### Server-side requirements

There are three modes of operation for a server. The
server MUST support one of these modes.

* The server operates entirely without TLS ('NOTLS'); OR

* The server insists upon TLS, and forces the client to
  upgrade by erroring any NBD options other than `NBD_OPT_STARTTLS`
  with `NBD_REP_ERR_TLS_REQD` ('FORCEDTLS'); this in practice means
  that all option negotiation (apart from the `NBD_OPT_STARTTLS`
  itself) is carried out with TLS; OR

* The server provides TLS, and it is mandatory on zero or more
  exports, and is available at the client's option on all
  other exports ('SELECTIVETLS'). The server does not force
  the client to upgrade to TLS during option haggling (as
  if the client ultimately were to choose a non-TLS-only export,
  stopping TLS is not possible). Instead it permits the client
  to upgrade as and when it chooses, but unless an upgrade to
  TLS has already taken place, the server errors attempts
  to enter transmission mode on TLS-only exports, MAY
  refuse to provide information about TLS-only exports
  via `NBD_OPT_INFO`, MAY refuse to provide information
  about non-existent exports via `NBD_OPT_INFO`, and MAY omit
  exports that are TLS-only from `NBD_OPT_LIST`.

The server MAY determine the mode in which it operates
dependent upon the session (for instance it might be
more liberal with TCP connections made over the loopback
interface) but it MUST be consistent in its mode
of operation across the lifespan of a single TCP connection
to the server. A client MUST NOT assume indications from
a prior TCP session to a given server will be relevant
to a subsequent session.

The server MUST operate in NOTLS mode unless the server
set flag `NBD_FLAG_FIXED_NEWSTYLE` and the client replied
with `NBD_FLAG_C_FIXED_NEWSTYLE` in the fixed newstyle
negotiation.

These modes of operations are described in detail below.

#### NOTLS mode

If the server receives `NBD_OPT_STARTTLS` it MUST respond with
`NBD_REP_ERR_POLICY` (if it does not support TLS for
policy reasons), `NBD_REP_ERR_UNSUP` (if it does not
support the `NBD_OPT_STARTTLS` option at all) or another
error explicitly permitted by this document. The server MUST NOT
respond to any option request with `NBD_REP_ERR_TLS_REQD`.

#### FORCEDTLS mode

If the server receives `NBD_OPT_STARTTLS` prior to negotiating
TLS, it MUST reply with `NBD_REP_ACK`. If the server receives
`NBD_OPT_STARTTLS` when TLS has already been negotiated, it
it MUST reply with `NBD_REP_ERR_INVALID`.

After an `NBD_REP_ACK` reply has been sent, the server MUST be
prepared for a TLS handshake, and all further data MUST be sent
and received over TLS. There is no downgrade to a non-TLS session.

As per the TLS standard, the handshake MAY be initiated either
by the server (having sent the `NBD_REP_ACK`) or by the client.
If the handshake is unsuccessful (for instance the client's
certificate does not match) the server MUST terminate the
session as by this stage it is too late to continue without TLS
as the acknowledgement has been sent.

If the server receives any other option, including `NBD_OPT_INFO`
and unsupported options, it MUST reply with `NBD_REP_ERR_TLS_REQD`
if TLS has not been initiated; `NBD_OPT_INFO` is included as in this
mode, all exports are TLS-only. If the server receives a request to
enter transmission mode via `NBD_OPT_EXPORT_NAME` when TLS has not
been initiated, then as this request cannot error, it MUST
terminate the session. If the server receives a request to
enter transmission mode via `NBD_OPT_GO` when TLS has not been
initiated, it MUST error with `NBD_REP_ERR_TLS_REQD`.

The server MUST NOT send `NBD_REP_ERR_TLS_REQD` in reply to
any option if TLS has already been initiated.

The FORCEDTLS mode of operation has an implementation problem in
that the client MAY legally simply send a `NBD_OPT_EXPORT_NAME`
to enter transmission mode without previously sending any options.
This is avoided by use of `NBD_OPT_INFO` and `NBD_OPT_GO`.

#### SELECTIVETLS mode

If the server receives `NBD_OPT_STARTTLS` prior to negotiating
TLS, it MUST reply with `NBD_REP_ACK` and initiate TLS as set
out under 'FORCEDTLS' above. If the server receives
`NBD_OPT_STARTTLS` when TLS has already been negotiated, it
it MUST reply with `NBD_REP_ERR_INVALID`.

If the server receives `NBD_OPT_INFO` or `NBD_OPT_GO` and TLS
has not been initiated, it MAY reply with `NBD_REP_ERR_TLS_REQD`
if that export is non-existent, and MUST reply with
`NBD_REP_ERR_TLS_REQD` if that export is TLS-only.

If the server receives a request to enter transmission mode
via `NBD_OPT_EXPORT_NAME` on a TLS-only export when TLS has not
been initiated, then as this request cannot error, it MUST
terminate the session.

The server MUST NOT send `NBD_REP_ERR_TLS_REQD` in reply to
any option if TLS has already been negotiated. The server
MUST NOT send `NBD_REP_ERR_TLS_REQD` in response to any
option other than `NBD_OPT_INFO`, `NBD_OPT_GO` and
`NBD_OPT_EXPORT_NAME`, and only in those cases in respect of
a TLS-only or non-existent export.

There is a degenerate case of SELECTIVETLS where all
exports are TLS-only. This is permitted in part to make programming
of servers easier. Operation is a little different from FORCEDTLS,
as the client is not forced to upgrade to TLS prior to any options
being processed, and the server MAY choose to give information on
non-existent exports via `NBD_OPT_INFO` responses prior to an upgrade
to TLS.

### Client-side requirements

If the client supports TLS at all, it MUST be prepared
to deal with servers operating in any of the above modes.
Notwithstanding, a client MAY always terminate the session or
refuse to connect to a particular export if TLS is
not available and the user requires TLS.

The client MUST NOT issue `NBD_OPT_STARTTLS` unless the server
set flag `NBD_FLAG_FIXED_NEWSTYLE` and the client replied
with `NBD_FLAG_C_FIXED_NEWSTYLE` in the fixed newstyle
negotiation.

The client MUST NOT issue `NBD_OPT_STARTTLS` if TLS has already
been initiated.

Subject to the above two limitations, the client MAY send
`NBD_OPT_STARTTLS` at any time to initiate a TLS session. If the
client receives `NBD_REP_ACK` in response, it MUST immediately
upgrade the session to TLS. If it receives `NBD_REP_ERR_UNSUP`,
`NBD_REP_ERR_POLICY` or any other error in response, it indicates
that the server cannot or will not upgrade the session to TLS,
and therefore the client MUST either continue the session
without TLS, or terminate the session.

A client that prefers to use TLS irrespective of whether
the server makes TLS mandatory SHOULD send `NBD_OPT_STARTTLS`
as the first option. This will ensure option haggling is subject
to TLS, and will thus prevent the possibility of options being
compromised by a Man-in-the-Middle attack. Note that the
`NBD_OPT_STARTTLS` itself may be compromised - see 'downgrade
attacks' for more details. For this reason, a client which only
wishes to use TLS SHOULD terminate the session if the
`NBD_OPT_STARTTLS` replies with an error.

If the TLS handshake is unsuccessful (for instance the server's
certificate does not validate) the client MUST terminate the
session as by this stage it is too late to continue without TLS.

If the client receives an `NBD_REP_ERR_TLS_REQD` in response
to any option, it implies that this option cannot be executed
unless a TLS upgrade is performed. If the option is any
option other than `NBD_OPT_INFO` or `NBD_OPT_GO`, this
indicates that no option will succeed unless a TLS upgrade
is performed; the client MAY therefore choose to issue
an `NBD_OPT_STARTTLS`, or MAY terminate the session (if
for instance it does not support TLS or does not have
appropriate credentials for this server). If the client
receives `NBD_REP_ERR_TLS_REQD` in response to
`NBD_OPT_INFO` or `NBD_OPT_GO` this indicates that the
export referred to within the option is either non-existent
or requires TLS; the client MAY therefore choose to issue
an `NBD_OPT_STARTTLS`, MAY terminate the session (if
for instance it does not support TLS or does not have
appropriate credentials for this server), or MAY continue
in another manner without TLS, for instance by querying
or using other exports.

If a client supports TLS, it SHOULD use `NBD_OPT_GO`
(if the server supports it) in place
of `NBD_OPT_EXPORT_NAME`. The reason for this is set out in
the final paragraphs of the sections under 'FORCEDTLS'
and 'SELECTIVETLS': this gives an opportunity for the
server to transmit that an error going into transmission
mode is due to the client's failure to initiate TLS,
and the fact that the client may obtain information about
which exports are TLS-only through `NBD_OPT_INFO`.

### Security considerations

#### TLS versions

NBD implementations supporting TLS MUST support TLS version 1.2,
SHOULD support any later versions. NBD implementations
MAY support older versions but SHOULD NOT do so by default
(i.e. they SHOULD only be available by a configuration change).
Older versions SHOULD NOT be used where there is a risk of security
problems with those older versions or of a downgrade attack
against TLS versions.

#### Protocol downgrade attacks

A danger inherent in any scheme relying on the negotiation
of whether TLS should be employed is downgrade attacks within
the NBD protocol.

There are two main dangers:

* A Man-in-the-Middle (MitM) hijacks a session and impersonates
  the server (possibly by proxying it) claiming not to support
  TLS. In this manner, the client is confused into operating
  in a plain-text manner with the MitM (with the session possibly
  being proxied in plain-text to the server using the method
  below).

* The MitM hijacks a session and impersonates the client
  (possibly by proxying it) claiming not to support TLS. In
  this manner the server is confused into operating in a plain-text
  manner with the MitM (with the session being possibly
  proxied to the client with the method above).

With regard to the first, any client that does not wish
to be subject to potential downgrade attack SHOULD ensure
that if a TLS endpoint is specified by the client, it
ensures that TLS is negotiated prior to sending or
requesting sensitive data. To recap, the client MAY send
`NBD_OPT_STARTTLS` at any point during option haggling,
and MAY terminate the session if `NBD_REP_ACK` is not
provided.

With regard to the second, any server that does not wish
to be subject to a potential downgrade attack SHOULD either
used FORCEDTLS mode, or should force TLS on those exports
it is concerned about using SELECTIVE mode and TLS-only
exports. It is not possible to avoid downgrade attacks
on exports which may be served either via TLS or in plain
text unless the client insists on TLS.

### Status

This functionality has not yet been implemented by the reference
implementation, but was implemented by qemu and subsequently
by other users, so has been moved out of the "experimental" section.

## Block sizes

During transmission phase, several operations are constrained by the
export size sent by the final `NBD_OPT_EXPORT_NAME` or `NBD_OPT_GO`,
as well as by three block sizes defined here (minimum, preferred, and
maximum).  If a client can honor server block sizes (as set out in
`NBD_OPT_BLOCK_SIZE`), it SHOULD announce this
during the handshake phase, and SHOULD use `NBD_OPT_GO` rather than
`NBD_OPT_EXPORT_NAME`.  A server SHOULD advertise the block size
contraints during handshake phase via `NBD_OPT_INFO`.  A server
and client MAY agree on block sizes via out of band means.

If block sizes have not been advertised or agreed on externally, then
a client SHOULD assume a default minimum block size of 1, a preferred
block size of 2^12 (4,096), and a maximum block size of the smaller of
the export size or 0xffffffff (effectively unlimited).  A server that
wants to enforce block sizes other than the defaults specified here
MAY refuse to go into transmission phase with a client that uses
`NBD_OPT_EXPORT_NAME` (via a hard disconnect) or which fails to use
`NBD_OPT_BLOCK_SIZE` (where the server uses
`NBD_REP_ERR_BLOCK_SIZE_REQD` in response to `NBD_OPT_GO`), although a
server SHOULD permit such clients if block sizes can be agreed on
externally.  When allowing such clients, the server MUST cleanly error
commands that fall outside block size parameters without corrupting
data; even so, this may limit interoperability.

A client MAY choose to operate as if tighter block sizes had been
specified (for example, even when the server advertises the default
minimum block size of 1, a client may safely use a minimum block size
of 2^9 (512), a preferred block size of 2^16 (65,536), and a maximum
block size of 2^25 (33,554,432)).  Notwithstanding any maximum block
size advertised, either the server or the client MAY initiate a hard
disconnect if the size of a request or a reply is large enough to be
deemed a denial of service attack.

The minimum block size represents the smallest addressable length and
alignment within the export, although writing to an area that small
may require the server to use a less-efficient read-modify-write
action.  If advertised, this value MUST be a power of 2, MUST NOT be
larger than 2^16 (65,536), and MAY be as small as 1 for an export
backed by a regular file, although the values of 2^9 (512) or 2^12
(4,096) are more typical for an export backed by a block device.  If a
server advertises a minimum block size, the advertised export size
SHOULD be an integer multiple of that block size, since otherwise, the
client would be unable to access the final few bytes of the export.

The preferred block size represents the minimum size at which aligned
requests will have efficient I/O, avoiding behaviour such as
read-modify-write.  If advertised, this MUST be a power of 2 at least
as large as the smaller of the minimum block size and 2^12 (4,096),
although larger values (such as the minimum granularity of a hole) are
also appropriate.  The preferred block size MAY be larger than the
export size, in which case the client is unable to utilize the
preferred block size for that export.  The server MAY advertise an
export size that is not an integer multiple of the preferred block
size.

The maximum block size represents the maximum length that the server
is willing to handle in one request.  If advertised, it MUST be either
an integer multiple of the minimum block size or the value 0xffffffff
for no inherent limit, MUST be at least as large as the smaller of the
preferred block size or export size, and SHOULD be at least 2^25
(33,554,432) if the export is that large, but MAY be something other
than a power of 2.  For convenience, the server MAY advertise a
maximum block size that is larger than the export size, although in
that case, the client MUST treat the export size as the effective
maximum block size (as further constrained by a non-zero offset).

Where a transmission request can have a non-zero *offset* and/or
*length* (such as `NBD_CMD_READ`, `NBD_CMD_WRITE`, or `NBD_CMD_TRIM`),
the client MUST ensure that *offset* and *length* are integer
multiples of any advertised minimum block size, and SHOULD use integer
multiples of any advertised preferred block size where possible.  For
those requests, the client MUST NOT use a *length* larger than any
advertised maximum block size or which, when added to *offset*, would
exceed the export size.  The server SHOULD report an `EINVAL` error if
the client's request is not aligned to advertised minimum block size
boundaries, or is larger than the advertised maximum block size,
although the server MAY instead initiate a hard disconnect if a large
*length* could be deemed as a denial of service attack.

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

- bit 0, `NBD_FLAG_FIXED_NEWSTYLE`; MUST be set by servers that
  support the fixed newstyle protocol
- bit 1, `NBD_FLAG_NO_ZEROES`; if set, and if the client replies with
  `NBD_FLAG_C_NO_ZEROES` in the client flags field, the server MUST NOT
  send the 124 bytes of zero at the end of the negotiation.

The server MUST NOT set any other flags, and SHOULD NOT change behaviour
unless the client responds with a corresponding flag.  The server MUST
NOT set any of these flags during oldstyle negotiation.

##### Transmission flags

This field of 16 bits is sent by the server after option haggling, or
immediately after the handshake flags field in oldstyle negotiation.

Many of these flags allow the server to expose to the client which
features it understands (in which case they are documented below
as "`NBD_FLAG_XXX` exposes feature `YYY`"). In each case, the server
MAY set the flag for features it supports. The server MUST NOT set the
flag for features it does not support. The client MUST NOT use a feature
documented as 'exposed' by a flag unless that flag was set.

The field has the following format:

- bit 0, `NBD_FLAG_HAS_FLAGS`: MUST always be 1.
- bit 1, `NBD_FLAG_READ_ONLY`: The server MAY set this flag to indicate
  to the client that the export is read-only (exports might be read-only
  in a manner undetectable to the server, for instance because of
  permissions). If this flag is set, the server MUST error subsequent
  write operations to the export.
- bit 2, `NBD_FLAG_SEND_FLUSH`: exposes support for `NBD_CMD_FLUSH`.
- bit 3, `NBD_FLAG_SEND_FUA`: exposes support for `NBD_CMD_FLAG_FUA`.
- bit 4, `NBD_FLAG_ROTATIONAL`: the server MAY set this flag to 1 to
  inform the client that the export has the characteristics of a rotational
  medium, and the client MAY schedule I/O accesses in a manner corresponding
  to the setting of this flag.
- bit 5, `NBD_FLAG_SEND_TRIM`: exposes support for `NBD_CMD_TRIM`.
- bit 6, `NBD_FLAG_SEND_WRITE_ZEROES`: defined by the
  experimental `WRITE_ZEROES` [extension](https://github.com/yoe/nbd/blob/extension-write-zeroes/doc/proto.md).
- bit 7, `NBD_FLAG_SEND_DF`: defined by the experimental `STRUCTURED_REPLY`
  [extension](https://github.com/yoe/nbd/blob/extension-structured-reply/doc/proto.md).

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

Clients MUST NOT set any other flags; the server MUST drop the TCP
connection if the client sets an unknown flag, or a flag that does
not match something advertised by the server.

#### Option types

These values are used in the "option" field during the option haggling
of the newstyle negotiation.

- `NBD_OPT_EXPORT_NAME` (1)

    Choose the export which the client would like to use, end option
    haggling, and proceed to the transmission phase.

    Data: String, name of the export, as free-form text.
    The length of the name is determined from the option header. If the
    chosen export does not exist or requirements for the chosen export
    are not met (e.g., the client did not initiate TLS for an export
    where the server requires it), the server MUST terminate the
    session.

    A special, "empty", name (i.e., the length field is zero and no name
    is specified), is reserved for a "default" export, to be used in cases
    where explicitly specifying an export name makes no sense.

    This is the only valid option in nonfixed newstyle negotiation. A
    server which wishes to use any other option MUST support fixed
    newstyle.

    A major problem of this option is that it does not support the
    return of error messages to the client in case of problems. To
    remedy this, `NBD_OPT_GO` has been introduced (see below).

- `NBD_OPT_ABORT` (2)

    The client desires to abort the negotiation and terminate the
    session. The server MUST reply with `NBD_REP_ACK`.

    Previous versions of this document were unclear on whether
    the server should send a reply to `NBD_OPT_ABORT`. Therefore
    the client SHOULD gracefully handle the server closing the
    connection after receiving an `NBD_OPT_ABORT` without it
    sending a reply. Similarly the server SHOULD gracefully handle
    the client sending an `NBD_OPT_ABORT` and closing the connection
    without waiting for a reply.

- `NBD_OPT_LIST` (3)

    Return zero or more `NBD_REP_SERVER` replies, one for each export,
    followed by `NBD_REP_ACK` or an error (such as
    `NBD_REP_ERR_SHUTDOWN`). The server MAY omit entries from this
    list if TLS has not been negotiated, the server is operating in
    SELECTIVETLS mode, and the entry concerned is a TLS-only export.

- `NBD_OPT_PEEK_EXPORT` (4)

    Was defined by the (withdrawn) experimental `PEEK_EXPORT` extension;
    not in use.

- `NBD_OPT_STARTTLS` (5)

    The client wishes to initiate TLS.

    The server MUST either reply with `NBD_REP_ACK` after which
    point the connection is upgraded to TLS, or an error reply
    explicitly permitted by this document.

    See the section on TLS above for further details.

- `NBD_OPT_INFO` (6) and `NBD_OPT_GO` (7)

    Both options have identical formats for requests and replies. The only
    difference is that after a successful reply to `NBD_OPT_GO` (i.e. one
    or more `NBD_REP_INFO` then an `NBD_REP_ACK`), transmission mode is
    entered immediately.  Therefore these commands share common
    documentation.

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

    - String: name of the export (as with `NBD_OPT_EXPORT_NAME`, the length
      comes from the option header).

    If no name is specified (i.e. a zero length string is provided),
    this specifies the default export (if any), as with
    `NBD_OPT_EXPORT_NAME`.

    The server replies with a number of `NBD_REP_INFO` replies (as few
    as zero if an error is reported, at least one on success), then
    concludes the list of information with a final error reply or with
    a declaration of success, as follows:

    - `NBD_REP_ACK`: The server accepts the chosen export, and has
      completed providing information.  In this case, the server MUST
      send at least one `NBD_REP_INFO`, with an `NBD_INFO_EXPORT`
      information type.
    - `NBD_REP_ERR_UNKNOWN`: The chosen export does not exist on this
      server.  In this case, the server SHOULD NOT send `NBD_REP_INFO`
      replies.
    - `NBD_REP_ERR_TLS_REQD`: The server requires the client to
      initiate TLS before any revealing any further details about this
      export.  In this case, a FORCEDTLS server MUST NOT send
      `NBD_REP_INFO` replies, but a SELECTIVETLS server MAY do so if
      this is a TLS-only export.
    - `NBD_REP_ERR_BLOCK_SIZE_REQD`: The server requires the client to
      negotiate `NBD_OPT_BLOCK_SIZE` prior to entering transmission
      phase, because the server will be using non-default block sizes.
      In this case, the server SHOULD first send at least an
      `NBD_REP_INFO` reply with `NBD_INFO_BLOCK_SIZE` data.  This
      error MUST NOT be used if the client has already negotiated
      `NBD_OPT_BLOCK_SIZE`.

    Additionally, if TLS has not been initiated, the server MAY reply
    with `NBD_REP_ERR_TLS_REQD` (instead of `NBD_REP_ERR_UNKNOWN`) to
    requests for exports that are unknown. This is so that clients
    that have not initiated TLS cannot enumerate exports.  A
    SELECTIVETLS server that chooses to hide unknown exports in this
    manner SHOULD NOT send `NBD_REP_INFO` replies for a TLS-only
    export.

    For backwards compatibility, clients SHOULD be prepared to also
    handle `NBD_REP_ERR_UNSUP` by falling back to using `NBD_OPT_EXPORT_NAME`.

    Other errors (such as `NBD_REP_ERR_SHUTDOWN`) are also possible,
    as permitted elsewhere in this document, with no constraints on
    the number of preceeding `NBD_REP_INFO`.

    If there are no intervening option requests between a successful
    `NBD_OPT_INFO` (that is, one where the reply ended with a final
    `NBD_REP_ACK`) and an `NBD_OPT_GO` with the same parameters, then
    the server MUST reply with the same set of information, such as
    transmission flags in the `NBD_INFO_EXPORT` reply, although the
    ordering of the intermediate `NBD_REP_INFO` messages MAY differ.
    Otherwise, due to the intervening option requests or the use of
    different parameters, the server MAY send different data in the
    successful response, and/or MAY fail the second request.

    The reply to an `NBD_OPT_GO` is identical to the reply to
    `NBD_OPT_INFO` save that if the reply indicates success (i.e. ends
    with `NBD_REP_ACK`), the client and the server both immediately
    enter the transmission phase. The server MUST NOT send any zero
    padding bytes after the `NBD_REP_ACK` data, whether or not the
    client negotiated the `NBD_FLAG_C_NO_ZEROES` flag. The server MUST
    NOT send the final `NBD_REP_ACK` reply until all other pending
    option replies have been sent by the server, and a client MUST NOT
    send any further option requests after `NBD_OPT_GO` unless it
    first receives an error reply.

- `NBD_OPT_GO` (7)

    See above under `NBD_OPT_INFO`.

- `NBD_OPT_STRUCTURED_REPLY` (8)

    Defined by the experimental `STRUCTURED_REPLY` [extension](https://github.com/yoe/nbd/blob/extension-structured-reply/doc/proto.md).

- `NBD_OPT_BLOCK_SIZE` (9)

    The client wishes to inform the server of its intent to obey block
    sizes.  The option request has no additional data.

    Some servers are able to make optimizations, such as opening files
    with O_DIRECT, if they know that the client will obey a particular
    minimum block size, where it must fall back to safer but slower code
    if the client might send unaligned requests.

    The server MUST reply with `NBD_REP_ACK`, after which point the
    client SHOULD use `NBD_OPT_GO` rather than `NBD_OPT_EXPORT_NAME`,
    and the server SHOULD include `NBD_INFO_BLOCK_SIZE` in its reply.
    If successfully negotiated, and the server advertises block sizes,
    the client MUST NOT send unaligned requests.

    For backwards compatibility, clients SHOULD be prepared to also
    handle `NBD_REP_ERR_UNSUP`, which means the server SHOULD NOT be
    advertising block sizes, and the client MAY assume the server will
    honor default block sizes.

    Note that a client MAY obey non-default block sizes even without
    advertising intent or even when the server does not advertise block
    sizes; and that a server MAY advertise block sizes even when a client
    does not advertise intent.  Therefore, the use of this option is
    independent of whether the server uses `NBD_INFO_BLOCK_SIZE`.

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
    - String, name of the export, as expected by `NBD_OPT_EXPORT_NAME`,
      `NBD_OPT_INFO`, or `NBD_OPT_GO`
    - If length of name < (reply packet header length - 4), then the
      rest of the data contains some implementation-specific details
      about the export. This is not currently implemented, but future
      versions of nbd-server may send along some details about the
      export. Therefore, unless explicitly documented otherwise by a
      particular client request, this field is defined to be a string
      suitable for direct display to a human being.

* `NBD_REP_INFO` (3)

    A detailed description about an aspect of an export.  The response
    to `NBD_OPT_INFO` and `NBD_OPT_GO` includes zero or more of these
    messages prior to a final error reply, or at least one before an
    `NBD_REP_ACK` reply indicating success.  The server MUST send an
    `NBD_INFO_EXPORT` information type at some point before sending an
    `NBD_REP_ACK`, so that `NBD_OPT_GO` can provide a superset of the
    information given in response to `NBD_OPT_EXPORT_NAME`; all other
    information types are optional.  A particular information type
    SHOULD only appear once for a given export unless documented
    otherwise.

    A client MUST NOT rely on any particular ordering amongst the
    `NBD_OPT_INFO` replies, and MUST ignore information types that it
    does not recognize.

    The acceptable values for the header *length* field are determined
    by the information type, and includes the 2 bytes for the type
    designator, in the following general layout:

    - 16 bits, information type (e.g. `NBD_INFO_EXPORT`)  
    - *length - 2* bytes, information payload  

    The following information types are defined:

    * `NBD_INFO_EXPORT` (0)

      Mandatory information before a successful completion of
      `NBD_OPT_INFO` or `NBD_OPT_GO`.  Describes the same information
      that is sent in response to the older `NBD_OPT_EXPORT_NAME`,
      except that there are no trailing zeroes whether or not
      `NBD_FLAG_C_NO_ZEROES` was negotiated.  *length* MUST be 12, and
      the reply payload is interpreted as follows:

      - 16 bits, `NBD_INFO_EXPORT`  
      - 64 bits, size of the export in bytes (unsigned)  
      - 16 bits, transmission flags  

    * `NBD_INFO_NAME` (1)

      Represents the server's canonical name of the export. The name
      MAY differ from the name presented in the client's option
      request, and the information item MAY be omitted if the client
      option request already used the canonical name.  This
      information type represents the same name that would appear in
      the name portion of an `NBD_REP_SERVER` in response to
      `NBD_OPT_LIST`. The *length* MUST be at least 2, and the reply
      payload is interpreted as:

      - 16 bits, `NBD_INFO_NAME`  
      - String: name of the export, *length - 2* bytes  

    * `NBD_INFO_DESCRIPTION` (2)

      A description of the export, suitable for direct display to the
      human being.  This information type represents the same optional
      description that may appear after the name portion of an
      `NBD_REP_SERVER` in response to `NBD_OPT_LIST`. The *length*
      MUST be at least 2, and the reply payload is interpreted as:

      - 16 bits, `NBD_INFO_DESCRIPTION`  
      - String: description of the export, *length - 2* bytes  

    * `NBD_INFO_BLOCK_SIZE` (3)

      Represents the server's advertised block sizes; see the "Block
      sizes" section for more details on what these values represent,
      and on constraints on their values.  The server MAY send this
      info whether or not the client has negotiated
      `NBD_OPT_BLOCK_SIZE`, and SHOULD send this info if it intends to
      enforce block sizes other than the defaults. The *length* MUST
      be 14, and the reply payload is interpreted as:

      - 16 bits, `NBD_INFO_BLOCK_SIZE`  
      - 32 bits, minimum block size  
      - 32 bits, preferred block size  
      - 32 bits, maximum block size  


There are a number of error reply types, all of which are denoted by
having bit 31 set. All error replies MAY have some data set, in which
case that data is an error message string suitable for display to the user.

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
    initiated first. In the case of `NBD_OPT_INFO` and `NBD_OPT_GO`
    this unwillingness MAY (depending on the TLS mode) be limited
    to the export in question. See the section on TLS above for
    further details.

* `NBD_REP_ERR_UNKNOWN` (2^31 + 6)

    The requested export is not available.

* `NBD_REP_ERR_SHUTDOWN` (2^32 + 7)

    The server is unwilling to continue negotiation as it is in the
    process of being shut down.

* `NBD_REP_ERR_BLOCK_SIZE_REQD` (2^32 + 8)

    The server is unwilling to enter transmission phase for a given
    export unless the client first acknowledges (via
    `NBD_OPT_BLOCK_SIZE`) that it will obey non-default block sizing
    requirements.

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
  writing data (current commands are `NBD_CMD_WRITE`
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
  [extension](https://github.com/yoe/nbd/blob/extension-write-zeroes/doc/proto.md).
- bit 2, `NBD_CMD_FLAG_DF`; defined by the experimental `STRUCTURED_REPLY`
  [extension](https://github.com/yoe/nbd/blob/extension-structured-reply/doc/proto.md).


#### Request types

The following request types exist:

* `NBD_CMD_READ` (0)

    A read request. Length and offset define the data to be read.

    The server MUST reply with a reply header,
    followed immediately by *length* bytes
    of data, read from *offset* bytes into the file, unless an error
    condition has occurred.

    If an error occurs, the server SHOULD set the appropriate error
    code in the error field. The server MUST then either initiate
    a hard disconnect, or send *length* bytes of data (these bytes MAY be
    invalid, in which case they SHOULD be zero); this is true even if
    the error is `EINVAL` for bad flags detected before even
    attempting to read.

    If an error occurs while reading after the server has already sent
    out the reply header with an error field set to zero (i.e.,
    signalling no error), the server MUST immediately initiate a
    hard disconnect; it MUST NOT send any further data to the client.

* `NBD_CMD_WRITE` (1)

    A write request. Length and offset define the location and amount of
    data to be written. The client MUST follow the request header with
    *length* number of bytes to be written to the device.

    The server MUST write the data to disk, and then send the reply
    message. The server MAY send the reply message before the data has
    reached permanent storage.

    If an error occurs, the server MUST set the appropriate error code
    in the error field.

* `NBD_CMD_DISC` (2)

    A disconnect request. The server MUST handle all outstanding
    requests, shut down the TLS session (if one is running), and
    close the TCP session.  A client MUST NOT send
    anything to the server after sending an `NBD_CMD_DISC` command.

    The values of the length and offset fields in a disconnect request
    MUST be zero.

    There is no reply to an `NBD_CMD_DISC`.

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

* `NBD_CMD_WRITE_ZEROES` (6)

    Defined by the experimental `WRITE_ZEROES` [extension](https://github.com/yoe/nbd/blob/extension-write-zeroes/doc/proto.md).

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
* `EOVERFLOW` (75), defined in the  experimental `STRUCTURED_REPLY`
  [extension](https://github.com/yoe/nbd/blob/extension-structured-reply/doc/proto.md).
* `ESHUTDOWN` (108), Server is in the process of being shut down.

The server SHOULD return `ENOSPC` if it receives a write request
including one or more sectors beyond the size of the device.  It also
SHOULD map the `EDQUOT` and `EFBIG` errors to `ENOSPC`.  It SHOULD
return `EINVAL` if it receives a read or trim request including one or
more sectors beyond the size of the device, or if a read or write
request is not aligned to advertised minimum block sizes. Finally, it
SHOULD return `EPERM` if it receives a write or trim request on a
read-only export.

The server SHOULD return `EINVAL` if it receives an unknown command.

The server SHOULD return `EINVAL` if it receives an unknown command flag. It
also SHOULD return `EINVAL` if it receives a request with a flag not explicitly
documented as applicable to the given request.

Which error to return in any other case is not specified by the NBD
protocol.

The server SHOULD NOT return `ENOMEM` if at all possible.

## Experimental extensions

In additional to the normative elements of the specification set out
herein, various experimental non-normative extensions have been
proposed. These may not be implemented in any known server or client,
and are subject to change at any point. A full implementation may
require changes to the specifications, or cause the specifications to
be withdrawn altogether.

These experimental extensions are set out in git branches starting
with names starting with the word 'extension'.

Currently known are:

* The `WRITE_ZEROES` [extension](https://github.com/yoe/nbd/blob/extension-write-zeroes/doc/proto.md).

* The `STRUCTURED_REPLY` [extension](https://github.com/yoe/nbd/blob/extension-structured-reply/doc/proto.md)

* The `INFO` [extension](https://github.com/yoe/nbd/blob/extension-info/doc/proto.md).

Implementors of these extensions are strongly suggested to contact the
[mailinglist](mailto:nbd-general@lists.sourceforge.net) in order to help
fine-tune the specifications before committing to a particular
implementation.

Those proposing further extensions should also contact the
[mailinglist](mailto:nbd-general@lists.sourceforge.net). It is
possible to reserve command codes etc. within this document
for such proposed extensions. Aside from that, extensions are
written as branches which can be merged into master if and
when those extensions are promoted to the normative version
of the document in the master branch.

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
