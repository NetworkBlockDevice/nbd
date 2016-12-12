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
C: 32 bits, client flags  

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

The client MUST NOT send any option until it has received a final
reply to any option it has sent (note that some options e.g.
`NBD_OPT_LIST` have multiple replies, and the final reply is
the last of those).

#### Termination of the session during option haggling

There are three possible mechanisms to end option haggling:

* Transmission mode can be entered (by the client sending
  `NBD_OPT_EXPORT_NAME`). This is documented
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
error any inflight option and SHOULD error further options received
(other than an `NBD_OPT_ABORT`) with `NBD_REP_ERR_SHUTDOWN`.

If the client receives `NBD_REP_ERR_SHUTDOWN` it MUST initiate
a soft disconnect.

### Transmission

There are three message types in the transmission phase: the request,
the simple reply, and the structured reply chunk.  The
transmission phase consists of a series of transactions, where the
client submits requests and the server sends corresponding replies
with either a single simple reply or a series of one or more
structured reply chunks per request.  The phase continues until
either side terminates transmission; this can be performed cleanly
only by the client.

Note that without client negotiation, the server MUST use only simple
replies, and that it is impossible to tell by reading the server
traffic in isolation whether a data field will be present; the simple
reply is also problematic for error handling of the `NBD_CMD_READ`
request.  Therefore, structured replies can be used to create a
a context-free server stream; see below.

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
  and `NBD_CMD_TRIM`) that the server
  completes (i.e. replies to) prior to processing to a
  `NBD_CMD_FLUSH` MUST be written to non-volatile
  storage prior to replying to that `NBD_CMD_FLUSH`. This
  paragraph only applies if `NBD_FLAG_SEND_FLUSH` is set within
  the transmission flags, as otherwise `NBD_CMD_FLUSH` will never
  be sent by the client to the server.

* A client which uses multiple connections to a server to parallelize
  commands MUST NOT issue an `NBD_CMD_FLUSH` request until it has
  received the reply for all write commands which it expects to be
  covered by the flush.

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
requests if structured replies have not been negotiated using
`NBD_OPT_STRUCTURED_REPLY`. If structured replies have been negotiated, a simple
reply MAY be used as a reply to any request other than `NBD_CMD_READ`,
but only if the reply has no data payload.  The message looks as
follows:

S: 32 bits, 0x67446698, magic (`NBD_SIMPLE_REPLY_MAGIC`; used to be
   `NBD_REPLY_MAGIC`)  
S: 32 bits, error (MAY be zero)  
S: 64 bits, handle  
S: (*length* bytes of data if the request is of type `NBD_CMD_READ`)  

#### Structured reply chunk message

Some of the major downsides of the default simple reply to
`NBD_CMD_READ` are as follows.  First, it is not possible to support
partial reads or early errors (the command must succeed or fail as a
whole, and either *length* bytes of data must be sent or a hard disconnect
must be initiated, even if the failure is `EINVAL` due to bad flags).
Second, there is no way to efficiently skip over portions of a sparse
file that are known to contain all zeroes.  Finally, it is not
possible to reliably decode the server traffic without also having
context of what pending read requests were sent by the client.
Therefore structured replies are also permitted if negotiated.

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
accompanied by a string payload to present to a human user.

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
  or `NBD_OPT_ABORT` with `NBD_REP_ERR_TLS_REQD` ('FORCEDTLS'); this
  in practice means that all option negotiation (apart from the
  `NBD_OPT_STARTTLS` itself) is carried out with TLS; OR

* The server provides TLS, and it is mandatory on zero or more
  exports, and is available at the client's option on all
  other exports ('SELECTIVETLS'). The server does not force
  the client to upgrade to TLS during option haggling (as
  if the client ultimately were to choose a non-TLS-only export,
  stopping TLS is not possible). Instead it permits the client
  to upgrade as and when it chooses, but unless an upgrade to
  TLS has already taken place, the server errors attempts
  to enter transmission mode on TLS-only exports, and MAY omit
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

If the server receives any other option, it MUST reply with
`NBD_REP_ERR_TLS_REQD` if TLS has not been initiated.
If the server receives a request to
enter transmission mode via `NBD_OPT_EXPORT_NAME` when TLS has not
been initiated, then as this request cannot error, it MUST
terminate the session.

The server MUST NOT send `NBD_REP_ERR_TLS_REQD` in reply to
any option if TLS has already been initiated.

The FORCEDTLS mode of operation has an implementation problem in
that the client MAY legally simply send a `NBD_OPT_EXPORT_NAME`
to enter transmission mode without previously sending any options.

#### SELECTIVETLS mode

If the server receives `NBD_OPT_STARTTLS` prior to negotiating
TLS, it MUST reply with `NBD_REP_ACK` and initiate TLS as set
out under 'FORCEDTLS' above. If the server receives
`NBD_OPT_STARTTLS` when TLS has already been negotiated, it
it MUST reply with `NBD_REP_ERR_INVALID`.

If the server receives a request to enter transmission mode
via `NBD_OPT_EXPORT_NAME` on a TLS-only export when TLS has not
been initiated, then as this request cannot error, it MUST
terminate the session.

The server MUST NOT send `NBD_REP_ERR_TLS_REQD` in reply to
any option if TLS has already been negotiated.

There is a degenerate case of SELECTIVETLS where all
exports are TLS-only. This is permitted in part to make programming
of servers easier. Operation is a little different from FORCEDTLS,
as the client is not forced to upgrade to TLS prior to any options
being processed.

The SELECTIVETLS mode of operation has an implementation problem
in that unless the INFO extension is supported, the client that
does not use TLS may have its access to exports denied without
it being able to ascertain the reason. For instance it may
go into transmission mode using `NBD_OPT_EXPORT_NAME` - which
does not return an error as no options will be denied with
`NBD_REP_ERR_TLS_REQD`. Further there is no way to remotely
determine whether an export requires TLS, and therefore this
must be initiated between client and server out of band.

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
unless a TLS upgrade is performed. This
indicates that no option will succeed unless a TLS upgrade
is performed; the client MAY therefore choose to issue
an `NBD_OPT_STARTTLS`, or MAY terminate the session (if
for instance it does not support TLS or does not have
appropriate credentials for this server).

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

## Metadata querying

With the availability of sparse storage formats, it is often needed to
query the status of a particular range and read only those blocks of
data that are actually present on the block device.

Some storage formats and operations over such formats express a
concept of data dirtiness. Whether the operation is block device
mirroring, incremental block device backup or any other operation with
a concept of data dirtiness, they all share a need to provide a list
of ranges that this particular operation treats as dirty.

To provide such classes of information, the NBD protocol has a generic
framework for querying metadata; however, its use must first be
negotiated, and one or more metadata contexts must be selected.

The procedure works as follows:

- First, during negotiation, the client MUST select one or more metadata
  contexts with the `NBD_OPT_SET_META_CONTEXT` command. If needed, the client
  can use `NBD_OPT_LIST_META_CONTEXT` to list contexts.
- During transmission, a client can then indicate interest in metadata
  for a given region by way of the `NBD_CMD_BLOCK_STATUS` command, where
  *offset* and *length* indicate the area of interest. The server MUST
  then respond with the requested information, for all contexts which
  were selected during negotiation. For every metadata context, the
  server sends one set of extent chunks, where the sizes of the
  extents MUST be less than or equal to the length as specified in the
  request. Each extent comes with a *flags* field, the semantics of
  which are defined by the metadata context.
- A server MUST reply to `NBD_CMD_BLOCK_STATUS` with a structured reply
  of type `NBD_REPLY_TYPE_BLOCK_STATUS`.

A client MUST NOT use `NBD_CMD_BLOCK_STATUS` unless it selected a
nonzero number of metadata contexts during negotiation. Servers SHOULD
reply to clients doing so anyway with `EINVAL`.

The reply to the `NBD_CMD_BLOCK_STATUS` request MUST be sent by a
structured reply; this implies that in order to use metadata querying,
structured replies MUST be negotiated first.

This standard defines exactly one metadata context; it is called
`base:allocation`, and it provides information on the basic allocation
status of extents (that is, whether they are allocated at all in a
sparse file context).

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
  experimental `WRITE_ZEROES` [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-write-zeroes/doc/proto.md).
- bit 7, `NBD_FLAG_SEND_DF`: do not fragment a structured reply. The
  server MUST set this transmission flag to 1 if the
  `NBD_CMD_READ` request supports the `NBD_CMD_FLAG_DF` flag, and
  MUST leave this flag clear if structured replies have not been
  negotiated. Clients MUST NOT set the `NBD_CMD_FLAG_DF` request
  flag unless this transmission flag is set.
- bit 8, `NBD_FLAG_CAN_MULTI_CONN`: Indicates that the server operates
  entirely without cache, or that the cache it uses is shared among all
  connections to the given device. In particular, if this flag is
  present, then the effects of `NBD_CMD_FLUSH` and `NBD_CMD_FLAG_FUA`
  MUST be visible across all connections when the server sends its reply
  to that command to the client. In the absense of this flag, clients
  SHOULD NOT multiplex their commands over more than one connection to
  the export.

Clients SHOULD ignore unknown flags.

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
    return of error messages to the client in case of problems.

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

- `NBD_OPT_INFO` (6)

    Defined by the experimental `INFO` [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-info/doc/proto.md).

- `NBD_OPT_GO` (7)

    Defined by the experimental `INFO` [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-info/doc/proto.md).

- `NBD_OPT_STRUCTURED_REPLY` (8)

    The client wishes to use structured replies during the
    transmission phase.  The option request has no additional data.

    The server replies with the following:

    - `NBD_REP_ACK`: Structured replies have been negotiated; the
      server MUST use structured replies to the `NBD_CMD_READ`
      transmission request.  Other extensions that require structured
      replies may now be negotiated.
    - For backwards compatibility, clients SHOULD be prepared to also
      handle `NBD_REP_ERR_UNSUP`; in this case, no structured replies
      will be sent.

    It is envisioned that future extensions will add other new
    requests that may require a data payload in the reply.  A server
    that supports such extensions SHOULD NOT advertise those
    extensions until the client negotiates structured replies; and a
    client MUST NOT make use of those extensions without first
    enabling the `NBD_OPT_STRUCTURED_REPLY` extension.

- `NBD_OPT_BLOCK_SIZE` (9)

    Defined by the experimental `INFO` [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-info/doc/proto.md).

- `NBD_OPT_LIST_META_CONTEXT` (10)

    Return a list of `NBD_REP_META_CONTEXT` replies, one per context,
    followed by an `NBD_REP_ACK`. If a server replies to such a request
    with no error message, clients MAY send NBD_CMD_BLOCK_STATUS
    commands during the transmission phase.

    If the query string is syntactically invalid, the server SHOULD send
    `NBD_REP_ERR_INVALID`. If the query string is syntactically valid
    but finds no metadata contexts, the server MUST send a single
    reply of type `NBD_REP_ACK`.

    This option MUST NOT be requested unless structured replies have
    been negotiated first. If a client attempts to do so, a server
    SHOULD send `NBD_REP_ERR_INVALID`.

    Data:
    - 32 bits, length of export name
    - String, name of export for which we wish to list or select metadata
      contexts.
    - 32 bits, length of query
    - String, query to select a subset of the available metadata
      contexts. If this is not specified (i.e., the "length of query"
      field is 0 and no query is sent), then the server MUST send all
      the metadata contexts it knows about. If specified, this query
      string MUST start with a name that uniquely identifies a server
      implementation; e.g., the reference implementation that
      accompanies this document would support query strings starting
      with 'nbd-server:'

    The server MUST reply with a list of `NBD_REP_META_CONTEXT` replies,
    followed by `NBD_REP_ACK`. The metadata context ID in these replies
    is reserved and SHOULD be set to zero; clients SHOULD disregard it.

- `NBD_OPT_SET_META_CONTEXT` (11)

    Change the set of active metadata contexts. Issuing this command
    replaces all previously-set metadata contexts; clients must ensure
    that all metadata contexts they're interested in are selected with
    the final query that they sent.

    Data:
    - 32 bits, length of query
    - String, query to select metadata contexts. The syntax of this
      query is implementation-defined, except that it MUST start with a
      namespace. This namespace may be one of the following:
        - `base:`, for metadata contexts defined by this document;
        - `nbd-server:`, for metadata contexts defined by the
          implementation that accompanies this document (none
          currently);
        - `x-*:`, where `*` can be replaced by any random string not
          containing colons, for local experiments. This SHOULD NOT be
          used by metadata contexts that are expected to e widely used.
        - third-party implementations can register additional
          namespaces by simple request to the mailinglist.

    The server MUST reply with a number of `NBD_REP_META_CONTEXT`
    replies, one for each selected metadata context, each with a unique
    metadata context ID. It is not an error if a
    `NBD_OPT_SET_META_CONTEXT` option does not select any metadata
    context, provided the client then does not attempt to issue
    `NBD_CMD_BLOCK_STATUS` commands.

#### Option reply types

These values are used in the "reply type" field, sent by the server
during option haggling in the fixed newstyle negotiation.

- `NBD_REP_ACK` (1)

    Will be sent by the server when it accepts the option and no further
    information is available, or when sending data related to the option
    (in the case of `NBD_OPT_LIST`) has finished. No data.

- `NBD_REP_SERVER` (2)

    A description of an export. Data:

    - 32 bits, length of name (unsigned); MUST be no larger than the
      reply packet header length - 4
    - String, name of the export, as expected by `NBD_OPT_EXPORT_NAME`
    - If length of name < (reply packet header length - 4), then the
      rest of the data contains some implementation-specific details
      about the export. This is not currently implemented, but future
      versions of nbd-server may send along some details about the
      export. Therefore, unless explicitly documented otherwise by a
      particular client request, this field is defined to be a string
      suitable for direct display to a human being.

- `NBD_REP_INFO` (3)

    Defined by the experimental `INFO` [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-info/doc/proto.md).

- `NBD_REP_META_CONTEXT` (4)

    A description of a metadata context. Data:

    - 32 bits, NBD metadata context ID.
    - String, name of the metadata context. This is not required to be
      a human-readable string, but it MUST be valid UTF-8 data.

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
    initiated first.

* `NBD_REP_ERR_UNKNOWN` (2^31 + 6)

    Defined by the experimental `INFO` [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-info/doc/proto.md).

* `NBD_REP_ERR_SHUTDOWN` (2^31 + 7)

    The server is unwilling to continue negotiation as it is in the
    process of being shut down.

* `NBD_REP_ERR_BLOCK_SIZE_REQD` (2^31 + 8)

    Defined by the experimental `INFO` [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-info/doc/proto.md).

##### Metadata contexts

The `base:allocation` metadata context is the basic "allocated at all"
metadata context. If an extent is marked with `NBD_STATE_HOLE` at that
context, this means that the given extent is not allocated in the
backend storage, and that writing to the extent MAY result in the ENOSPC
error. This supports sparse file semantics on the server side. If a
server has only one metadata context (the default), then writing to an
extent which has `NBD_STATE_HOLE` clear MUST NOT fail with ENOSPC.

It defines the following flags for the flags field:

- `NBD_STATE_HOLE` (bit 0): if set, the block represents a hole (and
  future writes to that area may cause fragmentation or encounter an
  `ENOSPC` error); if clear, the block is allocated or the server could
  not otherwise determine its status. Note that the use of
  `NBD_CMD_TRIM` is related to this status, but that the server MAY
  report a hole even where trim has not been requested, and also that a
  server MAY report metadata even where a trim has been requested.
- `NBD_STATE_ZERO` (bit 1): if set, the block contents read as all
  zeroes; if clear, the block contents are not known. Note that the use
  of `NBD_CMD_WRITE_ZEROES` is related to this status, but that the
  server MAY report zeroes even where write zeroes has not been
  requested, and also that a server MAY report unknown content even
  where write zeroes has been requested.

It is not an error for a server to report that a region of the
export has both `NBD_STATE_HOLE` set and `NBD_STATE_ZERO` clear. The
contents of such an area is undefined, and may not be stable;
clients who are aware of the existence of such a region SHOULD NOT
read it.

For the `base:allocation` context, the remainder of the flags field is
reserved. Servers SHOULD set it to all-zero; clients MUST ignore unknown
flags.

For all other cases, this specification requires no specific semantics of
metadata contexts, except that all the information they provide MUST be
representable within the flags field as defined for
`NBD_REPLY_TYPE_BLOCK_STATUS`.

Likewise, the syntax of query strings is not specified by this document.

Server implementations SHOULD document their syntax for query strings
and semantics for resulting metadata contexts in a document like this
one.

### Transmission phase

#### Flag fields

##### Command flags

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
  [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-write-zeroes/doc/proto.md).
- bit 2, `NBD_CMD_FLAG_DF`; the "don't fragment" flag, valid during `NBD_CMD_READ`.
   SHOULD be set to 1 if the client requires the server to send at most one
   content chunk in reply.  MUST NOT be set unless the transmission
   flags include `NBD_FLAG_SEND_DF`.  Use of this flag MAY trigger an
   `EOVERFLOW` error chunk, if the request length is too large.
- bit 3, `NBD_CMD_FLAG_REQ_ONE`; valid during `NBD_CMD_BLOCK_STATUS`. If
  set, the client is interested in only one extent per metadata
  context. If this flag is present, the server SHOULD NOT send metadata
  on more than one extent in the reply. Clients SHOULD NOT use this flag
  on multiple requests for successive regions in the export.

##### Structured reply flags

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

#### Structured reply types

These values are used in the "type" field of a structured reply.
Some chunk types can additionally be categorized by role, such as
*error chunks* or *content chunks*.  Each type determines how to
interpret the "length" bytes of payload.

- `NBD_REPLY_TYPE_NONE` (0)

  *length* MUST be 0 (and the payload field omitted).  This chunk
  type MUST always be used with the `NBD_REPLY_FLAG_DONE` bit set
  (that is, it may appear at most once in a structured reply, and
  is only useful as the final reply chunk).  If no earlier error
  chunks were sent, then this type implies that the overall client
  request is successful.  Valid as a reply to any request.

- `NBD_REPLY_TYPE_OFFSET_DATA` (1)

  This chunk type is in the content chunk category.  *length* MUST
  be at least 9.  It represents the contents of *length - 8* bytes
  of the file, starting at *offset*.  The data MUST lie within the
  bounds of the original offset and length of the client's
  request, and MUST NOT overlap with the bounds of any earlier
  content chunk or error chunk in the same reply.  This chunk MAY
  be used more than once in a reply, unless the `NBD_CMD_FLAG_DF`
  flag was set.  Valid as a reply to `NBD_CMD_READ`.

  The payload is structured as:

  64 bits: offset (unsigned)  
  *length - 8* bytes: data  

- `NBD_REPLY_TYPE_OFFSET_HOLE` (2)

  This chunk type is in the content chunk category.  *length* MUST
  be exactly 12.  It represents that the contents of *hole size*
  bytes starting at *offset* read as all zeroes.  The hole MUST
  lie within the bounds of the original offset and length of the
  client's request, and MUST NOT overlap with the bounds of any
  earlier content chunk or error chunk in the same reply.  This
  chunk MAY be used more than once in a reply, unless the
  `NBD_CMD_FLAG_DF` flag was set.  Valid as a reply to
  `NBD_CMD_READ`.

  The payload is structured as:

  64 bits: offset (unsigned)  
  32 bits: hole size (unsigned, MUST be nonzero)  

- `NBD_REPLY_TYPE_BLOCK_STATUS` (5)

    *length* MUST be 4 + (a positive integer multiple of 8).  This reply
    represents a series of consecutive block descriptors where the sum
    of the lengths of the descriptors MUST not be greater than the
    length of the original request. This chunk type MUST appear exactly
    once per metadata ID in a structured reply.

    The payload starts with:

        * 32 bits, metadata context ID

    and is followed by a list of one or more descriptors, each with this
    layout:

        * 32 bits, length (unsigned, MUST NOT be zero)
        * 32 bits, status flags

    If the client used the `NBD_CMD_FLAG_REQ_ONE` flag in the request,
    then every reply chunk MUST NOT contain more than one descriptor.

    Even if the client did not use the `NBD_CMD_FLAG_REQ_ONE` flag in
    its request, the server MAY return less descriptors in the reply
    than would be required to fully specify the whole range of requested
    information to the client, if the number of descriptors would be
    over 16 otherwise and looking up the information would be too
    resource-intensive for the server.

All error chunk types have bit 15 set, and begin with the same
*error*, *message length*, and optional *message* fields as
`NBD_REPLY_TYPE_ERROR`.  If non-zero, *message length* indicates
that an optional error string message appears next, suitable for
display to a human user.  The header *length* then covers any
remaining structured fields at the end.

- `NBD_REPLY_TYPE_ERROR` (2^15 + 1)

  This chunk type is in the error chunk category.  *length* MUST
  be at least 6.  This chunk represents that an error occurred,
  and the client MAY NOT make any assumptions about partial
  success. This type SHOULD NOT be used more than once in a
  structured reply.  Valid as a reply to any request.

  The payload is structured as:

  32 bits: error (MUST be nonzero)  
  16 bits: message length (no more than header *length* - 6)  
  *message length* bytes: optional string suitable for
    direct display to a human being  

- `NBD_REPLY_TYPE_ERROR_OFFSET` (2^15 + 2)

  This chunk type is in the error chunk category.  *length* MUST
  be at least 14.  This reply represents that an error occurred at
  a given offset, which MUST lie within the original offset and
  length of the request; the client can use this offset to
  determine if request had any partial success.  This chunk type
  MAY appear multiple times in a structured reply, although the
  same offset SHOULD NOT be repeated.  Likewise, if content chunks
  were sent earlier in the structured reply, the server SHOULD NOT
  send multiple distinct offsets that lie within the bounds of a
  single content chunk.  Valid as a reply to `NBD_CMD_READ`,
  `NBD_CMD_WRITE`, `NBD_CMD_TRIM`, and `NBD_CMD_BLOCK_STATUS`.

  The payload is structured as:

  32 bits: error (MUST be non-zero)  
  16 bits: message length (no more than header *length* - 14)  
  *message length* bytes: optional string suitable for
     direct display to a human being  
  64 bits: offset (unsigned)  

If the client receives an unknown or unexpected type with bit 15
set, it MUST consider the current reply as errored, but MAY
continue transmission unless it detects that *message length* is
too large to fit within the *length* specified by the header.  For
all other messages with unknown or unexpected type or inconsistent
contents, the client MUST initiate a hard disconnect.

#### Request types

The following request types exist:

* `NBD_CMD_READ` (0)

    A read request. Length and offset define the data to be read. The
    server MUST reply with either a simple reply or a structured
    reply, according to whether the structured replies have been
    negotiated using `NBD_OPT_STRUCTURED_REPLY`.

    *Simple replies*

    If structured replies were not negotiated, then a read request
    MUST always be answered by a simple reply, as documented above
    (using magic 0x67446698 `NBD_SIMPLE_REPLY_MAGIC`, and containing
    length bytes of data according to the client's request).

    If an error occurs, the server SHOULD set the appropriate error code
    in the error field. The server MAY then initiate a hard disconnect.
    If it chooses not to, it MUST NOT send any payload for this request.

    If an error occurs while reading after the server has already sent
    out the reply header with an error field set to zero (i.e.,
    signalling no error), the server MUST immediately initiate a
    hard disconnect; it MUST NOT send any further data to the client.

    *Structured replies*

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

    A client MAY initiate a hard disconnect if it detects that the server
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

    A flush request. The server MUST NOT send a
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

    Defined by the experimental `WRITE_ZEROES` [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-write-zeroes/doc/proto.md).

* `NBD_CMD_BLOCK_STATUS` (7)

    A block status query request. Length and offset define the range of
    interest. Clients MUST NOT use this request unless metadata
    contexts have been negotiated, which in turn requires the client to
    first negotiate structured replies. For a successful return, the
    server MUST use a structured reply, containing at least one chunk of
    type `NBD_REPLY_TYPE_BLOCK_STATUS`, where the status field of each
    descriptor is determined by the flags field as defined by the
    metadata context.

    The list of block status descriptors within the
    `NBD_REPLY_TYPE_BLOCK_STATUS` chunk represent consecutive portions
    of the file starting from specified *offset*, and the sum of the
    *length* fields of each descriptor MUST not be greater than the
    overall *length* of the request. This means that the server MAY
    return less data than required. However the server MUST return at
    least one status descriptor.  The server SHOULD use different
    *status* values between consecutive descriptors, and SHOULD use
    descriptor lengths that are an integer multiple of 512 bytes where
    possible (the first and last descriptor of an unaligned query being
    the most obvious places for an exception). The status flags are
    intentionally defined so that a server MAY always safely report a
    status of 0 for any block, although the server SHOULD return
    additional status values when they can be easily detected.

    If an error occurs, the server SHOULD set the appropriate error
    code in the error field of an error chunk. However, if the error
    does not involve invalid usage (such as a request beyond the bounds
    of the file), a server MAY reply with a single block status
    descriptor with *length* matching the requested length, and *status*
    of 0 rather than reporting the error.

    A client MAY initiate a hard disconnect if it detects that the
    server has sent an invalid chunk. The server SHOULD return `EINVAL`
    if it receives a `NBD_CMD_BLOCK_STATUS` request including one or
    more sectors beyond the size of the device.

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
* `EOVERFLOW` (75), Value too large.
* `ESHUTDOWN` (108), Server is in the process of being shut down.

The server SHOULD return `ENOSPC` if it receives a write request
including one or more sectors beyond the size of the device.  It also
SHOULD map the `EDQUOT` and `EFBIG` errors to `ENOSPC`.  Finally, it
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

In addition to the normative elements of the specification set out
herein, various experimental non-normative extensions have been
proposed. These may not be implemented in any known server or client,
and are subject to change at any point. A full implementation may
require changes to the specifications, or cause the specifications to
be withdrawn altogether.

These experimental extensions are set out in git branches starting
with names starting with the word 'extension'.

Currently known are:

* The `WRITE_ZEROES` [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-write-zeroes/doc/proto.md).

* The `STRUCTURED_REPLY` [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-structured-reply/doc/proto.md)

* The `INFO` [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-info/doc/proto.md).

* The `BLOCK_STATUS` [extension](https://github.com/NetworkBlockDevice/nbd/blob/extension-blockstatus/doc/proto.md).

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
