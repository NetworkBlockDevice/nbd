/* nbdkit
 * Copyright (C) 2013 Red Hat Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of Red Hat nor the names of its contributors may be
 * used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY RED HAT AND CONTRIBUTORS ''AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL RED HAT OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef NBDKIT_PROTOCOL_H
#define NBDKIT_PROTOCOL_H

#include <stdint.h>

/* Old-style handshake. */
struct old_handshake {
  char nbdmagic[8];           /* "NBDMAGIC" */
  uint64_t version;           /* OLD_VERSION, in network byte order */
  uint64_t exportsize;        /* in network byte order */
  uint16_t gflags;            /* global flags, in network byte order */
  uint16_t eflags;            /* per-export flags, in network byte order */
  char zeroes[124];           /* must be sent as zero bytes */
} __attribute__((packed));

#define OLD_VERSION UINT64_C(0x420281861253)

/* New-style handshake. */
struct new_handshake {
  char nbdmagic[8];           /* "NBDMAGIC" */
  uint64_t version;           /* NEW_VERSION, in network byte order */
  uint16_t gflags;            /* global flags, in network byte order */
} __attribute__((packed));

#define NEW_VERSION UINT64_C(0x49484156454F5054)

/* New-style handshake option (sent by the client to us). */
struct new_option {
  uint64_t version;           /* NEW_VERSION, in network byte order */
  uint32_t option;            /* NBD_OPT_* */
  uint32_t optlen;            /* option data length */
  /* option data follows */
} __attribute__((packed));

/* Fixed newstyle handshake reply message. */
struct fixed_new_option_reply {
  uint64_t magic;             /* NBD_REP_MAGIC, network byte order */
  uint32_t option;            /* option we are replying to */
  uint32_t reply;             /* NBD_REP_* */
  uint32_t replylen;
} __attribute__((packed));

#define NBD_REP_MAGIC UINT64_C(0x3e889045565a9)

/* New-style handshake server reply. */
struct new_handshake_finish {
  uint64_t exportsize;        /* in network byte order */
  uint16_t eflags;            /* per-export flags, in network byte order */
  char zeroes[124];           /* must be sent as zero bytes */
} __attribute__((packed));

/* Global flags. */
#define NBD_FLAG_FIXED_NEWSTYLE 1

/* Per-export flags. */
#define NBD_FLAG_HAS_FLAGS   1
#define NBD_FLAG_READ_ONLY   2
#define NBD_FLAG_SEND_FLUSH  4
#define NBD_FLAG_SEND_FUA    8
#define NBD_FLAG_ROTATIONAL 16
#define NBD_FLAG_SEND_TRIM  32

/* NBD options (new style handshake only). */
#define NBD_OPT_EXPORT_NAME  1
#define NBD_OPT_ABORT        2
#define NBD_OPT_LIST         3

#define NBD_REP_ACK          1
#define NBD_REP_SERVER       2
#define NBD_REP_ERR_UNSUP    0x80000001
#define NBD_REP_ERR_POLICY   0x80000002
#define NBD_REP_ERR_INVALID  0x80000003
#define NBD_REP_ERR_PLATFORM 0x80000004

/* Request (client -> server). */
struct request {
  uint32_t magic;               /* NBD_REQUEST_MAGIC. */
  uint32_t type;                /* Request type. */
  uint64_t handle;              /* Opaque handle. */
  uint64_t offset;              /* Request offset. */
  uint32_t count;               /* Request length. */
} __attribute__((packed));

/* Reply (server -> client). */
struct reply {
  uint32_t magic;               /* NBD_REPLY_MAGIC. */
  uint32_t error;               /* NBD_SUCCESS or one of NBD_E*. */
  uint64_t handle;              /* Opaque handle. */
} __attribute__((packed));

#define NBD_REQUEST_MAGIC 0x25609513
#define NBD_REPLY_MAGIC 0x67446698

#define NBD_CMD_READ              0
#define NBD_CMD_WRITE             1
#define NBD_CMD_DISC              2 /* Disconnect. */
#define NBD_CMD_FLUSH             3
#define NBD_CMD_TRIM              4
#define NBD_CMD_MASK_COMMAND 0xffff
#define NBD_CMD_FLAG_FUA    (1<<16)

/* Error codes (previously errno).
 * See http://git.qemu.org/?p=qemu.git;a=commitdiff;h=ca4414804114fd0095b317785bc0b51862e62ebb
 */
#define NBD_SUCCESS     0
#define NBD_EPERM       1
#define NBD_EIO         5
#define NBD_ENOMEM     12
#define NBD_EINVAL     22
#define NBD_ENOSPC     28

#endif /* NBDKIT_PROTOCOL_H */
