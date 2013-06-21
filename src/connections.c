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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <endian.h>
#include <sys/types.h>

#include <pthread.h>

#include "nbdkit-plugin.h"
#include "internal.h"
#include "protocol.h"

/* Maximum read or write request that we will handle. */
#define MAX_REQUEST_SIZE (64 * 1024 * 1024)

static struct connection *new_connection (int sockin, int sockout);
static void free_connection (struct connection *conn);
static int negotiate_handshake (struct connection *conn);
static int recv_request_send_reply (struct connection *conn);

static int
_handle_single_connection (int sockin, int sockout)
{
  int r;
  struct connection *conn = new_connection (sockin, sockout);

  if (!conn)
    goto err;

  if (plugin_open (conn, readonly) == -1)
    goto err;

  tls_set_name (plugin_name ());

  /* Handshake. */
  if (negotiate_handshake (conn) == -1)
    goto err;

  /* Process requests.  XXX Allow these to be dispatched in parallel using
   * a thread pool.
   */
  while (!quit) {
    r = recv_request_send_reply (conn);
    if (r == -1)
      goto err;
    if (r == 0)
      break;
  }

  free_connection (conn);
  return 0;

 err:
  free_connection (conn);
  return -1;
}

int
handle_single_connection (int sockin, int sockout)
{
  int r;

  plugin_lock_connection ();
  r = _handle_single_connection (sockin, sockout);
  plugin_unlock_connection ();

  return r;
}

static struct connection *
new_connection (int sockin, int sockout)
{
  struct connection *conn;

  conn = calloc (1, sizeof *conn);
  if (conn == NULL) {
    perror ("malloc");
    return NULL;
  }

  conn->sockin = sockin;
  conn->sockout = sockout;
  pthread_mutex_init (&conn->request_lock, NULL);

  return conn;
}

static void
free_connection (struct connection *conn)
{
  if (!conn)
    return;

  if (conn->sockin >= 0)
    close (conn->sockin);
  if (conn->sockout >= 0 && conn->sockin != conn->sockout)
    close (conn->sockout);

  pthread_mutex_destroy (&conn->request_lock);

  if (conn->handle)
    plugin_close (conn);

  free (conn);
}

/* XXX Note because we don't support multiple plugins or export names,
 * we are using the old-style handshake.  This will be fixed.
 */
static int
_negotiate_handshake (struct connection *conn)
{
  struct old_handshake handshake;
  int64_t r;
  uint64_t exportsize;
  uint16_t gflags, eflags;
  int fl;

  r = plugin_get_size (conn);
  if (r == -1)
    return -1;
  if (r < 0) {
    nbdkit_error (".get_size function returned invalid value "
                  "(%" PRIi64 ")", r);
    return -1;
  }
  exportsize = (uint64_t) r;
  conn->exportsize = exportsize;

  gflags = 0;
  eflags = NBD_FLAG_HAS_FLAGS;

  fl = plugin_can_write (conn);
  if (fl == -1)
    return -1;
  if (readonly || !fl) {
    eflags |= NBD_FLAG_READ_ONLY;
    conn->readonly = 1;
  }

  fl = plugin_can_flush (conn);
  if (fl == -1)
    return -1;
  if (fl) {
    eflags |= NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA;
    conn->can_flush = 1;
  }

  fl = plugin_is_rotational (conn);
  if (fl == -1)
    return -1;
  if (fl) {
    eflags |= NBD_FLAG_ROTATIONAL;
    conn->is_rotational = 1;
  }

  fl = plugin_can_trim (conn);
  if (fl == -1)
    return -1;
  if (fl) {
    eflags |= NBD_FLAG_SEND_TRIM;
    conn->can_trim = 1;
  }

  debug ("flags: global 0x%x export 0x%x", gflags, eflags);

  memset (&handshake, 0, sizeof handshake);
  memcpy (handshake.nbdmagic, "NBDMAGIC", 8);
  handshake.version = htobe64 (OLD_VERSION);
  handshake.exportsize = htobe64 (exportsize);
  handshake.gflags = htobe16 (gflags);
  handshake.eflags = htobe16 (eflags);

  if (xwrite (conn->sockout, &handshake, sizeof handshake) == -1) {
    nbdkit_error ("write: %m");
    return -1;
  }

  return 0;
}

static int
negotiate_handshake (struct connection *conn)
{
  int r;

  plugin_lock_request (conn);
  r = _negotiate_handshake (conn);
  plugin_unlock_request (conn);

  return r;
}

static int
valid_range (struct connection *conn, uint64_t offset, uint32_t count)
{
  uint64_t exportsize = conn->exportsize;

  return count > 0 && offset <= exportsize && offset + count <= exportsize;
}

static int
validate_request (struct connection *conn,
                  uint32_t cmd, uint32_t flags, uint64_t offset, uint32_t count,
                  uint32_t *error)
{
  int r;

  /* Validate cmd, offset, count. */
  switch (cmd) {
  case NBD_CMD_READ:
  case NBD_CMD_WRITE:
  case NBD_CMD_TRIM:
    r = valid_range (conn, offset, count);
    if (r == -1)
      return -1;
    if (r == 0) {
      /* XXX Allow writes to extend the disk? */
      nbdkit_error ("invalid request: offset and length are out of range");
      *error = EIO;
      return 0;
    }
    break;

  case NBD_CMD_FLUSH:
    if (offset != 0 || count != 0) {
      nbdkit_error ("invalid flush request: expecting offset and length == 0");
      *error = EINVAL;
      return 0;
    }
    break;

  default:
    nbdkit_error ("invalid request: unknown command (%" PRIu32 ") ignored",
                  cmd);
    *error = EINVAL;
    return 0;
  }

  /* Refuse over-large read and write requests. */
  if ((cmd == NBD_CMD_WRITE || cmd == NBD_CMD_READ) &&
      count > MAX_REQUEST_SIZE) {
    nbdkit_error ("invalid request: data request is too large (%" PRIu32
                  " > %d)", count, MAX_REQUEST_SIZE);
    *error = ENOMEM;
    return 0;
  }

  /* Readonly connection? */
  if (conn->readonly &&
      (cmd == NBD_CMD_WRITE || cmd == NBD_CMD_FLUSH ||
       cmd == NBD_CMD_TRIM)) {
    nbdkit_error ("invalid request: write request on readonly connection");
    *error = EROFS;
    return 0;
  }

  /* Flush allowed? */
  if (!conn->can_flush && cmd == NBD_CMD_FLUSH) {
    nbdkit_error ("invalid request: flush operation not supported");
    *error = EINVAL;
    return 0;
  }

  /* Trim allowed? */
  if (!conn->can_trim && cmd == NBD_CMD_TRIM) {
    nbdkit_error ("invalid request: trim operation not supported");
    *error = EINVAL;
    return 0;
  }

  return 1;                     /* Commands validates. */
}

/* This is called with the request lock held to actually execute the
 * request (by calling the plugin).  Note that the request fields have
 * been validated already in 'validate_request' so we don't have to
 * check them again.  'buf' is either the data to be written or the
 * data to be returned, and points to a buffer of size 'count' bytes.
 *
 * Only returns -1 if there is a fatal error and the connection cannot
 * continue.
 *
 * On read/write errors, sets *error to errno (or EIO if errno is not
 * set) and returns 0.
 */
static int
_handle_request (struct connection *conn,
                 uint32_t cmd, uint32_t flags, uint64_t offset, uint32_t count,
                 void *buf,
                 uint32_t *error)
{
  bool flush_after_command;
  int r;

  /* Flush after command performed? */
  flush_after_command = (flags & NBD_CMD_FLAG_FUA) != 0;
  if (!conn->can_flush || conn->readonly)
    flush_after_command = false;

  switch (cmd) {
  case NBD_CMD_READ:
    r = plugin_pread (conn, buf, count, offset);
    if (r == -1) {
      *error = errno ? errno : EIO;
      return 0;
    }
    break;

  case NBD_CMD_WRITE:
    r = plugin_pwrite (conn, buf, count, offset);
    if (r == -1) {
      *error = errno ? errno : EIO;
      return 0;
    }
    break;

  case NBD_CMD_FLUSH:
    r = plugin_flush (conn);
    if (r == -1) {
      *error = errno ? errno : EIO;
      return 0;
    }
    break;

  case NBD_CMD_TRIM:
    r = plugin_trim (conn, count, offset);
    if (r == -1) {
      *error = errno ? errno : EIO;
      return 0;
    }
    break;

  default:
    abort ();
  }

  if (flush_after_command) {
    r = plugin_flush (conn);
    if (r == -1) {
      *error = errno ? errno : EIO;
      return 0;
    }
  }

  return 0;
}

static int
handle_request (struct connection *conn,
                uint32_t cmd, uint32_t flags, uint64_t offset, uint32_t count,
                void *buf,
                uint32_t *error)
{
  int r;

  plugin_lock_request (conn);
  r = _handle_request (conn, cmd, flags, offset, count, buf, error);
  plugin_unlock_request (conn);

  return r;
}

static void
skip_over_write_buffer (int sock, size_t count)
{
  char buf[BUFSIZ];
  ssize_t r;

  while (count > 0) {
    r = read (sock, buf, count > BUFSIZ ? BUFSIZ : count);
    if (r == -1) {
      nbdkit_error ("skipping write buffer: %m");
      return;
    }
    if (r == 0)
      return;
    count -= r;
  }
}

static int
recv_request_send_reply (struct connection *conn)
{
  int r;
  struct request request;
  struct reply reply;
  uint32_t magic, cmd, flags, count, error = 0;
  uint64_t offset;
  CLEANUP_FREE char *buf = NULL;

  /* Read the request packet. */
  r = xread (conn->sockin, &request, sizeof request);
  if (r == -1) {
    nbdkit_error ("read request: %m");
    return -1;
  }
  if (r == 0) {
    debug ("client closed input socket, closing connection");
    return 0;                   /* disconnect */
  }

  magic = be32toh (request.magic);
  if (magic != NBD_REQUEST_MAGIC) {
    nbdkit_error ("invalid request: 'magic' field is incorrect (0x%x)", magic);
    return -1;
  }

  cmd = be32toh (request.type);
  flags = cmd;
  cmd &= NBD_CMD_MASK_COMMAND;

  offset = be64toh (request.offset);
  count = be32toh (request.count);

  if (cmd == NBD_CMD_DISC) {
    debug ("client sent disconnect command, closing connection");
    return 0;                   /* disconnect */
  }

  /* Validate the request. */
  r = validate_request (conn, cmd, flags, offset, count, &error);
  if (r == -1)
    return -1;
  if (r == 0) {                 /* request not valid */
    if (cmd == NBD_CMD_WRITE)
      skip_over_write_buffer (conn->sockin, count);
    goto send_reply;
  }

  /* Allocate the data buffer used for either read or write requests. */
  if (cmd == NBD_CMD_READ || cmd == NBD_CMD_WRITE) {
    buf = malloc (count);
    if (buf == NULL) {
      perror ("malloc");
      error = ENOMEM;
      if (cmd == NBD_CMD_WRITE)
        skip_over_write_buffer (conn->sockin, count);
      goto send_reply;
    }
  }

  /* Receive the write data buffer. */
  if (cmd == NBD_CMD_WRITE) {
    r = xread (conn->sockin, buf, count);
    if (r == -1) {
      nbdkit_error ("read data: %m");
      return -1;
    }
    if (r == 0) {
      debug ("client closed input unexpectedly, closing connection");
      return 0;                 /* disconnect */
    }
  }

  /* Perform the request.  Only this part happens inside the request lock. */
  r = handle_request (conn, cmd, flags, offset, count, buf, &error);
  if (r == -1)
    return -1;

  /* Send the reply packet. */
 send_reply:
  reply.magic = htobe32 (NBD_REPLY_MAGIC);
  reply.handle = request.handle;
  reply.error = htobe32 (error);

  r = xwrite (conn->sockout, &reply, sizeof reply);
  if (r == -1) {
    nbdkit_error ("write reply: %m");
    return -1;
  }

  /* Send the read data buffer. */
  if (cmd == NBD_CMD_READ) {
    r = xwrite (conn->sockout, buf, count);
    if (r == -1) {
      nbdkit_error ("write data: %m");
      return -1;
    }
  }

  return 1;                     /* command processed ok */
}
