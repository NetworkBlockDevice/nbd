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
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "nbdkit-plugin.h"
#include "internal.h"

char *
nbdkit_absolute_path (const char *path)
{
  CLEANUP_FREE char *pwd = NULL;
  char *ret;

  if (path == NULL || *path == '\0') {
    nbdkit_error ("cannot convert null or empty path to an absolute path");
    return NULL;
  }

  if (*path == '/') {
    ret = strdup (path);
    if (!ret) {
      nbdkit_error ("strdup: %m");
      return NULL;
    }
    return ret;
  }

  pwd = get_current_dir_name ();
  if (pwd == NULL) {
    nbdkit_error ("get_current_dir_name: %m");
    return NULL;
  }

  if (asprintf (&ret, "%s/%s", pwd, path) == -1) {
    nbdkit_error ("asprintf: %m");
    return NULL;
  }

  return ret;
}

/* XXX Multiple problems with this function.  Really we should use the
 * 'human*' functions from gnulib.
 */
int64_t
nbdkit_parse_size (const char *str)
{
  uint64_t size;
  char t;

  if (sscanf (str, "%" SCNu64, &size) == 1)
    return (int64_t) size;
  if (sscanf (str, "%" SCNu64 "%c", &size, &t) == 2) {
    switch (t) {
    case 'b': case 'B':
      return (int64_t) size;
    case 'k': case 'K':
      return (int64_t) size * 1024;
    case 'm': case 'M':
      return (int64_t) size * 1024 * 1024;
    case 'g': case 'G':
      return (int64_t) size * 1024 * 1024 * 1024;
    case 't': case 'T':
      return (int64_t) size * 1024 * 1024 * 1024 * 1024;
    case 'p': case 'P':
      return (int64_t) size * 1024 * 1024 * 1024 * 1024 * 1024;
    case 'e': case 'E':
      return (int64_t) size * 1024 * 1024 * 1024 * 1024 * 1024 * 1024;

    case 's': case 'S':         /* "sectors", ie. units of 512 bytes,
                                 * even if that's not the real sector size
                                 */
      return (int64_t) size * 512;

    default:
      nbdkit_error ("could not parse size: unknown specifier '%c'", t);
      return -1;
    }
  }

  nbdkit_error ("could not parse size string (%s)", str);
  return -1;
}

/* Write buffer to socket and either succeed completely (returns 0)
 * or fail (returns -1).
 */
int
xwrite (int sock, const void *vbuf, size_t len)
{
  const char *buf = vbuf;
  ssize_t r;

  while (len > 0) {
    r = write (sock, buf, len);
    if (r == -1) {
      if (errno == EINTR || errno == EAGAIN)
        continue;
      return -1;
    }
    buf += r;
    len -= r;
  }

  return 0;
}

/* Read buffer from socket and either succeed completely (returns > 0),
 * read an EOF (returns 0), or fail (returns -1).
 */
int
xread (int sock, void *vbuf, size_t len)
{
  char *buf = vbuf;
  ssize_t r;
  bool first_read = true;

  while (len > 0) {
    r = read (sock, buf, len);
    if (r == -1) {
      if (errno == EINTR || errno == EAGAIN)
        continue;
      return -1;
    }
    if (r == 0) {
      if (first_read)
        return 0;
      /* Partial record read.  This is an error. */
      errno = EBADMSG;
      return -1;
    }
    first_read = false;
    buf += r;
    len -= r;
  }

  return 1;
}
