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

/* example3:
 *
 * A simple read-write filesystem which stores all changes in
 * a temporary file that is thrown away after each connection.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <nbdkit-plugin.h>

/* The size of disk in bytes (initialized by size=<SIZE> parameter).
 * If size parameter is not specified, it defaults to 100M.
 */
static uint64_t size = 100 * 1024 * 1024;

/* Called for each key=value passed on the command line.  This plugin
 * only accepts optional size=<SIZE> parameter.
 */
static int
example3_config (const char *key, const char *value)
{
  int64_t r;

  if (strcmp (key, "size") == 0) {
    r = nbdkit_parse_size (value);
    if (r == -1)
      return -1;
    size = (uint64_t) r;
  }
  else {
    nbdkit_error ("unknown parameter '%s'", key);
    return -1;
  }

  return 0;
}

#define example3_config_help \
  "size=<SIZE>  (optional) Size of the backing disk (default: 100M)"

/* The per-connection handle. */
struct example3_handle {
  int fd;
};

/* Create the per-connection handle. */
static void *
example3_open (void)
{
  struct example3_handle *h;
  char template[] = "/var/tmp/diskXXXXXX";

  h = malloc (sizeof *h);
  if (h == NULL) {
    nbdkit_error ("malloc: %m");
    return NULL;
  }

  h->fd = mkstemp (template);
  if (h->fd == -1) {
    nbdkit_error ("mkstemp: %s: %m", template);
    free (h);
    return NULL;
  }

  unlink (template);

  /* This creates a raw-format sparse file of the required size. */
  if (ftruncate (h->fd, size) == -1) {
    nbdkit_error ("ftruncate: %m");
    close (h->fd);
    free (h);
    return NULL;
  }

  return h;
}

/* Free up the per-connection handle. */
static void
example3_close (void *handle)
{
  struct example3_handle *h = handle;

  close (h->fd);
  free (h);
}

/* In fact NBDKIT_THREAD_MODEL_SERIALIZE_REQUESTS would work here.
 * However for the benefit of people who blindly cut and paste code
 * without bothering to read any documentation, leave this at a safe
 * default.
 */
#define THREAD_MODEL NBDKIT_THREAD_MODEL_SERIALIZE_ALL_REQUESTS

/* Get the file size. */
static int64_t
example3_get_size (void *handle)
{
  return (int64_t) size;
}

/* Read data from the file. */
static int
example3_pread (void *handle, void *buf, uint32_t count, uint64_t offset)
{
  struct example3_handle *h = handle;

  while (count > 0) {
    ssize_t r = pread (h->fd, buf, count, offset);
    if (r == -1) {
      nbdkit_error ("pead: %m");
      return -1;
    }
    if (r == 0) {
      nbdkit_error ("pread: unexpected end of file");
      return -1;
    }
    buf += r;
    count -= r;
    offset += r;
  }

  return 0;
}

/* Write data to the file. */
static int
example3_pwrite (void *handle, const void *buf, uint32_t count, uint64_t offset)
{
  struct example3_handle *h = handle;

  while (count > 0) {
    ssize_t r = pwrite (h->fd, buf, count, offset);
    if (r == -1) {
      nbdkit_error ("pwrite: %m");
      return -1;
    }
    buf += r;
    count -= r;
    offset += r;
  }

  return 0;
}

/* Flush the file to disk. */
static int
example3_flush (void *handle)
{
  struct example3_handle *h = handle;

  if (fdatasync (h->fd) == -1) {
    nbdkit_error ("fdatasync: %m");
    return -1;
  }

  return 0;
}

static struct nbdkit_plugin plugin = {
  .name              = "example3",
  .version           = PACKAGE_VERSION,
  .config            = example3_config,
  .config_help       = example3_config_help,
  .open              = example3_open,
  .close             = example3_close,
  .get_size          = example3_get_size,
  .pread             = example3_pread,
  .pwrite            = example3_pwrite,
  .flush             = example3_flush,
};

NBDKIT_REGISTER_PLUGIN(plugin)
