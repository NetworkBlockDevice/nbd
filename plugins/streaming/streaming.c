/* nbdkit
 * Copyright (C) 2014 Red Hat Inc.
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
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <nbdkit-plugin.h>

static char *filename = NULL;
static int fd = -1;

/* In theory INT64_MAX, but it breaks qemu's NBD driver. */
static int64_t size = INT64_MAX/2;

/* Flag if we have entered the unrecoverable error state because of
 * a seek backwards.
 */
static int errorstate = 0;

/* Highest byte (+1) that has been written in the data stream. */
static uint64_t highestwrite = 0;

/* Called for each key=value passed on the command line. */
static int
streaming_config (const char *key, const char *value)
{
  if (strcmp (key, "pipe") == 0) {
    /* See FILENAMES AND PATHS in nbdkit-plugin(3). */
    filename = nbdkit_absolute_path (value);
    if (!filename)
      return -1;
  }
  else if (strcmp (key, "size") == 0) {
    size = nbdkit_parse_size (value);
    if (size == -1)
      return -1;
  }
  else {
    nbdkit_error ("unknown parameter '%s'", key);
    return -1;
  }

  return 0;
}

/* Check the user did pass a pipe=<FILENAME> parameter. */
static int
streaming_config_complete (void)
{
  if (filename == NULL) {
    nbdkit_error ("you must supply the pipe=<FILENAME> parameter after the plugin name on the command line");
    return -1;
  }

  /* Open the file blindly.  If this fails with ENOENT then we create a
   * FIFO and try again.
   */
 again:
  fd = open (filename, O_RDWR|O_CLOEXEC|O_NOCTTY);
  if (fd == -1) {
    if (errno != ENOENT) {
      nbdkit_error ("open: %s: %m", filename);
      return -1;
    }
    if (mknod (filename, S_IFIFO | 0666, 0) == -1) {
      nbdkit_error ("mknod: %s: %m", filename);
      return -1;
    }
    goto again;
  }

  return 0;
}

/* nbdkit is shutting down. */
static void
streaming_unload (void)
{
  if (fd >= 0)
    close (fd);
  free (filename);
}

#define streaming_config_help \
  "pipe=<FILENAME>     (required) The filename to serve.\n" \
  "size=<SIZE>         (optional) Stream size."

/* Create the per-connection handle. */
static void *
streaming_open (int readonly)
{
  void *h;

  if (readonly) {
    nbdkit_error ("you cannot use the -r option with the streaming plugin");
    return NULL;
  }

  if (errorstate) {
    nbdkit_error ("unrecoverable error state, no new connections can be opened");
    return NULL;
  }

  /* There is no handle, so return an arbitrary non-NULL pointer. */
  h = &fd;

  return h;
}

/* Free up the per-connection handle. */
static void
streaming_close (void *handle)
{
}

#define THREAD_MODEL NBDKIT_THREAD_MODEL_SERIALIZE_ALL_REQUESTS

/* Return the size of the stream (infinite). */
static int64_t
streaming_get_size (void *handle)
{
  return size;
}

/* Write data to the stream. */
static int
streaming_pwrite (void *handle, const void *buf,
                  uint32_t count, uint64_t offset)
{
  size_t n;
  ssize_t r;

  if (errorstate) {
    nbdkit_error ("unrecoverable error state");
    errno = EIO;
    return -1;
  }

  if (offset < highestwrite) {
    nbdkit_error ("client tried to seek backwards and write: the streaming plugin does not currently support this");
    errorstate = 1;
    errno = EIO;
    return -1;
  }

  /* Need to write some zeroes. */
  if (offset > highestwrite) {
    int64_t size = offset - highestwrite;
    char buf[4096];

    memset (buf, 0, sizeof buf);

    while (size > 0) {
      n = size > sizeof buf ? sizeof buf : size;
      r = write (fd, buf, n);
      if (r == -1) {
        nbdkit_error ("write: %m");
        errorstate = 1;
        return -1;
      }
      highestwrite += r;
      size -= r;
    }
  }

  /* Write the data. */
  while (count > 0) {
    r = write (fd, buf, count);
    if (r == -1) {
      nbdkit_error ("write: %m");
      errorstate = 1;
      return -1;
    }
    buf += r;
    highestwrite += r;
    count -= r;
  }

  return 0;
}

/* Read data back from the stream. */
static int
streaming_pread (void *handle, void *buf, uint32_t count, uint64_t offset)
{
  if (errorstate) {
    nbdkit_error ("unrecoverable error state");
    errno = EIO;
    return -1;
  }

  /* Allow reads which are entirely >= highestwrite.  These return zeroes. */
  if (offset >= highestwrite) {
    memset (buf, 0, count);
    return 0;
  }

  nbdkit_error ("client tried to read: the streaming plugin does not currently support this");
  errorstate = 1;
  errno = EIO;
  return -1;
}

static struct nbdkit_plugin plugin = {
  .name              = "streaming",
  .longname          = "nbdkit streaming plugin",
  .version           = PACKAGE_VERSION,
  .unload            = streaming_unload,
  .config            = streaming_config,
  .config_complete   = streaming_config_complete,
  .config_help       = streaming_config_help,
  .open              = streaming_open,
  .close             = streaming_close,
  .get_size          = streaming_get_size,
  .pwrite            = streaming_pwrite,
  .pread             = streaming_pread,
};

NBDKIT_REGISTER_PLUGIN(plugin)
