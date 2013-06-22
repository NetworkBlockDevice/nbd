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
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <lzma.h>

#include <nbdkit-plugin.h>

#include "xzfile.h"

static char *filename = NULL;
static uint64_t maxblock = 512 * 1024 * 1024;

static void
xz_unload (void)
{
  free (filename);
}

/* Called for each key=value passed on the command line.  This plugin
 * only accepts file=<filename>, which is required.
 */
static int
xz_config (const char *key, const char *value)
{
  if (strcmp (key, "file") == 0) {
    /* See FILENAMES AND PATHS in nbdkit-plugin(3). */
    filename = nbdkit_absolute_path (value);
    if (!filename)
      return -1;
  }
  else if (strcmp (key, "maxblock") == 0) {
    int64_t r = nbdkit_parse_size (value);
    if (r == -1)
      return -1;
    maxblock = (uint64_t) r;
  }
  else {
    nbdkit_error ("unknown parameter '%s'", key);
    return -1;
  }

  return 0;
}

/* Check the user did pass a file=<FILENAME> parameter. */
static int
xz_config_complete (void)
{
  if (filename == NULL) {
    nbdkit_error ("you must supply the file=<FILENAME> parameter after the plugin name on the command line");
    return -1;
  }

  return 0;
}

#define xz_config_help \
  "file=<FILENAME>     (required) The filename to serve.\n" \
  "maxblock=<SIZE>     (optional) Maximum block size allowed (default: 512M)"

/* Translate a gzerror to nbdkit_error. */
#define nbdkit_gzerror(gz, fs, ...)                        \
  do {                                                     \
    int gzerrnum;                                          \
    const char *gzerr = gzerror ((gz), &gzerrnum);         \
    if (gzerrnum == Z_ERRNO) {                             \
      nbdkit_error ((fs ": %m"), ## __VA_ARGS__);          \
    } else {                                               \
      nbdkit_error ((fs ": %s"), ## __VA_ARGS__, gzerr);   \
    }                                                      \
  } while (0)

/* The per-connection handle. */
struct xz_handle {
  xzfile *xz;

  /* Currently we cache just one block of uncompressed data.  We could
   * be much smarter! XXX
   */
  char *data;
  uint64_t start, size;

  /* The cache is rubbish, but let's collect stats about how rubbish
   * it is.
   */
  size_t hits, misses;
};

/* Create the per-connection handle. */
static void *
xz_open (int readonly)
{
  struct xz_handle *h;

  h = malloc (sizeof *h);
  if (h == NULL) {
    nbdkit_error ("malloc: %m");
    return NULL;
  }

  h->data = NULL;
  h->start = h->size = 0;
  h->hits = h->misses = 0;

  h->xz = xzfile_open (filename);
  if (!h->xz)
    goto err1;

  if (maxblock < xzfile_max_uncompressed_block_size (h->xz)) {
    nbdkit_error ("%s: xz file largest block is bigger than maxblock\n"
                  "Either recompress the xz file with smaller blocks (see nbdkit-xz-plugin(1))\n"
                  "or make maxblock parameter bigger.\n"
                  "maxblock = %" PRIu64 " (bytes)\n"
                  "largest block in xz file = %" PRIu64 " (bytes)",
                  filename,
                  maxblock,
                  xzfile_max_uncompressed_block_size (h->xz));
    goto err1;
  }

  return h;

 err1:
  free (h);
  return NULL;
}

/* Free up the per-connection handle. */
static void
xz_close (void *handle)
{
  struct xz_handle *h = handle;

  nbdkit_debug ("cache: hits = %" PRIu64 ", misses = %" PRIu64,
                h->hits, h->misses);

  free (h->data);
  xzfile_close (h->xz);
  free (h);
}

#define THREAD_MODEL NBDKIT_THREAD_MODEL_SERIALIZE_REQUESTS

/* Get the file size. */
static int64_t
xz_get_size (void *handle)
{
  struct xz_handle *h = handle;

  return xzfile_get_size (h->xz);
}

/* Read data from the file. */
static int
xz_pread (void *handle, void *buf, uint32_t count, uint64_t offset)
{
  struct xz_handle *h = handle;
  uint32_t n;

  /* Does this block lie entirely within the existing cached data? */
  if (h->data != NULL &&
      h->start <= offset && offset+count <= h->start + h->size) {
    h->hits++;
    nbdkit_debug ("pread: hit: copying data from buffer offset %" PRIu64,
                  offset - h->start);
    memcpy (buf, &h->data[offset - h->start], count);
    return 0;
  }

  h->misses++;

  free (h->data);
  h->data = xzfile_read_block (h->xz, offset, &h->start, &h->size);
  if (h->data == NULL)
    return -1;

  nbdkit_debug ("pread: miss: read block containing offset %" PRIu64
                " [%" PRIu64 " + %" PRIu64 "]",
                offset, h->start, h->size);

  /* It's possible if the blocks are really small or oddly aligned or
   * if the requests are large that we need to read the following
   * block to satisfy the request.
   */
  n = count;
  if (h->start + h->size - offset < n)
    n = h->start + h->size - offset;

  nbdkit_debug ("pread: miss: copying data from buffer offset %" PRIu64,
                offset - h->start);

  memcpy (buf, &h->data[offset - h->start], n);
  buf += n;
  count -= n;
  offset += n;
  if (count > 0)
    return xz_pread (h, buf, count, offset);

  return 0;
}

static struct nbdkit_plugin plugin = {
  .name              = "xz",
  .version           = PACKAGE_VERSION,
  .unload            = xz_unload,
  .config            = xz_config,
  .config_complete   = xz_config_complete,
  .config_help       = xz_config_help,
  .open              = xz_open,
  .close             = xz_close,
  .get_size          = xz_get_size,
  .pread             = xz_pread,
};

NBDKIT_REGISTER_PLUGIN(plugin)
