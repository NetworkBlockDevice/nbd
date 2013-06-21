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

#include <zlib.h>

#include <nbdkit-plugin.h>

static char *filename = NULL;

static void
gzip_unload (void)
{
  free (filename);
}

/* Called for each key=value passed on the command line.  This plugin
 * only accepts file=<filename>, which is required.
 */
static int
gzip_config (const char *key, const char *value)
{
  if (strcmp (key, "file") == 0) {
    /* See FILENAMES AND PATHS in nbdkit-plugin(3). */
    filename = nbdkit_absolute_path (value);
    if (!filename)
      return -1;
  }
  else {
    nbdkit_error ("unknown parameter '%s'", key);
    return -1;
  }

  return 0;
}

/* Check the user did pass a file=<FILENAME> parameter. */
static int
gzip_config_complete (void)
{
  if (filename == NULL) {
    nbdkit_error ("you must supply the file=<FILENAME> parameter after the plugin name on the command line");
    return -1;
  }

  return 0;
}

#define gzip_config_help \
  "file=<FILENAME>     (required) The filename to serve."

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
struct gzip_handle {
  gzFile gz;
  uint64_t exportsize;
};

/* Create the per-connection handle. */
static void *
gzip_open (int readonly)
{
  struct gzip_handle *h;
  char buf[BUFSIZ];
  int r;

  h = malloc (sizeof *h);
  if (h == NULL) {
    nbdkit_error ("malloc: %m");
    return NULL;
  }

  h->gz = gzopen (filename, "r");
  if (h->gz == NULL) {
    nbdkit_error ("gzopen: %s: %m", filename);
    goto err1;
  }

  gzbuffer (h->gz, 128 * 1024);

  /* Work out the size of the uncompressed file - expensive!  Note
   * that seeking to the end of the file is not supported, so instead
   * we have to read the file and discard it.
   */
  h->exportsize = 0;
  do {
    r = gzread (h->gz, buf, BUFSIZ);
    h->exportsize += r;
  } while (r > 0);
  if (r == -1) {
    nbdkit_gzerror (h->gz, "gzread: %s", filename);
    goto err2;
  }

  nbdkit_debug ("gzip: %s: uncompressed size = %" PRIu64,
                filename, h->exportsize);

  if (gzrewind (h->gz) == -1) {
    nbdkit_gzerror (h->gz, "gzrewind: unable to rewind file");
    goto err2;
  }

  return h;

 err2:
  gzclose (h->gz);
 err1:
  free (h);
  return NULL;
}

/* Free up the per-connection handle. */
static void
gzip_close (void *handle)
{
  struct gzip_handle *h = handle;

  gzclose (h->gz);
  free (h);
}

#define THREAD_MODEL NBDKIT_THREAD_MODEL_SERIALIZE_REQUESTS

/* Get the file size. */
static int64_t
gzip_get_size (void *handle)
{
  struct gzip_handle *h = handle;

  return h->exportsize;
}

/* Read data from the file. */
static int
gzip_pread (void *handle, void *buf, uint32_t count, uint64_t offset)
{
  struct gzip_handle *h = handle;

  if (gzseek (h->gz, offset, SEEK_SET) == -1) {
    nbdkit_gzerror (h->gz, "gzseek");
    return -1;
  }

  while (count > 0) {
    int r = gzread (h->gz, buf, count);
    if (r == -1) {
      nbdkit_gzerror (h->gz, "gzread");
      return -1;
    }
    if (r == 0) {
      nbdkit_error ("gzread: unexpected end of file (count=%" PRIu32 ")",
                    count);
      return -1;
    }
    buf += r;
    count -= r;
  }

  return 0;
}

static struct nbdkit_plugin plugin = {
  .name              = "gzip",
  .version           = PACKAGE_VERSION,
  .unload            = gzip_unload,
  .config            = gzip_config,
  .config_complete   = gzip_config_complete,
  .config_help       = gzip_config_help,
  .open              = gzip_open,
  .close             = gzip_close,
  .get_size          = gzip_get_size,
  .pread             = gzip_pread,
};

NBDKIT_REGISTER_PLUGIN(plugin)
