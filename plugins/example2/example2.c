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

/* example2:
 *
 * A simple but more realistic read-only file server.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <nbdkit-plugin.h>

static char *filename = NULL;

static void
example2_unload (void)
{
  free (filename);
}

/* Called for each key=value passed on the command line.  This plugin
 * only accepts file=<filename>, which is required.
 */
static int
example2_config (const char *key, const char *value)
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
example2_config_complete (void)
{
  if (filename == NULL) {
    nbdkit_error ("you must supply the file=<FILENAME> parameter after the plugin name on the command line");
    return -1;
  }

  return 0;
}

#define example2_config_help \
  "file=<FILENAME>     (required) The filename to serve."

/* The per-connection handle. */
struct example2_handle {
  int fd;
};

/* Create the per-connection handle.
 *
 * Because this plugin can only serve readonly, we can ignore the
 * 'readonly' parameter.
 */
static void *
example2_open (int readonly)
{
  struct example2_handle *h;

  h = malloc (sizeof *h);
  if (h == NULL) {
    nbdkit_error ("malloc: %m");
    return NULL;
  }

  h->fd = open (filename, O_RDONLY|O_CLOEXEC);
  if (h->fd == -1) {
    nbdkit_error ("open: %s: %m", filename);
    free (h);
    return NULL;
  }

  return h;
}

/* Free up the per-connection handle. */
static void
example2_close (void *handle)
{
  struct example2_handle *h = handle;

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
example2_get_size (void *handle)
{
  struct example2_handle *h = handle;
  struct stat statbuf;

  if (fstat (h->fd, &statbuf) == -1) {
    nbdkit_error ("stat: %m");
    return -1;
  }

  return statbuf.st_size;
}

/* Read data from the file. */
static int
example2_pread (void *handle, void *buf, uint32_t count, uint64_t offset)
{
  struct example2_handle *h = handle;

  while (count > 0) {
    ssize_t r = pread (h->fd, buf, count, offset);
    if (r == -1) {
      nbdkit_error ("pread: %m");
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

static struct nbdkit_plugin plugin = {
  .name              = "example2",
  .version           = PACKAGE_VERSION,
  .unload            = example2_unload,
  .config            = example2_config,
  .config_complete   = example2_config_complete,
  .config_help       = example2_config_help,
  .open              = example2_open,
  .close             = example2_close,
  .get_size          = example2_get_size,
  .pread             = example2_pread,
};

NBDKIT_REGISTER_PLUGIN(plugin)
