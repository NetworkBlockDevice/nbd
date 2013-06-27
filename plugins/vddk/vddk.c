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
#include <string.h>
#include <unistd.h>

#include <nbdkit-plugin.h>

#include <vixDiskLib.h>

#define VDDK_MAJOR 5
#define VDDK_MINOR 1

char *filename = NULL;
char *config = NULL;
const char *libdir = VDDK_LIBDIR;

#define VDDK_ERROR(err, fs, ...)                                \
  do {                                                          \
    char *vddk_err_msg;                                         \
    vddk_err_msg = VixDiskLib_GetErrorText ((err), NULL);       \
    nbdkit_error (fs ": %s", ##__VA_ARGS__, vddk_err_msg);      \
    VixDiskLib_FreeErrorText (vddk_err_msg);                    \
  } while (0)

static void
trim (char *str)
{
  size_t len = strlen (str);

  if (len > 0 && str[len-1] == '\n')
    str[len-1] = '\0';
}

/* Turn log messages from the library into nbdkit_debug. */
static void
debug_function (const char *fs, va_list args)
{
  char *str;

  if (vasprintf (&str, fs, args) == -1) {
    nbdkit_debug ("lost debug message: %s", fs);
    return;
  }

  trim (str);

  nbdkit_debug ("%s", str);
  free (str);
}

/* Turn error messages from the library into nbdkit_error. */
static void
error_function (const char *fs, va_list args)
{
  char *str;

  if (vasprintf (&str, fs, args) == -1) {
    nbdkit_error ("lost error message: %s", fs);
    return;
  }

  trim (str);

  nbdkit_error ("%s", str);
  free (str);
}

/* XXX Load callback needs a way to return errors. */
static int load_error = 0;

/* Load and unload the plugin. */
static void
vddk_load (void)
{
  VixError err;

  err = VixDiskLib_InitEx (VDDK_MAJOR, VDDK_MINOR,
                           &debug_function, &error_function, &error_function,
                           libdir, config);
  if (err != VIX_OK) {
    VDDK_ERROR (err, "VixDiskLib_InitEx");
    load_error = 1;
  }
}

static void
vddk_unload (void)
{
  VixDiskLib_Exit ();
  free (filename);
  free (config);
}

/* Configuration. */
static int
vddk_config (const char *key, const char *value)
{
  if (strcmp (key, "file") == 0) {
    /* See FILENAMES AND PATHS in nbdkit-plugin(3). */
    filename = nbdkit_absolute_path (value);
    if (!filename)
      return -1;
  }
  else if (strcmp (key, "config") == 0) {
    config = nbdkit_absolute_path (value);
    if (!config)
      return -1;
  }
  else if (strcmp (key, "libdir") == 0) {
    libdir = value;
  }
  else {
    nbdkit_error ("unknown parameter '%s'", key);
    return -1;
  }

  return 0;
}

static int
vddk_config_complete (void)
{
  if (filename == NULL) {
    nbdkit_error ("you must supply the file=<FILENAME> parameter after the plugin name on the command line");
    return -1;
  }

  return 0;
}

#define vddk_config_help \
  "file=<FILENAME>     (required) The filename (eg. VMDK file) to serve.\n" \
  "config=<FILENAME>   (optional) Location of VMware VDDK configuration file.\n" \
  "libdir=<LIBRARY>    (optional) Location of VMware VDDK library."

/* The per-connection handle. */
struct vddk_handle {
  VixDiskLibConnection connection; /* connection */
  VixDiskLibHandle handle;         /* disk handle */
};

/* Create the per-connection handle. */
static void *
vddk_open (int readonly)
{
  struct vddk_handle *h;
  VixError err;
  uint32_t flags;

  if (load_error) {
    nbdkit_error ("VDDK plugin could not be initialized");
    return NULL;
  }

  h = malloc (sizeof *h);
  if (h == NULL) {
    nbdkit_error ("malloc: %m");
    return NULL;
  }

  err = VixDiskLib_Connect (NULL, &h->connection);
  if (err != VIX_OK) {
    VDDK_ERROR (err, "VixDiskLib_Connect");
    goto err1;
  }

  flags = 0;
  if (readonly)
    flags |= VIXDISKLIB_FLAG_OPEN_READ_ONLY;

  err = VixDiskLib_Open (h->connection, filename, flags, &h->handle);
  if (err != VIX_OK) {
    VDDK_ERROR (err, "VixDiskLib_Open: %s", filename);
    goto err2;
  }

  return h;

 err2:
  VixDiskLib_Disconnect (h->connection);
 err1:
  free (h);
  return NULL;
}

/* Free up the per-connection handle. */
static void
vddk_close (void *handle)
{
  struct vddk_handle *h = handle;

  VixDiskLib_Close (h->handle);
  VixDiskLib_Disconnect (h->connection);
  free (h);
}

#define THREAD_MODEL NBDKIT_THREAD_MODEL_SERIALIZE_REQUESTS

/* Get the file size. */
static int64_t
vddk_get_size (void *handle)
{
  struct vddk_handle *h = handle;
  VixDiskLibInfo *info;
  VixError err;
  uint64_t size;

  err = VixDiskLib_GetInfo (h->handle, &info);
  if (err != VIX_OK) {
    VDDK_ERROR (err, "VixDiskLib_GetInfo");
    return -1;
  }

  size = info->capacity * (uint64_t)VIXDISKLIB_SECTOR_SIZE;

  VixDiskLib_FreeInfo (info);

  return (int64_t) size;
}

/* Read data from the file.
 *
 * Note that reads have to be aligned to sectors (XXX).
 */
static int
vddk_pread (void *handle, void *buf, uint32_t count, uint64_t offset)
{
  struct vddk_handle *h = handle;
  VixError err;

  /* Align to sectors. */
  if ((offset & (VIXDISKLIB_SECTOR_SIZE-1)) != 0) {
    nbdkit_error ("read is not aligned to sectors");
    return -1;
  }
  if ((count & (VIXDISKLIB_SECTOR_SIZE-1)) != 0) {
    nbdkit_error ("read is not aligned to sectors");
    return -1;
  }
  offset /= VIXDISKLIB_SECTOR_SIZE;
  count /= VIXDISKLIB_SECTOR_SIZE;

  err = VixDiskLib_Read (h->handle, offset, count, buf);
  if (err != VIX_OK) {
    VDDK_ERROR (err, "VixDiskLib_Read");
    return -1;
  }

  return 0;
}

/* Write data to the file.
 *
 * Note that writes have to be aligned to sectors (XXX).
 */
static int
vddk_pwrite (void *handle, const void *buf, uint32_t count, uint64_t offset)
{
  struct vddk_handle *h = handle;
  VixError err;

  /* Align to sectors. */
  if ((offset & (VIXDISKLIB_SECTOR_SIZE-1)) != 0) {
    nbdkit_error ("read is not aligned to sectors");
    return -1;
  }
  if ((count & (VIXDISKLIB_SECTOR_SIZE-1)) != 0) {
    nbdkit_error ("read is not aligned to sectors");
    return -1;
  }
  offset /= VIXDISKLIB_SECTOR_SIZE;
  count /= VIXDISKLIB_SECTOR_SIZE;

  err = VixDiskLib_Write (h->handle, offset, count, buf);
  if (err != VIX_OK) {
    VDDK_ERROR (err, "VixDiskLib_Write");
    return -1;
  }

  return 0;
}

static struct nbdkit_plugin plugin = {
  .name              = "vddk",
  .longname          = "VMware VDDK plugin",
  .version           = PACKAGE_VERSION,
  .load              = vddk_load,
  .unload            = vddk_unload,
  .config            = vddk_config,
  .config_complete   = vddk_config_complete,
  .config_help       = vddk_config_help,
  .open              = vddk_open,
  .close             = vddk_close,
  .get_size          = vddk_get_size,
  .pread             = vddk_pread,
  .pwrite            = vddk_pwrite,
};

NBDKIT_REGISTER_PLUGIN(plugin)
