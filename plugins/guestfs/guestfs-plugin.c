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
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <guestfs.h>

#include <nbdkit-plugin.h>

/* Configuration. */
static const char *connect = NULL; /* libvirt URI */
static const char *export = NULL;  /* export device or file */
static const char *format = NULL;  /* format parameter */
static int trace = 0, debug = 0;

/* disk and domain options.  (NB: list stored in reverse order) */
struct drive {
  struct drive *next;
  enum { drv_disk, drv_domain } type;
  const char *value;
  const char *format;
};
struct drive *drives = NULL;

/* mount options.  (NB: list stored in reverse order)  */
struct mount {
  struct mount *next;
  enum { mount_inspect, mount_fs } type;
  const char *dev;
  const char *mp;
};
struct mount *mounts = NULL;

static int
plugin_guestfs_config (const char *key, const char *value)
{
  if (strcmp (key, "debug") == 0) {
    if (sscanf (value, "%d", &debug) != 1) {
      nbdkit_error ("could not parse 'debug' option, expecting an integer");
      return -1;
    }
  }
  else if (strcmp (key, "trace") == 0) {
    if (sscanf (value, "%d", &trace) != 1) {
      nbdkit_error ("could not parse 'trace' option, expecting an integer");
      return -1;
    }
  }
  else if (strcmp (key, "connect") == 0) {
    connect = value;
  }
  else if (strcmp (key, "export") == 0) {
    export = value;
  }
  else if (strcmp (key, "format") == 0) {
    if (strcmp (value, "") != 0)
      format = value;
    else
      format = NULL;
  }
  else if (strcmp (key, "disk") == 0) {
    struct drive *d;

    d = malloc (sizeof *d);
    if (!d) {
      nbdkit_error ("malloc: %m");
      return -1;
    }
    d->type = drv_disk;
    d->value = value;
    d->format = format;
    d->next = drives;
    drives = d;
  }
  else if (strcmp (key, "domain") == 0) {
    struct drive *d;

    d = malloc (sizeof *d);
    if (!d) {
      nbdkit_error ("malloc: %m");
      return -1;
    }
    d->type = drv_domain;
    d->value = value;
    d->next = drives;
    drives = d;
  }
  else if (strcmp (key, "mount") == 0) {
    struct mount *m;
    char *p;

    m = malloc (sizeof *m);
    if (!m) {
      nbdkit_error ("malloc: %m");
      return -1;
    }

    if (strcmp (value, "inspect") == 0) {
      m->type = mount_inspect;
      m->dev = m->mp = NULL;
    }
    else if ((p = strchr (value, ':')) != NULL) {
      *p = '\0';
      m->type = mount_fs;
      m->dev = value;
      m->mp = p+1;
    }
    else {
      m->type = mount_fs;
      m->dev = value;
      m->mp = "/";
    }
    m->next = mounts;
    mounts = m;
  }
  else {
    nbdkit_error ("unknown parameter '%s'", key);
    return -1;
  }

  return 0;
}

static int
plugin_guestfs_config_complete (void)
{
  if (export == NULL) {
    nbdkit_error ("the 'export' parameter is required");
    return -1;
  }

  if (drives == NULL) {
    nbdkit_error ("at least one 'disk' or 'domain' parameter is required");
    return -1;
  }

  return 0;
}

#define plugin_guestfs_config_help                              \
  "connect=<URI>       (optional) libvirt connection URI\n"         \
  "domain=<DOMAIN>                libvirt domain name\n"            \
  "disk=<DISK>                    disk name\n"                      \
  "mount=inspect|MOUNT            mount filesystems\n"              \
  "export=DEVICE|FILE  (required) export device or file"

/* Free up the structures used to store the command line arguments.
 * Note the static strings don't need to be freed.
 */
static void
plugin_guestfs_unload (void)
{
  struct drive *d, *d_next;
  struct mount *m, *m_next;

  for (d = drives; d != NULL; d = d_next) {
    d_next = d->next;
    free (d);
  }

  for (m = mounts; m != NULL; m = m_next) {
    m_next = m->next;
    free (m);
  }
}

/* For libguestfs errors. */
#define GERROR(g,fs,...)                                                \
  do {                                                                  \
    nbdkit_error (fs ": %s", ##__VA_ARGS__,                             \
                  guestfs_last_error ((g)));                            \
  } while (0)

/* The per-connection handle. */
struct handle {
  guestfs_h *g;
  bool is_device;
  uint64_t exportsize;
};

static int set_up_logging (guestfs_h *g);
static int add_disks (guestfs_h *g, int readonly, struct drive *);
static int mount_filesystems (guestfs_h *g, int readonly, struct mount *);

/* Create the per-connection handle. */
static void *
plugin_guestfs_open (int readonly)
{
  struct handle *h;
  int64_t r;

  h = malloc (sizeof *h);
  if (h == NULL) {
    nbdkit_error ("malloc: %m");
    return NULL;
  }

  h->g = guestfs_create_flags (GUESTFS_CREATE_NO_ENVIRONMENT);
  if (!h->g) {
    nbdkit_error ("creating libguestfs handle: %m");
    goto err1;
  }

  guestfs_set_error_handler (h->g, NULL, NULL);

  if (trace)
    guestfs_set_trace (h->g, 1);

  if (debug)
    guestfs_set_verbose (h->g, 1);

  if (guestfs_parse_environment (h->g) == -1) {
    GERROR (h->g, "guestfs_parse_environment");
    goto err2;
  }

  if (set_up_logging (h->g) == -1)
    goto err2;

  if (add_disks (h->g, readonly, drives) == -1)
    goto err2;

  if (guestfs_launch (h->g) == -1) {
    GERROR (h->g, "guestfs_launch");
    goto err2;
  }

  if (mount_filesystems (h->g, readonly, mounts) == -1)
    goto err2;

  /* Exported thing. */
  if (strncmp (export, "/dev/", 5) == 0) {
    h->is_device = true;
    r = guestfs_blockdev_getsize64 (h->g, export);
    if (r == -1) {
      GERROR (h->g, "%s: guestfs_blockdev_getsize64", export);
      goto err2;
    }
    h->exportsize = (uint64_t) r;
  }
  else {
    h->is_device = false;
    r = guestfs_filesize (h->g, export);
    if (r == -1) {
      GERROR (h->g, "%s: guestfs_filesize", export);
      goto err2;
    }
    h->exportsize = (uint64_t) r;
  }

  nbdkit_debug ("guestfs: export %s, size = %" PRIu64 " bytes",
                export, h->exportsize);

  return h;

 err2:
  guestfs_close (h->g);
 err1:
  free (h);
  return NULL;
}

static void
log_to_nbdkit (guestfs_h *g,
               void *opaque,
               uint64_t event,
               int eh,
               int flags,
               const char *buf, size_t buf_len,
               const uint64_t *array, size_t array_len)
{
  char *sbuf;

  /* Note the buffer may not be \0 terminated.  Hence this. */
  sbuf = strndup (buf, buf_len);
  if (sbuf) {
    nbdkit_debug ("%s", sbuf);
    free (sbuf);
  }
}

static int
set_up_logging (guestfs_h *g)
{
  int eh;
  const uint64_t EVENTS =
    GUESTFS_EVENT_APPLIANCE | GUESTFS_EVENT_LIBRARY | GUESTFS_EVENT_TRACE;

  eh = guestfs_set_event_callback (g, log_to_nbdkit, EVENTS, 0, NULL);
  if (eh == -1) {
    GERROR (g, "guestfs_set_event_callback");
    return -1;
  }

  return 0;
}

static int
add_disks (guestfs_h *g, int readonly, struct drive *drives)
{
  struct guestfs_add_domain_argv domain_optargs;
  struct guestfs_add_drive_opts_argv drive_optargs;

  if (drives == NULL)
    return 0;

  /* Because the 'drives' list is stored in reverse order, use some
   * creative recursion to add the drives in the intended order.
   */
  if (add_disks (g, readonly, drives->next) == -1)
    return -1;

  switch (drives->type) {
  case drv_domain:
    domain_optargs.bitmask =
      GUESTFS_ADD_DOMAIN_READONLY_BITMASK |
      GUESTFS_ADD_DOMAIN_ALLOWUUID_BITMASK;
    domain_optargs.readonly = readonly;
    domain_optargs.allowuuid = 1;
    if (connect) {
      domain_optargs.bitmask |= GUESTFS_ADD_DOMAIN_LIBVIRTURI_BITMASK;
      domain_optargs.libvirturi = connect;
    }
    if (guestfs_add_domain_argv (g, drives->value, &domain_optargs) == -1) {
      GERROR (g, "domain %s", drives->value);
      return -1;
    }
    break;

  case drv_disk:
    drive_optargs.bitmask = GUESTFS_ADD_DRIVE_OPTS_READONLY_BITMASK;
    drive_optargs.readonly = readonly;
    if (drives->format) {
      drive_optargs.bitmask |= GUESTFS_ADD_DRIVE_OPTS_FORMAT_BITMASK;
      drive_optargs.format = drives->format;
    }
    if (guestfs_add_drive_opts_argv (g, drives->value, &drive_optargs) == -1) {
      GERROR (g, "disk %s", drives->value);
      return -1;
    }
    break;

  default:
    abort ();
  }

  return 0;
}

static int
inspect_and_mount (guestfs_h *g, const char *options)
{
  char **roots = NULL;
  const char *root;
  char **mountpoints = NULL;
  size_t i, mounted;
  int ret = -1;

  roots = guestfs_inspect_os (g);
  if (roots == NULL) {
    GERROR (g, "mount=inspect: guestfs_inspect_os");
    goto out;
  }

  if (roots[0] == NULL) {
    nbdkit_error ("no operating system was found inside this disk image");
    goto out;
  }

  if (roots[1] != NULL) {
    nbdkit_error ("multiple operating system were found; the plugin doesn't support that");
    goto out;
  }
  root = roots[0];

  mountpoints = guestfs_inspect_get_mountpoints (g, root);
  if (mountpoints == NULL) {
    GERROR (g, "mount=inspect: guestfs_inspect_get_mountpoints");
    goto out;
  }

  /* Ignore errors as long as at least one filesystem is mountable. */
  mounted = 0;
  for (i = 0; mountpoints[i] != NULL; i += 2) {
    if (guestfs_mount_options (g, options,
                               mountpoints[i+1], mountpoints[i]) == 0)
      mounted++;
  }
  if (mounted == 0) {
    nbdkit_error ("mount=inspect: could not mount any filesystems");
    goto out;
  }

  ret = 0;
 out:
  if (roots) {
    for (i = 0; roots[i] != NULL; ++i)
      free (roots[i]);
    free (roots);
  }
  if (mountpoints) {
    for (i = 0; mountpoints[i] != NULL; ++i)
      free (mountpoints[i]);
    free (mountpoints);
  }

  return ret;
}

static int
mount_filesystems (guestfs_h *g, int readonly, struct mount *mounts)
{
  const char *options = readonly ? "ro" : "";

  if (mounts == NULL)
    return 0;

  /* Because the 'mounts' list is stored in reverse order, use some
   * creative recursion to add the drives in the intended order.
   */
  if (mount_filesystems (g, readonly, mounts->next) == -1)
    return -1;

  switch (mounts->type) {
  case mount_fs:
    if (guestfs_mount_options (g, options, mounts->dev, mounts->mp) == -1) {
      GERROR (g, "mount [%s] %s:%s", options, mounts->dev, mounts->mp);
      return -1;
    }
    break;

  case mount_inspect:
    /* Ask libguestfs to inspect for operating systems. */
    if (inspect_and_mount (g, options) == -1)
      return -1;
    break;
  }

  return 0;
}

/* Free up the per-connection handle. */
static void
plugin_guestfs_close (void *handle)
{
  struct handle *h = handle;

  if (guestfs_shutdown (h->g) == -1) {
    GERROR (h->g, "shutdown failure: there may be unwritten data");
    /* ... but we can't do anything about it, see note in nbdkit-plugin(3) */
  }
  guestfs_close (h->g);
  free (h);
}

#define THREAD_MODEL NBDKIT_THREAD_MODEL_SERIALIZE_REQUESTS

/* Get the file size. */
static int64_t
plugin_guestfs_get_size (void *handle)
{
  struct handle *h = handle;

  return h->exportsize;
}

/* Read data. */
static int
plugin_guestfs_pread (void *handle, void *buf, uint32_t count, uint64_t offset)
{
  struct handle *h = handle;
  char *(*pr) (guestfs_h *, const char *, int, int64_t, size_t *);
  char *data;
  size_t size;

  if (h->is_device)
    pr = guestfs_pread_device;
  else
    pr = guestfs_pread;

  while (count > 0) {
    data = pr (h->g, export, count, offset, &size);
    if (!data) {
      GERROR (h->g, "%s: pread", export);
      errno = guestfs_last_errno (h->g) ? : EIO;
      return -1;
    }

    memcpy (buf, data, size);
    free (data);

    buf += size;
    offset += size;
    count -= size;
  }

  return 0;
}

/* Write data. */
static int
plugin_guestfs_pwrite (void *handle, const void *buf,
                       uint32_t count, uint64_t offset)
{
  struct handle *h = handle;
  int (*pw) (guestfs_h *, const char *, const char *, size_t, int64_t);
  int r;

  if (h->is_device)
    pw = guestfs_pwrite_device;
  else
    pw = guestfs_pwrite;

  while (count > 0) {
    r = pw (h->g, export, buf, count, offset);
    if (r == -1) {
      GERROR (h->g, "%s: pwrite", export);
      errno = guestfs_last_errno (h->g) ? : EIO;
      return -1;
    }

    buf += r;
    offset += r;
    count -= r;
  }

  return 0;
}

/* Sync. */
static int
plugin_guestfs_flush (void *handle)
{
  struct handle *h = handle;

  if (guestfs_sync (h->g) == -1) {
    GERROR (h->g, "guestfs_sync");
    errno = guestfs_last_errno (h->g) ? : EIO;
    return -1;
  }

  return 0;
}

static struct nbdkit_plugin plugin = {
  .name              = "guestfs",
  .longname          = "nbdkit guestfs plugin",
  .version           = PACKAGE_VERSION,
  .config            = plugin_guestfs_config,
  .config_complete   = plugin_guestfs_config_complete,
  .config_help       = plugin_guestfs_config_help,
  .unload            = plugin_guestfs_unload,
  .open              = plugin_guestfs_open,
  .close             = plugin_guestfs_close,
  .get_size          = plugin_guestfs_get_size,
  .pread             = plugin_guestfs_pread,
  .pwrite            = plugin_guestfs_pwrite,
  .flush             = plugin_guestfs_flush,
};

NBDKIT_REGISTER_PLUGIN(plugin)
