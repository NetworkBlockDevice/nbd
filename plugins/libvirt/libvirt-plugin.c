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

/* libvirt-plugin:
 *
 * This uses the libvirt virDomainBlockPeek API to access the disks of
 * libvirt guests, even remotely.  This only works read-only (since
 * libvirt does not have an equivalent write API).
 *
 * http://libvirt.org/html/libvirt-libvirt.html#virDomainBlockPeek
 *
 * Note to compile this, ./configure must be able to find libvirt.
 * To unconditionally disable this plugin, use ./configure --without-libvirt
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <libvirt/libvirt.h>

#include <nbdkit-plugin.h>

/* Configuration. */
static const char *connect = NULL;
static const char *domain = NULL;
static const char *disk = NULL;

static int
virt_config (const char *key, const char *value)
{
  if (strcmp (key, "connect") == 0) {
    connect = value;
  }
  else if (strcmp (key, "domain") == 0) {
    domain = value;
  }
  else if (strcmp (key, "disk") == 0) {
    disk = value;
  }
  else {
    nbdkit_error ("unknown parameter '%s'", key);
    return -1;
  }

  return 0;
}

static int
virt_config_complete (void)
{
  if (domain == NULL) {
    nbdkit_error ("the 'domain' parameter is required");
    return -1;
  }
  if (disk == NULL) {
    nbdkit_error ("the 'disk' parameter is required");
    return -1;
  }
  return 0;
}

#define virt_config_help                                        \
  "connect=<URI>   (optional) libvirt connection URI\n"         \
  "domain=<DOMAIN> (required) libvirt domain name\n"            \
  "disk=<DISK>     (required) guest disk name"

/* The per-connection handle. */
struct virt_handle {
  virConnectPtr conn;
  virDomainPtr dom;
  uint64_t exportsize;
};

/* Create the per-connection handle. */
static void *
virt_open (void)
{
  struct virt_handle *h;
  virDomainBlockInfo info;

  h = malloc (sizeof *h);
  if (h == NULL) {
    nbdkit_error ("malloc: %m");
    return NULL;
  }

  /* Connect to libvirt. */
  h->conn = virConnectOpen (connect);
  if (!h->conn) {
    nbdkit_error ("virConnectOpen failed, see earlier error messages");
    goto err1;
  }

  /* Open the domain. */
  h->dom = virDomainLookupByName (h->conn, domain);
  if (!h->dom) {
    nbdkit_error ("virDomainLookupByName: "
                  "cannot open domain '%s'", domain);
    goto err2;
  }

  if (virDomainGetBlockInfo (h->dom, disk, &info, 0) == -1) {
    nbdkit_error ("virDomainGetBlockInfo: "
                  "cannot read information about disk '%s' from domain '%s'",
                  disk, domain);
    goto err3;
  }
  h->exportsize = info.physical;

  return h;

err3:
  virDomainFree (h->dom);
err2:
  virConnectClose (h->conn);
err1:
  free (h);
  return NULL;
}

/* Free up the per-connection handle. */
static void
virt_close (void *handle)
{
  struct virt_handle *h = handle;

  virDomainFree (h->dom);
  virConnectClose (h->conn);
  free (h);
}

#define THREAD_MODEL NBDKIT_THREAD_MODEL_SERIALIZE_REQUESTS

/* Get the file size. */
static int64_t
virt_get_size (void *handle)
{
  struct virt_handle *h = handle;

  return h->exportsize;
}

/* Read data from the file. */
static int
virt_pread (void *handle, void *buf, uint32_t count, uint64_t offset)
{
  struct virt_handle *h = handle;
  uint32_t c;

  while (count > 0) {
    /* Limit requests to 1MB, which was the limit in 0.9.13 (it has since
     * been raised).
     */
    c = count;
    if (c > 1024*1024)
      c = 1024*1024;

    if (virDomainBlockPeek (h->dom, disk, offset, c, buf, 0) == -1) {
      nbdkit_error ("virDomainBlockPeek: cannot read block from disk '%s'",
                    disk);
      errno = EIO;
      return -1;
    }

    buf += c;
    count -= c;
    offset += c;
  }

  return 0;
}

static struct nbdkit_plugin plugin = {
  .name              = "libvirt",
  .longname          = "nbdkit libvirt plugin",
  .version           = PACKAGE_VERSION,
  .config            = virt_config,
  .config_complete   = virt_config_complete,
  .config_help       = virt_config_help,
  .open              = virt_open,
  .close             = virt_close,
  .get_size          = virt_get_size,
  .pread             = virt_pread,
};

NBDKIT_REGISTER_PLUGIN(plugin)
