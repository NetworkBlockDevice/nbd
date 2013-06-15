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
#include <inttypes.h>
#include <assert.h>

#include <dlfcn.h>

#include "nbdkit-plugin.h"
#include "internal.h"

static pthread_mutex_t connection_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t all_requests_lock = PTHREAD_MUTEX_INITIALIZER;

/* Currently the server can only load one plugin (see TODO).  Hence we
 * can just use globals to store these.
 */
static const char *filename;
static void *dl;
static struct nbdkit_plugin plugin;

void
plugin_register (const char *_filename,
                 void *_dl, struct nbdkit_plugin *(*plugin_init) (void))
{
  const struct nbdkit_plugin *_plugin;
  size_t i, len, size;

  filename = _filename;
  dl = _dl;

  debug ("registering %s", filename);

  /* Call the initialization function which returns the address of the
   * plugin's own 'struct nbdkit_plugin'.
   */
  _plugin = plugin_init ();
  if (!_plugin) {
    fprintf (stderr, "%s: %s: plugin registration function failed\n",
             program_name, filename);
    exit (EXIT_FAILURE);
  }

  /* Check for incompatible future versions. */
  if (_plugin->_api_version != 1) {
    fprintf (stderr, "%s: %s: plugin is incompatible with this version of nbdkit (_api_version = %d)\n",
             program_name, filename, _plugin->_api_version);
    exit (EXIT_FAILURE);
  }

  /* Since the plugin might be much older than the current version of
   * nbdkit, only copy up to the self-declared _struct_size of the
   * plugin and zero out the rest.  If the plugin is much newer then
   * we'll only call the "old" fields.
   */
  size = sizeof plugin;         /* our struct */
  memset (&plugin, 0, size);
  if (size > _plugin->_struct_size)
    size = _plugin->_struct_size;
  memcpy (&plugin, _plugin, size);

  /* Check for the minimum fields which must exist in the
   * plugin struct.
   */
  if (plugin.name == NULL) {
    fprintf (stderr, "%s: %s: plugin must have a .name field\n",
             program_name, filename);
    exit (EXIT_FAILURE);
  }
  if (plugin.open == NULL) {
    fprintf (stderr, "%s: %s: plugin must have a .open callback\n",
             program_name, filename);
    exit (EXIT_FAILURE);
  }
  if (plugin.get_size == NULL) {
    fprintf (stderr, "%s: %s: plugin must have a .get_size callback\n",
             program_name, filename);
    exit (EXIT_FAILURE);
  }
  if (plugin.pread == NULL) {
    fprintf (stderr, "%s: %s: plugin must have a .pread callback\n",
             program_name, filename);
    exit (EXIT_FAILURE);
  }

  len = strlen (plugin.name);
  if (len == 0) {
    fprintf (stderr, "%s: %s: plugin.name field must not be empty\n",
             program_name, filename);
    exit (EXIT_FAILURE);
  }
  for (i = 0; i < len; ++i) {
    if (!((plugin.name[i] >= '0' && plugin.name[i] <= '9') ||
          (plugin.name[i] >= 'a' && plugin.name[i] <= 'z') ||
          (plugin.name[i] >= 'A' && plugin.name[i] <= 'Z'))) {
      fprintf (stderr, "%s: %s: plugin.name ('%s') field must contain only ASCII alphanumeric characters\n",
               program_name, filename, plugin.name);
      exit (EXIT_FAILURE);
    }
  }

  debug ("registered %s (name %s)", filename, plugin.name);

  /* Call the on-load callback if it exists. */
  debug ("%s: load", filename);
  if (plugin.load)
    plugin.load ();
}

void
plugin_cleanup (void)
{
  if (dl) {
    debug ("%s: unload", filename);
    if (plugin.unload)
      plugin.unload ();

    dlclose (dl);
    dl = NULL;
  }
}

const char *
plugin_name (void)
{
  assert (dl);

  return plugin.name;
}

void
plugin_usage (void)
{
  assert (dl);

  printf ("%s", plugin.name);
  if (plugin.longname)
    printf (" (%s)", plugin.longname);
  printf ("\n");
  if (plugin.description) {
    printf ("\n");
    printf ("%s\n", plugin.description);
  }
  if (plugin.config_help) {
    printf ("\n");
    printf ("%s\n", plugin.config_help);
  }
}

void
plugin_version (void)
{
  assert (dl);

  printf ("%s", plugin.name);
  if (plugin.version)
    printf (" %s", plugin.version);
  printf ("\n");
}

void
plugin_config (const char *key, const char *value)
{
  assert (dl);

  debug ("%s: config key=%s, value=%s",
         filename, key, value);

  if (plugin.config == NULL) {
    fprintf (stderr, "%s: %s: this plugin does not need command line configuration\n"
             "Try using: %s --help %s\n",
             program_name, filename,
             program_name, filename);
    exit (EXIT_FAILURE);
  }

  if (plugin.config (key, value) == -1)
    exit (EXIT_FAILURE);
}

void
plugin_config_complete (void)
{
  assert (dl);

  debug ("%s: config_complete", filename);

  if (!plugin.config_complete)
    return;

  if (plugin.config_complete () == -1)
    exit (EXIT_FAILURE);
}

/* Handle the thread model. */
void
plugin_lock_connection (void)
{
  assert (dl);

  if (plugin._thread_model <= NBDKIT_THREAD_MODEL_SERIALIZE_CONNECTIONS) {
    debug ("%s: acquire connection lock", filename);
    pthread_mutex_lock (&connection_lock);
  }
}

void
plugin_unlock_connection (void)
{
  assert (dl);

  if (plugin._thread_model <= NBDKIT_THREAD_MODEL_SERIALIZE_CONNECTIONS) {
    debug ("%s: release connection lock", filename);
    pthread_mutex_unlock (&connection_lock);
  }
}

void
plugin_lock_request (struct connection *conn)
{
  assert (dl);

  if (plugin._thread_model <= NBDKIT_THREAD_MODEL_SERIALIZE_ALL_REQUESTS) {
    debug ("%s: acquire global request lock", filename);
    pthread_mutex_lock (&all_requests_lock);
  }

  if (plugin._thread_model <= NBDKIT_THREAD_MODEL_SERIALIZE_REQUESTS) {
    debug ("%s: acquire per-connection request lock", filename);
    pthread_mutex_lock (&conn->request_lock);
  }
}

void
plugin_unlock_request (struct connection *conn)
{
  assert (dl);

  if (plugin._thread_model <= NBDKIT_THREAD_MODEL_SERIALIZE_REQUESTS) {
    debug ("%s: release per-connection request lock", filename);
    pthread_mutex_unlock (&conn->request_lock);
  }

  if (plugin._thread_model <= NBDKIT_THREAD_MODEL_SERIALIZE_ALL_REQUESTS) {
    debug ("%s: release global request lock", filename);
    pthread_mutex_unlock (&all_requests_lock);
  }
}

int
plugin_open (struct connection *conn)
{
  void *handle;

  assert (dl);
  assert (conn->handle == NULL);
  assert (plugin.open != NULL);

  debug ("%s: open", filename);

  handle = plugin.open ();
  if (!handle)
    return -1;

  conn->handle = handle;
  return 0;
}

void
plugin_close (struct connection *conn)
{
  assert (dl);
  assert (conn->handle);

  debug ("close");

  if (plugin.close)
    plugin.close (conn->handle);

  conn->handle = NULL;
}

int64_t
plugin_get_size (struct connection *conn)
{
  assert (dl);
  assert (conn->handle);
  assert (plugin.get_size != NULL);

  debug ("get_size");

  return plugin.get_size (conn->handle);
}

int
plugin_can_write (struct connection *conn)
{
  assert (dl);
  assert (conn->handle);

  debug ("can_write");

  if (plugin.can_write)
    return plugin.can_write (conn->handle);
  else
    return plugin.pwrite != NULL;
}

int
plugin_can_flush (struct connection *conn)
{
  assert (dl);
  assert (conn->handle);

  debug ("can_flush");

  if (plugin.can_flush)
    return plugin.can_flush (conn->handle);
  else
    return plugin.flush != NULL;
}

int
plugin_is_rotational (struct connection *conn)
{
  assert (dl);
  assert (conn->handle);

  debug ("is_rotational");

  if (plugin.is_rotational)
    return plugin.is_rotational (conn->handle);
  else
    return 0; /* assume false */
}

int
plugin_can_trim (struct connection *conn)
{
  assert (dl);
  assert (conn->handle);

  debug ("can_trim");

  if (plugin.can_trim)
    return plugin.can_trim (conn->handle);
  else
    return plugin.trim != NULL;
}

int
plugin_pread (struct connection *conn,
              void *buf, uint32_t count, uint64_t offset)
{
  assert (dl);
  assert (conn->handle);
  assert (plugin.pread != NULL);

  debug ("pread count=%" PRIu32 " offset=%" PRIu64, count, offset);

  return plugin.pread (conn->handle, buf, count, offset);
}

int
plugin_pwrite (struct connection *conn,
               void *buf, uint32_t count, uint64_t offset)
{
  assert (dl);
  assert (conn->handle);

  debug ("pwrite count=%" PRIu32 " offset=%" PRIu64, count, offset);

  if (plugin.pwrite != NULL)
    return plugin.pwrite (conn->handle, buf, count, offset);
  else {
    errno = EROFS;
    return -1;
  }
}

int
plugin_flush (struct connection *conn)
{
  assert (dl);
  assert (conn->handle);

  debug ("flush");

  if (plugin.flush != NULL)
    return plugin.flush (conn->handle);
  else {
    errno = EINVAL;
    return -1;
  }
}

int
plugin_trim (struct connection *conn, uint32_t count, uint64_t offset)
{
  assert (dl);
  assert (conn->handle);

  debug ("trim count=%" PRIu32 " offset=%" PRIu64, count, offset);

  if (plugin.trim != NULL)
    return plugin.trim (conn->handle, count, offset);
  else {
    errno = EINVAL;
    return -1;
  }
}
