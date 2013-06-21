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

/* See nbdkit-plugin(3) for documentation and how to write a plugin. */

#ifndef NBDKIT_PLUGIN_H
#define NBDKIT_PLUGIN_H

#include <stdarg.h>
#include <stdint.h>

#define NBDKIT_THREAD_MODEL_SERIALIZE_CONNECTIONS     0
#define NBDKIT_THREAD_MODEL_SERIALIZE_ALL_REQUESTS    1
#define NBDKIT_THREAD_MODEL_SERIALIZE_REQUESTS        2
#define NBDKIT_THREAD_MODEL_PARALLEL                  3

struct nbdkit_plugin {
  uint64_t _struct_size;
  int _api_version;
  int _thread_model;

  const char *name;
  const char *longname;
  const char *version;
  const char *description;

  void (*load) (void);
  void (*unload) (void);

  int (*config) (const char *key, const char *value);
  int (*config_complete) (void);
  const char *config_help;

  void * (*open) (int readonly);
  void (*close) (void *handle);

  int64_t (*get_size) (void *handle);

  int (*can_write) (void *handle);
  int (*can_flush) (void *handle);
  int (*is_rotational) (void *handle);
  int (*can_trim) (void *handle);

  int (*pread) (void *handle, void *buf, uint32_t count, uint64_t offset);
  int (*pwrite) (void *handle, const void *buf, uint32_t count, uint64_t offset);
  int (*flush) (void *handle);
  int (*trim) (void *handle, uint32_t count, uint64_t offset);

  /* int (*set_exportname) (void *handle, const char *exportname); */
};

extern void nbdkit_error (const char *msg, ...)
  __attribute__((format (printf, 1, 2)));
extern void nbdkit_verror (const char *msg, va_list args);
extern void nbdkit_debug (const char *msg, ...)
  __attribute__((format (printf, 1, 2)));
extern void nbdkit_vdebug (const char *msg, va_list args);

extern char *nbdkit_absolute_path (const char *path);
extern int64_t nbdkit_parse_size (const char *str);

#define NBDKIT_REGISTER_PLUGIN(plugin)                                  \
  struct nbdkit_plugin *                                                \
  plugin_init (void)                                                    \
  {                                                                     \
    (plugin)._struct_size = sizeof (plugin);                            \
    (plugin)._api_version = 1;                                          \
    (plugin)._thread_model = THREAD_MODEL;                              \
    return &(plugin);                                                   \
  }

#endif /* NBDKIT_PLUGIN_H */
