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

#ifndef NBDKIT_INTERNAL_H
#define NBDKIT_INTERNAL_H

#include <stdbool.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <pthread.h>

#include "nbdkit-plugin.h"

#ifdef __APPLE__
#define UNIX_PATH_MAX 104
#else
#define UNIX_PATH_MAX 108
#endif

/* main.c */
extern const char *ipaddr;
extern int newstyle;
extern const char *port;
extern int readonly;
extern char *unixsocket;
extern int verbose;

extern volatile int quit;

/* cleanup.c */
extern void cleanup_free (void *ptr);
#ifdef HAVE_ATTRIBUTE_CLEANUP
#define CLEANUP_FREE __attribute__((cleanup (cleanup_free)))
#else
#define CLEANUP_FREE
#endif

/* connections.c */
struct connection {
  int sockin, sockout;
  pthread_mutex_t request_lock;
  void *handle;
  uint64_t exportsize;
  int readonly;
  int can_flush;
  int is_rotational;
  int can_trim;
};

extern int handle_single_connection (int sockin, int sockout);

/* errors.c */
#define debug nbdkit_debug

/* plugins.c */
extern void plugin_register (const char *_filename, void *_dl, struct nbdkit_plugin *(*plugin_init) (void));
extern void plugin_cleanup (void);
extern const char *plugin_name (void);
extern void plugin_usage (void);
extern void plugin_version (void);
extern void plugin_config (const char *key, const char *value);
extern void plugin_config_complete (void);
extern void plugin_lock_connection (void);
extern void plugin_unlock_connection (void);
extern void plugin_lock_request (struct connection *conn);
extern void plugin_unlock_request (struct connection *conn);
extern int plugin_open (struct connection *conn, int readonly);
extern void plugin_close (struct connection *conn);
extern int64_t plugin_get_size (struct connection *conn);
extern int plugin_can_write (struct connection *conn);
extern int plugin_can_flush (struct connection *conn);
extern int plugin_is_rotational (struct connection *conn);
extern int plugin_can_trim (struct connection *conn);
extern int plugin_pread (struct connection *conn, void *buf, uint32_t count, uint64_t offset);
extern int plugin_pwrite (struct connection *conn, void *buf, uint32_t count, uint64_t offset);
extern int plugin_flush (struct connection *conn);
extern int plugin_trim (struct connection *conn, uint32_t count, uint64_t offset);

/* sockets.c */
extern int *bind_unix_socket (size_t *);
extern int *bind_tcpip_socket (size_t *);
extern void accept_incoming_connections (int *socks, size_t nr_socks);
extern void free_listening_sockets (int *socks, size_t nr_socks);

/* tls.c */
extern void tls_init (void);
extern void tls_new_server_thread (void);
extern void tls_set_name (const char *name);
extern void tls_set_instance_num (size_t instance_num);
extern void tls_set_sockaddr (struct sockaddr *addr, socklen_t addrlen);
extern const char *tls_get_name (void);
extern size_t tls_get_instance_num (void);
/*extern void tls_get_sockaddr ();*/

/* utils.c */
extern int xread (int sock, void *buf, size_t len);
extern int xwrite (int sock, const void *buf, size_t len);

/* Declare program_name. */
#if HAVE_DECL_PROGRAM_INVOCATION_SHORT_NAME == 1
#include <errno.h>
#define program_name program_invocation_short_name
#else
#define program_name "nbdkit"
#endif

#endif /* NBDKIT_INTERNAL_H */
