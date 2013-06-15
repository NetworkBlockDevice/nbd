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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <assert.h>

#include <pthread.h>

#include "nbdkit-plugin.h"
#include "internal.h"

int *
bind_unix_socket (size_t *nr_socks)
{
  size_t len;
  int sock;
  struct sockaddr_un addr;
  int *ret;

  assert (unixsocket);
  assert (unixsocket[0] == '/');

  len = strlen (unixsocket);
  if (len >= UNIX_PATH_MAX) {
    fprintf (stderr, "%s: -U option: path too long (max is %d) bytes",
             program_name, UNIX_PATH_MAX-1);
    exit (EXIT_FAILURE);
  }

  sock = socket (AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
  if (sock == -1) {
    perror ("socket");
    exit (EXIT_FAILURE);
  }

  addr.sun_family = AF_UNIX;
  memcpy (addr.sun_path, unixsocket, len);

  if (bind (sock, (struct sockaddr *) &addr, sizeof addr) == -1) {
    perror (unixsocket);
    exit (EXIT_FAILURE);
  }

  if (listen (sock, SOMAXCONN) == -1) {
    perror ("listen");
    exit (EXIT_FAILURE);
  }

  ret = malloc (sizeof (int));
  if (!ret) {
    perror ("malloc");
    exit (EXIT_FAILURE);
  }
  ret[0] = sock;
  *nr_socks = 1;

  debug ("bound to unix socket %s", unixsocket);

  return ret;
}

int *
bind_tcpip_socket (size_t *nr_socks)
{
  struct addrinfo *ai = NULL;
  struct addrinfo hints;
  struct addrinfo *a;
  int err, opt;
  int *socks = NULL;
  bool addr_in_use;

  if (port == NULL)
    port = "10809";

  memset (&hints, 0, sizeof hints);
  hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
  hints.ai_socktype = SOCK_STREAM;

  err = getaddrinfo (ipaddr, port, &hints, &ai);
  if (err != 0) {
    fprintf (stderr, "%s: getaddrinfo: %s: %s: %s",
             program_name,
             ipaddr ? ipaddr : "<any>",
             port,
             gai_strerror (err));
    exit (EXIT_FAILURE);
  }

  *nr_socks = 0;

  for (a = ai; a != NULL; a = a->ai_next) {
    int sock;

    sock = socket (a->ai_family, a->ai_socktype, a->ai_protocol);
    if (sock == -1) {
      perror ("socket");
      exit (EXIT_FAILURE);
    }

    opt = 1;
    if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt) == -1)
      perror ("setsockopt: SO_REUSEADDR");

#ifdef IPV6_V6ONLY
    if (a->ai_family == PF_INET6) {
      if (setsockopt (sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof opt) == -1)
        perror ("setsockopt: IPv6 only");
    }
#endif

    if (bind (sock, a->ai_addr, a->ai_addrlen) == -1) {
      if (errno == EADDRINUSE) {
        addr_in_use = true;
        close (sock);
        continue;
      }
      perror ("bind");
      exit (EXIT_FAILURE);
    }

    if (listen (sock, SOMAXCONN) == -1) {
      perror ("listen");
      exit (EXIT_FAILURE);
    }

    (*nr_socks)++;
    socks = realloc (socks, sizeof (int) * (*nr_socks));
    if (!socks) {
      perror ("realloc");
      exit (EXIT_FAILURE);
    }
    socks[*nr_socks - 1] = sock;
  }

  freeaddrinfo (ai);

  if (*nr_socks == 0 && addr_in_use) {
    fprintf (stderr, "%s: unable to bind to any sockets: %s\n",
             program_name, strerror (EADDRINUSE));
    exit (EXIT_FAILURE);
  }

  debug ("bound to IP address %s:%s (%d socket(s))",
         ipaddr ? ipaddr : "<any>", port, *nr_socks);

  return socks;
}

void
free_listening_sockets (int *socks, size_t nr_socks)
{
  size_t i;

  for (i = 0; i < nr_socks; ++i)
    close (socks[i]);
  free (socks);
}

struct thread_data {
  int sock;
  size_t instance_num;
  struct sockaddr addr;
  socklen_t addrlen;
};

static void *
start_thread (void *datav)
{
  struct thread_data *data = datav;

  debug ("accepted connection");

  /* Set thread-local data. */
  tls_new_server_thread ();
  tls_set_instance_num (data->instance_num);
  tls_set_sockaddr (&data->addr, data->addrlen);

  handle_single_connection (data->sock, data->sock);

  return NULL;
}

static void
accept_connection (int listen_sock)
{
  int err;
  pthread_attr_t attrs;
  pthread_t thread;
  struct thread_data thread_data;
  static size_t instance_num = 1;

  thread_data.instance_num = instance_num++;
  thread_data.addrlen = sizeof thread_data.addr;
 again:
  thread_data.sock = accept (listen_sock,
                             &thread_data.addr, &thread_data.addrlen);
  if (thread_data.sock == -1) {
    if (errno == EINTR || errno == EAGAIN)
      goto again;
    perror ("accept");
    return;
  }

  /* Start a thread to handle this connection.  Note we always do this
   * even for non-threaded plugins.  There are mutexes in plugins.c
   * which ensure that non-threaded plugins are handled correctly.
   */
  pthread_attr_init (&attrs);
  pthread_attr_setdetachstate (&attrs, PTHREAD_CREATE_DETACHED);
  err = pthread_create (&thread, &attrs, start_thread, &thread_data);
  pthread_attr_destroy (&attrs);
  if (err != 0) {
    fprintf (stderr, "%s: pthread_create: %s\n", program_name, strerror (err));
    close (thread_data.sock);
    return;
  }

  /* If the thread starts successfully, then it is responsible for
   * closing the socket.
   */
}

void
accept_incoming_connections (int *socks, size_t nr_socks)
{
  struct pollfd fds[nr_socks];
  size_t i;
  int r;

  while (!quit) {
    for (i = 0; i < nr_socks; ++i) {
      fds[i].fd = socks[i];
      fds[i].events = POLLIN;
      fds[i].revents = 0;
    }

    r = poll (fds, nr_socks, -1);
    if (r == -1) {
      if (errno == EINTR || errno == EAGAIN)
        continue;
      perror ("poll");
      exit (EXIT_FAILURE);
    }

    for (i = 0; i < nr_socks; ++i) {
      if (fds[i].revents & POLLIN)
        accept_connection (fds[i].fd);
    }
  }
}
