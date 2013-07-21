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
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <pthread.h>

#include "nbdkit-plugin.h"
#include "internal.h"

/* Note currently all thread-local storage data is informational.
 * It's mainly used for smart error and debug messages.
 *
 * The main thread does not have any associated TLS, *unless* it is
 * serving a request (the '-s' option).
 */

struct tls {
  const char *name;             /* Can be NULL. */
  size_t instance_num;          /* Can be 0. */
  struct sockaddr *addr;
  socklen_t addrlen;
};

static pthread_key_t tls_key;

static void
free_tls (void *tlsv)
{
  struct tls *tls = tlsv;

  free (tls->addr);
  free (tls);
}

void
tls_init (void)
{
  int err;

  err = pthread_key_create (&tls_key, free_tls);
  if (err != 0) {
    fprintf (stderr, "%s: pthread_key_create: %s\n",
             program_name, strerror (err));
    exit (EXIT_FAILURE);
  }
}

void
tls_new_server_thread (void)
{
  struct tls *tls;

  tls = calloc (1, sizeof *tls);
  if (tls == NULL) {
    perror ("malloc");
    exit (EXIT_FAILURE);
  }
  pthread_setspecific (tls_key, tls);
}

void
tls_set_name (const char *name)
{
  struct tls *tls = pthread_getspecific (tls_key);

  if (tls)
    tls->name = name;
}

void
tls_set_instance_num (size_t instance_num)
{
  struct tls *tls = pthread_getspecific (tls_key);

  if (tls)
    tls->instance_num = instance_num;
}

void
tls_set_sockaddr (struct sockaddr *addr, socklen_t addrlen)
{
  struct tls *tls = pthread_getspecific (tls_key);

  if (tls) {
    free(tls->addr);
    tls->addr = calloc (1, addrlen);
    if (tls->addr == NULL) {
      perror ("calloc");
      exit (EXIT_FAILURE);
    }
    memcpy(tls->addr, addr, addrlen);
  }
}

const char *
tls_get_name (void)
{
  struct tls *tls = pthread_getspecific (tls_key);

  if (!tls)
    return NULL;

  return tls->name;
}

size_t
tls_get_instance_num (void)
{
  struct tls *tls = pthread_getspecific (tls_key);

  if (!tls)
    return 0;

  return tls->instance_num;
}
