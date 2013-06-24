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
#include <stdint.h>
#include <inttypes.h>

#include <nbdkit-plugin.h>

#include "blkcache.h"

/* Implemented as a very simple LRU list with a fixed depth. */
struct blkcache {
  size_t maxdepth;
  struct block *blocks;
  blkcache_stats stats;
};

struct block {
  uint64_t start;
  uint64_t size;
  char *data;
};

blkcache *
new_blkcache (size_t maxdepth)
{
  blkcache *c;

  c = malloc (sizeof *c);
  if (!c) {
    nbdkit_error ("malloc: %m");
    return NULL;
  }

  c->blocks = calloc (maxdepth, sizeof (struct block));
  if (!c->blocks) {
    nbdkit_error ("calloc: %m");
    free (c);
    return NULL;
  }
  c->maxdepth = maxdepth;
  c->stats.hits = c->stats.misses = 0;

  return c;
}

void
free_blkcache (blkcache *c)
{
  size_t i;

  for (i = 0; i < c->maxdepth; ++i)
    free (c->blocks[i].data);
  free (c->blocks);
  free (c);
}

char *
get_block (blkcache *c, uint64_t offset, uint64_t *start, uint64_t *size)
{
  size_t i;
  struct block tmp;

  for (i = 0; i < c->maxdepth; ++i) {
    if (c->blocks[i].data != NULL &&
        c->blocks[i].start <= offset &&
        offset < c->blocks[i].start + c->blocks[i].size) {
      /* This block is now most recently used, so put it at the start. */
      if (i > 0) {
        tmp = c->blocks[0];
        c->blocks[0] = c->blocks[i];
        c->blocks[i] = tmp;
      }

      c->stats.hits++;
      *start = c->blocks[0].start;
      *size = c->blocks[0].size;
      return c->blocks[0].data;
    }
  }

  c->stats.misses++;
  return NULL;
}

int
put_block (blkcache *c, uint64_t start, uint64_t size, char *data)
{
  size_t i;

  /* Eject the least recently used block. */
  i = c->maxdepth-1;
  if (c->blocks[i].data != NULL)
    free (c->blocks[i].data);

  for (; i >= 1; --i)
    c->blocks[i] = c->blocks[i-1];

  /* The new block is most recently used, so it goes at the start. */
  c->blocks[0].start = start;
  c->blocks[0].size = size;
  c->blocks[0].data = data;

  return 0;
}

void
blkcache_get_stats (blkcache *c, blkcache_stats *ret)
{
  memcpy (ret, &c->stats, sizeof (c->stats));
}
