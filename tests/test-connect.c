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
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <guestfs.h>

#include "test.h"

int
main (int argc, char *argv[])
{
  guestfs_h *g;
  int r;
  int64_t size;
  char **parts;
  size_t i;

  if (test_start_nbdkit (NBDKIT_PLUGIN ("example1"), NULL) == -1)
    exit (EXIT_FAILURE);

  /* Parent (test program). */
  g = guestfs_create ();
  if (g == NULL) {
    perror ("guestfs_create");
    exit (EXIT_FAILURE);
  }

  r = guestfs_add_drive_opts (g, "",
                              GUESTFS_ADD_DRIVE_OPTS_FORMAT, "raw",
                              GUESTFS_ADD_DRIVE_OPTS_PROTOCOL, "nbd",
                              GUESTFS_ADD_DRIVE_OPTS_SERVER, server,
                              -1);
  if (r == -1)
    exit (EXIT_FAILURE);

  if (guestfs_launch (g) == -1)
    exit (EXIT_FAILURE);

  /* The example1 plugin makes a static virtual disk which is 100 MB
   * in size and has one empty partition.  Check this.
   */
  size = guestfs_blockdev_getsize64 (g, "/dev/sda");
  if (size == -1)
    exit (EXIT_FAILURE);
  if (size != 104857600) {
    fprintf (stderr,
             "%s FAILED: incorrect disk size (actual: %" PRIi64
             ", expected: 104857600)\n", program_name, size);
    exit (EXIT_FAILURE);
  }

  parts = guestfs_list_partitions (g);
  if (!parts)
    exit (EXIT_FAILURE);
  if (parts[0] == NULL || parts[1] != NULL ||
      strcmp (parts[0], "/dev/sda1") != 0) {
    fprintf (stderr,
             "%s FAILED: incorrect result from guestfs_list_partitions\n",
             program_name);
    exit (EXIT_FAILURE);
  }

  for (i = 0; parts[i] != NULL; ++i)
    free (parts[i]);
  free (parts);

  guestfs_close (g);
  exit (EXIT_SUCCESS);
}
