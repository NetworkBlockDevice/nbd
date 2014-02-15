/* nbdkit
 * Copyright (C) 2013-2014 Red Hat Inc.
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
  char *data;

  if (test_start_nbdkit (NBDKIT_PLUGIN (LANG), "script=" SCRIPT, NULL) == -1)
    exit (EXIT_FAILURE);

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

  /* The test script creates an empty disk.  We format it, write some
   * data, and check we can read it back.
   */

  if (guestfs_part_disk (g, "/dev/sda", "mbr") == -1)
    exit (EXIT_FAILURE);
  if (guestfs_mkfs (g, "ext4", "/dev/sda1") == -1)
    exit (EXIT_FAILURE);

  if (guestfs_mount (g, "/dev/sda1", "/") == -1)
    exit (EXIT_FAILURE);

#define filename "/hello.txt"
#define content "hello, people of the world"

  if (guestfs_write (g, filename, content, strlen (content)) == -1)
    exit (EXIT_FAILURE);

  data = guestfs_cat (g, filename);
  if (!data)
    exit (EXIT_FAILURE);

  if (strcmp (data, content) != 0) {
    fprintf (stderr, "%s FAILED: unexpected content of %s file (actual: %s, expected: %s)\n",
             program_name, filename, data, content);
    exit (EXIT_FAILURE);
  }

  /* Run sync to test flush path. */
  if (guestfs_sync (g) == -1)
    exit (EXIT_FAILURE);

  /* Run fstrim to test trim path.  However only recent versions of
   * libguestfs have this, and it probably only works in recent
   * versions of qemu.
   */
#ifdef GUESTFS_HAVE_FSTRIM
  if (guestfs_fstrim (g, "/", -1) == -1)
    exit (EXIT_FAILURE);
#endif

  if (guestfs_shutdown (g) == -1)
    exit (EXIT_FAILURE);

  guestfs_close (g);
  exit (EXIT_SUCCESS);
}
