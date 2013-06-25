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
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#include "test.h"

static char tmpdir[] = "/tmp/nbdkitXXXXXX";
static char sockpath[] = "/tmp/nbdkitXXXXXX/sock";
static char unixsockpath[] = "unix:/tmp/nbdkitXXXXXX/sock";
static char pidpath[] = "/tmp/nbdkitXXXXXX/pid";

pid_t pid = 0;
const char *server[2] = { unixsockpath, NULL };

static void
cleanup (void)
{
  if (pid > 0)
    kill (pid, SIGTERM);

  unlink (pidpath);
  unlink (sockpath);
  rmdir (tmpdir);
}

int
test_start_nbdkit (const char *plugin, ...)
{
  size_t i, len;

  if (mkdtemp (tmpdir) == NULL) {
    perror ("mkdtemp");
    return -1;
  }
  len = strlen (tmpdir);
  memcpy (sockpath, tmpdir, len);
  memcpy (unixsockpath+5, tmpdir, len);
  memcpy (pidpath, tmpdir, len);

  pid = fork ();
  if (pid == 0) {               /* Child (nbdkit). */
    const char *p;
    const int MAX_ARGS = 64;
    const char *argv[MAX_ARGS+1];
    va_list args;

    argv[0] = "nbdkit";
    argv[1] = "-U";
    argv[2] = sockpath;
    argv[3] = "-P";
    argv[4] = pidpath;
    argv[5] = "-f";
    argv[6] = plugin;
    i = 7;

    va_start (args, plugin);
    while ((p = va_arg (args, const char *)) != NULL) {
      if (i >= MAX_ARGS)
        abort ();
      argv[i] = p;
      ++i;
    }
    va_end (args);
    argv[i] = NULL;

    execvp ("../src/nbdkit", (char **) argv);
    perror ("exec: nbdkit");
    _exit (EXIT_FAILURE);
  }

  /* Ensure nbdkit is killed and temporary files are deleted when the
   * main program exits.
   */
  atexit (cleanup);

  /* Wait for the pidfile to turn up, which indicates that nbdkit has
   * started up successfully and is ready to serve requests.  However
   * if 'pid' exits in this time it indicates a failure to start up.
   * Also there is a timeout in case nbdkit hangs.
   */
  for (i = 0; i < NBDKIT_START_TIMEOUT; ++i) {
    if (waitpid (pid, NULL, WNOHANG) == pid)
      goto early_exit;

    if (kill (pid, 0) == -1) {
      if (errno == ESRCH) {
      early_exit:
        fprintf (stderr,
                 "%s FAILED: nbdkit exited before starting to serve files\n",
                 program_name);
        pid = 0;
        return -1;
      }
      perror ("kill");
    }

    if (access (pidpath, F_OK) == 0)
      break;

    sleep (1);
  }

  return 0;
}
