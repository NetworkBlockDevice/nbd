/* nbdkit
 * Copyright (C) 2014 Red Hat Inc.
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

/* NB: The terminology used by libcurl is confusing!
 *
 * WRITEFUNCTION / write_cb is used when reading from the remote server
 * READFUNCTION / read_cb is used when writing to the remote server.
 *
 * We use the same terminology as libcurl here.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <curl/curl.h>

#include <nbdkit-plugin.h>

static const char *url = NULL;
static const char *user = NULL;
static char *password = NULL;
static int sslverify = 1;
static int timeout = 0;

static void
curl_load (void)
{
  curl_global_init (CURL_GLOBAL_DEFAULT);
}

static void
curl_unload (void)
{
  free (password);
  curl_global_cleanup ();
}

/* Called for each key=value passed on the command line. */
static int
curl_config (const char *key, const char *value)
{
  if (strcmp (key, "url") == 0)
    url = value;

  else if (strcmp (key, "user") == 0)
    user = value;

  else if (strcmp (key, "password") == 0) {
    free (password);
    password = NULL;

    if (strcmp (value, "-") == 0) {
      ssize_t r;

      printf ("password: ");
      r = getline (&password, NULL, stdin);
      if (r == -1) {
        nbdkit_error ("could not read password from stdin: %m");
        return -1;
      }
      if (password && r > 0 && password[r-1] == '\n')
        password[r-1] = '\0';
    }
    else
      password = strdup (value);
  }

  else if (strcmp (key, "sslverify") == 0) {
    if (sscanf (value, "%d", &sslverify) != 1) {
      nbdkit_error ("'sslverify' must be 0 or 1");
      return -1;
    }
  }

  else if (strcmp (key, "timeout") == 0) {
    if (sscanf (value, "%d", &timeout) != 1 || timeout < 0) {
      nbdkit_error ("'timeout' must be 0 or a positive timeout in seconds");
      return -1;
    }
  }

  else {
    nbdkit_error ("unknown parameter '%s'", key);
    return -1;
  }

  return 0;
}

/* Check the user did pass a url parameter. */
static int
curl_config_complete (void)
{
  if (url == NULL) {
    nbdkit_error ("you must supply the url=<URL> parameter after the plugin name on the command line");
    return -1;
  }

  return 0;
}

#define curl_config_help \
  "timeout=<TIMEOUT>          Set the timeout for requests (seconds).\n" \
  "password=<PASSWORD>        The password for the user account.\n" \
  "sslverify=0                Do not verify SSL certificate of remote host.\n" \
  "url=<URL>       (required) The disk image URL to serve.\n" \
  "user=<USER>                The user to log in as."

/* The per-connection handle. */
struct curl_handle {
  CURL *c;
  int accept_range;
  int64_t exportsize;
  char errbuf[CURL_ERROR_SIZE];
  char *write_buf;
  uint32_t write_count;
  const char *read_buf;
  uint32_t read_count;
};

/* Translate CURLcode to nbdkit_error. */
#define display_curl_error(h, r, fs, ...)                       \
  do {                                                          \
    nbdkit_error ((fs ": %s: %s"), ## __VA_ARGS__,              \
                  curl_easy_strerror ((r)), (h)->errbuf);       \
  } while (0)

static size_t header_cb (void *ptr, size_t size, size_t nmemb, void *opaque);
static size_t write_cb (char *ptr, size_t size, size_t nmemb, void *opaque);
static size_t read_cb (void *ptr, size_t size, size_t nmemb, void *opaque);

/* Create the per-connection handle. */
static void *
curl_open (int readonly)
{
  struct curl_handle *h;
  CURLcode r;
  double d;

  h = calloc (1, sizeof *h);
  if (h == NULL) {
    nbdkit_error ("calloc: %m");
    return NULL;
  }

  h->c = curl_easy_init ();
  if (h->c == NULL) {
    nbdkit_error ("curl_easy_init: failed: %m");
    goto err;
  }

  nbdkit_debug ("opened libcurl easy handle");

  curl_easy_setopt (h->c, CURLOPT_ERRORBUFFER, h->errbuf);

  r = curl_easy_setopt (h->c, CURLOPT_URL, url);
  if (r != CURLE_OK) {
    display_curl_error (h, r, "curl_easy_setopt: CURLOPT_URL [%s]", url);
    goto err;
  }

  nbdkit_debug ("set libcurl URL: %s", url);

  /* Other possible settings, which could be specified on the command line:
CURLOPT_PROXY
  */
  curl_easy_setopt (h->c, CURLOPT_AUTOREFERER, 1);
  curl_easy_setopt (h->c, CURLOPT_FOLLOWLOCATION, 1);
  curl_easy_setopt (h->c, CURLOPT_FAILONERROR, 1);
  if (timeout > 0)
    curl_easy_setopt (h->c, CURLOPT_TIMEOUT, timeout);
  if (sslverify == 0)
    curl_easy_setopt (h->c, CURLOPT_SSL_VERIFYPEER, sslverify);
  if (user)
    curl_easy_setopt (h->c, CURLOPT_USERNAME, user);
  if (password)
    curl_easy_setopt (h->c, CURLOPT_USERPWD, password);

  /* Get the file size and also whether the remote HTTP server
   * supports byte ranges.
   */
  h->accept_range = 0;
  curl_easy_setopt (h->c, CURLOPT_NOBODY, 1); /* No Body, not nobody! */
  curl_easy_setopt (h->c, CURLOPT_HEADERFUNCTION, header_cb);
  curl_easy_setopt (h->c, CURLOPT_HEADERDATA, h);
  r = curl_easy_perform (h->c);
  if (r != CURLE_OK) {
    display_curl_error (h, r, "problem doing HEAD request to fetch size of URL [%s]", url);
    goto err;
  }

  r = curl_easy_getinfo (h->c, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &d);
  if (r != CURLE_OK) {
    display_curl_error (h, r, "could not get length of remote file [%s]", url);
    goto err;
  }

  if (d == -1) {
    nbdkit_error ("could not get length of remote file [%s], is the URL correct?", url);
    goto err;
  }

  h->exportsize = (size_t) d;
  nbdkit_debug ("content length: %" PRIi64, h->exportsize);

  if (strncasecmp (url, "http://", strlen ("http://")) == 0 ||
      strncasecmp (url, "https://", strlen ("https://")) == 0) {
    if (!h->accept_range) {
      nbdkit_error ("server does not support 'range' (byte range) requests");
      goto err;
    }

    nbdkit_debug ("accept range supported (for HTTP/HTTPS)");
  }

  /* Get set up for reading and writing. */
  curl_easy_setopt (h->c, CURLOPT_HEADERFUNCTION, NULL);
  curl_easy_setopt (h->c, CURLOPT_HEADERDATA, NULL);
  curl_easy_setopt (h->c, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt (h->c, CURLOPT_WRITEDATA, h);
  if (!readonly) {
    curl_easy_setopt (h->c, CURLOPT_READFUNCTION, read_cb);
    curl_easy_setopt (h->c, CURLOPT_READDATA, h);
  }

  nbdkit_debug ("returning new handle %p", h);

  return h;

 err:
  if (h->c)
    curl_easy_cleanup (h->c);
  free (h);
  return NULL;
}

static size_t
header_cb (void *ptr, size_t size, size_t nmemb, void *opaque)
{
  struct curl_handle *h = opaque;
  size_t realsize = size * nmemb;
  size_t len;
  const char *accept_line = "Accept-Ranges: bytes";
  const char *line = ptr;

  if (realsize >= strlen (accept_line) &&
      strncmp (line, accept_line, strlen (accept_line)) == 0)
    h->accept_range = 1;

  /* Useful to print the server headers when debugging.  However we
   * must strip off trailing \r?\n from each line.
   */
  len = realsize;
  if (len > 0 && line[len-1] == '\n')
    len--;
  if (len > 0 && line[len-1] == '\r')
    len--;
  if (len > 0)
    nbdkit_debug ("S: %.*s", (int) len, line);

  return realsize;
}

/* Free up the per-connection handle. */
static void
curl_close (void *handle)
{
  struct curl_handle *h = handle;

  curl_easy_cleanup (h->c);
  free (h);
}

#define THREAD_MODEL NBDKIT_THREAD_MODEL_SERIALIZE_REQUESTS

/* Get the file size. */
static int64_t
curl_get_size (void *handle)
{
  struct curl_handle *h = handle;

  return h->exportsize;
}

/* Read data from the remote server. */
static int
curl_pread (void *handle, void *buf, uint32_t count, uint64_t offset)
{
  struct curl_handle *h = handle;
  CURLcode r;
  char range[128];

  /* Tell the write_cb where we want the data to be written.  write_cb
   * will update this if the data comes in multiple sections.
   */
  h->write_buf = buf;
  h->write_count = count;

  curl_easy_setopt (h->c, CURLOPT_HTTPGET, 1);

  /* Make an HTTP range request. */
  snprintf (range, sizeof range, "%" PRIu64 "-%" PRIu64,
            offset, offset + count);
  curl_easy_setopt (h->c, CURLOPT_RANGE, range);

  /* The assumption here is that curl will look after timeouts. */
  r = curl_easy_perform (h->c);
  if (r != CURLE_OK) {
    display_curl_error (h, r, "pread: curl_easy_perform");
    return -1;
  }

  /* Could use curl_easy_getinfo here to obtain further information
   * about the connection.
   */

  /* As far as I understand the cURL API, this should never happen. */
  assert (h->write_count == 0);

  return 0;
}

static size_t
write_cb (char *ptr, size_t size, size_t nmemb, void *opaque)
{
  struct curl_handle *h = opaque;
  size_t orig_realsize = size * nmemb;
  size_t realsize = orig_realsize;

  assert (h->write_buf);

  /* Don't read more than the requested amount of data, even if the
   * server or libcurl sends more.
   */
  if (realsize > h->write_count)
    realsize = h->write_count;

  memcpy (h->write_buf, ptr, realsize);

  h->write_count -= realsize;
  h->write_buf += realsize;

  return orig_realsize;
}

/* Write data to the remote server. */
static int
curl_pwrite (void *handle, const void *buf, uint32_t count, uint64_t offset)
{
  struct curl_handle *h = handle;
  CURLcode r;
  char range[128];

  /* Tell the read_cb where we want the data to be read from.  read_cb
   * will update this if the data comes in multiple sections.
   */
  h->read_buf = buf;
  h->read_count = count;

  curl_easy_setopt (h->c, CURLOPT_UPLOAD, 1);

  /* Make an HTTP range request. */
  snprintf (range, sizeof range, "%" PRIu64 "-%" PRIu64,
            offset, offset + count);
  curl_easy_setopt (h->c, CURLOPT_RANGE, range);

  /* The assumption here is that curl will look after timeouts. */
  r = curl_easy_perform (h->c);
  if (r != CURLE_OK) {
    display_curl_error (h, r, "pwrite: curl_easy_perform");
    return -1;
  }

  /* Could use curl_easy_getinfo here to obtain further information
   * about the connection.
   */

  /* As far as I understand the cURL API, this should never happen. */
  assert (h->read_count == 0);

  return 0;
}

static size_t
read_cb (void *ptr, size_t size, size_t nmemb, void *opaque)
{
  struct curl_handle *h = opaque;
  size_t realsize = size * nmemb;

  assert (h->read_buf);
  if (realsize > h->read_count)
    realsize = h->read_count;

  memcpy (ptr, h->read_buf, realsize);

  h->read_count -= realsize;
  h->read_buf += realsize;

  return realsize;
}

static struct nbdkit_plugin plugin = {
  .name              = "curl",
  .version           = PACKAGE_VERSION,
  .load              = curl_load,
  .unload            = curl_unload,
  .config            = curl_config,
  .config_complete   = curl_config_complete,
  .config_help       = curl_config_help,
  .open              = curl_open,
  .close             = curl_close,
  .get_size          = curl_get_size,
  .pread             = curl_pread,
  .pwrite            = curl_pwrite,
};

NBDKIT_REGISTER_PLUGIN(plugin)
