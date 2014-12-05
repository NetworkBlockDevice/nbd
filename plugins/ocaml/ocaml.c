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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/printexc.h>
#include <caml/threads.h>

#include <nbdkit-plugin.h>

/* This constructor runs when the plugin loads, and initializes the
 * OCaml runtime, and lets the plugin set up its callbacks.
 */
static void constructor (void) __attribute__((constructor));
static void
constructor (void)
{
  char *argv[2] = { "nbdkit", NULL };

  /* Initialize OCaml runtime. */
  caml_startup (argv);
}

/* Instead of using the NBDKIT_REGISTER_PLUGIN macro, we construct the
 * nbdkit_plugin struct and return it.
 */
static void unload_wrapper (void);

static struct nbdkit_plugin plugin = {
  ._struct_size = sizeof (plugin),
  ._api_version = NBDKIT_API_VERSION,

  /* The following field is used as a canary to detect whether the
   * OCaml code started up and called us back successfully.  If it's
   * still set to NULL when plugin_init is called, then we can print a
   * suitable error message.
   */
  .name = NULL,

  .unload = unload_wrapper,
};

/* These globals store the OCaml functions that we actually call.
 * Also the assigned ones are roots to ensure the GC doesn't free them.
 */
static value load_fn;
static value unload_fn;
static value config_fn;
static value config_complete_fn;
static value open_fn;
static value close_fn;
static value get_size_fn;
static value can_write_fn;
static value can_flush_fn;
static value is_rotational_fn;
static value can_trim_fn;
static value pread_fn;
static value pwrite_fn;
static value flush_fn;
static value trim_fn;

/* Wrapper functions that translate calls from C (ie. nbdkit) to OCaml. */

static void
load_wrapper (void)
{
  caml_leave_blocking_section ();
  caml_callback (load_fn, Val_unit);
  caml_enter_blocking_section ();
}

/* We always have an unload function, since it also has to free the
 * globals we allocated.
 */
static void
unload_wrapper (void)
{
  if (unload_fn) {
    caml_leave_blocking_section ();
    caml_callback (unload_fn, Val_unit);
    caml_enter_blocking_section ();
  }

  free ((char *) plugin.name);
  free ((char *) plugin.longname);
  free ((char *) plugin.version);
  free ((char *) plugin.description);

  if (load_fn)
    caml_remove_generational_global_root (&load_fn);
  if (unload_fn)
    caml_remove_generational_global_root (&unload_fn);
  if (config_fn)
    caml_remove_generational_global_root (&config_fn);
  if (config_complete_fn)
    caml_remove_generational_global_root (&config_complete_fn);

  free ((char *) plugin.config_help);

  if (open_fn)
    caml_remove_generational_global_root (&open_fn);
  if (close_fn)
    caml_remove_generational_global_root (&close_fn);
  if (get_size_fn)
    caml_remove_generational_global_root (&get_size_fn);
  if (can_write_fn)
    caml_remove_generational_global_root (&can_write_fn);
  if (can_flush_fn)
    caml_remove_generational_global_root (&can_flush_fn);
  if (is_rotational_fn)
    caml_remove_generational_global_root (&is_rotational_fn);
  if (can_trim_fn)
    caml_remove_generational_global_root (&can_trim_fn);
  if (pread_fn)
    caml_remove_generational_global_root (&pread_fn);
  if (pwrite_fn)
    caml_remove_generational_global_root (&pwrite_fn);
  if (flush_fn)
    caml_remove_generational_global_root (&flush_fn);
  if (trim_fn)
    caml_remove_generational_global_root (&trim_fn);
}

static int
config_wrapper (const char *key, const char *val)
{
  CAMLparam0 ();
  CAMLlocal3 (keyv, valv, rv);

  caml_leave_blocking_section ();

  keyv = caml_copy_string (key);
  valv = caml_copy_string (val);

  rv = caml_callback2_exn (config_fn, keyv, valv);
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    caml_enter_blocking_section ();
    CAMLreturnT (int, -1);
  }

  caml_enter_blocking_section ();
  CAMLreturnT (int, 0);
}

static int
config_complete_wrapper (void)
{
  CAMLparam0 ();
  CAMLlocal1 (rv);

  caml_leave_blocking_section ();

  rv = caml_callback_exn (config_complete_fn, Val_unit);
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    caml_enter_blocking_section ();
    CAMLreturnT (int, -1);
  }

  caml_enter_blocking_section ();
  CAMLreturnT (int, 0);
}

static void *
open_wrapper (int readonly)
{
  CAMLparam0 ();
  CAMLlocal1 (rv);
  value *ret;

  caml_leave_blocking_section ();

  rv = caml_callback_exn (open_fn, Val_bool (readonly));
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    caml_enter_blocking_section ();
    CAMLreturnT (void *, NULL);
  }

  /* Allocate a root on the C heap that points to the OCaml handle. */
  ret = malloc (sizeof *ret);
  if (ret == NULL) abort ();
  *ret = rv;
  caml_register_generational_global_root (ret);

  caml_enter_blocking_section ();
  CAMLreturnT (void *, ret);
}

static void
close_wrapper (void *h)
{
  CAMLparam0 ();
  CAMLlocal1 (rv);

  caml_leave_blocking_section ();

  rv = caml_callback_exn (close_fn, *(value *) h);
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    /*FALLTHROUGH*/
  }

  caml_remove_generational_global_root (h);
  free (h);

  caml_enter_blocking_section ();
  CAMLreturn0;
}

static int64_t
get_size_wrapper (void *h)
{
  CAMLparam0 ();
  CAMLlocal1 (rv);
  int64_t r;

  caml_leave_blocking_section ();

  rv = caml_callback_exn (get_size_fn, *(value *) h);
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    caml_enter_blocking_section ();
    CAMLreturnT (int64_t, -1);
  }

  r = Int64_val (rv);

  caml_enter_blocking_section ();
  CAMLreturnT (int64_t, r);
}

static int
can_write_wrapper (void *h)
{
  CAMLparam0 ();
  CAMLlocal1 (rv);

  caml_leave_blocking_section ();

  rv = caml_callback_exn (can_write_fn, *(value *) h);
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    caml_enter_blocking_section ();
    CAMLreturnT (int, -1);
  }

  caml_enter_blocking_section ();
  CAMLreturnT (int, Bool_val (rv));
}

static int
can_flush_wrapper (void *h)
{
  CAMLparam0 ();
  CAMLlocal1 (rv);

  caml_leave_blocking_section ();

  rv = caml_callback_exn (can_flush_fn, *(value *) h);
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    caml_enter_blocking_section ();
    CAMLreturnT (int, -1);
  }

  caml_enter_blocking_section ();
  CAMLreturnT (int, Bool_val (rv));
}

static int
is_rotational_wrapper (void *h)
{
  CAMLparam0 ();
  CAMLlocal1 (rv);

  caml_leave_blocking_section ();

  rv = caml_callback_exn (is_rotational_fn, *(value *) h);
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    caml_enter_blocking_section ();
    CAMLreturnT (int, -1);
  }

  caml_enter_blocking_section ();
  CAMLreturnT (int, Bool_val (rv));
}

static int
can_trim_wrapper (void *h)
{
  CAMLparam0 ();
  CAMLlocal1 (rv);

  caml_leave_blocking_section ();

  rv = caml_callback_exn (can_trim_fn, *(value *) h);
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    caml_enter_blocking_section ();
    CAMLreturnT (int, -1);
  }

  caml_enter_blocking_section ();
  CAMLreturnT (int, Bool_val (rv));
}

static int
pread_wrapper (void *h, void *buf, uint32_t count, uint64_t offset)
{
  CAMLparam0 ();
  CAMLlocal3 (rv, strv, offsetv);

  caml_leave_blocking_section ();

  strv = caml_alloc_string (count);
  offsetv = caml_copy_int64 (offset);

  rv = caml_callback3_exn (pread_fn, *(value *) h, strv, offsetv);
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    caml_enter_blocking_section ();
    CAMLreturnT (int, -1);
  }

  memcpy (buf, String_val (strv), count);

  caml_enter_blocking_section ();
  CAMLreturnT (int, 0);
}

static int
pwrite_wrapper (void *h, const void *buf, uint32_t count, uint64_t offset)
{
  CAMLparam0 ();
  CAMLlocal3 (rv, strv, offsetv);

  caml_leave_blocking_section ();

  strv = caml_alloc_string (count);
  memcpy (String_val (strv), buf, count);
  offsetv = caml_copy_int64 (offset);

  rv = caml_callback3_exn (pwrite_fn, *(value *) h, strv, offsetv);
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    caml_enter_blocking_section ();
    CAMLreturnT (int, -1);
  }

  caml_enter_blocking_section ();
  CAMLreturnT (int, 0);
}

static int
flush_wrapper (void *h)
{
  CAMLparam0 ();
  CAMLlocal1 (rv);

  caml_leave_blocking_section ();

  rv = caml_callback_exn (flush_fn, *(value *) h);
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    CAMLreturnT (int, -1);
  }

  caml_enter_blocking_section ();
  CAMLreturnT (int, 0);
}

static int
trim_wrapper (void *h, uint32_t count, uint64_t offset)
{
  CAMLparam0 ();
  CAMLlocal3 (rv, countv, offsetv);

  caml_leave_blocking_section ();

  countv = caml_copy_int32 (count);
  offsetv = caml_copy_int32 (offset);

  rv = caml_callback3_exn (flush_fn, *(value *) h, countv, offsetv);
  if (Is_exception_result (rv)) {
    nbdkit_error ("%s", caml_format_exception (Extract_exception (rv)));
    CAMLreturnT (int, -1);
  }

  caml_enter_blocking_section ();
  CAMLreturnT (int, 0);
}

value
ocaml_nbdkit_set_thread_model (value modelv)
{
  plugin._thread_model = Int_val (modelv);
  return Val_unit;
}

value
ocaml_nbdkit_set_name (value namev)
{
  plugin.name = strdup (String_val (namev));
  return Val_unit;
}

value
ocaml_nbdkit_set_longname (value longnamev)
{
  plugin.longname = strdup (String_val (longnamev));
  return Val_unit;
}

value
ocaml_nbdkit_set_version (value versionv)
{
  plugin.version = strdup (String_val (versionv));
  return Val_unit;
}

value
ocaml_nbdkit_set_description (value descriptionv)
{
  plugin.description = strdup (String_val (descriptionv));
  return Val_unit;
}

value
ocaml_nbdkit_set_config_help (value helpv)
{
  plugin.config_help = strdup (String_val (helpv));
  return Val_unit;
}

#define SET(fn)                                         \
  value                                                 \
  ocaml_nbdkit_set_##fn (value fv)                      \
  {                                                     \
    plugin.fn = fn##_wrapper;                           \
    fn##_fn = fv;                                       \
    caml_register_generational_global_root (&fn##_fn);  \
    return Val_unit;                                    \
  }

SET(load)
SET(unload)
SET(config)
SET(config_complete)
SET(open)
SET(close)
SET(get_size)
SET(can_write)
SET(can_flush)
SET(is_rotational)
SET(can_trim)
SET(pread)
SET(pwrite)
SET(flush)
SET(trim)

struct nbdkit_plugin *
plugin_init (void)
{
  if (plugin.name == NULL) {
    fprintf (stderr, "error: OCaml code did not call NBDKit.register_plugin\n");
    exit (EXIT_FAILURE);
  }
  return &plugin;
}
