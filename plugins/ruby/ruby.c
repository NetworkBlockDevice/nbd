/* nbdkit
 * Copyright (C) 2013-2016 Red Hat Inc.
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
#include <assert.h>

#include <nbdkit-plugin.h>

#include <ruby.h>

static void
plugin_rb_load (void)
{
  ruby_init ();
  //ruby_init_loadpath (); - needed? XXX
}

/* Wrapper to make fb_funcall2 (only slightly) less insane.
 * https://gist.github.com/ammar/2787174
 */

static VALUE
funcall2_wrapper (VALUE argvv)
{
  VALUE *argv = (VALUE *) argvv;
  volatile VALUE obj, method;
  VALUE *args;
  int argc;

  obj = argv[0];
  method = argv[1];
  argc = argv[2];
  args = (VALUE *) argv[3];

  return rb_funcall2 (obj, method, argc, args);
}

/* This should not be a global. XXX */
enum plugin_rb_exception {
  NO_EXCEPTION = 0,
  EXCEPTION_NO_METHOD_ERROR,    /* NoMethodError */
  EXCEPTION_OTHER,              /* none of the above */
};
static enum plugin_rb_exception exception_happened;

static VALUE
exception_handler (VALUE argvv, VALUE exn)
{
  volatile VALUE message;

  if (rb_obj_is_kind_of (exn, rb_eNoMethodError))
    exception_happened = EXCEPTION_NO_METHOD_ERROR;
  else {
    /* Some other exception, so print it. */
    exception_happened = EXCEPTION_OTHER;

    message = rb_funcall (exn, rb_intern ("to_s"), 0);
    nbdkit_error ("ruby: %s", StringValueCStr (message));
  }

  return Qnil;
}

static VALUE
funcall2 (VALUE receiver, ID method_id, int argc, volatile VALUE *argv)
{
  int i;
  VALUE args[4];
  VALUE result;

  args[0] = receiver;
  args[1] = method_id;
  args[2] = argc;
  args[3] = (VALUE) argv;

  for (i = 0; i <= 3; ++i)
    rb_gc_register_address (&args[i]);

  result = rb_rescue2 (RUBY_METHOD_FUNC (funcall2_wrapper), (VALUE) args,
                       RUBY_METHOD_FUNC (exception_handler), (VALUE) args,
                       rb_eException, (VALUE) 0);

  for (i = 3; i >= 0; --i)
    rb_gc_unregister_address (&args[i]);

  return result;
}

static const char *script = NULL;
static void *code = NULL;

static int
plugin_rb_config (const char *key, const char *value)
{
  /* The first parameter must be "script". */
  if (!script) {
    int state;

    if (strcmp (key, "script") != 0) {
      nbdkit_error ("the first parameter must be script=/path/to/ruby/script.rb");
      return -1;
    }
    script = value;

    /* Load the Ruby script into the interpreter. */
    const char *options[] = { "--", script };
    code = ruby_options (2, (char **) options);

    /* Check if we managed to compile the Ruby script to code. */
    if (!ruby_executable_node (code, &state)) {
      nbdkit_error ("could not compile ruby script (%s, state=%d)",
                    script, state);
      return -1;
    }

    /* Execute the Ruby script. */
    state = ruby_exec_node (code);
    if (state) {
      nbdkit_error ("could not execute ruby script (%s, state=%d)",
                    script, state);
      return -1;
    }

    return 0;
  }
  else {
    volatile VALUE argv[2];

    argv[0] = rb_str_new2 (key);
    argv[1] = rb_str_new2 (value);
    exception_happened = 0;
    (void) funcall2 (Qnil, rb_intern ("config"), 2, argv);
    if (exception_happened == EXCEPTION_NO_METHOD_ERROR) {
      /* No config method, emulate what core nbdkit does if the
       * config callback is NULL.
       */
      nbdkit_error ("%s: this plugin does not need command line configuration",
                    script);
      return -1;
    }
    else if (exception_happened == EXCEPTION_OTHER)
      return -1;

    return 0;
  }
}

static int
plugin_rb_config_complete (void)
{
  if (!script) {
    nbdkit_error ("the first parameter must be script=/path/to/ruby/script.rb");
    return -1;
  }

  assert (code != NULL);

  exception_happened = 0;
  (void) funcall2 (Qnil, rb_intern ("config_complete"), 0, NULL);
  if (exception_happened == EXCEPTION_NO_METHOD_ERROR)
    return 0;          /* no config_complete method defined, ignore */
  else if (exception_happened == EXCEPTION_OTHER)
    return -1;

  return 0;
}

static void
plugin_rb_unload (void)
{
  if (ruby_cleanup (0) != 0)
    nbdkit_error ("ruby_cleanup failed");
}

static void *
plugin_rb_open (int readonly)
{
  volatile VALUE argv[1];
  volatile VALUE rv;

  argv[0] = readonly ? Qtrue : Qfalse;
  exception_happened = 0;
  rv = funcall2 (Qnil, rb_intern ("open"), 1, argv);
  if (exception_happened == EXCEPTION_NO_METHOD_ERROR) {
    nbdkit_error ("%s: missing callback: %s", script, "open");
    return NULL;
  }
  else if (exception_happened == EXCEPTION_OTHER)
    return NULL;

  return (void *) rv;
}

static void
plugin_rb_close (void *handle)
{
  volatile VALUE argv[1];

  argv[0] = (VALUE) handle;
  (void) funcall2 (Qnil, rb_intern ("close"), 1, argv);
  /* OK to ignore exceptions here, if they are important then an error
   * was printed already.
   */
}

static int64_t
plugin_rb_get_size (void *handle)
{
  volatile VALUE argv[1];
  volatile VALUE rv;

  argv[0] = (VALUE) handle;
  exception_happened = 0;
  rv = funcall2 (Qnil, rb_intern ("get_size"), 1, argv);
  if (exception_happened == EXCEPTION_NO_METHOD_ERROR) {
    nbdkit_error ("%s: missing callback: %s", script, "get_size");
    return -1;
  }
  else if (exception_happened == EXCEPTION_OTHER)
    return -1;

  return NUM2ULL (rv);
}

static int
plugin_rb_pread (void *handle, void *buf,
                 uint32_t count, uint64_t offset)
{
  volatile VALUE argv[3];
  volatile VALUE rv;

  argv[0] = (VALUE) handle;
  argv[1] = ULL2NUM (count);
  argv[2] = ULL2NUM (offset);
  exception_happened = 0;
  rv = funcall2 (Qnil, rb_intern ("pread"), 3, argv);
  if (exception_happened == EXCEPTION_NO_METHOD_ERROR) {
    nbdkit_error ("%s: missing callback: %s", script, "pread");
    return -1;
  }
  else if (exception_happened == EXCEPTION_OTHER)
    return -1;

  if (RSTRING_LEN (rv) < count) {
    nbdkit_error ("%s: byte array returned from pread is too small",
                  script);
    return -1;
  }

  memcpy (buf, RSTRING_PTR (rv), count);
  return 0;
}

static int
plugin_rb_pwrite (void *handle, const void *buf,
                  uint32_t count, uint64_t offset)
{
  volatile VALUE argv[3];

  argv[0] = (VALUE) handle;
  argv[1] = rb_str_new (buf, count);
  argv[2] = ULL2NUM (offset);
  exception_happened = 0;
  (void) funcall2 (Qnil, rb_intern ("pwrite"), 3, argv);
  if (exception_happened == EXCEPTION_NO_METHOD_ERROR) {
    nbdkit_error ("%s: missing callback: %s", script, "pwrite");
    return -1;
  }
  else if (exception_happened == EXCEPTION_OTHER)
    return -1;

  return 0;
}

static int
plugin_rb_flush (void *handle)
{
  volatile VALUE argv[1];

  argv[0] = (VALUE) handle;
  exception_happened = 0;
  (void) funcall2 (Qnil, rb_intern ("flush"), 1, argv);
  if (exception_happened == EXCEPTION_NO_METHOD_ERROR) {
    nbdkit_error ("%s: not implemented: %s", script, "flush");
    return -1;
  }
  else if (exception_happened == EXCEPTION_OTHER)
    return -1;

  return 0;
}

static int
plugin_rb_trim (void *handle, uint32_t count, uint64_t offset)
{
  volatile VALUE argv[3];

  argv[0] = (VALUE) handle;
  argv[1] = ULL2NUM (count);
  argv[2] = ULL2NUM (offset);
  exception_happened = 0;
  (void) funcall2 (Qnil, rb_intern ("trim"), 3, argv);
  if (exception_happened == EXCEPTION_NO_METHOD_ERROR) {
    nbdkit_error ("%s: not implemented: %s", script, "trim");
    return -1;
  }
  else if (exception_happened == EXCEPTION_OTHER)
    return -1;

  return 0;
}

static int
plugin_rb_can_write (void *handle)
{
  volatile VALUE argv[1];
  volatile VALUE rv;

  argv[0] = (VALUE) handle;
  exception_happened = 0;
  rv = funcall2 (Qnil, rb_intern ("can_write"), 1, argv);
  if (exception_happened == EXCEPTION_NO_METHOD_ERROR)
    /* Fall back to checking if the pwrite method exists. */
    rv = rb_funcall (Qnil, rb_intern ("respond_to?"),
                     2, ID2SYM (rb_intern ("pwrite")), Qtrue);
  else if (exception_happened == EXCEPTION_OTHER)
    return -1;

  return RTEST (rv);
}

static int
plugin_rb_can_flush (void *handle)
{
  volatile VALUE argv[1];
  volatile VALUE rv;

  argv[0] = (VALUE) handle;
  exception_happened = 0;
  rv = funcall2 (Qnil, rb_intern ("can_flush"), 1, argv);
  if (exception_happened == EXCEPTION_NO_METHOD_ERROR)
    /* Fall back to checking if the flush method exists. */
    rv = rb_funcall (Qnil, rb_intern ("respond_to?"),
                     2, ID2SYM (rb_intern ("flush")), Qtrue);
  else if (exception_happened == EXCEPTION_OTHER)
    return -1;

  return RTEST (rv);
}

static int
plugin_rb_is_rotational (void *handle)
{
  volatile VALUE argv[1];
  volatile VALUE rv;

  argv[0] = (VALUE) handle;
  exception_happened = 0;
  rv = funcall2 (Qnil, rb_intern ("is_rotational"), 1, argv);
  if (exception_happened == EXCEPTION_NO_METHOD_ERROR)
    return 0;
  else if (exception_happened == EXCEPTION_OTHER)
    return -1;

  return RTEST (rv);
}

static int
plugin_rb_can_trim (void *handle)
{
  volatile VALUE argv[1];
  volatile VALUE rv;

  argv[0] = (VALUE) handle;
  exception_happened = 0;
  rv = funcall2 (Qnil, rb_intern ("can_trim"), 1, argv);
  if (exception_happened == EXCEPTION_NO_METHOD_ERROR)
    /* Fall back to checking if the trim method exists. */
    rv = rb_funcall (Qnil, rb_intern ("respond_to?"),
                     2, ID2SYM (rb_intern ("trim")), Qtrue);
  else if (exception_happened == EXCEPTION_OTHER)
    return -1;

  return RTEST (rv);
}

#define plugin_rb_config_help \
  "script=<FILENAME>     (required) The Ruby plugin to run.\n" \
  "[other arguments may be used by the plugin that you load]"

/* Note use of a global variable above.  We can't change this without
 * fixing that (and lots more besides).
 */
#define THREAD_MODEL NBDKIT_THREAD_MODEL_SERIALIZE_ALL_REQUESTS

static struct nbdkit_plugin plugin = {
  .name              = "ruby",
  .version           = PACKAGE_VERSION,

  .load              = plugin_rb_load,
  .unload            = plugin_rb_unload,

  .config            = plugin_rb_config,
  .config_complete   = plugin_rb_config_complete,
  .config_help       = plugin_rb_config_help,

  .open              = plugin_rb_open,
  .close             = plugin_rb_close,

  .get_size          = plugin_rb_get_size,
  .can_write         = plugin_rb_can_write,
  .can_flush         = plugin_rb_can_flush,
  .is_rotational     = plugin_rb_is_rotational,
  .can_trim          = plugin_rb_can_trim,

  .pread             = plugin_rb_pread,
  .pwrite            = plugin_rb_pwrite,
  .flush             = plugin_rb_flush,
  .trim              = plugin_rb_trim,
};

NBDKIT_REGISTER_PLUGIN(plugin)
