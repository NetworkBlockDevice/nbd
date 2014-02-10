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

/* This has to be included first, else definitions conflict with
 * glibc header files.  Python is broken.
 */
#define PY_SSIZE_T_CLEAN 1
#include <Python.h>

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <nbdkit-plugin.h>

static const char *script;
static PyObject *module;

/* Is a callback defined? */
static int
callback_defined (const char *name, PyObject **obj_rtn)
{
  PyObject *obj;

  assert (script != NULL);
  assert (module != NULL);

  obj = PyObject_GetAttrString (module, name);
  if (!obj)
    return 0;

  if (obj_rtn != NULL)
    *obj_rtn = obj;
  else
    Py_DECREF (obj);

  return 1;
}

static int
check_python_failure (const char *callback)
{
  if (PyErr_Occurred ()) {
    nbdkit_error ("%s: callback failed: %s", script, callback);
    /* How to turn this into a string? XXX */
    PyErr_Print ();
    return -1;
  }
  return 0;
}

static void
py_load (void)
{
  Py_Initialize ();
}

static void
py_unload (void)
{
  if (module)
    Py_DECREF (module);

  Py_Finalize ();
}

static int
py_config (const char *key, const char *value)
{
  FILE *fp;
  PyObject *modname;
  PyObject *fn;
  PyObject *args;
  PyObject *r;

  if (!script) {
    /* The first parameter MUST be "script". */
    if (strcmp (key, "script") != 0) {
      nbdkit_error ("the first parameter must be script=/path/to/python/script.py");
      return -1;
    }
    script = value;

    /* Load the Python script. */
    fp = fopen (script, "r");
    if (!fp) {
      nbdkit_error ("%s: cannot open file: %m", script);
      return -1;
    }

    if (PyRun_SimpleFileEx (fp, script, 1) == -1) {
      nbdkit_error ("%s: error running this script", script);
      return -1;
    }
    /* Note that because closeit flag == 1, fp is now closed. */

    /* The script should define a module called __main__. */
    modname = PyString_FromString ("__main__");
    module = PyImport_Import (modname);
    Py_DECREF (modname);
    if (!module) {
      nbdkit_error ("%s: cannot find __main__ module", script);
      return -1;
    }

    /* Minimal set of callbacks which are required (by nbdkit itself). */
    if (!callback_defined ("open", NULL) ||
        !callback_defined ("get_size", NULL) ||
        !callback_defined ("pread", NULL)) {
      nbdkit_error ("%s: one of the required callbacks 'open', 'get_size' or 'pread' is not defined by this Python script.  nbdkit requires these callbacks.", script);
      return -1;
    }
  }
  else if (callback_defined ("config", &fn)) {
    /* Other parameters are passed to the Python .config callback. */
    PyErr_Clear ();

    args = PyTuple_New (2);
    PyTuple_SetItem (args, 0, PyString_FromString (key));
    PyTuple_SetItem (args, 1, PyString_FromString (value));
    r = PyObject_CallObject (fn, args);
    Py_DECREF (fn);
    Py_DECREF (args);
    if (check_python_failure ("config") == -1)
      return -1;
    Py_DECREF (r);
  }
  else {
    /* Emulate what core nbdkit does if a config callback is NULL. */
    nbdkit_error ("%s: this plugin does not need command line configuration",
                  script);
    return -1;
  }

  return 0;
}

static int
py_config_complete (void)
{
  PyObject *fn;
  PyObject *r;

  if (callback_defined ("config_complete", &fn)) {
    PyErr_Clear ();

    r = PyObject_CallObject (fn, NULL);
    Py_DECREF (fn);
    if (check_python_failure ("config_complete") == -1)
      return -1;
    Py_DECREF (r);
  }

  return 0;
}

static void *
py_open (int readonly)
{
  PyObject *fn;
  PyObject *args;
  PyObject *handle;

  if (!callback_defined ("open", &fn)) {
    nbdkit_error ("%s: missing callback: %s", script, "open");
    return NULL;
  }

  PyErr_Clear ();

  args = PyTuple_New (1);
  PyTuple_SetItem (args, 0, PyBool_FromLong (readonly));
  handle = PyObject_CallObject (fn, args);
  Py_DECREF (fn);
  Py_DECREF (args);
  if (check_python_failure ("open") == -1)
    return NULL;

  return handle;
}

static void
py_close (void *handle)
{
  PyObject *obj = handle;
  PyObject *fn;
  PyObject *args;
  PyObject *r;

  if (callback_defined ("close", &fn)) {
    PyErr_Clear ();

    args = PyTuple_New (1);
    Py_INCREF (obj); /* decremented by Py_DECREF (args) */
    PyTuple_SetItem (args, 0, obj);
    r = PyObject_CallObject (fn, args);
    Py_DECREF (fn);
    Py_DECREF (args);
    check_python_failure ("close");
    if (r)
      Py_DECREF (r);
  }

  Py_DECREF (obj);
}

static int64_t
py_get_size (void *handle)
{
  PyObject *obj = handle;
  PyObject *fn;
  PyObject *args;
  PyObject *r;
  int64_t ret;

  if (!callback_defined ("get_size", &fn)) {
    nbdkit_error ("%s: missing callback: %s", script, "get_size");
    return -1;
  }

  PyErr_Clear ();

  args = PyTuple_New (1);
  Py_INCREF (obj); /* decremented by Py_DECREF (args) */
  PyTuple_SetItem (args, 0, obj);
  r = PyObject_CallObject (fn, args);
  Py_DECREF (fn);
  Py_DECREF (args);
  if (check_python_failure ("get_size") == -1)
    return -1;

  ret = PyLong_AsLongLong (r);
  Py_DECREF (r);
  if (check_python_failure ("PyLong_AsLongLong") == -1)
    return -1;

  return ret;
}

static int
py_pread (void *handle, void *buf,
          uint32_t count, uint64_t offset)
{
  PyObject *obj = handle;
  PyObject *fn;
  PyObject *args;
  PyObject *r;

  if (!callback_defined ("pread", &fn)) {
    nbdkit_error ("%s: missing callback: %s", script, "pread");
    return -1;
  }

  PyErr_Clear ();

  args = PyTuple_New (3);
  Py_INCREF (obj); /* decremented by Py_DECREF (args) */
  PyTuple_SetItem (args, 0, obj);
  PyTuple_SetItem (args, 1, PyLong_FromLong (count));
  PyTuple_SetItem (args, 2, PyLong_FromUnsignedLongLong (offset));
  r = PyObject_CallObject (fn, args);
  Py_DECREF (fn);
  Py_DECREF (args);
  if (check_python_failure ("pread") == -1)
    return -1;

  if (!PyByteArray_Check (r)) {
    nbdkit_error ("%s: value returned from pread method is not a byte array",
                  script);
    Py_DECREF (r);
    return -1;
  }

  if (PyByteArray_Size (r) < count) {
    nbdkit_error ("%s: byte array returned from pread is too small", script);
    Py_DECREF (r);
    return -1;
  }

  memcpy (buf, PyByteArray_AsString (r), count);
  Py_DECREF (r);

  return 0;
}

static int
py_pwrite (void *handle, const void *buf,
           uint32_t count, uint64_t offset)
{
  PyObject *obj = handle;
  PyObject *fn;
  PyObject *args;
  PyObject *r;

  if (callback_defined ("pwrite", &fn)) {
    PyErr_Clear ();

    args = PyTuple_New (3);
    Py_INCREF (obj); /* decremented by Py_DECREF (args) */
    PyTuple_SetItem (args, 0, obj);
    PyTuple_SetItem (args, 1, PyByteArray_FromStringAndSize (buf, count));
    PyTuple_SetItem (args, 2, PyLong_FromUnsignedLongLong (offset));
    r = PyObject_CallObject (fn, args);
    Py_DECREF (fn);
    Py_DECREF (args);
    if (check_python_failure ("pwrite") == -1)
      return -1;
    Py_DECREF (r);
  }
  else {
    nbdkit_error ("%s not implemented", "pwrite");
    return -1;
  }

  return 0;
}

static int
py_flush (void *handle)
{
  PyObject *obj = handle;
  PyObject *fn;
  PyObject *args;
  PyObject *r;

  if (callback_defined ("flush", &fn)) {
    PyErr_Clear ();

    args = PyTuple_New (1);
    Py_INCREF (obj); /* decremented by Py_DECREF (args) */
    PyTuple_SetItem (args, 0, obj);
    r = PyObject_CallObject (fn, args);
    Py_DECREF (fn);
    Py_DECREF (args);
    if (check_python_failure ("flush") == -1)
      return -1;
    Py_DECREF (r);
  }
  else {
    nbdkit_error ("%s not implemented", "flush");
    return -1;
  }

  return 0;
}

static int
py_trim (void *handle, uint32_t count, uint64_t offset)
{
  PyObject *obj = handle;
  PyObject *fn;
  PyObject *args;
  PyObject *r;

  if (callback_defined ("trim", &fn)) {
    PyErr_Clear ();

    args = PyTuple_New (3);
    Py_INCREF (obj); /* decremented by Py_DECREF (args) */
    PyTuple_SetItem (args, 0, obj);
    PyTuple_SetItem (args, 1, PyLong_FromLong (count));
    PyTuple_SetItem (args, 2, PyLong_FromUnsignedLongLong (offset));
    r = PyObject_CallObject (fn, args);
    Py_DECREF (fn);
    Py_DECREF (args);
    if (check_python_failure ("trim") == -1)
      return -1;
    Py_DECREF (r);
  }
  else {
    nbdkit_error ("%s not implemented", "trim");
    return -1;
  }

  return 0;
}

static int
py_can_write (void *handle)
{
  PyObject *obj = handle;
  PyObject *fn;
  PyObject *args;
  PyObject *r;
  int ret;

  if (callback_defined ("can_write", &fn)) {
    PyErr_Clear ();

    args = PyTuple_New (1);
    Py_INCREF (obj); /* decremented by Py_DECREF (args) */
    PyTuple_SetItem (args, 0, obj);
    r = PyObject_CallObject (fn, args);
    Py_DECREF (fn);
    Py_DECREF (args);
    if (check_python_failure ("can_write") == -1)
      return -1;
    ret = r == Py_True;
    Py_DECREF (r);
    return ret;
  }
  /* No Perl can_write callback, but there's a Perl pwrite callback
   * defined, so return 1.  (In C modules, nbdkit would do this).
   */
  else if (callback_defined ("pwrite", NULL))
    return 1;
  else
    return 0;
}

static int
py_can_flush (void *handle)
{
  PyObject *obj = handle;
  PyObject *fn;
  PyObject *args;
  PyObject *r;
  int ret;

  if (callback_defined ("can_flush", &fn)) {
    PyErr_Clear ();

    args = PyTuple_New (1);
    Py_INCREF (obj); /* decremented by Py_DECREF (args) */
    PyTuple_SetItem (args, 0, obj);
    r = PyObject_CallObject (fn, args);
    Py_DECREF (fn);
    Py_DECREF (args);
    if (check_python_failure ("can_flush") == -1)
      return -1;
    ret = r == Py_True;
    Py_DECREF (r);
    return ret;
  }
  /* No Perl can_flush callback, but there's a Perl flush callback
   * defined, so return 1.  (In C modules, nbdkit would do this).
   */
  else if (callback_defined ("flush", NULL))
    return 1;
  else
    return 0;
}

static int
py_is_rotational (void *handle)
{
  PyObject *obj = handle;
  PyObject *fn;
  PyObject *args;
  PyObject *r;
  int ret;

  if (callback_defined ("is_rotational", &fn)) {
    PyErr_Clear ();

    args = PyTuple_New (1);
    Py_INCREF (obj); /* decremented by Py_DECREF (args) */
    PyTuple_SetItem (args, 0, obj);
    r = PyObject_CallObject (fn, args);
    Py_DECREF (fn);
    Py_DECREF (args);
    if (check_python_failure ("is_rotational") == -1)
      return -1;
    ret = r == Py_True;
    Py_DECREF (r);
    return ret;
  }
  else
    return 0;
}

static int
py_can_trim (void *handle)
{
  PyObject *obj = handle;
  PyObject *fn;
  PyObject *args;
  PyObject *r;
  int ret;

  if (callback_defined ("can_trim", &fn)) {
    PyErr_Clear ();

    args = PyTuple_New (1);
    Py_INCREF (obj); /* decremented by Py_DECREF (args) */
    PyTuple_SetItem (args, 0, obj);
    r = PyObject_CallObject (fn, args);
    Py_DECREF (fn);
    Py_DECREF (args);
    if (check_python_failure ("can_trim") == -1)
      return -1;
    ret = r == Py_True;
    Py_DECREF (r);
    return ret;
  }
  /* No Perl can_trim callback, but there's a Perl trim callback
   * defined, so return 1.  (In C modules, nbdkit would do this).
   */
  else if (callback_defined ("trim", NULL))
    return 1;
  else
    return 0;
}

#define py_config_help \
  "script=<FILENAME>     (required) The Python plugin to run.\n" \
  "[other arguments may be used by the plugin that you load]"

#define THREAD_MODEL NBDKIT_THREAD_MODEL_SERIALIZE_ALL_REQUESTS

static struct nbdkit_plugin plugin = {
  .name              = "python",
  .version           = PACKAGE_VERSION,

  .load              = py_load,
  .unload            = py_unload,

  .config            = py_config,
  .config_complete   = py_config_complete,
  .config_help       = py_config_help,

  .open              = py_open,
  .close             = py_close,

  .get_size          = py_get_size,
  .can_write         = py_can_write,
  .can_flush         = py_can_flush,
  .is_rotational     = py_is_rotational,
  .can_trim          = py_can_trim,

  .pread             = py_pread,
  .pwrite            = py_pwrite,
  .flush             = py_flush,
  .trim              = py_trim,
};

NBDKIT_REGISTER_PLUGIN(plugin)
