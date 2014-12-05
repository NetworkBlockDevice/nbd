(* nbdkit OCaml interface
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
 *)

open Printf

type 'a plugin = {
  name : string;
  longname : string;
  version : string;
  description : string;

  load : (unit -> unit) option;
  unload : (unit -> unit) option;
  config : (string -> string -> unit) option;
  config_complete : (unit -> unit) option;
  config_help : string;

  open_connection : (bool -> 'a) option;
  close : ('a -> unit) option;
  get_size : ('a -> int64) option;
  can_write : ('a -> bool) option;
  can_flush : ('a -> bool) option;
  is_rotational : ('a -> bool) option;
  can_trim : ('a -> bool) option;
  pread : ('a -> string -> int64 -> unit) option;
  pwrite : ('a -> string -> int64 -> unit) option;
  flush : ('a -> unit) option;
  trim : ('a -> int32 -> int64 -> unit) option;
}

let default_callbacks = {
  name = "";
  longname = "";
  version = "";
  description = "";

  load = None;
  unload = None;
  config = None;
  config_complete = None;
  config_help = "";

  open_connection = None;
  close = None;
  get_size = None;
  can_write = None;
  can_flush = None;
  is_rotational = None;
  can_trim = None;
  pread = None;
  pwrite = None;
  flush = None;
  trim = None;
}

type thread_model =
| THREAD_MODEL_SERIALIZE_CONNECTIONS
| THREAD_MODEL_SERIALIZE_ALL_REQUESTS
| THREAD_MODEL_SERIALIZE_REQUESTS
| THREAD_MODEL_PARALLEL

external set_thread_model : int -> unit = "ocaml_nbdkit_set_thread_model" "noalloc"

external set_name : string -> unit = "ocaml_nbdkit_set_name" "noalloc"
external set_longname : string -> unit = "ocaml_nbdkit_set_longname" "noalloc"
external set_version : string -> unit = "ocaml_nbdkit_set_version" "noalloc"
external set_description : string -> unit = "ocaml_nbdkit_set_description" "noalloc"

external set_load : (unit -> unit) -> unit = "ocaml_nbdkit_set_load"
external set_unload : (unit -> unit) -> unit = "ocaml_nbdkit_set_unload"
external set_config : (string -> string -> unit) -> unit = "ocaml_nbdkit_set_config"
external set_config_complete : (unit -> unit) -> unit = "ocaml_nbdkit_set_config_complete"
external set_config_help : string -> unit = "ocaml_nbdkit_set_config_help" "noalloc"

external set_open : (bool -> 'a) -> unit = "ocaml_nbdkit_set_open"
external set_close : ('a -> unit) -> unit = "ocaml_nbdkit_set_close"
external set_get_size : ('a -> int64) -> unit = "ocaml_nbdkit_set_get_size"
external set_can_write : ('a -> bool) -> unit = "ocaml_nbdkit_set_can_write"
external set_can_flush : ('a -> bool) -> unit = "ocaml_nbdkit_set_can_flush"
external set_is_rotational : ('a -> bool) -> unit = "ocaml_nbdkit_set_is_rotational"
external set_can_trim : ('a -> bool) -> unit = "ocaml_nbdkit_set_can_trim"
external set_pread : ('a -> string -> int64 -> unit) -> unit = "ocaml_nbdkit_set_pread"
external set_pwrite : ('a -> string -> int64 -> unit) -> unit = "ocaml_nbdkit_set_pwrite"
external set_flush : ('a -> unit) -> unit = "ocaml_nbdkit_set_flush"
external set_trim : ('a -> int32 -> int64 -> unit) -> unit = "ocaml_nbdkit_set_trim"

let may f = function None -> () | Some a -> f a

let register_plugin thread_model plugin =
  (* Check the required fields have been set by the caller. *)
  if plugin.name = "" then
    failwith "'.name' field in NBDKit.plugin structure must be set";
  if plugin.open_connection = None then
    failwith (sprintf "%s: '.open_connection' field in NBDKit.plugin structure must be set"
                plugin.name);
  if plugin.get_size = None then
    failwith (sprintf "%s: '.get_size' field in NBDKit.plugin structure must be set"
                plugin.name);
  if plugin.pread = None then
    failwith (sprintf "%s: '.pread' field in NBDKit.plugin structure must be set"
                plugin.name);

  (* Set the fields in the C code. *)
  set_thread_model (Obj.magic thread_model);

  set_name plugin.name;
  if plugin.longname <> "" then
    set_longname plugin.longname;
  if plugin.version <> "" then
    set_version plugin.version;
  if plugin.description <> "" then
    set_description plugin.description;

  may set_load plugin.load;
  may set_unload plugin.unload;
  may set_config plugin.config;
  may set_config_complete plugin.config_complete;
  if plugin.config_help <> "" then
    set_config_help plugin.config_help;

  may set_open plugin.open_connection;
  may set_close plugin.close;
  may set_get_size plugin.get_size;
  may set_can_write plugin.can_write;
  may set_can_flush plugin.can_flush;
  may set_is_rotational plugin.is_rotational;
  may set_can_trim plugin.can_trim;
  may set_pread plugin.pread;
  may set_pwrite plugin.pwrite;
  may set_flush plugin.flush;
  may set_trim plugin.trim
