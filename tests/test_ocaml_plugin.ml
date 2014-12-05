type handle = {
  disk : string;                        (* The disk image. *)
}

let test_load () =
  ()
let test_unload () =
  ()

let params = ref []

let test_config k v =
  params := (k, v) :: !params

let test_config_complete () =
  let params = List.rev !params in
  assert (params = [ "a", "1"; "b", "2"; "c", "3" ])

let test_open readonly =
  let disk =
    let s = String.create (512 * 8) in
    for i = 0 to 511 do
      for j = 0 to 7 do
        s.[i*8+j] <- Char.chr (j+1)
      done
    done;
    s in
  { disk = disk }

let test_close h =
  ()

let test_get_size h =
  Int64.of_int (String.length h.disk)

let test_pread h buf offset =
  let len = String.length buf in
  String.blit h.disk (Int64.to_int offset) buf 0 len

let test_pwrite h buf offset =
  let len = String.length buf in
  String.blit buf 0 h.disk (Int64.to_int offset) len

let plugin = {
  NBDKit.default_callbacks with
    NBDKit.name     = "testocaml";
    version         = "1.0";

    load            = Some test_load;
    unload          = Some test_unload;
    config          = Some test_config;
    config_complete = Some test_config_complete;

    open_connection = Some test_open;
    close           = Some test_close;
    get_size        = Some test_get_size;
    pread           = Some test_pread;
    pwrite          = Some test_pwrite;
}

let thread_model = NBDKit.THREAD_MODEL_SERIALIZE_CONNECTIONS

let () = NBDKit.register_plugin thread_model plugin
