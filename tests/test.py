disk = "\0" * (1024*1024);

def config_complete():
    pass

def open(readonly):
    return 1

def get_size(h):
    global disk
    return len (disk)

def can_write(h):
    return True

def can_flush(h):
    return True

def is_rotational(h):
    return False

def can_trim(h):
    return True

def pread(h, count, offset):
    global disk
    return bytearray (disk[offset:offset+count])

def pwrite(h, buf, offset):
    global disk
    end = offset + len (buf)
    disk = disk[:offset] + buf + disk[end:]

def flush(h):
    pass

def trim(h, count, offset):
    pass
