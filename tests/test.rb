$disk = "\0" * (1024*1024);

def config_complete()
end

def open(readonly)
  return {}
end

def get_size(h)
  return $disk.bytesize
end

def can_write(h)
  return true
end

def can_flush(h)
  return true
end

def is_rotational(h)
  return false
end

def can_trim(h)
  return true
end

def pread(h, count, offset)
  return $disk.byteslice(offset, count)
end

def pwrite(h, buf, offset)
  # Is this using bytes or chars? XXX
  $disk[offset, buf.length] = buf
end

def flush(h)
end

def trim(h, count, offset)
end
