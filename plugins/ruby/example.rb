# Example Ruby plugin.
#
# This example can be freely used for any purpose.

# Run it from the build directory like this:
#
#   ./src/nbdkit -f -v ./plugins/ruby/.libs/nbdkit-ruby-plugin.so  \
#       script=./plugins/ruby/example.rb test1=foo test2=bar
#
# Or run it after installing nbdkit like this:
#
#   nbdkit -f -v ruby script=./plugins/ruby/example.rb test1=foo test2=bar
#
# The -f -v arguments are optional.  They cause the server to stay in
# the foreground and print debugging, which is useful when testing.
#
# You can connect to the server using guestfish or qemu, eg:
#
#   guestfish --format=raw -a nbd://localhost
#   ><fs> run
#   ><fs> part-disk /dev/sda mbr
#   ><fs> mkfs ext2 /dev/sda1
#   ><fs> list-filesystems
#   ><fs> mount /dev/sda1 /
#   ><fs> [etc]

$disk = "\0" * (1024 * 1024)

def config(key, value)
  printf("%s = %s\n", key, value)
end

def open(readonly)
  # You can return any non-nil Ruby object as a handle.  The
  # same object is passed as the first argument to the other
  # callbacks.
  h = {}
  return h
end

def get_size(h)
  return $disk.bytesize
end

def pread(h, count, offset)
  return $disk.byteslice(offset, count)
end

def pwrite(h, buf, offset)
  # Hmm, is this using bytes or chars? XXX
  $disk[offset, buf.length] = buf
end
