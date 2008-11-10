nbdsrvr is (C) 2003 by folkert@vanheusden.com
New versions can be obtained from:
http://www.vanheusden.com/ (browse to the
"microsoft windows software" section).

Usage:

nbdsrvr filename portnumber

filename must be an image of a filesystem or
whatever kind of device you whish to use. Can
also be an empty file.
For example, create an empty file of 10MB
called "image.dat"
Then:
nbdsrvr image.dat 9000
On your linux-box:
nbd-client hostname 9000 /dev/ndX
hostname is the hostname of your windows-box,
/dev/ndX is the device you want to couple the
image to.
After that, you could create a filesystem on
this image: on your Linux-box, type:
mke2fs /dev/ndX
and then mount it:
mount /dev/ndX /mnt

Good luck!


-- Folkert van Heusden, 2003/07/13, 21:59
