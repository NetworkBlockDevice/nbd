#!/bin/sh
# vim: ft=sh
#
# skeleton	example file to build /etc/init.d/ scripts.
#		This file should be used to construct scripts for /etc/init.d.
#
#		Written by Miquel van Smoorenburg <miquels@cistron.nl>.
#		Modified for Debian GNU/Linux
#		by Ian Murdock <imurdock@gnu.ai.mit.edu>.
# 		Modified for the nbd-client package
#		by Wouter Verhelst <wouter@debian.org>
#
### BEGIN INIT INFO
# Provides: nbd-client
# Required-Start: $network $local_fs
# Required-Stop: $network
# Default-Start: S
# Default-Stop: 0 6
# X-Start-Before: mountnfs
# Short-Description: Network Block Device client
### END INIT INFO
#
# Version:	@(#)skeleton  1.8  03-Mar-1998  miquels@cistron.nl

PATH=/sbin:/bin:/usr/sbin:/usr/bin
DAEMON="/sbin/nbd-client"
NAME="nbd-client"
DESC="NBD client process"

test -f /etc/nbd-client && . /etc/nbd-client

test -x $DAEMON || exit 0

case "$1" in
    connect)
	# I don't use start-stop-daemon: nbd-client only does some setup
	# for the connection; the 'nbd-client' you see in your ps output
	# later on is a kernel thread...
	modprobe nbd
	echo -n 'Connecting...'
	for dev in $(awk '/^(( \t)*[^#])/{print $1}' /etc/nbdtab)
	do
	  # cfq deadlocks NBD devices, so switch to something else if cfq is
	  # selected by default
	  # This doesn't take into account non-udev devnames, but since
	  # there's really no other option these days...
	  if grep '\[cfq\]' "/sys/block/${dev}/queue/scheduler" >/dev/null; then
	  	echo deadline > "/sys/block/${dev}/queue/scheduler"
	  fi
	  if nbd-client -c "${dev}" >/dev/null
	  then
	  	echo "${dev} already connected, skipping..."
	  else
		nbd-client ${dev}
	  fi
	done
	;;
    start)
	echo -n "Starting $DESC: "
	$0 connect
	if [ ! -f /run/sendsigs.omit.d/nbd-client ]
	then
	  for x in $(cat /proc/cmdline); do
	    case $x in
	      nbdroot=*,*,*)
	        nbdroot="${x#nbdroot=}"
	        nbdbasedev=$(echo "$nbdroot" | sed -e 's/^.*,//')
	        nbdrootdev=/dev/$nbdbasedev
	        ;;
	      root=/dev/nbd*)
	        nbdrootdev="${x#root=}"
	        ;;
	    esac
	  done
	  OMITKILL="$OMITKILL ${nbdrootdev%p*}"
	  for x in $OMITKILL
	  do
	    nbd-client -c $x >> /run/sendsigs.omit.d/nbd-client
	  done
	fi
	;;
    stop)
	echo "Stopping $DESC: "
	for dev in $(awk '/^(( \t)*[^#])/{print $1}' /etc/nbdtab)
	do
	  nbd-client -d /dev/$dev
	done
	rmmod nbd
	echo "$NAME."
	;;
    restart|force-reload)
	$0 stop
	sleep 10
	$0 start
	;;
    *)
	N=/etc/init.d/$NAME
	echo "Usage: $N {start|connect|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
