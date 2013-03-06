#! /bin/bash
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

get_devices() {
    DEVICES=
    i=0
    while [ ! -z "${NBD_TYPE[$i]}" ]
    do
	if [ "${NBD_TYPE[$i]}" == "$1" ]
	then
	    DEVICES="$DEVICES ${NBD_DEVICE[$i]}"
	fi
	i=$(($i + 1))
    done
}

get_all_devices() {
	if [ "$KILLALL" == "false" ]
	then
	    DEVICES=${NBD_DEVICE[*]}
	else
	    if [ -d /dev/nbd ]
	    then
		    DEVICES=/dev/nbd/*
	    else
		    DEVICES=/dev/nb*
	    fi
	fi
}

get_swap_devices() {
	if [ "$KILLALL" == "false" ]
	then
	    get_devices s
	else
	    if [ -f /proc/swaps ]
	    then
		DEVICES=`grep '^/dev/nb' /proc/swaps | cut -d ' ' -f1`
	    else
		get_all_devices
	    fi
	fi
}

get_mount_devices() {
	if [ "$KILLALL" == "false" ]
	then
	    get_devices f
	else
	    DEVICES=`mount | cut -d " " -f 1 | grep /dev/nbd`
	fi
}


case "$1" in
    connect)
	# I don't use start-stop-daemon: nbd-client only does some setup
	# for the connection; the 'nbd-client' you see in your ps output
	# later on is a kernel thread...
	modprobe nbd
	echo -n 'Connecting...'
	i=0
	while [ ! -z "${NBD_TYPE[$i]}" ]
	  do
	  # cfq deadlocks NBD devices, so switch to something else if cfq is
	  # selected by default
	  # This doesn't take into account non-udev devnames, but since
	  # there's really no other option these days...
	  if grep '\[cfq\]' "/sys/block/${NBD_DEVICE[$i]/\/dev\//}/queue/scheduler" >/dev/null; then
	  	echo deadline > "/sys/block/${NBD_DEVICE[$i]/\/dev\//}/queue/scheduler"
	  fi
	  if nbd-client -c "${NBD_DEVICE[$i]}" >/dev/null
	  then
	  	echo "${NBD_DEVICE[$i]} already connected, skipping..."
	  else
		if [ -z "${NBD_NAME[$i]}" -a -z "${NBD_PORT[$i]}" ]
		then
			echo "Either NBD_NAME or NBD_PORT must be specified for ${NBD_DEVICE[$i]}"
		else
			if $DAEMON "${NBD_HOST[$i]}" ${NBD_NAME[$i]:+-N "${NBD_NAME[$i]}"} ${NBD_PORT[$i]:+"${NBD_PORT[$i]}"} "${NBD_DEVICE[$i]}" ${NBD_EXTRA[$i]}
			then
				echo "connected ${NBD_DEVICE[$i]}"
			else
				echo "could not connect ${NBD_DEVICE[$i]}"
			fi
		fi
	  fi
	  i=$(($i + 1))
	done
	;;
    start)
	echo -n "Starting $DESC: "
	$0 connect
	$0 activate
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
    activate)
	echo 'Activating...'
	i=0
	while [ ! -z "${NBD_TYPE[$i]}" -a ! -z "$(nbd-client -c "${NBD_DEVICE[$i]}")" ]
	do
	  case "${NBD_TYPE[$i]}" in
	      "s")
	      	  /sbin/mkswap "${NBD_DEVICE[$i]}"
		  /sbin/swapon "${NBD_DEVICE[$i]}"
		  echo "${NBD_DEVICE[$i]}: swap activated."
		  ;;
	      "f")
	          line=$(grep "${NBD_DEVICE[$i]}" /etc/fstab | grep "_netdev")
		  if [ -z "$line" ]
		  then
		    # sysvinit takes care of these.
		    spinner="-C"
		    case "$TERM" in
		      dumb|network|unknown|"") spinner="" ;;
		    esac
		    /sbin/fsck $spinner -a "${NBD_DEVICE[$i]}"
		    if [ $? -lt 2 ]
		        then
		        /bin/mount "${NBD_DEVICE[$i]}"
		        echo "${NBD_DEVICE[$i]}: filesystem mounted."
		    else
		        echo "fsck of ${NBD_DEVICE[$i]} failed. Not mounting."
		    fi
		  fi
		  ;;
	      "r")
		  # Nothing needs to be done
		  echo "${NBD_DEVICE[$i]}: raw selected. doing nothing."
		  ;;
	      *)
		  echo "Error: NBD_TYPE[$i] contains unknown value ${NBD_TYPE[$i]}"
		  ;;
	  esac
	  i=$(( $i + 1 ))
	done
	echo "$NAME."
	;;
    stop)
	echo "Stopping $DESC: "
	get_mount_devices
	for dev in $DEVICES
	do
	  # Ignore devices with _netdev option (sysvinit takes care of those)
	  line=$(grep $dev /etc/fstab | grep "_netdev")
	  if [ -z "$line" ]
	  then
	    echo "umounting filesystem from $dev..."
	    umount $dev 2>/dev/null
	    if [ $? -eq 1 ]
	    then
	      echo -n "umount of $dev failed! Data loss may occur! will continue in 10 seconds..."
	      sleep 1
	      for i in 9 8 7 6 5 4 3 2 1
	      do
	        echo -n $i" "
		sleep 1
	      done
	      echo "ok, going on..."
	    fi
	  fi
	  echo $dev
	done
	get_swap_devices
	if [ "$DEVICES" ]
	    then
	    echo "Invoking swapoff on $DEVICES..."
	    swapoff $DEVICES 2>/dev/null
	fi
	get_all_devices
	for i in $DEVICES
	do
	  echo "Disconnecting $i"
	  $DAEMON -d $i 2>/dev/null >/dev/null
	done
	rmmod nbd
	echo "$NAME."
	;;
    restart|force-reload)
    	if dpkg --compare-versions "$(uname -r)" gt "2.4"
	then
		$0 stop
		sleep 10
		$0 start
	else
		echo "Need 2.4-kernel for disconnect. As such, restart won't work"
		echo "Either upgrade to a 2.4-kernel, or use $0 stop, restart the server,"
		echo "and do $0 start."
	fi
	;;
    *)
	N=/etc/init.d/$NAME
	echo "Usage: $N {start|connect|stop|restart|force-reload|activate}" >&2
	exit 1
	;;
esac

exit 0
