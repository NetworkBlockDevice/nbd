#!/bin/sh
# vim:ft=sh
#
# skeleton	example file to build /etc/init.d/ scripts.
#		This file should be used to construct scripts for /etc/init.d.
#
#		Written by Miquel van Smoorenburg <miquels@cistron.nl>.
#		Modified for Debian GNU/Linux
#		by Ian Murdock <imurdock@gnu.ai.mit.edu>.
# 		Modified for the nbd-server package
#		by Wouter Verhelst <wouter@debian.org>
#
# Version:	@(#)skeleton  1.8  03-Mar-1998  miquels@cistron.nl
#
### BEGIN INIT INFO 
# Provides: nbd-server 
# Required-Start: $remote_fs $syslog
# Required-Stop: $remote_fs $syslog
# Should-Start: $network
# Should-Stop: $network
# Default-Start: 2 3 4 5 
# Default-Stop: 0 1 6 
# Short-Description: Network Block Device server
### END INIT INFO

PATH=/sbin:/bin:/usr/sbin:/usr/bin
DAEMON="/bin/nbd-server"
NAME="nbd-server"
DESC="Network Block Device server"

test -x $DAEMON || exit 0

case "$1" in
    start)
	start-stop-daemon --start --quiet --exec /bin/nbd-server --oknodo --pidfile /var/run/nbd-server.pid
	echo " $NAME."
	;;
    stop)
	echo -n "Stopping $DESC:"
	start-stop-daemon --stop --quiet --exec /bin/nbd-server --oknodo --pidfile /var/run/nbd-server.pid --retry 1
	echo " $NAME."
	;;
    reload)
    	echo -n "Reloading $DESC:"
	if [ -f /var/run/nbd-server.pid ]
	then
		kill -HUP $(cat /var/run/nbd-server.pid)
	fi
	;;
    restart|force-reload)
	echo "Restarting the $DESC is pretty harsh on clients still using it."
	echo -n "waiting 5 seconds..."
	sleep 5
	echo "You have been warned!"
	echo -n "Restarting $DESC: "
	$0 stop
	sleep 10
	$0 start
	;;
    *)
	N=/etc/init.d/$NAME
	# echo "Usage: $N {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: $N {start|stop|restart|force-reload}" >&2
	exit 1
	;;
esac

exit 0
