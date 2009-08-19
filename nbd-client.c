/*
 * Open connection for network block device
 *
 * Copyright 1997,1998 Pavel Machek, distribute under GPL
 *  <pavel@atrey.karlin.mff.cuni.cz>
 *
 * Version 1.0 - 64bit issues should be fixed, now
 * Version 1.1 - added bs (blocksize) option (Alexey Guzeev, aga@permonline.ru)
 * Version 1.2 - I added new option '-d' to send the disconnect request
 * Version 2.0 - Version synchronised with server
 * Version 2.1 - Check for disconnection before INIT_PASSWD is received
 * 	to make errormsg a bit more helpful in case the server can't
 * 	open the exported file.
 */

#include "config.h"
#include "lfs.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/in.h>		/* sockaddr_in, htons, in_addr */
#include <netdb.h>		/* hostent, gethostby*, getservby* */
#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <errno.h>

#ifndef __GNUC__
#error I need GCC to work
#endif

#include <linux/ioctl.h>
#define MY_NAME "nbd_client"
#include "cliserv.h"

int check_conn(char* devname, int do_print) {
	char buf[256];
	char* p;
	int fd;
	int len;
	if(!strncmp(devname, "/dev/", 5)) {
		devname+=5;
	}
	if((p=strchr(devname, 'p'))) {
		/* We can't do checks on partitions. */
		*p='\0';
	}
	snprintf(buf, 256, "/sys/block/%s/pid", devname);
	if((fd=open(buf, O_RDONLY))<0) {
		if(errno==ENOENT) {
			return 1;
		} else {
			return 2;
		}
	}
	len=read(fd, buf, 256);
	buf[len-1]='\0';
	if(do_print) printf("%s\n", buf);
	return 0;
}

int opennet(char *name, int port, int sdp) {
	int sock;
	struct sockaddr_in xaddrin;
	int xaddrinlen = sizeof(xaddrin);
	struct hostent *hostn;
	int af;

	hostn = gethostbyname(name);
	if (!hostn)
		err("Gethostname failed: %h\n");

	af = AF_INET;
	if(sdp) {
#ifdef WITH_SDP
		af = AF_INET_SDP;
#else
		err("Can't do SDP: I was not compiled with SDP support!");
#endif
	}
	if ((sock = socket(af, SOCK_STREAM, IPPROTO_TCP)) < 0)
		err("Socket failed: %m");

	xaddrin.sin_family = af;
	xaddrin.sin_port = htons(port);
	xaddrin.sin_addr.s_addr = *((int *) hostn->h_addr);
	if ((connect(sock, (struct sockaddr *) &xaddrin, xaddrinlen) < 0))
		err("Connect: %m");

	setmysockopt(sock);
	return sock;
}

void negotiate(int sock, u64 *rsize64, u32 *flags) {
	u64 magic, size64;
	char buf[256] = "\0\0\0\0\0\0\0\0\0";

	printf("Negotiation: ");
	if (read(sock, buf, 8) < 0)
		err("Failed/1: %m");
	if (strlen(buf)==0)
		err("Server closed connection");
	if (strcmp(buf, INIT_PASSWD))
		err("INIT_PASSWD bad");
	printf(".");
	if (read(sock, &magic, sizeof(magic)) < 0)
		err("Failed/2: %m");
	magic = ntohll(magic);
	if (magic != cliserv_magic)
		err("Not enough cliserv_magic");
	printf(".");

	if (read(sock, &size64, sizeof(size64)) < 0)
		err("Failed/3: %m\n");
	size64 = ntohll(size64);

#ifdef NBD_SET_SIZE_BLOCKS
	if ((size64>>10) > (~0UL >> 1)) {
		printf("size = %luMB", (unsigned long)(size64>>20));
		err("Exported device is too big for me. Get 64-bit machine :-(\n");
	} else
		printf("size = %luKB", (unsigned long)(size64>>10));
#else
	if (size64 > (~0UL >> 1)) {
		printf("size = %luKB", (unsigned long)(size64>>10));
		err("Exported device is too big. Get 64-bit machine or newer kernel :-(\n");
	} else
		printf("size = %lu", (unsigned long)(size64));
#endif

	if (read(sock, flags, sizeof(*flags)) < 0)
		err("Failed/4: %m\n");
	*flags = ntohl(*flags);

	if (read(sock, &buf, 124) < 0)
		err("Failed/5: %m\n");
	printf("\n");

	*rsize64 = size64;
}

void setsizes(int nbd, u64 size64, int blocksize, u32 flags) {
	unsigned long size;
	int read_only = (flags & NBD_FLAG_READ_ONLY) ? 1 : 0;

#ifdef NBD_SET_SIZE_BLOCKS
	if (size64/blocksize > (~0UL >> 1))
		err("Device too large.\n");
	else {
		int er;
		if (ioctl(nbd, NBD_SET_BLKSIZE, (unsigned long)blocksize) < 0)
			err("Ioctl/1.1a failed: %m\n");
		size = (unsigned long)(size64/blocksize);
		if ((er = ioctl(nbd, NBD_SET_SIZE_BLOCKS, size)) < 0)
			err("Ioctl/1.1b failed: %m\n");
		fprintf(stderr, "bs=%d, sz=%lu\n", blocksize, size);
	}
#else
	if (size64 > (~0UL >> 1)) {
		err("Device too large.\n");
	} else {
		size = (unsigned long)size64;
		if (ioctl(nbd, NBD_SET_SIZE, size) < 0)
			err("Ioctl NBD_SET_SIZE failed: %m\n");
	}
#endif

	ioctl(nbd, NBD_CLEAR_SOCK);

	if (ioctl(nbd, BLKROSET, (unsigned long) &read_only) < 0)
		err("Unable to set read-only attribute for device");
}

void set_timeout(int nbd, int timeout) {
	if (timeout) {
#ifdef NBD_SET_TIMEOUT
		if (ioctl(nbd, NBD_SET_TIMEOUT, (unsigned long)timeout) < 0)
			err("Ioctl NBD_SET_TIMEOUT failed: %m\n");
		fprintf(stderr, "timeout=%d\n", timeout);
#else
		err("Ioctl NBD_SET_TIMEOUT cannot be called when compiled on a system that does not support it\n");
#endif
	}
}

void finish_sock(int sock, int nbd, int swap) {
	if (ioctl(nbd, NBD_SET_SOCK, sock) < 0)
		err("Ioctl NBD_SET_SOCK failed: %m\n");

	if (swap)
		mlockall(MCL_CURRENT | MCL_FUTURE);
}

int main(int argc, char *argv[]) {
	int port, sock, nbd;
	int blocksize=1024;
	char *hostname, *nbddev;
	int swap=0;
	int cont=0;
	int timeout=0;
	int sdp=0;
	int nofork=0;
	u64 size64;
	u32 flags;

	logging();

	if (argc < 3) {
	errmsg:
		fprintf(stderr, "nbd-client version %s\n", PACKAGE_VERSION);
		fprintf(stderr, "Usage: nbd-client [bs=blocksize] [timeout=sec] host port nbd_device [-swap] [-persist] [-nofork]\n");
		fprintf(stderr, "Or   : nbd-client -d nbd_device\n");
		fprintf(stderr, "Or   : nbd-client -c nbd_device\n");
		fprintf(stderr, "Default value for blocksize is 1024 (recommended for ethernet)\n");
		fprintf(stderr, "Allowed values for blocksize are 512,1024,2048,4096\n"); /* will be checked in kernel :) */
		fprintf(stderr, "Note, that kernel 2.4.2 and older ones do not work correctly with\n");
		fprintf(stderr, "blocksizes other than 1024 without patches\n");
		return 1;
	}

	++argv; --argc; /* skip programname */

	if (strcmp(argv[0], "-d")==0) {
		nbd = open(argv[1], O_RDWR);
		if (nbd < 0)
			err("Cannot open NBD: %m\nPlease ensure the 'nbd' module is loaded.");
		printf("Disconnecting: que, ");
		if (ioctl(nbd, NBD_CLEAR_QUE)< 0)
			err("Ioctl failed: %m\n");
		printf("disconnect, ");
#ifdef NBD_DISCONNECT
		if (ioctl(nbd, NBD_DISCONNECT)<0)
			err("Ioctl failed: %m\n");
		printf("sock, ");
#else
		fprintf(stderr, "Can't disconnect: I was not compiled with disconnect support!\n" );
		exit(1);
#endif
		if (ioctl(nbd, NBD_CLEAR_SOCK)<0)
			err("Ioctl failed: %m\n");
		printf("done\n");
		return 0;
	}
	if(strcmp(argv[0], "-c")==0) {
		return check_conn(argv[1], 1);
	}
	
	if (strncmp(argv[0], "bs=", 3)==0) {
		blocksize=atoi(argv[0]+3);
		++argv; --argc; /* skip blocksize */
	}

	if (strncmp(argv[0], "timeout=", 8)==0) {
		timeout=atoi(argv[0]+8);
		++argv; --argc; /* skip timeout */
	}
	
	if (argc==0) goto errmsg;
	hostname=argv[0];
	++argv; --argc; /* skip hostname */

	if (argc==0) goto errmsg;
	port = atoi(argv[0]);
	++argv; --argc; /* skip port */

	if (argc==0) goto errmsg;
	nbddev = argv[0];
	nbd = open(nbddev, O_RDWR);
	if (nbd < 0)
	  err("Cannot open NBD: %m\nPlease ensure the 'nbd' module is loaded.");
	++argv; --argc; /* skip device */

	if (argc>3) goto errmsg;
	if (argc) {
		if(strncmp(argv[0], "-swap", 5)==0) {
			swap=1;
			++argv;--argc;
		}
	}
	if (argc) {
		if(strncmp(argv[0], "-persist", 8)==0) {
			cont=1;
			++argv;--argc;
		}
	}
	if (argc) {
		if(strncmp(argv[0], "-sdp", 4)==0) {
			sdp=1;
			++argv;--argc;
		}
	}
	if (argc) {
		if(strncmp(argv[0], "-nofork", 7)==0) {
			nofork=1;
			++argv;--argc;
		}
	}
	if(argc) goto errmsg;
	sock = opennet(hostname, port, sdp);
	argv=NULL; argc=0; /* don't use it later suddenly */

	negotiate(sock, &size64, &flags);
	setsizes(nbd, size64, blocksize, flags);
	set_timeout(nbd, timeout);
	finish_sock(sock, nbd, swap);

	/* Go daemon */
	
	daemon(0,0);
	do {
#ifndef NOFORK
		if (!nofork) {
			if (fork()) {
				while(check_conn(nbddev, 0)) {
					sleep(1);
				}
				open(nbddev, O_RDONLY);
				exit(0);
			}
		}
#endif

		if (ioctl(nbd, NBD_DO_IT) < 0) {
			fprintf(stderr, "Kernel call returned: %m");
			if(errno==EBADR) {
				/* The user probably did 'nbd-client -d' on us.
				 * quit */
				cont=0;
			} else {
				if(cont) {
					u64 new_size;
					u32 new_flags;

					fprintf(stderr, " Reconnecting\n");
					close(sock); close(nbd);
					sock = opennet(hostname, port, sdp);
					nbd = open(nbddev, O_RDWR);
					negotiate(sock, &new_size, &new_flags);
					if (size64 != new_size) {
						err("Size of the device changed. Bye");
					}
					setsizes(nbd, size64, blocksize,
								new_flags);

					set_timeout(nbd, timeout);
					finish_sock(sock,nbd,swap);
				}
			}
		} else {
			/* We're on 2.4. It's not clearly defined what exactly
			 * happened at this point. Probably best to quit, now
			 */
			fprintf(stderr, "Kernel call returned.");
			cont=0;
		}
	} while(cont);
	printf("Closing: que, ");
	ioctl(nbd, NBD_CLEAR_QUE);
	printf("sock, ");
	ioctl(nbd, NBD_CLEAR_SOCK);
	printf("done\n");
	return 0;
}
