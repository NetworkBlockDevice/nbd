/*
 * Open connection for network block device
 *
 * Copyright 1997,1998 Pavel Machek, distribute under GPL
 *  <pavel@atrey.karlin.mff.cuni.cz>
 * Copyright (c) 2002 - 2011 Wouter Verhelst <w@uter.be>
 *
 * Version 1.0 - 64bit issues should be fixed, now
 * Version 1.1 - added bs (blocksize) option (Alexey Guzeev, aga@permonline.ru)
 * Version 1.2 - I added new option '-d' to send the disconnect request
 * Version 2.0 - Version synchronised with server
 * Version 2.1 - Check for disconnection before INIT_PASSWD is received
 * 	to make errormsg a bit more helpful in case the server can't
 * 	open the exported file.
 * 16/03/2010 - Add IPv6 support.
 * 	Kitt Tientanopajai <kitt@kitty.in.th>
 *	Neutron Soutmun <neo.neutron@gmail.com>
 *	Suriya Soutmun <darksolar@gmail.com>
 */

#include "config.h"
#include "lfs.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>

#include <linux/ioctl.h>
#define MY_NAME "nbd_client"
#include "cliserv.h"

#ifdef WITH_SDP
#include <sdp_inet.h>
#endif

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

int opennet(char *name, char* portstr, int sdp) {
	int sock;
	struct addrinfo hints;
	struct addrinfo *ai = NULL;
	struct addrinfo *rp = NULL;
	int e;

	memset(&hints,'\0',sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
	hints.ai_protocol = IPPROTO_TCP;

	e = getaddrinfo(name, portstr, &hints, &ai);

	if(e != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(e));
		freeaddrinfo(ai);
		exit(EXIT_FAILURE);
	}

	if(sdp) {
#ifdef WITH_SDP
		if (ai->ai_family == AF_INET)
			ai->ai_family = AF_INET_SDP;
		else (ai->ai_family == AF_INET6)
			ai->ai_family = AF_INET6_SDP;
#else
		err("Can't do SDP: I was not compiled with SDP support!");
#endif
	}

	for(rp = ai; rp != NULL; rp = rp->ai_next) {
		sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if(sock == -1)
			continue;	/* error */

		if(connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
			break;		/* success */
	}

	if (rp == NULL)
		err("Socket failed: %m");

	setmysockopt(sock);

	freeaddrinfo(ai);
	return sock;
}

void negotiate(int sock, u64 *rsize64, u32 *flags, char* name) {
	u64 magic, size64;
	uint16_t tmp;
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
	if(name) {
		uint32_t opt;
		uint32_t namesize;
		uint32_t reserved = 0;

		if (magic != opts_magic)
			err("Not enough opts_magic");
		printf(".");
		if(read(sock, &tmp, sizeof(uint16_t)) < 0) {
			err("Failed reading flags: %m");
		}
		*flags = ((u32)ntohs(tmp));

		/* reserved for future use*/
		if (write(sock, &reserved, sizeof(reserved)) < 0)
			err("Failed/2.1: %m");

		/* Write the export name that we're after */
		magic = ntohll(opts_magic);
		if (write(sock, &magic, sizeof(magic)) < 0)
			err("Failed/2.2: %m");
		opt = ntohl(NBD_OPT_EXPORT_NAME);
		if (write(sock, &opt, sizeof(opt)) < 0)
			err("Failed/2.3: %m");
		namesize = (u32)strlen(name);
		namesize = ntohl(namesize);
		if (write(sock, &namesize, sizeof(namesize)) < 0)
			err("Failed/2.4: %m");
		if (write(sock, name, strlen(name)) < 0)
			err("Failed/2.4: %m");
	} else {
		if (magic != cliserv_magic)
			err("Not enough cliserv_magic");
		printf(".");
	}

	if (read(sock, &size64, sizeof(size64)) < 0)
		err("Failed/3: %m\n");
	size64 = ntohll(size64);

#ifdef NBD_SET_SIZE_BLOCKS
	if ((size64>>12) > (uint64_t)~0UL) {
		printf("size = %luMB", (unsigned long)(size64>>20));
		err("Exported device is too big for me. Get 64-bit machine :-(\n");
	} else
		printf("size = %luMB", (unsigned long)(size64>>20));
#else
	if (size64 > (~0UL >> 1)) {
		printf("size = %luKB", (unsigned long)(size64>>10));
		err("Exported device is too big. Get 64-bit machine or newer kernel :-(\n");
	} else
		printf("size = %lu", (unsigned long)(size64));
#endif

	if(!name) {
		if (read(sock, flags, sizeof(*flags)) < 0)
			err("Failed/4: %m\n");
		*flags = ntohl(*flags);
	} else {
		if(read(sock, &tmp, sizeof(tmp)) < 0)
			err("Failed/4: %m\n");
		*flags |= (uint32_t)ntohs(tmp);
	}

	if (read(sock, &buf, 124) < 0)
		err("Failed/5: %m\n");
	printf("\n");

	*rsize64 = size64;
}

void setsizes(int nbd, u64 size64, int blocksize, u32 flags) {
	unsigned long size;
	int read_only = (flags & NBD_FLAG_READ_ONLY) ? 1 : 0;

#ifdef NBD_SET_SIZE_BLOCKS
	if (size64>>12 > (uint64_t)~0UL)
		err("Device too large.\n");
	else {
		if (ioctl(nbd, NBD_SET_BLKSIZE, 4096UL) < 0)
			err("Ioctl/1.1a failed: %m\n");
		size = (unsigned long)(size64>>12);
		if (ioctl(nbd, NBD_SET_SIZE_BLOCKS, size) < 0)
			err("Ioctl/1.1b failed: %m\n");
		if (ioctl(nbd, NBD_SET_BLKSIZE, (unsigned long)blocksize) < 0)
			err("Ioctl/1.1c failed: %m\n");
		fprintf(stderr, "bs=%d, sz=%llu bytes\n", blocksize, 4096ULL*size);
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

	/* ignore error as kernel may not support */
	ioctl(nbd, NBD_SET_FLAGS, (unsigned long) flags);

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

void usage(char* errmsg, ...) {
	if(errmsg) {
		char tmp[256];
		va_list ap;
		va_start(ap, errmsg);
		snprintf(tmp, 256, "ERROR: %s\n\n", errmsg);
		vfprintf(stderr, errmsg, ap);
		va_end(ap);
	} else {
		fprintf(stderr, "nbd-client version %s\n", PACKAGE_VERSION);
	}
	fprintf(stderr, "Usage: nbd-client host port nbd_device [-block-size|-b block size] [-timeout|-t timeout] [-swap|-s] [-sdp|-S] [-persist|-p] [-nofork|-n]\n");
	fprintf(stderr, "Or   : nbd-client -name|-N name host [port] nbd_device [-block-size|-b block size] [-timeout|-t timeout] [-swap|-s] [-sdp|-S] [-persist|-p] [-nofork|-n]\n");
	fprintf(stderr, "Or   : nbd-client -d nbd_device\n");
	fprintf(stderr, "Or   : nbd-client -c nbd_device\n");
	fprintf(stderr, "Or   : nbd-client -h|--help\n");
	fprintf(stderr, "Default value for blocksize is 1024 (recommended for ethernet)\n");
	fprintf(stderr, "Allowed values for blocksize are 512,1024,2048,4096\n"); /* will be checked in kernel :) */
	fprintf(stderr, "Note, that kernel 2.4.2 and older ones do not work correctly with\n");
	fprintf(stderr, "blocksizes other than 1024 without patches\n");
	fprintf(stderr, "Default value for port with -N is 10809. Note that port must always be numeric\n");
}

void disconnect(char* device) {
	int nbd = open(device, O_RDWR);

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
}

int main(int argc, char *argv[]) {
	char* port=NULL;
	int sock, nbd;
	int blocksize=1024;
	char *hostname=NULL;
	char *nbddev=NULL;
	int swap=0;
	int cont=0;
	int timeout=0;
	int sdp=0;
	int G_GNUC_UNUSED nofork=0; // if -dNOFORK
	u64 size64;
	u32 flags;
	int c;
	int nonspecial=0;
	char* name=NULL;
	struct option long_options[] = {
		{ "block-size", required_argument, NULL, 'b' },
		{ "check", required_argument, NULL, 'c' },
		{ "disconnect", required_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "name", required_argument, NULL, 'N' },
		{ "nofork", no_argument, NULL, 'n' },
		{ "persist", no_argument, NULL, 'p' },
		{ "sdp", no_argument, NULL, 'S' },
		{ "swap", no_argument, NULL, 's' },
		{ "timeout", required_argument, NULL, 't' },
		{ 0, 0, 0, 0 }, 
	};

	logging();

	while((c=getopt_long_only(argc, argv, "-b:c:d:hnN:pSst:", long_options, NULL))>=0) {
		switch(c) {
		case 1:
			// non-option argument
			if(strchr(optarg, '=')) {
				// old-style 'bs=' or 'timeout='
				// argument
				fprintf(stderr, "WARNING: old-style command-line argument encountered. This is deprecated.\n");
				if(!strncmp(optarg, "bs=", 3)) {
					optarg+=3;
					goto blocksize;
				}
				if(!strncmp(optarg, "timeout=", 8)) {
					optarg+=8;
					goto timeout;
				}
				usage("unknown option %s encountered", optarg);
				exit(EXIT_FAILURE);
			}
			switch(nonspecial++) {
				case 0:
					// host
					hostname=optarg;
					break;
				case 1:
					// port
					if(!strtol(optarg, NULL, 0)) {
						// not parseable as a number, assume it's the device and we have a name
						nbddev = optarg;
						nonspecial++;
					} else {
						port = optarg;
					}
					break;
				case 2:
					// device
					nbddev = optarg;
					break;
				default:
					usage("too many non-option arguments specified");
					exit(EXIT_FAILURE);
			}
			break;
		case 'b':
		      blocksize:
			blocksize=(int)strtol(optarg, NULL, 0);
			break;
		case 'c':
			return check_conn(optarg, 1);
		case 'd':
			disconnect(optarg);
			exit(EXIT_SUCCESS);
		case 'h':
			usage(NULL);
			exit(EXIT_SUCCESS);
		case 'n':
			nofork=1;
			break;
		case 'N':
			name=optarg;
			if(!port) {
				port = NBD_DEFAULT_PORT;
			}
			break;
		case 'p':
			cont=1;
			break;
		case 's':
			swap=1;
			break;
		case 'S':
			sdp=1;
			break;
		case 't':
		      timeout:
			timeout=strtol(optarg, NULL, 0);
			break;
		default:
			fprintf(stderr, "E: option eaten by 42 mice\n");
			exit(EXIT_FAILURE);
		}
	}

	if((!port && !name) || !hostname || !nbddev) {
		usage("not enough information specified");
		exit(EXIT_FAILURE);
	}

	nbd = open(nbddev, O_RDWR);
	if (nbd < 0)
	  err("Cannot open NBD: %m\nPlease ensure the 'nbd' module is loaded.");

	sock = opennet(hostname, port, sdp);

	negotiate(sock, &size64, &flags, name);
	setsizes(nbd, size64, blocksize, flags);
	set_timeout(nbd, timeout);
	finish_sock(sock, nbd, swap);

	/* Go daemon */
	
#ifndef NOFORK
	if(!nofork) {
		if (daemon(0,0) < 0)
			err("Cannot detach from terminal");
	}
#endif
	do {
#ifndef NOFORK
		if (!fork()) {
			/* Due to a race, the kernel NBD driver cannot
			 * call for a reread of the partition table
			 * in the handling of the NBD_DO_IT ioctl().
			 * Therefore, this is done in the first open()
			 * of the device. We therefore make sure that
			 * the device is opened at least once after the
			 * connection was made. This has to be done in a
			 * separate process, since the NBD_DO_IT ioctl()
			 * does not return until the NBD device has
			 * disconnected.
			 */
			while(check_conn(nbddev, 0)) {
				sleep(1);
			}
			open(nbddev, O_RDONLY);
			exit(0);
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
					negotiate(sock, &new_size, &new_flags, name);
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
