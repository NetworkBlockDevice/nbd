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
#include "netdb-compat.h"
#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>

#include <linux/ioctl.h>
#define MY_NAME "nbd_client"
#include "cliserv.h"

#ifdef WITH_SDP
#include <sdp_inet.h>
#endif

#define NBDC_DO_LIST 1

int check_conn(char* devname, int do_print) {
	char buf[256];
	char* p;
	int fd;
	int len;

	if( (p=strrchr(devname, '/')) ) {
		devname=p+1;
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
		return -1;
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

	if (rp == NULL) {
		err_nonfatal("Socket failed: %m");
		return -1;
	}

	setmysockopt(sock);

	freeaddrinfo(ai);
	return sock;
}

void ask_list(int sock) {
	uint32_t opt;
	uint32_t opt_server;
	uint32_t len;
	uint32_t reptype;
	uint64_t magic;
	const int BUF_SIZE = 1024;
	char buf[BUF_SIZE];

	magic = ntohll(opts_magic);
	if (write(sock, &magic, sizeof(magic)) < 0)
		err("Failed/2.2: %m");

	/* Ask for the list */
	opt = htonl(NBD_OPT_LIST);
	if(write(sock, &opt, sizeof(opt)) < 0) {
		err("writing list option failed: %m");
	}
	/* Send the length (zero) */
	len = htonl(0);
	if(write(sock, &len, sizeof(len)) < 0) {
		err("writing length failed: %m");
	}
	/* newline, move away from the "Negotiation:" line */
	printf("\n");
	do {
		memset(buf, 0, 1024);
		if(read(sock, &magic, sizeof(magic)) < 0) {
			err("Reading magic from server: %m");
		}
		if(read(sock, &opt_server, sizeof(opt_server)) < 0) {
			err("Reading option: %m");
		}
		if(read(sock, &reptype, sizeof(reptype)) <0) {
			err("Reading reply from server: %m");
		}
		if(read(sock, &len, sizeof(len)) < 0) {
			err("Reading length from server: %m");
		}
		magic=ntohll(magic);
		len=ntohl(len);
		reptype=ntohl(reptype);
		if(magic != rep_magic) {
			err("Not enough magic from server");
		}
		if(reptype & NBD_REP_FLAG_ERROR) {
			switch(reptype) {
				case NBD_REP_ERR_POLICY:
					fprintf(stderr, "\nE: listing not allowed by server.\n");
					break;
				default:
					fprintf(stderr, "\nE: unexpected error from server.\n");
					break;
			}
			if(len) {
				if(read(sock, buf, len) < 0) {
					fprintf(stderr, "\nE: could not read error message from server\n");
				}
				fprintf(stderr, "Server said: %s\n", buf);
			}
			exit(EXIT_FAILURE);
		} else {
			if(len) {
				if(reptype != NBD_REP_SERVER) {
					err("Server sent us a reply we don't understand!");
				}
				if(read(sock, &len, sizeof(len)) < 0) {
					fprintf(stderr, "\nE: could not read export name length from server\n");
					exit(EXIT_FAILURE);
				}
				len=ntohl(len);
				if (len >= BUF_SIZE) {
					fprintf(stderr, "\nE: export name on server too long\n");
					exit(EXIT_FAILURE);
				}
				if(read(sock, buf, len) < 0) {
					fprintf(stderr, "\nE: could not read export name from server\n");
					exit(EXIT_FAILURE);
				}
				buf[len] = 0;
				printf("%s\n", buf);
			}
		}
	} while(reptype != NBD_REP_ACK);
	opt=htonl(NBD_OPT_ABORT);
	len=htonl(0);
	magic=htonll(opts_magic);
	if (write(sock, &magic, sizeof(magic)) < 0)
		err("Failed/2.2: %m");
	if (write(sock, &opt, sizeof(opt)) < 0)
		err("Failed writing abort");
	if (write(sock, &len, sizeof(len)) < 0)
		err("Failed writing length");
}

void negotiate(int sock, u64 *rsize64, u32 *flags, char* name, uint32_t needed_flags, uint32_t client_flags, uint32_t do_opts) {
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

		if (magic != opts_magic) {
			if(magic == cliserv_magic) {
				err("It looks like you're trying to connect to an oldstyle server with a named export. This won't work.");
			}
		}
		printf(".");
		if(read(sock, &tmp, sizeof(uint16_t)) < 0) {
			err("Failed reading flags: %m");
		}
		*flags = ((u32)ntohs(tmp));
		if((needed_flags & *flags) != needed_flags) {
			/* There's currently really only one reason why this
			 * check could possibly fail, but we may need to change
			 * this error message in the future... */
			fprintf(stderr, "\nE: Server does not support listing exports\n");
			exit(EXIT_FAILURE);
		}

		client_flags = htonl(client_flags);
		if (write(sock, &client_flags, sizeof(client_flags)) < 0)
			err("Failed/2.1: %m");

		if(do_opts & NBDC_DO_LIST) {
			ask_list(sock);
			exit(EXIT_SUCCESS);
		}

		/* Write the export name that we're after */
		magic = htonll(opts_magic);
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
		if (magic != cliserv_magic) {
			if(magic != opts_magic)
				err("Not enough cliserv_magic");
			else
				err("It looks like you're trying to connect to a newstyle server with the oldstyle protocol. Try the -N option.");
		}
		printf(".");
	}

	if (read(sock, &size64, sizeof(size64)) <= 0) {
		if (!errno)
			err("Server closed connection");
		err("Failed/3: %m\n");
	}
	size64 = ntohll(size64);

	if ((size64>>12) > (uint64_t)~0UL) {
		printf("size = %luMB", (unsigned long)(size64>>20));
		err("Exported device is too big for me. Get 64-bit machine :-(\n");
	} else
		printf("size = %luMB", (unsigned long)(size64>>20));

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

	ioctl(nbd, NBD_CLEAR_SOCK);

	/* ignore error as kernel may not support */
	ioctl(nbd, NBD_SET_FLAGS, (unsigned long) flags);

	if (ioctl(nbd, BLKROSET, (unsigned long) &read_only) < 0)
		err("Unable to set read-only attribute for device");
}

void set_timeout(int nbd, int timeout) {
	if (timeout) {
		if (ioctl(nbd, NBD_SET_TIMEOUT, (unsigned long)timeout) < 0)
			err("Ioctl NBD_SET_TIMEOUT failed: %m\n");
		fprintf(stderr, "timeout=%d\n", timeout);
	}
}

void finish_sock(int sock, int nbd, int swap) {
	if (ioctl(nbd, NBD_SET_SOCK, sock) < 0)
		err("Ioctl NBD_SET_SOCK failed: %m\n");

	if (swap)
		mlockall(MCL_CURRENT | MCL_FUTURE);
}

static int
oom_adjust(const char *file, const char *value)
{
	int fd, rc;
	size_t len;

	fd = open(file, O_WRONLY);
	if (fd < 0)
		return -1;
	len = strlen(value);
	rc = write(fd, value, len) != (ssize_t) len;
	close(fd);
	return rc ? -1 : 0;
}

void usage(char* errmsg, ...) {
	if(errmsg) {
		char tmp[256];
		va_list ap;
		va_start(ap, errmsg);
		snprintf(tmp, 256, "ERROR: %s\n\n", errmsg);
		vfprintf(stderr, tmp, ap);
		va_end(ap);
	} else {
		fprintf(stderr, "nbd-client version %s\n", PACKAGE_VERSION);
	}
	fprintf(stderr, "Usage: nbd-client host port nbd_device [-block-size|-b block size] [-timeout|-t timeout] [-swap|-s] [-sdp|-S] [-persist|-p] [-nofork|-n]\n");
	fprintf(stderr, "Or   : nbd-client -name|-N name host [port] nbd_device [-block-size|-b block size] [-timeout|-t timeout] [-swap|-s] [-sdp|-S] [-persist|-p] [-nofork|-n]\n");
	fprintf(stderr, "Or   : nbd-client -d nbd_device\n");
	fprintf(stderr, "Or   : nbd-client -c nbd_device\n");
	fprintf(stderr, "Or   : nbd-client -h|--help\n");
	fprintf(stderr, "Or   : nbd-client -l|--list host\n");
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
	if (ioctl(nbd, NBD_DISCONNECT)<0)
		err("Ioctl failed: %m\n");
	printf("sock, ");
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
	uint32_t needed_flags=0;
	uint32_t cflags=0;
	uint32_t opts=0;
	sigset_t block, old;
	struct option long_options[] = {
		{ "block-size", required_argument, NULL, 'b' },
		{ "check", required_argument, NULL, 'c' },
		{ "disconnect", required_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "list", no_argument, NULL, 'l' },
		{ "name", required_argument, NULL, 'N' },
		{ "nofork", no_argument, NULL, 'n' },
		{ "persist", no_argument, NULL, 'p' },
		{ "sdp", no_argument, NULL, 'S' },
		{ "swap", no_argument, NULL, 's' },
		{ "timeout", required_argument, NULL, 't' },
		{ 0, 0, 0, 0 }, 
	};

	logging();

	while((c=getopt_long_only(argc, argv, "-b:c:d:hlnN:pSst:", long_options, NULL))>=0) {
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
		case 'l':
			needed_flags |= NBD_FLAG_FIXED_NEWSTYLE;
			cflags |= NBD_FLAG_C_FIXED_NEWSTYLE;
			opts |= NBDC_DO_LIST;
			name="";
			nbddev="";
			port = NBD_DEFAULT_PORT;
			break;
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

	sock = opennet(hostname, port, sdp);
	if (sock < 0)
		exit(EXIT_FAILURE);

	negotiate(sock, &size64, &flags, name, needed_flags, cflags, opts);

	nbd = open(nbddev, O_RDWR);
	if (nbd < 0)
	  err("Cannot open NBD: %m\nPlease ensure the 'nbd' module is loaded.");

	setsizes(nbd, size64, blocksize, flags);
	set_timeout(nbd, timeout);
	finish_sock(sock, nbd, swap);
	if (swap) {
		/* try linux >= 2.6.36 interface first */
		if (oom_adjust("/proc/self/oom_score_adj", "-1000")) {
			/* fall back to linux <= 2.6.35 interface */
			oom_adjust("/proc/self/oom_adj", "-17");
		}
	}

	/* Go daemon */
	
#ifndef NOFORK
	if(!nofork) {
		if (daemon(0,0) < 0)
			err("Cannot detach from terminal");
	}
#endif
	do {
#ifndef NOFORK

		sigfillset(&block);
		sigdelset(&block, SIGKILL);
		sigdelset(&block, SIGTERM);
		sigdelset(&block, SIGPIPE);
		sigprocmask(SIG_SETMASK, &block, &old);

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
		        int error = errno;
			fprintf(stderr, "nbd,%d: Kernel call returned: %d", getpid(), error);
			if(error==EBADR) {
				/* The user probably did 'nbd-client -d' on us.
				 * quit */
				cont=0;
			} else {
				if(cont) {
					u64 new_size;
					u32 new_flags;

					close(sock); close(nbd);
					for (;;) {
						fprintf(stderr, " Reconnecting\n");
						sock = opennet(hostname, port, sdp);
						if (sock >= 0)
							break;
						sleep (1);
					}
					nbd = open(nbddev, O_RDWR);
					if (nbd < 0)
						err("Cannot open NBD: %m");
					negotiate(sock, &new_size, &new_flags, name, needed_flags, cflags, opts);
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
