/*
 * Open connection for network block device
 *
 * Copyright 1997,1998 Pavel Machek, distribute under GPL
 *  <pavel@atrey.karlin.mff.cuni.cz>
 *
 * Version 1.0 - 64bit issues should be fixed, now
 */

/* I added new option '-d' to send the disconnect request */

#include <asm/page.h>
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

#define MY_NAME "nbd_client"
#ifndef __GNUC__
#error I need GCC to work
#endif

#include <linux/ioctl.h>
#include "cliserv.h"

int opennet(char *name, int port)
{
	int sock;
	struct sockaddr_in xaddrin;
	int xaddrinlen = sizeof(xaddrin);
	struct hostent *hostn;

	hostn = gethostbyname(name);
	if (!hostn)
		err("Gethostname failed: %h\n");

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		err("Socket failed: %m");

	xaddrin.sin_family = AF_INET;
	xaddrin.sin_port = htons(port);
	xaddrin.sin_addr.s_addr = *((int *) hostn->h_addr);
	if ((connect(sock, (struct sockaddr *) &xaddrin, xaddrinlen) < 0))
		err("Connect: %m");

	setmysockopt(sock);
	return sock;
}

int main(int argc, char *argv[])
{
	int port, sock, nbd, one = 1;
	u64 magic, size64;
	unsigned long size;
	char buf[256] = "\0\0\0\0\0\0\0\0\0";
	int swap = (argc > 4);

	logging();

	if (argc < 2) {
	errmsg:
		fprintf(stderr, "Usage: host port nbd_device -swap\n");
		fprintf(stderr, "or     -d nbd_device \n");
		return 1;
	}

	if (strcmp(argv[1],"-d")==0) {
	  nbd = open(argv[2], O_RDWR);
	  if (nbd < 0)
		err("Can not open NBD: %m");
	  printf("Disconnecting: que, ");
	  if (ioctl(nbd, NBD_CLEAR_QUE)< 0)
		err("Ioctl failed: %m\n");
	  printf("disconnect, ");
#ifdef NBD_DISCONNECT
	  if (ioctl(nbd, NBD_DISCONNECT)<0)
		err("Ioctl failed: %m\n");
	  printf("sock, ");
#else
	  die("Can't disconnect: I was not compiled with disconnect support!\n" );
#endif
	  if (ioctl(nbd, NBD_CLEAR_SOCK)<0)
		err("Ioctl failed: %m\n");
	  printf("done\n");
	  return 0;
	}
	
	if (argc<4) goto errmsg;
	port = atoi(argv[2]);
	sock = opennet(argv[1], port);
	nbd = open(argv[3], O_RDWR);
	if (nbd < 0)
	  err("Can not open NBD: %m");

	printf("Negotiation: ");
	if (read(sock, buf, 8) < 0)
		err("Failed/1: %m");
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
	if (size64 > (~0UL >> 1)) {
#ifdef NBD_SET_SIZE_BLOCKS
		if ((size64 >> 10) > (~0UL >> 1)) {
			printf("size = %luMB", (unsigned long)(size64>>20));
			err("Exported device is too big for me. Get 64-bit machine :-(\n");
		} else
			printf("size = %luKB", (unsigned long)(size64>>10));
#else
		printf("size = %luKB", (unsigned long)(size64>>10));
		err("Exported device is too big. Get 64-bit machine or newer kernel :-(\n");
#endif
	} else
		printf("size = %lu", (unsigned long)(size64));

	if (read(sock, &buf, 128) < 0)
		err("Failed/4: %m\n");
	printf("\n");

	if (size64 > (~0UL >> 1)) {
#ifdef NBD_SET_SIZE_BLOCKS
		if ((size64 >> 10) > (~0UL >> 1))
		/*
		 * If you really need NBDs larger than 2TB on 32-bit
		 * machines you can use blocksizes larger than 1kB
		 * - FIXME
		 */
			err("Device too large.\n");
		else {
			int er;

			if (ioctl(nbd, NBD_SET_BLKSIZE, 1UL << 10) < 0)
				err("Ioctl/1.1a failed: %m\n");
			size = (unsigned long)(size64 >> 10);
			if ((er = ioctl(nbd, NBD_SET_SIZE_BLOCKS, size)) < 0)
				err("Ioctl/1.1b failed: %m\n");
		}
#else
		err("Device too large.\n");
#endif
	} else {
		size = (unsigned long)size64;
		if (ioctl(nbd, NBD_SET_SIZE, size) < 0)
			err("Ioctl/1 failed: %m\n");
	}
	ioctl(nbd, NBD_CLEAR_SOCK);
	if (ioctl(nbd, NBD_SET_SOCK, sock) < 0)
		err("Ioctl/2 failed: %m\n");

#ifndef SO_SWAPPING
	if (swap)
		err("You have to compile me on machine with swapping patch enabled in order to use it later.");
#else
	if (swap)
		if (setsockopt(sock, SOL_SOCKET, SO_SWAPPING, &one, sizeof(int)) < 0)
			 err("Could not enable swapping: %m");
#endif

	/* Go daemon */

	chdir("/");
	if (fork())
		exit(0);

	if (ioctl(nbd, NBD_DO_IT) < 0)
		fprintf(stderr, "Kernel call returned: %m");
	else
		fprintf(stderr, "Kernel call returned.");
	printf("Closing: que, ");
	ioctl(nbd, NBD_CLEAR_QUE);
	printf("sock, ");
	ioctl(nbd, NBD_CLEAR_SOCK);
	printf("done\n");
	return 0;
}
