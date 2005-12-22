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
 *     to make errormsg a bit more helpful in case the server can't
 *     open the exported file.
 * Version 2.2 - Be more of a daemon. -- Roy Keene <nbd@rkeene.org>
 */


#include "config.h"
#include "lfs.h"

#include <asm/page.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/in.h>         /* sockaddr_in, htons, in_addr */
#include <netdb.h>              /* hostent, gethostby*, getservby* */
#include <stdio.h>
#include <fcntl.h>
#include <syslog.h>
#include <stdlib.h>
#include <linux/ioctl.h>
#define MY_NAME "nbd_client"
#include "cliserv.h"

void print_help(void) {
	fprintf(stderr, "nbd-client version %s\n", PACKAGE_VERSION);
	fprintf(stderr, "Usage:  nbd-client <host> <port> <nbd_device>\n");
	fprintf(stderr, "        nbd-client -d <nbd_device>\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  host        Host to connect to.\n");
	fprintf(stderr, "  port        Port to connect to nbd server on.\n");
	fprintf(stderr, "  nbd_device  Device to connect NBD server specified to.\n");
	return;
}

/*
 * SYNOPSIS:
 *   void daeomize(void);
 *
 * NOTES:
 *   This function accomplishes everything needed to become a daemon.
 *   It returns nothing, on failure the program must abort.
 *
 */
void daemonize(void) {
	pid_t pid;

	chdir("/");

	setsid();

	pid = fork();

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}
	if (pid < 0) {
		err_noexit("fork() failed.");
		exit(EXIT_FAILURE);
	}

	return;
}

int opennet(const char *name, int port) {
	int sock;
	struct sockaddr_in xaddrin;
	int xaddrinlen = sizeof(xaddrin);
	struct hostent *hostn = NULL;

	hostn = gethostbyname(name);
	if (!hostn) {
		err_noexit("gethostname() failed: %h\n");
		return(-1);
	}

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		err_noexit("socket() failed: %m");
		return(-1);
	}

	xaddrin.sin_family = AF_INET;
	xaddrin.sin_port = htons(port);
	xaddrin.sin_addr.s_addr = *((int *) hostn->h_addr);
	if ((connect(sock, (struct sockaddr *) &xaddrin, xaddrinlen) < 0)) {
		err_noexit("Connect: %m");
		close(sock);
		return(-1);
	}

	setmysockopt(sock);

	return(sock);
}

int nbd_disable(const char *nbddev) {
	int nbd_fd;
	int retval = EXIT_SUCCESS;

	nbd_fd = open(nbddev, O_RDWR);
	if (nbd_fd < 0) {
		fprintf(stderr, "Can not open NBD: %s\n", strerror(errno));
		return(EXIT_FAILURE);
	}

	printf("Disconnecting: ");
	if (ioctl(nbd_fd, NBD_CLEAR_QUE) < 0) {
		printf("queue [FAILED], ");
		retval = EXIT_FAILURE;
	} else {
		printf("queue, ");
	}

#ifdef NBD_DISCONNECT
	if (ioctl(nbd_fd, NBD_DISCONNECT) < 0) {
		printf("disconnect [FAILED], ");
		retval = EXIT_FAILURE;
	} else {
		printf("disconnect, ");
	}
#endif

	if (ioctl(nbd_fd, NBD_CLEAR_SOCK) < 0) {
		printf("clear [FAILED], ");
		retval = EXIT_FAILURE;
	} else {
		printf("clear, ");
	}

	printf("done.\n");

	close(nbd_fd);

	return(retval);
}

int nbd_enable(const char *host, int port, const char *nbddev, unsigned long blocksize) {
	uint64_t magic, size64;
	unsigned long size;
	ssize_t read_ret;
	char buf[256] = {0};
	int nbd_fd, sock_fd;
	int ioctl_ret;

	nbd_fd = open(nbddev, O_RDWR);
	if (nbd_fd < 0) {
		err_noexit("Could not open NBD: %m");
		return(EXIT_FAILURE);
	}

	sock_fd = opennet(host, port);
	if (sock_fd < 0) {
		/* opennet() returns its own error messages. */
		close(nbd_fd);
		return(EXIT_FAILURE);
	}

	read_ret = read(sock_fd, buf, 8);
	if (read_ret != 8) {
		close(sock_fd);
		close(nbd_fd);
		if (read_ret < 0) {
			err_noexit("Error reading initial password, aborting: %m");
		} else {
			err_noexit("Error reading initial password, aborting.");
		}
		return(EXIT_FAILURE);
	}

	if (strcmp(buf, INIT_PASSWD) != 0) {
		close(sock_fd);
		close(nbd_fd);
		err_noexit("Bad initial password, aborting.");
		return(EXIT_FAILURE);
	}

	read_ret = read(sock_fd, &magic, sizeof(magic));
	if (read_ret != sizeof(magic)) {
		close(sock_fd);
		close(nbd_fd);
		if (read_ret < 0) {
			err_noexit("Error reading magic, aborting: %m");
		} else {
			err_noexit("Error reading magic, aborting.");
		}
		return(EXIT_FAILURE);
	}

	magic = ntohll(magic);

	if (magic != cliserv_magic) {
		close(sock_fd);
		close(nbd_fd);
		err_noexit("Bad magic, aborting.");
		return(EXIT_FAILURE);
	}

	read_ret = read(sock_fd, &size64, sizeof(size64));
	if (read_ret != sizeof(size64)) {
		close(sock_fd);
		close(nbd_fd);
		if (read_ret < 0) {
			err_noexit("Invalid size, aborting: %m");
		} else {
			err_noexit("Invalid size, aborting.");
		}
		return(EXIT_FAILURE);
	}

	size64 = ntohll(size64);

#ifdef NBD_SET_SIZE_BLOCKS
	if ((size64>>10) > (~0UL >> 1)) {
//		printf("size = %luMB\n", (unsigned long)(size64>>20));

		close(sock_fd);
		close(nbd_fd);

		err_noexit("Exported device is too big for me. Get 64-bit machine :-(");

		return(EXIT_FAILURE);
	} else {
//		printf("size = %luKB\n", (unsigned long)(size64>>10));
	}
#else
	if (size64 > (~0UL >> 1)) {
//		printf("size = %luKB\n", (unsigned long)(size64>>10));

		close(sock_fd);
		close(nbd_fd);

		err_noexit("Exported device is too big. Get 64-bit machine or newer kernel :-(");

		return(EXIT_FAILURE);
	} else {
//		printf("size = %lu\n", (unsigned long)(size64));
	}
#endif

	read_ret = read(sock_fd, buf, 128);
	if (read_ret != 128) {
		close(sock_fd);
		close(nbd_fd);
		if (read_ret < 0) {
			err_noexit("Error reading data, aborting: %m");
		} else {
			err_noexit("Error reading data, aborting.");
		}
		return(EXIT_FAILURE);
	}

#ifdef NBD_SET_SIZE_BLOCKS
	if ((size64 / blocksize) > (~0UL >> 1)) {
		close(sock_fd);
		close(nbd_fd);

		err_noexit("Device too large.\n");

		return(EXIT_FAILURE);
	} else {
		if (ioctl(nbd_fd, NBD_SET_BLKSIZE, blocksize) < 0) {
			close(sock_fd);
			close(nbd_fd);

			err_noexit("Ioctl/1.1a failed: %m");

			return(EXIT_FAILURE);
		}
		size = size64 / blocksize;

		ioctl_ret = ioctl(nbd_fd, NBD_SET_SIZE_BLOCKS, size);
		if (ioctl_ret < 0) {
			close(sock_fd);
			close(nbd_fd);

			err_noexit("Ioctl/1.1b failed: %m");

			return(EXIT_FAILURE);
		}
//		printf("bs=%lu, sz=%lu\n", blocksize, size);
	}
#else
	if (size64 > (~0UL >> 1)) {
		close(sock_fd);
		close(nbd_fd);

		err_noexit("Device too large.\n");

		return(EXIT_FAILURE);
	} else {
		size = size64;

		if (ioctl(nbd_fd, NBD_SET_SIZE, size) < 0) {
			close(sock_fd);
			close(nbd_fd);

			err_noexit("Ioctl/1 failed: %m\n");

			return(EXIT_FAILURE);
		}
	}
#endif

	ioctl_ret = ioctl(nbd_fd, NBD_CLEAR_SOCK);
	if (ioctl_ret < 0) {
		close(sock_fd);
		close(nbd_fd);

		err_noexit("ioctl(nbd_fd, NBD_CLEAR_SOCK) failed, aborting: %m");

		return(EXIT_FAILURE);
	}

	ioctl_ret = ioctl(nbd_fd, NBD_SET_SOCK, sock_fd);
	if (ioctl_ret < 0) {
		close(sock_fd);
		close(nbd_fd);

		err_noexit("ioctl(nbd_fd, NBD_SET_SOCK, sock_fd) failed, aborting: %m");

		return(EXIT_FAILURE);
	}

	/* This ioctl() call only returns when the connection is terminated by the other end closing the socket. */
	ioctl_ret = ioctl(nbd_fd, NBD_DO_IT);
	if (ioctl_ret < 0) {
		err_noexit("Connection terminated: %m");
	} else {
		err_noexit("Connection terminated.");
	}

	ioctl(nbd_fd, NBD_CLEAR_QUE);
#ifdef NBD_DISCONNECT
	ioctl(nbd_fd, NBD_DISCONNECT);
#endif
	ioctl(nbd_fd, NBD_CLEAR_SOCK);

	close(sock_fd);
	close(nbd_fd);

	return(EXIT_FAILURE);
}

int main(int argc, char **argv) {
	uint16_t port = 2000;
	uint32_t bs = 1024;
	char *host, *nbddev, *bs_str;

	if (argc < 3) {
		print_help();
		return(EXIT_FAILURE);
	}

	if (strcmp(argv[1], "-d") == 0) {
		nbddev = argv[2];
		return(nbd_disable(nbddev));
	}

	if (argc < 4) {
		print_help();
		return(EXIT_FAILURE);
	}

	host = argv[1];
	port = atoi(argv[2]);
	nbddev = argv[3];

	logging();

	daemonize();

	while (1) {
		nbd_enable(host, port, nbddev, bs);
		sleep(30);
	}

	return(EXIT_FAILURE);
}
