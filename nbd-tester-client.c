/*
 * Test client to test the NBD server. Doesn't do anything useful, except
 * checking that the server does, actually, work.
 *
 * Note that the only 'real' test is to check the client against a kernel. If
 * it works here but does not work in the kernel, then that's most likely a bug
 * in this program and/or in nbd-server.
 *
 * Copyright(c) 2006  Wouter Verhelst
 *
 * This program is Free Software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation, in version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>
#include "config.h"
#include "lfs.h"
#define MY_NAME "nbd-tester-client"
#include "cliserv.h"

#include <netinet/in.h>
#include <glib.h>

static gchar errstr[1024];
const static int errstr_len=1024;

typedef enum {
	CONNECTION_TYPE_NONE,
	CONNECTION_TYPE_CONNECT,
	CONNECTION_TYPE_INIT_PASSWD,
	CONNECTION_TYPE_CLISERV,
	CONNECTION_TYPE_FULL,
} CONNECTION_TYPE;

typedef enum {
	CONNECTION_CLOSE_PROPERLY,
	CONNECTION_CLOSE_FAST,
} CLOSE_TYPE;

inline int read_all(int f, void *buf, size_t len) {
	ssize_t res;
	size_t retval=0;

	while(len>0) {
		if((res=read(f, buf, len)) <=0) {
			snprintf(errstr, errstr_len, "Read failed: %s", strerror(errno));
			return -1;
		}
		len-=res;
		buf+=res;
		retval+=res;
	}
	return retval;
}

int setup_connection(gchar *hostname, int port, CONNECTION_TYPE ctype) {
	int sock;
	struct hostent *host;
	struct sockaddr_in addr;
	char buf[256];
	u64 tmp64;

	sock=0;
	if(ctype<CONNECTION_TYPE_CONNECT)
		goto end;
	if((sock=socket(PF_INET, SOCK_STREAM, IPPROTO_TCP))<0) {
		strncpy(errstr, strerror(errno), errstr_len);
		goto err;
	}
	setmysockopt(sock);
	if(!(host=gethostbyname(hostname))) {
		strncpy(errstr, strerror(errno), errstr_len);
		goto err_open;
	}
	addr.sin_family=AF_INET;
	addr.sin_port=htons(port);
	addr.sin_addr.s_addr=*((int *) host->h_addr);
	if((connect(sock, (struct sockaddr *)&addr, sizeof(addr))<0)) {
		strncpy(errstr, strerror(errno), errstr_len);
		goto err_open;
	}
	if(ctype<CONNECTION_TYPE_INIT_PASSWD)
		goto end;
	if(read_all(sock, buf, strlen(INIT_PASSWD))<0) {
		snprintf(errstr, errstr_len, "Could not read INIT_PASSWD: %s",
				strerror(errno));
		goto err_open;
	}
	if(strlen(buf)==0) {
		snprintf(errstr, errstr_len, "Server closed connection");
		goto err_open;
	}
	if(strncmp(buf, INIT_PASSWD, strlen(INIT_PASSWD))) {
		snprintf(errstr, errstr_len, "INIT_PASSWD does not match");
		goto err_open;
	}
	if(ctype<CONNECTION_TYPE_CLISERV)
		goto end;
	if(read_all(sock, &tmp64, sizeof(tmp64))<0) {
		snprintf(errstr, errstr_len, "Could not read cliserv_magic: %s",
				strerror(errno));
		goto err_open;
	}
	tmp64=ntohll(tmp64);
	if(tmp64 != cliserv_magic) {
		strncpy(errstr, "cliserv_magic does not match", errstr_len);
		goto err_open;
	}
	if(ctype<CONNECTION_TYPE_FULL)
		goto end;
	/* The information we get now contains information on sizes. If
	 * we're here, that means we want a 'working' connection, but
	 * we're not interested in the sizes. So, read them but throw
	 * the values away. We need to read the size of the device (a
	 * 64bit integer) plus the reserved fields (128 bytes; should
	 * all be zeroes).
	 */
	read_all(sock, buf, sizeof(tmp64)+128);
	goto end;
err_open:
	close(sock);
err:
	sock=-1;
end:
	return sock;
}

int close_connection(int sock, CLOSE_TYPE type) {
	struct nbd_request req;
	u64 counter=0;

	switch(type) {
		case CONNECTION_CLOSE_PROPERLY:
			req.magic=htonl(NBD_REQUEST_MAGIC);
			req.type=htonl(NBD_CMD_DISC);
			memcpy(&(req.handle), &(counter), sizeof(counter));
			counter++;
			req.from=0;
			req.len=0;
			if(write(sock, &req, sizeof(req))<0) {
				snprintf(errstr, errstr_len, "Could not write to socket: %s", strerror(errno));
				return -1;
			}
		case CONNECTION_CLOSE_FAST:
			if(close(sock)<0) {
				snprintf(errstr, errstr_len, "Could not close socket: %s", strerror(errno));
				return -1;
			}
			break;
		default:
			g_critical("Your compiler is on crack!"); /* or I am buggy */
			return -1;
	}
	return 0;
}

int read_packet_check_header(int sock, size_t datasize, long long int curhandle) {
	struct nbd_reply rep;
	int retval=0;
	char buf[datasize];

	read_all(sock, &rep, sizeof(rep));
	rep.magic=ntohl(rep.magic);
	rep.error=ntohl(rep.error);
	if(rep.magic!=NBD_REPLY_MAGIC) {
		snprintf(errstr, errstr_len, "Received package with incorrect reply_magic. Index of sent packages is %lld (0x%llX), received handle is %lld (0x%llX). Received magic 0x%lX, expected 0x%lX", curhandle, curhandle, *((u64*)rep.handle), *((u64*)rep.handle), (long unsigned int)rep.magic, (long unsigned int)NBD_REPLY_MAGIC);
		retval=-1;
		goto end;
	}
	if(rep.error) {
		snprintf(errstr, errstr_len, "Received error from server: %ld (0x%lX). Handle is %lld (0x%llX).", (long int)rep.error, (long unsigned int)rep.error, (long long int)(*((u64*)rep.handle)), *((u64*)rep.handle));
		retval=-1;
		goto end;
	}
	read_all(sock, &buf, datasize);

end:
	return retval;
}

int throughput_test(gchar* hostname, int port, int sock, char sock_is_open, char close_sock) {
	long long int i;
	char buf[1024];
	struct nbd_request req;
	u64 size;
	int requests=0;
	fd_set set;
	struct timeval tv;
	struct timeval start;
	struct timeval stop;
	float timespan;
	int speed;
	char speedchar[2] = { '\0', '\0' };
	int retval=0;
	size_t tmp;
	signed int do_write=TRUE;

	size=0;
	if(!sock_is_open) {
		if((sock=setup_connection(hostname, port, CONNECTION_TYPE_CLISERV))<0) {
			g_warning("Could not open socket: %s", errstr);
			retval=-1;
			goto err;
		}
	} else {
		/* Assume the file is at least 4k in size. Not much of a test
		 * this way, but, well. */
		size=4096;
	}
	if((tmp=read_all(sock, &size, sizeof(u64)))<0) {
		retval=-1;
		snprintf(errstr, errstr_len, "Could not read from socket: %s", strerror(errno));
		goto err_open;
	}
	if(tmp==0) {
		retval=-1;
		snprintf(errstr, errstr_len, "Server closed connection unexpectedly when trying to read size of device in throughput test");
		goto err;
	}
	read_all(sock,&buf,128);
	size=ntohll(size);
	req.magic=htonl(NBD_REQUEST_MAGIC);
	req.type=htonl(NBD_CMD_READ);
	req.len=htonl(1024);
	if(gettimeofday(&start, NULL)<0) {
		retval=-1;
		snprintf(errstr, errstr_len, "Could not measure start time: %s", strerror(errno));
		goto err_open;
	}
	for(i=0;i+1024<=size;i+=1024) {
		if(do_write) {
			memcpy(&(req.handle),&i,sizeof(i));
			req.from=htonll(i);
			write(sock, &req, sizeof(req));
			printf("Requests(+): %d\n", ++requests);
		}
		do {
			FD_ZERO(&set);
			FD_SET(sock, &set);
			tv.tv_sec=0;
			tv.tv_usec=0;
			select(sock+1, &set, NULL, NULL, &tv);
			if(FD_ISSET(sock, &set)) {
				/* Okay, there's something ready for
				 * reading here */
				if(read_packet_check_header(sock, 1024, i)<0) {
					retval=-1;
					goto err_open;
				}
				printf("Requests(-): %d\n", --requests);
			}
		} while FD_ISSET(sock, &set);
		/* Now wait until we can write again or until a second have
		 * passed, whichever comes first*/
		FD_ZERO(&set);
		FD_SET(sock, &set);
		tv.tv_sec=1;
		tv.tv_usec=0;
		do_write=select(sock+1,NULL,&set,NULL,&tv);
		if(!do_write) printf("Select finished\n");
		if(do_write<0) {
			snprintf(errstr, errstr_len, "select: %s", strerror(errno));
			retval=-1;
			goto err_open;
		}
	}
	/* Now empty the read buffer */
	do {
		FD_ZERO(&set);
		FD_SET(sock, &set);
		tv.tv_sec=0;
		tv.tv_usec=0;
		select(sock+1, &set, NULL, NULL, &tv);
		if(FD_ISSET(sock, &set)) {
			/* Okay, there's something ready for
			 * reading here */
			read_packet_check_header(sock, 1024, i);
			printf("Requests(-): %d\n", --requests);
		}
	} while (requests);
	if(gettimeofday(&stop, NULL)<0) {
		retval=-1;
		snprintf(errstr, errstr_len, "Could not measure end time: %s", strerror(errno));
		goto err_open;
	}
	timespan=stop.tv_sec-start.tv_sec+(stop.tv_usec-start.tv_usec)/1000000;
	speed=(int)(size/timespan);
	if(speed>1024) {
		speed>>=10;
		speedchar[0]='K';
	}
	if(speed>1024) {
		speed>>=10;
		speedchar[0]='M';
	}
	if(speed>1024) {
		speed>>=10;
		speedchar[0]='G';
	}
	g_message("Throughput test complete. Took %.3f seconds to complete, %d%sB/s",timespan,speed,speedchar);

err_open:
	if(close_sock) {
		close_connection(sock, CONNECTION_CLOSE_PROPERLY);
	}
err:
	return retval;
}

int main(int argc, char**argv) {
	gchar *hostname;
	long int p;
	int port;
	int sock=0;

	if(argc<3) {
		g_message("Not enough arguments");
		g_message("Usage: %s <hostname> <port>", argv[0]);
		exit(EXIT_FAILURE);
	}
	logging();
	hostname=g_strdup(argv[1]);
	p=(strtol(argv[2], NULL, 0));
	if(p==LONG_MIN||p==LONG_MAX) {
		g_critical("Could not parse port number: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	port=(int)p;

	if(throughput_test(hostname, port, sock, FALSE, TRUE)<0) {
		g_warning("Could not run throughput test: %s", errstr);
		exit(EXIT_FAILURE);
	}

	return 0;
}
