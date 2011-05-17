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
#include <stdbool.h>
#include <string.h>
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

static uint64_t size;

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

#define TEST_WRITE (1<<0)
#define TEST_FLUSH (1<<1)

int timeval_subtract (struct timeval *result, struct timeval *x,
		      struct timeval *y) {
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}
	
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;
	
	return x->tv_sec < y->tv_sec;
}

double timeval_diff_to_double (struct timeval * x, struct timeval * y) {
	struct timeval r;
	timeval_subtract(&r, x, y);
	return r.tv_sec * 1.0 + r.tv_usec/1000000.0;
}

static inline int read_all(int f, void *buf, size_t len) {
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

static inline int write_all(int f, void *buf, size_t len) {
	ssize_t res;
	size_t retval=0;

	while(len>0) {
		if((res=write(f, buf, len)) <=0) {
			snprintf(errstr, errstr_len, "Write failed: %s", strerror(errno));
			return -1;
		}
		len-=res;
		buf+=res;
		retval+=res;
	}
	return retval;
}

#define READ_ALL_ERRCHK(f, buf, len, whereto, errmsg...) if((read_all(f, buf, len))<=0) { snprintf(errstr, errstr_len, ##errmsg); goto whereto; }
#define READ_ALL_ERR_RT(f, buf, len, whereto, rval, errmsg...) if((read_all(f, buf, len))<=0) { snprintf(errstr, errstr_len, ##errmsg); retval = rval; goto whereto; }

#define WRITE_ALL_ERRCHK(f, buf, len, whereto, errmsg...) if((write_all(f, buf, len))<=0) { snprintf(errstr, errstr_len, ##errmsg); goto whereto; }
#define WRITE_ALL_ERR_RT(f, buf, len, whereto, rval, errmsg...) if((write_all(f, buf, len))<=0) { snprintf(errstr, errstr_len, ##errmsg); retval = rval; goto whereto; }

int setup_connection(gchar *hostname, int port, gchar* name, CONNECTION_TYPE ctype, int* serverflags) {
	int sock;
	struct hostent *host;
	struct sockaddr_in addr;
	char buf[256];
	uint64_t mymagic = (name ? opts_magic : cliserv_magic);
	u64 tmp64;
	uint32_t tmp32 = 0;

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
	READ_ALL_ERRCHK(sock, buf, strlen(INIT_PASSWD), err_open, "Could not read INIT_PASSWD: %s", strerror(errno));
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
	READ_ALL_ERRCHK(sock, &tmp64, sizeof(tmp64), err_open, "Could not read cliserv_magic: %s", strerror(errno));
	tmp64=ntohll(tmp64);
	if(tmp64 != mymagic) {
		strncpy(errstr, "mymagic does not match", errstr_len);
		goto err_open;
	}
	if(ctype<CONNECTION_TYPE_FULL)
		goto end;
	if(!name) {
		READ_ALL_ERRCHK(sock, &size, sizeof(size), err_open, "Could not read size: %s", strerror(errno));
		size=ntohll(size);
		READ_ALL_ERRCHK(sock, buf, 128, err_open, "Could not read data: %s", strerror(errno));
		goto end;
	}
	/* flags */
	READ_ALL_ERRCHK(sock, buf, sizeof(uint16_t), err_open, "Could not read reserved field: %s", strerror(errno));
	/* reserved field */
	WRITE_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err_open, "Could not write reserved field: %s", strerror(errno));
	/* magic */
	tmp64 = htonll(opts_magic);
	WRITE_ALL_ERRCHK(sock, &tmp64, sizeof(tmp64), err_open, "Could not write magic: %s", strerror(errno));
	/* name */
	tmp32 = htonl(NBD_OPT_EXPORT_NAME);
	WRITE_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err_open, "Could not write option: %s", strerror(errno));
	tmp32 = htonl((uint32_t)strlen(name));
	WRITE_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err_open, "Could not write name length: %s", strerror(errno));
	WRITE_ALL_ERRCHK(sock, name, strlen(name), err_open, "Could not write name:: %s", strerror(errno));
	READ_ALL_ERRCHK(sock, &size, sizeof(size), err_open, "Could not read size: %s", strerror(errno));
	size = ntohll(size);
	uint16_t flags;
	READ_ALL_ERRCHK(sock, &flags, sizeof(uint16_t), err_open, "Could not read flags: %s", strerror(errno));
	flags = ntohs(flags);
	*serverflags = flags;
	g_warning("Server flags are: %08x", flags);
	READ_ALL_ERRCHK(sock, buf, 124, err_open, "Could not read reserved zeroes: %s", strerror(errno));
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

	READ_ALL_ERR_RT(sock, &rep, sizeof(rep), end, -1, "Could not read reply header: %s", strerror(errno));
	rep.magic=ntohl(rep.magic);
	rep.error=ntohl(rep.error);
	if(rep.magic!=NBD_REPLY_MAGIC) {
		snprintf(errstr, errstr_len, "Received package with incorrect reply_magic. Index of sent packages is %lld (0x%llX), received handle is %lld (0x%llX). Received magic 0x%lX, expected 0x%lX", (long long int)curhandle, (long long unsigned int)curhandle, (long long int)*((u64*)rep.handle), (long long unsigned int)*((u64*)rep.handle), (long unsigned int)rep.magic, (long unsigned int)NBD_REPLY_MAGIC);
		retval=-1;
		goto end;
	}
	if(rep.error) {
		snprintf(errstr, errstr_len, "Received error from server: %ld (0x%lX). Handle is %lld (0x%llX).", (long int)rep.error, (long unsigned int)rep.error, (long long int)(*((u64*)rep.handle)), (long long unsigned int)*((u64*)rep.handle));
		retval=-1;
		goto end;
	}
	if (datasize)
		READ_ALL_ERR_RT(sock, &buf, datasize, end, -1, "Could not read data: %s", strerror(errno));

end:
	return retval;
}

int oversize_test(gchar* hostname, int port, char* name, int sock,
		  char sock_is_open, char close_sock, int testflags) {
	int retval=0;
	struct nbd_request req;
	struct nbd_reply rep;
	int request=0;
	int i=0;
	int serverflags = 0;
	pid_t mypid = getpid();
	char buf[((1024*1024)+sizeof(struct nbd_request)/2)<<1];
	bool got_err;

	/* This should work */
	if(!sock_is_open) {
		if((sock=setup_connection(hostname, port, name, CONNECTION_TYPE_FULL, &serverflags))<0) {
			g_warning("Could not open socket: %s", errstr);
			retval=-1;
			goto err;
		}
	}
	req.magic=htonl(NBD_REQUEST_MAGIC);
	req.type=htonl(NBD_CMD_READ);
	req.len=htonl(1024*1024);
	memcpy(&(req.handle),&i,sizeof(i));
	req.from=htonll(i);
	WRITE_ALL_ERR_RT(sock, &req, sizeof(req), err, -1, "Could not write request: %s", strerror(errno));
	printf("%d: testing oversized request: %d: ", getpid(), ntohl(req.len));
	READ_ALL_ERR_RT(sock, &rep, sizeof(struct nbd_reply), err, -1, "Could not read reply header: %s", strerror(errno));
	READ_ALL_ERR_RT(sock, &buf, ntohl(req.len), err, -1, "Could not read data: %s", strerror(errno));
	if(rep.error) {
		snprintf(errstr, errstr_len, "Received unexpected error: %d", rep.error);
		retval=-1;
		goto err;
	} else {
		printf("OK\n");
	}
	/* This probably should not work */
	i++; req.from=htonll(i);
	req.len = htonl(ntohl(req.len) + sizeof(struct nbd_request) / 2);
	WRITE_ALL_ERR_RT(sock, &req, sizeof(req), err, -1, "Could not write request: %s", strerror(errno));
	printf("%d: testing oversized request: %d: ", getpid(), ntohl(req.len));
	READ_ALL_ERR_RT(sock, &rep, sizeof(struct nbd_reply), err, -1, "Could not read reply header: %s", strerror(errno));
	READ_ALL_ERR_RT(sock, &buf, ntohl(req.len), err, -1, "Could not read data: %s", strerror(errno));
	if(rep.error) {
		printf("Received expected error\n");
		got_err=true;
	} else {
		printf("OK\n");
		got_err=false;
	}
	/* ... unless this works, too */
	i++; req.from=htonll(i);
	req.len = htonl(ntohl(req.len) << 1);
	WRITE_ALL_ERR_RT(sock, &req, sizeof(req), err, -1, "Could not write request: %s", strerror(errno));
	printf("%d: testing oversized request: %d: ", getpid(), ntohl(req.len));
	READ_ALL_ERR_RT(sock, &rep, sizeof(struct nbd_reply), err, -1, "Could not read reply header: %s", strerror(errno));
	READ_ALL_ERR_RT(sock, &buf, ntohl(req.len), err, -1, "Could not read data: %s", strerror(errno));
	if(rep.error) {
		printf("error\n");
	} else {
		printf("OK\n");
	}
	if((rep.error && !got_err) || (!rep.error && got_err)) {
		printf("Received unexpected error\n");
		retval=-1;
	}
  err:
	return retval;
}

int throughput_test(gchar* hostname, int port, char* name, int sock,
		    char sock_is_open, char close_sock, int testflags) {
	long long int i;
	char buf[1024];
	char writebuf[1024];
	struct nbd_request req;
	int requests=0;
	fd_set set;
	struct timeval tv;
	struct timeval start;
	struct timeval stop;
	double timespan;
	double speed;
	char speedchar[2] = { '\0', '\0' };
	int retval=0;
	int serverflags = 0;
	size_t tmp;
	signed int do_write=TRUE;
	pid_t mypid = getpid();


	if (!(testflags & TEST_WRITE))
		testflags &= ~TEST_FLUSH;

	memset (writebuf, 'X', sizeof(1024));
	size=0;
	if(!sock_is_open) {
		if((sock=setup_connection(hostname, port, name, CONNECTION_TYPE_FULL, &serverflags))<0) {
			g_warning("Could not open socket: %s", errstr);
			retval=-1;
			goto err;
		}
	}
	if ((testflags & TEST_FLUSH) && ((serverflags & (NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA))
					 != (NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA))) {
		snprintf(errstr, errstr_len, "Server did not supply flush capability flags");
		retval = -1;
		goto err_open;
	}
	req.magic=htonl(NBD_REQUEST_MAGIC);
	req.len=htonl(1024);
	if(gettimeofday(&start, NULL)<0) {
		retval=-1;
		snprintf(errstr, errstr_len, "Could not measure start time: %s", strerror(errno));
		goto err_open;
	}
	for(i=0;i+1024<=size;i+=1024) {
		if(do_write) {
			int sendfua = (testflags & TEST_FLUSH) && ((i & 15) == 3);
			int sendflush = (testflags & TEST_FLUSH) && ((i & 15) == 11);
			req.type=htonl((testflags & TEST_WRITE)?NBD_CMD_WRITE:NBD_CMD_READ);
			if (sendfua)
				req.type = htonl(NBD_CMD_WRITE | NBD_CMD_FLAG_FUA);
			memcpy(&(req.handle),&i,sizeof(i));
			req.from=htonll(i);
			if (write_all(sock, &req, sizeof(req)) <0) {
				retval=-1;
				goto err_open;
			}
			if (testflags & TEST_WRITE) {
				if (write_all(sock, writebuf, 1024) <0) {
					retval=-1;
					goto err_open;
				}
			}
			printf("%d: Requests(+): %d\n", (int)mypid, ++requests);
			if (sendflush) {
				long long int j = i ^ (1LL<<63);
				req.type = htonl(NBD_CMD_FLUSH);
				memcpy(&(req.handle),&j,sizeof(j));
				req.from=0;
				if (write_all(sock, &req, sizeof(req)) <0) {
					retval=-1;
					goto err_open;
				}
				printf("%d: Requests(+): %d\n", (int)mypid, ++requests);
			}
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
				if(read_packet_check_header(sock, (testflags & TEST_WRITE)?0:1024, i)<0) {
					retval=-1;
					goto err_open;
				}
				printf("%d: Requests(-): %d\n", (int)mypid, --requests);
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
			read_packet_check_header(sock, (testflags & TEST_WRITE)?0:1024, i);
			printf("%d: Requests(-): %d\n", (int)mypid, --requests);
		}
	} while (requests);
	if(gettimeofday(&stop, NULL)<0) {
		retval=-1;
		snprintf(errstr, errstr_len, "Could not measure end time: %s", strerror(errno));
		goto err_open;
	}
	timespan=timeval_diff_to_double(&stop, &start);
	speed=size/timespan;
	if(speed>1024) {
		speed=speed/1024.0;
		speedchar[0]='K';
	}
	if(speed>1024) {
		speed=speed/1024.0;
		speedchar[0]='M';
	}
	if(speed>1024) {
		speed=speed/1024.0;
		speedchar[0]='G';
	}
	g_message("%d: Throughput %s test complete. Took %.3f seconds to complete, %.3f%sib/s", (int)getpid(), (testflags & TEST_WRITE)?"write":"read", timespan, speed, speedchar);

err_open:
	if(close_sock) {
		close_connection(sock, CONNECTION_CLOSE_PROPERLY);
	}
err:
	return retval;
}

typedef int (*testfunc)(gchar*, int, char*, int, char, char, int);

int main(int argc, char**argv) {
	gchar *hostname;
	long int p = 0;
	char* name = NULL;
	int sock=0;
	int c;
	bool want_port = TRUE;
	int nonopt=0;
	int testflags=0;
	testfunc test = throughput_test;

	if(argc<3) {
		g_message("%d: Not enough arguments", (int)getpid());
		g_message("%d: Usage: %s <hostname> <port>", (int)getpid(), argv[0]);
		g_message("%d: Or: %s <hostname> -N <exportname>", (int)getpid(), argv[0]);
		exit(EXIT_FAILURE);
	}
	logging();
	while((c=getopt(argc, argv, "-N:owf"))>=0) {
		switch(c) {
			case 1:
				switch(nonopt) {
					case 0:
						hostname=g_strdup(optarg);
						nonopt++;
						break;
					case 1:
						if(want_port)
						p=(strtol(argv[2], NULL, 0));
						if(p==LONG_MIN||p==LONG_MAX) {
							g_critical("Could not parse port number: %s", strerror(errno));
							exit(EXIT_FAILURE);
						}
						break;
				}
				break;
			case 'N':
				name=g_strdup(optarg);
				p = 10809;
				want_port = false;
				break;
			case 'o':
				test=oversize_test;
				break;
			case 'w':
				testflags|=TEST_WRITE;
				break;
			case 'f':
				testflags|=TEST_FLUSH;
				break;
		}
	}

	if(test(hostname, (int)p, name, sock, FALSE, TRUE, testflags)<0) {
		g_warning("Could not run test: %s", errstr);
		exit(EXIT_FAILURE);
	}

	return 0;
}
