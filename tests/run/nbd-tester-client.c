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
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>
#include "config.h"
#include "lfs.h"
#include <netinet/in.h>
#include <glib.h>

#define MY_NAME "nbd-tester-client"
#include "cliserv.h"

#if HAVE_GNUTLS
#include "crypto-gnutls.h"
#endif

static gchar errstr[1024];
const static int errstr_len = 1023;

static uint64_t size;

static int looseordering = 0;

static gchar *transactionlog = "nbd-tester-client.tr";
static gchar *certfile = NULL;
static gchar *keyfile = NULL;
static gchar *cacertfile = NULL;
static gchar *tlshostname = NULL;

typedef enum {
	CONNECTION_TYPE_INIT_PASSWD,
	CONNECTION_TYPE_CLISERV,
	CONNECTION_TYPE_HANDSHAKE,
	CONNECTION_TYPE_FULL,
} CONNECTION_TYPE;

typedef enum {
	CONNECTION_CLOSE_PROPERLY,
	CONNECTION_CLOSE_FAST,
} CLOSE_TYPE;

struct reqcontext {
	uint64_t seq;
	uint64_t origcookie;
	struct nbd_request req;
	struct reqcontext *next;
	struct reqcontext *prev;
};

struct rclist {
	struct reqcontext *head;
	struct reqcontext *tail;
	int numitems;
};

struct chunk {
	char *buffer;
	char *readptr;
	char *writeptr;
	uint64_t space;
	uint64_t length;
	struct chunk *next;
	struct chunk *prev;
};

struct chunklist {
	struct chunk *head;
	struct chunk *tail;
	int numitems;
};

struct blkitem {
	uint32_t seq;
	int32_t inflightr;
	int32_t inflightw;
};

void rclist_unlink(struct rclist *l, struct reqcontext *p)
{
	if (p && l) {
		struct reqcontext *prev = p->prev;
		struct reqcontext *next = p->next;

		/* Fix link to previous */
		if (prev)
			prev->next = next;
		else
			l->head = next;

		if (next)
			next->prev = prev;
		else
			l->tail = prev;

		p->prev = NULL;
		p->next = NULL;
		l->numitems--;
	}
}

/* Add a new list item to the tail */
void rclist_addtail(struct rclist *l, struct reqcontext *p)
{
	if (!p || !l)
		return;
	if (l->tail) {
		if (l->tail->next)
			g_warning("addtail found list tail has a next pointer");
		l->tail->next = p;
		p->next = NULL;
		p->prev = l->tail;
		l->tail = p;
	} else {
		if (l->head)
			g_warning("addtail found no list tail but a list head");
		l->head = p;
		l->tail = p;
		p->prev = NULL;
		p->next = NULL;
	}
	l->numitems++;
}

void chunklist_unlink(struct chunklist *l, struct chunk *p)
{
	if (p && l) {
		struct chunk *prev = p->prev;
		struct chunk *next = p->next;

		/* Fix link to previous */
		if (prev)
			prev->next = next;
		else
			l->head = next;

		if (next)
			next->prev = prev;
		else
			l->tail = prev;

		p->prev = NULL;
		p->next = NULL;
		l->numitems--;
	}
}

/* Add a new list item to the tail */
void chunklist_addtail(struct chunklist *l, struct chunk *p)
{
	if (!p || !l)
		return;
	if (l->tail) {
		if (l->tail->next)
			g_warning("addtail found list tail has a next pointer");
		l->tail->next = p;
		p->next = NULL;
		p->prev = l->tail;
		l->tail = p;
	} else {
		if (l->head)
			g_warning("addtail found no list tail but a list head");
		l->head = p;
		l->tail = p;
		p->prev = NULL;
		p->next = NULL;
	}
	l->numitems++;
}

/* Add some new bytes to a chunklist */
void addbuffer(struct chunklist *l, void *data, uint64_t len)
{
	void *buf;
	uint64_t size = 64 * 1024;
	struct chunk *pchunk;

	while (len > 0) {
		/* First see if there is a current chunk, and if it has space */
		if (l->tail && l->tail->space) {
			uint64_t towrite = len;
			if (towrite > l->tail->space)
				towrite = l->tail->space;
			memcpy(l->tail->writeptr, data, towrite);
			l->tail->length += towrite;
			l->tail->space -= towrite;
			l->tail->writeptr += towrite;
			len -= towrite;
			data += towrite;
		}

		if (len > 0) {
			/* We still need to write more, so prepare a new chunk */
			if ((NULL == (buf = malloc(size)))
			    || (NULL ==
				(pchunk = calloc(1, sizeof(struct chunk))))) {
				g_critical("Out of memory");
				exit(1);
			}

			pchunk->buffer = buf;
			pchunk->readptr = buf;
			pchunk->writeptr = buf;
			pchunk->space = size;
			chunklist_addtail(l, pchunk);
		}
	}

}

/* returns 0 on success, -1 on failure */
int writebuffer(int fd, struct chunklist *l)
{

	struct chunk *pchunk = NULL;
	int res;
	if (!l)
		return 0;

	while (!pchunk) {
		pchunk = l->head;
		if (!pchunk)
			return 0;
		if (!(pchunk->length) || !(pchunk->readptr)) {
			chunklist_unlink(l, pchunk);
			free(pchunk->buffer);
			free(pchunk);
			pchunk = NULL;
		}
	}

	/* OK we have a chunk with some data in */
	res = write(fd, pchunk->readptr, pchunk->length);
	if (res == 0)
		errno = EAGAIN;
	if (res <= 0)
		return -1;
	pchunk->length -= res;
	pchunk->readptr += res;
	if (!pchunk->length) {
		chunklist_unlink(l, pchunk);
		free(pchunk->buffer);
		free(pchunk);
	}
	return 0;
}

#define TEST_WRITE              (1<<0)
#define TEST_FLUSH              (1<<1)
#define TEST_EXPECT_ERROR       (1<<2)

int timeval_subtract(struct timeval *result, struct timeval *x,
		     struct timeval *y)
{
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

double timeval_diff_to_double(struct timeval *x, struct timeval *y)
{
	struct timeval r;
	timeval_subtract(&r, x, y);
	return r.tv_sec * 1.0 + r.tv_usec / 1000000.0;
}

static inline int read_all(int f, void *buf, size_t len)
{
	ssize_t res;
	size_t retval = 0;

	while (len > 0) {
		if ((res = read(f, buf, len)) <= 0) {
			if (!res)
				errno = EAGAIN;
			snprintf(errstr, errstr_len, "Read failed: %s",
				 strerror(errno));
			return -1;
		}
		len -= res;
		buf += res;
		retval += res;
	}
	return retval;
}

static inline int write_all(int f, void *buf, size_t len)
{
	ssize_t res;
	size_t retval = 0;

	while (len > 0) {
		if ((res = write(f, buf, len)) <= 0) {
			if (!res)
				errno = EAGAIN;
			snprintf(errstr, errstr_len, "Write failed: %s",
				 strerror(errno));
			return -1;
		}
		len -= res;
		buf += res;
		retval += res;
	}
	return retval;
}

static int tlserrout (void *opaque, const char *format, va_list ap) {
	return vfprintf(stderr, format, ap);
}

#define READ_ALL_ERRCHK(f, buf, len, whereto, errmsg...) if((read_all(f, buf, len))<=0) { snprintf(errstr, errstr_len, ##errmsg); goto whereto; }
#define READ_ALL_ERR_RT(f, buf, len, whereto, rval, errmsg...) if((read_all(f, buf, len))<=0) { snprintf(errstr, errstr_len, ##errmsg); retval = rval; goto whereto; }

#define WRITE_ALL_ERRCHK(f, buf, len, whereto, errmsg...) if((write_all(f, buf, len))<=0) { snprintf(errstr, errstr_len, ##errmsg); goto whereto; }
#define WRITE_ALL_ERR_RT(f, buf, len, whereto, rval, errmsg...) if((write_all(f, buf, len))<=0) { snprintf(errstr, errstr_len, ##errmsg); retval = rval; goto whereto; }

int setup_connection_common(int sock, char *name, CONNECTION_TYPE ctype,
			    int *serverflags, int testflags)
{
	char buf[256];
	u64 tmp64;
	uint64_t mymagic = (name ? opts_magic : cliserv_magic);
	uint32_t tmp32 = 0;
	uint16_t handshakeflags = 0;
	uint32_t negotiationflags = 0;

	if (ctype < CONNECTION_TYPE_INIT_PASSWD)
		goto end;
	READ_ALL_ERRCHK(sock, buf, strlen(INIT_PASSWD), err,
			"Could not read INIT_PASSWD: %s", strerror(errno));
	buf[strlen(INIT_PASSWD)] = 0;
	if (strlen(buf) == 0) {
		snprintf(errstr, errstr_len, "Server closed connection");
		goto err;
	}
	if (strncmp(buf, INIT_PASSWD, strlen(INIT_PASSWD))) {
		snprintf(errstr, errstr_len, "INIT_PASSWD does not match");
		goto err;
	}
	if (ctype < CONNECTION_TYPE_CLISERV)
		goto end;
	READ_ALL_ERRCHK(sock, &tmp64, sizeof(tmp64), err,
			"Could not read cliserv_magic: %s", strerror(errno));
	tmp64 = ntohll(tmp64);
	if (tmp64 != mymagic) {
		strncpy(errstr, "mymagic does not match", errstr_len);
		goto err;
	}
	if (ctype < CONNECTION_TYPE_HANDSHAKE)
		goto end;
	if (!name) {
		READ_ALL_ERRCHK(sock, &size, sizeof(size), err,
				"Could not read size: %s", strerror(errno));
		size = ntohll(size);
		uint32_t flags;
		READ_ALL_ERRCHK(sock, &flags, sizeof(uint32_t), err,
				"Could not read flags: %s", strerror(errno));
		flags = ntohl(flags);
		*serverflags = flags;
		READ_ALL_ERRCHK(sock, buf, 124, err, "Could not read data: %s",
				strerror(errno));
		goto end;
	}
	/* handshake flags */
	READ_ALL_ERRCHK(sock, &handshakeflags, sizeof(handshakeflags), err,
			"Could not read reserved field: %s", strerror(errno));
	handshakeflags = ntohs(handshakeflags);
	/* negotiation flags */
	if (handshakeflags & NBD_FLAG_FIXED_NEWSTYLE)
		negotiationflags |= NBD_FLAG_C_FIXED_NEWSTYLE;
	else if (keyfile) {
		snprintf(errstr, errstr_len, "Cannot negotiate TLS without NBD_FLAG_FIXED_NEWSTYLE");
		goto err;
	}
	negotiationflags = htonl(negotiationflags);
	WRITE_ALL_ERRCHK(sock, &negotiationflags, sizeof(negotiationflags), err,
			 "Could not write reserved field: %s", strerror(errno));
	if (ctype < CONNECTION_TYPE_FULL) {
		/* Server must support newstyle for this test */
		if (!(handshakeflags & NBD_FLAG_FIXED_NEWSTYLE)) {
			strncpy(errstr, "server does not support handshake", errstr_len);
			goto err;
		}
		goto end;
	}
#if HAVE_GNUTLS
	/* TLS */
	if (keyfile) {
		int plainfd[2]; // [0] is used by the proxy, [1] is used by NBD
		tlssession_t *s = NULL;
		int ret;

		/* magic */
		tmp64 = htonll(opts_magic);
		WRITE_ALL_ERRCHK(sock, &tmp64, sizeof(tmp64), err,
				 "Could not write magic: %s", strerror(errno));
		/* starttls */
		tmp32 = htonl(NBD_OPT_STARTTLS);
		WRITE_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
			 "Could not write option: %s", strerror(errno));
		/* length of data */
		tmp32 = htonl(0);
		WRITE_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
			 "Could not write option length: %s", strerror(errno));

		READ_ALL_ERRCHK(sock, &tmp64, sizeof(tmp64), err,
				"Could not read cliserv_magic: %s", strerror(errno));
		tmp64 = ntohll(tmp64);
		if (tmp64 != NBD_OPT_REPLY_MAGIC) {
			strncpy(errstr, "reply magic does not match", errstr_len);
			goto err;
		}
		READ_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
				"Could not read option type: %s", strerror(errno));
		tmp32 = ntohl(tmp32);
		if (tmp32 != NBD_OPT_STARTTLS) {
			strncpy(errstr, "Reply to wrong option", errstr_len);
			goto err;
		}
		READ_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
				"Could not read option reply type: %s", strerror(errno));
		tmp32 = ntohl(tmp32);
		if (tmp32 != NBD_REP_ACK) {
			if(tmp32 & NBD_REP_FLAG_ERROR) {
				snprintf(errstr, errstr_len, "Received error %d", tmp32 & ~NBD_REP_FLAG_ERROR);
			} else {
				snprintf(errstr, errstr_len, "Option reply type %d != NBD_REP_ACK", tmp32);
			}
			goto err;
		}
		READ_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
				"Could not read option data length: %s", strerror(errno));
		tmp32 = ntohl(tmp32);
		if (tmp32 != 0) {
			strncpy(errstr, "Option reply data length != 0", errstr_len);
			goto err;
		}

		s = tlssession_new(FALSE,
				   keyfile,
				   certfile,
				   cacertfile,
				   tlshostname,
				   !cacertfile || !tlshostname, // insecure flag
#ifdef DODBG
				   1, // debug
#else
				   0, // debug
#endif
				   NULL, // quitfn
				   tlserrout, // erroutfn
				   NULL // opaque
			);
		if (!s) {
			strncpy(errstr, "Cannot establish TLS session", errstr_len);
			goto err;
		}

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, plainfd) < 0) {
			strncpy(errstr, "Cannot get socket pair", errstr_len);
			goto err;
		}

		if (set_nonblocking(plainfd[0], 0) <0 ||
		    set_nonblocking(plainfd[1], 0) <0 ||
		    set_nonblocking(sock, 0) <0) {
			close(plainfd[0]);
			close(plainfd[1]);
			strncpy(errstr, "Cannot set socket options", errstr_len);
			goto err;
		}

		ret = fork();
		if (ret < 0)
			err("Could not fork");
		else if (ret == 0) {
			// we are the child
			signal (SIGPIPE, SIG_IGN);
			close(plainfd[1]);
			tlssession_mainloop(sock, plainfd[0], s);
			close(sock);
			close(plainfd[0]);
			exit(0);
		}
		close(plainfd[0]);
		close(sock);
		sock = plainfd[1]; /* use the decrypted FD from now on */
	}
#else
	if (keyfile) {
		strncpy(errstr, "TLS requested but support not compiled in", errstr_len);
		goto err;
	}
#endif
	if(testflags & TEST_EXPECT_ERROR) {
		struct sigaction act;
		memset(&act, 0, sizeof act);
		act.sa_handler = SIG_IGN;
		sigaction(SIGPIPE, &act, NULL);
	}
	/* magic */
	tmp64 = htonll(opts_magic);
	WRITE_ALL_ERRCHK(sock, &tmp64, sizeof(tmp64), err,
			 "Could not write magic: %s", strerror(errno));
	/* name */
	tmp32 = htonl(NBD_OPT_EXPORT_NAME);
	WRITE_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
			 "Could not write option: %s", strerror(errno));
	tmp32 = htonl((uint32_t) strlen(name));
	WRITE_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
			 "Could not write name length: %s", strerror(errno));
	WRITE_ALL_ERRCHK(sock, name, strlen(name), err,
			 "Could not write name:: %s", strerror(errno));
	READ_ALL_ERRCHK(sock, &size, sizeof(size), err,
			"Could not read size: %s", strerror(errno));
	size = ntohll(size);
	uint16_t flags;
	READ_ALL_ERRCHK(sock, &flags, sizeof(uint16_t), err,
			"Could not read flags: %s", strerror(errno));
	flags = ntohs(flags);
	*serverflags = flags;
	READ_ALL_ERRCHK(sock, buf, 124, err,
			"Could not read reserved zeroes: %s", strerror(errno));
	goto end;
err:
	close(sock);
	sock = -1;
end:
	return sock;
}

int setup_unix_connection(gchar * unixsock)
{
	struct sockaddr_un addr;
	int sock;

	sock = 0;
	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		strncpy(errstr, strerror(errno), errstr_len);
		goto err;
	}

	setmysockopt(sock);
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, unixsock, sizeof addr.sun_path);
	addr.sun_path[sizeof(addr.sun_path)-1] = '\0';
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		strncpy(errstr, strerror(errno), errstr_len);
		goto err_open;
	}
	goto end;
err_open:
	close(sock);
err:
	sock = -1;
end:
	return sock;
}

int setup_inet_connection(gchar * hostname, int port)
{
	int sock;
	struct hostent *host;
	struct sockaddr_in addr;

	sock = 0;
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		strncpy(errstr, strerror(errno), errstr_len);
		goto err;
	}
	setmysockopt(sock);
	if (!(host = gethostbyname(hostname))) {
		strncpy(errstr, hstrerror(h_errno), errstr_len);
		goto err_open;
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *((int *)host->h_addr);
	memset(&addr.sin_zero, 0, sizeof(addr.sin_zero));
	if ((connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0)) {
		strncpy(errstr, strerror(errno), errstr_len);
		goto err_open;
	}
	goto end;
err_open:
	close(sock);
err:
	sock = -1;
end:
	return sock;
}

int setup_inetd_connection(gchar **argv)
{
	int sv[2], status;
	pid_t child;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
		strncpy(errstr, strerror(errno), errstr_len);
		return -1;
	}

	child = vfork();
	if (child == 0) {
		dup2(sv[0], 0);
		close(sv[0]);
		close(sv[1]);
		execvp(argv[0], argv);
		perror("execvp");
		_exit(-1);
	} else if (child == -1) {
		close(sv[0]);
		close(sv[1]);
		strncpy(errstr, strerror(errno), errstr_len);
		return -1;
	}

	close(sv[0]);
	if (waitpid(child, &status, WNOHANG)) {
		close(sv[1]);
		return -1;
	}

	setmysockopt(sv[1]);
	return sv[1];
}

int close_connection(int sock, CLOSE_TYPE type)
{
	struct nbd_request req;
	u64 counter = 0;

	switch (type) {
	case CONNECTION_CLOSE_PROPERLY:
		req.magic = htonl(NBD_REQUEST_MAGIC);
		req.type = htonl(NBD_CMD_DISC);
		req.cookie = htonll(counter);
		counter++;
		req.from = 0;
		req.len = 0;
		if (write(sock, &req, sizeof(req)) < 0) {
			snprintf(errstr, errstr_len,
				 "Could not write to socket: %s",
				 strerror(errno));
			return -1;
		}
		/* falls through */
	case CONNECTION_CLOSE_FAST:
		if (close(sock) < 0) {
			snprintf(errstr, errstr_len,
				 "Could not close socket: %s", strerror(errno));
			return -1;
		}
		break;
	default:
		g_critical("Your compiler is on crack!");	/* or I am buggy */
		return -1;
	}
	return 0;
}

int read_packet_check_header(int sock, size_t datasize, long long int curcookie)
{
	struct nbd_reply rep;
	int retval = 0;
	char buf[datasize];

	READ_ALL_ERR_RT(sock, &rep, sizeof(rep), end, -1,
			"Could not read reply header: %s", strerror(errno));
	rep.magic = ntohl(rep.magic);
	rep.error = ntohl(rep.error);
	if (rep.magic != NBD_REPLY_MAGIC) {
		snprintf(errstr, errstr_len,
			 "Received package with incorrect reply_magic. Index of sent packages is %lld (0x%llX), received cookie is %lld (0x%llX). Received magic 0x%lX, expected 0x%lX",
			 (long long int)curcookie,
			 (long long unsigned int)curcookie,
			 (long long int)rep.cookie,
			 (long long unsigned int)rep.cookie,
			 (long unsigned int)rep.magic,
			 (long unsigned int)NBD_REPLY_MAGIC);
		retval = -1;
		goto end;
	}
	if (rep.error) {
		snprintf(errstr, errstr_len,
			 "Received error from server: %ld (0x%lX). Cookie is %lld (0x%llX).",
			 (long int)rep.error, (long unsigned int)rep.error,
			 (long long int)rep.cookie,
			 (long long unsigned int)rep.cookie);
		retval = -2;
		goto end;
	}
	if (datasize)
		READ_ALL_ERR_RT(sock, &buf, datasize, end, -1,
				"Could not read data: %s", strerror(errno));

end:
	return retval;
}

int oversize_test(char *name, int sock, char close_sock, int testflags)
{
	int retval = 0;
	struct nbd_request req;
	struct nbd_reply rep;
	int i = 0;
	int serverflags = 0;
	pid_t G_GNUC_UNUSED mypid = getpid();
	char buf[((1024 * 1024) + sizeof(struct nbd_request) / 2) << 1];
	bool got_err;

	/* This should work */
	if ((sock =
		 setup_connection_common(sock, name,
				  CONNECTION_TYPE_FULL,
				  &serverflags, testflags)) < 0) {
		g_warning("Could not open socket: %s", errstr);
		retval = -1;
		goto err;
	}
	req.magic = htonl(NBD_REQUEST_MAGIC);
	req.type = htonl(NBD_CMD_READ);
	req.len = htonl(1024 * 1024);
	req.cookie = htonll(i);
	req.from = htonll(i);
	WRITE_ALL_ERR_RT(sock, &req, sizeof(req), err, -1,
			 "Could not write request: %s", strerror(errno));
	printf("%d: testing oversized request: %d: ", getpid(), ntohl(req.len));
	READ_ALL_ERR_RT(sock, &rep, sizeof(struct nbd_reply), err, -1,
			"Could not read reply header: %s", strerror(errno));
	READ_ALL_ERR_RT(sock, &buf, ntohl(req.len), err, -1,
			"Could not read data: %s", strerror(errno));
	if (rep.error) {
		snprintf(errstr, errstr_len, "Received unexpected error: %d",
			 rep.error);
		retval = -1;
		goto err;
	} else {
		printf("OK\n");
	}
	/* This probably should not work */
	i++;
	req.from = htonll(i);
	req.len = htonl(ntohl(req.len) + sizeof(struct nbd_request) / 2);
	WRITE_ALL_ERR_RT(sock, &req, sizeof(req), err, -1,
			 "Could not write request: %s", strerror(errno));
	printf("%d: testing oversized request: %d: ", getpid(), ntohl(req.len));
	READ_ALL_ERR_RT(sock, &rep, sizeof(struct nbd_reply), err, -1,
			"Could not read reply header: %s", strerror(errno));
	READ_ALL_ERR_RT(sock, &buf, ntohl(req.len), err, -1,
			"Could not read data: %s", strerror(errno));
	if (rep.error) {
		printf("Received expected error\n");
		got_err = true;
	} else {
		printf("OK\n");
		got_err = false;
	}
	/* ... unless this works, too */
	i++;
	req.from = htonll(i);
	req.len = htonl(ntohl(req.len) << 1);
	WRITE_ALL_ERR_RT(sock, &req, sizeof(req), err, -1,
			 "Could not write request: %s", strerror(errno));
	printf("%d: testing oversized request: %d: ", getpid(), ntohl(req.len));
	READ_ALL_ERR_RT(sock, &rep, sizeof(struct nbd_reply), err, -1,
			"Could not read reply header: %s", strerror(errno));
	READ_ALL_ERR_RT(sock, &buf, ntohl(req.len), err, -1,
			"Could not read data: %s", strerror(errno));
	if (rep.error) {
		printf("error\n");
	} else {
		printf("OK\n");
	}
	if ((rep.error && !got_err) || (!rep.error && got_err)) {
		printf("Received unexpected error\n");
		retval = -1;
	}
err:
	return retval;
}

int handshake_test(char *name, int sock, char close_sock, int testflags)
{
	int retval = -1;
	int serverflags = 0;
	u64 tmp64;
	uint32_t tmp32 = 0;

	/* This should work */
	if ((sock =
		setup_connection_common(sock, name,
				  CONNECTION_TYPE_HANDSHAKE,
				  &serverflags, testflags)) < 0) {
		g_warning("Could not open socket: %s", errstr);
		goto err;
	}

	/* Intentionally throw an unknown option at the server */
	tmp64 = htonll(opts_magic);
	WRITE_ALL_ERRCHK(sock, &tmp64, sizeof(tmp64), err,
			 "Could not write magic: %s", strerror(errno));
	tmp32 = htonl(0x7654321);
	WRITE_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
			 "Could not write option: %s", strerror(errno));
	tmp32 = htonl((uint32_t) sizeof(tmp32));
	WRITE_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
			 "Could not write option length: %s", strerror(errno));
	WRITE_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
			 "Could not write option payload: %s", strerror(errno));
	/* Expect proper error from server */
	READ_ALL_ERRCHK(sock, &tmp64, sizeof(tmp64), err,
			"Could not read magic: %s", strerror(errno));
	tmp64 = ntohll(tmp64);
	if (tmp64 != 0x3e889045565a9LL) {
		strncpy(errstr, "magic does not match", errstr_len);
		goto err;
	}
	READ_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
			"Could not read option: %s", strerror(errno));
	tmp32 = ntohl(tmp32);
	if (tmp32 != 0x7654321) {
		strncpy(errstr, "option does not match", errstr_len);
		goto err;
	}
	READ_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
			"Could not read status: %s", strerror(errno));
	tmp32 = ntohl(tmp32);
	if (tmp32 != NBD_REP_ERR_UNSUP) {
		strncpy(errstr, "status does not match", errstr_len);
		goto err;
	}
	READ_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
			"Could not read length: %s", strerror(errno));
	tmp32 = ntohl(tmp32);
	while (tmp32) {
		char buf[1024];
		size_t len = tmp32 < sizeof(buf) ? tmp32 : sizeof(buf);
		READ_ALL_ERRCHK(sock, buf, len, err,
				"Could not read payload: %s", strerror(errno));
		tmp32 -= len;
	}


	/* Send NBD_OPT_ABORT to close the connection */
	tmp64 = htonll(opts_magic);
	WRITE_ALL_ERRCHK(sock, &tmp64, sizeof(tmp64), err,
			 "Could not write magic: %s", strerror(errno));
	tmp32 = htonl(NBD_OPT_ABORT);
	WRITE_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
			 "Could not write option: %s", strerror(errno));
	tmp32 = htonl((uint32_t) 0);
	WRITE_ALL_ERRCHK(sock, &tmp32, sizeof(tmp32), err,
			 "Could not write option length: %s", strerror(errno));

	retval = 0;

	g_message("Handshake test completed. No errors encountered.");
err:
	return retval;
}

int throughput_test(char *name, int sock, char close_sock, int testflags)
{
	long long int i;
	char writebuf[1024];
	struct nbd_request req;
	int requests = 0;
	fd_set set;
	struct timeval tv;
	struct timeval start;
	struct timeval stop;
	double timespan;
	double speed;
	char speedchar[2] = { '\0', '\0' };
	int retval = 0;
	int serverflags = 0;
	signed int do_write = TRUE;
	pid_t mypid = getpid();
	char *print = getenv("NBD_TEST_SILENT");

	if (!(testflags & TEST_WRITE))
		testflags &= ~TEST_FLUSH;

	memset(writebuf, 'X', 1024);
	size = 0;
	if ((sock =
		 setup_connection_common(sock, name,
				  CONNECTION_TYPE_FULL,
				  &serverflags, testflags)) < 0) {
		g_warning("Could not open socket: %s", errstr);
		if(testflags & TEST_EXPECT_ERROR) {
			g_message("Test failed, as expected");
			retval = 0;
		} else {
			retval = -1;
		}
		goto err;
	}
	if ((testflags & TEST_FLUSH)
	    && ((serverflags & (NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA))
		!= (NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA))) {
		snprintf(errstr, errstr_len,
			 "Server did not supply flush capability flags");
		retval = -1;
		goto err_open;
	}
	req.magic = htonl(NBD_REQUEST_MAGIC);
	req.len = htonl(1024);
	if (gettimeofday(&start, NULL) < 0) {
		retval = -1;
		snprintf(errstr, errstr_len, "Could not measure start time: %s",
			 strerror(errno));
		goto err_open;
	}
	for (i = 0; i + 1024 <= size; i += 1024) {
		if (do_write) {
			int sendfua = (testflags & TEST_FLUSH)
			    && (((i >> 10) & 15) == 3);
			int sendflush = (testflags & TEST_FLUSH)
			    && (((i >> 10) & 15) == 11);
			req.type =
			    htonl((testflags & TEST_WRITE) ? NBD_CMD_WRITE :
				  NBD_CMD_READ);
			if (sendfua)
				req.type =
				    htonl(NBD_CMD_WRITE | NBD_CMD_FLAG_FUA);
			req.cookie = htonll(i);
			req.from = htonll(i);
			if (write_all(sock, &req, sizeof(req)) < 0) {
				retval = -1;
				goto err_open;
			}
			if (testflags & TEST_WRITE) {
				if (write_all(sock, writebuf, 1024) < 0) {
					retval = -1;
					goto err_open;
				}
			}
			++requests;
			if (sendflush) {
				long long int j = i ^ (1LL << 63);
				req.type = htonl(NBD_CMD_FLUSH);
				req.cookie = htonll(j);
				req.from = 0;
				req.len = 0;
				if (write_all(sock, &req, sizeof(req)) < 0) {
					retval = -1;
					goto err_open;
				}
				req.len = htonl(1024);
				++requests;
			}
		}
		do {
			FD_ZERO(&set);
			FD_SET(sock, &set);
			tv.tv_sec = 0;
			tv.tv_usec = 0;
			select(sock + 1, &set, NULL, NULL, &tv);
			if (FD_ISSET(sock, &set)) {
				/* Okay, there's something ready for
				 * reading here */
				int rv;
				if ((rv =
				     read_packet_check_header(sock,
							      (testflags &
							       TEST_WRITE) ? 0 :
							      1024, i)) < 0) {
					if (!(testflags & TEST_EXPECT_ERROR)
					    || rv != -2) {
						retval = -1;
					} else {
						printf("\n");
					}
					goto err_open;
				} else {
					if (testflags & TEST_EXPECT_ERROR) {
						retval = -1;
						goto err_open;
					}
				}
				--requests;
			}
		} while (FD_ISSET(sock, &set));
		/* Now wait until we can write again or until a second have
		 * passed, whichever comes first*/
		FD_ZERO(&set);
		FD_SET(sock, &set);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		do_write = select(sock + 1, NULL, &set, NULL, &tv);
		if (!do_write)
			printf("Select finished\n");
		if (do_write < 0) {
			snprintf(errstr, errstr_len, "select: %s",
				 strerror(errno));
			retval = -1;
			goto err_open;
		}
		if(print == NULL) {
			printf("%d: Requests: %d  \r", (int)mypid, requests);
		}
	}
	/* Now empty the read buffer */
	do {
		FD_ZERO(&set);
		FD_SET(sock, &set);
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		select(sock + 1, &set, NULL, NULL, &tv);
		if (FD_ISSET(sock, &set)) {
			/* Okay, there's something ready for
			 * reading here */
			read_packet_check_header(sock,
						 (testflags & TEST_WRITE) ? 0 :
						 1024, i);
			--requests;
		}
		if(print == NULL) {
			printf("%d: Requests: %d  \r", (int)mypid, requests);
		}
	} while (requests);
	printf("%d: Requests: %d  \n", (int)mypid, requests);
	if (gettimeofday(&stop, NULL) < 0) {
		retval = -1;
		snprintf(errstr, errstr_len, "Could not measure end time: %s",
			 strerror(errno));
		goto err_open;
	}
	timespan = timeval_diff_to_double(&stop, &start);
	speed = size / timespan;
	if (speed > 1024) {
		speed = speed / 1024.0;
		speedchar[0] = 'K';
	}
	if (speed > 1024) {
		speed = speed / 1024.0;
		speedchar[0] = 'M';
	}
	if (speed > 1024) {
		speed = speed / 1024.0;
		speedchar[0] = 'G';
	}
	g_message
	    ("%d: Throughput %s test (%s flushes) complete. Took %.3f seconds to complete, %.3f%sib/s",
	     (int)getpid(), (testflags & TEST_WRITE) ? "write" : "read",
	     (testflags & TEST_FLUSH) ? "with" : "without", timespan, speed,
	     speedchar);

err_open:
	if (close_sock) {
		close_connection(sock, CONNECTION_CLOSE_PROPERLY);
	}
err:
	return retval;
}

/*
 * fill 512 byte buffer 'buf' with a hashed selection of interesting data based
 * only on cookie and blknum. The first word is blknum, and the second cookie, for ease
 * of understanding. Things with cookie 0 are blank.
 */
static inline void makebuf(char *buf, uint64_t seq, uint64_t blknum)
{
	uint64_t x = ((uint64_t) blknum) ^ (seq << 32) ^ (seq >> 32);
	uint64_t *p = (uint64_t *) buf;
	int i;
	if (!seq) {
		bzero(buf, 512);
		return;
	}
	for (i = 0; i < 512 / sizeof(uint64_t); i++) {
		int s;
		*(p++) = x;
		x += 0xFEEDA1ECDEADBEEFULL + i + (((uint64_t) i) << 56);
		s = x & 63;
		x = x ^ (x << s) ^ (x >> (64 - s)) ^ 0xAA55AA55AA55AA55ULL ^
		    seq;
	}
}

static inline int checkbuf(char *buf, uint64_t seq, uint64_t blknum)
{
	uint64_t cmp[64];	// 512/8 = 64
	makebuf((char *)cmp, seq, blknum);
	return memcmp(cmp, buf, 512) ? -1 : 0;
}

static inline void dumpcommand(char *text, uint32_t command)
{
#ifdef DEBUG_COMMANDS
	command = ntohl(command);
	char *ctext;
	switch (command & NBD_CMD_MASK_COMMAND) {
	case NBD_CMD_READ:
		ctext = "NBD_CMD_READ";
		break;
	case NBD_CMD_WRITE:
		ctext = "NBD_CMD_WRITE";
		break;
	case NBD_CMD_DISC:
		ctext = "NBD_CMD_DISC";
		break;
	case NBD_CMD_FLUSH:
		ctext = "NBD_CMD_FLUSH";
		break;
	default:
		ctext = "UNKNOWN";
		break;
	}
	printf("%s: %s [%s] (0x%08x)\n",
	       text,
	       ctext, (command & NBD_CMD_FLAG_FUA) ? "FUA" : "NONE", command);
#endif
}

/* return an unused cookie */
uint64_t getrandomcookie(GHashTable * phash)
{
	uint64_t cookie = 0;
	int i;
	do {
		/* RAND_MAX may be as low as 2^15 */
		for (i = 1; i <= 5; i++)
			cookie ^= random() ^ (cookie << 15);
	} while (g_hash_table_lookup(phash, &cookie));
	return cookie;
}

int integrity_test(char *name, int sock, char close_sock, int testflags)
{
	struct nbd_reply rep;
	fd_set rset;
	fd_set wset;
	struct timeval tv;
	struct timeval start;
	struct timeval stop;
	double timespan;
	double speed;
	char speedchar[2] = { '\0', '\0' };
	int retval = -1;
	int serverflags = 0;
	pid_t G_GNUC_UNUSED mypid = getpid();
	int blkhashfd = -1;
	char *blkhashname = NULL;
	struct blkitem *blkhash = NULL;
	int logfd = -1;
	uint64_t seq = 1;
	uint64_t processed = 0;
	uint64_t printer = 0;
	char *do_print = getenv("NBD_TEST_SILENT");
	uint64_t xfer = 0;
	int readtransactionfile = 1;
	int blocked = 0;
	struct rclist txqueue = { NULL, NULL, 0 };
	struct rclist inflight = { NULL, NULL, 0 };
	struct chunklist txbuf = { NULL, NULL, 0 };

	GHashTable *cookiehash = g_hash_table_new(g_int64_hash, g_int64_equal);

	size = 0;
	if ((sock =
		 setup_connection_common(sock, name,
				  CONNECTION_TYPE_FULL,
				  &serverflags, testflags)) < 0) {
		g_warning("Could not open socket: %s", errstr);
		goto err;
	}

	if ((serverflags & (NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA))
	    != (NBD_FLAG_SEND_FLUSH | NBD_FLAG_SEND_FUA))
		g_warning
		    ("Server flags do not support FLUSH and FUA - these may error");

#ifdef HAVE_MKSTEMP
	blkhashname = strdup("/tmp/blkarray-XXXXXX");
	if (!blkhashname || (-1 == (blkhashfd = mkstemp(blkhashname)))) {
		g_warning("Could not open temp file: %s", strerror(errno));
		goto err;
	}
#else
	/* use tmpnam here to avoid further feature test nightmare */
	if (-1 == (blkhashfd = open(blkhashname = strdup(tmpnam(NULL)),
				    O_CREAT | O_RDWR,
				    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH))) {
		g_warning("Could not open temp file: %s", strerror(errno));
		goto err;
	}
#endif
	/* Ensure space freed if we die */
	if (-1 == unlink(blkhashname)) {
		g_warning("Could not unlink temp file: %s", strerror(errno));
		goto err;
	}

	if (-1 ==
	    lseek(blkhashfd, (off_t) ((size >> 9) * sizeof(struct blkitem)),
		  SEEK_SET)) {
		g_warning("Could not llseek temp file: %s", strerror(errno));
		goto err;
	}

	if (-1 == write(blkhashfd, "\0", 1)) {
		g_warning("Could not write temp file: %s", strerror(errno));
		goto err;
	}

	if (NULL == (blkhash = mmap(NULL,
				    (size >> 9) * sizeof(struct blkitem),
				    PROT_READ | PROT_WRITE,
				    MAP_SHARED, blkhashfd, 0))) {
		g_warning("Could not mmap temp file: %s", strerror(errno));
		goto err;
	}

	if (-1 == (logfd = open(transactionlog, O_RDONLY))) {
		g_warning("Could open log file: %s", strerror(errno));
		goto err;
	}

	if (gettimeofday(&start, NULL) < 0) {
		snprintf(errstr, errstr_len, "Could not measure start time: %s",
			 strerror(errno));
		goto err_open;
	}

	while (readtransactionfile || txqueue.numitems || txbuf.numitems
	       || inflight.numitems) {
		int ret;

		uint32_t magic;
		uint32_t command;
		uint64_t from;
		uint32_t len;
		struct reqcontext *prc;

		*errstr = 0;

		FD_ZERO(&wset);
		FD_ZERO(&rset);
		if (readtransactionfile)
			FD_SET(logfd, &rset);
		if ((!blocked && txqueue.numitems) || txbuf.numitems)
			FD_SET(sock, &wset);
		if (inflight.numitems)
			FD_SET(sock, &rset);
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		ret =
		    select(1 + ((sock > logfd) ? sock : logfd), &rset, &wset,
			   NULL, &tv);
		if (ret == 0) {
			snprintf(errstr, errstr_len,
				 "Timeout reading from socket");
			goto err_open;
		} else if (ret < 0) {
			g_warning("Could not mmap temp file: %s", errstr);
			goto err;
		}
		/* We know we've got at least one thing to do here then */

		/* Get a command from the transaction log */
		if (FD_ISSET(logfd, &rset)) {

			/* Read a request or reply from the transaction file */
			READ_ALL_ERRCHK(logfd,
					&magic,
					sizeof(magic),
					err_open,
					"Could not read transaction log: %s",
					strerror(errno));
			magic = ntohl(magic);
			switch (magic) {
			case NBD_REQUEST_MAGIC:
				if (NULL ==
				    (prc =
				     calloc(1, sizeof(struct reqcontext)))) {
					snprintf(errstr, errstr_len,
						 "Could not allocate request");
					goto err_open;
				}
				READ_ALL_ERRCHK(logfd,
						sizeof(magic) +
						(char *)&(prc->req),
						sizeof(struct nbd_request) -
						sizeof(magic), err_open,
						"Could not read transaction log: %s",
						strerror(errno));
				prc->req.magic = htonl(NBD_REQUEST_MAGIC);
				prc->origcookie = htonll(prc->req.cookie);
				prc->seq = seq++;
				if ((ntohl(prc->req.type) &
				     NBD_CMD_MASK_COMMAND) == NBD_CMD_DISC) {
					/* no more to read; don't enqueue as no reply
					 * we will disconnect manually at the end
					 */
					readtransactionfile = 0;
					free(prc);
				} else {
					dumpcommand("Enqueuing command",
						    prc->req.type);
					rclist_addtail(&txqueue, prc);
				}
				prc = NULL;
				break;
			case NBD_REPLY_MAGIC:
				READ_ALL_ERRCHK(logfd,
						sizeof(magic) + (char *)(&rep),
						sizeof(struct nbd_reply) -
						sizeof(magic), err_open,
						"Could not read transaction log: %s",
						strerror(errno));

				if (rep.error) {
					snprintf(errstr, errstr_len,
						 "Transaction log file contained errored transaction");
					goto err_open;
				}

				/* We do not need to consume data on a read reply as there is
				 * none in the log */
				break;
			default:
				snprintf(errstr, errstr_len,
					 "Could not measure start time: %08x",
					 magic);
				goto err_open;
			}
		}

		/* See if we have a write we can do */
		if (FD_ISSET(sock, &wset)) {
			if ((!(txqueue.head) && !(txbuf.head)) || blocked)
				g_warning
				    ("Socket write FD set but we shouldn't have been interested");

			/* If there is no buffered data, generate some */
			if (!blocked && !(txbuf.head)
			    && (NULL != (prc = txqueue.head))) {
				if (ntohl(prc->req.magic) != NBD_REQUEST_MAGIC) {
					g_warning
					    ("Asked to write a request without a magic number");
					goto err_open;
				}

				command = ntohl(prc->req.type);
				from = ntohll(prc->req.from);
				len = ntohl(prc->req.len);

				/* First check whether we can touch this command at all. If this
				 * command is a read, and there is an inflight write, OR if this
				 * command is a write, and there is an inflight read or write, then
				 * we need to leave the command alone and signal that we are blocked
				 */

				if (!looseordering) {
					uint64_t cfrom;
					uint32_t clen;
					cfrom = from;
					clen = len;
					while (clen > 0) {
						uint64_t blknum = cfrom >> 9;
						if (cfrom >= size) {
							snprintf(errstr,
								 errstr_len,
								 "offset %llx beyond size %llx",
								 (long long int)
								 cfrom,
								 (long long int)
								 size);
							goto err_open;
						}
						if (blkhash[blknum].inflightw ||
						    (blkhash[blknum].inflightr
						     &&
						     ((command &
						       NBD_CMD_MASK_COMMAND) ==
						      NBD_CMD_WRITE))) {
							blocked = 1;
							break;
						}
						cfrom += 512;
						clen -= 512;
					}
				}

				if (blocked)
					goto skipdequeue;

				rclist_unlink(&txqueue, prc);
				rclist_addtail(&inflight, prc);

				dumpcommand("Sending command", prc->req.type);
				/* we rewrite the cookie as they otherwise may not be unique */
				prc->req.cookie = getrandomcookie(cookiehash);
				g_hash_table_insert(cookiehash, &prc->req.cookie,
						    prc);
				addbuffer(&txbuf, &(prc->req),
					  sizeof(struct nbd_request));
				switch (command & NBD_CMD_MASK_COMMAND) {
				case NBD_CMD_WRITE:
					xfer += len;
					while (len > 0) {
						uint64_t blknum = from >> 9;
						char dbuf[512];
						if (from >= size) {
							snprintf(errstr,
								 errstr_len,
								 "offset %llx beyond size %llx",
								 (long long int)
								 from,
								 (long long int)
								 size);
							goto err_open;
						}
						(blkhash[blknum].inflightw)++;
						/* work out what we should be writing */
						makebuf(dbuf, prc->seq, blknum);
						addbuffer(&txbuf, dbuf, 512);
						from += 512;
						len -= 512;
					}
					break;
				case NBD_CMD_READ:
					xfer += len;
					while (len > 0) {
						uint64_t blknum = from >> 9;
						if (from >= size) {
							snprintf(errstr,
								 errstr_len,
								 "offset %llx beyond size %llx",
								 (long long int)
								 from,
								 (long long int)
								 size);
							goto err_open;
						}
						(blkhash[blknum].inflightr)++;
						from += 512;
						len -= 512;
					}
					break;
				case NBD_CMD_DISC:
				case NBD_CMD_FLUSH:
					break;
				default:
					snprintf(errstr, errstr_len,
						 "Incomprehensible command: %08x",
						 command);
					goto err_open;
					break;
				}

				prc = NULL;
			}
skipdequeue:

			/* there should be some now */
			if (writebuffer(sock, &txbuf) < 0) {
				snprintf(errstr, errstr_len,
					 "Failed to write to socket buffer: %s",
					 strerror(errno));
				goto err_open;
			}

		}

		/* See if there is a reply to be processed from the socket */
		if (FD_ISSET(sock, &rset)) {
			/* Okay, there's something ready for
			 * reading here */

			READ_ALL_ERRCHK(sock,
					&rep,
					sizeof(struct nbd_reply),
					err_open,
					"Could not read from server socket: %s",
					strerror(errno));

			if (rep.magic != htonl(NBD_REPLY_MAGIC)) {
				snprintf(errstr, errstr_len,
					 "Bad magic from server");
				goto err_open;
			}

			if (rep.error) {
				snprintf(errstr, errstr_len,
					 "Server errored a transaction");
				goto err_open;
			}

			uint64_t cookie;
			cookie = rep.cookie;
			prc = g_hash_table_lookup(cookiehash, &cookie);
			if (!prc) {
				snprintf(errstr, errstr_len,
					 "Unrecognised cookie in reply: 0x%llX",
					 (long long unsigned int)rep.cookie);
				goto err_open;
			}
			if (!g_hash_table_remove(cookiehash, &cookie)) {
				snprintf(errstr, errstr_len,
					 "Could not remove cookie from hash: 0x%llX",
					 (long long unsigned int)rep.cookie);
				goto err_open;
			}

			if (prc->req.magic != htonl(NBD_REQUEST_MAGIC)) {
				snprintf(errstr, errstr_len,
					 "Bad magic in inflight data: %08x",
					 prc->req.magic);
				goto err_open;
			}

			dumpcommand("Processing reply to command",
				    prc->req.type);
			command = ntohl(prc->req.type);
			from = ntohll(prc->req.from);
			len = ntohl(prc->req.len);

			switch (command & NBD_CMD_MASK_COMMAND) {
			case NBD_CMD_READ:
				while (len > 0) {
					uint64_t blknum = from >> 9;
					char dbuf[512];
					if (from >= size) {
						snprintf(errstr, errstr_len,
							 "offset %llx beyond size %llx",
							 (long long int)from,
							 (long long int)size);
						goto err_open;
					}
					READ_ALL_ERRCHK(sock,
							dbuf,
							512,
							err_open,
							"Could not read data: %s",
							strerror(errno));
					if (--(blkhash[blknum].inflightr) < 0) {
						snprintf(errstr, errstr_len,
							 "Received a read reply for offset %llx when not in flight",
							 (long long int)from);
						goto err_open;
					}
					/* work out what we was written */
					if (checkbuf
					    (dbuf, blkhash[blknum].seq,
					     blknum)) {
						snprintf(errstr, errstr_len,
							 "Bad reply data: I wanted blk %08x, seq %08x but I got (at a guess) blk %08x, seq %08x",
							 (unsigned int)blknum,
							 blkhash[blknum].seq,
							 ((uint32_t
							   *) (dbuf))[0],
							 ((uint32_t
							   *) (dbuf))[1]
						    );
						goto err_open;

					}
					from += 512;
					len -= 512;
				}
				break;
			case NBD_CMD_WRITE:
				/* subsequent reads should get data with this seq */
				while (len > 0) {
					uint64_t blknum = from >> 9;
					if (--(blkhash[blknum].inflightw) < 0) {
						snprintf(errstr, errstr_len,
							 "Received a write reply for offset %llx when not in flight",
							 (long long int)from);
						goto err_open;
					}
					blkhash[blknum].seq =
					    (uint32_t) (prc->seq);
					from += 512;
					len -= 512;
				}
				break;
			default:
				break;
			}
			blocked = 0;
			processed++;
			rclist_unlink(&inflight, prc);
			prc->req.magic = 0;	/* so a duplicate reply is detected */
			free(prc);
		}

		if ((do_print == NULL && !(printer++ % 5000))
		    || !(readtransactionfile || txqueue.numitems
			 || inflight.numitems))
			printf
			    ("%d: Seq %08lld Queued: %08d Inflight: %08d Done: %08lld\r",
			     (int)mypid, (long long int)seq, txqueue.numitems,
			     inflight.numitems, (long long int)processed);

	}

	printf("\n");

	if (gettimeofday(&stop, NULL) < 0) {
		snprintf(errstr, errstr_len, "Could not measure end time: %s",
			 strerror(errno));
		goto err_open;
	}
	timespan = timeval_diff_to_double(&stop, &start);
	speed = xfer / timespan;
	if (speed > 1024) {
		speed = speed / 1024.0;
		speedchar[0] = 'K';
	}
	if (speed > 1024) {
		speed = speed / 1024.0;
		speedchar[0] = 'M';
	}
	if (speed > 1024) {
		speed = speed / 1024.0;
		speedchar[0] = 'G';
	}
	g_message
	    ("%d: Integrity %s test complete. Took %.3f seconds to complete, %.3f%sib/s",
	     (int)getpid(), (testflags & TEST_WRITE) ? "write" : "read",
	     timespan, speed, speedchar);

	retval = 0;

err_open:
	if (close_sock) {
		close_connection(sock, CONNECTION_CLOSE_PROPERLY);
	}
err:
	if (size && blkhash)
		munmap(blkhash, (size >> 9) * sizeof(struct blkitem));

	if (blkhashfd != -1)
		close(blkhashfd);

	if (logfd != -1)
		close(logfd);

	if (blkhashname)
		free(blkhashname);

	if (*errstr)
		g_warning("%s", errstr);

	g_hash_table_destroy(cookiehash);

	return retval;
}

void handle_nonopt(char *opt, gchar ** hostname, long int *p)
{
	static int nonopt = 0;

	switch (nonopt) {
	case 0:
		*hostname = g_strdup(opt);
		nonopt++;
		break;
	case 1:
		*p = (strtol(opt, NULL, 0));
		if (*p == LONG_MIN || *p == LONG_MAX) {
			g_critical("Could not parse port number: %s",
				   strerror(errno));
			exit(EXIT_FAILURE);
		}
		break;
	}
}

typedef int (*testfunc) (char *, int, char, int);

int main(int argc, char **argv)
{
	gchar *hostname = NULL, *unixsock = NULL;
	long int p = 10809;
	char *name = NULL;
	int sock = -1;
	int c;
	int testflags = 0;
	testfunc test = throughput_test;

#if HAVE_GNUTLS
	tlssession_init();
#endif

	/* Ignore SIGPIPE as we want to pick up the error from write() */
	signal(SIGPIPE, SIG_IGN);

	errstr[errstr_len] = '\0';

	if (argc < 3) {
		g_message("%d: Not enough arguments", (int)getpid());
		g_message("%d: Usage: %s <hostname> <port>", (int)getpid(),
			  argv[0]);
		g_message("%d: Or: %s <hostname> -N <exportname> [<port>]",
			  (int)getpid(), argv[0]);
		g_message("%d: Or: %s -u <unix socket> -N <exportname>",
			  (int)getpid(), argv[0]);
		exit(EXIT_FAILURE);
	}
	logging(MY_NAME);
	while ((c = getopt(argc, argv, "FN:t:owfilu:hC:K:A:H:I")) >= 0) {
		switch (c) {
		case 1:
			handle_nonopt(optarg, &hostname, &p);
			break;
		case 'N':
			name = g_strdup(optarg);
			break;
		case 'F':
			testflags |= TEST_EXPECT_ERROR;
			break;
		case 't':
			transactionlog = g_strdup(optarg);
			break;
		case 'o':
			test = oversize_test;
			break;
		case 'l':
			looseordering = 1;
			break;
		case 'w':
			testflags |= TEST_WRITE;
			break;
		case 'f':
			testflags |= TEST_FLUSH;
			break;
		case 'I':
#ifndef ISSERVER
			err_nonfatal("inetd mode not supported without syslog support");
			return 77;
#else
			p = -1;
			break;
#endif
		case 'i':
			test = integrity_test;
			break;
		case 'u':
			unixsock = g_strdup(optarg);
			break;
		case 'h':
			test = handshake_test;
			break;
#if HAVE_GNUTLS
		case 'C':
			certfile=g_strdup(optarg);
			break;
		case 'K':
			keyfile=g_strdup(optarg);
			break;
		case 'A':
			cacertfile=g_strdup(optarg);
			break;
		case 'H':
			tlshostname=g_strdup(optarg);
			break;
#else
		case 'C':
		case 'K':
		case 'H':
		case 'A':
			g_warning("TLS support not compiled in");
			/* Do not change this - looked for by test suite */
			exit(77);
#endif
		}
	}

	if (p != -1) {
		while (optind < argc) {
			handle_nonopt(argv[optind++], &hostname, &p);
		}
	}

	if (keyfile && !certfile)
		certfile = g_strdup(keyfile);

	if (!tlshostname && hostname)
		tlshostname = g_strdup(hostname);

	if (hostname != NULL) {
		sock = setup_inet_connection(hostname, p);
	} else if (unixsock != NULL) {
		sock = setup_unix_connection(unixsock);
	} else if (p == -1) {
		sock = setup_inetd_connection(argv + optind);
	} else {
		g_error("need a hostname, a unix domain socket or inetd-mode command line!");
		return -1;
	}

	if (sock == -1) {
		g_warning("Could not establish a connection: %s", errstr);
		exit(EXIT_FAILURE);
	}

	if (test(name, sock, TRUE, testflags)
	    < 0) {
		g_warning("Could not run test: %s", errstr);
		exit(EXIT_FAILURE);
	}

	return 0;
}
