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
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include "netdb-compat.h"
#include <inttypes.h>
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
#include <stdbool.h>
#include <time.h>

#include <linux/ioctl.h>
#define MY_NAME "nbd_client"
#include "cliserv.h"

#if HAVE_GNUTLS && !defined(NOTLS)
#include "crypto-gnutls.h"
#endif

#ifdef WITH_SDP
#include <sdp_inet.h>
#endif

#define NBDC_DO_LIST 1

/* tcp keepalive frequency */
int tcpkeepalive = 0;

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
	if(len < 0) {
		perror("could not read from server");
		close(fd);
		return 2;
	}
	buf[(len < 256) ? len : 255]='\0';
	if(do_print) printf("%s\n", buf);
	close(fd);
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
			
		close(sock);
	}

	if (rp == NULL) {
		err_nonfatal("Socket failed: %m");
		sock = -1;
		goto err;
	}

	setmysockopt(sock);

	if (tcpkeepalive > 0) {
		int optval = 1;
		socklen_t optlen = sizeof(optval);
		if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
			err_nonfatal("Failed to set SO_KEEPALIVE: %m");
			sock = -1;
			goto err;
		}
#ifdef TCP_KEEPIDLE
		if (ioctl(sock, TCP_KEEPIDLE, tcpkeepalive) == -1) {
			err_nonfatal("Failed to set TCP_KEEPIDLE: %m");
			sock = -1;
			goto err;
		}
#endif
#ifdef TCP_KEEPINTVL
		if (ioctl(sock, TCP_KEEPINTVL, tcpkeepalive) == -1) {
			err_nonfatal("Failed to set TCP_KEEPINTVL: %m");
			sock = -1;
			goto err;
		}
#endif
	}

err:
	freeaddrinfo(ai);
	return sock;
}

int openunix(const char *path) {
	int sock;
	struct sockaddr_un un_addr;
	memset(&un_addr, 0, sizeof(un_addr));

	un_addr.sun_family = AF_UNIX;
	if (strnlen(path, sizeof(un_addr.sun_path)) == sizeof(un_addr.sun_path)) {
		err_nonfatal("UNIX socket path too long");
		return -1;
	}

	strncpy(un_addr.sun_path, path, sizeof(un_addr.sun_path) - 1);

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		err_nonfatal("SOCKET failed");
		return -1;
	};

	if (connect(sock, &un_addr, sizeof(un_addr)) == -1) {
		err_nonfatal("CONNECT failed");
		close(sock);
		return -1;
	}
	return sock;
}

void send_request(int sock, uint32_t opt, ssize_t datasize, void* data) {
	struct {
		uint64_t magic;
		uint32_t opt;
		uint32_t datasize;
	} __attribute__((packed)) header = {
		ntohll(opts_magic),
		ntohl(opt),
		ntohl(datasize),
	};
	if(datasize < 0) {
		datasize = strlen((char*)data);
		header.datasize = htonl(datasize);
	}
	writeit(sock, &header, sizeof(header));
	if(data != NULL) {
		writeit(sock, data, datasize);
	}
}

void send_info_request(int sock, uint32_t opt, int n_reqs, uint16_t* reqs, char* name) {
	uint16_t rlen = htons(n_reqs);
	uint32_t nlen = htonl(strlen(name));

	send_request(sock, opt, sizeof(uint32_t) + strlen(name) + sizeof(uint16_t) + n_reqs * sizeof(uint16_t), NULL);
	writeit(sock, &nlen, sizeof(nlen));
	writeit(sock, name, strlen(name));
	writeit(sock, &rlen, sizeof(rlen));
	if(n_reqs > 0) {
		writeit(sock, reqs, n_reqs * sizeof(uint16_t));
	}
}

struct reply {
	uint64_t magic;
	uint32_t opt;
	uint32_t reply_type;
	uint32_t datasize;
	char data[];
} __attribute__((packed));

struct reply* read_reply(int sock) {
	struct reply *retval = malloc(sizeof(struct reply));
	readit(sock, retval, sizeof(*retval));
	retval->magic = ntohll(retval->magic);
	retval->opt = ntohl(retval->opt);
	retval->reply_type = ntohl(retval->reply_type);
	retval->datasize = ntohl(retval->datasize);
	if (retval->magic != rep_magic) {
		fprintf(stderr, "E: received invalid negotiation magic %" PRIu64 " (expected %" PRIu64 ")", retval->magic, rep_magic);
		exit(EXIT_FAILURE);
	}
	if (retval->datasize > 0) {
		retval = realloc(retval, sizeof(struct reply) + retval->datasize);
		readit(sock, &(retval->data), retval->datasize);
	}
	return retval;
}

void ask_list(int sock) {
	uint32_t opt;
	uint32_t opt_server;
	uint32_t len;
	uint32_t lenn;
	uint32_t reptype;
	uint64_t magic;
	int rlen;
	const int BUF_SIZE = 1024;
	char buf[BUF_SIZE];

	send_request(sock, NBD_OPT_LIST, 0, NULL);
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
			if(len > 0 && len < BUF_SIZE) {
				if((rlen=read(sock, buf, len)) < 0) {
					fprintf(stderr, "\nE: could not read error message from server\n");
				} else {
					buf[rlen] = '\0';
					fprintf(stderr, "Server said: %s\n", buf);
				}
			}
			exit(EXIT_FAILURE);
		} else {
			if(reptype != NBD_REP_ACK) {
				if(reptype != NBD_REP_SERVER) {
					err("Server sent us a reply we don't understand!");
				}
				if(read(sock, &lenn, sizeof(lenn)) < 0) {
					fprintf(stderr, "\nE: could not read export name length from server\n");
					exit(EXIT_FAILURE);
				}
				lenn=ntohl(lenn);
				if (lenn >= BUF_SIZE) {
					fprintf(stderr, "\nE: export name on server too long\n");
					exit(EXIT_FAILURE);
				}
				if(read(sock, buf, lenn) < 0) {
					fprintf(stderr, "\nE: could not read export name from server\n");
					exit(EXIT_FAILURE);
				}
				buf[lenn] = 0;
				printf("%s", buf);
				len -= lenn;
				len -= sizeof(lenn);
				if(len > 0) {
					if(read(sock, buf, len) < 0) {
						fprintf(stderr, "\nE: could not read export description from server\n");
						exit(EXIT_FAILURE);
					}
					buf[len] = 0;
					printf(": %s\n", buf);
				} else {
					printf("\n");
				}
			}
		}
	} while(reptype != NBD_REP_ACK);
	send_request(sock, NBD_OPT_ABORT, 0, NULL);
}

void parse_sizes(char *buf, uint64_t *size, uint16_t *flags) {
	memcpy(size, buf, sizeof(*size));
	*size = ntohll(*size);
	buf += sizeof(size);
	memcpy(flags, buf, sizeof(*flags));
	*flags = ntohs(*flags);

	if ((*size>>12) > (uint64_t)~0UL) {
		printf("size = %luMB", (unsigned long)(*size>>20));
		err("Exported device is too big for me. Get 64-bit machine :-(\n");
	} else {
		printf("size = %luMB", (unsigned long)(*size>>20));
	}
	printf("\n");
}

void negotiate(int *sockp, u64 *rsize64, uint16_t *flags, char* name, uint32_t needed_flags, uint32_t client_flags, uint32_t do_opts, char *certfile, char *keyfile, char *cacertfile, char *tlshostname, bool tls) {
	u64 magic;
	uint16_t tmp;
	uint16_t global_flags;
	char buf[256] = "\0\0\0\0\0\0\0\0\0";
	uint32_t opt;
	uint32_t namesize;
	int sock = *sockp;

	printf("Negotiation: ");
	readit(sock, buf, 8);
	if (strcmp(buf, INIT_PASSWD))
		err("INIT_PASSWD bad");
	printf(".");
	readit(sock, &magic, sizeof(magic));
	magic = ntohll(magic);
	if (magic != opts_magic) {
		if(magic == cliserv_magic) {
			err("It looks like you're trying to connect to an oldstyle server. This is no longer supported since nbd 3.10.");
		}
	}
	printf(".");
	readit(sock, &tmp, sizeof(uint16_t));
	global_flags = ntohs(tmp);
	if((needed_flags & global_flags) != needed_flags) {
		/* There's currently really only one reason why this
		 * check could possibly fail, but we may need to change
		 * this error message in the future... */
		fprintf(stderr, "\nE: Server does not support listing exports\n");
		exit(EXIT_FAILURE);
	}

	if (global_flags & NBD_FLAG_NO_ZEROES) {
		client_flags |= NBD_FLAG_C_NO_ZEROES;
	}
	client_flags = htonl(client_flags);
	if (write(sock, &client_flags, sizeof(client_flags)) < 0)
		err("Failed/2.1: %m");

#if HAVE_GNUTLS && !defined(NOTLS)
        /* TLS */
        if (tls) {
		int plainfd[2]; // [0] is used by the proxy, [1] is used by NBD
		tlssession_t *s = NULL;
		int ret;
		uint32_t tmp32;
		uint64_t tmp64;

		send_request(sock, NBD_OPT_STARTTLS, 0, NULL);

		if (read(sock, &tmp64, sizeof(tmp64)) < 0)
			err("Could not read cliserv_magic: %m");
		tmp64 = ntohll(tmp64);
		if (tmp64 != NBD_OPT_REPLY_MAGIC) {
			err("reply magic does not match");
		}
		if (read(sock, &tmp32, sizeof(tmp32)) < 0)
			err("Could not read option type: %m");
		tmp32 = ntohl(tmp32);
		if (tmp32 != NBD_OPT_STARTTLS)
			err("Reply to wrong option");
		if (read(sock, &tmp32, sizeof(tmp32)) < 0)
			err("Could not read option reply type: %m");
		tmp32 = ntohl(tmp32);
		if (tmp32 != NBD_REP_ACK) {
			err("Option reply type != NBD_REP_ACK");
		}
		if (read(sock, &tmp32, sizeof(tmp32)) < 0) err(
			"Could not read option data length: %m");
		tmp32 = ntohl(tmp32);
		if (tmp32 != 0) {
			err("Option reply data length != 0");
		}
		s = tlssession_new(0,
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
				   NULL, // erroutfn
				   NULL // opaque
			);
		if (!s)
			err("Cannot establish TLS session");

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, plainfd) < 0)
			err("Cannot get socket pair");

		if (set_nonblocking(plainfd[0], 0) <0 ||
		    set_nonblocking(plainfd[1], 0) <0 ||
		    set_nonblocking(sock, 0) <0) {
			close(plainfd[0]);
			close(plainfd[1]);
			err("Cannot set socket options");
		}

		ret = fork();
		if (ret < 0)
			err("Could not fork");
		else if (ret == 0) {
			// we are the child
			if (daemon(0, 0) < 0) {
				/* no one will see this */
				fprintf(stderr, "Can't detach from the terminal");
				exit(1);
			}
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
		*sockp = sock;
	}
#else
	if (keyfile) {
		err("TLS requested but support not compiled in");
	}
#endif

	if(do_opts & NBDC_DO_LIST) {
		ask_list(sock);
		exit(EXIT_SUCCESS);
	}

	send_info_request(sock, NBD_OPT_GO, 0, NULL, name);

	struct reply *rep = NULL;
	
	do {
		if(rep != NULL) free(rep);
		rep = read_reply(sock);
		if(rep->reply_type & NBD_REP_FLAG_ERROR) {
			if(rep->reply_type == NBD_REP_ERR_UNSUP) {
				free(rep);
				/* server doesn't support NBD_OPT_GO or NBD_OPT_INFO,
				 * fall back to NBD_OPT_EXPORT_NAME */
				send_request(sock, NBD_OPT_EXPORT_NAME, -1, name);
				char b[sizeof(*flags) + sizeof(*rsize64)];
				readit(sock, b, sizeof(b));
				parse_sizes(b, rsize64, flags);
				if(!(global_flags & NBD_FLAG_NO_ZEROES)) {
					readit(sock, buf, 124);
				}
				return;
			} else {
				err("Unknown error in reply to NBD_OPT_GO; cannot continue");
				exit(EXIT_FAILURE);
			}
		}
		uint16_t info_type;
		switch(rep->reply_type) {
			case NBD_REP_INFO:
				memcpy(&info_type, rep->data, 2);
				info_type = htons(info_type);
				switch(info_type) {
					case NBD_INFO_EXPORT:
						parse_sizes(rep->data + 2, rsize64, flags);
						break;
					default:
						// ignore these, don't need them
						break;
				}
				break;
			case NBD_REP_ACK:
				break;
			default:
				err_nonfatal("Unknown reply to NBD_OPT_GO received");
		}
	} while(rep->reply_type != NBD_REP_ACK);
	free(rep);
}

bool get_from_config(char* cfgname, char** name_ptr, char** dev_ptr, char** hostn_ptr, int* bs, int* timeout, int* persist, int* swap, int* sdp, int* b_unix, char**port, int* num_conns, char **certfile, char **keyfile, char **cacertfile, char **tlshostname) {
	int fd = open(SYSCONFDIR "/nbdtab", O_RDONLY);
	bool retval = false;
	if(fd < 0) {
		fprintf(stderr, "while opening %s: ", SYSCONFDIR "/nbdtab");
		perror("could not open config file");
		goto out;
	}
	off_t size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	void *data = NULL;
	char *fsep = "\n\t# ";
	char *lsep = "\n#";

	if(size < 0) {
		perror("E: mmap'ing nbdtab");
		exit(EXIT_FAILURE);
	}

	data = mmap(NULL, (size_t)size, PROT_READ, MAP_SHARED, fd, 0);
	if(!strncmp(cfgname, "/dev/", 5)) {
		cfgname += 5;
	}
	char *loc = strstr((const char*)data, cfgname);
	if(!loc) {
		goto out;
	}
	size_t l = strlen(cfgname) + 6;
	*dev_ptr = malloc(l);
	snprintf(*dev_ptr, l, "/dev/%s", cfgname);

	size_t line_len, field_len, ws_len;
#define CHECK_LEN field_len = strcspn(loc, fsep); ws_len = strspn(loc+field_len, fsep); if(field_len > line_len || line_len <= 0) { goto out; }
#define MOVE_NEXT line_len -= field_len + ws_len; loc += field_len + ws_len
	// find length of line
	line_len = strcspn(loc, lsep);
	// first field is the device node name, which we already know, so skip it
	CHECK_LEN;
	MOVE_NEXT;
	// next field is the hostname
	CHECK_LEN;
	*hostn_ptr = strndup(loc, field_len);
	MOVE_NEXT;
	// third field is the export name
	CHECK_LEN;
	*name_ptr = strndup(loc, field_len);
	if(ws_len + field_len > line_len) {
		// optional last field is not there, so return success
		retval = true;
		goto out;
	}
	MOVE_NEXT;
	CHECK_LEN;
#undef CHECK_LEN
#undef MOVE_NEXT
	// fourth field is the options field, a comma-separated field of options
	do {
		if(!strncmp(loc, "conns=", 6)) {
			*num_conns = (int)strtol(loc+6, &loc, 0);
			goto next;
		}
		if(!strncmp(loc, "bs=", 3)) {
			*bs = (int)strtol(loc+3, &loc, 0);
			goto next;
		}
		if(!strncmp(loc, "timeout=", 8)) {
			*timeout = (int)strtol(loc+8, &loc, 0);
			goto next;
		}
		if(!strncmp(loc, "port=", 5)) {
			*port = strndup(loc+5, strcspn(loc+5, ","));
			goto next;
		}
		if(!strncmp(loc, "persist", 7)) {
			loc += 7;
			*persist = 1;
			goto next;
		}
		if(!strncmp(loc, "swap", 4)) {
			*swap = 1;
			loc += 4;
			goto next;
		}
		if(!strncmp(loc, "sdp", 3)) {
			*sdp = 1;
			loc += 3;
			goto next;
		}
		if(!strncmp(loc, "unix", 4)) {
			*b_unix = 1;
			loc += 4;
			goto next;
		}
		if(!strncmp(loc, "certfile=", 9)) {
			*certfile = strndup(loc+9, strcspn(loc+9, ","));
			goto next;
		}
		if(!strncmp(loc, "keyfile=", 8)) {
			*keyfile = strndup(loc+8, strcspn(loc+8, ","));
			goto next;
		}
		if(!strncmp(loc, "cacertfile=", 11)) {
			*cacertfile = strndup(loc+11, strcspn(loc+11, ","));
			goto next;
		}
		if(!strncmp(loc, "tlshostname=", 9)) {
			*tlshostname = strndup(loc+9, strcspn(loc+9, ","));
			goto next;
		}
		// skip unknown options, with a warning unless they start with a '_'
		l = strcspn(loc, ",");
		if(*loc != '_') {
			char* s = strndup(loc, l);
			fprintf(stderr, "Warning: unknown option '%s' found in nbdtab file", s);
			free(s);
		}
		loc += l;
next:
		if(*loc == ',') {
			loc++;
		}
	} while(strcspn(loc, lsep) > 0);
	retval = true;
out:
	if(data != NULL) {
		munmap(data, size);
	}
	if(fd >= 0) {
		close(fd);
	}
	return retval;
}

void setsizes(int nbd, u64 size64, int blocksize, u32 flags) {
	unsigned long size;
	int read_only = (flags & NBD_FLAG_READ_ONLY) ? 1 : 0;

	if (size64>>12 > (uint64_t)~0UL)
		err("Device too large.\n");
	else {
		int tmp_blocksize = 4096;
		if (size64 / (u64)blocksize <= (uint64_t)~0UL)
			tmp_blocksize = blocksize;
		if (ioctl(nbd, NBD_SET_BLKSIZE, tmp_blocksize) < 0) {
			fprintf(stderr, "Failed to set blocksize %d\n",
				tmp_blocksize);
			err("Ioctl/1.1a failed: %m\n");
		}
		size = (unsigned long)(size64 / (u64)tmp_blocksize);
		if (ioctl(nbd, NBD_SET_SIZE_BLOCKS, size) < 0)
			err("Ioctl/1.1b failed: %m\n");
		if (tmp_blocksize != blocksize) {
			if (ioctl(nbd, NBD_SET_BLKSIZE, (unsigned long)blocksize) < 0) {
				fprintf(stderr, "Failed to set blocksize %d\n",
					blocksize);
				err("Ioctl/1.1c failed: %m\n");
			}
		}
		fprintf(stderr, "bs=%d, sz=%" PRIu64 " bytes\n", blocksize, (u64)tmp_blocksize * size);
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
	if (ioctl(nbd, NBD_SET_SOCK, sock) < 0) {
		if (errno == EBUSY)
			err("Kernel doesn't support multiple connections\n");
		else
			err("Ioctl NBD_SET_SOCK failed: %m\n");
	}

#ifndef __ANDROID__
	if (swap)
		mlockall(MCL_CURRENT | MCL_FUTURE);
#endif
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
	fprintf(stderr, "Usage: nbd-client -name|-N name host [port] nbd_device\n\t[-block-size|-b block size] [-timeout|-t timeout] [-swap|-s] [-sdp|-S]\n\t[-persist|-p] [-nofork|-n] [-systemd-mark|-m]\n");
	fprintf(stderr, "Or   : nbd-client -u (with same arguments as above)\n");
	fprintf(stderr, "Or   : nbd-client nbdX\n");
	fprintf(stderr, "Or   : nbd-client -d nbd_device\n");
	fprintf(stderr, "Or   : nbd-client -c nbd_device\n");
	fprintf(stderr, "Or   : nbd-client -h|--help\n");
	fprintf(stderr, "Or   : nbd-client -l|--list host\n");
#if HAVE_GNUTLS && !defined(NOTLS)
	fprintf(stderr, "All commands that connect to a host also take:\n\t[-F|-certfile certfile] [-K|-keyfile keyfile]\n\t[-A|-cacertfile cacertfile] [-H|-tlshostname hostname] [-x|-enable-tls]\n");
#endif
	fprintf(stderr, "Default value for blocksize is 1024 (recommended for ethernet)\n");
	fprintf(stderr, "Allowed values for blocksize are 512,1024,2048,4096\n"); /* will be checked in kernel :) */
	fprintf(stderr, "Note, that kernel 2.4.2 and older ones do not work correctly with\n");
	fprintf(stderr, "blocksizes other than 1024 without patches\n");
	fprintf(stderr, "Default value for port is 10809. Note that port must always be numeric\n");
}

void disconnect(char* device) {
	int nbd = open(device, O_RDWR);

	if (nbd < 0)
		err("Cannot open NBD: %m\nPlease ensure the 'nbd' module is loaded.");
	printf("disconnect, ");
	if (ioctl(nbd, NBD_DISCONNECT)<0)
		err("Ioctl failed: %m\n");
	printf("sock, ");
	if (ioctl(nbd, NBD_CLEAR_SOCK)<0)
		err("Ioctl failed: %m\n");
	printf("done\n");
}

int main(int argc, char *argv[]) {
	char* port=NBD_DEFAULT_PORT;
	int sock, nbd;
	int blocksize=1024;
	char *hostname=NULL;
	char *nbddev=NULL;
	int swap=0;
	int cont=0;
	int timeout=0;
	int sdp=0;
	int G_GNUC_UNUSED nofork=0; // if -dNOFORK
	pid_t main_pid;
	u64 size64;
	uint16_t flags = 0;
	int c;
	int nonspecial=0;
	int b_unix=0;
	char* name="";
	uint16_t needed_flags=0;
	uint32_t cflags=NBD_FLAG_C_FIXED_NEWSTYLE;
	uint32_t opts=0;
	sigset_t block, old;
	char *certfile = NULL;
	char *keyfile = NULL;
	char *cacertfile = NULL;
	char *tlshostname = NULL;
	bool tls = false;
	struct sigaction sa;
	int num_connections = 1;
	struct option long_options[] = {
		{ "block-size", required_argument, NULL, 'b' },
		{ "check", required_argument, NULL, 'c' },
		{ "connections", required_argument, NULL, 'C'},
		{ "disconnect", required_argument, NULL, 'd' },
		{ "help", no_argument, NULL, 'h' },
		{ "list", no_argument, NULL, 'l' },
		{ "name", required_argument, NULL, 'N' },
		{ "nofork", no_argument, NULL, 'n' },
		{ "persist", no_argument, NULL, 'p' },
		{ "sdp", no_argument, NULL, 'S' },
		{ "swap", no_argument, NULL, 's' },
		{ "systemd-mark", no_argument, NULL, 'm' },
		{ "timeout", required_argument, NULL, 't' },
		{ "unix", no_argument, NULL, 'u' },
		{ "certfile", required_argument, NULL, 'F' },
		{ "keyfile", required_argument, NULL, 'K' },
		{ "cacertfile", required_argument, NULL, 'A' },
		{ "tlshostname", required_argument, NULL, 'H' },
		{ "enable-tls", no_argument, NULL, 'x' },
		{ "keepalive", required_argument, NULL, 'k' },
		{ 0, 0, 0, 0 }, 
	};
	int i;

	logging(MY_NAME);

#if HAVE_GNUTLS && !defined(NOTLS)
        tlssession_init();
#endif

	while((c=getopt_long_only(argc, argv, "-b:c:d:hlnN:pSst:uC:K:A:H:xk:", long_options, NULL))>=0) {
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
						// not parseable as a number, assume it's the device
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
		case 'C':
			num_connections = (int)strtol(optarg, NULL, 0);
			break;
		case 'd':
			disconnect(optarg);
			exit(EXIT_SUCCESS);
		case 'h':
			usage(NULL);
			exit(EXIT_SUCCESS);
		case 'l':
			needed_flags |= NBD_FLAG_FIXED_NEWSTYLE;
			opts |= NBDC_DO_LIST;
			nbddev="";
			break;
		case 'm':
			argv[0][0] = '@';
			break;
		case 'n':
			nofork=1;
			break;
		case 'N':
			name=optarg;
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
		case 'u':
			b_unix = 1;
			break;
#if HAVE_GNUTLS && !defined(NOTLS)
		case 'x':
			tls = true;
			break;
                case 'F':
                        certfile=strdup(optarg);
                        break;
                case 'K':
                        keyfile=strdup(optarg);
                        break;
                case 'A':
                        cacertfile=strdup(optarg);
                        break;
                case 'H':
                        tlshostname=strdup(optarg);
                        break;
#else
                case 'F':
                case 'K':
                case 'H':
                case 'A':
			fprintf(stderr, "E: TLS support not compiled in\n");
                        exit(EXIT_FAILURE);
#endif
		case 'k':
			tcpkeepalive = (int)strtol(optarg, NULL, 0);
			break;
		default:
			fprintf(stderr, "E: option eaten by 42 mice\n");
			exit(EXIT_FAILURE);
		}
	}

#ifdef __ANDROID__
  if (swap)
    err("swap option unsupported on Android because mlockall is unsupported.");
#endif
	if(hostname) {
		if((!name || !nbddev) && !(opts & NBDC_DO_LIST)) {
			if(!strncmp(hostname, "nbd", 3) || !strncmp(hostname, "/dev/nbd", 8)) {
				if(!get_from_config(hostname, &name, &nbddev, &hostname, &blocksize, &timeout, &cont, &swap, &sdp, &b_unix, &port, &num_connections, &certfile, &keyfile, &cacertfile, &hostname)) {
					usage("no valid configuration for specified device found", hostname);
					exit(EXIT_FAILURE);
				}
			} else {
				usage("not enough information specified, and argument didn't look like an nbd device");
				exit(EXIT_FAILURE);
			}
		}
	} else {
		usage("no information specified");
		exit(EXIT_FAILURE);
	}

        if (keyfile && !certfile)
		certfile = strdup(keyfile);

	if (certfile != NULL || keyfile != NULL || cacertfile != NULL || tlshostname != NULL) {
		tls = true;
	}

        if (!tlshostname && hostname)
                tlshostname = strdup(hostname);

	if(strlen(name)==0 && !(opts & NBDC_DO_LIST)) {
		printf("Warning: the oldstyle protocol is no longer supported.\nThis method now uses the newstyle protocol with a default export\n");
	}

	if(!(opts & NBDC_DO_LIST)) {
		nbd = open(nbddev, O_RDWR);
		if (nbd < 0)
			err("Cannot open NBD: %m\nPlease ensure the 'nbd' module is loaded.");
	}

	for (i = 0; i < num_connections; i++) {
		if (b_unix)
			sock = openunix(hostname);
		else
			sock = opennet(hostname, port, sdp);
		if (sock < 0)
			exit(EXIT_FAILURE);

		negotiate(&sock, &size64, &flags, name, needed_flags, cflags, opts, certfile, keyfile, cacertfile, tlshostname, tls);
		if (i == 0) {
			setsizes(nbd, size64, blocksize, flags);
			set_timeout(nbd, timeout);
		}
		finish_sock(sock, nbd, swap);
		if (swap) {
			if (keyfile)
				fprintf(stderr, "Warning: using swap and TLS is prone to deadlock\n");
			/* try linux >= 2.6.36 interface first */
			if (oom_adjust("/proc/self/oom_score_adj", "-1000")) {
				/* fall back to linux <= 2.6.35 interface */
				oom_adjust("/proc/self/oom_adj", "-17");
			}
		}
	}

	/* Go daemon */
	
#ifndef NOFORK
	if(!nofork) {
		if (daemon(0,0) < 0)
			err("Cannot detach from terminal");
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
#endif
	/* For child to check its parent */
	main_pid = getpid();
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
			struct timespec req = {
				.tv_sec = 0,
				.tv_nsec = 100000000,
			};
			while(check_conn(nbddev, 0)) {
				if (main_pid != getppid()) {
					/* check_conn() will not return 0 when nbd disconnected
					 * and parent exited during this loop. So the child has to
					 * explicitly check parent identity and exit if parent
					 * exited */
					exit(0);
				}
				nanosleep(&req, NULL);
			}
			if(open(nbddev, O_RDONLY) < 0) {
				perror("could not open device for updating partition table");
			}
			exit(0);
		}
#endif

		if (ioctl(nbd, NBD_DO_IT) < 0) {
			int error = errno;
			fprintf(stderr, "nbd,%d: Kernel call returned: %d", main_pid, error);
			if(error==EBADR) {
				/* The user probably did 'nbd-client -d' on us.
				 * quit */
				cont=0;
			} else {
				if(cont) {
					u64 new_size;
					uint16_t new_flags;

					close(sock); close(nbd);
					for (;;) {
						fprintf(stderr, " Reconnecting\n");
						if (b_unix)
							sock = openunix(hostname);
						else
							sock = opennet(hostname, port, sdp);
						if (sock >= 0)
							break;
						sleep (1);
					}
					nbd = open(nbddev, O_RDWR);
					if (nbd < 0)
						err("Cannot open NBD: %m");
					negotiate(&sock, &new_size, &new_flags, name, needed_flags, cflags, opts, certfile, keyfile, cacertfile, tlshostname, tls);
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
	printf("sock, ");
	ioctl(nbd, NBD_CLEAR_SOCK);
	printf("done\n");
	return 0;
}
