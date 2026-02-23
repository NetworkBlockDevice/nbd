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

#if HAVE_NETLINK
#include "nbd-netlink.h"
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#endif

#define MY_NAME "nbd_client"
#include "cliserv.h"

#if HAVE_GNUTLS && !defined(NOTLS)
#include "crypto-gnutls.h"
#endif

#include "nbdclt.h"
#include "nbdtab_parser.tab.h"

CLIENT* cur_client;
extern FILE *yyin, *yyout;
bool found_config = false;
bool parse_error = false;

#define SET_PROP(str, member, rval) if(!strcmp(property, str)) { cur_client->member = (rval); return; }
void nbdtab_set_property(char *property, char *val) {
	if(found_config) return;
	SET_PROP("port", port, val);
	SET_PROP("certfile", cert, val);
	SET_PROP("keyfile", key, val);
	SET_PROP("cacertfile", cacert, val);
	SET_PROP("tlshostname", tlshostn, val);
	SET_PROP("priority", priority, val);
	SET_PROP("bs", bs, strtol(val, NULL, 10));
	SET_PROP("timeout", timeout, strtol(val, NULL, 10));
	SET_PROP("dead-timeout", dead_conn_timeout, strtol(val, NULL, 10));
	SET_PROP("conns", nconn, strtol(val, NULL, 10));
	if(*property != '_') {
		fprintf(stderr, "Warning: unknown option '%s' found in nbdtab file", property);
	}
}
#undef SET_PROP

#define SET_FLAG(str, member) if(!strcmp(property, str)) { cur_client->member = true; return; }
void nbdtab_set_flag(char *property) {
	if(found_config) return;
	SET_FLAG("no_optgo", no_optgo);
	SET_FLAG("persist", persist);
	SET_FLAG("swap", swap);
	SET_FLAG("unix", b_unix);
	SET_FLAG("preinit", preinit);
	SET_FLAG("tls", tls);
	if(*property != '_') {
		fprintf(stderr, "Warning: unknown option '%s' found in nbdtab file", property);
	}
}

void nbdtab_commit_line(char *devn, char *hostn, char *exportname) {
	if(!strncmp(devn, "/dev/", 5)) {
		devn += 5;
	}
	if(!strcmp(cur_client->dev, devn)) {
		found_config = true;
		cur_client->hostn = hostn;
		cur_client->name = exportname;
	} else {
		if(!found_config) {
			char *tmp = cur_client->dev;
			memset(cur_client, 0, sizeof(CLIENT));
			cur_client->bs = 512;
			cur_client->nconn = 1;
			cur_client->dev = tmp;
		}
	}
	return;
}

void yyerror(char *msg) {
	parse_error = true;
	fprintf(stderr, "parse error parsing " SYSCONFDIR "/nbdtab: %s", msg);
}

#undef SET_FLAG

#define NBDC_DO_LIST 1

#if HAVE_NETLINK
static int callback(struct nl_msg *msg, void *arg) {
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *msg_attr[NBD_ATTR_MAX + 1];
	int ret;
	uint32_t index;

	ret = nla_parse(msg_attr, NBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL);
	if (ret)
		err("Invalid response from the kernel\n");
	if (!msg_attr[NBD_ATTR_INDEX])
		err("Did not receive index from the kernel\n");
	index = nla_get_u32(msg_attr[NBD_ATTR_INDEX]);
	printf("Connected /dev/nbd%d\n", (int)index);
	return NL_OK;
}

static struct nl_sock *get_nbd_socket(int *driver_id) {
	struct nl_sock *socket;

	socket = nl_socket_alloc();
	if (!socket)
		err("Couldn't allocate netlink socket\n");

	if (genl_connect(socket))
		err("Couldn't connect to the generic netlink socket\n");
	*driver_id = genl_ctrl_resolve(socket, "nbd");
	if (*driver_id < 0)
		err("Couldn't resolve the nbd netlink family, make sure the nbd module is loaded and your nbd driver supports the netlink interface.\n");
	return socket;
}

static void netlink_configure(int index, int *sockfds, uint16_t flags,
			      const char *identifier) {
	struct nl_sock *socket;
	struct nlattr *sock_attr;
	struct nl_msg *msg;
	int driver_id, i;
	int ret;

	socket = get_nbd_socket(&driver_id);
	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, callback, NULL);

	msg = nlmsg_alloc();
	if (!msg)
		err("Couldn't allocate netlink message\n");
	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
		    NBD_CMD_CONNECT, 0);
	if (index >= 0)
		NLA_PUT_U32(msg, NBD_ATTR_INDEX, index);
	NLA_PUT_U64(msg, NBD_ATTR_SIZE_BYTES, cur_client->size64);
	NLA_PUT_U64(msg, NBD_ATTR_BLOCK_SIZE_BYTES, cur_client->bs);
	NLA_PUT_U64(msg, NBD_ATTR_SERVER_FLAGS, flags);
	if (cur_client->timeout)
		NLA_PUT_U64(msg, NBD_ATTR_TIMEOUT, cur_client->timeout);
	if (cur_client->dead_conn_timeout)
		NLA_PUT_U64(msg, NBD_ATTR_DEAD_CONN_TIMEOUT, cur_client->dead_conn_timeout);
	else if (cur_client->persist_mode)
		NLA_PUT_U64(msg, NBD_ATTR_DEAD_CONN_TIMEOUT, 30); /* Default 30 seconds for persist mode */
	if (identifier)
		NLA_PUT_STRING(msg, NBD_ATTR_BACKEND_IDENTIFIER, identifier);

	sock_attr = nla_nest_start(msg, NBD_ATTR_SOCKETS);
	if (!sock_attr)
		err("Couldn't nest the sockets for our connection\n");
	for (i = 0; i < cur_client->nconn; i++) {
		struct nlattr *sock_opt;
		sock_opt = nla_nest_start(msg, NBD_SOCK_ITEM);
		if (!sock_opt)
			err("Couldn't nest the sockets for our connection\n");
		NLA_PUT_U32(msg, NBD_SOCK_FD, sockfds[i]);
		nla_nest_end(msg, sock_opt);
	}
	nla_nest_end(msg, sock_attr);

	ret = nl_send_sync(socket, msg);
	if (ret < 0) {
                if(geteuid() != 0) {
                        err_code("Failed to setup device. Are you root?\n", ret);
                } else {
		        err_code("Failed to setup device, check dmesg\n", ret);
                }
        }
	return;
nla_put_failure:
	err("Failed to create netlink message\n");
}

static void netlink_disconnect(char *nbddev) {
	struct nl_sock *socket;
	struct nl_msg *msg;
	int driver_id;
	int ret;

	int index = -1;
	if (nbddev) {
		if (sscanf(nbddev, "/dev/nbd%d", &index) != 1)
			err("Invalid nbd device target\n");
	}
	if (index < 0)
		err("Invalid nbd device target\n");

	socket = get_nbd_socket(&driver_id);

	msg = nlmsg_alloc();
	if (!msg)
		err("Couldn't allocate netlink message\n");
	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
		    NBD_CMD_DISCONNECT, 0);
	NLA_PUT_U32(msg, NBD_ATTR_INDEX, index);
	ret = nl_send_sync(socket, msg);
	if (ret < 0)
		err_code("Failed to disconnect device, check dmsg\n", ret);
	nl_socket_free(socket);
	return;
nla_put_failure:
	err("Failed to create netlink message\n");
}
#else
static void netlink_configure(int index, int *sockfds, uint16_t flags,
			      const char *identifier)
{
}

static void netlink_disconnect(char *nbddev)
{
}
#endif /* HAVE_NETLINK */

#if HAVE_NETLINK
static struct nla_policy nbd_device_policy[NBD_DEVICE_ATTR_MAX + 1] = {
	[NBD_DEVICE_INDEX]		=	{ .type = NLA_U32 },
	[NBD_DEVICE_CONNECTED]		=	{ .type = NLA_U8 },
};

static int status_callback(struct nl_msg *msg, void *arg) {
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *msg_attr[NBD_ATTR_MAX + 1];
	struct nlattr *attr;
	int ret, rem;
	int *connected = (int *)arg;

	ret = nla_parse(msg_attr, NBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL);
	if (ret)
		return NL_OK;

	if (!msg_attr[NBD_ATTR_DEVICE_LIST])
		return NL_OK;

	nla_for_each_nested(attr, msg_attr[NBD_ATTR_DEVICE_LIST], rem) {
		struct nlattr *device[NBD_DEVICE_ATTR_MAX + 1];
		uint32_t index;
		uint8_t connected_status;

		if (nla_type(attr) != NBD_DEVICE_ITEM)
			continue;
		
		ret = nla_parse_nested(device, NBD_DEVICE_ATTR_MAX, attr,
				       nbd_device_policy);
		if (ret)
			continue;

		if (!device[NBD_DEVICE_INDEX] || !device[NBD_DEVICE_CONNECTED])
			continue;

		index = nla_get_u32(device[NBD_DEVICE_INDEX]);
		connected_status = nla_get_u8(device[NBD_DEVICE_CONNECTED]);
		
		*connected = connected_status ? 0 : 1; /* 0 = connected, 1 = disconnected */
		break; /* We only care about the first device for check_conn */
	}
	
	return NL_OK;
}

static int netlink_check_conn(char* devname, int do_print) {
	struct nl_sock *socket;
	struct nl_msg *msg;
	int driver_id, ret;
	int index = -1;
	int connected = -1; /* -1 = unknown, 0 = connected, 1 = disconnected */

	/* Parse device index from name */
	if (sscanf(devname, "/dev/nbd%d", &index) != 1) {
		if (sscanf(devname, "nbd%d", &index) != 1) {
			return 2; /* Invalid device name */
		}
	}

	/* Setup netlink socket */
	socket = nl_socket_alloc();
	if (!socket)
		return 2;

	if (genl_connect(socket)) {
		nl_socket_free(socket);
		return 2;
	}

	driver_id = genl_ctrl_resolve(socket, "nbd");
	if (driver_id < 0) {
		nl_socket_free(socket);
		return 2;
	}

	/* Set up callback to handle response */
	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, status_callback, &connected);

	/* Create status request message */
	msg = nlmsg_alloc();
	if (!msg) {
		nl_socket_free(socket);
		return 2;
	}

	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
		    NBD_CMD_STATUS, 0);
	NLA_PUT_U32(msg, NBD_ATTR_INDEX, index);

	/* Send message and get response */
	ret = nl_send_sync(socket, msg);
	if (ret < 0) {
		nl_socket_free(socket);
		return 2;
	}

	/* Receive the response */
	ret = nl_recvmsgs_default(socket);
	if (ret < 0) {
		nl_socket_free(socket);
		return 2;
	}

	nl_socket_free(socket);

	if (connected == -1) {
		/* Device not found or error */
		return 1;
	}

	if (do_print) {
		if (connected == 0) {
			printf("connected\n");
		} else {
			printf("disconnected\n");
		}
	}

	return connected; /* 0 = connected, 1 = disconnected */

nla_put_failure:
	nlmsg_free(msg);
	nl_socket_free(socket);
	return 2;
}
#endif /* HAVE_NETLINK */

int check_conn(char* devname, int do_print, int use_netlink) {
#if HAVE_NETLINK
	if (use_netlink) {
		/* Use netlink method when enabled */
		return netlink_check_conn(devname, do_print);
	}
	/* Fall through to old method when netlink disabled */
#endif
	/* Old method (fallback or when netlink not compiled in) */
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

int opennet(saved_connection_t *saved_conn) {
	int sock;
	struct addrinfo hints;
	struct addrinfo *ai = NULL;
	struct addrinfo *rp = NULL;
	int e;

	if (saved_conn && saved_conn->ai) {
		/* Use saved address info */
		for(rp = saved_conn->ai; rp != NULL; rp = rp->ai_next) {
			sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

			if(sock == -1)
				continue;	/* error */

			if(connect(sock, rp->ai_addr, rp->ai_addrlen) != -1)
				break;		/* success */

			close(sock);
		}

		if (rp != NULL) {
			setmysockopt(sock);
			return sock;
		}
		/* Fall back to fresh lookup if saved connection fails */
	}

	memset(&hints,'\0',sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
	hints.ai_protocol = IPPROTO_TCP;

	e = getaddrinfo(saved_conn ? saved_conn->hostname : cur_client->hostn, 
		       saved_conn ? saved_conn->port : cur_client->port, &hints, &ai);

	if(e != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(e));
		freeaddrinfo(ai);
		return -1;
	}

	/* Save the address info for future use */
	if (saved_conn) {
		if (saved_conn->ai) {
			freeaddrinfo(saved_conn->ai);
		}
		saved_conn->ai = ai;
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
		if (!saved_conn) {
			goto err;
		}
		return sock;
	}

	setmysockopt(sock);
	if (!saved_conn) {
err:
		freeaddrinfo(ai);
	}
	return sock;
}

int openunix() {
	int sock;
        char *path = cur_client->hostn;
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

	if (connect(sock, (struct sockaddr*)&un_addr, sizeof(un_addr)) == -1) {
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

	if (retval == NULL)
		return NULL;

	if(readit(sock, retval, sizeof(*retval)) < 0) {
		free(retval);
		return NULL;
	}

	retval->magic = ntohll(retval->magic);
	retval->opt = ntohl(retval->opt);
	retval->reply_type = ntohl(retval->reply_type);
	retval->datasize = ntohl(retval->datasize);
	if (retval->magic != rep_magic) {
		fprintf(stderr, "E: received invalid negotiation magic %" PRIu64 " (expected %" PRIu64 ")", retval->magic, rep_magic);
		exit(EXIT_FAILURE);
	}
	if (retval->datasize > 0 && retval->datasize < 4096) {
		struct reply *retval_r = realloc(retval, sizeof(struct reply) + retval->datasize);
		if (retval_r == NULL) {
			free(retval);
			return NULL;
		}
		retval = retval_r;
		readit(sock, &(retval->data), retval->datasize);
	}
	return retval;
}

void ask_list(int sock) {
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
					if(len >= BUF_SIZE) {
						fprintf(stderr, "\nE: export description read buffer overflow\n");
						exit(EXIT_FAILURE);
					}
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
	buf += sizeof(*size);
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

void send_opt_exportname(int sock, uint16_t *flags, char* name, uint16_t global_flags) {
	send_request(sock, NBD_OPT_EXPORT_NAME, -1, name);
	char b[sizeof(*flags) + sizeof(cur_client->size64)];
	if(readit(sock, b, sizeof(b)) < 0 && !cur_client->no_optgo) {
		err("E: server does not support NBD_OPT_GO and dropped connection after sending NBD_OPT_EXPORT_NAME. Try -g.");
	}
	parse_sizes(b, &(cur_client->size64), flags);
	if(!(global_flags & NBD_FLAG_NO_ZEROES)) {
		char buf[125];
		readit(sock, buf, 124);
	}
}

void negotiate(int *sockp, uint16_t *flags, uint32_t needed_flags, uint32_t client_flags, uint32_t do_opts) {
	uint64_t magic;
	uint16_t tmp;
	uint16_t global_flags;
	char buf[256] = "\0\0\0\0\0\0\0\0\0";
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
        if (cur_client->tls) {
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
				   cur_client->key,
				   cur_client->cert,
				   cur_client->cacert,
				   cur_client->tlshostn,
				   cur_client->priority,
				   !(cur_client->cacert) || !(cur_client->tlshostn), // insecure flag
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
	if (cur_client->tls) {
		err("TLS requested but support not compiled in");
	}
#endif

	if(do_opts & NBDC_DO_LIST) {
		ask_list(sock);
		exit(EXIT_SUCCESS);
	}

	struct reply *rep = NULL;

	if(cur_client->no_optgo) {
		send_opt_exportname(sock, flags, cur_client->name, global_flags);
		return;
	}

	send_info_request(sock, NBD_OPT_GO, 0, NULL, cur_client->name);

	do {
		if(rep != NULL) free(rep);
		rep = read_reply(sock);
		if(rep == NULL) {
			err("Unable to read reply.");
			exit(EXIT_FAILURE);
		}
		if(rep->reply_type & NBD_REP_FLAG_ERROR) {
			switch(rep->reply_type) {
				case NBD_REP_ERR_UNSUP:
					/* server doesn't support NBD_OPT_GO or NBD_OPT_INFO,
					 * fall back to NBD_OPT_EXPORT_NAME */
					send_opt_exportname(sock, flags, cur_client->name, global_flags);
					free(rep);
					return;
				case NBD_REP_ERR_POLICY:
					if(rep->datasize > 0) {
						char errstr[1024];
						rep->data[rep->datasize - 1] = '\0';
						snprintf(errstr, sizeof errstr, "Connection not allowed by server policy. Server said: %s", rep->data);
						err(errstr);
					} else {
						err("Connection not allowed by server policy.");
					}
					free(rep);
					exit(EXIT_FAILURE);
				default:
					if(rep->datasize > 0) {
						char errstr[1024];
						rep->data[rep->datasize - 1] = '\0';
						snprintf(errstr, sizeof errstr, "Unknown error returned by server. Server said: %s", rep->data);
						err(errstr);
					} else {
						err("Unknown error returned by server.");
					}
					free(rep);
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
						parse_sizes(rep->data + 2, &(cur_client->size64), flags);
						break;
					default:
						// ignore these, don't need them
						break;
				}
				break;
			case NBD_REP_ACK:
				break;
			default:
				err_nonfatal("Unknown reply to NBD_OPT_GO received, ignoring");
		}
	} while(rep->reply_type != NBD_REP_ACK);
	free(rep);
}

#if HAVE_NETLINK
#include <sys/select.h>

/* Callback for persist mode multicast messages */
static int persist_callback(struct nl_msg *msg, void *arg) {
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *msg_attr[NBD_ATTR_MAX + 1];
	struct nlattr *attr;
	int ret, rem;
	persist_connection_t *persist_conn = (persist_connection_t *)arg;
	uint32_t device_index;

	ret = nla_parse(msg_attr, NBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL);
	if (ret)
		return NL_OK;

	/* Check if this message is for our device */
	if (!msg_attr[NBD_ATTR_INDEX])
		return NL_OK;
	
	device_index = nla_get_u32(msg_attr[NBD_ATTR_INDEX]);
	/* TODO: Need to extract our device index and compare */
	
	switch (gnlh->cmd) {
		case NBD_CMD_LINK_DEAD:
			fprintf(stderr, "Received link dead notification for device %d\n", device_index);
			/* Trigger reconnection */
			/* This will be handled in the main loop */
			break;
		default:
			break;
	}
	
	return NL_OK;
}

/* Exponential backoff reconnection with maximum 3 minutes */
static int reconnect_with_backoff(persist_connection_t *persist_conn, int *new_sockfds) {
	int backoff_time = 1; /* Start with 1 second */
	int max_backoff = 180; /* Maximum 3 minutes */
	int attempt = 0;
	int i;
	
	while (backoff_time <= max_backoff) {
		fprintf(stderr, "Reconnection attempt %d, waiting %d seconds...\n", 
			attempt + 1, backoff_time);
		
		sleep(backoff_time);
		
		/* Try to establish all connections */
		for (i = 0; i < cur_client->nconn; i++) {
			if (cur_client->b_unix) {
				new_sockfds[i] = openunix();
			} else {
				new_sockfds[i] = opennet(persist_conn->conn);
			}
			
			if (new_sockfds[i] < 0) {
				/* Connection failed, clean up and retry */
				int j;
				for (j = 0; j < i; j++) {
					close(new_sockfds[j]);
				}
				break;
			}
			
			/* Negotiate connection parameters */
			if (!cur_client->preinit) {
				uint16_t new_flags = 0;
				negotiate(&new_sockfds[i], &new_flags, 0, NBD_FLAG_C_FIXED_NEWSTYLE, 0);
				/* TODO: Save and compare flags with original connection */
			}
		}
		
		/* Check if all connections were successful */
		int all_success = 1;
		for (i = 0; i < cur_client->nconn; i++) {
			if (new_sockfds[i] < 0) {
				all_success = 0;
				break;
			}
		}
		
		if (all_success) {
			fprintf(stderr, "Successfully reconnected after %d attempts\n", attempt + 1);
			return 0;
		}
		
		/* Exponential backoff */
		backoff_time *= 2;
		attempt++;
	}
	
	fprintf(stderr, "Failed to reconnect after %d attempts, giving up\n", attempt);
	return -1;
}

/* Send reconfigure message to kernel */
static int netlink_reconfigure(int device_index, int *sockfds) {
	struct nl_sock *socket;
	struct nl_msg *msg;
	struct nlattr *sock_attr;
	int driver_id, i, ret;

	socket = get_nbd_socket(&driver_id);
	
	msg = nlmsg_alloc();
	if (!msg)
		err("Couldn't allocate netlink message\n");
	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
		    NBD_CMD_RECONFIGURE, 0);
	if (device_index >= 0)
		NLA_PUT_U32(msg, NBD_ATTR_INDEX, device_index);

	sock_attr = nla_nest_start(msg, NBD_ATTR_SOCKETS);
	if (!sock_attr)
		err("Couldn't nest the sockets for reconnection\n");
	
	for (i = 0; i < cur_client->nconn; i++) {
		struct nlattr *sock_opt;
		sock_opt = nla_nest_start(msg, NBD_SOCK_ITEM);
		if (!sock_opt)
			err("Couldn't nest the sockets for our connection\n");
		NLA_PUT_U32(msg, NBD_SOCK_FD, sockfds[i]);
		nla_nest_end(msg, sock_opt);
	}
	nla_nest_end(msg, sock_attr);

	ret = nl_send_sync(socket, msg);
	if (ret < 0) {
		err_code("Failed to reconfigure device, check dmesg\n", ret);
		nl_socket_free(socket);
		return -1;
	}
	
	nl_socket_free(socket);
	return 0;
nla_put_failure:
	err("Failed to create reconfigure netlink message\n");
	return -1;
}

/* Cleanup function for persist connection */
static void cleanup_persist_connection(persist_connection_t *persist_conn) {
	if (!persist_conn)
		return;
		
	if (persist_conn->conn) {
		if (persist_conn->conn->ai) {
			freeaddrinfo(persist_conn->conn->ai);
		}
		if (persist_conn->conn->hostname) {
			free(persist_conn->conn->hostname);
		}
		if (persist_conn->conn->port) {
			free(persist_conn->conn->port);
		}
		free(persist_conn->conn);
	}
}

/* Main persist mode loop */
static int persist_mode_main(int device_index, int *initial_sockfds, uint16_t connection_flags) {
	struct nl_sock *mcast_socket = NULL;
	persist_connection_t persist_conn;
	int driver_id;
	int ret;
	sigset_t mask, oldmask;
	struct sigaction sa;
	
	/* Initialize persist connection structure */
	persist_conn.conn = malloc(sizeof(saved_connection_t));
	if (!persist_conn.conn)
		err("Cannot allocate saved connection\n");
	
	memset(persist_conn.conn, 0, sizeof(saved_connection_t));
	persist_conn.flags = connection_flags;
	persist_conn.size64 = cur_client->size64;
	persist_conn.blocksize = cur_client->bs;
	persist_conn.timeout = cur_client->timeout;
	
	/* Save initial connection details */
	if (!cur_client->b_unix) {
		persist_conn.conn->hostname = strdup(cur_client->hostn);
		persist_conn.conn->port = strdup(cur_client->port);
		/* Perform initial address resolution and save */
		opennet(persist_conn.conn);
	}
	
	/* Set up signal handling for clean shutdown */
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);
	
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
	
	/* Set up multicast socket for listening to disconnection messages */
	mcast_socket = nl_socket_alloc();
	if (!mcast_socket)
		err("Couldn't allocate multicast socket\n");
	
	if (genl_connect(mcast_socket))
		err("Couldn't connect to the multicast socket\n");
	
	driver_id = genl_ctrl_resolve(mcast_socket, "nbd");
	if (driver_id < 0)
		err("Couldn't resolve the nbd netlink family for multicast\n");
	
	/* Join multicast group */
	ret = nl_socket_add_membership(mcast_socket, genl_ctrl_resolve_grp(mcast_socket, "nbd", "nbd_mc_group"));
	if (ret < 0)
		err("Couldn't join nbd multicast group\n");
	
	/* Set up callback for multicast messages */
	nl_socket_modify_cb(mcast_socket, NL_CB_VALID, NL_CB_CUSTOM, persist_callback, &persist_conn);
	
	fprintf(stderr, "Persist mode active, monitoring device %d\n", device_index);
	
	/* Main monitoring loop */
	while (1) {
		fd_set readfds;
		int max_fd = nl_socket_get_fd(mcast_socket);
		struct timespec timeout_ts = { .tv_sec = 1, .tv_nsec = 0 };
		
		FD_ZERO(&readfds);
		FD_SET(max_fd, &readfds);
		
		/* Temporarily unblock signals for pselect */
		sigprocmask(SIG_SETMASK, &oldmask, NULL);
		
		/* Wait for multicast messages or timeout */
		ret = pselect(max_fd + 1, &readfds, NULL, NULL, &timeout_ts, &oldmask);
		
		/* Re-block signals */
		sigprocmask(SIG_BLOCK, &mask, NULL);
		
		if (ret < 0) {
			if (errno == EINTR) {
				fprintf(stderr, "Received interrupt signal, shutting down persist mode\n");
				break; /* Exit cleanly on interrupt */
			}
			err("Select failed in persist mode: %m\n");
		}
		
		if (ret > 0 && FD_ISSET(max_fd, &readfds)) {
			/* Process netlink messages */
			nl_recvmsgs_default(mcast_socket);
		}
	}
	
	/* Cleanup */
	cleanup_persist_connection(&persist_conn);
	
	if (mcast_socket) {
		nl_socket_free(mcast_socket);
	}
	
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
	
	return 0;
}

#endif /* HAVE_NETLINK */

bool get_from_config() {
	bool retval = false;
	yyin = fopen(SYSCONFDIR "/nbdtab", "r");
	yyout = fopen("/dev/null", "w");

	if(!strncmp(cur_client->dev, "/dev/", 5)) {
		cur_client->dev += 5;
	}
	if(yyin == NULL) {
		fprintf(stderr, "while opening %s: ", SYSCONFDIR "/nbdtab");
		perror("could not open config file");
		goto out;
	}
	yyparse();

	if(!found_config || parse_error) {
		goto out;
	}

        retval = true;
out:
	if(yyin != NULL) {
		fclose(yyin);
	}
	if(yyout != NULL) {
		fclose(yyout);
	}
	return retval;
}

void setsizes(int nbd, uint64_t size64, int blocksize, uint32_t flags) {
	unsigned long size;
	int read_only = (flags & NBD_FLAG_READ_ONLY) ? 1 : 0;

	if (size64>>12 > (uint64_t)~0UL)
		err("Device too large.\n");
	else {
		int tmp_blocksize = 4096;
		if (size64 / (uint64_t)blocksize <= (uint64_t)~0UL)
			tmp_blocksize = blocksize;
		if (ioctl(nbd, NBD_SET_BLKSIZE, tmp_blocksize) < 0) {
			fprintf(stderr, "Failed to set blocksize %d\n",
				tmp_blocksize);
			err("Ioctl/1.1a failed: %m\n");
		}
		size = (unsigned long)(size64 / (uint64_t)tmp_blocksize);
		if (ioctl(nbd, NBD_SET_SIZE_BLOCKS, size) < 0)
			err("Ioctl/1.1b failed: %m\n");
		if (tmp_blocksize != blocksize) {
			if (ioctl(nbd, NBD_SET_BLKSIZE, (unsigned long)blocksize) < 0) {
				fprintf(stderr, "Failed to set blocksize %d\n",
					blocksize);
				err("Ioctl/1.1c failed: %m\n");
			}
		}
		fprintf(stderr, "bs=%d, sz=%" PRIu64 " bytes\n", blocksize, (uint64_t)tmp_blocksize * size);
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
		fprintf(stderr, "%s version %s\n", PROG_NAME, PACKAGE_VERSION);
	}
#if HAVE_NETLINK
	fprintf(stderr, "Usage: nbd-client -name|-N name host [port] nbd_device\n\t[-block-size|-b block size] [-timeout|-t timeout] [-swap|-s]\n\t[-persist|-p] [-nofork|-n] [-systemd-mark|-m] [-i ident|-nonetlink|-L]\n\t[-readonly|-R] [-size|-B bytes] [-preinit|-P]\n");
#else
	fprintf(stderr, "Usage: nbd-client -name|-N name host [port] nbd_device\n\t[-block-size|-b block size] [-timeout|-t timeout] [-swap|-s]\n\t[-persist|-p] [-nofork|-n] [-systemd-mark|-m]\n\t[-readonly|-R] [-size|-B bytes] [-preinit|-P]\n");
#endif
	fprintf(stderr, "Or   : nbd-client -u (with same arguments as above)\n");
	fprintf(stderr, "Or   : nbd-client nbdX\n");
	fprintf(stderr, "Or   : nbd-client -d nbd_device\n");
	fprintf(stderr, "Or   : nbd-client -c nbd_device\n");
	fprintf(stderr, "Or   : nbd-client -h|--help\n");
	fprintf(stderr, "Or   : nbd-client -l|--list host\n");
	fprintf(stderr, "Or   : nbd-client -V|--version\n");
#if HAVE_GNUTLS && !defined(NOTLS)
	fprintf(stderr, "All commands that connect to a host also take:\n\t[-F|-certfile certfile] [-K|-keyfile keyfile]\n\t[-A|-cacertfile cacertfile] [-H|-tlshostname hostname] [-x|-enable-tls]\n\t[-y|-priority gnutls-priority-string]\n");
#endif
	fprintf(stderr, "Default value for blocksize is 512\n");
	fprintf(stderr, "Allowed values for blocksize are 512,1024,2048,4096\n"); /* will be checked in kernel :) */
	fprintf(stderr, "Note, that kernel 2.4.2 and older ones do not work correctly with\n");
	fprintf(stderr, "blocksizes other than 1024 without patches\n");
	fprintf(stderr, "Default value for port is 10809. Note that port must always be numeric\n");
	fprintf(stderr, "Bug reports and general discussion should go to %s\n", PACKAGE_BUGREPORT);
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
	close(nbd);
}

static const char *short_opts = "-B:b:c:d:gH:hlnN:PpRSst:uVxy:"
#if HAVE_NETLINK
	"i:L"
#endif
#if HAVE_GNUTLS
	"A:C:F:K:"
#endif
	"T"
	;

int main(int argc, char *argv[]) {
	char* port=NBD_DEFAULT_PORT;
	int sock, nbd;
	int G_GNUC_UNUSED nofork=0; // if -dNOFORK
	pid_t main_pid;
	uint16_t flags = 0;
	int c;
	int nonspecial=0;
	uint16_t needed_flags=0;
	uint32_t cflags=NBD_FLAG_C_FIXED_NEWSTYLE;
	uint32_t opts=0;
	sigset_t block, old;
	struct sigaction sa;
	char *identifier = NULL;
	int netlink = HAVE_NETLINK;
	int need_disconnect = 0;
	int do_check_conn = 0;
	char *check_device = NULL;
	int *sockfds;
	struct option long_options[] = {
		{ "cacertfile", required_argument, NULL, 'A' },
		{ "block-size", required_argument, NULL, 'b' },
		{ "size", required_argument, NULL, 'B' },
		{ "check", required_argument, NULL, 'c' },
		{ "connections", required_argument, NULL, 'C'},
		{ "disconnect", required_argument, NULL, 'd' },
		{ "certfile", required_argument, NULL, 'F' },
		{ "no-optgo", no_argument, NULL, 'g' },
		{ "help", no_argument, NULL, 'h' },
		{ "tlshostname", required_argument, NULL, 'H' },
#if HAVE_NETLINK
		{ "identifier", required_argument, NULL, 'i' },
#endif
		{ "keyfile", required_argument, NULL, 'K' },
		{ "list", no_argument, NULL, 'l' },
#if HAVE_NETLINK
		{ "nonetlink", no_argument, NULL, 'L' },
#endif
		{ "systemd-mark", no_argument, NULL, 'm' },
		{ "nofork", no_argument, NULL, 'n' },
		{ "name", required_argument, NULL, 'N' },
		{ "persist", no_argument, NULL, 'p' },
		{ "preinit", no_argument, NULL, 'P' },
		{ "readonly", no_argument, NULL, 'R' },
		{ "swap", no_argument, NULL, 's' },
		{ "timeout", required_argument, NULL, 't' },
		{ "dead-timeout", required_argument, NULL, 'T' },
		{ "unix", no_argument, NULL, 'u' },
		{ "version", no_argument, NULL, 'V' },
		{ "enable-tls", no_argument, NULL, 'x' },
		{ "priority", required_argument, NULL, 'y' },
		{ 0, 0, 0, 0 },
	};
	int i;

	logging(MY_NAME);

#if HAVE_GNUTLS && !defined(NOTLS)
        tlssession_init();
#endif
        cur_client = calloc(sizeof(CLIENT), 1);
        cur_client->bs = 512;
        cur_client->nconn = 1;
        cur_client->port = NBD_DEFAULT_PORT;

	while((c=getopt_long_only(argc, argv, short_opts, long_options, NULL))>=0) {
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
					cur_client->hostn=optarg;
					break;
				case 1:
					// port
					if(!strtol(optarg, NULL, 0)) {
						// not parseable as a number, assume it's the device
						cur_client->dev = optarg;
						nonspecial++;
					} else {
						port = optarg;
					}
					break;
				case 2:
					// device
					cur_client->dev = optarg;
					break;
				default:
					usage("too many non-option arguments specified");
					exit(EXIT_FAILURE);
			}
			break;
		case 'b':
		      blocksize:
			cur_client->bs=(int)strtol(optarg, NULL, 0);
			if(cur_client->bs == 0 || (cur_client->bs % 512) != 0) {
				fprintf(stderr, "E: blocksize is not a multiple of 512! This is not allowed\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'B':
			cur_client->force_size64=(uint64_t)strtoull(optarg, NULL, 0);
			if(cur_client->force_size64 == 0) {
				fprintf(stderr, "E: Invalid size\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'c':
			do_check_conn = 1;
			check_device = optarg;
			break;
		case 'C':
			cur_client->nconn = (int)strtol(optarg, NULL, 0);
			break;
		case 'd':
			need_disconnect = 1;
			cur_client->dev = strdup(optarg);
			break;
		case 'g':
			cur_client->no_optgo = true;
			break;
		case 'h':
			usage(NULL);
			exit(EXIT_SUCCESS);
#if HAVE_NETLINK
		case 'i':
			identifier = optarg;
			break;
#endif
		case 'l':
			needed_flags |= NBD_FLAG_FIXED_NEWSTYLE;
			opts |= NBDC_DO_LIST;
			cur_client->dev="";
			break;
#if HAVE_NETLINK
		case 'L':
			netlink = 0;
			break;
#endif
		case 'm':
			argv[0][0] = '@';
			break;
		case 'n':
			nofork=1;
			break;
		case 'N':
			cur_client->name = optarg;
			break;
		case 'p':
                        cur_client->persist = true;
			break;
		case 'P':
			cur_client->preinit = true;
			break;
		case 'R':
			cur_client->force_ro = true;
			break;
		case 's':
			cur_client->swap = true;
			break;
		case 'T':
			cur_client->dead_conn_timeout = strtol(optarg, NULL, 0);
			break;
		case 't':
		      timeout:
			cur_client->timeout = strtol(optarg, NULL, 0);
			break;
		case 'u':
			cur_client->b_unix = 1;
			break;
		case 'V':
			printf("This is %s, from %s\n", PROG_NAME, PACKAGE_STRING);
			return 0;
#if HAVE_GNUTLS && !defined(NOTLS)
		case 'x':
			cur_client->tls = true;
			break;
                case 'F':
                        cur_client->cert=strdup(optarg);
                        break;
                case 'K':
                        cur_client->key=strdup(optarg);
                        break;
                case 'A':
                        cur_client->cacert=strdup(optarg);
                        break;
                case 'H':
                        cur_client->tlshostn=strdup(optarg);
                        break;
                case 'y':
                        cur_client->priority=strdup(optarg);
                        break;
#else
                case 'F':
                case 'K':
                case 'H':
                case 'A':
		        case 'y':
			fprintf(stderr, "E: TLS support not compiled in\n");
                        exit(EXIT_FAILURE);
#endif
		default:
			fprintf(stderr, "E: option eaten by 42 mice\n");
			exit(EXIT_FAILURE);
		}
	}

	/* Handle check_conn request after all options are processed */
	if (do_check_conn) {
		return check_conn(check_device, 1, netlink);
	}

	if (need_disconnect) {
		if (netlink)
			netlink_disconnect(cur_client->dev);
		else
			disconnect(cur_client->dev);
		exit(EXIT_SUCCESS);
	}
#ifdef __ANDROID__
  if (swap)
    err("swap option unsupported on Android because mlockall is unsupported.");
#endif
	if(cur_client->hostn) {
		if((!cur_client->name || !cur_client->dev) && !(opts & NBDC_DO_LIST)) {
			if(!strncmp(cur_client->hostn, "nbd", 3) || !strncmp(cur_client->hostn, "/dev/nbd", 8)) {
                                cur_client->dev = cur_client->hostn;
				if(!get_from_config()) {
					usage("no valid configuration for specified device found", cur_client->hostn);
					exit(EXIT_FAILURE);
				}
			} else if (!netlink) {
				usage("not enough information specified, and argument didn't look like an nbd device");
				exit(EXIT_FAILURE);
			}
		}
	} else {
		usage("no information specified");
		exit(EXIT_FAILURE);
	}

        if (cur_client->key && !cur_client->cert)
		cur_client->cert = strdup(cur_client->key);

	if (cur_client->cert != NULL || cur_client->key != NULL || cur_client->cacert != NULL || cur_client->tlshostn != NULL) {
		cur_client->tls = true;
	}

	if (cur_client->preinit) {
		if (cur_client->tls) {
			fprintf(stderr, "E: preinit connection cannot be used with TLS\n");
			exit(EXIT_FAILURE);
		}
		if (!cur_client->force_size64) {
			fprintf(stderr, "E: preinit connection requires specifying size\n");
			exit(EXIT_FAILURE);
		}
	}

        if (!cur_client->tlshostn && cur_client->hostn && !cur_client->b_unix)
                cur_client->tlshostn = strdup(cur_client->hostn);

	if (netlink)
		nofork = 1;
	else if (identifier) {
		fprintf(stderr, "E: identifier is only useful with netlink\n");
		exit(EXIT_FAILURE);
	}

	if((cur_client->force_size64 % cur_client->bs) != 0) {
		fprintf(stderr, "E: size (%" PRIu64 " bytes) is not a multiple of blocksize (%d)!\n", cur_client->force_size64, cur_client->bs);
		exit(EXIT_FAILURE);
	}

	if(!cur_client->name)
		cur_client->name = "";
	if((strlen(cur_client->name)==0) && !(opts & NBDC_DO_LIST)) {
		printf("Warning: the oldstyle protocol is no longer supported.\nThis method now uses the newstyle protocol with a default export\n");
	}

	if(!(opts & NBDC_DO_LIST) && !netlink) {
		nbd = open(cur_client->dev, O_RDWR);
		if (nbd < 0)
			err("Cannot open NBD: %m\nPlease ensure the 'nbd' module is loaded.");
	}

	if (netlink) {
		sockfds = malloc(sizeof(int) * cur_client->nconn);
		if (!sockfds)
			err("Cannot allocate the socket fd's array");
	}

	for (i = 0; i < cur_client->nconn; i++) {
		if (cur_client->b_unix)
			sock = openunix();
		else
			sock = opennet(NULL);
		if (sock < 0)
			exit(EXIT_FAILURE);

		if (!cur_client->preinit)
			negotiate(&sock, &flags, needed_flags, cflags, opts);
		if (cur_client->force_ro)
			flags |= NBD_FLAG_READ_ONLY;
		if (cur_client->force_size64)
			cur_client->size64 = cur_client->force_size64;
		if (netlink) {
			sockfds[i] = sock;
			continue;
		}

		if (i == 0) {
			setsizes(nbd, cur_client->size64, cur_client->bs, flags);
			set_timeout(nbd, cur_client->timeout);
		}
		finish_sock(sock, nbd, cur_client->swap);
		if (cur_client->swap) {
			if (cur_client->tls)
				fprintf(stderr, "Warning: using swap and TLS is prone to deadlock\n");
			/* try linux >= 2.6.36 interface first */
			if (oom_adjust("/proc/self/oom_score_adj", "-1000")) {
				/* fall back to linux <= 2.6.35 interface */
				oom_adjust("/proc/self/oom_adj", "-17");
			}
		}
	}

	if (netlink) {
		int index = -1;
		if (cur_client->dev) {
			if (sscanf(cur_client->dev, "/dev/nbd%d", &index) != 1)
				err("Invalid nbd device target\n");
		}
		netlink_configure(index, sockfds, flags, identifier);
		
		/* If persist mode is enabled, start the monitoring loop */
		if (cur_client->persist_mode) {
			return persist_mode_main(index, sockfds, flags);
		}
		
		return 0;
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
			while(check_conn(cur_client->dev, 0, 0)) {
				if (main_pid != getppid()) {
					/* check_conn() will not return 0 when nbd disconnected
					 * and parent exited during this loop. So the child has to
					 * explicitly check parent identity and exit if parent
					 * exited */
					exit(0);
				}
				nanosleep(&req, NULL);
			}
			if(open(cur_client->dev, O_RDONLY) < 0) {
				perror("could not open device for updating partition table");
			}
			exit(0);
		}
#endif

		if (ioctl(nbd, NBD_DO_IT) < 0) {
			int error = errno;
			fprintf(stderr, "nbd,%d: Kernel call returned: %s\n", main_pid, strerror(errno));
			if(error==EBADR) {
				/* The user probably did 'nbd-client -d' on us.
				 * quit */
                                cur_client->persist_mode = false;
			} else {
				if(cur_client->persist_mode) {
					uint64_t old_size = cur_client->size64;
					uint16_t new_flags;

					close(sock); close(nbd);
					for (;;) {
						fprintf(stderr, " Reconnecting\n");
						if (cur_client->b_unix)
							sock = openunix();
						else
							sock = opennet(NULL);
						if (sock >= 0)
							break;
						sleep (1);
					}
					nbd = open(cur_client->dev, O_RDWR);
					if (nbd < 0)
						err("Cannot open NBD: %m");
					negotiate(&sock, &new_flags, needed_flags, cflags, opts);
					if (old_size != cur_client->size64) {
						err("Size of the device changed. Bye");
					}
					setsizes(nbd, cur_client->size64, cur_client->bs,
								new_flags);

					set_timeout(nbd, cur_client->timeout);
					finish_sock(sock,nbd,cur_client->swap);
				}
			}
		} else {
			/* We're on 2.4. It's not clearly defined what exactly
			 * happened at this point. Probably best to quit, now
			 */
			fprintf(stderr, "Kernel call returned.\n");
                        cur_client->persist_mode = false;
		}
	} while(cur_client->persist_mode);
	printf("sock, ");
	ioctl(nbd, NBD_CLEAR_SOCK);
	printf("done\n");
	return 0;
}
