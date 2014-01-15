#include "config.h"
#include "nbd-debug.h"

#include <nbdsrv.h>

#include <assert.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#define LINELEN 256	  /**< Size of static buffer used to read the
			       authorization file (yuck) */

#include <cliserv.h>

bool address_matches(const char* mask, const void* addr, int af, GError** err) {
	struct addrinfo *res, *aitmp, hints;
	char *masksep;
	char privmask[strlen(mask)+1];
	int masklen;
	int addrlen = af == AF_INET ? 4 : 16;

	assert(af == AF_INET || af == AF_INET6);

	strcpy(privmask, mask);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST;

	if((masksep = strchr(privmask, '/'))) {
		*masksep = '\0';
		masklen = strtol(++masksep, NULL, 10);
	} else {
		masklen = addrlen * 8;
	}

	int e;
	if((e = getaddrinfo(privmask, NULL, &hints, &res))) {
		g_set_error(err, NBDS_ERR, NBDS_ERR_GAI, "could not parse netmask line: %s", gai_strerror(e));
		return false;
	}
	aitmp = res;
	while(res) {
		const uint8_t* byte_s = addr;
		uint8_t* byte_t;
		uint8_t mask = 0;
		int len_left = masklen;
		if(res->ai_family != af) {
			goto next;
		}
		switch(af) {
			case AF_INET:
				byte_t = (uint8_t*)(&(((struct sockaddr_in*)(res->ai_addr))->sin_addr));
				break;
			case AF_INET6:
				byte_t = (uint8_t*)(&(((struct sockaddr_in6*)(res->ai_addr))->sin6_addr));
				break;
		}
		while(len_left >= 8) {
			if(*byte_s != *byte_t) {
				goto next;
			}
			byte_s++; byte_t++;
			len_left -= 8;
		}
		if(len_left) {
			mask = getmaskbyte(len_left);
			if((*byte_s & mask) != (*byte_t & mask)) {
				goto  next;
			}
		}
		freeaddrinfo(aitmp);
		return true;
	next:
		res = res->ai_next;
	}
	freeaddrinfo(aitmp);
	return false;
}

uint8_t getmaskbyte(int masklen) {
	if(masklen >= 8) {
		return 0xFF;
	}
	uint8_t retval = 0;
	for(int i = 7; i + masklen > 7; i--) {
		retval |= 1 << i;
	}

	return retval;
}

int authorized_client(CLIENT *opts) {
	FILE *f ;
	char line[LINELEN]; 
	char *tmp;
	struct in_addr addr;
	struct in_addr client;
	struct in_addr cltemp;
	int len;

	if ((f=fopen(opts->server->authname,"r"))==NULL) {
                msg(LOG_INFO, "Can't open authorization file %s (%s).",
                    opts->server->authname, strerror(errno));
		return 1 ; 
	}
  
	while (fgets(line,LINELEN,f)!=NULL) {
		char* pos;
		/* Drop comments */
		if((pos = strchr(line, '#'))) {
			*pos = '\0';
		}
		/* Skip whitespace */
		pos = line;
		while((*pos) && isspace(*pos)) {
			pos++;
		}
		/* Skip content-free lines */
		if(!(*pos)) {
			continue;
		}
		struct sockaddr* sa = (struct sockaddr*)&opts->clientaddr;
		if(address_matches(line, sa->sa_data, sa->sa_family, NULL)) {
			return 1;
		}
	}
	fclose(f);
	return 0;
}

/**
 * duplicate server
 * @param s the old server we want to duplicate
 * @return new duplicated server
 **/
SERVER* dup_serve(const SERVER *const s) {
	SERVER *serve = NULL;

	serve=g_new0(SERVER, 1);
	if(serve == NULL)
		return NULL;

	if(s->exportname)
		serve->exportname = g_strdup(s->exportname);

	serve->expected_size = s->expected_size;

	if(s->listenaddr)
		serve->listenaddr = g_strdup(s->listenaddr);

	serve->port = s->port;

	if(s->authname)
		serve->authname = strdup(s->authname);

	serve->flags = s->flags;
	serve->socket = s->socket;
	serve->socket_family = s->socket_family;
	serve->virtstyle = s->virtstyle;
	serve->cidrlen = s->cidrlen;

	if(s->prerun)
		serve->prerun = g_strdup(s->prerun);

	if(s->postrun)
		serve->postrun = g_strdup(s->postrun);

	if(s->transactionlog)
		serve->transactionlog = g_strdup(s->transactionlog);
	
	if(s->servename)
		serve->servename = g_strdup(s->servename);

	serve->max_connections = s->max_connections;

	return serve;
}

int append_serve(const SERVER *const s, GArray *const a) {
	SERVER *ns = NULL;
	struct addrinfo hints;
	struct addrinfo *ai = NULL;
	struct addrinfo *rp = NULL;
	char   host[NI_MAXHOST];
	gchar  *port = NULL;
	int e;
	int ret;

	assert(s != NULL);
	if(a == NULL) {
		return -1;
	}

	port = g_strdup_printf("%d", s->port);

	memset(&hints,'\0',sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;
	hints.ai_protocol = IPPROTO_TCP;

	e = getaddrinfo(s->listenaddr, port, &hints, &ai);

	if (port)
		g_free(port);

	if(e == 0) {
		for (rp = ai; rp != NULL; rp = rp->ai_next) {
			e = getnameinfo(rp->ai_addr, rp->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);

			if (e != 0) { // error
				fprintf(stderr, "getnameinfo: %s\n", gai_strerror(e));
				continue;
			}

			// duplicate server and set listenaddr to resolved IP address
			ns = dup_serve (s);
			if (ns) {
				ns->listenaddr = g_strdup(host);
				ns->socket_family = rp->ai_family;
				g_array_append_val(a, *ns);
				free(ns);
				ns = NULL;
			}
		}

		ret = 0;
	} else {
		fprintf(stderr, "getaddrinfo failed on listen host/address: %s (%s)\n", s->listenaddr ? s->listenaddr : "any", gai_strerror(e));
		ret = -1;
	}

	if (ai)
		freeaddrinfo(ai);

	return ret;
}

uint64_t size_autodetect(int fhandle) {
	off_t es;
	u64 bytes __attribute__((unused));
	struct stat stat_buf;
	int error;

#ifdef HAVE_SYS_MOUNT_H
#ifdef HAVE_SYS_IOCTL_H
#ifdef BLKGETSIZE64
	DEBUG("looking for export size with ioctl BLKGETSIZE64\n");
	if (!ioctl(fhandle, BLKGETSIZE64, &bytes) && bytes) {
		return bytes;
	}
#endif /* BLKGETSIZE64 */
#endif /* HAVE_SYS_IOCTL_H */
#endif /* HAVE_SYS_MOUNT_H */

	DEBUG("looking for fhandle size with fstat\n");
	stat_buf.st_size = 0;
	error = fstat(fhandle, &stat_buf);
	if (!error) {
		/* always believe stat if a regular file as it might really
		 * be zero length */
		if (S_ISREG(stat_buf.st_mode) || (stat_buf.st_size > 0))
			return (uint64_t)stat_buf.st_size;
        } else {
                DEBUG("fstat failed: %s", strerror(errno));
        }

	DEBUG("looking for fhandle size with lseek SEEK_END\n");
	es = lseek(fhandle, (off_t)0, SEEK_END);
	if (es > ((off_t)0)) {
		return (uint64_t)es;
        } else {
                DEBUG("lseek failed: %d", errno==EBADF?1:(errno==ESPIPE?2:(errno==EINVAL?3:4)));
        }

	DEBUG("Could not find size of exported block device: %s", strerror(errno));
	return UINT64_MAX;
}

