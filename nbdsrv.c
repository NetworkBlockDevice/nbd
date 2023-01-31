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
#include <pthread.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <treefiles.h>
#include "backend.h"
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif

#define LINELEN 256	  /**< Size of static buffer used to read the
			       authorization file (yuck) */
#include <cliserv.h>

bool address_matches(const char* mask, const struct sockaddr* addr, GError** err) {
	struct addrinfo *res, *aitmp, hints;
	char *masksep;
	char privmask[strlen(mask)+1];
	int masklen;
	int addrlen = addr->sa_family == AF_INET ? 4 : 16;
#define IPV4_MAP_PREFIX 12
	uint8_t ipv4_mapped[IPV4_MAP_PREFIX+4] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		255, 255, 0, 0, 0, 0};

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
		assert(addr->sa_family == AF_INET || addr->sa_family == AF_INET6);
		const uint8_t* byte_s;
		uint8_t* byte_t;
		uint8_t mask = 0;
		int len_left = masklen;
		if(res->ai_family == addr->sa_family) {
			/* Both addresses are the same address family so do a simple comparison */
			switch(addr->sa_family) {
			case AF_INET:
				byte_s = (const uint8_t*)(&(((struct sockaddr_in*)addr)->sin_addr));
				byte_t = (uint8_t*)(&(((struct sockaddr_in*)(res->ai_addr))->sin_addr));
				break;
			case AF_INET6:
				byte_s = (const uint8_t*)(&(((struct sockaddr_in6*)addr)->sin6_addr));
				byte_t = (uint8_t*)(&(((struct sockaddr_in6*)(res->ai_addr))->sin6_addr));
				break;
			}
		} else {
			/* Addresses are different families, compare IPv4-mapped IPv6 address */
			switch(addr->sa_family) {
			case AF_INET:
				/* Map client address to IPv6 for comparison */
				memcpy(&ipv4_mapped[IPV4_MAP_PREFIX], &(((struct sockaddr_in*)addr)->sin_addr), 4);
				byte_s = (const uint8_t*)&ipv4_mapped;
				byte_t = (uint8_t*)(&(((struct sockaddr_in6*)(res->ai_addr))->sin6_addr));
				len_left += IPV4_MAP_PREFIX * 8;
				break;
			case AF_INET6:
				byte_s = (const uint8_t*)(&(((struct sockaddr_in6*)addr)->sin6_addr));
				/* Map res to IPv6 for comparison */
				memcpy(&ipv4_mapped[IPV4_MAP_PREFIX], &(((struct sockaddr_in*)(res->ai_addr))->sin_addr), 4);
				byte_t = &ipv4_mapped[0];
				len_left += IPV4_MAP_PREFIX * 8;
				break;
			}
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

	if (opts->server->authname == NULL) {
		msg(LOG_INFO, "No authorization file, granting access.");
		return 1;
	}

	if ((f=fopen(opts->server->authname,"r"))==NULL) {
                msg(LOG_INFO, "Can't open authorization file %s (%s).",
                    opts->server->authname, strerror(errno));
		return 1 ; 
	}
  
	while (fgets(line,LINELEN,f)!=NULL) {
		char* pos;
		char* endpos;
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
		/* Trim trailing whitespace */
		endpos = pos;
		while ((*endpos) && !isspace(*endpos))
			endpos++;
		*endpos = '\0';
		if(address_matches(pos, (struct sockaddr*)&opts->clientaddr, NULL)) {
			fclose(f);
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

	if(s->authname)
		serve->authname = g_strdup(s->authname);

	serve->flags = s->flags;
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

	if(s->cowdir)
		serve->cowdir = g_strdup(s->cowdir);

	serve->max_connections = s->max_connections;

	return serve;
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

int exptrim(struct nbd_request* req, CLIENT* client) {
	/* Caller did range checking */
	assert(!(client->server->flags & F_READONLY));
	assert(req->from + req->len <= client->exportsize);
	/* For copy-on-write, we should trim on the diff file. Not yet
	 * implemented. */
	if(client->server->flags & F_COPYONWRITE) {
		DEBUG("TRIM not supported yet on copy-on-write exports");
		return 0;
	}
	if (client->server->flags & F_TREEFILES) {
		/* start address of first block to be trimmed */
		off_t min = ( ( req->from + TREEPAGESIZE - 1 ) / TREEPAGESIZE) * TREEPAGESIZE;
		/* start address of first block NOT to be trimmed */
		off_t max = ( ( req->from + req->len ) / TREEPAGESIZE) * TREEPAGESIZE;
		while (min<max) {
			delete_treefile(client->exportname,client->exportsize,min);
			min+=TREEPAGESIZE;
		}
		DEBUG("Performed TRIM request on TREE structure from %llu to %llu", (unsigned long long) req->from, (unsigned long long) req->len);
		return 0;
	}
	FILE_INFO cur = g_array_index(client->export, FILE_INFO, 0);
	FILE_INFO next;
	int i = 1;
	do {
		if(i<client->export->len) {
			next = g_array_index(client->export, FILE_INFO, i);
		} else {
			next.fhandle = -1;
			next.startoff = client->exportsize;
		}
		if(cur.startoff <= req->from && next.startoff - cur.startoff >= req->len) {
			off_t reqoff = req->from - cur.startoff;
			off_t curlen = next.startoff - reqoff;
			off_t reqlen = curlen - reqoff > req->len ? req->len : curlen - reqoff;
			punch_hole(cur.fhandle, reqoff, reqlen);
		}
		cur = next;
		i++;
	} while(i < client->export->len && cur.startoff < (req->from + req->len));
	DEBUG("Performed TRIM request from %llu to %llu", (unsigned long long) req->from, (unsigned long long) req->len);
	return 0;
}

pthread_mutex_t cntmutex = PTHREAD_MUTEX_INITIALIZER;

SERVER* serve_inc_ref(SERVER *s) {
	pthread_mutex_lock(&cntmutex);
	s->refcnt++;
	pthread_mutex_unlock(&cntmutex);
	return s;
}

SERVER* serve_dec_ref(SERVER *s) {
	pthread_mutex_lock(&cntmutex);
	if(--(s->refcnt) == 0) {
		g_free(s);
		s = NULL;
	}
	pthread_mutex_unlock(&cntmutex);
	return s;
}

void serve_clear_element(SERVER **server) {
	serve_dec_ref(*server);
}
