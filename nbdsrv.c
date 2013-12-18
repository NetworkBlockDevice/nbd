#include "config.h"

#define ISSERVER

#include <assert.h>
#include <ctype.h>
#include <nbdsrv.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

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

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = 0;
	hints.ai_protocol = 0;
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

