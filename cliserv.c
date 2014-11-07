#include <config.h>
#include <cliserv.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>

const u64 cliserv_magic = 0x00420281861253LL;
const u64 opts_magic = 0x49484156454F5054LL;
const u64 rep_magic = 0x3e889045565a9LL;

void setmysockopt(int sock) {
	int size = 1;
#if 0
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int)) < 0)
		 INFO("(no sockopt/1: %m)");
#endif
#ifdef	IPPROTO_TCP
	size = 1;
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &size, sizeof(int)) < 0)
		 INFO("(no sockopt/2: %m)");
#endif
#if 0
	size = 1024;
	if (setsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &size, sizeof(int)) < 0)
		 INFO("(no sockopt/3: %m)");
#endif
}

void err_nonfatal(const char *s) {
	char s1[150], *s2;

	strncpy(s1, s, sizeof(s1));
	if ((s2 = strstr(s, "%m"))) {
		strcpy(s1 + (s2 - s), strerror(errno));
		s2 += 2;
		strcpy(s1 + strlen(s1), s2);
	}
#ifndef	sun
	/* Solaris doesn't have %h in syslog */
	else if ((s2 = strstr(s, "%h"))) {
		strcpy(s1 + (s2 - s), hstrerror(h_errno));
		s2 += 2;
		strcpy(s1 + strlen(s1), s2);
	}
#endif

	s1[sizeof(s1)-1] = '\0';
#ifdef ISSERVER
	syslog(LOG_ERR, "%s", s1);
	syslog(LOG_ERR, "Exiting.");
#endif
	fprintf(stderr, "Error: %s\nExiting.\n", s1);
}

void err(const char *s) {
	err_nonfatal(s);
	exit(EXIT_FAILURE);
}

void logging(void) {
#ifdef ISSERVER
	openlog(MY_NAME, LOG_PID, LOG_DAEMON);
#endif
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

#ifdef WORDS_BIGENDIAN
u64 ntohll(u64 a) {
	return a;
}
#else
u64 ntohll(u64 a) {
	u32 lo = a & 0xffffffff;
	u32 hi = a >> 32U;
	lo = ntohl(lo);
	hi = ntohl(hi);
	return ((u64) lo) << 32U | hi;
}
#endif
