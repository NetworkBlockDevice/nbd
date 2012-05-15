/* This header file is shared by client & server. They really have
 * something to share...
 * */

/* Client/server protocol is as follows:
   Send INIT_PASSWD
   Send 64-bit cliserv_magic
   Send 64-bit size of exported device
   Send 128 bytes of zeros (reserved for future use)
 */

#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <stdlib.h>

#if SIZEOF_UNSIGNED_SHORT_INT==4
typedef unsigned short u32;
#elif SIZEOF_UNSIGNED_INT==4
typedef unsigned int u32;
#elif SIZEOF_UNSIGNED_LONG_INT==4
typedef unsigned long u32;
#else
#error I need at least some 32-bit type
#endif

#if SIZEOF_UNSIGNED_INT==8
typedef unsigned int u64;
#elif SIZEOF_UNSIGNED_LONG_INT==8
typedef unsigned long u64;
#elif SIZEOF_UNSIGNED_LONG_LONG_INT==8
typedef unsigned long long u64;
#else
#error I need at least some 64-bit type
#endif

#define __be32 u32
#define __be64 u64
#include "nbd.h"

#ifndef HAVE_FDATASYNC
#define fdatasync(arg) fsync(arg)
#endif

#if NBD_LFS==1
/* /usr/include/features.h (included from /usr/include/sys/types.h)
   defines this when _GNU_SOURCE is defined
 */
#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE
#endif
#define _FILE_OFFSET_BITS 64
#endif

u64 cliserv_magic = 0x00420281861253LL;
u64 opts_magic = 0x49484156454F5054LL;
u64 rep_magic = 0x3e889045565a9LL;
#define INIT_PASSWD "NBDMAGIC"

#define INFO(a) do { } while(0)

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

#ifndef G_GNUC_NORETURN
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#define G_GNUC_NORETURN __attribute__((__noreturn__))
#define G_GNUC_UNUSED __attribute__((unused))
#else
#define G_GNUC_NORETURN
#define G_GNUC_UNUSED
#endif
#endif

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

void err(const char *s) G_GNUC_NORETURN;

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
#define htonll ntohll

#define NBD_DEFAULT_PORT	"10809"	/* Port on which named exports are
					 * served */

/* Options that the client can select to the server */
#define NBD_OPT_EXPORT_NAME	(1)	/** Client wants to select a named export (is followed by name of export) */
#define NBD_OPT_ABORT		(2)	/** Client wishes to abort negotiation */
#define NBD_OPT_LIST		(3)	/** Client request list of supported exports (not followed by data) */

/* Replies the server can send during negotiation */
#define NBD_REP_ACK		(1)	/** ACK a request. Data: option number to be acked */
#define NBD_REP_SERVER		(2)	/** Reply to NBD_OPT_LIST (one of these per server; must be followed by NBD_REP_ACK to signal the end of the list */
#define NBD_REP_FLAG_ERROR	(1 << 31)	/** If the high bit is set, the reply is an error */
#define NBD_REP_ERR_UNSUP	(1 | NBD_REP_FLAG_ERROR)	/** Client requested an option not understood by this version of the server */
#define NBD_REP_ERR_POLICY	(2 | NBD_REP_FLAG_ERROR)	/** Client requested an option not allowed by server configuration. (e.g., the option was disabled) */
#define NBD_REP_ERR_INVALID	(3 | NBD_REP_FLAG_ERROR)	/** Client issued an invalid request */
#define NBD_REP_ERR_PLATFORM	(4 | NBD_REP_FLAG_ERROR)	/** Option not supported on this platform */

/* Global flags */
#define NBD_FLAG_FIXED_NEWSTYLE (1 << 0)	/* new-style export that actually supports extending */
/* Flags from client to server. Only one such option currently. */
#define NBD_FLAG_C_FIXED_NEWSTYLE NBD_FLAG_FIXED_NEWSTYLE
