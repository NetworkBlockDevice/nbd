#include <config.h>
#include <fcntl.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <cliserv.h>
#include <nbd-debug.h>

const u64 cliserv_magic = 0x00420281861253LL;
const u64 opts_magic = 0x49484156454F5054LL;
const u64 rep_magic = 0x3e889045565a9LL;

/**
 * Set a socket to blocking or non-blocking
 *
 * @param fd The socket's FD
 * @param nb nonzero to set to non-blocking, else 0 to set to blocking
 * @return 0 - OK, -1 failed
 */
int set_nonblocking(int fd, int nb) {
	int sf = fcntl (fd, F_GETFL, 0);
	if (sf == -1)
		return -1;
	return fcntl (fd, F_SETFL, nb ? (sf | O_NONBLOCK) : (sf & ~O_NONBLOCK));
}


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
		strncpy(s1 + (s2 - s), strerror(errno), sizeof(s1) - (s2 - s));
		s2 += 2;
		strncpy(s1 + strlen(s1), s2, sizeof(s1) - strlen(s1));
	}
#ifndef	sun
	/* Solaris doesn't have %h in syslog */
	else if ((s2 = strstr(s, "%h"))) {
		strncpy(s1 + (s2 - s), hstrerror(h_errno), sizeof(s1) - (s2 - s));
		s2 += 2;
		strncpy(s1 + strlen(s1), s2, sizeof(s1) - strlen(s1));
	}
#endif

	s1[sizeof(s1)-1] = '\0';
#ifdef ISSERVER
	syslog(LOG_ERR, "%s", s1);
	syslog(LOG_ERR, "Exiting.");
#endif
	fprintf(stderr, "Error: %s\n", s1);
}

void err(const char *s) {
	err_nonfatal(s);
	fprintf(stderr, "Exiting.\n");
	exit(EXIT_FAILURE);
}

void logging(const char* name) {
#ifdef ISSERVER
	openlog(name, LOG_PID, LOG_DAEMON);
#endif
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

#ifndef ntohll
#ifdef WORDS_BIGENDIAN
uint64_t ntohll(uint64_t a) {
	return a;
}
#else
uint64_t ntohll(uint64_t a) {
	u32 lo = a & 0xffffffff;
	u32 hi = a >> 32U;
	lo = ntohl(lo);
	hi = ntohl(hi);
	return ((uint64_t) lo) << 32U | hi;
}
#endif
#endif

/**
 * Read data from a file descriptor into a buffer
 *
 * @param f a file descriptor
 * @param buf a buffer
 * @param len the number of bytes to be read
 * @return 0 on completion, or -1 on failure
 **/
int readit(int f, void *buf, size_t len) {
	ssize_t res;
	while (len > 0) {
		DEBUG("*");
		res = read(f, buf, len);
		if (res > 0) {
			len -= res;
			buf += res;
		} else if (res < 0) {
			if(errno != EAGAIN) {
				err_nonfatal("Read failed: %m");
				return -1;
			}
		} else {
			errno = ECONNRESET;
			return -1;
		}
	}
	return 0;
}

/**
 * Write data from a buffer into a filedescriptor
 *
 * @param f a file descriptor
 * @param buf a buffer containing data
 * @param len the number of bytes to be written
 * @return 0 on success, or -1 if the socket was closed
 **/
int writeit(int f, void *buf, size_t len) {
	ssize_t res;
	while (len > 0) {
		DEBUG("+");
		if ((res = write(f, buf, len)) <= 0) {
			switch(errno) {
				case EAGAIN:
					break;
				default:
					err_nonfatal("Send failed: %m");
					return -1;
			}
		}
		len -= res;
		buf += res;
	}
	return 0;
}
