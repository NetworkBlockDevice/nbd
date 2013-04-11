#ifndef NETDB_COMPAT_H
#define NETDB_COMPAT_H

/* AI_NUMERICSERV as a value for the `ai_flags' member
 * of `struct addrinfo' of header <netdb.h> has only
 * been available since:
 *
 *   POSIX 1003.1-2008, Issue 7
 *   glibc 2.3.4
 *   Mac OS X 10.6
 *   etc.
 *
 * Fortunately, its main purpose seems to be only
 * to optimize calls of `getaddrinfo', and because it
 * is meant to be a bit flag, it can therefore be
 * [relatively] safely ignored by defining it to have
 * the value zero.
 */

#ifndef AI_NUMERICSERV
#define AI_NUMERICSERV 0
#endif

#endif
