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

#ifndef G_GNUC_NORETURN
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
#define G_GNUC_NORETURN __attribute__((__noreturn__))
#define G_GNUC_UNUSED __attribute__((unused))
#else
#define G_GNUC_NORETURN
#define G_GNUC_UNUSED
#endif
#endif

extern const u64 cliserv_magic;
extern const u64 opts_magic;
extern const u64 rep_magic;

#define INIT_PASSWD "NBDMAGIC"

#define INFO(a) do { } while(0)

int set_nonblocking(int fd, int nb);
void setmysockopt(int sock);
void err_nonfatal(const char *s);

void nbd_err(const char *s) G_GNUC_NORETURN;
#define err(S) nbd_err(S)

void logging(const char* name);

#ifndef ntohll
uint64_t ntohll(uint64_t a);
#endif
#ifndef htonll
#define htonll ntohll
#endif

int readit(int f, void *buf, size_t len);
int writeit(int f, void *buf, size_t len);

#define NBD_DEFAULT_PORT	"10809"	/* Port on which named exports are
					 * served */

/* Options that the client can select to the server */
#define NBD_OPT_EXPORT_NAME	 (1)	/**< Client wants to select a named export (is followed by name of export) */
#define NBD_OPT_ABORT		 (2)	/**< Client wishes to abort negotiation */
#define NBD_OPT_LIST		 (3)	/**< Client request list of supported exports (not followed by data) */
#define NBD_OPT_STARTTLS	 (5)	/**< Client wishes to initiate TLS */
#define NBD_OPT_INFO		 (6)	/**< Client wants information about the given export */
#define NBD_OPT_GO		 (7)	/**< Client wants to select the given and move to the transmission phase */
#define NBD_OPT_STRUCTURED_REPLY (8)	/**< Client wants to see structured replies */

/* Replies the server can send during negotiation */
#define NBD_REP_ACK		(1)	/**< ACK a request. Data: option number to be acked */
#define NBD_REP_SERVER		(2)	/**< Reply to NBD_OPT_LIST (one of these per server; must be followed by NBD_REP_ACK to signal the end of the list */
#define NBD_REP_INFO		(3)	/**< Reply to NBD_OPT_INFO */
#define NBD_REP_FLAG_ERROR	(1 << 31)	/** If the high bit is set, the reply is an error */
#define NBD_REP_ERR_UNSUP	(1 | NBD_REP_FLAG_ERROR)	/**< Client requested an option not understood by this version of the server */
#define NBD_REP_ERR_POLICY	(2 | NBD_REP_FLAG_ERROR)	/**< Client requested an option not allowed by server configuration. (e.g., the option was disabled) */
#define NBD_REP_ERR_INVALID	(3 | NBD_REP_FLAG_ERROR)	/**< Client issued an invalid request */
#define NBD_REP_ERR_PLATFORM	(4 | NBD_REP_FLAG_ERROR)	/**< Option not supported on this platform */
#define NBD_REP_ERR_TLS_REQD	(5 | NBD_REP_FLAG_ERROR)	/**< TLS required */
#define NBD_REP_ERR_UNKNOWN	(6 | NBD_REP_FLAG_ERROR)	/**< NBD_OPT_INFO or ..._GO requested on unknown export */
#define NBD_REP_ERR_BLOCK_SIZE_REQD (8 | NBD_REP_FLAG_ERROR)	/**< Server is not willing to serve the export without the block size being negotiated */

/* Global flags */
#define NBD_FLAG_FIXED_NEWSTYLE (1 << 0)	/**< new-style export that actually supports extending */
#define NBD_FLAG_NO_ZEROES	(1 << 1)	/**< we won't send the 128 bits of zeroes if the client sends NBD_FLAG_C_NO_ZEROES */
/* Flags from client to server. */
#define NBD_FLAG_C_FIXED_NEWSTYLE NBD_FLAG_FIXED_NEWSTYLE
#define NBD_FLAG_C_NO_ZEROES	NBD_FLAG_NO_ZEROES

/* Info types */
#define NBD_INFO_EXPORT		(0)
#define NBD_INFO_NAME		(1)
#define NBD_INFO_DESCRIPTION	(2)
#define NBD_INFO_BLOCK_SIZE	(3)
