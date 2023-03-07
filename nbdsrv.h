#ifndef NBDSRV_H
#define NBDSRV_H

#include "lfs.h"

#include <glib.h>
#include <stdbool.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <semaphore.h>
#include "nbd.h"

/* Structures */

/**
 * Types of virtuatlization
 **/
typedef enum {
	VIRT_NONE=0,	/**< No virtualization */
	VIRT_IPLIT,	/**< Literal IP address as part of the filename */
	VIRT_IPHASH,	/**< Replacing all dots in an ip address by a / before
			     doing the same as in IPLIT */
	VIRT_CIDR,	/**< Every subnet in its own directory */
} VIRT_STYLE;

/**
 * Variables associated with a server.
 **/
typedef struct {
	gchar* exportname;    /**< (unprocessed) filename of the file we're exporting */
	uint64_t expected_size; /**< size of the exported file as it was told to
			       us through configuration */
	gchar* listenaddr;   /**< The IP address we're listening on */
	char* authname;      /**< filename of the authorization file */
	int flags;           /**< flags associated with this exported file */
	VIRT_STYLE virtstyle;/**< The style of virtualization, if any */
	uint8_t cidrlen;     /**< The length of the mask when we use
				  CIDR-style virtualization */
	gchar* prerun;	     /**< command to be ran after connecting a client,
				  but before starting to serve */
	gchar* postrun;	     /**< command that will be ran after the client
				  disconnects */
	gchar* servename;    /**< name of the export as selected by nbd-client */
	int max_connections; /**< maximum number of opened connections */
	int numclients;      /**< number of clients connected to this export */
	gchar* transactionlog;/**< filename for transaction log */
	gchar* cowdir;	     /**< directory for copy-on-write diff files. */
	int refcnt;	     /**< reference counter */
} SERVER;

/**
  * Variables associated with a client connection
  */
typedef struct _client {
	uint64_t exportsize;	/**< size of the file we're exporting */
	char *clientname;	/**< peer, in human-readable format */
	struct sockaddr_storage clientaddr; /**< peer, in binary format, network byte order */
	char *exportname;	/**< (processed) filename of the file we're exporting */
	GArray *export;		/**< array of FILE_INFO of exported files;
				     array size is always 1 unless we're doing
				     the multiple file option */
	pthread_rwlock_t export_lock;
	int net;		/**< The actual client socket */
	SERVER *server;		/**< The server this client is getting data from */
	char* difffilename;	/**< filename of the copy-on-write file, if any */
	int difffile;		/**< filedescriptor of copyonwrite file. @todo shouldn't this be an array too? (cfr
				     export) Or make -m and -c mutually exclusive */
	uint32_t difffilelen;	/**< number of pages in difffile */
	uint32_t *difmap;	/**< see comment on the global difmap for this one */
	int transactionlogfd;	/**< fd for transaction log */
	char semname[100];	/**< name of the posix sem that protects access to the transaction log */
	sem_t *logsem;		/**< posix sem that protects access to the transaction log */
	int clientfeats;	/**< Client flags specified during negotiation */
	int clientflags;	/**< Internal flags for this client, as determined by nbd-server */
	pthread_mutex_t lock;	/**< socket lock */
	void *tls_session;	/**< TLS session context. Is NULL unless STARTTLS
				     has been negotiated. */
	int (*socket_read)(struct _client*, void* buf, size_t len);
	int (*socket_write)(struct _client*, void* buf, size_t len);
	void (*socket_closed)(struct _client*);
} CLIENT;

/**
 * Variables associated with an open file
 **/
typedef struct {
	int fhandle;      /**< file descriptor */
	off_t startoff;   /**< starting offset of this file */
} FILE_INFO;

typedef struct {
	struct nbd_request *req;
	char *buf;
	size_t buflen;
	size_t current_offset;
	uint32_t current_len;
	unsigned int is_structured : 1;
	unsigned int df : 1;
} READ_CTX;

/* Constants and macros */

/**
 * Error domain common for all NBD server errors.
 **/
#define NBDS_ERR g_quark_from_static_string("server-error-quark")

/**
 * NBD server error codes.
 **/
typedef enum {
        NBDS_ERR_CFILE_NOTFOUND,          /**< The configuration file is not found */
        NBDS_ERR_CFILE_MISSING_GENERIC,   /**< The (required) group "generic" is missing */
        NBDS_ERR_CFILE_KEY_MISSING,       /**< A (required) key is missing */
        NBDS_ERR_CFILE_VALUE_INVALID,     /**< A value is syntactically invalid */
        NBDS_ERR_CFILE_VALUE_UNSUPPORTED, /**< A value is not supported in this build */
        NBDS_ERR_CFILE_NO_EXPORTS,        /**< A config file was specified that does not
                                               define any exports */
        NBDS_ERR_CFILE_INCORRECT_PORT,    /**< The reserved port was specified for an
                                               old-style export. */
        NBDS_ERR_CFILE_DIR_UNKNOWN,       /**< A directory requested does not exist*/
        NBDS_ERR_CFILE_READDIR_ERR,       /**< Error occurred during readdir() */
        NBDS_ERR_CFILE_INVALID_SPLICE,    /**< We can't use splice with the other options
                                               specified for the export. */
        NBDS_ERR_SO_LINGER,               /**< Failed to set SO_LINGER to a socket */
        NBDS_ERR_SO_REUSEADDR,            /**< Failed to set SO_REUSEADDR to a socket */
        NBDS_ERR_SO_KEEPALIVE,            /**< Failed to set SO_KEEPALIVE to a socket */
        NBDS_ERR_GAI,                     /**< Failed to get address info */
        NBDS_ERR_SOCKET,                  /**< Failed to create a socket */
        NBDS_ERR_BIND,                    /**< Failed to bind an address to socket */
        NBDS_ERR_LISTEN,                  /**< Failed to start listening on a socket */
        NBDS_ERR_SYS,                     /**< Underlying system call or library error */
        NBDS_ERR_CFILE_INVALID_WAIT,      /**< We can't use wait with the other options
                                               specified for the export. */
} NBDS_ERRS;

/**
  * Logging macros.
  *
  * @todo remove this. We should use g_log in all cases, and use the
  * logging mangler to redirect to syslog if and when necessary.
  */
#ifdef ISSERVER
#define msg(prio, ...) syslog(prio, __VA_ARGS__)
#else
#define msg(prio, ...) g_log(G_LOG_DOMAIN, G_LOG_LEVEL_MESSAGE, __VA_ARGS__)
#endif
#define MY_NAME "nbd_server"

/** Per-export flags: */
#define F_READONLY 1      /**< flag to tell us a file is readonly */
#define F_MULTIFILE 2	  /**< flag to tell us a file is exported using -m */
#define F_COPYONWRITE 4	  /**< flag to tell us a file is exported using
			    copyonwrite */
#define F_AUTOREADONLY 8  /**< flag to tell us a file is set to autoreadonly */
#define F_SPARSE 16	  /**< flag to tell us copyronwrite should use a sparse file */
#define F_SDP 32	  /**< flag to tell us the export should be done using the Socket Direct Protocol for RDMA */
#define F_SYNC 64	  /**< Whether to fsync() after a write */
#define F_FLUSH 128	  /**< Whether server wants FLUSH to be sent by the client */
#define F_FUA 256	  /**< Whether server wants FUA to be sent by the client */
#define F_ROTATIONAL 512  /**< Whether server wants the client to implement the elevator algorithm */
#define F_TEMPORARY 1024  /**< Whether the backing file is temporary and should be created then unlinked */
#define F_TRIM 2048       /**< Whether server wants TRIM (discard) to be sent by the client */
#define F_FIXED 4096	  /**< Client supports fixed new-style protocol (and can thus send us extra options */
#define F_TREEFILES 8192  /**< flag to tell us a file is exported using -t */
#define F_FORCEDTLS 16384 /**< TLS is required, either for the server as a whole or for a given export */
#define F_SPLICE 32768	  /**< flag to tell us to use splice for read/write operations */
#define F_WAIT 65536      /**< flag to tell us to wait for file creation */
#define F_DATALOG 131072  /**< flag to tell us that the transaction log shall contain the written data */

/** Internal flags (for clientflags) */

#define F_STRUCTURED 1

/* Functions */

/**
  * Check whether a given address matches a given netmask.
  *
  * @param mask the address or netmask to check against, in ASCII representation
  * @param addr the address to check
  *
  * @return true if the address matches the mask, false otherwise; in case of
  * failure to parse netmask, returns false with err set appropriately.
  * @todo decide what to do with v6-mapped IPv4 addresses.
  */
bool address_matches(const char* mask, const struct sockaddr* addr, GError** err);

/**
  * Gets a byte to allow for address masking.
  *
  * @param masklen the length of the requested mask.
  * @return if the length of the mask is 8 or longer, 0xFF. Otherwise, a byte
  * with `masklen' number of leading bits set to 1, everything else set to 0.
  */
uint8_t getmaskbyte(int masklen) G_GNUC_PURE;

/**
 * Check whether a client is allowed to connect. Works with an authorization
 * file which contains one line per machine or network, with CIDR-style
 * netmasks.
 *
 * @param opts The client who's trying to connect.
 * @return 0 - authorization refused, 1 - OK
 **/
int authorized_client(CLIENT *opts);

/**
 * duplicate server
 * @param s the old server we want to duplicate
 * @return new duplicated server
 **/
SERVER* dup_serve(const SERVER *const s);

/**
 * Detect the size of a file.
 *
 * @param fhandle An open filedescriptor
 * @return the size of the file, or UINT64_MAX if detection was
 * impossible.
 **/
uint64_t size_autodetect(int fhandle);

/**
 * increase the ref counter for a SERVER
 *
 * @param s the server to increase
 **/
SERVER* serve_inc_ref(SERVER *s);

/**
 * decrement the reference counter or a SERVER
 *
 * @param s the server to decrement
 **/
SERVER* serve_dec_ref(SERVER *s);

/**
 * call serve_dec_ref on *s
 *
 * @param s a pointer to a pointer to a SERVER to decrement
 **/
void serve_clear_element(SERVER **s);

/**
 * Punch a hole in the backend file (if supported by the current system).
 *
 * @param req the request for which this is being processed
 * @param client the client for which we're processing this request
 **/
int exptrim(struct nbd_request* req, CLIENT* client);
#endif //NBDSRV_H
