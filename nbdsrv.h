#ifndef NBDSRV_H
#define NBDSRV_H

#include <glib.h>
#include <stdbool.h>
#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

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
	off_t expected_size; /**< size of the exported file as it was told to
			       us through configuration */
	gchar* listenaddr;   /**< The IP address we're listening on */
	unsigned int port;   /**< port we're exporting this file at */
	char* authname;      /**< filename of the authorization file */
	int flags;           /**< flags associated with this exported file */
	int socket;	     /**< The socket of this server. */
	int socket_family;   /**< family of the socket */
	VIRT_STYLE virtstyle;/**< The style of virtualization, if any */
	uint8_t cidrlen;     /**< The length of the mask when we use
				  CIDR-style virtualization */
	gchar* prerun;	     /**< command to be ran after connecting a client,
				  but before starting to serve */
	gchar* postrun;	     /**< command that will be ran after the client
				  disconnects */
	gchar* servename;    /**< name of the export as selected by nbd-client */
	int max_connections; /**< maximum number of opened connections */
	gchar* transactionlog;/**< filename for transaction log */
} SERVER;

/**
  * Variables associated with a client connection
  */
typedef struct {
	off_t exportsize;    /**< size of the file we're exporting */
	char *clientname;    /**< peer, in human-readable format */
	struct sockaddr_storage clientaddr; /**< peer, in binary format, network byte order */
	char *exportname;    /**< (processed) filename of the file we're exporting */
	GArray *export;    /**< array of FILE_INFO of exported files;
			       array size is always 1 unless we're
			       doing the multiple file option */
	int net;	     /**< The actual client socket */
	SERVER *server;	     /**< The server this client is getting data from */
	char* difffilename;  /**< filename of the copy-on-write file, if any */
	int difffile;	     /**< filedescriptor of copyonwrite file. @todo
			       shouldn't this be an array too? (cfr export) Or
			       make -m and -c mutually exclusive */
	uint32_t difffilelen;     /**< number of pages in difffile */
	uint32_t *difmap;	     /**< see comment on the global difmap for this one */
	gboolean modern;     /**< client was negotiated using modern negotiation protocol */
	int transactionlogfd;/**< fd for transaction log */
	int clientfeats;     /**< Features supported by this client */
} CLIENT;

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
        NBDS_ERR_SO_LINGER,               /**< Failed to set SO_LINGER to a socket */
        NBDS_ERR_SO_REUSEADDR,            /**< Failed to set SO_REUSEADDR to a socket */
        NBDS_ERR_SO_KEEPALIVE,            /**< Failed to set SO_KEEPALIVE to a socket */
        NBDS_ERR_GAI,                     /**< Failed to get address info */
        NBDS_ERR_SOCKET,                  /**< Failed to create a socket */
        NBDS_ERR_BIND,                    /**< Failed to bind an address to socket */
        NBDS_ERR_LISTEN,                  /**< Failed to start listening on a socket */
        NBDS_ERR_SYS,                     /**< Underlying system call or library error */
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

/* Functions */

/**
  * Check whether a given address matches a given netmask.
  *
  * @param mask the address or netmask to check against, in ASCII representation
  * @param addr the address to check, in network byte order
  * @param af the address family of the passed address (AF_INET or AF_INET6)
  *
  * @return true if the address matches the mask, false otherwise; in case of
  * failure to parse netmask, returns false with err set appropriately.
  * @todo decide what to do with v6-mapped IPv4 addresses.
  */
bool address_matches(const char* mask, const void* addr, int af, GError** err);

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

#endif //NBDSRV_H
