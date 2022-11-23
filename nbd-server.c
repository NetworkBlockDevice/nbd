/*
 * Network Block Device - server
 *
 * Copyright 1996-1998 Pavel Machek, distribute under GPL
 *  <pavel@atrey.karlin.mff.cuni.cz>
 * Copyright 2001-2004 Wouter Verhelst <wouter@debian.org>
 * Copyright 2002 Anton Altaparmakov <aia21@cam.ac.uk>
 *
 * Version 1.0 - hopefully 64-bit-clean
 * Version 1.1 - merging enhancements from Josh Parsons, <josh@coombs.anu.edu.au>
 * Version 1.2 - autodetect size of block devices, thanx to Peter T. Breuer" <ptb@it.uc3m.es>
 * Version 1.5 - can compile on Unix systems that don't have 64 bit integer
 *	type, or don't have 64 bit file offsets by defining FS_32BIT
 *	in compile options for nbd-server *only*. This can be done
 *	with make FSCHOICE=-DFS_32BIT nbd-server. (I don't have the
 *	original autoconf input file, or I would make it a configure
 *	option.) Ken Yap <ken@nlc.net.au>.
 * Version 1.6 - fix autodetection of block device size and really make 64 bit
 * 	clean on 32 bit machines. Anton Altaparmakov <aia21@cam.ac.uk>
 * Version 2.0 - Version synchronised with client
 * Version 2.1 - Reap zombie client processes when they exit. Removed
 * 	(uncommented) the _IO magic, it's no longer necessary. Wouter
 * 	Verhelst <wouter@debian.org>
 * Version 2.2 - Auto switch to read-only mode (usefull for floppies).
 * Version 2.3 - Fixed code so that Large File Support works. This
 *	removes the FS_32BIT compile-time directive; define
 *	_FILE_OFFSET_BITS=64 and _LARGEFILE_SOURCE if you used to be
 *	using FS_32BIT. This will allow you to use files >2GB instead of
 *	having to use the -m option. Wouter Verhelst <wouter@debian.org>
 * Version 2.4 - Added code to keep track of children, so that we can
 * 	properly kill them from initscripts. Add a call to daemon(),
 * 	so that processes don't think they have to wait for us, which is
 * 	interesting for initscripts as well. Wouter Verhelst
 * 	<wouter@debian.org>
 * Version 2.5 - Bugfix release: forgot to reset child_arraysize to
 *      zero after fork()ing, resulting in nbd-server going berserk
 *      when it receives a signal with at least one child open. Wouter
 *      Verhelst <wouter@debian.org>
 * 10/10/2003 - Added socket option SO_KEEPALIVE (sf.net bug 819235);
 * 	rectified type of mainloop::size_host (sf.net bugs 814435 and
 * 	817385); close the PID file after writing to it, so that the
 * 	daemon can actually be found. Wouter Verhelst
 * 	<wouter@debian.org>
 * 10/10/2003 - Size of the data "size_host" was wrong and so was not
 *  	correctly put in network endianness. Many types were corrected
 *  	(size_t and off_t instead of int).  <vspaceg@sourceforge.net>
 * Version 2.6 - Some code cleanup.
 * Version 2.7 - Better build system.
 * 11/02/2004 - Doxygenified the source, modularized it a bit. Needs a 
 * 	lot more work, but this is a start. Wouter Verhelst
 * 	<wouter@debian.org>
 * 16/03/2010 - Add IPv6 support.
 *	Kitt Tientanopajai <kitt@kitty.in.th>
 *	Neutron Soutmun <neo.neutron@gmail.com>
 *	Suriya Soutmun <darksolar@gmail.com>
 */

/* Includes LFS defines, which defines behaviours of some of the following
 * headers, so must come before those */
#include "lfs.h"
#define _DEFAULT_SOURCE
#define _XOPEN_SOURCE 500 /* to get pread/pwrite */
#if NEED_BSD_SOURCE
#define _BSD_SOURCE /* to get DT_* macros on some platforms */
#endif
#define _DARWIN_C_SOURCE /* to get DT_* macros on OS X */

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/un.h>
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include <sys/param.h>
#include <signal.h>
#include <errno.h>
#include <libgen.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#if HAVE_FALLOC_PH
#include <linux/falloc.h>
#endif
#if HAVE_BLKDISCARD
#include <linux/fs.h>
#endif
#include <arpa/inet.h>
#include <strings.h>
#include <dirent.h>
#ifdef HAVE_SYS_DIR_H
#include <sys/dir.h>
#endif
#ifdef HAVE_SYS_DIRENT_H
#include <sys/dirent.h>
#endif
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <ctype.h>
#include <inttypes.h>

#include <glib.h>

#if HAVE_OLD_GLIB
#include <pthread.h>
#endif

/* used in cliserv.h, so must come first */
#define MY_NAME "nbd_server"
#include "cliserv.h"
#include "nbd-debug.h"
#include "netdb-compat.h"
#include "backend.h"
#include "treefiles.h"
#include "nbd-helper.h"

#ifdef WITH_SDP
#include <sdp_inet.h>
#endif

#if HAVE_FSCTL_SET_ZERO_DATA
#include <io.h>
/* don't include <windows.h> to avoid redefining eg the ERROR macro */
#define NOMINMAX 1
#include <windef.h>
#include <winbase.h>
#include <winioctl.h>
#endif

/** Default position of the config file */
#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif
#define CFILE SYSCONFDIR "/nbd-server/config"

#if HAVE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#endif

#ifndef HAVE_G_MEMDUP2
/* Our uses of g_memdup2 below are safe from g_memdup's 32-bit overflow */
#define g_memdup2 g_memdup
#endif

/** Where our config file actually is */
gchar* config_file_pos;

/** global flags */
int glob_flags=0;

/* Whether we should avoid daemonizing the main process */
int nodaemon = 0;

/* Whether we should avoid forking into child processes */
int dontfork = 0;

/**
 * The highest value a variable of type off_t can reach. This is a signed
 * integer, so set all bits except for the leftmost one.
 **/
#define OFFT_MAX ~((off_t)1<<(sizeof(off_t)*8-1))
#define BUFSIZE ((1024*1024)+sizeof(struct nbd_reply)) /**< Size of buffer that can hold requests */
#define DIFFPAGESIZE 4096 /**< diff file uses those chunks */

/** Global flags: */
#define F_OLDSTYLE 1	  /**< Allow oldstyle (port-based) exports */
#define F_LIST 2	  /**< Allow clients to list the exports on a server */
#define F_NO_ZEROES 4	  /**< Do not send zeros to client */
#define F_DUAL_LISTEN 8	  /**< Listen on both TCP and unix socket */
// also accepts F_FORCEDTLS (which is 16384)
GHashTable *children;
char pidfname[256]; /**< name of our PID file */
char default_authname[] = SYSCONFDIR "/nbd-server/allow"; /**< default name of allow file */

#define NEG_INIT	(1 << 0)
#define NEG_OLD		(1 << 1)
#define NEG_MODERN	(1 << 2)

/*
 * If we want what the system really has set we'd have to read
 * /proc/sys/fs/pipe-max-size, but for now 1mb should be enough.
 */
#define MAX_PIPE_SIZE (1 * 1024 * 1024)
#define SPLICE_IN	0
#define SPLICE_OUT	1

#include <nbdsrv.h>

/* Our thread pool */
GThreadPool *tpool;

/* A work package for the thread pool functions */
struct work_package {
	CLIENT* client;
	struct nbd_request* req;
	int pipefd[2];
	void* data; /**< for write requests */
};

static volatile sig_atomic_t is_sigchld_caught; /**< Flag set by
						     SIGCHLD handler
						     to mark a child
						     exit */

static volatile sig_atomic_t is_sigterm_caught; /**< Flag set by
						     SIGTERM handler
						     to mark a exit
						     request */

static volatile sig_atomic_t is_sighup_caught; /**< Flag set by SIGHUP
                                                    handler to mark a
                                                    reconfiguration
                                                    request */

GArray* modernsocks;	  /**< Sockets for the modern handler. Not used
			       if a client was only specified on the
			       command line; only port used if
			       oldstyle is set to false (and then the
			       command-line client isn't used, gna gna).
			       This may be more than one socket on
			       systems that don't support serving IPv4
			       and IPv6 from the same socket (like,
			       e.g., FreeBSD) */
GArray* childsocks;	/**< parent-side sockets for communication with children */
int commsocket;		/**< child-side socket for communication with parent */
static sem_t file_wait_sem;

bool logged_oversized=false;  /**< whether we logged oversized requests already */

/**
 * Type of configuration file values
 **/
typedef enum {
	PARAM_INT,		/**< This parameter is an integer */
	PARAM_INT64,		/**< This parameter is an integer */
	PARAM_STRING,		/**< This parameter is a string */
	PARAM_BOOL,		/**< This parameter is a boolean */
} PARAM_TYPE;

/**
 * Configuration file values
 **/
typedef struct {
	gchar *paramname;	/**< Name of the parameter, as it appears in
				  the config file */
	gboolean required;	/**< Whether this is a required (as opposed to
				  optional) parameter */
	PARAM_TYPE ptype;	/**< Type of the parameter. */
	gpointer target;	/**< Pointer to where the data of this
				  parameter should be written. If ptype is
				  PARAM_BOOL, the data is or'ed rather than
				  overwritten. */
	gint flagval;		/**< Flag mask for this parameter in case ptype
				  is PARAM_BOOL. */
} PARAM;

/**
 * Configuration file values of the "generic" section
 **/
struct generic_conf {
        gchar *user;            /**< user we run the server as    */
        gchar *group;           /**< group we run running as      */
        gchar *modernaddr;      /**< address of the modern socket */
        gchar *modernport;      /**< port of the modern socket    */
        gchar *unixsock;	/**< file name of the unix domain socket */
	gchar *certfile;        /**< certificate file             */
	gchar *keyfile;         /**< key file                     */
	gchar *cacertfile;      /**< CA certificate file          */
	gchar *tlsprio;		/**< TLS priority string	  */
        gint flags;             /**< global flags                 */
	gint threads;		/**< maximum number of parallel threads we want to run */
};

#if HAVE_GNUTLS
static int writeit_tls(gnutls_session_t s, void *buf, size_t len) {
	ssize_t res;
	char *m;
	while(len > 0) {
		DEBUG("+");
		if ((res = gnutls_record_send(s, buf, len)) < 0 && !gnutls_error_is_fatal(res)) {
			m = g_strdup_printf("issue while sending data: %s", gnutls_strerror(res));
			err_nonfatal(m);
			g_free(m);
		} else if(res < 0) {
			m = g_strdup_printf("could not send data: %s", gnutls_strerror(res));
			err_nonfatal(m);
			g_free(m);
			return -1;
		} else {
			len -= res;
			buf += res;
		}
	}
	return 0;
}

static int readit_tls(gnutls_session_t s, void *buf, size_t len) {
	ssize_t res;
	char *m;
	while(len > 0) {
		DEBUG("*");
		if((res = gnutls_record_recv(s, buf, len)) < 0 && !gnutls_error_is_fatal(res)) {
			m = g_strdup_printf("issue while receiving data: %s", gnutls_strerror(res));
			err_nonfatal(m);
			g_free(m);
		} else if(res < 0) {
			m = g_strdup_printf("could not receive data: %s", gnutls_strerror(res));
			err_nonfatal(m);
			g_free(m);
			return -1;
		} else {
			len -= res;
			buf += res;
		}
	}
	return 0;
}

static int socket_read_tls(CLIENT* client, void *buf, size_t len) {
	return readit_tls(*((gnutls_session_t*)client->tls_session), buf, len);
}

static int socket_write_tls(CLIENT* client, void *buf, size_t len) {
	return writeit_tls(*((gnutls_session_t*)client->tls_session), buf, len);
}
#endif // HAVE_GNUTLS

static int socket_read_notls(CLIENT* client, void *buf, size_t len) {
	return readit(client->net, buf, len);
}

static int socket_write_notls(CLIENT* client, void *buf, size_t len) {
	return writeit(client->net, buf, len);
}

static void socket_read(CLIENT* client, void *buf, size_t len) {
	g_assert(client->socket_read != NULL);
	if(client->socket_read(client, buf, len)<0) {
		g_assert(client->socket_closed != NULL);
		client->socket_closed(client);
	}
}

/**
 * Consume data from a socket that we don't want
 *
 * @param c the client to read from
 * @param len the number of bytes to consume
 * @param buf a buffer
 * @param bufsiz the size of the buffer
 **/
static inline void consume(CLIENT* c, size_t len, void * buf, size_t bufsiz) {
	size_t curlen;
	while (len>0) {
		curlen = (len>bufsiz)?bufsiz:len;
		socket_read(c, buf, curlen);
		len -= curlen;
	}
}

/**
 * Consume a length field and corresponding payload that we don't want
 *
 * @param c the client to read from
 **/
static inline void consume_len(CLIENT* c) {
	uint32_t len;
	char buf[1024];

	socket_read(c, &len, sizeof(len));
	len = ntohl(len);
	consume(c, len, buf, sizeof(buf));
}

static void socket_write(CLIENT* client, void *buf, size_t len) {
	g_assert(client->socket_write != NULL);
	if(client->socket_write(client, buf, len)<0) {
		g_assert(client->socket_closed != NULL);
		client->socket_closed(client);
	}
}

static inline void socket_closed_negotiate(CLIENT* client) {
	err("Negotiation failed: %m");
}

static void cleanup_transactionlog(CLIENT *client) {

	if (client->transactionlogfd != -1) {
		close(client->transactionlogfd);
		client->transactionlogfd = -1;
	}
	if (client->logsem != SEM_FAILED) {
		sem_close(client->logsem);
		client->logsem = SEM_FAILED;
		sem_unlink(client->semname);
	}
}

static void lock_logsem(CLIENT *client) {
	sem_wait(client->logsem);
}
static void unlock_logsem(CLIENT *client) {
	sem_post(client->logsem);
}

/**
 * Run a command. This is used for the ``prerun'' and ``postrun'' config file
 * options
 *
 * @param command the command to be ran. Read from the config file
 * @param file the file name we're about to export
 **/
int do_run(gchar* command, gchar* file) {
	gchar* cmd;
	int retval=0;

	if(command && *command) {
		cmd = g_strdup_printf(command, file);
		retval=system(cmd);
		g_free(cmd);
	}
	return retval;
}

static inline void finalize_client(CLIENT* client) {
	g_thread_pool_free(tpool, FALSE, TRUE);
	do_run(client->server->postrun, client->exportname);
	if(client->transactionlogfd != -1)
		cleanup_transactionlog(client);

	if(client->server->flags & F_COPYONWRITE) {
		unlink(client->difffilename);
	}
	serve_dec_ref(client->server);
}

static inline void socket_closed_transmission(CLIENT* client) {
	int saved_errno = errno;
	finalize_client(client);
	errno = saved_errno;
	err("Connection dropped: %m");
}

#ifdef HAVE_SPLICE
/**
 * Splice data between a pipe and a file descriptor
 *
 * @param fd_in The fd to splice from.
 * @param off_in The fd_in offset to splice from.
 * @param fd_out The fd to splice to.
 * @param off_out The fd_out offset to splice to.
 * @param len The length to splice.
 */
static inline void spliceit(int fd_in, loff_t *off_in, int fd_out,
			    loff_t *off_out, size_t len)
{
	ssize_t ret;
	while (len > 0) {
		if ((ret = splice(fd_in, off_in, fd_out, off_out, len,
				  SPLICE_F_MOVE)) <= 0)
			err("Splice failed: %m");
		len -= ret;
	}
}
#endif

/**
 * Print out a message about how to use nbd-server. Split out to a separate
 * function so that we can call it from multiple places
 */
void usage() {
	printf("This is nbd-server version " VERSION "\n");
	printf("Usage: [ip:|ip6@]port file_to_export [size][kKmM] [-l authorize_file] [-r] [-m] [-c] [-C configuration file] [-p PID file name] [-o section name] [-M max connections] [-V] [-n] [-d]\n"
	       "\t-r|--read-only\t\tread only\n"
	       "\t-m|--multi-file\t\tmultiple file\n"
	       "\t-c|--copy-on-write\tcopy on write\n"
	       "\t-C|--config-file\tspecify an alternate configuration file\n"
	       "\t-l|--authorize-file\tfile with list of hosts that are allowed to\n\t\t\t\tconnect.\n"
	       "\t-p|--pid-file\t\tspecify a filename to write our PID to\n"
	       "\t-o|--output-config\toutput a config file section for what you\n\t\t\t\tspecified on the command line, with the\n\t\t\t\tspecified section name\n"
	       "\t-M|--max-connection\tspecify the maximum number of opened connections\n"
	       "\t-V|--version\t\toutput the version and exit\n"
	       "\t-n|--nodaemon\t\tdo not daemonize main process\n"
	       "\t-d|--dont-fork\t\tdo not fork (implies --nodaemon)\n\n"
	       "\tif port is set to 0, stdin is used (for running from inetd).\n"
	       "\tif file_to_export contains '%%s', it is substituted with the IP\n"
	       "\t\taddress of the machine trying to connect\n" 
	       "\tif ip is set, it contains the local IP address on which we're listening.\n\tif not, the server will listen on all local IP addresses\n");
	printf("Using configuration file %s\n", CFILE);
	printf("For help, or when encountering bugs, please contact %s\n", PACKAGE_BUGREPORT);
}

/* Dumps a config file section of the given SERVER*, and exits. */
void dump_section(SERVER* serve, gchar* section_header) {
	printf("[%s]\n", section_header);
	printf("\texportname = %s\n", serve->exportname);
	printf("\tlistenaddr = %s\n", serve->listenaddr);
	if(serve->flags & F_READONLY) {
		printf("\treadonly = true\n");
	}
	if(serve->flags & F_MULTIFILE) {
		printf("\tmultifile = true\n");
	}
	if(serve->flags & F_TREEFILES) {
		printf("\ttreefiles = true\n");
	}
	if(serve->flags & F_COPYONWRITE) {
		printf("\tcopyonwrite = true\n");
	}
	if(serve->expected_size) {
		printf("\tfilesize = %lld\n", (long long int)serve->expected_size);
	}
	if(serve->authname) {
		printf("\tauthfile = %s\n", serve->authname);
	}
	exit(EXIT_SUCCESS);
}

/**
 * Parse the command line.
 *
 * @param argc the argc argument to main()
 * @param argv the argv argument to main()
 **/
SERVER* cmdline(int argc, char *argv[], struct generic_conf *genconf) {
	int i=0;
	int nonspecial=0;
	int c;
	struct option long_options[] = {
		{"read-only", no_argument, NULL, 'r'},
		{"multi-file", no_argument, NULL, 'm'},
		{"copy-on-write", no_argument, NULL, 'c'},
		{"nodaemon", no_argument, NULL, 'n'},
		{"dont-fork", no_argument, NULL, 'd'},
		{"authorize-file", required_argument, NULL, 'l'},
		{"config-file", required_argument, NULL, 'C'},
		{"pid-file", required_argument, NULL, 'p'},
		{"output-config", required_argument, NULL, 'o'},
		{"max-connection", required_argument, NULL, 'M'},
		{"version", no_argument, NULL, 'V'},
		{0,0,0,0}
	};
	SERVER *serve;
	off_t es;
	size_t last;
	char suffix;
	bool do_output=false;
	gchar* section_header="";
	gchar** addr_port;

	if(argc==1) {
		return NULL;
	}
	serve=serve_inc_ref((SERVER*)g_new0(SERVER, 1));
	serve->authname = g_strdup(default_authname);
	serve->virtstyle=VIRT_IPLIT;
	while((c=getopt_long(argc, argv, "-C:cwndl:mo:rp:M:V", long_options, &i))>=0) {
		switch (c) {
		case 1:
			/* non-option argument */
			switch(nonspecial++) {
			case 0:
				if(strchr(optarg, ':') == strrchr(optarg, ':')) {
					addr_port=g_strsplit(optarg, ":", 2);

					/* Check for "@" - maybe user using this separator
						 for IPv4 address */
					if(!addr_port[1]) {
						g_strfreev(addr_port);
						addr_port=g_strsplit(optarg, "@", 2);
					}
				} else {
					addr_port=g_strsplit(optarg, "@", 2);
				}

				if(addr_port[1]) {
					genconf->modernport=g_strdup(addr_port[1]);
					genconf->modernaddr=g_strdup(addr_port[0]);
				} else {
					g_free(genconf->modernaddr);
					genconf->modernaddr=NULL;
					genconf->modernport=g_strdup(addr_port[0]);
				}
				g_strfreev(addr_port);
				break;
			case 1:
				serve->exportname = g_strdup(optarg);
				if(serve->exportname[0] != '/') {
					fprintf(stderr, "E: The to be exported file needs to be an absolute filename!\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 2:
				last=strlen(optarg)-1;
				suffix=optarg[last];
				if (suffix == 'k' || suffix == 'K' ||
				    suffix == 'm' || suffix == 'M')
					optarg[last] = '\0';
				es = (off_t)atoll(optarg);
				switch (suffix) {
					case 'm':
					case 'M':  es <<= 10;
					case 'k':
					case 'K':  es <<= 10;
					default :  break;
				}
				serve->expected_size = es;
				break;
			}
			break;
		case 'r':
			serve->flags |= F_READONLY;
			break;
		case 'm':
			serve->flags |= F_MULTIFILE;
			break;
		case 'o':
			do_output = true;
			section_header = g_strdup(optarg);
			break;
		case 'p':
			strncpy(pidfname, optarg, 256);
			pidfname[255]='\0';
			break;
		case 'c': 
			serve->flags |=F_COPYONWRITE;
		        break;
		case 'n':
			nodaemon = 1;
		        break;
		case 'd': 
			dontfork = 1;
			nodaemon = 1;
		        break;
		case 'C':
			g_free(config_file_pos);
			config_file_pos=g_strdup(optarg);
			break;
		case 'l':
			g_free(serve->authname);
			serve->authname=g_strdup(optarg);
			break;
		case 'M':
			serve->max_connections = strtol(optarg, NULL, 0);
			break;
		case 'V':
			printf("This is nbd-server version " VERSION "\n");
			exit(EXIT_SUCCESS);
			break;
		default:
			usage();
			exit(EXIT_FAILURE);
			break;
		}
	}
	/* What's left: the port to export, the name of the to be exported
	 * file, and, optionally, the size of the file, in that order. */
	if(nonspecial<2) {
		serve=serve_dec_ref(serve);
	} else {
		serve->servename = "";
	}
	if(do_output) {
		if(!serve) {
			g_critical("Need a complete configuration on the command line to output a config file section!");
			exit(EXIT_FAILURE);
		}
		dump_section(serve, section_header);
	}
	return serve;
}

/* forward definition of parse_cfile */
GArray* parse_cfile(gchar* f, struct generic_conf *genconf, bool expect_generic, GError** e);

#ifdef HAVE_STRUCT_DIRENT_D_TYPE
#define NBD_D_TYPE de->d_type
#else
#define NBD_D_TYPE 0
#define DT_UNKNOWN 0
#define DT_REG 1
#endif

/**
 * Parse config file snippets in a directory. Uses readdir() and friends
 * to find files and open them, then passes them on to parse_cfile
 * with have_global set false
 **/
GArray* do_cfile_dir(gchar* dir, struct generic_conf *const genconf, GError** e) {
	DIR* dirh = opendir(dir);
	struct dirent* de;
	gchar* fname;
	GArray* retval = NULL;
	GArray* tmp;
	struct stat stbuf;

	if(!dirh) {
		g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_DIR_UNKNOWN, "Invalid directory specified: %s", strerror(errno));
		return NULL;
	}
	errno=0;
	while((de = readdir(dirh))) {
		int saved_errno=errno;
		fname = g_build_filename(dir, de->d_name, NULL);
		switch(NBD_D_TYPE) {
			case DT_UNKNOWN:
				/* Filesystem doesn't return type of
				 * file through readdir, or struct dirent
				 * doesn't have d_type. Run stat() on the file
				 * instead */
				if(stat(fname, &stbuf)) {
					perror("stat");
					goto err_out;
				}
				if (!S_ISREG(stbuf.st_mode)) {
					goto next;
				}
			case DT_REG:
				/* Skip unless the name ends with '.conf' */
				if(strcmp((de->d_name + strlen(de->d_name) - 5), ".conf")) {
					goto next;
				}
				tmp = parse_cfile(fname, genconf, false, e);
				errno=saved_errno;
				if(*e) {
					goto err_out;
				}
				if(!retval)
					retval = g_array_new(FALSE, TRUE, sizeof(SERVER*));
				retval = g_array_append_vals(retval, tmp->data, tmp->len);
				g_array_free(tmp, TRUE);
			default:
				break;
		}
	next:
		g_free(fname);
	}
	if(errno) {
		g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_READDIR_ERR, "Error trying to read directory: %s", strerror(errno));
	err_out:
		if(retval)
			g_array_free(retval, TRUE);
		retval = NULL;
	}
	if(dirh)
		closedir(dirh);
	return retval;
}

/**
 * Parse the config file.
 *
 * @param f the name of the config file
 *
 * @param genconf a pointer to generic configuration which will get
 *        updated with parsed values. If NULL, then parsed generic
 *        configuration values are safely and silently discarded.
 *
 * @param e a GError. Error code can be any of the following:
 *        NBDS_ERR_CFILE_NOTFOUND, NBDS_ERR_CFILE_MISSING_GENERIC,
 *        NBDS_ERR_CFILE_VALUE_INVALID, NBDS_ERR_CFILE_VALUE_UNSUPPORTED
 *        or NBDS_ERR_CFILE_NO_EXPORTS. @see NBDS_ERRS.
 *
 * @param expect_generic if true, we expect a configuration file that
 * 	  contains a [generic] section. If false, we don't.
 *
 * @return a GArray of SERVER* pointers. If the config file is empty or does not
 *	exist, returns an empty GArray; if the config file contains an
 *	error, returns NULL, and e is set appropriately
 **/
GArray* parse_cfile(gchar* f, struct generic_conf *const genconf, bool expect_generic, GError** e) {
	const char* DEFAULT_ERROR = "Could not parse %s in group %s: %s";
	const char* MISSING_REQUIRED_ERROR = "Could not find required value %s in group %s: %s";
	gchar* cfdir = NULL;
	SERVER s;
	gchar *virtstyle=NULL;
	PARAM lp[] = {
		{ "exportname", TRUE,	PARAM_STRING, 	&(s.exportname),	0 },
		{ "authfile",	FALSE,	PARAM_STRING,	&(s.authname),		0 },
		{ "filesize",	FALSE,	PARAM_OFFT,	&(s.expected_size),	0 },
		{ "virtstyle",	FALSE,	PARAM_STRING,	&(virtstyle),		0 },
		{ "prerun",	FALSE,	PARAM_STRING,	&(s.prerun),		0 },
		{ "postrun",	FALSE,	PARAM_STRING,	&(s.postrun),		0 },
		{ "transactionlog", FALSE, PARAM_STRING, &(s.transactionlog),	0 },
		{ "cowdir",	FALSE,	PARAM_STRING,	&(s.cowdir),		0 },
		{ "readonly",	FALSE,	PARAM_BOOL,	&(s.flags),		F_READONLY },
		{ "multifile",	FALSE,	PARAM_BOOL,	&(s.flags),		F_MULTIFILE },
		{ "treefiles",	FALSE,	PARAM_BOOL,	&(s.flags),		F_TREEFILES },
		{ "copyonwrite", FALSE,	PARAM_BOOL,	&(s.flags),		F_COPYONWRITE },
		{ "waitfile",   FALSE,	PARAM_BOOL,	&(s.flags),		F_WAIT },
		{ "sparse_cow",	FALSE,	PARAM_BOOL,	&(s.flags),		F_SPARSE },
		{ "sdp",	FALSE,	PARAM_BOOL,	&(s.flags),		F_SDP },
		{ "sync",	FALSE,  PARAM_BOOL,	&(s.flags),		F_SYNC },
		{ "flush",	FALSE,  PARAM_BOOL,	&(s.flags),		F_FLUSH },
		{ "fua",	FALSE,  PARAM_BOOL,	&(s.flags),		F_FUA },
		{ "rotational",	FALSE,  PARAM_BOOL,	&(s.flags),		F_ROTATIONAL },
		{ "temporary",	FALSE,  PARAM_BOOL,	&(s.flags),		F_TEMPORARY },
		{ "trim",	FALSE,  PARAM_BOOL,	&(s.flags),		F_TRIM },
		{ "datalog",	FALSE,  PARAM_BOOL,	&(s.flags),		F_DATALOG },
		{ "listenaddr", FALSE,  PARAM_STRING,   &(s.listenaddr),	0 },
		{ "maxconnections", FALSE, PARAM_INT,	&(s.max_connections),	0 },
		{ "force_tls",	FALSE,	PARAM_BOOL,	&(s.flags),		F_FORCEDTLS },
		{ "splice",	FALSE,	PARAM_BOOL,	&(s.flags),		F_SPLICE},
	};
	const int lp_size=sizeof(lp)/sizeof(PARAM);
        struct generic_conf genconftmp;
	PARAM gp[] = {
		{ "user",	FALSE, PARAM_STRING,	&(genconftmp.user),       0 },
		{ "group",	FALSE, PARAM_STRING,	&(genconftmp.group),      0 },
		{ "oldstyle",	FALSE, PARAM_BOOL,	&(genconftmp.flags),      F_OLDSTYLE }, // only left here so we can issue an appropriate error message when the option is used
		{ "listenaddr", FALSE, PARAM_STRING,	&(genconftmp.modernaddr), 0 },
		{ "port", 	FALSE, PARAM_STRING,	&(genconftmp.modernport), 0 },
		{ "includedir", FALSE, PARAM_STRING,	&cfdir,                   0 },
		{ "allowlist",  FALSE, PARAM_BOOL,	&(genconftmp.flags),      F_LIST },
		{ "unixsock",	FALSE, PARAM_STRING,    &(genconftmp.unixsock),   0 },
		{ "duallisten",	FALSE, PARAM_BOOL,	&(genconftmp.flags),	  F_DUAL_LISTEN }, // Used to listen on both TCP and unix socket
		{ "max_threads", FALSE, PARAM_INT,	&(genconftmp.threads),	  0 },
		{ "force_tls", FALSE, PARAM_BOOL,	&(genconftmp.flags),	  F_FORCEDTLS },
		{ "certfile",   FALSE, PARAM_STRING,    &(genconftmp.certfile),   0 },
		{ "keyfile",    FALSE, PARAM_STRING,    &(genconftmp.keyfile),    0 },
		{ "cacertfile", FALSE, PARAM_STRING,    &(genconftmp.cacertfile), 0 },
		{ "tlsprio",	FALSE,  PARAM_STRING,   &(genconftmp.tlsprio),    0 },
	};
	PARAM* p=gp;
	int p_size=sizeof(gp)/sizeof(PARAM);
	GKeyFile *cfile;
	GError *err = NULL;
	const char *err_msg=NULL;
	GArray *retval=NULL;
	gchar **groups;
	gboolean bval;
	gint ival;
	gint64 i64val;
	gchar* sval;
	gchar* startgroup;
	gint i;
	gint j;

        memset(&genconftmp, 0, sizeof(struct generic_conf));

	genconftmp.tlsprio = "NORMAL:-VERS-TLS-ALL:+VERS-TLS1.2:%SERVER_PRECEDENCE";

        if (genconf) {
                /* Use the passed configuration values as defaults. The
                 * parsing algorithm below updates all parameter targets
                 * found from configuration files. */
                memcpy(&genconftmp, genconf, sizeof(struct generic_conf));
        }

	cfile = g_key_file_new();
	retval = g_array_new(FALSE, TRUE, sizeof(SERVER*));
	if(expect_generic) {
		g_array_set_clear_func(retval, (GDestroyNotify)serve_dec_ref);
	}
	if(!g_key_file_load_from_file(cfile, f, G_KEY_FILE_KEEP_COMMENTS |
			G_KEY_FILE_KEEP_TRANSLATIONS, &err)) {
		g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_NOTFOUND, "Could not open config file %s: %s",
				f, err->message);
		g_key_file_free(cfile);
		return retval;
	}
	startgroup = g_key_file_get_start_group(cfile);
	if((!startgroup || strcmp(startgroup, "generic")) && expect_generic) {
		g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_MISSING_GENERIC, "Config file does not contain the [generic] group!");
		g_key_file_free(cfile);
		return NULL;
	}
	groups = g_key_file_get_groups(cfile, NULL);
	for(i=0;groups[i];i++) {
		memset(&s, '\0', sizeof(SERVER));

		/* After the [generic] group or when we're parsing an include
		 * directory, start parsing exports */
		if(i==1 || !expect_generic) {
			p=lp;
			p_size=lp_size;
		} 
		for(j=0;j<p_size;j++) {
			assert(p[j].target != NULL);
			assert(p[j].ptype==PARAM_INT||p[j].ptype==PARAM_STRING||p[j].ptype==PARAM_BOOL||p[j].ptype==PARAM_INT64);
			switch(p[j].ptype) {
				case PARAM_INT:
					ival = g_key_file_get_integer(cfile,
								groups[i],
								p[j].paramname,
								&err);
					if(!err) {
						*((gint*)p[j].target) = ival;
					}
					break;
				case PARAM_INT64:
					i64val = g_key_file_get_int64(cfile,
								groups[i],
								p[j].paramname,
								&err);
					if(!err) {
						*((gint64*)p[j].target) = i64val;
					}
					break;
				case PARAM_STRING:
					sval = g_key_file_get_string(cfile,
								groups[i],
								p[j].paramname,
								&err);
					if(!err) {
						*((gchar**)p[j].target) = sval;
					}
					break;
				case PARAM_BOOL:
					bval = g_key_file_get_boolean(cfile,
							groups[i],
							p[j].paramname, &err);
					if(!err) {
						if(bval) {
							*((gint*)p[j].target) |= p[j].flagval;
						} else {
							*((gint*)p[j].target) &= ~(p[j].flagval);
						}
					}
					break;
			}
			if(err) {
				if(err->code == G_KEY_FILE_ERROR_KEY_NOT_FOUND) {
					if(!p[j].required) {
						/* Ignore not-found error for optional values */
						g_clear_error(&err);
						continue;
					} else {
						err_msg = MISSING_REQUIRED_ERROR;
					}
				} else {
					err_msg = DEFAULT_ERROR;
				}
				g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_VALUE_INVALID, err_msg, p[j].paramname, groups[i], err->message);
				g_array_free(retval, TRUE);
				g_error_free(err);
				g_key_file_free(cfile);
				return NULL;
			}
		}
		if(virtstyle) {
			if(!strncmp(virtstyle, "none", 4)) {
				s.virtstyle=VIRT_NONE;
			} else if(!strncmp(virtstyle, "ipliteral", 9)) {
				s.virtstyle=VIRT_IPLIT;
			} else if(!strncmp(virtstyle, "iphash", 6)) {
				s.virtstyle=VIRT_IPHASH;
			} else if(!strncmp(virtstyle, "cidrhash", 8)) {
				s.virtstyle=VIRT_CIDR;
				if(strlen(virtstyle)<10) {
					g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_VALUE_INVALID, "Invalid value %s for parameter virtstyle in group %s: missing length", virtstyle, groups[i]);
					g_array_free(retval, TRUE);
					g_key_file_free(cfile);
					return NULL;
				}
				s.cidrlen=strtol(virtstyle+8, NULL, 0);
			} else {
				g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_VALUE_INVALID, "Invalid value %s for parameter virtstyle in group %s", virtstyle, groups[i]);
				g_array_free(retval, TRUE);
				g_key_file_free(cfile);
				return NULL;
			}
		} else {
			s.virtstyle=VIRT_IPLIT;
		}
		if(genconftmp.flags & F_OLDSTYLE) {
			g_message("Since 3.10, the oldstyle protocol is no longer supported. Please migrate to the newstyle protocol.");
			g_message("Exiting.");
			return NULL;
		}
#ifndef HAVE_SPLICE
		if (s.flags & F_SPLICE) {
			g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_VALUE_UNSUPPORTED, "This nbd-server was built without splice support, yet group %s uses it", groups[i]);
			g_array_free(retval, TRUE);
			g_key_file_free(cfile);
			return NULL;
		}
#endif
		/* We can't mix copyonwrite and splice. */
		if ((s.flags & F_COPYONWRITE) && (s.flags & F_SPLICE)) {
			g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_INVALID_SPLICE,
				    "Cannot mix copyonwrite with splice for an export in group %s",
				    groups[i]);
			g_array_free(retval, TRUE);
			g_key_file_free(cfile);
			return NULL;
		}
		if ((s.flags & F_COPYONWRITE) && (s.flags & F_WAIT)) {
			g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_INVALID_WAIT,
				    "Cannot mix copyonwrite with waitfile for an export in group %s",
				    groups[i]);
			g_array_free(retval, TRUE);
			g_key_file_free(cfile);
			return NULL;
		}
		/* We can't mix datalog and splice. */
		if ((s.flags & F_DATALOG) && (s.flags & F_SPLICE)) {
			g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_INVALID_SPLICE,
				    "Cannot mix datalog with splice for an export in group %s",
				    groups[i]);
			g_array_free(retval, TRUE);
			g_key_file_free(cfile);
			return NULL;
		}
		/* Don't need to free this, it's not our string */
		virtstyle=NULL;
		/* Don't append values for the [generic] group */
		if(i>0 || !expect_generic) {
			s.servename = groups[i];

			SERVER *srv = serve_inc_ref(g_memdup2(&s, sizeof(SERVER)));
			g_array_append_val(retval, srv);
		}
#ifndef WITH_SDP
		if(s.flags & F_SDP) {
			g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_VALUE_UNSUPPORTED, "This nbd-server was built without support for SDP, yet group %s uses it", groups[i]);
			g_array_free(retval, TRUE);
			g_key_file_free(cfile);
			return NULL;
		}
#endif
	}
	g_key_file_free(cfile);
	if(cfdir) {
		GArray* extra = do_cfile_dir(cfdir, &genconftmp, e);
		if(extra) {
			retval = g_array_append_vals(retval, extra->data, extra->len);
			i+=extra->len;
			g_array_free(extra, TRUE);
		} else {
			if(*e) {
				g_array_free(retval, TRUE);
				return NULL;
			}
		}
	}
	if(i==1 && expect_generic) {
		g_set_error(e, NBDS_ERR, NBDS_ERR_CFILE_NO_EXPORTS, "The config file does not specify any exports");
	}

        if (genconf) {
                /* Return the updated generic configuration through the
                 * pointer parameter. */
                memcpy(genconf, &genconftmp, sizeof(struct generic_conf));
        }

	return retval;
}

/**
 * Handle SIGCHLD by setting atomically a flag which will be evaluated in the
 * main loop of the root server process. This allows us to separate the signal
 * catching from th actual task triggered by SIGCHLD and hence processing in the
 * interrupt context is kept as minimial as possible.
 *
 * @param s the signal we're handling (must be SIGCHLD, or something
 * is severely wrong)
 **/
static void sigchld_handler(const int s G_GNUC_UNUSED) {
        is_sigchld_caught = 1;
}

/**
 * Kill a child. Called from sigterm_handler::g_hash_table_foreach.
 *
 * @param key the key
 * @param value the value corresponding to the above key
 * @param user_data a pointer which we always set to 1, so that we know what
 * will happen next.
 **/
void killchild(gpointer key, gpointer value, gpointer user_data) {
	pid_t *pid=value;

	kill(*pid, SIGTERM);
}

/**
 * Handle SIGTERM by setting atomically a flag which will be evaluated in the
 * main loop of the root server process. This allows us to separate the signal
 * catching from th actual task triggered by SIGTERM and hence processing in the
 * interrupt context is kept as minimial as possible.
 *
 * @param s the signal we're handling (must be SIGTERM, or something
 * is severely wrong).
 **/
static void sigterm_handler(const int s G_GNUC_UNUSED) {
	is_sigterm_caught = 1;
}

/**
 * Handle SIGHUP by setting atomically a flag which will be evaluated in
 * the main loop of the root server process. This allows us to separate
 * the signal catching from th actual task triggered by SIGHUP and hence
 * processing in the interrupt context is kept as minimial as possible.
 *
 * @param s the signal we're handling (must be SIGHUP, or something
 * is severely wrong).
 **/
static void sighup_handler(const int s G_GNUC_UNUSED) {
        is_sighup_caught = 1;
}

static void sigusr1_handler(const int s G_GNUC_UNUSED) {
	msg(LOG_INFO, "Got SIGUSR1");
	sem_post(&file_wait_sem);
}

/**
 * Get the file handle and offset, given an export offset.
 *
 * @param client The client we're serving for
 * @param a The offset to get corresponding file/offset for
 * @param fhandle [out] File descriptor
 * @param foffset [out] Offset into fhandle
 * @param maxbytes [out] Tells how many bytes can be read/written
 * from fhandle starting at foffset (0 if there is no limit)
 * @return 0 on success, -1 on failure
 **/
int get_filepos(CLIENT *client, off_t a, int* fhandle, off_t* foffset, size_t* maxbytes ) {
	GArray * const export = client->export;

	/* Negative offset not allowed */
	if(a < 0)
		return -1;

	/* Open separate file for treefiles */
        if (client->server->flags & F_TREEFILES) {
		*foffset = a % TREEPAGESIZE;
		*maxbytes = (( 1 + (a/TREEPAGESIZE) ) * TREEPAGESIZE) - a; // start position of next block
		*fhandle = open_treefile(client->exportname, ((client->server->flags & F_READONLY) ? O_RDONLY : O_RDWR), client->exportsize,a, &client->lock);
		return 0;
	}

	/* Binary search for last file with starting offset <= a */
	FILE_INFO fi;
	int start = 0;
	int end = export->len - 1;
	while( start <= end ) {
		int mid = (start + end) / 2;
		fi = g_array_index(export, FILE_INFO, mid);
		if( fi.startoff < a ) {
			start = mid + 1;
		} else if( fi.startoff > a ) {
			end = mid - 1;
		} else {
			start = end = mid;
			break;
		}
	}

	/* end should never go negative, since first startoff is 0 and a >= 0 */
	assert(end >= 0);

	fi = g_array_index(export, FILE_INFO, end);
	*fhandle = fi.fhandle;
	*foffset = a - fi.startoff;
	*maxbytes = 0;
	if( end+1 < export->len ) {
		FILE_INFO fi_next = g_array_index(export, FILE_INFO, end+1);
		*maxbytes = fi_next.startoff - a;
	}

	return 0;
}

/**
 * Write an amount of bytes at a given offset to the right file. This
 * abstracts the write-side of the multiple file option.
 *
 * @param a The offset where the write should start
 * @param buf The buffer to write from
 * @param len The length of buf
 * @param client The client we're serving for
 * @param fua Flag to indicate 'Force Unit Access'
 * @return The number of bytes actually written, or -1 in case of an error
 **/
ssize_t rawexpwrite(off_t a, char *buf, size_t len, CLIENT *client, int fua) {
	int fhandle;
	off_t foffset;
	size_t maxbytes;
	ssize_t retval;

	if(get_filepos(client, a, &fhandle, &foffset, &maxbytes))
		return -1;
	if(maxbytes && len > maxbytes)
		len = maxbytes;

	DEBUG("(WRITE to fd %d offset %llu len %u fua %d), ", fhandle, (long long unsigned)foffset, (unsigned int)len, fua);

	retval = pwrite(fhandle, buf, len, foffset);
	if(client->server->flags & F_SYNC) {
		fsync(fhandle);
	} else if (fua) {

	  /* This is where we would do the following
	   *   #ifdef USE_SYNC_FILE_RANGE
	   * However, we don't, for the reasons set out below
	   * by Christoph Hellwig <hch@infradead.org>
	   *
	   * [BEGINS] 
	   * fdatasync is equivalent to fsync except that it does not flush
	   * non-essential metadata (basically just timestamps in practice), but it
	   * does flush metadata requried to find the data again, e.g. allocation
	   * information and extent maps.  sync_file_range does nothing but flush
	   * out pagecache content - it means you basically won't get your data
	   * back in case of a crash if you either:
	   * 
	   *  a) have a volatile write cache in your disk (e.g. any normal SATA disk)
	   *  b) are using a sparse file on a filesystem
	   *  c) are using a fallocate-preallocated file on a filesystem
	   *  d) use any file on a COW filesystem like btrfs
	   * 
	   * e.g. it only does anything useful for you if you do not have a volatile
	   * write cache, and either use a raw block device node, or just overwrite
	   * an already fully allocated (and not preallocated) file on a non-COW
	   * filesystem.
	   * [ENDS]
	   *
	   * What we should do is open a second FD with O_DSYNC set, then write to
	   * that when appropriate. However, with a Linux client, every REQ_FUA
	   * immediately follows a REQ_FLUSH, so fdatasync does not cause performance
	   * problems.
	   *
	   */
#if 0
		sync_file_range(fhandle, foffset, len,
				SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE |
				SYNC_FILE_RANGE_WAIT_AFTER);
#else
		fdatasync(fhandle);
#endif
	}
	/* close file pointer in case of treefiles */
        if (client->server->flags & F_TREEFILES) {
		close(fhandle);
	}
	return retval;
}

/**
 * Call rawexpwrite repeatedly until all data has been written.
 *
 * @param a The offset where the write should start
 * @param buf The buffer to write from
 * @param len The length of buf
 * @param client The client we're serving for
 * @param fua Flag to indicate 'Force Unit Access'
 * @return 0 on success, nonzero on failure
 **/
int rawexpwrite_fully(off_t a, char *buf, size_t len, CLIENT *client, int fua) {
	ssize_t ret=0;

	while(len > 0 && (ret=rawexpwrite(a, buf, len, client, fua)) > 0 ) {
		a += ret;
		buf += ret;
		len -= ret;
	}
	return (ret < 0 || len != 0);
}

/**
 * Read an amount of bytes at a given offset from the right file. This
 * abstracts the read-side of the multiple files option.
 *
 * @param a The offset where the read should start
 * @param buf A buffer to read into
 * @param len The size of buf
 * @param client The client we're serving for
 * @return The number of bytes actually read, or -1 in case of an
 * error.
 **/
ssize_t rawexpread(off_t a, char *buf, size_t len, CLIENT *client) {
	int fhandle;
	off_t foffset;
	size_t maxbytes;
	ssize_t retval;

	if(get_filepos(client, a, &fhandle, &foffset, &maxbytes))
		return -1;
	if(maxbytes && len > maxbytes)
		len = maxbytes;

	DEBUG("(READ from fd %d offset %llu len %u), ", fhandle, (long long unsigned int)foffset, (unsigned int)len);

	retval = pread(fhandle, buf, len, foffset);
        if (client->server->flags & F_TREEFILES) {
		close(fhandle);
	}
	return retval;
}

/**
 * Call rawexpread repeatedly until all data has been read.
 * @return 0 on success, nonzero on failure
 **/
int rawexpread_fully(off_t a, char *buf, size_t len, CLIENT *client) {
	ssize_t ret=0;

	while(len > 0 && (ret=rawexpread(a, buf, len, client)) > 0 ) {
		a += ret;
		buf += ret;
		len -= ret;
	}
	return (ret < 0 || len != 0);
}

#ifdef HAVE_SPLICE
int rawexpsplice(int pipe, off_t a, size_t len, CLIENT *client, int dir,
		 int fua)
{
	int fhandle;
	off_t foffset;
	size_t maxbytes;
	ssize_t retval;

	if (get_filepos(client, a, &fhandle, &foffset, &maxbytes))
		return -1;
	if (maxbytes && len > maxbytes)
		len = maxbytes;

	DEBUG("(SPLICE %s fd %d offset %llu len %u), ",
	      (dir == SPLICE_IN) ? "from" : "to", fhandle,
	      (unsigned long long)a, (unsigned)len);

	/*
	 * SPLICE_F_MOVE doesn't actually work at the moment, but in the future
	 * it might, so go ahead and use it.
	 */
	if (dir == SPLICE_IN) {
		retval = splice(fhandle, &foffset, pipe, NULL, len,
				SPLICE_F_MOVE);
	} else {
		retval = splice(pipe, NULL, fhandle, &foffset, len,
				SPLICE_F_MOVE);
		if (client->server->flags & F_SYNC)
			fsync(fhandle);
		else if (fua)
			fdatasync(fhandle);
	}
	if (client->server->flags & F_TREEFILES)
		close(fhandle);
	return retval;
}

/**
 * Splice an amount of bytes from the given offset from/into the right file
 * from/into the given pipe.
 * @param pipe The pipe we are using for this splice.
 * @param a The offset of the file we are operating on.
 * @param len The length of the splice.
 * @param client The client we're splicing for.
 * @param dir The direction we are doing the splice in.
 * @param fua Set if this is a write and we need to fua.
 * @return 0 on success, nonzero on failure.
 */
int expsplice(int pipe, off_t a, size_t len, CLIENT *client, int dir, int fua)
{
	ssize_t ret;

	while (len > 0 &&
	       (ret = rawexpsplice(pipe, a, len, client, dir, fua)) > 0) {
		a += ret;
		len -= ret;
	}
	return (ret < 0 || len != 0);
}
#endif /* HAVE_SPLICE */

/**
 * Read an amount of bytes at a given offset from the right file. This
 * abstracts the read-side of the copyonwrite stuff, and calls
 * rawexpread() with the right parameters to do the actual work.
 * @param a The offset where the read should start
 * @param buf A buffer to read into
 * @param len The size of buf
 * @param client The client we're going to read for
 * @return 0 on success, nonzero on failure
 **/
int expread(off_t a, char *buf, size_t len, CLIENT *client) {
	off_t rdlen, offset;
	off_t mapcnt, mapl, maph, pagestart;

	DEBUG("Asked to read %u bytes at %llu.\n", (unsigned int)len, (unsigned long long)a);

	if (!(client->server->flags & F_COPYONWRITE) && !((client->server->flags & F_WAIT) && (client->export == NULL)))
		return(rawexpread_fully(a, buf, len, client));

	mapl=a/DIFFPAGESIZE; maph=(a+len-1)/DIFFPAGESIZE;

	for (mapcnt=mapl;mapcnt<=maph;mapcnt++) {
		pagestart=mapcnt*DIFFPAGESIZE;
		offset=a-pagestart;
		rdlen=(0<DIFFPAGESIZE-offset && len<(size_t)(DIFFPAGESIZE-offset)) ?
			len : (size_t)DIFFPAGESIZE-offset;
		if (!(client->server->flags & F_COPYONWRITE))
			pthread_rwlock_rdlock(&client->export_lock);
		if (client->difmap[mapcnt]!=(u32)(-1)) { /* the block is already there */
			DEBUG("Page %llu is at %lu\n", (unsigned long long)mapcnt,
			       (unsigned long)(client->difmap[mapcnt]));
			if (pread(client->difffile, buf, rdlen, client->difmap[mapcnt]*DIFFPAGESIZE+offset) != rdlen) goto fail;
		} else { /* the block is not there */
			if ((client->server->flags & F_WAIT) && (client->export == NULL)){
				DEBUG("Page %llu is not here, and waiting for file\n",
				       (unsigned long long)mapcnt);
				goto fail;
			} else {
				DEBUG("Page %llu is not here, we read the original one\n",
				       (unsigned long long)mapcnt);
				if(rawexpread_fully(a, buf, rdlen, client)) goto fail;
			}
		}
		if (!(client->server->flags & F_COPYONWRITE))
			pthread_rwlock_unlock(&client->export_lock);
		len-=rdlen; a+=rdlen; buf+=rdlen;
	}
	return 0;
fail:
	if (!(client->server->flags & F_COPYONWRITE))
		pthread_rwlock_unlock(&client->export_lock);
	return -1;
}

/**
 * Write an amount of bytes at a given offset to the right file. This
 * abstracts the write-side of the copyonwrite option, and calls
 * rawexpwrite() with the right parameters to do the actual work.
 *
 * @param a The offset where the write should start
 * @param buf The buffer to write from
 * @param len The length of buf
 * @param client The client we're going to write for.
 * @param fua Flag to indicate 'Force Unit Access'
 * @return 0 on success, nonzero on failure
 **/
int expwrite(off_t a, char *buf, size_t len, CLIENT *client, int fua) {
	char pagebuf[DIFFPAGESIZE];
	off_t mapcnt,mapl,maph;
	off_t wrlen,rdlen; 
	off_t pagestart;
	off_t offset;

	DEBUG("Asked to write %u bytes at %llu.\n", (unsigned int)len, (unsigned long long)a);


	if (!(client->server->flags & F_COPYONWRITE) && !((client->server->flags & F_WAIT) && (client->export == NULL)))
		return(rawexpwrite_fully(a, buf, len, client, fua)); 

	mapl=a/DIFFPAGESIZE ; maph=(a+len-1)/DIFFPAGESIZE ;

	for (mapcnt=mapl;mapcnt<=maph;mapcnt++) {
		pagestart=mapcnt*DIFFPAGESIZE ;
		offset=a-pagestart ;
		wrlen=(0<DIFFPAGESIZE-offset && len<(size_t)(DIFFPAGESIZE-offset)) ?
			len : (size_t)DIFFPAGESIZE-offset;

		if (!(client->server->flags & F_COPYONWRITE))
			pthread_rwlock_rdlock(&client->export_lock);
		if (client->difmap[mapcnt]!=(u32)(-1)) { /* the block is already there */
			DEBUG("Page %llu is at %lu\n", (unsigned long long)mapcnt,
			       (unsigned long)(client->difmap[mapcnt])) ;
			if (pwrite(client->difffile, buf, wrlen, client->difmap[mapcnt]*DIFFPAGESIZE+offset) != wrlen) goto fail;
		} else { /* the block is not there */
			client->difmap[mapcnt]=(client->server->flags&F_SPARSE)?mapcnt:client->difffilelen++;
			DEBUG("Page %llu is not here, we put it at %lu\n",
			       (unsigned long long)mapcnt,
			       (unsigned long)(client->difmap[mapcnt]));
			if ((offset != 0) || (wrlen != DIFFPAGESIZE)){
				if ((client->server->flags & F_WAIT) && (client->export == NULL)){
					DEBUG("error: we can write only whole page while waiting for file\n");
					goto fail;
				}
				rdlen=DIFFPAGESIZE ;
				if (rawexpread_fully(pagestart, pagebuf, rdlen, client))
					goto fail;
			}
			memcpy(pagebuf+offset,buf,wrlen) ;
			if (write(client->difffile, pagebuf, DIFFPAGESIZE) != DIFFPAGESIZE)
				goto fail;
		}						    
		if (!(client->server->flags & F_COPYONWRITE))
			pthread_rwlock_unlock(&client->export_lock);
		len-=wrlen ; a+=wrlen ; buf+=wrlen ;
	}
	if (client->server->flags & F_SYNC) {
		fsync(client->difffile);
	} else if (fua) {
		/* open question: would it be cheaper to do multiple sync_file_ranges?
		   as we iterate through the above?
		 */
		fdatasync(client->difffile);
	}
	return 0;
fail:
	if (!(client->server->flags & F_COPYONWRITE))
		pthread_rwlock_unlock(&client->export_lock);
	return -1;
	
}


/**
 * Write an amount of zeroes at a given offset to the right file.
 * This routine could be optimised by not calling expwrite. However,
 * this is by far the simplest way to do it.
 *
 * @param req the request
 * @param client The client we're going to write for.
 * @return 0 on success, nonzero on failure
 **/
int expwrite_zeroes(struct nbd_request* req, CLIENT* client, int fua) {
	off_t a = req->from;
	size_t len = req->len;
	size_t maxsize = 64LL*1024LL*1024LL;
	/* use calloc() as sadly MAP_ANON is apparently not POSIX standard */
	char *buf = calloc (1, maxsize);
	int ret;
	while (len > 0) {
		size_t l = len;
		if (l > maxsize)
			l = maxsize;
		ret = expwrite(a, buf, l, client, fua);
		if (ret) {
			free(buf);
			return ret;
		}
		len -= l;
	}
	free(buf);
	return 0;
}

/**
 * Flush data to a client
 *
 * @param client The client we're going to write for.
 * @return 0 on success, nonzero on failure
 **/
int expflush(CLIENT *client) {
	gint i;

        if (client->server->flags & F_COPYONWRITE) {
		return fsync(client->difffile);
	}

        if (client->server->flags & F_WAIT) {
		return fsync(client->difffile);
	}

        if (client->server->flags & F_TREEFILES ) {
		// all we can do is force sync the entire filesystem containing the tree
		if (client->server->flags & F_READONLY)
			return 0;
		sync();
		return 0;
	}
	
	for (i = 0; i < client->export->len; i++) {
		FILE_INFO fi = g_array_index(client->export, FILE_INFO, i);
		if (fsync(fi.fhandle) < 0)
			return -1;
	}
	
	return 0;
}

void punch_hole(int fd, off_t off, off_t len) {
	DEBUG("Request to punch a hole in fd=%d, starting from %llu, length %llu\n", fd, (unsigned long long)off, (unsigned long long)len);
	errno = 0;
// fallocate -- files, Linux
#if HAVE_FALLOC_PH
	do {
		if(fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, off, len) == 0)
			return;
	} while(errno == EINTR);
#endif
// ioctl(BLKDISCARD) -- block devices, Linux
#if HAVE_BLKDISCARD
	uint64_t range[2] = {off, len};
	do {
		if(ioctl(fd, BLKDISCARD, range) == 0)
			return;
	} while(errno == EINTR);
#endif
// Windows
#if HAVE_FSCTL_SET_ZERO_DATA
	FILE_ZERO_DATA_INFORMATION zerodata;
	zerodata.FileOffset.QuadPart = off;
	zerodata.BeyondFinalZero.QuadPart = off + len;
	HANDLE w32handle = (HANDLE)_get_osfhandle(fd);
	DWORD bytesret;
	DeviceIoControl(w32handle, FSCTL_SET_ZERO_DATA, &zerodata, sizeof(zerodata), NULL, 0, &bytesret, NULL);
	return;
#endif
	if(errno) {
		DEBUG("punching holes failed: %s", strerror(errno));
	} else {
		DEBUG("punching holes not supported on this platform\n");
	}
}

static void send_reply(CLIENT* client, uint32_t opt, uint32_t reply_type, ssize_t datasize, void* data) {
	struct {
		uint64_t magic;
		uint32_t opt;
		uint32_t reply_type;
		uint32_t datasize;
	} __attribute__ ((packed)) header = {
		htonll(0x3e889045565a9LL),
		htonl(opt),
		htonl(reply_type),
		htonl(datasize),
	};
	if(datasize < 0) {
		datasize = strlen((char*)data);
		header.datasize = htonl(datasize);
	}
	socket_write(client, &header, sizeof(header));
	if(data != NULL) {
		socket_write(client, data, datasize);
	}
}

/**
 * Find the name of the file we have to serve. This will use g_strdup_printf
 * to put the IP address of the client inside a filename containing
 * "%s" (in the form as specified by the "virtstyle" option). That name
 * is then written to client->exportname.
 *
 * @param net A socket connected to an nbd client
 * @param client information about the client. The IP address in human-readable
 * format will be written to a new char* buffer, the address of which will be
 * stored in client->clientname.
 * @return: 0 - OK, -1 - failed.
 **/
int set_peername(int net, CLIENT *client) {
	struct sockaddr_storage netaddr;
	struct sockaddr* addr = (struct sockaddr*)&netaddr;
	socklen_t addrinlen = sizeof( struct sockaddr_storage );
	struct addrinfo hints;
	struct addrinfo *ai = NULL;
	char peername[NI_MAXHOST];
	char netname[NI_MAXHOST];
	char *tmp = NULL;
	int i;
	int e;

	if (getsockname(net, addr, &addrinlen) < 0) {
		msg(LOG_INFO, "getsockname failed: %m");
		return -1;
	}

	if(netaddr.ss_family == AF_UNIX) {
		client->clientaddr.ss_family = AF_UNIX;
		strcpy(peername, "unix");
	} else {
		if (getpeername(net, (struct sockaddr *) &(client->clientaddr), &addrinlen) < 0) {
			msg(LOG_INFO, "getpeername failed: %m");
			return -1;
		}
		if((e = getnameinfo((struct sockaddr *)&(client->clientaddr), addrinlen,
				peername, sizeof (peername), NULL, 0, NI_NUMERICHOST))) {
			msg(LOG_INFO, "getnameinfo failed: %s", gai_strerror(e));
			return -1;
		}

		memset(&hints, '\0', sizeof (hints));
		hints.ai_flags = AI_ADDRCONFIG;
		e = getaddrinfo(peername, NULL, &hints, &ai);

		if(e != 0) {
			msg(LOG_INFO, "getaddrinfo failed: %s", gai_strerror(e));
			freeaddrinfo(ai);
			return -1;
		}
	}

	if(strncmp(peername, "::ffff:", 7) == 0) {
		memmove(peername, peername+7, strlen(peername));
	}

	switch(client->server->virtstyle) {
		case VIRT_NONE:
			msg(LOG_DEBUG, "virtualization is off");
			client->exportname=g_strdup(client->server->exportname);
			break;
		case VIRT_IPHASH:
			msg(LOG_DEBUG, "virtstyle iphash");
			for(i=0;i<strlen(peername);i++) {
				if(peername[i]=='.') {
					peername[i]='/';
				}
			}
		case VIRT_IPLIT:
			msg(LOG_DEBUG, "virtstyle ipliteral");
			client->exportname=g_strdup_printf(client->server->exportname, peername);
			break;
		case VIRT_CIDR:
			msg(LOG_DEBUG, "virtstyle cidr %d", client->server->cidrlen);
			memcpy(&netaddr, &(client->clientaddr), addrinlen);
			int addrbits;
			if(client->clientaddr.ss_family == AF_UNIX) {
				tmp = g_strdup(peername);
			} else {
				assert((ai->ai_family == AF_INET) || (ai->ai_family == AF_INET6));
				if(ai->ai_family == AF_INET) {
					addrbits = 32;
				} else if(ai->ai_family == AF_INET6) {
					addrbits = 128;
				} else {
					g_assert_not_reached();
				}
				uint8_t* addrptr = (uint8_t*)(((struct sockaddr*)&netaddr)->sa_data);
				for(int i = 0; i < addrbits; i+=8) {
					int masklen = client->server->cidrlen - i;
					masklen = masklen > 0 ? masklen : 0;
					uint8_t mask = getmaskbyte(masklen);
					*addrptr &= mask;
					addrptr++;
				}
				getnameinfo((struct sockaddr *) &netaddr, addrinlen,
								netname, sizeof (netname), NULL, 0, NI_NUMERICHOST);
				tmp=g_strdup_printf("%s/%s", netname, peername);
			}

			if(tmp != NULL) {
				client->exportname=g_strdup_printf(client->server->exportname, tmp);
				g_free(tmp);
			}

			break;
	}

	if(ai) {
		freeaddrinfo(ai);
	}
        msg(LOG_INFO, "connect from %s, assigned file is %s",
            peername, client->exportname);
	client->clientname=g_strdup(peername);
	return 0;
}

int commit_diff(CLIENT* client, bool lock, int fhandle){
	int dirtycount = 0;
	int pagecount = client->exportsize/DIFFPAGESIZE;
	off_t offset;
	char* buf = malloc(sizeof(char)*DIFFPAGESIZE);

	for (int i=0; i<pagecount; i++){
		offset = DIFFPAGESIZE*i;
		if (lock)
			pthread_rwlock_wrlock(&client->export_lock);
		if (client->difmap[i] != (u32)-1){
			dirtycount += 1;
			DEBUG("flushing dirty page %d, offset %ld\n", i, offset);
			if (pread(client->difffile, buf, DIFFPAGESIZE, client->difmap[i]*DIFFPAGESIZE) != DIFFPAGESIZE) {
				msg(LOG_WARNING, "could not read while committing diff: %m");
				if(lock) {
					pthread_rwlock_unlock(&client->export_lock);
				}
				break;
			}
			if (pwrite(fhandle, buf, DIFFPAGESIZE, offset) != DIFFPAGESIZE) {
				msg(LOG_WARNING, "could not write while committing diff: %m");
				if (lock) {
					pthread_rwlock_unlock(&client->export_lock);
				}
				break;
			}
			client->difmap[i] = (u32)-1;
		}
		if (lock)
			pthread_rwlock_unlock(&client->export_lock);
	}

	free(buf);
	return dirtycount;
}

void* wait_file(void *void_ptr) {
	CLIENT* client = (CLIENT *)void_ptr;
	FILE_INFO fi;
	GArray* export;
	mode_t mode = O_RDWR;
	int dirtycount;

	fi.fhandle = -1;
	fi.startoff = 0;

	while (fi.fhandle < 1){
		sem_wait(&file_wait_sem);
		msg(LOG_INFO, "checking for file %s", client->server->exportname);
		fi.fhandle = open(client->server->exportname, mode);
	}

	msg(LOG_INFO, "File %s appeared, fd %d", client->server->exportname, fi.fhandle);

	// first time there may be lot of data so we lock only per page
	do {
		dirtycount = commit_diff(client, true, fi.fhandle);
	} while (dirtycount > 0);
	
	//last time we lock export for the whole time until we switch write destination
	pthread_rwlock_wrlock(&client->export_lock);
	do {
		dirtycount = commit_diff(client, false, fi.fhandle);
	} while (dirtycount > 0);

	export = g_array_new(TRUE, TRUE, sizeof(FILE_INFO));
	g_array_append_val(export, fi);

	client->export = export;
	pthread_rwlock_unlock(&client->export_lock);
	msg(LOG_INFO, "Waiting for file ended, switching to exported file %s", client->server->exportname);

	return NULL;
}

/**
 * Set up client export array, which is an array of FILE_INFO.
 * Also, split a single exportfile into multiple ones, if that was asked.
 * @param client information on the client which we want to setup export for
 **/
bool setupexport(CLIENT* client) {
	int i = 0;
	off_t laststartoff = 0, lastsize = 0;
	int multifile = (client->server->flags & F_MULTIFILE);
	int treefile = (client->server->flags & F_TREEFILES);
	int temporary = (client->server->flags & F_TEMPORARY) && !multifile;
	int cancreate = (client->server->expected_size) && !multifile;

	if (treefile || (client->server->flags & F_WAIT)) {
		client->export = NULL; // this could be thousands of files so we open handles on demand although its slower
		client->exportsize = client->server->expected_size; // available space is not checked, as it could change during runtime anyway

		if(client->server->flags & F_WAIT){
			pthread_t wait_file_thread;
			if (pthread_create(&wait_file_thread, NULL, wait_file, client)){
				DEBUG("failed to create wait_file thread");
				return false;
			}
		}

	} else {
		client->export = g_array_new(TRUE, TRUE, sizeof(FILE_INFO));

		/* If multi-file, open as many files as we can.
		 * If not, open exactly one file.
		 * Calculate file sizes as we go to get total size. */
		for(i=0; ; i++) {
			FILE_INFO fi;
			gchar *tmpname;
			gchar* error_string;

			if (i)
				cancreate = 0;
			/* if expected_size is specified, and this is the first file, we can create the file */
			mode_t mode = (client->server->flags & F_READONLY) ?
			  O_RDONLY : (O_RDWR | (cancreate?O_CREAT:0));

			if (temporary) {
				tmpname=g_strdup_printf("%s.%d-XXXXXX", client->exportname, i);
				DEBUG( "Opening %s\n", tmpname );
				fi.fhandle = mkstemp(tmpname);
			} else {
				if(multifile) {
					tmpname=g_strdup_printf("%s.%d", client->exportname, i);
				} else {
					tmpname=g_strdup(client->exportname);
				}
				DEBUG( "Opening %s\n", tmpname );
				fi.fhandle = open(tmpname, mode, 0600);
				if(fi.fhandle == -1 && mode == O_RDWR) {
					/* Try again because maybe media was read-only */
					fi.fhandle = open(tmpname, O_RDONLY);
					if(fi.fhandle != -1) {
						/* Opening the base file in copyonwrite mode is
						 * okay */
						if(!(client->server->flags & F_COPYONWRITE)) {
							client->server->flags |= F_AUTOREADONLY;
							client->server->flags |= F_READONLY;
						}
					}
				}
			}
			if(fi.fhandle == -1) {
				if(multifile && i>0)
					break;
				error_string=g_strdup_printf(
					"Could not open exported file %s: %%m",
					tmpname);
				err_nonfatal(error_string);
				return false;
			}

			if (temporary) {
				unlink(tmpname); /* File will stick around whilst FD open */
			}

			fi.startoff = laststartoff + lastsize;
			g_array_append_val(client->export, fi);
			g_free(tmpname);

			/* Starting offset and size of this file will be used to
			 * calculate starting offset of next file */
			laststartoff = fi.startoff;
			lastsize = size_autodetect(fi.fhandle);

			/* If we created the file, it will be length zero */
			if (!lastsize && cancreate) {
				assert(!multifile);
				if(ftruncate (fi.fhandle, client->server->expected_size)<0) {
					err_nonfatal("Could not expand file: %m");
					return false;
				}
				lastsize = client->server->expected_size;
				break; /* don't look for any more files */
			}

			if(!multifile || temporary)
				break;
		}

		/* Set export size to total calculated size */
		client->exportsize = laststartoff + lastsize;

		/* Export size may be overridden */
		if(client->server->expected_size) {
			/* desired size must be <= total calculated size */
			if(client->server->expected_size > client->exportsize) {
				err_nonfatal("Size of exported file is too big\n");
				return false;
			}

			client->exportsize = client->server->expected_size;
		}
	}

	msg(LOG_INFO, "Size of exported file/device is %llu", (unsigned long long)client->exportsize);
	if(multifile) {
		msg(LOG_INFO, "Total number of files: %d", i);
	}
	if(treefile) {
		msg(LOG_INFO, "Total number of (potential) files: %" PRId64, (client->exportsize+TREEPAGESIZE-1)/TREEPAGESIZE);
	}
	return true;
}

bool copyonwrite_prepare(CLIENT* client) {
	off_t i;
	gchar* dir;
	gchar* export_base;
	if (client->server->cowdir != NULL) {
		dir = g_strdup(client->server->cowdir);
	} else {
		dir = g_strdup(dirname(client->exportname));
	}
	export_base = g_strdup(basename(client->exportname));
	client->difffilename = g_strdup_printf("%s/%s-%s-%d.diff",dir,export_base,client->clientname,
		(int)getpid());
	g_free(dir);
	g_free(export_base);
	msg(LOG_INFO, "About to create map and diff file %s", client->difffilename) ;
	client->difffile=open(client->difffilename,O_RDWR | O_CREAT | O_TRUNC,0600) ;
	if (client->difffile<0) {
		err("Could not create diff file (%m)");
		return false;
	}
	if ((client->difmap=calloc(client->exportsize/DIFFPAGESIZE,sizeof(u32)))==NULL) {
		err("Could not allocate memory");
		return false;
	}
	for (i=0;i<client->exportsize/DIFFPAGESIZE;i++) client->difmap[i]=(u32)-1;

	return true;
}

void send_export_info(CLIENT* client, SERVER* server, bool maybe_zeroes) {
	uint64_t size_host = htonll((u64)(client->exportsize));
	uint16_t flags = NBD_FLAG_HAS_FLAGS | NBD_FLAG_SEND_WRITE_ZEROES;

	socket_write(client, &size_host, 8);
	if (server->flags & F_READONLY)
		flags |= NBD_FLAG_READ_ONLY;
	if (server->flags & F_FLUSH)
		flags |= NBD_FLAG_SEND_FLUSH;
	if (server->flags & F_FUA)
		flags |= NBD_FLAG_SEND_FUA;
	if (server->flags & F_ROTATIONAL)
		flags |= NBD_FLAG_ROTATIONAL;
	if (server->flags & F_TRIM)
		flags |= NBD_FLAG_SEND_TRIM;
	if (!(server->flags & F_COPYONWRITE))
		flags |= NBD_FLAG_CAN_MULTI_CONN;
	flags = htons(flags);
	socket_write(client, &flags, sizeof(flags));
	if (!(glob_flags & F_NO_ZEROES) && maybe_zeroes) {
		char zeros[128];
		memset(zeros, '\0', sizeof(zeros));
		socket_write(client, zeros, 124);
	}
}

/**
  * Setup the transaction log
  *
  * The function does all things required for the transaction log:
  * - Create a new log file.
  * - allocate the posix semaphore for synchronization.
  * - Report if a log file already exists.
  * - If needed add a header to the log.
  *
  * If something goes wrong, logging is disabled.
  *
  * @param client the CLIENT structure with .server and .net members set
  * up correctly
  */
static void setup_transactionlog(CLIENT *client) {
	struct stat fdinfo;
	int ret;

	/* 1) create the file */
	if((client->transactionlogfd =
				open(client->server->transactionlog,
					O_WRONLY | O_CREAT,
					S_IRUSR | S_IWUSR)) ==
			-1) {
		msg(LOG_INFO, "Could not open transactionlog %s, moving on without it",
				client->server->transactionlog);
	}

	/* 2) If needed, write flags */
	if (client->server->flags & F_DATALOG) {
		struct nbd_request req;
		int ret;

		req.magic = htonl(NBD_TRACELOG_MAGIC);
		req.type = htonl(NBD_TRACELOG_SET_DATALOG);
		memset(req.handle, 0, sizeof(req.handle));
		req.from = htonll(NBD_TRACELOG_FROM_MAGIC);
		req.len = htonl(TRUE);

		ret = writeit(client->transactionlogfd, &req, sizeof(struct nbd_request));
		if (ret < 0) {
			msg(LOG_INFO, "Could not write to transactionlog %s, moving on without it",
				client->server->transactionlog);
			close(client->transactionlogfd);
			client->transactionlogfd = -1;
		}
	}

	/* 3) Allocate the semaphore used for locking */
	ret = fstat(client->transactionlogfd, &fdinfo);
	if (ret == -1) {
		msg(LOG_INFO, "Could not stat transactionlog %s, moving on without it",
			client->server->transactionlog);
		close(client->transactionlogfd);
		client->transactionlogfd = -1;
		return;
	}
	snprintf(client->semname, sizeof(client->semname), "/nbd-server-%llx-%llx",
				(unsigned long long)fdinfo.st_dev,
				(unsigned long long)fdinfo.st_ino);
	client->logsem = sem_open(client->semname, O_CREAT, 0600, 1);
	if (client->logsem == SEM_FAILED) {
		msg(LOG_INFO, "Could not allocate semaphore for transactionlog %s, moving on without it",
			client->server->transactionlog);
		close(client->transactionlogfd);
		client->transactionlogfd = -1;
	}
}

/**
  * Commit to exporting the chosen export
  *
  * When a client sends NBD_OPT_EXPORT_NAME or NBD_OPT_GO, we need to do
  * a number of things (verify whether the client is allowed access, try
  * to open files, etc etc) before we're ready to actually serve the
  * export.
  *
  * This function does all those things.
  *
  * @param client the CLIENT structure with .server and .net members set
  * up correctly
  * @return true if the client is allowed access to the export, false
  * otherwise
  */
static bool commit_client(CLIENT* client, SERVER* server) {
	char acl;
	uint32_t len;

	client->server = serve_inc_ref(server);
	client->exportsize = OFFT_MAX;
	client->transactionlogfd = -1;
	if(pthread_mutex_init(&(client->lock), NULL)) {
		msg(LOG_ERR, "Unable to initialize mutex");
		return false;
	}
	if (pthread_rwlock_init(&client->export_lock, NULL)){
                msg(LOG_ERR, "Unable to initialize write lock");
		return false;
	}
	/* Check whether we exceeded the maximum number of allowed
	 * clients already */
	if(dontfork) {
		acl = 'Y';
	} else {
		len = strlen(client->server->servename);
		writeit(commsocket, &len, sizeof len);
		writeit(commsocket, client->server->servename, len);
		readit(commsocket, &acl, 1);
		close(commsocket);
	}
	switch(acl) {
		case 'N':
			msg(LOG_ERR, "Connection not allowed (too many clients)");
			return false;
		case 'X':
			msg(LOG_ERR, "Connection not allowed (unknown by parent?!?)");
			return false;
	}

	/* Check whether the client is listed in the authfile */
        if (set_peername(client->net, client)) {
                msg(LOG_ERR, "Failed to set peername");
		return false;
        }

        if (!authorized_client(client)) {
                msg(LOG_INFO, "Client '%s' is not authorized to access",
                    client->clientname);
		return false;
        }

	/* Set up the transactionlog, if we need one */
	if (client->server->transactionlog && (client->transactionlogfd == -1))
		setup_transactionlog(client);

	/* Run any pre scripts that we may need */
	if (do_run(client->server->prerun, client->exportname)) {
		msg(LOG_INFO, "Client '%s' not allowed access by prerun script",
				client->clientname);
		return false;
	}
	client->socket_closed = socket_closed_transmission;
	if(!setupexport(client)) {
		return false;
	}

	if (client->server->flags & F_COPYONWRITE) {
		if(!copyonwrite_prepare(client)) {
			return false;
		}
	}

	if (client->server->flags & F_WAIT) {
		if(!copyonwrite_prepare(client)) {
			return false;
		}
	}

	setmysockopt(client->net);

	return true;
}

static CLIENT* handle_export_name(CLIENT* client, uint32_t opt, GArray* servers, uint32_t cflags) {
	uint32_t namelen;
	char* name;
	int i;

	socket_read(client, &namelen, sizeof(namelen));
	namelen = ntohl(namelen);
	if(namelen > 4096) {
		return NULL;
	}
	if(namelen > 0) {
		name = malloc(namelen+1);
		name[namelen]=0;
		socket_read(client, name, namelen);
	} else {
		name = strdup("");
	}
	for(i=0; i<servers->len; i++) {
		SERVER* serve = (g_array_index(servers, SERVER*, i));
		// hide exports that are TLS-only if we haven't negotiated TLS
		// yet
		if ((serve->flags & F_FORCEDTLS) && !client->tls_session) {
			continue;
		}
		if(!strcmp(serve->servename, name)) {
			client->clientfeats = cflags;
			free(name);
			if(!commit_client(client, serve)) {
				return NULL;
			}
			send_export_info(client, serve, true);
			return client;
		}
	}
	free(name);
	err("Negotiation failed/8a: Requested export not found, or is TLS-only and client did not negotiate TLS");
}

static void handle_list(CLIENT* client, uint32_t opt, GArray* servers, uint32_t cflags) {
	uint32_t len;
	int i;
	char buf[1024];
	char *ptr = buf + sizeof(len);

	socket_read(client, &len, sizeof(len));
	len = ntohl(len);
	if(len) {
		send_reply(client, opt, NBD_REP_ERR_INVALID, -1, "NBD_OPT_LIST with nonzero data length is not a valid request");
	}
	if(!(glob_flags & F_LIST)) {
		send_reply(client, opt, NBD_REP_ERR_POLICY, -1, "Listing of exports denied by server configuration");
		err_nonfatal("Client tried disallowed list option");
		return;
	}
	for(i=0; i<servers->len; i++) {
		SERVER* serve = (g_array_index(servers, SERVER*, i));
		// Hide TLS-only exports if we haven't negotiated TLS yet
		if(!client->tls_session && (serve->flags & F_FORCEDTLS)) {
			continue;
		}
		len = htonl(strlen(serve->servename));
		memcpy(buf, &len, sizeof(len));
		strncpy(ptr, serve->servename, sizeof(buf) - sizeof(len));
		send_reply(client, opt, NBD_REP_SERVER, strlen(serve->servename)+sizeof(len), buf);
	}
	send_reply(client, opt, NBD_REP_ACK, 0, NULL);
}

#if HAVE_GNUTLS
static int verify_cert(gnutls_session_t session) {
	int ret;
	unsigned int status, cert_list_size;
	const gnutls_datum_t *cert_list;
	gnutls_x509_crt_t cert;
	time_t now = time(NULL);

	ret = gnutls_certificate_verify_peers2(session, &status);
	if(ret < 0 || status != 0 || gnutls_certificate_type_get(session) !=
			GNUTLS_CRT_X509) {
		goto err;
	}

	if(gnutls_x509_crt_init(&cert) < 0) {
		goto err;
	}

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
	if(cert_list == NULL) {
		goto err;
	}
	if(gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER) < 0) {
		goto err;
	}
	if(gnutls_x509_crt_get_activation_time(cert) > now) {
		goto err;
	}
	if(gnutls_x509_crt_get_expiration_time(cert) < now) {
		goto err;
	}
	// TODO: check CRLs and/or OCSP etc. Patches welcome.
	msg(LOG_INFO, "client certificate verification successful");
	return 0;
err:
	msg(LOG_ERR, "E: client certificate verification failed");
	return GNUTLS_E_CERTIFICATE_ERROR;
}

CLIENT* handle_starttls(CLIENT* client, int opt, GArray* servers, uint32_t cflags, struct generic_conf *genconf) {
#define check_rv(c) if((c)<0) { retval = NULL; goto exit; }
	gnutls_certificate_credentials_t x509_cred;
	CLIENT* retval = client;
	gnutls_priority_t priority_cache;
	gnutls_session_t *session = g_new0(gnutls_session_t, 1);
	int ret;
	int len;

	socket_read(client, &len, sizeof(len));
	if(G_UNLIKELY(len != 0)) {
		char buf[1024*1024];
		consume(client, len, buf, sizeof(buf));
		send_reply(client, opt, NBD_REP_ERR_INVALID, -1, "Sending a STARTTLS command with data is invalid");
		return NULL;
	}

	send_reply(client, opt, NBD_REP_ACK, 0, NULL);

	check_rv(gnutls_certificate_allocate_credentials(&x509_cred));
	gnutls_certificate_set_verify_function(x509_cred, verify_cert);
	check_rv(gnutls_certificate_set_x509_trust_file(x509_cred, genconf->cacertfile, GNUTLS_X509_FMT_PEM));
	check_rv(gnutls_certificate_set_x509_key_file(x509_cred, genconf->certfile, genconf->keyfile, GNUTLS_X509_FMT_PEM));
	check_rv(gnutls_priority_init(&priority_cache, genconf->tlsprio, NULL));
	check_rv(gnutls_init(session, GNUTLS_SERVER));
	check_rv(gnutls_priority_set(*session, priority_cache));
	check_rv(gnutls_credentials_set(*session, GNUTLS_CRD_CERTIFICATE, x509_cred));

	gnutls_certificate_server_set_request(*session, GNUTLS_CERT_REQUEST);
#if GNUTLS_VERSION_NUMBER >= 0x030109
	gnutls_transport_set_int(*session, client->net);
#else
	gnutls_transport_set_ptr(*session, (gnutls_transport_ptr_t) (intptr_t) client->net);
#endif
	do {
		ret = gnutls_handshake(*session);
	} while(ret < 0 && gnutls_error_is_fatal(ret) == 0);

	if (ret < 0) {
		err_nonfatal(gnutls_strerror(ret));
		gnutls_bye(*session, GNUTLS_SHUT_RDWR);
		gnutls_deinit(*session);
		g_free(session);
		return NULL;
	}
	client->tls_session = session;
	client->socket_read = socket_read_tls;
	client->socket_write = socket_write_tls;
#undef check_rv
exit:
	if(retval == NULL && session != NULL) {
		g_free(session);
	}
	/* export names cannot be chosen before NBD_OPT_STARTTLS and be retained */
	if(retval != NULL && retval->server != NULL) {
		retval->server = NULL;
	}
	return retval;
}
#endif

/**
  * Handle an NBD_OPT_INFO or NBD_OPT_GO request.
  *
  * XXX this matches the proposal I sent out, rather than the officially
  * documented version of this command. Need to bring the two in sync
  * one way or the other.
  */
static bool handle_info(CLIENT* client, uint32_t opt, GArray* servers, uint32_t cflags) {
	uint32_t namelen, len;
	char *name;
	int i;
	SERVER *server = NULL;
	uint16_t n_requests;
	uint16_t request;
	char buf[1024];
	bool sent_export = false;
	uint32_t reptype = NBD_REP_ERR_UNKNOWN;
	char *msg = "Export unknown";

	socket_read(client, &len, sizeof(len));
	len = htonl(len);
	socket_read(client, &namelen, sizeof(namelen));
	namelen = htonl(namelen);
	if(namelen > (len - 6)) {
		send_reply(client, opt, NBD_REP_ERR_INVALID, -1, "An OPT_INFO request cannot be smaller than the length of the name + 6");
		consume(client, len - sizeof(namelen), buf, sizeof(buf));
	}
	if(namelen > 4096) {
		send_reply(client, opt, NBD_REP_ERR_INVALID, -1, "The name for this OPT_INFO request is too long");
		consume(client, namelen, buf, sizeof(buf));
	}
	if(namelen > 0) {
		name = malloc(namelen + 1);
		name[namelen] = 0;
		socket_read(client, name, namelen);
	} else {
		name = strdup("");
	}
	for(i=0; i<servers->len; i++) {
		SERVER *serve = (g_array_index(servers, SERVER*, i));
		if (!strcmp(serve->servename, name)) {
			if ((serve->flags & F_FORCEDTLS) && !client->tls_session) {
				reptype = NBD_REP_ERR_TLS_REQD;
				msg = "TLS is required for that export";
				continue;
			}
			server = serve;
		}
	}
	free(name);
	socket_read(client, &n_requests, sizeof(n_requests));
	n_requests = ntohs(n_requests);
	if(!server) {
		consume(client, n_requests * sizeof(request), buf,
				sizeof(buf));
		send_reply(client, opt, reptype, -1, msg);
		return false;
	}
	if (opt == NBD_OPT_GO) {
		client->clientfeats = cflags;
		if(!commit_client(client, server)) {
			send_reply(client, opt, NBD_REP_ERR_POLICY, -1, "Access denied by server configuration");
			return false;
		}
	}
	for(i=0; i<n_requests; i++) {
		socket_read(client, &request, sizeof(request));
		switch(ntohs(request)) {
			case NBD_INFO_EXPORT:
				send_reply(client, opt, NBD_REP_INFO, 12, NULL);
				socket_write(client, &request, 2);
				send_export_info(client, server, false);
				sent_export = true;
				break;
			default:
				// ignore all other options for now.
				break;
		}
	}
	if(!sent_export) {
		request = htons(NBD_INFO_EXPORT);
		send_reply(client, opt, NBD_REP_INFO, 12, NULL);
		socket_write(client, &request, 2);
		send_export_info(client, server, false);
	}
	send_reply(client, opt, NBD_REP_ACK, 0, NULL);

	return true;
}

/**
 * Do the initial negotiation.
 *
 * @param net The socket we're doing the negotiation over.
 * @param servers The array of known servers.
 * @param genconf the global options (needed for accessing TLS config data)
 **/
CLIENT* negotiate(int net, GArray* servers, struct generic_conf *genconf) {
	uint16_t smallflags = NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES;
	uint64_t magic;
	uint32_t cflags = 0;
	uint32_t opt;
	CLIENT* client = g_new0(CLIENT, 1);
	client->net = net;
	client->socket_read = socket_read_notls;
	client->socket_write = socket_write_notls;
	client->socket_closed = socket_closed_negotiate;
	client->transactionlogfd = -1;
	client->logsem = SEM_FAILED;

	assert(servers != NULL);
	socket_write(client, INIT_PASSWD, 8);
	magic = htonll(opts_magic);
	socket_write(client, &magic, sizeof(magic));

	smallflags = htons(smallflags);
	socket_write(client, &smallflags, sizeof(uint16_t));
	socket_read(client, &cflags, sizeof(cflags));
	cflags = htonl(cflags);
	if (cflags & NBD_FLAG_C_NO_ZEROES) {
		glob_flags |= F_NO_ZEROES;
	}
	do {
		socket_read(client, &magic, sizeof(magic));
		magic = ntohll(magic);
		if(magic != opts_magic) {
			err_nonfatal("Negotiation failed/5a: magic mismatch");
			goto handler_err;
		}
		socket_read(client, &opt, sizeof(opt));
		opt = ntohl(opt);
		if(client->tls_session == NULL
				&& glob_flags & F_FORCEDTLS
				&& opt != NBD_OPT_STARTTLS) {
			if(opt == NBD_OPT_EXPORT_NAME) {
				// can't send an error message for EXPORT_NAME,
				// so must do hard close
				goto handler_err;
			}
			if(opt == NBD_OPT_ABORT) {
				// handled below
				break;
			}
			consume_len(client);
			send_reply(client, opt, NBD_REP_ERR_TLS_REQD, -1, "TLS is required on this server");
			continue;
		}
		switch(opt) {
		case NBD_OPT_EXPORT_NAME:
			// NBD_OPT_EXPORT_NAME must be the last
			// selected option, so return from here
			// if that is chosen.
			if(handle_export_name(client, opt, servers, cflags) != NULL) {
				return client;
			} else {
				goto handler_err;
			}
			break;
		case NBD_OPT_LIST:
			handle_list(client, opt, servers, cflags);
			break;
		case NBD_OPT_ABORT:
			// handled below
			break;
		case NBD_OPT_STARTTLS:
#if !HAVE_GNUTLS
			consume_len(client);
			send_reply(client, opt, NBD_REP_ERR_PLATFORM, -1, "This nbd-server was compiled without TLS support");
#else
			if(client->tls_session != NULL) {
				consume_len(client);
				send_reply(client, opt, NBD_REP_ERR_INVALID, -1, "Invalid STARTTLS request: TLS has already been negotiated!");
				continue;
			}
			if(genconf->keyfile == NULL) {
				consume_len(client);
				send_reply(client, opt, NBD_REP_ERR_POLICY, -1, "TLS not allowed on this server");
				continue;
			}
			if(handle_starttls(client, opt, servers, cflags, genconf) == NULL) {
				// can't recover from failed TLS negotiation.
				goto handler_err;
			}
#endif
			break;
		case NBD_OPT_GO:
		case NBD_OPT_INFO:
			if(handle_info(client, opt, servers, cflags) && opt == NBD_OPT_GO) {
				return client;
			}
			break;
		default:
			consume_len(client);
			send_reply(client, opt, NBD_REP_ERR_UNSUP, -1, "The given option is unknown to this server implementation");
			break;
		}
	} while((opt != NBD_OPT_EXPORT_NAME) && (opt != NBD_OPT_ABORT));
	if(opt == NBD_OPT_ABORT) {
		err_nonfatal("Session terminated by client");
		goto handler_err;
	}
	err_nonfatal("Weird things happened: reached end of negotiation without success");
handler_err:
	g_free(client);
	return NULL;
}

static int nbd_errno(int errcode) {
	switch (errcode) {
	case EPERM:
		return htonl(1);
	case EIO:
		return htonl(5);
	case ENOMEM:
		return htonl(12);
	case EINVAL:
		return htonl(22);
	case EFBIG:
	case ENOSPC:
#ifdef EDQUOT
	case EDQUOT:
#endif
		return htonl(28); // ENOSPC
	default:
		return htonl(22); // EINVAL
	}
}

static void package_dispose(struct work_package* package) {
	if (package->pipefd[0] > 0)
		close(package->pipefd[0]);
	if (package->pipefd[1] > 0)
		close(package->pipefd[1]);
	g_free(package->data);
	g_free(package->req);
	g_free(package);
}

static int mkpipe(int pipefd[2], size_t len)
{
	if (len > MAX_PIPE_SIZE)
		return -1;
	if (pipe(pipefd))
		return -1;

#ifdef HAVE_SPLICE
	if (fcntl(pipefd[1], F_SETPIPE_SZ, MAX_PIPE_SIZE) < MAX_PIPE_SIZE) {
		close(pipefd[0]);
		close(pipefd[1]);
		pipefd[0] = -1;
		pipefd[1] = -1;
		return -1;
	}
#endif

	return 0;
}

struct work_package* package_create(CLIENT* client, struct nbd_request* req) {
	struct work_package* rv = calloc(sizeof (struct work_package), 1);

	rv->req = req;
	rv->client = client;
	rv->data = NULL;
	rv->pipefd[0] = -1;
	rv->pipefd[1] = -1;

	if((req->type & NBD_CMD_MASK_COMMAND) == NBD_CMD_WRITE) {
		if (client->server->flags & F_SPLICE) {
			if (mkpipe(rv->pipefd, req->len))
				rv->data = malloc(req->len);
		} else {
			rv->data = malloc(req->len);
		}
	}

	return rv;
}

static void setup_reply(struct nbd_reply* rep, struct nbd_request* req) {
	rep->magic = htonl(NBD_REPLY_MAGIC);
	rep->error = 0;
	memcpy(&(rep->handle), &(req->handle), sizeof(req->handle));
}

static void log_reply(CLIENT *client, struct nbd_reply *prply)
{
	if (client->transactionlogfd != -1) {
		lock_logsem(client);
		writeit(client->transactionlogfd, prply, sizeof(*prply));
		unlock_logsem(client);
	}
}

#ifdef HAVE_SPLICE
static int handle_splice_read(CLIENT *client, struct nbd_request *req)
{
	struct nbd_reply rep;
	int pipefd[2];

	// splice doesn't work with TLS
	if (client->tls_session != NULL)
		return -1;

	if (mkpipe(pipefd, req->len))
		return -1;

	if (expsplice(pipefd[1], req->from, req->len, client, SPLICE_IN, 0)) {
		close(pipefd[1]);
		close(pipefd[0]);
		return -1;
	}

	DEBUG("handling read request (splice)\n");
	setup_reply(&rep, req);
	log_reply(client, &rep);
	pthread_mutex_lock(&(client->lock));
	writeit(client->net, &rep, sizeof(rep));
	spliceit(pipefd[0], NULL, client->net, NULL, req->len);
	pthread_mutex_unlock(&(client->lock));
	close(pipefd[0]);
	close(pipefd[1]);
	return 0;
}
#endif

static void handle_normal_read(CLIENT *client, struct nbd_request *req)
{
	struct nbd_reply rep;
	void* buf = malloc(req->len);
	if(!buf) {
		err("Could not allocate memory for request");
	}
	DEBUG("handling read request\n");
	setup_reply(&rep, req);
	if(expread(req->from, buf, req->len, client)) {
		DEBUG("Read failed: %m");
		rep.error = nbd_errno(errno);
	}
	log_reply(client, &rep);
	pthread_mutex_lock(&(client->lock));
	socket_write(client, &rep, sizeof rep);
	if(!rep.error) {
		socket_write(client, buf, req->len);
	}
	pthread_mutex_unlock(&(client->lock));
	free(buf);
}

static void handle_read(CLIENT* client, struct nbd_request* req)
{
#ifdef HAVE_SPLICE
	/*
	 * If we have splice set we want to try that first, and if that fails
	 * for whatever reason we fall through to ye olde read.
	 */
	if (client->server->flags & F_SPLICE)
		if (!handle_splice_read(client, req))
			return;
#endif
	handle_normal_read(client, req);
}

static void handle_write(struct work_package *pkg)
{
	CLIENT *client = pkg->client;
	struct nbd_request *req = pkg->req;
	struct nbd_reply rep;
	int fua = !!(req->type & NBD_CMD_FLAG_FUA);

	DEBUG("handling write request\n");
	setup_reply(&rep, req);

#ifdef HAVE_SPLICE
	if (!pkg->data) {
		if (expsplice(pkg->pipefd[0], req->from, req->len, client,
			      SPLICE_OUT, fua)) {
			DEBUG("Splice failed: %m");
			rep.error = nbd_errno(errno);
		}
	} else
#endif
	{
		if(expwrite(req->from, pkg->data, req->len, client, fua)) {
			DEBUG("Write failed: %m");
			rep.error = nbd_errno(errno);
		}
	}
	log_reply(client, &rep);
	pthread_mutex_lock(&(client->lock));
	socket_write(client, &rep, sizeof rep);
	pthread_mutex_unlock(&(client->lock));
}

static void handle_flush(CLIENT* client, struct nbd_request* req) {
	struct nbd_reply rep;
	DEBUG("handling flush request\n");
	setup_reply(&rep, req);
	if(expflush(client)) {
		DEBUG("Flush failed: %m");
		rep.error = nbd_errno(errno);
	}
	log_reply(client, &rep);
	pthread_mutex_lock(&(client->lock));
	socket_write(client, &rep, sizeof rep);
	pthread_mutex_unlock(&(client->lock));
}

static void handle_trim(CLIENT* client, struct nbd_request* req) {
	struct nbd_reply rep;
	DEBUG("handling trim request\n");
	setup_reply(&rep, req);
	if(exptrim(req, client)) {
		DEBUG("Trim failed: %m");
		rep.error = nbd_errno(errno);
	}
	log_reply(client, &rep);
	pthread_mutex_lock(&(client->lock));
	socket_write(client, &rep, sizeof rep);
	pthread_mutex_unlock(&(client->lock));
}

static void handle_write_zeroes(CLIENT* client, struct nbd_request* req) {
	struct nbd_reply rep;
	DEBUG("handling write_zeroes request\n");
	int fua = !!(req->type & NBD_CMD_FLAG_FUA);
	setup_reply(&rep, req);
	if(expwrite_zeroes(req, client, fua)) {
		DEBUG("Write_zeroes failed: %m");
		rep.error = nbd_errno(errno);
	}
	// For now, don't trim
	// TODO: handle this far more efficiently with reference to the
	// actual backing driver
	log_reply(client, &rep);
	pthread_mutex_lock(&(client->lock));
	socket_write(client, &rep, sizeof rep);
	pthread_mutex_unlock(&(client->lock));
}


static bool bad_write(CLIENT* client, struct nbd_request* req) {
	if ((client->server->flags & F_READONLY) ||
	    (client->server->flags & F_AUTOREADONLY)) {
		DEBUG("[WRITE to READONLY!]");
		return true;
	}
	return false;
}

static bool bad_range(CLIENT* client, struct nbd_request* req) {
	if(req->from > client->exportsize ||
	   req->from + req->len > client->exportsize) {
		DEBUG("[out of bounds!]");
		return true;
	}
	return false;
}

static void handle_request(gpointer data, gpointer user_data) {
	struct work_package* package = (struct work_package*) data;
	uint32_t type = package->req->type & NBD_CMD_MASK_COMMAND;
	uint32_t flags = package->req->type & ~NBD_CMD_MASK_COMMAND;
	struct nbd_reply rep;
	int err = EINVAL;

	if(flags & ~(NBD_CMD_FLAG_FUA | NBD_CMD_FLAG_NO_HOLE)) {
		msg(LOG_ERR, "E: received invalid flag %d on command %d, ignoring", flags, type);
		goto error;
	}

	switch(type) {
		case NBD_CMD_READ:
			if (bad_range(package->client, package->req)) {
				goto error;
			}
			handle_read(package->client, package->req);
			break;
		case NBD_CMD_WRITE:
			if (bad_write(package->client, package->req)) {
				err = EPERM;
				goto error;
			}
			if (bad_range(package->client, package->req)) {
				err = ENOSPC;
				goto error;
			}
			handle_write(package);
			break;
		case NBD_CMD_FLUSH:
			handle_flush(package->client, package->req);
			break;
		case NBD_CMD_TRIM:
			if (bad_write(package->client, package->req)) {
				err = EPERM;
				goto error;
			}
			if (bad_range(package->client, package->req)) {
				goto error;
			}
			handle_trim(package->client, package->req);
			break;
		case NBD_CMD_WRITE_ZEROES:
			if (bad_write(package->client, package->req)) {
				err = EPERM;
				goto error;
			}
			if (bad_range(package->client, package->req)) {
				err = ENOSPC;
				goto error;
			}
			handle_write_zeroes(package->client, package->req);
			break;
		default:
			msg(LOG_ERR, "E: received unknown command %d of type, ignoring", package->req->type);
			goto error;
	}
	goto end;
error:
	setup_reply(&rep, package->req);
	rep.error = nbd_errno(err);
	log_reply(package->client, &rep);
	pthread_mutex_lock(&(package->client->lock));
	socket_write(package->client, &rep, sizeof rep);
	pthread_mutex_unlock(&(package->client->lock));
end:
	package_dispose(package);
}

static int mainloop_threaded(CLIENT* client) {
	struct nbd_request* req;
	struct work_package* pkg;
	int write_data = false;

	DEBUG("Entering request loop\n");
	while(1) {
		req = calloc(sizeof (struct nbd_request), 1);

		socket_read(client, req, sizeof(struct nbd_request));

		if(client->transactionlogfd != -1) {
			lock_logsem(client);
			writeit(client->transactionlogfd, req, sizeof(struct nbd_request));
			if(((ntohl(req->type) & NBD_CMD_MASK_COMMAND) == NBD_CMD_WRITE) &&
					(client->server->flags & F_DATALOG) &&
					!(client->server->flags & F_SPLICE)) {
				write_data = true;
			} else {
				write_data = false;
				unlock_logsem(client);
			}
		}

		req->from = ntohll(req->from);
		req->type = ntohl(req->type);
		req->len = ntohl(req->len);


		if(req->magic != htonl(NBD_REQUEST_MAGIC))
			err("Protocol error: not enough magic.");

		pkg = package_create(client, req);

		if((req->type & NBD_CMD_MASK_COMMAND) == NBD_CMD_WRITE) {
#ifdef HAVE_SPLICE
			if ((client->server->flags & F_SPLICE) &&
			    (req->len <= MAX_PIPE_SIZE && pkg->pipefd[1] > 0) &&
			    (client->tls_session == NULL))
				spliceit(client->net, NULL, pkg->pipefd[1],
					 NULL, req->len);
			else
#endif
				socket_read(client, pkg->data, req->len);

			if (write_data) {
				writeit(client->transactionlogfd, pkg->data, req->len);
				unlock_logsem(client);
				write_data = false;
			}
		}
		if(req->type == NBD_CMD_DISC) {
			finalize_client(client);
			return 0;
		}
		g_thread_pool_push(tpool, pkg, NULL);
	}
}

/**
 * Destroy a pid_t*
 * @param data a pointer to pid_t which should be freed
 **/
void destroy_pid_t(gpointer data) {
	g_free(data);
}

static pid_t
spawn_child(int* socket)
{
        pid_t pid;
        sigset_t newset;
        sigset_t oldset;
	int sockets[2];

        sigemptyset(&newset);
        sigaddset(&newset, SIGCHLD);
        sigaddset(&newset, SIGTERM);
        sigprocmask(SIG_BLOCK, &newset, &oldset);
	socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
        pid = fork();
        if (pid < 0) {
                msg(LOG_ERR, "Could not fork (%s)", strerror(errno));
                close(sockets[0]);
                close(sockets[1]);
                goto out;
        }
        if (pid > 0) { /* Parent */
                pid_t *pidp;

                pidp = g_malloc(sizeof(pid_t));
                *pidp = pid;
		*socket = sockets[1];
		close(sockets[0]);
                g_hash_table_insert(children, pidp, pidp);
                goto out;
        }
        /* Child */
	*socket = sockets[0];
	close(sockets[1]);
        /* Child's signal disposition is reset to default. */
        signal(SIGCHLD, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
        sigemptyset(&oldset);
out:
        sigprocmask(SIG_SETMASK, &oldset, NULL);
        return pid;
}

static int
socket_accept(const int sock)
{
        struct sockaddr_storage addrin;
        socklen_t addrinlen = sizeof(addrin);
        int net;

        net = accept(sock, (struct sockaddr *) &addrin, &addrinlen);
        if (net < 0) {
                err_nonfatal("Failed to accept socket connection: %m");
        }

        return net;
}

static void
handle_modern_connection(GArray *const servers, const int sock, struct generic_conf *genconf)
{
        int net;
        pid_t pid;
        CLIENT *client = NULL;
        int sock_flags_old;
        int sock_flags_new;

        net = socket_accept(sock);
        if (net < 0)
                return;

        if (!dontfork) {
                pid = spawn_child(&commsocket);
                if (pid) {
                        if (pid > 0) {
                                msg(LOG_INFO, "Spawned a child process");
				g_array_append_val(childsocks, commsocket);
			}
                        if (pid < 0)
                                msg(LOG_ERR, "Failed to spawn a child process");
                        close(net);
                        return;
                }
                /* Child just continues. */
        }

        sock_flags_old = fcntl(net, F_GETFL, 0);
        if (sock_flags_old == -1) {
                msg(LOG_ERR, "Failed to get socket flags");
                goto handler_err;
        }

        sock_flags_new = sock_flags_old & ~O_NONBLOCK;
        if (sock_flags_new != sock_flags_old &&
            fcntl(net, F_SETFL, sock_flags_new) == -1) {
                msg(LOG_ERR, "Failed to set socket to blocking mode");
                goto handler_err;
        }

        client = negotiate(net, servers, genconf);
        if (!client) {
                msg(LOG_ERR, "Modern initial negotiation failed");
                goto handler_err;
        }

        if (!dontfork) {
                int i;

                /* Free all root server resources here, because we are
                 * currently in the child process serving one specific
                 * connection. These are not simply needed anymore. */
                g_hash_table_destroy(children);
                children = NULL;
                for (i = 0; i < modernsocks->len; i++) {
                        close(g_array_index(modernsocks, int, i));
                }
                g_array_free(modernsocks, TRUE);

                /* Now that we are in the child process after a
                 * succesful negotiation, we do not need the list of
                 * servers anymore, get rid of it.*/
                g_array_free(servers, FALSE);
        }

        msg(LOG_INFO, "Starting to serve");
        mainloop_threaded(client);
        exit(EXIT_SUCCESS);

handler_err:
	close(net);
        g_free(client);

        if (!dontfork) {
                exit(EXIT_FAILURE);
        }
}

static int handle_childname(GArray* servers, int socket)
{
	uint32_t len;
	char *buf;
	int i, r, rt = 0;

	while(rt < sizeof(len)) {
		switch((r = read(socket, &len, sizeof len))) {
			case 0:
				return -1;
			case -1:
				err_nonfatal("Error reading from acl socket: %m");
				return -1;
			default:
				rt += r;
				break;
		}
	}
	buf = g_malloc0(len + 1);
	readit(socket, buf, len);
	buf[len] = 0;
	for(i=0; i<servers->len; i++) {
		SERVER* srv = g_array_index(servers, SERVER*, i);
		if(strcmp(srv->servename, buf) == 0) {
			if(srv->max_connections == 0 || srv->max_connections > srv->numclients) {
				writeit(socket, "Y", 1);
				srv->numclients++;
			} else {
				writeit(socket, "N", 1);
			}
			goto exit;
		}
	}
	writeit(socket, "X", 1);
exit:
	g_free(buf);
	return 0;
}

/**
 * Return the index of the server whose servename matches the given
 * name.
 *
 * @param servename a string to match
 * @param servers an array of servers
 * @return the first index of the server whose servename matches the
 *         given name or -1 if one cannot be found
 **/
static int get_index_by_servename(const gchar *const servename,
                                  const GArray *const servers) {
        int i;

        for (i = 0; i < servers->len; ++i) {
                const SERVER* server = g_array_index(servers, SERVER*, i);

                if (strcmp(servename, server->servename) == 0)
                        return i;
        }

        return -1;
}

/**
 * Parse configuration files and add servers to the array if they don't
 * already exist there. The existence is tested by comparing
 * servenames. A server is appended to the array only if its servename
 * is unique among all other servers.
 *
 * @param servers an array of servers
 * @param genconf a pointer to generic configuration
 * @return the number of new servers appended to the array, or -1 in
 *         case of an error
 **/
static int append_new_servers(GArray *const servers, struct generic_conf *genconf, GError **const gerror) {
        int i;
        GArray *new_servers;
        const int old_len = servers->len;
        int retval = -1;

        new_servers = parse_cfile(config_file_pos, genconf, true, gerror);
        g_thread_pool_set_max_threads(tpool, genconf->threads, NULL);
        if (!new_servers)
                goto out;

        for (i = 0; i < new_servers->len; ++i) {
                SERVER *new_server = g_array_index(new_servers, SERVER*, i);

                if (new_server->servename
                    && -1 == get_index_by_servename(new_server->servename,
                                                    servers)) {
			g_array_append_val(servers, new_server);
                }
        }

        retval = servers->len - old_len;
out:
        g_array_free(new_servers, TRUE);

        return retval;
}

void serveloop(GArray* servers, struct generic_conf *genconf) G_GNUC_NORETURN;
/**
 * Loop through the available servers, and serve them. Never returns.
 **/
void serveloop(GArray* servers, struct generic_conf *genconf) {
	int i;
	int mmax, max;
	fd_set mset;
	fd_set rset;
	sigset_t blocking_mask;
	sigset_t original_mask;

	/* 
	 * Set up the master fd_set. The set of descriptors we need
	 * to select() for never changes anyway and it buys us a *lot*
	 * of time to only build this once. However, if we ever choose
	 * to not fork() for clients anymore, we may have to revisit
	 * this.
	 */
	mmax=0;
	FD_ZERO(&mset);
	for(i=0;i<modernsocks->len;i++) {
		int sock = g_array_index(modernsocks, int, i);
		FD_SET(sock, &mset);
		mmax=sock>mmax?sock:mmax;
	}

	/* Construct a signal mask which is used to make signal testing and
	 * receiving an atomic operation to ensure no signal is received between
	 * tests and blocking pselect(). */
	if (sigemptyset(&blocking_mask) == -1)
		err("failed to initialize blocking_mask: %m");

	if (sigaddset(&blocking_mask, SIGCHLD) == -1)
		err("failed to add SIGCHLD to blocking_mask: %m");

	if (sigaddset(&blocking_mask, SIGHUP) == -1)
		err("failed to add SIGHUP to blocking_mask: %m");

	if (sigaddset(&blocking_mask, SIGTERM) == -1)
		err("failed to add SIGTERM to blocking_mask: %m");

	if (sigprocmask(SIG_BLOCK, &blocking_mask, &original_mask) == -1)
	    err("failed to block signals: %m");

	for(;;) {
		if (is_sigterm_caught) {
			is_sigterm_caught = 0;

			g_hash_table_foreach(children, killchild, NULL);
			unlink(pidfname);

			exit(EXIT_SUCCESS);
		}

		if (is_sigchld_caught) {
			int status;
			int* i;
			pid_t pid;

			is_sigchld_caught = 0;

			while ((pid=waitpid(-1, &status, WNOHANG)) > 0) {
				if (WIFEXITED(status)) {
					msg(LOG_INFO, "Child exited with %d", WEXITSTATUS(status));
				}
				i = g_hash_table_lookup(children, &pid);
				if (!i) {
					msg(LOG_INFO, "SIGCHLD received for an unknown child with PID %ld", (long)pid);
				} else {
					DEBUG("Removing %d from the list of children", pid);
					g_hash_table_remove(children, &pid);
				}
			}
		}

                /* SIGHUP causes the root server process to reconfigure
                 * itself and add new export servers for each newly
                 * found export configuration group, i.e. spawn new
                 * server processes for each previously non-existent
                 * export. This does not alter old runtime configuration
                 * but just appends new exports. */
                if (is_sighup_caught) {
                        int n;
                        GError *gerror = NULL;

                        msg(LOG_INFO, "reconfiguration request received");
                        is_sighup_caught = 0; /* Reset to allow catching
                                               * it again. */

                        n = append_new_servers(servers, genconf, &gerror);
                        if (n == -1)
                                msg(LOG_ERR, "failed to append new servers: %s",
                                    gerror->message);

                        for (i = servers->len - n; i < servers->len; ++i) {
                                const SERVER *server = g_array_index(servers,
                                                                    SERVER*, i);

                                msg(LOG_INFO, "reconfigured new server: %s",
                                    server->servename);
                        }
                }

		memcpy(&rset, &mset, sizeof(fd_set));
		max=mmax;
		for(i=0;i<childsocks->len;i++) {
			int sock = g_array_index(childsocks, int, i);
			FD_SET(sock, &rset);
			max=sock>max?sock:max;
		}

		if (pselect(max + 1, &rset, NULL, NULL, NULL, &original_mask) > 0) {
			DEBUG("accept, ");
			for(i=0; i < modernsocks->len; i++) {
				int sock = g_array_index(modernsocks, int, i);
				if(!FD_ISSET(sock, &rset)) {
					continue;
				}

				handle_modern_connection(servers, sock, genconf);
			}
			for(i=0; i < childsocks->len; i++) {
				int sock = g_array_index(childsocks, int, i);

				if(FD_ISSET(sock, &rset)) {
					if(handle_childname(servers, sock) < 0) {
						close(sock);
						g_array_remove_index(childsocks, i);
					}
				}
			}
		}
	}
}

/**
 * Set server socket options.
 *
 * @param socket a socket descriptor of the server
 *
 * @param gerror a pointer to an error object pointer used for reporting
 *        errors. On error, if gerror is not NULL, *gerror is set and -1
 *        is returned.
 *
 * @return 0 on success, -1 on error
 **/
int dosockopts(const int socket, GError **const gerror) {
#ifndef sun
	int yes=1;
#else
	char yes='1';
#endif /* sun */
	struct linger l;

	/* lose the pesky "Address already in use" error message */
	if (setsockopt(socket,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) {
                g_set_error(gerror, NBDS_ERR, NBDS_ERR_SO_REUSEADDR,
                            "failed to set socket option SO_REUSEADDR: %s",
                            strerror(errno));
                return -1;
	}
	l.l_onoff = 1;
	l.l_linger = 10;
	if (setsockopt(socket,SOL_SOCKET,SO_LINGER,&l,sizeof(l)) == -1) {
                g_set_error(gerror, NBDS_ERR, NBDS_ERR_SO_LINGER,
                            "failed to set socket option SO_LINGER: %s",
                            strerror(errno));
                return -1;
	}
	if (setsockopt(socket,SOL_SOCKET,SO_KEEPALIVE,&yes,sizeof(int)) == -1) {
                g_set_error(gerror, NBDS_ERR, NBDS_ERR_SO_KEEPALIVE,
                            "failed to set socket option SO_KEEPALIVE: %s",
                            strerror(errno));
                return -1;
	}

        return 0;
}

int open_unix(const gchar *const sockname, GError **const gerror) {
	struct sockaddr_un sa;
	int sock=-1;
	int retval=-1;

	memset(&sa, 0, sizeof(struct sockaddr_un));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, sockname, sizeof sa.sun_path);
	sa.sun_path[sizeof(sa.sun_path)-1] = '\0';
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sock < 0) {
		g_set_error(gerror, NBDS_ERR, NBDS_ERR_SOCKET,
				"failed to open a unix socket: "
				"failed to create socket: %s",
				strerror(errno));
		goto out;
	}
	if(bind(sock, (struct sockaddr*)&sa, sizeof(struct sockaddr_un))<0) {
		g_set_error(gerror, NBDS_ERR, NBDS_ERR_BIND,
				"failed to open a unix socket: "
				"failed to bind to address %s: %s",
				sockname, strerror(errno));
		goto out;
	}
	if(listen(sock, 10)<0) {
		g_set_error(gerror, NBDS_ERR, NBDS_ERR_BIND,
				"failed to open a unix socket: "
				"failed to start listening: %s",
				strerror(errno));
		goto out;
	}
	retval=0;
	g_array_append_val(modernsocks, sock);
out:
	if(retval<0 && sock >= 0) {
		close(sock);
	}

	return retval;
}

int open_modern(const gchar *const addr, const gchar *const port,
                GError **const gerror) {
	struct addrinfo hints;
	struct addrinfo* ai = NULL;
	struct addrinfo* ai_bak = NULL;
	struct sock_flags;
	int e;
        int retval = -1;
	int sock = -1;
	gchar** addrs;
	gchar const* l_addr = addr;

	if(!addr || strlen(addr) == 0) {
		l_addr = "::, 0.0.0.0";
	}

	addrs = g_strsplit_set(l_addr, ", \t", -1);

	for(int i=0; addrs[i]!=NULL; i++) {
		if(addrs[i][0] == '\0') {
			continue;
		}
		memset(&hints, '\0', sizeof(hints));
		hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_family = AF_UNSPEC;
		hints.ai_protocol = IPPROTO_TCP;
		e = getaddrinfo(addrs[i], port ? port : NBD_DEFAULT_PORT, &hints, &ai);
		ai_bak = ai;
		if(e != 0 && addrs[i+1] == NULL && modernsocks->len == 0) {
			g_set_error(gerror, NBDS_ERR, NBDS_ERR_GAI,
				    "failed to open a modern socket: "
				    "failed to get address info: %s",
				    gai_strerror(e));
			goto out;
		}

		while(ai != NULL) {
			sock = -1;

			if((sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol))<0) {
				g_set_error(gerror, NBDS_ERR, NBDS_ERR_SOCKET,
					    "failed to open a modern socket: "
					    "failed to create a socket: %s",
					    strerror(errno));
				goto out;
			}

			if (dosockopts(sock, gerror) == -1) {
				g_prefix_error(gerror, "failed to open a modern socket: ");
				goto out;
			}

			if(bind(sock, ai->ai_addr, ai->ai_addrlen)) {
				/*
				 * Some systems will return multiple entries for the
				 * same address when we ask it for something
				 * AF_UNSPEC, even though the first entry will
				 * listen to both protocols. Other systems will
				 * return multiple entries too, but we actually
				 * do need to open both.
				 *
				 * Handle this by ignoring EADDRINUSE if we've
				 * already got at least one socket open
				 */
				if(errno == EADDRINUSE && modernsocks->len > 0) {
					goto next;
				}
				g_set_error(gerror, NBDS_ERR, NBDS_ERR_BIND,
					    "failed to open a modern socket: "
					    "failed to bind an address to a socket: %s",
					    strerror(errno));
				goto out;
			}

			if(listen(sock, 10) <0) {
				g_set_error(gerror, NBDS_ERR, NBDS_ERR_BIND,
					    "failed to open a modern socket: "
					    "failed to start listening on a socket: %s",
					    strerror(errno));
				goto out;
			}
			g_array_append_val(modernsocks, sock);
		next:
			ai = ai->ai_next;
		}
		if(ai_bak) {
			freeaddrinfo(ai_bak);
			ai_bak=NULL;
		}
	}

        retval = 0;
out:

        if (retval == -1 && sock >= 0) {
                close(sock);
        }
	if(ai_bak)
		freeaddrinfo(ai_bak);

        return retval;
}

/**
 * Connect our servers.
 **/
void setup_servers(GArray *const servers, const gchar *const modernaddr,
                   const gchar *const modernport, const gchar* unixsock,
                   const gint flags ) {
	struct sigaction sa;

	if(unixsock != NULL) {
		GError* gerror = NULL;
		if(open_unix(unixsock, &gerror) == -1) {
			msg(LOG_ERR, "failed to setup servers: %s",
					gerror->message);
			g_clear_error(&gerror);
			exit(EXIT_FAILURE);
		}
	}
	if (((flags & F_DUAL_LISTEN) != 0) || (unixsock == NULL)) {
		GError *gerror = NULL;
		if (open_modern(modernaddr, modernport, &gerror) == -1) {
			msg(LOG_ERR, "failed to setup servers: %s",
				gerror->message);
			g_clear_error(&gerror);
			exit(EXIT_FAILURE);
		}
	}
	children=g_hash_table_new_full(g_int_hash, g_int_equal, NULL, destroy_pid_t);

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGTERM);
	sa.sa_flags = SA_RESTART;
	if(sigaction(SIGCHLD, &sa, NULL) == -1)
		err("sigaction: %m");

	sa.sa_handler = sigterm_handler;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGCHLD);
	sa.sa_flags = SA_RESTART;
	if(sigaction(SIGTERM, &sa, NULL) == -1)
		err("sigaction: %m");

	sa.sa_handler = sighup_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if(sigaction(SIGHUP, &sa, NULL) == -1)
		err("sigaction: %m");

	sa.sa_handler = sigusr1_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if(sigaction(SIGUSR1, &sa, NULL) == -1)
		err("sigaction: %m");
}

/**
 * Go daemon (unless we specified at compile time that we didn't want this)
 * @param serve the first server of our configuration. If its port is zero,
 * 	then do not daemonize, because we're doing inetd then. This parameter
 * 	is only used to create a PID file of the form
 * 	/var/run/nbd-server.&lt;port&gt;.pid; it's not modified in any way.
 **/
#if !defined(NODAEMON)
void daemonize() {
	FILE*pidf;

	if(daemon(0,0)<0) {
		err("daemon");
	}
	if(!*pidfname) {
		strncpy(pidfname, "/var/run/nbd-server.pid", 255);
	}
	pidf=fopen(pidfname, "w");
	if(pidf) {
		fprintf(pidf,"%d\n", (int)getpid());
		fclose(pidf);
	} else {
		perror("fopen");
		fprintf(stderr, "Not fatal; continuing");
	}
}
#else
#define daemonize(serve)
#endif /* !defined(NODAEMON) */

/*
 * Everything beyond this point (in the file) is run in non-daemon mode.
 * The stuff above daemonize() isn't.
 */

/**
 * Set up user-ID and/or group-ID
 **/
void dousers(const gchar *const username, const gchar *const groupname) {
	struct passwd *pw;
	struct group *gr;
	gchar* str;
	if (groupname) {
		gr = getgrnam(groupname);
		if(!gr) {
			str = g_strdup_printf("Invalid group name: %s", groupname);
			err(str);
		}
		if(setgid(gr->gr_gid)<0) {
			err("Could not set GID: %m"); 
		}
	}
	if (username) {
		pw = getpwnam(username);
		if(!pw) {
			str = g_strdup_printf("Invalid user name: %s", username);
			err(str);
		}
		setgroups(0, NULL);
		if(setuid(pw->pw_uid)<0) {
			err("Could not set UID: %m");
		}
	}
}

#ifndef ISSERVER
void glib_message_syslog_redirect(const gchar *log_domain,
                                  GLogLevelFlags log_level,
                                  const gchar *message,
                                  gpointer user_data)
{
    int level=LOG_DEBUG;
    
    switch( log_level )
    {
      case G_LOG_FLAG_FATAL:
      case G_LOG_LEVEL_CRITICAL:
      case G_LOG_LEVEL_ERROR:    
        level=LOG_ERR; 
        break;
      case G_LOG_LEVEL_WARNING:
        level=LOG_WARNING;
        break;
      case G_LOG_LEVEL_MESSAGE:
      case G_LOG_LEVEL_INFO:
        level=LOG_INFO;
        break;
      case G_LOG_LEVEL_DEBUG:
        level=LOG_DEBUG;
	break;
      default:
        level=LOG_ERR;
    }
    syslog(level, "%s", message);
}
#endif

/**
 * Main entry point...
 **/
int main(int argc, char *argv[]) {
	SERVER *serve;
	GArray *servers;
	GError *gerr=NULL;
	struct generic_conf genconf;

	memset(&genconf, 0, sizeof(struct generic_conf));

	if (sizeof( struct nbd_request )!=28) {
		fprintf(stderr,"Bad size of structure. Alignment problems?\n");
		exit(EXIT_FAILURE) ;
	}

	modernsocks = g_array_new(FALSE, FALSE, sizeof(int));
	childsocks = g_array_new(FALSE, FALSE, sizeof(int));

	logging(MY_NAME);
	config_file_pos = g_strdup(CFILE);
	serve=cmdline(argc, argv, &genconf);

	genconf.threads = 4;
        servers = parse_cfile(config_file_pos, &genconf, true, &gerr);

        /* Update global variables with parsed values. This will be
         * removed once we get rid of global configuration variables. */
        glob_flags   |= genconf.flags;

	if(serve) {
		g_array_append_val(servers, serve);
	}
    
	if(!servers || !servers->len) {
                if(gerr && !(gerr->domain == NBDS_ERR
                            && gerr->code == NBDS_ERR_CFILE_NOTFOUND)) {
			g_warning("Could not parse config file: %s", 
					gerr ? gerr->message : "Unknown error");
		}
	}
	if(serve) {
		g_warning("Specifying an export on the command line no longer uses the oldstyle protocol.");
	}

	if((!serve) && (!servers||!servers->len)) {
		if(gerr)
			g_message("No configured exports; quitting.");
		exit(EXIT_FAILURE);
	}
	if (!nodaemon)
		daemonize();
#if HAVE_OLD_GLIB
	g_thread_init(NULL);
#endif
	tpool = g_thread_pool_new(handle_request, NULL, genconf.threads, FALSE, NULL);

	setup_servers(servers, genconf.modernaddr, genconf.modernport,
			genconf.unixsock, genconf.flags);
	dousers(genconf.user, genconf.group);

#if HAVE_GNUTLS
	gnutls_global_init();
	static gnutls_dh_params_t dh_params;
	gnutls_dh_params_init(&dh_params);
	gnutls_dh_params_generate2(dh_params,
				gnutls_sec_param_to_pk_bits(GNUTLS_PK_DH,
// Renamed in GnuTLS 3.3
#if GNUTLS_VERSION_NUMBER >= 0x030300
					GNUTLS_SEC_PARAM_MEDIUM
#else
					GNUTLS_SEC_PARAM_NORMAL
#endif
					));
#endif

	if((genconf.modernport != NULL) && strcmp(genconf.modernport, "0")==0) {
#ifndef ISSERVER
		err("inetd mode requires syslog");
#endif
		CLIENT* client = negotiate(0, servers, &genconf);
		if(!client) {
			exit(EXIT_FAILURE);
		}
		mainloop_threaded(client);
		return 0;
	}

	serveloop(servers, &genconf);
}
