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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>		/* select */
#include <sys/wait.h>		/* wait */
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <sys/param.h>
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>		/* For BLKGETSIZE */
#endif
#include <signal.h>		/* sigaction */
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <strings.h>
#include <dirent.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>

#include <glib.h>

/* used in cliserv.h, so must come first */
#define MY_NAME "nbd_server"
#include "cliserv.h"

#ifdef WITH_SDP
#include <sdp_inet.h>
#endif

/** Default position of the config file */
#ifndef SYSCONFDIR
#define SYSCONFDIR "/etc"
#endif
#define CFILE SYSCONFDIR "/nbd-server/config"

/** Where our config file actually is */
gchar* config_file_pos;

/** What user we're running as */
gchar* runuser=NULL;
/** What group we're running as */
gchar* rungroup=NULL;
/** whether to export using the old negotiation protocol (port-based) */
gboolean do_oldstyle=FALSE;

/** Logging macros, now nothing goes to syslog unless you say ISSERVER */
#ifdef ISSERVER
#define msg2(a,b) syslog(a,b)
#define msg3(a,b,c) syslog(a,b,c)
#define msg4(a,b,c,d) syslog(a,b,c,d)
#else
#define msg2(a,b) g_message(b)
#define msg3(a,b,c) g_message(b,c)
#define msg4(a,b,c,d) g_message(b,c,d)
#endif

/* Debugging macros */
//#define DODBG
#ifdef DODBG
#define DEBUG( a ) printf( a )
#define DEBUG2( a,b ) printf( a,b )
#define DEBUG3( a,b,c ) printf( a,b,c )
#define DEBUG4( a,b,c,d ) printf( a,b,c,d )
#else
#define DEBUG( a )
#define DEBUG2( a,b ) 
#define DEBUG3( a,b,c ) 
#define DEBUG4( a,b,c,d ) 
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif
/**
 * The highest value a variable of type off_t can reach. This is a signed
 * integer, so set all bits except for the leftmost one.
 **/
#define OFFT_MAX ~((off_t)1<<(sizeof(off_t)*8-1))
#define LINELEN 256	  /**< Size of static buffer used to read the
			       authorization file (yuck) */
#define BUFSIZE ((1024*1024)+sizeof(struct nbd_reply)) /**< Size of buffer that can hold requests */
#define DIFFPAGESIZE 4096 /**< diff file uses those chunks */
#define F_READONLY 1      /**< flag to tell us a file is readonly */
#define F_MULTIFILE 2	  /**< flag to tell us a file is exported using -m */
#define F_COPYONWRITE 4	  /**< flag to tell us a file is exported using
			    copyonwrite */
#define F_AUTOREADONLY 8  /**< flag to tell us a file is set to autoreadonly */
#define F_SPARSE 16	  /**< flag to tell us copyronwrite should use a sparse file */
#define F_SDP 32	  /**< flag to tell us the export should be done using the Socket Direct Protocol for RDMA */
#define F_SYNC 64	  /**< Whether to fsync() after a write */
GHashTable *children;
char pidfname[256]; /**< name of our PID file */
char pidftemplate[256]; /**< template to be used for the filename of the PID file */
char default_authname[] = SYSCONFDIR "/nbd-server/allow"; /**< default name of allow file */

int modernsock=0;	  /**< Socket for the modern handler. Not used
			       if a client was only specified on the
			       command line; only port used if
			       oldstyle is set to false (and then the
			       command-line client isn't used, gna gna) */
char* modern_listen;	  /**< listenaddr value for modernsock */

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
} SERVER;

/**
 * Variables associated with a client socket.
 **/
typedef struct {
	int fhandle;      /**< file descriptor */
	off_t startoff;   /**< starting offset of this file */
} FILE_INFO;

typedef struct {
	off_t exportsize;    /**< size of the file we're exporting */
	char *clientname;    /**< peer */
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
	u32 difffilelen;     /**< number of pages in difffile */
	u32 *difmap;	     /**< see comment on the global difmap for this one */
	gboolean modern;     /**< client was negotiated using modern negotiation protocol */
} CLIENT;

/**
 * Type of configuration file values
 **/
typedef enum {
	PARAM_INT,		/**< This parameter is an integer */
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
 * Check whether a client is allowed to connect. Works with an authorization
 * file which contains one line per machine, no wildcards.
 *
 * @param opts The client who's trying to connect.
 * @return 0 - authorization refused, 1 - OK
 **/
int authorized_client(CLIENT *opts) {
	const char *ERRMSG="Invalid entry '%s' in authfile '%s', so, refusing all connections.";
	FILE *f ;
	char line[LINELEN]; 
	char *tmp;
	struct in_addr addr;
	struct in_addr client;
	struct in_addr cltemp;
	int len;

	if ((f=fopen(opts->server->authname,"r"))==NULL) {
		msg4(LOG_INFO,"Can't open authorization file %s (%s).",
		     opts->server->authname,strerror(errno)) ;
		return 1 ; 
	}
  
  	inet_aton(opts->clientname, &client);
	while (fgets(line,LINELEN,f)!=NULL) {
		if((tmp=index(line, '/'))) {
			if(strlen(line)<=tmp-line) {
				msg4(LOG_CRIT, ERRMSG, line, opts->server->authname);
				return 0;
			}
			*(tmp++)=0;
			if(!inet_aton(line,&addr)) {
				msg4(LOG_CRIT, ERRMSG, line, opts->server->authname);
				return 0;
			}
			len=strtol(tmp, NULL, 0);
			addr.s_addr>>=32-len;
			addr.s_addr<<=32-len;
			memcpy(&cltemp,&client,sizeof(client));
			cltemp.s_addr>>=32-len;
			cltemp.s_addr<<=32-len;
			if(addr.s_addr == cltemp.s_addr) {
				return 1;
			}
		}
		if (strncmp(line,opts->clientname,strlen(opts->clientname))==0) {
			fclose(f);
			return 1;
		}
	}
	fclose(f);
	return 0;
}

/**
 * Read data from a file descriptor into a buffer
 *
 * @param f a file descriptor
 * @param buf a buffer
 * @param len the number of bytes to be read
 **/
inline void readit(int f, void *buf, size_t len) {
	ssize_t res;
	while (len > 0) {
		DEBUG("*");
		if ((res = read(f, buf, len)) <= 0) {
			if(errno != EAGAIN) {
				err("Read failed: %m");
			}
		} else {
			len -= res;
			buf += res;
		}
	}
}

/**
 * Write data from a buffer into a filedescriptor
 *
 * @param f a file descriptor
 * @param buf a buffer containing data
 * @param len the number of bytes to be written
 **/
inline void writeit(int f, void *buf, size_t len) {
	ssize_t res;
	while (len > 0) {
		DEBUG("+");
		if ((res = write(f, buf, len)) <= 0)
			err("Send failed: %m");
		len -= res;
		buf += res;
	}
}

/**
 * Print out a message about how to use nbd-server. Split out to a separate
 * function so that we can call it from multiple places
 */
void usage() {
	printf("This is nbd-server version " VERSION "\n");
	printf("Usage: [ip:|ip6@]port file_to_export [size][kKmM] [-l authorize_file] [-r] [-m] [-c] [-C configuration file] [-p PID file name] [-o section name] [-M max connections]\n"
	       "\t-r|--read-only\t\tread only\n"
	       "\t-m|--multi-file\t\tmultiple file\n"
	       "\t-c|--copy-on-write\tcopy on write\n"
	       "\t-C|--config-file\tspecify an alternate configuration file\n"
	       "\t-l|--authorize-file\tfile with list of hosts that are allowed to\n\t\t\t\tconnect.\n"
	       "\t-p|--pid-file\t\tspecify a filename to write our PID to\n"
	       "\t-o|--output-config\toutput a config file section for what you\n\t\t\t\tspecified on the command line, with the\n\t\t\t\tspecified section name\n"
	       "\t-M|--max-connections\tspecify the maximum number of opened connections\n\n"
	       "\tif port is set to 0, stdin is used (for running from inetd)\n"
	       "\tif file_to_export contains '%%s', it is substituted with the IP\n"
	       "\t\taddress of the machine trying to connect\n" 
	       "\tif ip is set, it contains the local IP address on which we're listening.\n\tif not, the server will listen on all local IP addresses\n");
	printf("Using configuration file %s\n", CFILE);
}

/* Dumps a config file section of the given SERVER*, and exits. */
void dump_section(SERVER* serve, gchar* section_header) {
	printf("[%s]\n", section_header);
	printf("\texportname = %s\n", serve->exportname);
	printf("\tlistenaddr = %s\n", serve->listenaddr);
	printf("\tport = %d\n", serve->port);
	if(serve->flags & F_READONLY) {
		printf("\treadonly = true\n");
	}
	if(serve->flags & F_MULTIFILE) {
		printf("\tmultifile = true\n");
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
SERVER* cmdline(int argc, char *argv[]) {
	int i=0;
	int nonspecial=0;
	int c;
	struct option long_options[] = {
		{"read-only", no_argument, NULL, 'r'},
		{"multi-file", no_argument, NULL, 'm'},
		{"copy-on-write", no_argument, NULL, 'c'},
		{"authorize-file", required_argument, NULL, 'l'},
		{"config-file", required_argument, NULL, 'C'},
		{"pid-file", required_argument, NULL, 'p'},
		{"output-config", required_argument, NULL, 'o'},
		{"max-connection", required_argument, NULL, 'M'},
		{0,0,0,0}
	};
	SERVER *serve;
	off_t es;
	size_t last;
	char suffix;
	gboolean do_output=FALSE;
	gchar* section_header="";
	gchar** addr_port;

	if(argc==1) {
		return NULL;
	}
	serve=g_new0(SERVER, 1);
	serve->authname = g_strdup(default_authname);
	serve->virtstyle=VIRT_IPLIT;
	while((c=getopt_long(argc, argv, "-C:cl:mo:rp:M:", long_options, &i))>=0) {
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
					serve->port=strtol(addr_port[1], NULL, 0);
					serve->listenaddr=g_strdup(addr_port[0]);
				} else {
					serve->listenaddr=NULL;
					serve->port=strtol(addr_port[0], NULL, 0);
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
			do_output = TRUE;
			section_header = g_strdup(optarg);
			break;
		case 'p':
			strncpy(pidftemplate, optarg, 256);
			break;
		case 'c': 
			serve->flags |=F_COPYONWRITE;
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
		default:
			usage();
			exit(EXIT_FAILURE);
			break;
		}
	}
	/* What's left: the port to export, the name of the to be exported
	 * file, and, optionally, the size of the file, in that order. */
	if(nonspecial<2) {
		g_free(serve);
		serve=NULL;
	} else {
		do_oldstyle = TRUE;
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

/**
 * Error codes for config file parsing
 **/
typedef enum {
	CFILE_NOTFOUND,		/**< The configuration file is not found */
	CFILE_MISSING_GENERIC,	/**< The (required) group "generic" is missing */
	CFILE_KEY_MISSING,	/**< A (required) key is missing */
	CFILE_VALUE_INVALID,	/**< A value is syntactically invalid */
	CFILE_VALUE_UNSUPPORTED,/**< A value is not supported in this build */
	CFILE_PROGERR,		/**< Programmer error */
	CFILE_NO_EXPORTS,	/**< A config file was specified that does not
				     define any exports */
	CFILE_INCORRECT_PORT,	/**< The reserved port was specified for an
				     old-style export. */
} CFILE_ERRORS;

/**
 * Remove a SERVER from memory. Used from the hash table
 **/
void remove_server(gpointer s) {
	SERVER *server;

	server=(SERVER*)s;
	g_free(server->exportname);
	if(server->authname)
		g_free(server->authname);
	if(server->listenaddr)
		g_free(server->listenaddr);
	if(server->prerun)
		g_free(server->prerun);
	if(server->postrun)
		g_free(server->postrun);
	g_free(server);
}

/**
 * duplicate server
 * @param s the old server we want to duplicate
 * @return new duplicated server
 **/
SERVER* dup_serve(SERVER *s) {
	SERVER *serve = NULL;

	serve=g_new0(SERVER, 1);
	if(serve == NULL)
		return NULL;

	if(s->exportname)
		serve->exportname = g_strdup(s->exportname);

	serve->expected_size = s->expected_size;

	if(s->listenaddr)
		serve->listenaddr = g_strdup(s->listenaddr);

	serve->port = s->port;

	if(s->authname)
		serve->authname = strdup(s->authname);

	serve->flags = s->flags;
	serve->socket = serve->socket;
	serve->socket_family = serve->socket_family;
	serve->cidrlen = s->cidrlen;

	if(s->prerun)
		serve->prerun = g_strdup(s->prerun);

	if(s->postrun)
		serve->postrun = g_strdup(s->postrun);
	
	if(s->servename)
		serve->servename = g_strdup(s->servename);

	serve->max_connections = s->max_connections;

	return serve;
}

/**
 * append new server to array
 * @param s server
 * @param a server array
 * @return 0 success, -1 error
 */
int append_serve(SERVER *s, GArray *a) {
	SERVER *ns = NULL;
	struct addrinfo hints;
	struct addrinfo *ai = NULL;
	struct addrinfo *rp = NULL;
	char   host[NI_MAXHOST];
	gchar  *port = NULL;
	int e;
	int ret;

	if(!s) {
		err("Invalid parsing server");
		return -1;
	}

	port = g_strdup_printf("%d", s->port);

	memset(&hints,'\0',sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;
	hints.ai_protocol = IPPROTO_TCP;

	e = getaddrinfo(s->listenaddr, port, &hints, &ai);

	if (port)
		g_free(port);

	if(e == 0) {
		for (rp = ai; rp != NULL; rp = rp->ai_next) {
			e = getnameinfo(rp->ai_addr, rp->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);

			if (e != 0) { // error
				fprintf(stderr, "getnameinfo: %s\n", gai_strerror(e));
				continue;
			}

			// duplicate server and set listenaddr to resolved IP address
			ns = dup_serve (s);
			if (ns) {
				ns->listenaddr = g_strdup(host);
				ns->socket_family = rp->ai_family;
				g_array_append_val(a, *ns);
				free(ns);
				ns = NULL;
			}
		}

		ret = 0;
	} else {
		fprintf(stderr, "getaddrinfo failed on listen host/address: %s (%s)\n", s->listenaddr ? s->listenaddr : "any", gai_strerror(e));
		ret = -1;
	}

	if (ai)
		freeaddrinfo(ai);

	return ret;
}

/**
 * Parse the config file.
 *
 * @param f the name of the config file
 * @param e a GError. @see CFILE_ERRORS for what error values this function can
 * 	return.
 * @return a Array of SERVER* pointers, If the config file is empty or does not
 *	exist, returns an empty GHashTable; if the config file contains an
 *	error, returns NULL, and e is set appropriately
 **/
GArray* parse_cfile(gchar* f, GError** e) {
	const char* DEFAULT_ERROR = "Could not parse %s in group %s: %s";
	const char* MISSING_REQUIRED_ERROR = "Could not find required value %s in group %s: %s";
	SERVER s;
	gchar *virtstyle=NULL;
	PARAM lp[] = {
		{ "exportname", TRUE,	PARAM_STRING, 	NULL, 0 },
		{ "port", 	TRUE,	PARAM_INT, 	NULL, 0 },
		{ "authfile",	FALSE,	PARAM_STRING,	NULL, 0 },
		{ "filesize",	FALSE,	PARAM_INT,	NULL, 0 },
		{ "virtstyle",	FALSE,	PARAM_STRING,	NULL, 0 },
		{ "prerun",	FALSE,	PARAM_STRING,	NULL, 0 },
		{ "postrun",	FALSE,	PARAM_STRING,	NULL, 0 },
		{ "readonly",	FALSE,	PARAM_BOOL,	NULL, F_READONLY },
		{ "multifile",	FALSE,	PARAM_BOOL,	NULL, F_MULTIFILE },
		{ "copyonwrite", FALSE,	PARAM_BOOL,	NULL, F_COPYONWRITE },
		{ "sparse_cow",	FALSE,	PARAM_BOOL,	NULL, F_SPARSE },
		{ "sdp",	FALSE,	PARAM_BOOL,	NULL, F_SDP },
		{ "sync",	FALSE,  PARAM_BOOL,	NULL, F_SYNC },
		{ "listenaddr", FALSE,  PARAM_STRING,   NULL, 0 },
		{ "maxconnections", FALSE, PARAM_INT,	NULL, 0 },
	};
	const int lp_size=sizeof(lp)/sizeof(PARAM);
	PARAM gp[] = {
		{ "user",	FALSE, PARAM_STRING,	&runuser,	0 },
		{ "group",	FALSE, PARAM_STRING,	&rungroup,	0 },
		{ "oldstyle",	FALSE, PARAM_BOOL,	&do_oldstyle,	1 },
		{ "listenaddr", FALSE, PARAM_STRING,	&modern_listen, 0 },
	};
	PARAM* p=gp;
	int p_size=sizeof(gp)/sizeof(PARAM);
	GKeyFile *cfile;
	GError *err = NULL;
	const char *err_msg=NULL;
	GQuark errdomain;
	GArray *retval=NULL;
	gchar **groups;
	gboolean value;
	gchar* startgroup;
	gint i;
	gint j;

	errdomain = g_quark_from_string("parse_cfile");
	cfile = g_key_file_new();
	retval = g_array_new(FALSE, TRUE, sizeof(SERVER));
	if(!g_key_file_load_from_file(cfile, f, G_KEY_FILE_KEEP_COMMENTS |
			G_KEY_FILE_KEEP_TRANSLATIONS, &err)) {
		g_set_error(e, errdomain, CFILE_NOTFOUND, "Could not open config file %s.", f);
		g_key_file_free(cfile);
		return retval;
	}
	startgroup = g_key_file_get_start_group(cfile);
	if(!startgroup || strcmp(startgroup, "generic")) {
		g_set_error(e, errdomain, CFILE_MISSING_GENERIC, "Config file does not contain the [generic] group!");
		g_key_file_free(cfile);
		return NULL;
	}
	groups = g_key_file_get_groups(cfile, NULL);
	for(i=0;groups[i];i++) {
		memset(&s, '\0', sizeof(SERVER));
		lp[0].target=&(s.exportname);
		lp[1].target=&(s.port);
		lp[2].target=&(s.authname);
		lp[3].target=&(s.expected_size);
		lp[4].target=&(virtstyle);
		lp[5].target=&(s.prerun);
		lp[6].target=&(s.postrun);
		lp[7].target=lp[8].target=lp[9].target=
				lp[10].target=lp[11].target=
				lp[12].target=&(s.flags);
		lp[13].target=&(s.listenaddr);
		lp[14].target=&(s.max_connections);

		/* After the [generic] group, start parsing exports */
		if(i==1) {
			p=lp;
			p_size=lp_size;
		} 
		for(j=0;j<p_size;j++) {
			g_assert(p[j].target != NULL);
			g_assert(p[j].ptype==PARAM_INT||p[j].ptype==PARAM_STRING||p[j].ptype==PARAM_BOOL);
			switch(p[j].ptype) {
				case PARAM_INT:
					*((gint*)p[j].target) =
						g_key_file_get_integer(cfile,
								groups[i],
								p[j].paramname,
								&err);
					break;
				case PARAM_STRING:
					*((gchar**)p[j].target) =
						g_key_file_get_string(cfile,
								groups[i],
								p[j].paramname,
								&err);
					break;
				case PARAM_BOOL:
					value = g_key_file_get_boolean(cfile,
							groups[i],
							p[j].paramname, &err);
					if(!err) {
						if(value) {
							*((gint*)p[j].target) |= p[j].flagval;
						} else {
							*((gint*)p[j].target) &= ~(p[j].flagval);
						}
					}
					break;
			}
			if(!strcmp(p[j].paramname, "port") && !strcmp(p[j].target, NBD_DEFAULT_PORT)) {
				g_set_error(e, errdomain, CFILE_INCORRECT_PORT, "Config file specifies default port for oldstyle export");
				g_key_file_free(cfile);
				return NULL;
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
				g_set_error(e, errdomain, CFILE_VALUE_INVALID, err_msg, p[j].paramname, groups[i], err->message);
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
					g_set_error(e, errdomain, CFILE_VALUE_INVALID, "Invalid value %s for parameter virtstyle in group %s: missing length", virtstyle, groups[i]);
					g_array_free(retval, TRUE);
					g_key_file_free(cfile);
					return NULL;
				}
				s.cidrlen=strtol(virtstyle+8, NULL, 0);
			} else {
				g_set_error(e, errdomain, CFILE_VALUE_INVALID, "Invalid value %s for parameter virtstyle in group %s", virtstyle, groups[i]);
				g_array_free(retval, TRUE);
				g_key_file_free(cfile);
				return NULL;
			}
			if(s.port && !do_oldstyle) {
				g_warning("A port was specified, but oldstyle exports were not requested. This may not do what you expect.");
				g_warning("Please read 'man 5 nbd-server' and search for oldstyle for more info");
			}
		} else {
			s.virtstyle=VIRT_IPLIT;
		}
		/* Don't need to free this, it's not our string */
		virtstyle=NULL;
		/* Don't append values for the [generic] group */
		if(i>0) {
			s.socket_family = AF_UNSPEC;
			s.servename = groups[i];

			append_serve(&s, retval);
		} else {
			if(!do_oldstyle) {
				lp[1].required = 0;
			}
		}
#ifndef WITH_SDP
		if(s.flags & F_SDP) {
			g_set_error(e, errdomain, CFILE_VALUE_UNSUPPORTED, "This nbd-server was built without support for SDP, yet group %s uses it", groups[i]);
			g_array_free(retval, TRUE);
			g_key_file_free(cfile);
			return NULL;
		}
#endif
	}
	if(i==1) {
		g_set_error(e, errdomain, CFILE_NO_EXPORTS, "The config file does not specify any exports");
	}
	g_key_file_free(cfile);
	return retval;
}

/**
 * Signal handler for SIGCHLD
 * @param s the signal we're handling (must be SIGCHLD, or something
 * is severely wrong)
 **/
void sigchld_handler(int s) {
        int status;
	int* i;
	pid_t pid;

	while((pid=waitpid(-1, &status, WNOHANG)) > 0) {
		if(WIFEXITED(status)) {
			msg3(LOG_INFO, "Child exited with %d", WEXITSTATUS(status));
		}
		i=g_hash_table_lookup(children, &pid);
		if(!i) {
			msg3(LOG_INFO, "SIGCHLD received for an unknown child with PID %ld", (long)pid);
		} else {
			DEBUG2("Removing %d from the list of children", pid);
			g_hash_table_remove(children, &pid);
		}
	}
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
	int *parent=user_data;

	kill(*pid, SIGTERM);
	*parent=1;
}

/**
 * Handle SIGTERM and dispatch it to our children
 * @param s the signal we're handling (must be SIGTERM, or something
 * is severely wrong).
 **/
void sigterm_handler(int s) {
	int parent=0;

	g_hash_table_foreach(children, killchild, &parent);

	if(parent) {
		unlink(pidfname);
	}

	exit(EXIT_SUCCESS);
}

/**
 * Detect the size of a file.
 *
 * @param fhandle An open filedescriptor
 * @return the size of the file, or OFFT_MAX if detection was
 * impossible.
 **/
off_t size_autodetect(int fhandle) {
	off_t es;
	u64 bytes;
	struct stat stat_buf;
	int error;

#ifdef HAVE_SYS_MOUNT_H
#ifdef HAVE_SYS_IOCTL_H
#ifdef BLKGETSIZE64
	DEBUG("looking for export size with ioctl BLKGETSIZE64\n");
	if (!ioctl(fhandle, BLKGETSIZE64, &bytes) && bytes) {
		return (off_t)bytes;
	}
#endif /* BLKGETSIZE64 */
#endif /* HAVE_SYS_IOCTL_H */
#endif /* HAVE_SYS_MOUNT_H */

	DEBUG("looking for fhandle size with fstat\n");
	stat_buf.st_size = 0;
	error = fstat(fhandle, &stat_buf);
	if (!error) {
		if(stat_buf.st_size > 0)
			return (off_t)stat_buf.st_size;
        } else {
                err("fstat failed: %m");
        }

	DEBUG("looking for fhandle size with lseek SEEK_END\n");
	es = lseek(fhandle, (off_t)0, SEEK_END);
	if (es > ((off_t)0)) {
		return es;
        } else {
                DEBUG2("lseek failed: %d", errno==EBADF?1:(errno==ESPIPE?2:(errno==EINVAL?3:4)));
        }

	err("Could not find size of exported block device: %m");
	return OFFT_MAX;
}

/**
 * Get the file handle and offset, given an export offset.
 *
 * @param export An array of export files
 * @param a The offset to get corresponding file/offset for
 * @param fhandle [out] File descriptor
 * @param foffset [out] Offset into fhandle
 * @param maxbytes [out] Tells how many bytes can be read/written
 * from fhandle starting at foffset (0 if there is no limit)
 * @return 0 on success, -1 on failure
 **/
int get_filepos(GArray* export, off_t a, int* fhandle, off_t* foffset, size_t* maxbytes ) {
	/* Negative offset not allowed */
	if(a < 0)
		return -1;

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
	g_assert(end >= 0);

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
 * seek to a position in a file, with error handling.
 * @param handle a filedescriptor
 * @param a position to seek to
 * @todo get rid of this; lastpoint is a global variable right now, but it
 * shouldn't be. If we pass it on as a parameter, that makes things a *lot*
 * easier.
 **/
void myseek(int handle,off_t a) {
	if (lseek(handle, a, SEEK_SET) < 0) {
		err("Can not seek locally!\n");
	}
}

/**
 * Write an amount of bytes at a given offset to the right file. This
 * abstracts the write-side of the multiple file option.
 *
 * @param a The offset where the write should start
 * @param buf The buffer to write from
 * @param len The length of buf
 * @param client The client we're serving for
 * @return The number of bytes actually written, or -1 in case of an error
 **/
ssize_t rawexpwrite(off_t a, char *buf, size_t len, CLIENT *client) {
	int fhandle;
	off_t foffset;
	size_t maxbytes;
	ssize_t retval;

	if(get_filepos(client->export, a, &fhandle, &foffset, &maxbytes))
		return -1;
	if(maxbytes && len > maxbytes)
		len = maxbytes;

	DEBUG4("(WRITE to fd %d offset %llu len %u), ", fhandle, foffset, len);

	myseek(fhandle, foffset);
	retval = write(fhandle, buf, len);
	if(client->server->flags & F_SYNC) {
		fsync(fhandle);
	}
	return retval;
}

/**
 * Call rawexpwrite repeatedly until all data has been written.
 * @return 0 on success, nonzero on failure
 **/
int rawexpwrite_fully(off_t a, char *buf, size_t len, CLIENT *client) {
	ssize_t ret=0;

	while(len > 0 && (ret=rawexpwrite(a, buf, len, client)) > 0 ) {
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

	if(get_filepos(client->export, a, &fhandle, &foffset, &maxbytes))
		return -1;
	if(maxbytes && len > maxbytes)
		len = maxbytes;

	DEBUG4("(READ from fd %d offset %llu len %u), ", fhandle, foffset, len);

	myseek(fhandle, foffset);
	return read(fhandle, buf, len);
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

	if (!(client->server->flags & F_COPYONWRITE))
		return(rawexpread_fully(a, buf, len, client));
	DEBUG3("Asked to read %d bytes at %llu.\n", len, (unsigned long long)a);

	mapl=a/DIFFPAGESIZE; maph=(a+len-1)/DIFFPAGESIZE;

	for (mapcnt=mapl;mapcnt<=maph;mapcnt++) {
		pagestart=mapcnt*DIFFPAGESIZE;
		offset=a-pagestart;
		rdlen=(0<DIFFPAGESIZE-offset && len<(size_t)(DIFFPAGESIZE-offset)) ?
			len : (size_t)DIFFPAGESIZE-offset;
		if (client->difmap[mapcnt]!=(u32)(-1)) { /* the block is already there */
			DEBUG3("Page %llu is at %lu\n", (unsigned long long)mapcnt,
			       (unsigned long)(client->difmap[mapcnt]));
			myseek(client->difffile, client->difmap[mapcnt]*DIFFPAGESIZE+offset);
			if (read(client->difffile, buf, rdlen) != rdlen) return -1;
		} else { /* the block is not there */
			DEBUG2("Page %llu is not here, we read the original one\n",
			       (unsigned long long)mapcnt);
			if(rawexpread_fully(a, buf, rdlen, client)) return -1;
		}
		len-=rdlen; a+=rdlen; buf+=rdlen;
	}
	return 0;
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
 * @return 0 on success, nonzero on failure
 **/
int expwrite(off_t a, char *buf, size_t len, CLIENT *client) {
	char pagebuf[DIFFPAGESIZE];
	off_t mapcnt,mapl,maph;
	off_t wrlen,rdlen; 
	off_t pagestart;
	off_t offset;

	if (!(client->server->flags & F_COPYONWRITE))
		return(rawexpwrite_fully(a, buf, len, client)); 
	DEBUG3("Asked to write %d bytes at %llu.\n", len, (unsigned long long)a);

	mapl=a/DIFFPAGESIZE ; maph=(a+len-1)/DIFFPAGESIZE ;

	for (mapcnt=mapl;mapcnt<=maph;mapcnt++) {
		pagestart=mapcnt*DIFFPAGESIZE ;
		offset=a-pagestart ;
		wrlen=(0<DIFFPAGESIZE-offset && len<(size_t)(DIFFPAGESIZE-offset)) ?
			len : (size_t)DIFFPAGESIZE-offset;

		if (client->difmap[mapcnt]!=(u32)(-1)) { /* the block is already there */
			DEBUG3("Page %llu is at %lu\n", (unsigned long long)mapcnt,
			       (unsigned long)(client->difmap[mapcnt])) ;
			myseek(client->difffile,
					client->difmap[mapcnt]*DIFFPAGESIZE+offset);
			if (write(client->difffile, buf, wrlen) != wrlen) return -1 ;
		} else { /* the block is not there */
			myseek(client->difffile,client->difffilelen*DIFFPAGESIZE) ;
			client->difmap[mapcnt]=(client->server->flags&F_SPARSE)?mapcnt:client->difffilelen++;
			DEBUG3("Page %llu is not here, we put it at %lu\n",
			       (unsigned long long)mapcnt,
			       (unsigned long)(client->difmap[mapcnt]));
			rdlen=DIFFPAGESIZE ;
			if (rawexpread_fully(pagestart, pagebuf, rdlen, client))
				return -1;
			memcpy(pagebuf+offset,buf,wrlen) ;
			if (write(client->difffile, pagebuf, DIFFPAGESIZE) !=
					DIFFPAGESIZE)
				return -1;
		}						    
		len-=wrlen ; a+=wrlen ; buf+=wrlen ;
	}
	return 0;
}

/**
 * Do the initial negotiation.
 *
 * @param client The client we're negotiating with.
 **/
CLIENT* negotiate(int net, CLIENT *client, GArray* servers) {
	char zeros[128];
	uint64_t size_host;
	uint32_t flags = NBD_FLAG_HAS_FLAGS;
	uint16_t smallflags = 0;
	uint64_t magic;

	memset(zeros, '\0', sizeof(zeros));
	if(!client || !client->modern) {
		/* common */
		if (write(net, INIT_PASSWD, 8) < 0) {
			err_nonfatal("Negotiation failed: %m");
			if(client)
				exit(EXIT_FAILURE);
		}
		if(!client || client->modern) {
			/* modern */
			magic = htonll(opts_magic);
		} else {
			/* oldstyle */
			magic = htonll(cliserv_magic);
		}
		if (write(net, &magic, sizeof(magic)) < 0) {
			err_nonfatal("Negotiation failed: %m");
			if(client)
				exit(EXIT_FAILURE);
		}
	}
	if(!client) {
		/* modern */
		uint32_t reserved;
		uint32_t opt;
		uint32_t namelen;
		char* name;
		int i;

		if(!servers)
			err("programmer error");
		if (write(net, &smallflags, sizeof(uint16_t)) < 0)
			err("Negotiation failed: %m");
		if (read(net, &reserved, sizeof(reserved)) < 0)
			err("Negotiation failed: %m");
		if (read(net, &magic, sizeof(magic)) < 0)
			err("Negotiation failed: %m");
		magic = ntohll(magic);
		if(magic != opts_magic) {
			close(net);
			return NULL;
		}
		if (read(net, &opt, sizeof(opt)) < 0)
			err("Negotiation failed: %m");
		opt = ntohl(opt);
		if(opt != NBD_OPT_EXPORT_NAME) {
			close(net);
			return NULL;
		}
		if (read(net, &namelen, sizeof(namelen)) < 0)
			err("Negotiation failed: %m");
		namelen = ntohl(namelen);
		name = malloc(namelen+1);
		name[namelen]=0;
		if (read(net, name, namelen) < 0)
			err("Negotiation failed: %m");
		for(i=0; i<servers->len; i++) {
			SERVER* serve = &(g_array_index(servers, SERVER, i));
			if(!strcmp(serve->servename, name)) {
				CLIENT* client = g_new0(CLIENT, 1);
				client->server = serve;
				client->exportsize = OFFT_MAX;
				client->net = net;
				client->modern = TRUE;
				return client;
			}
		}
		return NULL;
	}
	/* common */
	size_host = htonll((u64)(client->exportsize));
	if (write(net, &size_host, 8) < 0)
		err("Negotiation failed: %m");
	if (client->server->flags & F_READONLY)
		flags |= NBD_FLAG_READ_ONLY;
	if (!client->modern) {
		/* oldstyle */
		flags = htonl(flags);
		if (write(client->net, &flags, 4) < 0)
			err("Negotiation failed: %m");
	} else {
		/* modern */
		smallflags = (uint16_t)(flags & ~((uint16_t)0));
		smallflags = htons(smallflags);
		if (write(client->net, &smallflags, sizeof(smallflags)) < 0) {
			err("Negotiation failed: %m");
		}
	}
	/* common */
	if (write(client->net, zeros, 124) < 0)
		err("Negotiation failed: %m");
	return NULL;
}

/** sending macro. */
#define SEND(net,reply) writeit( net, &reply, sizeof( reply ));
/** error macro. */
#define ERROR(client,reply,errcode) { reply.error = htonl(errcode); SEND(client->net,reply); reply.error = 0; }
/**
 * Serve a file to a single client.
 *
 * @todo This beast needs to be split up in many tiny little manageable
 * pieces. Preferably with a chainsaw.
 *
 * @param client The client we're going to serve to.
 * @return when the client disconnects
 **/
int mainloop(CLIENT *client) {
	struct nbd_request request;
	struct nbd_reply reply;
	gboolean go_on=TRUE;
#ifdef DODBG
	int i = 0;
#endif
	negotiate(client->net, client, NULL);
	DEBUG("Entering request loop!\n");
	reply.magic = htonl(NBD_REPLY_MAGIC);
	reply.error = 0;
	while (go_on) {
		char buf[BUFSIZE];
		size_t len;
#ifdef DODBG
		i++;
		printf("%d: ", i);
#endif
		readit(client->net, &request, sizeof(request));
		request.from = ntohll(request.from);
		request.type = ntohl(request.type);

		if (request.type==NBD_CMD_DISC) {
			msg2(LOG_INFO, "Disconnect request received.");
                	if (client->server->flags & F_COPYONWRITE) { 
				if (client->difmap) g_free(client->difmap) ;
                		close(client->difffile);
				unlink(client->difffilename);
				free(client->difffilename);
			}
			go_on=FALSE;
			continue;
		}

		len = ntohl(request.len);

		if (request.magic != htonl(NBD_REQUEST_MAGIC))
			err("Not enough magic.");
		if (len > BUFSIZE - sizeof(struct nbd_reply))
			err("Request too big!");
#ifdef DODBG
		printf("%s from %llu (%llu) len %d, ", request.type ? "WRITE" :
				"READ", (unsigned long long)request.from,
				(unsigned long long)request.from / 512, len);
#endif
		memcpy(reply.handle, request.handle, sizeof(reply.handle));
		if ((request.from + len) > (OFFT_MAX)) {
			DEBUG("[Number too large!]");
			ERROR(client, reply, EINVAL);
			continue;
		}

		if (((ssize_t)((off_t)request.from + len) > client->exportsize)) {
			DEBUG("[RANGE!]");
			ERROR(client, reply, EINVAL);
			continue;
		}

		if (request.type==NBD_CMD_WRITE) {
			DEBUG("wr: net->buf, ");
			readit(client->net, buf, len);
			DEBUG("buf->exp, ");
			if ((client->server->flags & F_READONLY) ||
			    (client->server->flags & F_AUTOREADONLY)) {
				DEBUG("[WRITE to READONLY!]");
				ERROR(client, reply, EPERM);
				continue;
			}
			if (expwrite(request.from, buf, len, client)) {
				DEBUG("Write failed: %m" );
				ERROR(client, reply, errno);
				continue;
			}
			SEND(client->net, reply);
			DEBUG("OK!\n");
			continue;
		}
		/* READ */

		DEBUG("exp->buf, ");
		if (expread(request.from, buf + sizeof(struct nbd_reply), len, client)) {
			DEBUG("Read failed: %m");
			ERROR(client, reply, errno);
			continue;
		}

		DEBUG("buf->net, ");
		memcpy(buf, &reply, sizeof(struct nbd_reply));
		writeit(client->net, buf, len + sizeof(struct nbd_reply));
		DEBUG("OK!\n");
	}
	return 0;
}

/**
 * Set up client export array, which is an array of FILE_INFO.
 * Also, split a single exportfile into multiple ones, if that was asked.
 * @param client information on the client which we want to setup export for
 **/
void setupexport(CLIENT* client) {
	int i;
	off_t laststartoff = 0, lastsize = 0;
	int multifile = (client->server->flags & F_MULTIFILE);

	client->export = g_array_new(TRUE, TRUE, sizeof(FILE_INFO));

	/* If multi-file, open as many files as we can.
	 * If not, open exactly one file.
	 * Calculate file sizes as we go to get total size. */
	for(i=0; ; i++) {
		FILE_INFO fi;
		gchar *tmpname;
		gchar* error_string;
		mode_t mode = (client->server->flags & F_READONLY) ? O_RDONLY : O_RDWR;

		if(multifile) {
			tmpname=g_strdup_printf("%s.%d", client->exportname, i);
		} else {
			tmpname=g_strdup(client->exportname);
		}
		DEBUG2( "Opening %s\n", tmpname );
		fi.fhandle = open(tmpname, mode);
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
		if(fi.fhandle == -1) {
			if(multifile && i>0)
				break;
			error_string=g_strdup_printf(
				"Could not open exported file %s: %%m",
				tmpname);
			err(error_string);
		}
		fi.startoff = laststartoff + lastsize;
		g_array_append_val(client->export, fi);
		g_free(tmpname);

		/* Starting offset and size of this file will be used to
		 * calculate starting offset of next file */
		laststartoff = fi.startoff;
		lastsize = size_autodetect(fi.fhandle);

		if(!multifile)
			break;
	}

	/* Set export size to total calculated size */
	client->exportsize = laststartoff + lastsize;

	/* Export size may be overridden */
	if(client->server->expected_size) {
		/* desired size must be <= total calculated size */
		if(client->server->expected_size > client->exportsize) {
			err("Size of exported file is too big\n");
		}

		client->exportsize = client->server->expected_size;
	}

	msg3(LOG_INFO, "Size of exported file/device is %llu", (unsigned long long)client->exportsize);
	if(multifile) {
		msg3(LOG_INFO, "Total number of files: %d", i);
	}
}

int copyonwrite_prepare(CLIENT* client) {
	off_t i;
	if ((client->difffilename = malloc(1024))==NULL)
		err("Failed to allocate string for diff file name");
	snprintf(client->difffilename, 1024, "%s-%s-%d.diff",client->exportname,client->clientname,
		(int)getpid()) ;
	client->difffilename[1023]='\0';
	msg3(LOG_INFO,"About to create map and diff file %s",client->difffilename) ;
	client->difffile=open(client->difffilename,O_RDWR | O_CREAT | O_TRUNC,0600) ;
	if (client->difffile<0) err("Could not create diff file (%m)") ;
	if ((client->difmap=calloc(client->exportsize/DIFFPAGESIZE,sizeof(u32)))==NULL)
		err("Could not allocate memory") ;
	for (i=0;i<client->exportsize/DIFFPAGESIZE;i++) client->difmap[i]=(u32)-1 ;

	return 0;
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

/**
 * Serve a connection. 
 *
 * @todo allow for multithreading, perhaps use libevent. Not just yet, though;
 * follow the road map.
 *
 * @param client a connected client
 **/
void serveconnection(CLIENT *client) {
	if(do_run(client->server->prerun, client->exportname)) {
		exit(EXIT_FAILURE);
	}
	setupexport(client);

	if (client->server->flags & F_COPYONWRITE) {
		copyonwrite_prepare(client);
	}

	setmysockopt(client->net);

	mainloop(client);
	do_run(client->server->postrun, client->exportname);
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
 **/
void set_peername(int net, CLIENT *client) {
	struct sockaddr_storage addrin;
	struct sockaddr_storage netaddr;
	struct sockaddr_in  *netaddr4 = NULL;
	struct sockaddr_in6 *netaddr6 = NULL;
	size_t addrinlen = sizeof( addrin );
	struct addrinfo hints;
	struct addrinfo *ai = NULL;
	char peername[NI_MAXHOST];
	char netname[NI_MAXHOST];
	char *tmp = NULL;
	int i;
	int e;
	int shift;

	if (getpeername(net, (struct sockaddr *) &addrin, (socklen_t *)&addrinlen) < 0)
		err("getsockname failed: %m");

	getnameinfo((struct sockaddr *)&addrin, (socklen_t)addrinlen,
		peername, sizeof (peername), NULL, 0, NI_NUMERICHOST);

	memset(&hints, '\0', sizeof (hints));
	hints.ai_flags = AI_ADDRCONFIG;
	e = getaddrinfo(peername, NULL, &hints, &ai);

	if(e != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(e));
		freeaddrinfo(ai);
		return;
	}

	switch(client->server->virtstyle) {
		case VIRT_NONE:
			client->exportname=g_strdup(client->server->exportname);
			break;
		case VIRT_IPHASH:
			for(i=0;i<strlen(peername);i++) {
				if(peername[i]=='.') {
					peername[i]='/';
				}
			}
		case VIRT_IPLIT:
			client->exportname=g_strdup_printf(client->server->exportname, peername);
			break;
		case VIRT_CIDR:
			memcpy(&netaddr, &addrin, addrinlen);
			if(ai->ai_family == AF_INET) {
				netaddr4 = (struct sockaddr_in *)&netaddr;
				(netaddr4->sin_addr).s_addr>>=32-(client->server->cidrlen);
				(netaddr4->sin_addr).s_addr<<=32-(client->server->cidrlen);

				getnameinfo((struct sockaddr *) netaddr4, (socklen_t) addrinlen,
							netname, sizeof (netname), NULL, 0, NI_NUMERICHOST);
				tmp=g_strdup_printf("%s/%s", netname, peername);
			}else if(ai->ai_family == AF_INET6) {
				netaddr6 = (struct sockaddr_in6 *)&netaddr;

				shift = 128-(client->server->cidrlen);
				i = 3;
				while(shift >= 32) {
					((netaddr6->sin6_addr).s6_addr32[i])=0;
					shift-=32;
					i--;
				}
				(netaddr6->sin6_addr).s6_addr32[i]>>=shift;
				(netaddr6->sin6_addr).s6_addr32[i]<<=shift;

				getnameinfo((struct sockaddr *)netaddr6, (socklen_t)addrinlen,
					    netname, sizeof(netname), NULL, 0, NI_NUMERICHOST);
				tmp=g_strdup_printf("%s/%s", netname, peername);
			}

			if(tmp != NULL)
			  client->exportname=g_strdup_printf(client->server->exportname, tmp);

			break;
	}

	freeaddrinfo(ai);
	msg4(LOG_INFO, "connect from %s, assigned file is %s", 
	     peername, client->exportname);
	client->clientname=g_strdup(peername);
}

/**
 * Destroy a pid_t*
 * @param data a pointer to pid_t which should be freed
 **/
void destroy_pid_t(gpointer data) {
	g_free(data);
}

/**
 * Loop through the available servers, and serve them. Never returns.
 **/
int serveloop(GArray* servers) {
	struct sockaddr_storage addrin;
	socklen_t addrinlen=sizeof(addrin);
	int i;
	int max;
	int sock;
	fd_set mset;
	fd_set rset;

	/* 
	 * Set up the master fd_set. The set of descriptors we need
	 * to select() for never changes anyway and it buys us a *lot*
	 * of time to only build this once. However, if we ever choose
	 * to not fork() for clients anymore, we may have to revisit
	 * this.
	 */
	max=0;
	FD_ZERO(&mset);
	for(i=0;i<servers->len;i++) {
		if((sock=(g_array_index(servers, SERVER, i)).socket)) {
			FD_SET(sock, &mset);
			max=sock>max?sock:max;
		}
	}
	if(modernsock) {
		FD_SET(modernsock, &mset);
		max=modernsock>max?modernsock:max;
	}
	for(;;) {
		CLIENT *client = NULL;
		pid_t *pid;

		memcpy(&rset, &mset, sizeof(fd_set));
		if(select(max+1, &rset, NULL, NULL, NULL)>0) {
			int net = 0;
			SERVER* serve;

			DEBUG("accept, ");
			if(FD_ISSET(modernsock, &rset)) {
				if((net=accept(modernsock, (struct sockaddr *) &addrin, &addrinlen)) < 0)
					err("accept: %m");
				client = negotiate(net, NULL, servers);
				if(!client) {
					err_nonfatal("negotiation failed");
					close(net);
					net=0;
				}
			}
			for(i=0;i<servers->len && !net;i++) {
				serve=&(g_array_index(servers, SERVER, i));
				if(FD_ISSET(serve->socket, &rset)) {
					if ((net=accept(serve->socket, (struct sockaddr *) &addrin, &addrinlen)) < 0)
						err("accept: %m");
				}
			}
			if(net) {
				int sock_flags;

				if(serve->max_connections > 0 &&
				   g_hash_table_size(children) >= serve->max_connections) {
					msg2(LOG_INFO, "Max connections reached");
					close(net);
					continue;
				}
				if((sock_flags = fcntl(net, F_GETFL, 0))==-1) {
					err("fcntl F_GETFL");
				}
				if(fcntl(net, F_SETFL, sock_flags &~O_NONBLOCK)==-1) {
					err("fcntl F_SETFL ~O_NONBLOCK");
				}
				if(!client) {
					client = g_new0(CLIENT, 1);
					client->server=serve;
					client->exportsize=OFFT_MAX;
					client->net=net;
				}
				set_peername(net, client);
				if (!authorized_client(client)) {
					msg2(LOG_INFO,"Unauthorized client") ;
					close(net);
					continue;
				}
				msg2(LOG_INFO,"Authorized client") ;
				pid=g_malloc(sizeof(pid_t));
#ifndef NOFORK
				if ((*pid=fork())<0) {
					msg3(LOG_INFO,"Could not fork (%s)",strerror(errno)) ;
					close(net);
					continue;
				}
				if (*pid>0) { /* parent */
					close(net);
					g_hash_table_insert(children, pid, pid);
					continue;
				}
				/* child */
				g_hash_table_destroy(children);
				for(i=0;i<servers->len;i++) {
					serve=&g_array_index(servers, SERVER, i);
					close(serve->socket);
				}
				/* FALSE does not free the
				actual data. This is required,
				because the client has a
				direct reference into that
				data, and otherwise we get a
				segfault... */
				g_array_free(servers, FALSE);
#endif // NOFORK
				msg2(LOG_INFO,"Starting to serve");
				serveconnection(client);
				exit(EXIT_SUCCESS);
			}
		}
	}
}

void dosockopts(int socket) {
#ifndef sun
	int yes=1;
#else
	char yes='1';
#endif /* sun */
	int sock_flags;

	/* lose the pesky "Address already in use" error message */
	if (setsockopt(socket,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) {
	        err("setsockopt SO_REUSEADDR");
	}
	if (setsockopt(socket,SOL_SOCKET,SO_KEEPALIVE,&yes,sizeof(int)) == -1) {
		err("setsockopt SO_KEEPALIVE");
	}

	/* make the listening socket non-blocking */
	if ((sock_flags = fcntl(socket, F_GETFL, 0)) == -1) {
		err("fcntl F_GETFL");
	}
	if (fcntl(socket, F_SETFL, sock_flags | O_NONBLOCK) == -1) {
		err("fcntl F_SETFL O_NONBLOCK");
	}
}

/**
 * Connect a server's socket.
 *
 * @param serve the server we want to connect.
 **/
int setup_serve(SERVER *serve) {
	struct addrinfo hints;
	struct addrinfo *ai = NULL;
	gchar *port = NULL;
	int e;

	if(!do_oldstyle) {
		return serve->servename ? 1 : 0;
	}
	memset(&hints,'\0',sizeof(hints));
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = serve->socket_family;

	port = g_strdup_printf ("%d", serve->port);
	if (port == NULL)
		return 0;

	e = getaddrinfo(serve->listenaddr,port,&hints,&ai);

	g_free(port);

	if(e != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(e));
		serve->socket = -1;
		freeaddrinfo(ai);
		exit(EXIT_FAILURE);
	}

	if(serve->socket_family == AF_UNSPEC)
		serve->socket_family = ai->ai_family;

#ifdef WITH_SDP
	if ((serve->flags) && F_SDP) {
		if (ai->ai_family == AF_INET)
			ai->ai_family = AF_INET_SDP;
		else (ai->ai_family == AF_INET6)
			ai->ai_family = AF_INET6_SDP;
	}
#endif
	if ((serve->socket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0)
		err("socket: %m");

	dosockopts(serve->socket);

	DEBUG("Waiting for connections... bind, ");
	e = bind(serve->socket, ai->ai_addr, ai->ai_addrlen);
	if (e != 0 && errno != EADDRINUSE)
		err("bind: %m");
	DEBUG("listen, ");
	if (listen(serve->socket, 1) < 0)
		err("listen: %m");

	freeaddrinfo (ai);
	if(serve->servename) {
		return 1;
	} else {
		return 0;
	}
}

void open_modern(void) {
	struct addrinfo hints;
	struct addrinfo* ai = NULL;
	struct sock_flags;
	int e;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	e = getaddrinfo(modern_listen, NBD_DEFAULT_PORT, &hints, &ai);
	if(e != 0) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(e));
		exit(EXIT_FAILURE);
	}
	if((modernsock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol))<0) {
		err("socket: %m");
	}

	dosockopts(modernsock);

	if(bind(modernsock, ai->ai_addr, ai->ai_addrlen)) {
		err("bind: %m");
	}
	if(listen(modernsock, 10) <0) {
		err("listen: %m");
	}

	freeaddrinfo(ai);
}

/**
 * Connect our servers.
 **/
void setup_servers(GArray* servers) {
	int i;
	struct sigaction sa;
	int want_modern=0;

	for(i=0;i<servers->len;i++) {
		want_modern |= setup_serve(&(g_array_index(servers, SERVER, i)));
	}
	if(want_modern) {
		open_modern();
	}
	children=g_hash_table_new_full(g_int_hash, g_int_equal, NULL, destroy_pid_t);

	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if(sigaction(SIGCHLD, &sa, NULL) == -1)
		err("sigaction: %m");
	sa.sa_handler = sigterm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if(sigaction(SIGTERM, &sa, NULL) == -1)
		err("sigaction: %m");
}

/**
 * Go daemon (unless we specified at compile time that we didn't want this)
 * @param serve the first server of our configuration. If its port is zero,
 * 	then do not daemonize, because we're doing inetd then. This parameter
 * 	is only used to create a PID file of the form
 * 	/var/run/nbd-server.&lt;port&gt;.pid; it's not modified in any way.
 **/
#if !defined(NODAEMON) && !defined(NOFORK)
void daemonize(SERVER* serve) {
	FILE*pidf;

	if(serve && !(serve->port)) {
		return;
	}
	if(daemon(0,0)<0) {
		err("daemon");
	}
	if(!*pidftemplate) {
		if(serve) {
			strncpy(pidftemplate, "/var/run/nbd-server.%d.pid", 255);
		} else {
			strncpy(pidftemplate, "/var/run/nbd-server.pid", 255);
		}
	}
	snprintf(pidfname, 255, pidftemplate, serve ? serve->port : 0);
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
#endif /* !defined(NODAEMON) && !defined(NOFORK) */

/*
 * Everything beyond this point (in the file) is run in non-daemon mode.
 * The stuff above daemonize() isn't.
 */

void serve_err(SERVER* serve, const char* msg) G_GNUC_NORETURN;

void serve_err(SERVER* serve, const char* msg) {
	g_message("Export of %s on port %d failed:", serve->exportname,
			serve->port);
	err(msg);
}

/**
 * Set up user-ID and/or group-ID
 **/
void dousers(void) {
	struct passwd *pw;
	struct group *gr;
	gchar* str;
	if(rungroup) {
		gr=getgrnam(rungroup);
		if(!gr) {
			str = g_strdup_printf("Invalid group name: %s", rungroup);
			err(str);
		}
		if(setgid(gr->gr_gid)<0) {
			err("Could not set GID: %m"); 
		}
	}
	if(runuser) {
		pw=getpwnam(runuser);
		if(!pw) {
			str = g_strdup_printf("Invalid user name: %s", runuser);
			err(str);
		}
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
	GError *err=NULL;

	if (sizeof( struct nbd_request )!=28) {
		fprintf(stderr,"Bad size of structure. Alignment problems?\n");
		exit(EXIT_FAILURE) ;
	}

	memset(pidftemplate, '\0', 256);

	logging();
	config_file_pos = g_strdup(CFILE);
	serve=cmdline(argc, argv);
	servers = parse_cfile(config_file_pos, &err);
	
	if(serve) {
		serve->socket_family = AF_UNSPEC;

		append_serve(serve, servers);
     
		if (!(serve->port)) {
			CLIENT *client;
#ifndef ISSERVER
			/* You really should define ISSERVER if you're going to use
			 * inetd mode, but if you don't, closing stdout and stderr
			 * (which inetd had connected to the client socket) will let it
			 * work. */
			close(1);
			close(2);
			open("/dev/null", O_WRONLY);
			open("/dev/null", O_WRONLY);
			g_log_set_default_handler( glib_message_syslog_redirect, NULL );
#endif
			client=g_malloc(sizeof(CLIENT));
			client->server=serve;
			client->net=0;
			client->exportsize=OFFT_MAX;
			set_peername(0,client);
			serveconnection(client);
			return 0;
		}
	}
    
	if(!servers || !servers->len) {
		if(err && !(err->domain == g_quark_from_string("parse_cfile")
				&& err->code == CFILE_NOTFOUND)) {
			g_warning("Could not parse config file: %s", 
					err ? err->message : "Unknown error");
		}
	}
	if(serve) {
		g_warning("Specifying an export on the command line is deprecated.");
		g_warning("Please use a configuration file instead.");
	}

	if((!serve) && (!servers||!servers->len)) {
		g_message("No configured exports; quitting.");
		exit(EXIT_FAILURE);
	}
	daemonize(serve);
	setup_servers(servers);
	dousers();
	serveloop(servers);
	return 0 ;
}
