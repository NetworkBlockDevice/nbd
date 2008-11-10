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
#include <netinet/tcp.h>
#include <netinet/in.h>		/* sockaddr_in, htons, in_addr */
#include <netdb.h>		/* hostent, gethostby*, getservby* */
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
#define BUFSIZE (1024*1024) /**< Size of buffer that can hold requests */
#define DIFFPAGESIZE 4096 /**< diff file uses those chunks */
#define F_READONLY 1      /**< flag to tell us a file is readonly */
#define F_MULTIFILE 2	  /**< flag to tell us a file is exported using -m */
#define F_COPYONWRITE 4	  /**< flag to tell us a file is exported using
			    copyonwrite */
#define F_AUTOREADONLY 8  /**< flag to tell us a file is set to autoreadonly */
#define F_SPARSE 16
GHashTable *children;
char pidfname[256]; /**< name of our PID file */
char pidftemplate[256]; /**< template to be used for the filename of the PID file */
char default_authname[] = SYSCONFDIR "/nbd-server/allow"; /**< default name of allow file */

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
	unsigned int port;   /**< port we're exporting this file at */
	char* authname;      /**< filename of the authorization file */
	int flags;           /**< flags associated with this exported file */
	unsigned int timeout;/**< how long a connection may be idle
			       (0=forever) */
	int socket;	     /**< The socket of this server. */
	VIRT_STYLE virtstyle;/**< The style of virtualization, if any */
	uint8_t cidrlen;     /**< The length of the mask when we use
				  CIDR-style virtualization */
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
			if(inet_aton(line,&addr)) {
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
		if ((res = read(f, buf, len)) <= 0)
			err("Read failed: %m");
		len -= res;
		buf += res;
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
	printf("Usage: port file_to_export [size][kKmM] [-l authorize_file] [-r] [-m] [-c] [-a timeout_sec] [-C configuration file] [-p PID file name]\n"
	       "\t-r|--read-only\t\tread only\n"
	       "\t-m|--multi-file\t\tmultiple file\n"
	       "\t-c|--copy-on-write\tcopy on write\n"
	       "\t-C|--config-file\tspecify an alternate configuration file\n"
	       "\t-l|--authorize-file\tfile with list of hosts that are allowed to\n\t\t\t\tconnect.\n"
	       "\t-a|--idle-time\t\tmaximum idle seconds; server terminates when\n\t\t\t\tidle time exceeded\n"
	       "\t-p|--pid-file\t\tspecify a filename to write our PID to\n\n"
	       "\tif port is set to 0, stdin is used (for running from inetd)\n"
	       "\tif file_to_export contains '%%s', it is substituted with the IP\n"
	       "\t\taddress of the machine trying to connect\n" );
	printf("Using configuration file %s\n", CFILE);
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
		{"idle-time", required_argument, NULL, 'a'},
		{"config-file", required_argument, NULL, 'C'},
		{"pid-file", required_argument, NULL, 'p'},
		{0,0,0,0}
	};
	SERVER *serve;
	off_t es;
	size_t last;
	char suffix;

	if(argc==1) {
		return NULL;
	}
	serve=g_new0(SERVER, 1);
	serve->authname = g_strdup(default_authname);
	while((c=getopt_long(argc, argv, "-a:C:cl:mrp:", long_options, &i))>=0) {
		switch (c) {
		case 1:
			/* non-option argument */
			switch(nonspecial++) {
			case 0:
				serve->port=strtol(optarg, NULL, 0);
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
				es = (off_t)atol(optarg);
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
		case 'a': 
			serve->timeout=strtol(optarg, NULL, 0);
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
	CFILE_PROGERR		/**< Programmer error */
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
	g_free(server);
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
		{ "timeout",	FALSE,	PARAM_INT,	NULL, 0 },
		{ "filesize",	FALSE,	PARAM_INT,	NULL, 0 },
		{ "virtstyle",	FALSE,	PARAM_STRING,	NULL, 0 },
		{ "readonly",	FALSE,	PARAM_BOOL,	NULL, F_READONLY },
		{ "multifile",	FALSE,	PARAM_BOOL,	NULL, F_MULTIFILE },
		{ "copyonwrite", FALSE,	PARAM_BOOL,	NULL, F_COPYONWRITE },
		{ "autoreadonly", FALSE, PARAM_BOOL,	NULL, F_AUTOREADONLY },
		{ "sparse_cow",	FALSE,	PARAM_BOOL,	NULL, F_SPARSE },
	};
	const int lp_size=11;
	PARAM gp[] = {
		{ "user",	FALSE, PARAM_STRING,	&runuser,	0 },
		{ "group",	FALSE, PARAM_STRING,	&rungroup,	0 },
	};
	PARAM* p=gp;
	int p_size=2;
	GKeyFile *cfile;
	GError *err = NULL;
	const char *err_msg=NULL;
	GQuark errdomain;
	GArray *retval=NULL;
	gchar **groups;
	gboolean value;
	gint i;
	gint j;

	errdomain = g_quark_from_string("parse_cfile");
	cfile = g_key_file_new();
	retval = g_array_new(FALSE, TRUE, sizeof(SERVER));
	if(!g_key_file_load_from_file(cfile, f, G_KEY_FILE_KEEP_COMMENTS |
			G_KEY_FILE_KEEP_TRANSLATIONS, &err)) {
		g_set_error(e, errdomain, CFILE_NOTFOUND, "Could not open config file.");
		g_key_file_free(cfile);
		return retval;
	}
	if(strcmp(g_key_file_get_start_group(cfile), "generic")) {
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
		lp[3].target=&(s.timeout);
		lp[4].target=&(s.expected_size);
		lp[5].target=&(virtstyle);
		lp[6].target=lp[7].target=lp[8].target=
				lp[9].target=lp[10].target=&(s.flags);
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
		} else {
			s.virtstyle=VIRT_IPLIT;
		}
		/* Don't need to free this, it's not our string */
		virtstyle=NULL;
		/* Don't append values for the [generic] group */
		if(i>0) {
			g_array_append_val(retval, s);
		}
	}
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

	exit(0);
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
	unsigned long sectors;
	struct stat stat_buf;
	int error;

#ifdef HAVE_SYS_MOUNT_H
#ifdef HAVE_SYS_IOCTL_H
#ifdef BLKGETSIZE
	DEBUG("looking for export size with ioctl BLKGETSIZE\n");
	if (!ioctl(fhandle, BLKGETSIZE, &sectors) && sectors) {
		es = (off_t)sectors * (off_t)512;
		return es;
	}
#endif /* BLKGETSIZE */
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

	if(get_filepos(client->export, a, &fhandle, &foffset, &maxbytes))
		return -1;
	if(maxbytes && len > maxbytes)
		len = maxbytes;

	DEBUG4("(WRITE to fd %d offset %Lu len %u), ", fhandle, foffset, len);

	myseek(fhandle, foffset);
	return write(fhandle, buf, len);
}

/**
 * Call rawexpwrite repeatedly until all data has been written.
 * @return 0 on success, nonzero on failure
 **/
int rawexpwrite_fully(off_t a, char *buf, size_t len, CLIENT *client) {
	ssize_t ret;

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

	DEBUG4("(READ from fd %d offset %Lu len %u), ", fhandle, foffset, len);

	myseek(fhandle, foffset);
	return read(fhandle, buf, len);
}

/**
 * Call rawexpread repeatedly until all data has been read.
 * @return 0 on success, nonzero on failure
 **/
int rawexpread_fully(off_t a, char *buf, size_t len, CLIENT *client) {
	ssize_t ret;

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
	DEBUG3("Asked to read %d bytes at %Lu.\n", len, (unsigned long long)a);

	mapl=a/DIFFPAGESIZE; maph=(a+len-1)/DIFFPAGESIZE;

	for (mapcnt=mapl;mapcnt<=maph;mapcnt++) {
		pagestart=mapcnt*DIFFPAGESIZE;
		offset=a-pagestart;
		rdlen=(0<DIFFPAGESIZE-offset && len<(size_t)(DIFFPAGESIZE-offset)) ?
			len : (size_t)DIFFPAGESIZE-offset;
		if (client->difmap[mapcnt]!=(u32)(-1)) { /* the block is already there */
			DEBUG3("Page %Lu is at %lu\n", (unsigned long long)mapcnt,
			       (unsigned long)(client->difmap[mapcnt]));
			myseek(client->difffile, client->difmap[mapcnt]*DIFFPAGESIZE+offset);
			if (read(client->difffile, buf, rdlen) != rdlen) return -1;
		} else { /* the block is not there */
			DEBUG2("Page %Lu is not here, we read the original one\n",
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
	DEBUG3("Asked to write %d bytes at %Lu.\n", len, (unsigned long long)a);

	mapl=a/DIFFPAGESIZE ; maph=(a+len-1)/DIFFPAGESIZE ;

	for (mapcnt=mapl;mapcnt<=maph;mapcnt++) {
		pagestart=mapcnt*DIFFPAGESIZE ;
		offset=a-pagestart ;
		wrlen=(0<DIFFPAGESIZE-offset && len<(size_t)(DIFFPAGESIZE-offset)) ?
			len : (size_t)DIFFPAGESIZE-offset;

		if (client->difmap[mapcnt]!=(u32)(-1)) { /* the block is already there */
			DEBUG3("Page %Lu is at %lu\n", (unsigned long long)mapcnt,
			       (unsigned long)(client->difmap[mapcnt])) ;
			myseek(client->difffile,
					client->difmap[mapcnt]*DIFFPAGESIZE+offset);
			if (write(client->difffile, buf, wrlen) != wrlen) return -1 ;
		} else { /* the block is not there */
			myseek(client->difffile,client->difffilelen*DIFFPAGESIZE) ;
			client->difmap[mapcnt]=(client->server->flags&F_SPARSE)?mapcnt:client->difffilelen++;
			DEBUG3("Page %Lu is not here, we put it at %lu\n",
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
void negotiate(CLIENT *client) {
	char zeros[300];
	u64 size_host;

	memset(zeros, '\0', 290);
	if (write(client->net, INIT_PASSWD, 8) < 0)
		err("Negotiation failed: %m");
	cliserv_magic = htonll(cliserv_magic);
	if (write(client->net, &cliserv_magic, sizeof(cliserv_magic)) < 0)
		err("Negotiation failed: %m");
	size_host = htonll((u64)(client->exportsize));
	if (write(client->net, &size_host, 8) < 0)
		err("Negotiation failed: %m");
	if (write(client->net, zeros, 128) < 0)
		err("Negotiation failed: %m");
}

/** sending macro. */
#define SEND(net,reply) writeit( net, &reply, sizeof( reply ));
/** error macro. */
#define ERROR(client,reply) { reply.error = htonl(-1); SEND(client->net,reply); reply.error = 0; }
/**
 * Serve a file to a single client.
 *
 * @todo This beast needs to be split up in many tiny little manageable
 * pieces. Preferably with a chainsaw.
 *
 * @param client The client we're going to serve to.
 * @return never
 **/
int mainloop(CLIENT *client) {
	struct nbd_request request;
	struct nbd_reply reply;
	gboolean go_on=TRUE;
#ifdef DODBG
	int i = 0;
#endif
	negotiate(client);
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
		if (client->server->timeout) 
			alarm(client->server->timeout);
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
		if (len > BUFSIZE + sizeof(struct nbd_reply))
			err("Request too big!");
#ifdef DODBG
		printf("%s from %Lu (%Lu) len %d, ", request.type ? "WRITE" :
				"READ", (unsigned long long)request.from,
				(unsigned long long)request.from / 512, len);
#endif
		memcpy(reply.handle, request.handle, sizeof(reply.handle));
		if ((request.from + len) > (OFFT_MAX)) {
			DEBUG("[Number too large!]");
			ERROR(client, reply);
			continue;
		}

		if (((ssize_t)((off_t)request.from + len) > client->exportsize)) {
			DEBUG("[RANGE!]");
			ERROR(client, reply);
			continue;
		}

		if (request.type==NBD_CMD_WRITE) {
			DEBUG("wr: net->buf, ");
			readit(client->net, buf, len);
			DEBUG("buf->exp, ");
			if ((client->server->flags & F_READONLY) ||
			    (client->server->flags & F_AUTOREADONLY)) {
				DEBUG("[WRITE to READONLY!]");
				ERROR(client, reply);
				continue;
			}
			if (expwrite(request.from, buf, len, client)) {
				DEBUG("Write failed: %m" );
				ERROR(client, reply);
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
			ERROR(client, reply);
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
				client->server->flags |= F_AUTOREADONLY;
				client->server->flags |= F_READONLY;
			}
		}
		if(fi.fhandle == -1) {
			if(multifile && i>0)
				break;
			err("Could not open exported file: %m");
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

	msg3(LOG_INFO, "Size of exported file/device is %Lu", (unsigned long long)client->exportsize);
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
 * Serve a connection. 
 *
 * @todo allow for multithreading, perhaps use libevent. Not just yet, though;
 * follow the road map.
 *
 * @param client a connected client
 **/
void serveconnection(CLIENT *client) {
	setupexport(client);

	if (client->server->flags & F_COPYONWRITE) {
		copyonwrite_prepare(client);
	}

	setmysockopt(client->net);

	mainloop(client);
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
	struct sockaddr_in addrin;
	struct sockaddr_in netaddr;
	size_t addrinlen = sizeof( addrin );
	char *peername;
	char *netname;
	char *tmp;
	int i;

	if (getpeername(net, (struct sockaddr *) &addrin, (socklen_t *)&addrinlen) < 0)
		err("getsockname failed: %m");
	peername = g_strdup(inet_ntoa(addrin.sin_addr));
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
			netaddr.sin_addr.s_addr>>=32-(client->server->cidrlen);
			netaddr.sin_addr.s_addr<<=32-(client->server->cidrlen);
			netname = inet_ntoa(netaddr.sin_addr);
			tmp=g_strdup_printf("%s/%s", netname, peername);
			client->exportname=g_strdup_printf(client->server->exportname, tmp);
			break;
	}

	g_free(peername);
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
 * Go daemon (unless we specified at compile time that we didn't want this)
 * @param serve the first server of our configuration. If its port is zero,
 * 	then do not daemonize, because we're doing inetd then. This parameter
 * 	is only used to create a PID file of the form
 * 	/var/run/nbd-server.&lt;port&gt;.pid; it's not modified in any way.
 **/
#if !defined(NODAEMON) && !defined(NOFORK)
void daemonize(SERVER* serve) {
	FILE*pidf;

	if(daemon(0,0)<0) {
		err("daemon");
	}
	if(!*pidftemplate) {
		if(serve) {
			strncpy(pidftemplate, "/var/run/server.%d.pid", 255);
		} else {
			strncpy(pidftemplate, "/var/run/server.pid", 255);
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

/**
 * Connect a server's socket.
 *
 * @param serve the server we want to connect.
 **/
void setup_serve(SERVER *serve) {
	struct sockaddr_in addrin;
	struct sigaction sa;
	int addrinlen = sizeof(addrin);
	int sock_flags;
#ifndef sun
	int yes=1;
#else
	char yes='1';
#endif /* sun */
	if ((serve->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		err("socket: %m");

	/* lose the pesky "Address already in use" error message */
	if (setsockopt(serve->socket,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) {
	        err("setsockopt SO_REUSEADDR");
	}
	if (setsockopt(serve->socket,SOL_SOCKET,SO_KEEPALIVE,&yes,sizeof(int)) == -1) {
		err("setsockopt SO_KEEPALIVE");
	}

	/* make the listening socket non-blocking */
	if ((sock_flags = fcntl(serve->socket, F_GETFL, 0)) == -1) {
		err("fcntl F_GETFL");
	}
	if (fcntl(serve->socket, F_SETFL, sock_flags | O_NONBLOCK) == -1) {
		err("fcntl F_SETFL O_NONBLOCK");
	}

	DEBUG("Waiting for connections... bind, ");
	addrin.sin_family = AF_INET;
	addrin.sin_port = htons(serve->port);
	addrin.sin_addr.s_addr = 0;
	if (bind(serve->socket, (struct sockaddr *) &addrin, addrinlen) < 0)
		err("bind: %m");
	DEBUG("listen, ");
	if (listen(serve->socket, 1) < 0)
		err("listen: %m");
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
 * Connect our servers.
 **/
void setup_servers(GArray* servers) {
	int i;

	for(i=0;i<servers->len;i++) {
		setup_serve(&(g_array_index(servers, SERVER, i)));
	}
	children=g_hash_table_new_full(g_int_hash, g_int_equal, NULL, destroy_pid_t);
}

/**
 * Loop through the available servers, and serve them.
 **/
int serveloop(GArray* servers) {
	struct sockaddr_in addrin;
	socklen_t addrinlen=sizeof(addrin);
	SERVER *serve;
	int i;
	int max;
	int sock;
	fd_set mset;
	fd_set rset;
	struct timeval tv;

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
		sock=(g_array_index(servers, SERVER, i)).socket;
		FD_SET(sock, &mset);
		max=sock>max?sock:max;
	}
	for(;;) {
		CLIENT *client;
		int net;
		pid_t *pid;

		memcpy(&rset, &mset, sizeof(fd_set));
		tv.tv_sec=0;
		tv.tv_usec=500;
		if(select(max+1, &rset, NULL, NULL, &tv)>0) {
			DEBUG("accept, ");
			for(i=0;i<servers->len;i++) {
				serve=&(g_array_index(servers, SERVER, i));
				if(FD_ISSET(serve->socket, &rset)) {
					if ((net=accept(serve->socket, (struct sockaddr *) &addrin, &addrinlen)) < 0)
						err("accept: %m");

					client = g_malloc(sizeof(CLIENT));
					client->server=serve;
					client->exportsize=OFFT_MAX;
					client->net=net;
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
					for(i=0;i<servers->len,serve=(g_array_index(servers, SERVER*, i));i++) {
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
				}
			}
		}
	}
}

/**
 * Set up user-ID and/or group-ID
 **/
void dousers(void) {
	struct passwd *pw;
	struct group *gr;
	if(runuser) {
		pw=getpwnam(runuser);
		if(setuid(pw->pw_uid)<0)
			msg3(LOG_DEBUG, "Could not set UID: %s", strerror(errno));
	}
	if(rungroup) {
		gr=getgrnam(rungroup);
		if(setgid(gr->gr_gid)<0)
			msg3(LOG_DEBUG, "Could not set GID: %s", strerror(errno));
	}
}

/**
 * Main entry point...
 **/
int main(int argc, char *argv[]) {
	SERVER *serve;
	GArray *servers;
	GError *err=NULL;

	if (sizeof( struct nbd_request )!=28) {
		fprintf(stderr,"Bad size of structure. Alignment problems?\n");
		exit(-1) ;
	}

	memset(pidftemplate, '\0', 256);

	logging();
	config_file_pos = g_strdup(CFILE);
	serve=cmdline(argc, argv);
	servers = parse_cfile(config_file_pos, &err);
	if(!servers || !servers->len) {
		g_warning("Could not parse config file: %s", err->message);
	}
	if(serve) {
		g_array_append_val(servers, *serve);
	}

/* We don't support this at this time */
#if 0
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
#endif
		client=g_malloc(sizeof(CLIENT));
		client->server=serve;
		client->net=0;
		client->exportsize=OFFT_MAX;
          	set_peername(0,client);
          	serveconnection(client);
          	return 0;
        }
#endif
	if((!serve) && (!servers||!servers->len)) {
		g_message("Nothing to do! Bye!");
		exit(EXIT_FAILURE);
	}
	daemonize(serve);
	setup_servers(servers);
	dousers();
	serveloop(servers);
	return 0 ;
}
