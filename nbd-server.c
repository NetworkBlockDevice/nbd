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
#include <sys/param.h>
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
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
#include <arpa/inet.h>
#include <strings.h>
#include <dirent.h>
#include <unistd.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <ctype.h>

#include <glib.h>

/* used in cliserv.h, so must come first */
#define MY_NAME "nbd_server"
#include "cliserv.h"
#include "nbd-debug.h"
#include "netdb-compat.h"

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

/** global flags */
int glob_flags=0;

/* Whether we should avoid forking */
int dontfork = 0;

/**
 * The highest value a variable of type off_t can reach. This is a signed
 * integer, so set all bits except for the leftmost one.
 **/
#define OFFT_MAX ~((off_t)1<<(sizeof(off_t)*8-1))
#define BUFSIZE ((1024*1024)+sizeof(struct nbd_reply)) /**< Size of buffer that can hold requests */
#define DIFFPAGESIZE 4096 /**< diff file uses those chunks */
#define TREEPAGESIZE 4096 /**< tree (block) files uses those chunks */
#define TREEDIRSIZE  1024 /**< number of files per subdirectory (or subdirs per subdirectory) */

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
#define F_TREEFILES 8192	  /**< flag to tell us a file is exported using -t */

/** Global flags: */
#define F_OLDSTYLE 1	  /**< Allow oldstyle (port-based) exports */
#define F_LIST 2	  /**< Allow clients to list the exports on a server */
#define F_NO_ZEROES 4	  /**< Do not send zeros to client */
GHashTable *children;
char pidfname[256]; /**< name of our PID file */
char pidftemplate[256]; /**< template to be used for the filename of the PID file */
char default_authname[] = SYSCONFDIR "/nbd-server/allow"; /**< default name of allow file */

#define NEG_INIT	(1 << 0)
#define NEG_OLD		(1 << 1)
#define NEG_MODERN	(1 << 2)

#include <nbdsrv.h>

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

bool logged_oversized=false;  /**< whether we logged oversized requests already */

/**
 * Variables associated with an open file
 **/
typedef struct {
	int fhandle;      /**< file descriptor */
	off_t startoff;   /**< starting offset of this file */
} FILE_INFO;

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
        gint flags;             /**< global flags                 */
};

/**
 * Translate a command name into human readable form
 *
 * @param command The command number (after applying NBD_CMD_MASK_COMMAND)
 * @return pointer to the command name
 **/
static inline const char * getcommandname(uint64_t command) {
	switch (command) {
	case NBD_CMD_READ:
		return "NBD_CMD_READ";
	case NBD_CMD_WRITE:
		return "NBD_CMD_WRITE";
	case NBD_CMD_DISC:
		return "NBD_CMD_DISC";
	case NBD_CMD_FLUSH:
		return "NBD_CMD_FLUSH";
	case NBD_CMD_TRIM:
		return "NBD_CMD_TRIM";
	default:
		return "UNKNOWN";
	}
}

/**
 * Read data from a file descriptor into a buffer
 *
 * @param f a file descriptor
 * @param buf a buffer
 * @param len the number of bytes to be read
 **/
static inline void readit(int f, void *buf, size_t len) {
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
 * Consume data from an FD that we don't want
 *
 * @param f a file descriptor
 * @param buf a buffer
 * @param len the number of bytes to consume
 * @param bufsiz the size of the buffer
 **/
static inline void consume(int f, void * buf, size_t len, size_t bufsiz) {
	size_t curlen;
	while (len>0) {
		curlen = (len>bufsiz)?bufsiz:len;
		readit(f, buf, curlen);
		len -= curlen;
	}
}

/**
 * Write data from a buffer into a filedescriptor
 *
 * @param f a file descriptor
 * @param buf a buffer containing data
 * @param len the number of bytes to be written
 **/
static inline void writeit(int f, void *buf, size_t len) {
	ssize_t res;
	while (len > 0) {
		DEBUG("+");
		if ((res = write(f, buf, len)) <= 0)
			err("Send failed: %m");
		len -= res;
		buf += res;
	}
}

void myseek(int handle,off_t a);

/**
 * Tree structure helper functions
 */

static void construct_path(char* name,int lenmax,off_t size, off_t pos, off_t * ppos) {
	if (lenmax<10)
		err("Char buffer overflow. This is likely a bug.");

	if (size<TREEDIRSIZE*TREEPAGESIZE) {
		// we are done, add filename
		snprintf(name,lenmax,"/FILE%04X",(pos/TREEPAGESIZE) % TREEDIRSIZE);
		*ppos = pos / (TREEPAGESIZE*TREEDIRSIZE);
	} else {
		construct_path(name+9,lenmax-9,size/TREEDIRSIZE,pos,ppos);
		char buffer[10];
		snprintf(buffer,sizeof(buffer),"/TREE%04X",*ppos % TREEDIRSIZE);
		memcpy(name,buffer,9); // copy into string without trailing zero
		*ppos/=TREEDIRSIZE;
	}
}

static void mkdir_path(char * path) {
	char *subpath=path+1;
	while (subpath=strchr(subpath,'/')) {
		*subpath='\0'; // path is modified in place with terminating null char instead of slash
		if (mkdir(path,0700)==-1) {
			if (errno!=EEXIST)
				err("Path access error! %m");
		}
		*subpath='/';
		subpath++;
	}
}

static int open_treefile(char* name,mode_t mode,off_t size,off_t pos) {
	char filename[256+strlen(name)];
	strcpy(filename,name);
	off_t ppos;
	construct_path(filename+strlen(name),256,size,pos,&ppos);

	DEBUG("Accessing treefile %s ( offset %llu of %llu)",filename,(unsigned long long)pos,(unsigned long long)size);

	int handle=open(filename, mode, 0600);
	if (handle<0 && errno==ENOENT) {
		if (mode & O_RDWR) {

			DEBUG("Creating new treepath");

			mkdir_path(filename);
			handle=open(filename, O_RDWR|O_CREAT, 0600);
			if (handle<0) {
				err("Error opening tree block file %m");
			}
		} else {

			DEBUG("Creating a dummy tempfile for reading");
			gchar * tmpname;
			tmpname = g_strdup_printf("dummy-XXXXXX");
			handle = mkstemp(tmpname);
			if (handle>0) {
				unlink(tmpname); /* File will stick around whilst FD open */
			} else {
				err("Error opening tree block file %m");
			}
			g_free(tmpname);
		}
		char *n = "\0";
		myseek(handle,TREEPAGESIZE-1);
		ssize_t c = write(handle,n,1);
		if (c<1) {
			err("Error setting tree block file size %m");
		}
	}
	return handle;
}

static void delete_treefile(char* name,off_t size,off_t pos) {
	char filename[256+strlen(name)];
	strcpy(filename,name);
	size_t psize=size;
	off_t ppos;
	construct_path(filename+strlen(name),256,size,pos,&ppos);

	DEBUG("Deleting treefile: %s",filename);

	if (unlink(filename)==-1)
		DEBUG("Deleting failed : %s",strerror(errno));
}


/**
 * Print out a message about how to use nbd-server. Split out to a separate
 * function so that we can call it from multiple places
 */
void usage() {
	printf("This is nbd-server version " VERSION "\n");
	printf("Usage: [ip:|ip6@]port file_to_export [size][kKmM] [-l authorize_file] [-r] [-m] [-c] [-C configuration file] [-p PID file name] [-o section name] [-M max connections] [-V]\n"
	       "\t-r|--read-only\t\tread only\n"
	       "\t-m|--multi-file\t\tmultiple file\n"
	       "\t-c|--copy-on-write\tcopy on write\n"
	       "\t-C|--config-file\tspecify an alternate configuration file\n"
	       "\t-l|--authorize-file\tfile with list of hosts that are allowed to\n\t\t\t\tconnect.\n"
	       "\t-p|--pid-file\t\tspecify a filename to write our PID to\n"
	       "\t-o|--output-config\toutput a config file section for what you\n\t\t\t\tspecified on the command line, with the\n\t\t\t\tspecified section name\n"
	       "\t-M|--max-connections\tspecify the maximum number of opened connections\n"
	       "\t-V|--version\toutput the version and exit\n\n"
	       "\tif port is set to 0, stdin is used (for running from inetd).\n"
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
SERVER* cmdline(int argc, char *argv[]) {
	int i=0;
	int nonspecial=0;
	int c;
	struct option long_options[] = {
		{"read-only", no_argument, NULL, 'r'},
		{"multi-file", no_argument, NULL, 'm'},
		{"copy-on-write", no_argument, NULL, 'c'},
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
	gboolean do_output=FALSE;
	gchar* section_header="";
	gchar** addr_port;

	if(argc==1) {
		return NULL;
	}
	serve=g_new0(SERVER, 1);
	serve->authname = g_strdup(default_authname);
	serve->virtstyle=VIRT_IPLIT;
	while((c=getopt_long(argc, argv, "-C:cdl:mo:rp:M:V", long_options, &i))>=0) {
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
			pidftemplate[255]='\0';
			break;
		case 'c': 
			serve->flags |=F_COPYONWRITE;
		        break;
		case 'd': 
			dontfork = 1;
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
		g_free(serve);
		serve=NULL;
	} else {
		glob_flags |= F_OLDSTYLE;
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
				 * file through readdir. Run stat() on
				 * the file instead */
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
					retval = g_array_new(FALSE, TRUE, sizeof(SERVER));
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
		{ "sparse_cow",	FALSE,	PARAM_BOOL,	&(s.flags),		F_SPARSE },
		{ "sdp",	FALSE,	PARAM_BOOL,	&(s.flags),		F_SDP },
		{ "sync",	FALSE,  PARAM_BOOL,	&(s.flags),		F_SYNC },
		{ "flush",	FALSE,  PARAM_BOOL,	&(s.flags),		F_FLUSH },
		{ "fua",	FALSE,  PARAM_BOOL,	&(s.flags),		F_FUA },
		{ "rotational",	FALSE,  PARAM_BOOL,	&(s.flags),		F_ROTATIONAL },
		{ "temporary",	FALSE,  PARAM_BOOL,	&(s.flags),		F_TEMPORARY },
		{ "trim",	FALSE,  PARAM_BOOL,	&(s.flags),		F_TRIM },
		{ "listenaddr", FALSE,  PARAM_STRING,   &(s.listenaddr),	0 },
		{ "maxconnections", FALSE, PARAM_INT,	&(s.max_connections),	0 },
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

        if (genconf) {
                /* Use the passed configuration values as defaults. The
                 * parsing algorithm below updates all parameter targets
                 * found from configuration files. */
                memcpy(&genconftmp, genconf, sizeof(struct generic_conf));
        }

	cfile = g_key_file_new();
	retval = g_array_new(FALSE, TRUE, sizeof(SERVER));
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
		/* Don't need to free this, it's not our string */
		virtstyle=NULL;
		/* Don't append values for the [generic] group */
		if(i>0 || !expect_generic) {
			s.socket_family = AF_UNSPEC;
			s.servename = groups[i];

			append_serve(&s, retval);
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
			msg(LOG_INFO, "Child exited with %d", WEXITSTATUS(status));
		}
		i=g_hash_table_lookup(children, &pid);
		if(!i) {
			msg(LOG_INFO, "SIGCHLD received for an unknown child with PID %ld", (long)pid);
		} else {
			DEBUG("Removing %d from the list of children", pid);
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

	kill(*pid, SIGTERM);
}

/**
 * Handle SIGTERM and dispatch it to our children
 * @param s the signal we're handling (must be SIGTERM, or something
 * is severely wrong).
 **/
void sigterm_handler(int s) {
	g_hash_table_foreach(children, killchild, NULL);
	unlink(pidfname);

	exit(EXIT_SUCCESS);
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
		*fhandle = open_treefile(client->exportname, ((client->server->flags & F_READONLY) ? O_RDONLY : O_RDWR), client->exportsize,a);
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
 * seek to a position in a file, with error handling.
 * @param handle a filedescriptor
 * @param a position to seek to
 * @todo get rid of this.
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

	myseek(fhandle, foffset);
	retval = write(fhandle, buf, len);
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

	myseek(fhandle, foffset);
	retval = read(fhandle, buf, len);
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
	DEBUG("Asked to read %u bytes at %llu.\n", (unsigned int)len, (unsigned long long)a);

	mapl=a/DIFFPAGESIZE; maph=(a+len-1)/DIFFPAGESIZE;

	for (mapcnt=mapl;mapcnt<=maph;mapcnt++) {
		pagestart=mapcnt*DIFFPAGESIZE;
		offset=a-pagestart;
		rdlen=(0<DIFFPAGESIZE-offset && len<(size_t)(DIFFPAGESIZE-offset)) ?
			len : (size_t)DIFFPAGESIZE-offset;
		if (client->difmap[mapcnt]!=(u32)(-1)) { /* the block is already there */
			DEBUG("Page %llu is at %lu\n", (unsigned long long)mapcnt,
			       (unsigned long)(client->difmap[mapcnt]));
			myseek(client->difffile, client->difmap[mapcnt]*DIFFPAGESIZE+offset);
			if (read(client->difffile, buf, rdlen) != rdlen) return -1;
		} else { /* the block is not there */
			DEBUG("Page %llu is not here, we read the original one\n",
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
 * @param fua Flag to indicate 'Force Unit Access'
 * @return 0 on success, nonzero on failure
 **/
int expwrite(off_t a, char *buf, size_t len, CLIENT *client, int fua) {
	char pagebuf[DIFFPAGESIZE];
	off_t mapcnt,mapl,maph;
	off_t wrlen,rdlen; 
	off_t pagestart;
	off_t offset;

	if (!(client->server->flags & F_COPYONWRITE))
		return(rawexpwrite_fully(a, buf, len, client, fua)); 
	DEBUG("Asked to write %u bytes at %llu.\n", (unsigned int)len, (unsigned long long)a);

	mapl=a/DIFFPAGESIZE ; maph=(a+len-1)/DIFFPAGESIZE ;

	for (mapcnt=mapl;mapcnt<=maph;mapcnt++) {
		pagestart=mapcnt*DIFFPAGESIZE ;
		offset=a-pagestart ;
		wrlen=(0<DIFFPAGESIZE-offset && len<(size_t)(DIFFPAGESIZE-offset)) ?
			len : (size_t)DIFFPAGESIZE-offset;

		if (client->difmap[mapcnt]!=(u32)(-1)) { /* the block is already there */
			DEBUG("Page %llu is at %lu\n", (unsigned long long)mapcnt,
			       (unsigned long)(client->difmap[mapcnt])) ;
			myseek(client->difffile,
					client->difmap[mapcnt]*DIFFPAGESIZE+offset);
			if (write(client->difffile, buf, wrlen) != wrlen) return -1 ;
		} else { /* the block is not there */
			myseek(client->difffile,client->difffilelen*DIFFPAGESIZE) ;
			client->difmap[mapcnt]=(client->server->flags&F_SPARSE)?mapcnt:client->difffilelen++;
			DEBUG("Page %llu is not here, we put it at %lu\n",
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
	if (client->server->flags & F_SYNC) {
		fsync(client->difffile);
	} else if (fua) {
		/* open question: would it be cheaper to do multiple sync_file_ranges?
		   as we iterate through the above?
		 */
		fdatasync(client->difffile);
	}
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

/*
 * If the current system supports it, call fallocate() on the backend
 * file to resparsify stuff that isn't needed anymore (see NBD_CMD_TRIM)
 */
int exptrim(struct nbd_request* req, CLIENT* client) {
        if (client->server->flags & F_TREEFILES) {
		if (client->server->flags & F_READONLY)
			return 0;

		off_t min = ( ( req->from + TREEPAGESIZE - 1 ) / TREEPAGESIZE) * TREEPAGESIZE; // start address of first to be trimmed block
		off_t max = ( ( req->from + req->len ) / TREEPAGESIZE) * TREEPAGESIZE; // start address of first not to be trimmed block
		while (min<max) {
			delete_treefile(client->exportname,client->exportsize,min);
			min+=TREEPAGESIZE;
		}
		DEBUG("Performed TRIM request on TREE structure from %llu to %llu", (unsigned long long) req->from, (unsigned long long) req->len);
		return 0;
	}
#if HAVE_FALLOC_PH
	FILE_INFO prev = g_array_index(client->export, FILE_INFO, 0);
	FILE_INFO cur = prev;
	int i = 1;
	/* We're running on a system that supports the
	 * FALLOC_FL_PUNCH_HOLE option to re-sparsify a file */
	do {
		if(i<client->export->len) {
			cur = g_array_index(client->export, FILE_INFO, i);
		}
		if(prev.startoff <= req->from) {
			off_t curoff = req->from - prev.startoff;
			off_t curlen = cur.startoff - prev.startoff - curoff;
			fallocate(prev.fhandle, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, curoff, curlen);
		}
		prev = cur;
	} while(i < client->export->len && cur.startoff < (req->from + req->len));
	DEBUG("Performed TRIM request from %llu to %llu", (unsigned long long) req->from, (unsigned long long) req->len);
#else
	DEBUG("Ignoring TRIM request (not supported on current platform");
#endif
	return 0;
}

static void send_reply(uint32_t opt, int net, uint32_t reply_type, size_t datasize, void* data) {
	uint64_t magic = htonll(0x3e889045565a9LL);
	reply_type = htonl(reply_type);
	uint32_t datsize = htonl(datasize);
	opt = htonl(opt);
	struct iovec v_data[] = {
		{ &magic, sizeof(magic) },
		{ &opt, sizeof(opt) },
		{ &reply_type, sizeof(reply_type) },
		{ &datsize, sizeof(datsize) },
		{ data, datasize },
	};
	size_t total = sizeof(magic) + sizeof(opt) + sizeof(reply_type) + sizeof(datsize) + datasize;
	ssize_t sent = writev(net, v_data, 5);
	if(sent != total) {
		perror("E: couldn't write enough data:");
	}
}

static CLIENT* handle_export_name(uint32_t opt, int net, GArray* servers, uint32_t cflags) {
	uint32_t namelen;
	char* name;
	int i;

	if (read(net, &namelen, sizeof(namelen)) < 0) {
		err("Negotiation failed/7: %m");
		return NULL;
	}
	namelen = ntohl(namelen);
	name = malloc(namelen+1);
	name[namelen]=0;
	if (read(net, name, namelen) < 0) {
		err("Negotiation failed/8: %m");
		free(name);
		return NULL;
	}
	for(i=0; i<servers->len; i++) {
		SERVER* serve = &(g_array_index(servers, SERVER, i));
		if(!strcmp(serve->servename, name)) {
			CLIENT* client = g_new0(CLIENT, 1);
			client->server = serve;
			client->exportsize = OFFT_MAX;
			client->net = net;
			client->modern = TRUE;
			client->transactionlogfd = -1;
			client->clientfeats = cflags;
			free(name);
			return client;
		}
	}
	err("Negotiation failed/8a: Requested export not found");
	free(name);
	return NULL;
}

static void handle_list(uint32_t opt, int net, GArray* servers, uint32_t cflags) {
	uint32_t len;
	int i;
	char buf[1024];
	char *ptr = buf + sizeof(len);

	if (read(net, &len, sizeof(len)) < 0)
		err("Negotiation failed/8: %m");
	len = ntohl(len);
	if(len) {
		send_reply(opt, net, NBD_REP_ERR_INVALID, 0, NULL);
	}
	if(!(glob_flags & F_LIST)) {
		send_reply(opt, net, NBD_REP_ERR_POLICY, 0, NULL);
		err_nonfatal("Client tried disallowed list option");
		return;
	}
	for(i=0; i<servers->len; i++) {
		SERVER* serve = &(g_array_index(servers, SERVER, i));
		len = htonl(strlen(serve->servename));
		memcpy(buf, &len, sizeof(len));
		strcpy(ptr, serve->servename);
		send_reply(opt, net, NBD_REP_SERVER, strlen(serve->servename)+sizeof(len), buf);
	}
	send_reply(opt, net, NBD_REP_ACK, 0, NULL);
}

/**
 * Do the initial negotiation.
 *
 * @param client The client we're negotiating with.
 **/
CLIENT* negotiate(int net, GArray* servers) {
	uint32_t flags = NBD_FLAG_HAS_FLAGS;
	uint16_t smallflags = NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES;
	uint64_t magic;
	uint32_t cflags = 0;
	uint32_t opt;

	assert(servers != NULL);
	if (write(net, INIT_PASSWD, 8) < 0)
		err_nonfatal("Negotiation failed/1: %m");
	magic = htonll(opts_magic);
	if (write(net, &magic, sizeof(magic)) < 0)
		err_nonfatal("Negotiation failed/2: %m");

	smallflags = htons(smallflags);
	if (write(net, &smallflags, sizeof(uint16_t)) < 0)
		err_nonfatal("Negotiation failed/3: %m");
	if (read(net, &cflags, sizeof(cflags)) < 0)
		err_nonfatal("Negotiation failed/4: %m");
	cflags = htonl(cflags);
	if (cflags & NBD_FLAG_C_NO_ZEROES) {
		glob_flags |= F_NO_ZEROES;
	}
	do {
		if (read(net, &magic, sizeof(magic)) < 0)
			err_nonfatal("Negotiation failed/5: %m");
		magic = ntohll(magic);
		if(magic != opts_magic) {
			err_nonfatal("Negotiation failed/5a: magic mismatch");
			return NULL;
		}
		if (read(net, &opt, sizeof(opt)) < 0)
			err_nonfatal("Negotiation failed/6: %m");
		opt = ntohl(opt);
		switch(opt) {
		case NBD_OPT_EXPORT_NAME:
			// NBD_OPT_EXPORT_NAME must be the last
			// selected option, so return from here
			// if that is chosen.
			return handle_export_name(opt, net, servers, cflags);
			break;
		case NBD_OPT_LIST:
			handle_list(opt, net, servers, cflags);
			break;
		case NBD_OPT_ABORT:
			// handled below
			break;
		default:
			send_reply(opt, net, NBD_REP_ERR_UNSUP, 0, NULL);
			break;
		}
	} while((opt != NBD_OPT_EXPORT_NAME) && (opt != NBD_OPT_ABORT));
	if(opt == NBD_OPT_ABORT) {
		err_nonfatal("Session terminated by client");
		return NULL;
	}
}

void send_export_info(CLIENT* client) {
	uint64_t size_host = htonll((u64)(client->exportsize));
	uint16_t flags = 0;

	if (write(client->net, &size_host, 8) < 0)
		err("Negotiation failed/9: %m");
	if (client->server->flags & F_READONLY)
		flags |= NBD_FLAG_READ_ONLY;
	if (client->server->flags & F_FLUSH)
		flags |= NBD_FLAG_SEND_FLUSH;
	if (client->server->flags & F_FUA)
		flags |= NBD_FLAG_SEND_FUA;
	if (client->server->flags & F_ROTATIONAL)
		flags |= NBD_FLAG_ROTATIONAL;
	if (client->server->flags & F_TRIM)
		flags |= NBD_FLAG_SEND_TRIM;
	flags = htons(flags);
	if (write(client->net, &flags, sizeof(flags)) < 0)
		err("Negotiation failed/11: %m");
	if (!(glob_flags & F_NO_ZEROES)) {
		char zeros[128];
		memset(zeros, '\0', sizeof(zeros));
		if (write(client->net, zeros, 124) < 0)
			err("Negotiation failed/12: %m");
	}
}

/** sending macro. */
#define SEND(net,reply) { writeit( net, &reply, sizeof( reply )); \
	if (client->transactionlogfd != -1) \
		writeit(client->transactionlogfd, &reply, sizeof(reply)); }
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
	send_export_info(client);
	DEBUG("Entering request loop!\n");
	reply.magic = htonl(NBD_REPLY_MAGIC);
	reply.error = 0;
	while (go_on) {
		char buf[BUFSIZE];
		char* p;
		size_t len;
		size_t currlen;
		size_t writelen;
		uint16_t command;
#ifdef DODBG
		i++;
		printf("%d: ", i);
#endif
		readit(client->net, &request, sizeof(request));
		if (client->transactionlogfd != -1)
			writeit(client->transactionlogfd, &request, sizeof(request));

		request.from = ntohll(request.from);
		request.type = ntohl(request.type);
		command = request.type & NBD_CMD_MASK_COMMAND;
		len = ntohl(request.len);

		DEBUG("%s from %llu (%llu) len %u, ", getcommandname(command),
				(unsigned long long)request.from,
				(unsigned long long)request.from / 512, len);

		if (request.magic != htonl(NBD_REQUEST_MAGIC))
			err("Not enough magic.");

		memcpy(reply.handle, request.handle, sizeof(reply.handle));

		if ((command==NBD_CMD_WRITE) || (command==NBD_CMD_READ)) {
			if (request.from + len < request.from) { // 64 bit overflow!!
				DEBUG("[Number too large!]");
				ERROR(client, reply, EINVAL);
				continue;
			}

			if (((off_t)request.from + len) > client->exportsize) {
				DEBUG("[RANGE!]");
				ERROR(client, reply, EINVAL);
				continue;
			}

			currlen = len;
			if (currlen > BUFSIZE - sizeof(struct nbd_reply)) {
				currlen = BUFSIZE - sizeof(struct nbd_reply);
				if(!logged_oversized) {
					msg(LOG_DEBUG, "oversized request (this is not a problem)");
					logged_oversized = true;
				}
			}
		}

		switch (command) {

		case NBD_CMD_DISC:
			msg(LOG_INFO, "Disconnect request received.");
                	if (client->server->flags & F_COPYONWRITE) { 
				if (client->difmap) g_free(client->difmap) ;
                		close(client->difffile);
				unlink(client->difffilename);
				free(client->difffilename);
			}
			go_on=FALSE;
			continue;

		case NBD_CMD_WRITE:
			DEBUG("wr: net->buf, ");
			while(len > 0) {
				readit(client->net, buf, currlen);
				DEBUG("buf->exp, ");
				if ((client->server->flags & F_READONLY) ||
				    (client->server->flags & F_AUTOREADONLY)) {
					DEBUG("[WRITE to READONLY!]");
					ERROR(client, reply, EPERM);
					consume(client->net, buf, len-currlen, BUFSIZE);
					continue;
				}
				if (expwrite(request.from, buf, currlen, client,
					     request.type & NBD_CMD_FLAG_FUA)) {
					DEBUG("Write failed: %m" );
					ERROR(client, reply, errno);
					consume(client->net, buf, len-currlen, BUFSIZE);
					continue;
				}
				len -= currlen;
				request.from += currlen;
				currlen = (len < BUFSIZE) ? len : BUFSIZE;
			}
			SEND(client->net, reply);
			DEBUG("OK!\n");
			continue;

		case NBD_CMD_FLUSH:
			DEBUG("fl: ");
			if (expflush(client)) {
				DEBUG("Flush failed: %m");
				ERROR(client, reply, errno);
				continue;
			}
			SEND(client->net, reply);
			DEBUG("OK!\n");
			continue;

		case NBD_CMD_READ:
			DEBUG("exp->buf, ");
			if (client->transactionlogfd != -1)
				writeit(client->transactionlogfd, &reply, sizeof(reply));
			writeit(client->net, &reply, sizeof(reply));
			p = buf;
			writelen = currlen;
			while(len > 0) {
				if (expread(request.from, p, currlen, client)) {
					DEBUG("Read failed: %m");
					ERROR(client, reply, errno);
					continue;
				}
				
				DEBUG("buf->net, ");
				writeit(client->net, buf, writelen);
				len -= currlen;
				request.from += currlen;
				currlen = (len < BUFSIZE) ? len : BUFSIZE;
				p = buf;
				writelen = currlen;
			}
			DEBUG("OK!\n");
			continue;

		case NBD_CMD_TRIM:
			/* The kernel module sets discard_zeroes_data == 0,
			 * so it is okay to do nothing.  */
			if (exptrim(&request, client)) {
				DEBUG("Trim failed: %m");
				ERROR(client, reply, errno);
				continue;
			}
			SEND(client->net, reply);
			continue;

		default:
			DEBUG ("Ignoring unknown command\n");
			continue;
		}
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
	int treefile = (client->server->flags & F_TREEFILES);
	int temporary = (client->server->flags & F_TEMPORARY) && !multifile;
	int cancreate = (client->server->expected_size) && !multifile;

	if (treefile) {
		client->export = NULL; // this could be thousands of files so we open handles on demand although its slower
		client->exportsize = client->server->expected_size; // available space is not checked, as it could change during runtime anyway
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
				err(error_string);
			}

			if (temporary)
				unlink(tmpname); /* File will stick around whilst FD open */

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
					err("Could not expand file: %m");
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
				err("Size of exported file is too big\n");
			}

			client->exportsize = client->server->expected_size;
		}
	}

	msg(LOG_INFO, "Size of exported file/device is %llu", (unsigned long long)client->exportsize);
	if(multifile) {
		msg(LOG_INFO, "Total number of files: %d", i);
	}
	if(treefile) {
		msg(LOG_INFO, "Total number of (potential) files: %d", (client->exportsize+TREEPAGESIZE-1)/TREEPAGESIZE);
	}
}

int copyonwrite_prepare(CLIENT* client) {
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
	if (client->server->transactionlog && (client->transactionlogfd == -1))
	{
		if (-1 == (client->transactionlogfd = open(client->server->transactionlog,
							   O_WRONLY | O_CREAT,
							   S_IRUSR | S_IWUSR)))
			g_warning("Could not open transaction log %s",
				  client->server->transactionlog);
	}

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

	if (-1 != client->transactionlogfd)
	{
		close(client->transactionlogfd);
		client->transactionlogfd = -1;
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

	if (getpeername(net, (struct sockaddr *) &(client->clientaddr), &addrinlen) < 0) {
		msg(LOG_INFO, "getpeername failed: %m");
		return -1;
	}

	if(addr->sa_family == AF_UNIX) {
		strcpy(peername, "unix");
	} else {
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
			if(addr->sa_family == AF_UNIX) {
				tmp = g_strdup(peername);
			} else {
				assert((ai->ai_family == AF_INET) || (ai->ai_family == AF_INET6));
				if(ai->ai_family == AF_INET) {
					addrbits = 32;
				} else if(ai->ai_family == AF_INET6) {
					addrbits = 128;
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

	freeaddrinfo(ai);
        msg(LOG_INFO, "connect from %s, assigned file is %s",
            peername, client->exportname);
	client->clientname=g_strdup(peername);
	return 0;
}

/**
 * Destroy a pid_t*
 * @param data a pointer to pid_t which should be freed
 **/
void destroy_pid_t(gpointer data) {
	g_free(data);
}

static pid_t
spawn_child()
{
        pid_t pid;
        sigset_t newset;
        sigset_t oldset;

        sigemptyset(&newset);
        sigaddset(&newset, SIGCHLD);
        sigaddset(&newset, SIGTERM);
        sigprocmask(SIG_BLOCK, &newset, &oldset);
        pid = fork();
        if (pid < 0) {
                msg(LOG_ERR, "Could not fork (%s)", strerror(errno));
                goto out;
        }
        if (pid > 0) { /* Parent */
                pid_t *pidp;

                pidp = g_malloc(sizeof(pid_t));
                *pidp = pid;
                g_hash_table_insert(children, pidp, pidp);
                goto out;
        }
        /* Child */
        signal(SIGCHLD, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGHUP, SIG_DFL);
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
handle_modern_connection(GArray *const servers, const int sock)
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
                pid = spawn_child();
                if (pid) {
                        if (pid > 0)
                                msg(LOG_INFO, "Spawned a child process");
                        if (pid < 0)
                                msg(LOG_ERR, "Failed to spawn a child process");
                        close(net);
                        return;
                }
                /* Child just continues. */
        }

        client = negotiate(net, servers);
        if (!client) {
                msg(LOG_ERR, "Modern initial negotiation failed");
                goto handler_err;
        }

        if (client->server->max_connections > 0 &&
           g_hash_table_size(children) >= client->server->max_connections) {
                msg(LOG_ERR, "Max connections (%d) reached",
                    client->server->max_connections);
                goto handler_err;
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

        if (set_peername(net, client)) {
                msg(LOG_ERR, "Failed to set peername");
                goto handler_err;
        }

        if (!authorized_client(client)) {
                msg(LOG_INFO, "Client '%s' is not authorized to access",
                    client->clientname);
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

                for (i = 0; i < servers->len; i++) {
                        const SERVER *const server = &g_array_index(servers, SERVER, i);
                        close(server->socket);
                }

                /* FALSE does not free the
                   actual data. This is required,
                   because the client has a
                   direct reference into that
                   data, and otherwise we get a
                   segfault... */
                g_array_free(servers, FALSE);
        }

        msg(LOG_INFO, "Starting to serve");
        serveconnection(client);
        exit(EXIT_SUCCESS);

handler_err:
        g_free(client);
        close(net);

        if (!dontfork) {
                exit(EXIT_FAILURE);
        }
}

static void
handle_oldstyle_connection(GArray *const servers, SERVER *const serve)
{
	int net;
	CLIENT *client = NULL;
	int sock_flags_old;
	int sock_flags_new;

	net = socket_accept(serve->socket);
	if (net < 0)
		return;

	if(serve->max_connections > 0 &&
	   g_hash_table_size(children) >= serve->max_connections) {
		msg(LOG_INFO, "Max connections reached");
		goto handle_connection_out;
	}
	if((sock_flags_old = fcntl(net, F_GETFL, 0)) == -1) {
		err("fcntl F_GETFL");
	}
	sock_flags_new = sock_flags_old & ~O_NONBLOCK;
	if (sock_flags_new != sock_flags_old &&
	    fcntl(net, F_SETFL, sock_flags_new) == -1) {
		err("fcntl F_SETFL ~O_NONBLOCK");
	}

	client = g_new0(CLIENT, 1);
	client->server=serve;
	client->exportsize=OFFT_MAX;
	client->net=net;
	client->transactionlogfd = -1;

	if (set_peername(net, client)) {
		goto handle_connection_out;
	}
	if (!authorized_client(client)) {
		msg(LOG_INFO, "Unauthorized client");
		goto handle_connection_out;
	}
	msg(LOG_INFO, "Authorized client");

	if (!dontfork) {
		pid_t pid;
		int i;
		sigset_t newset;
		sigset_t oldset;

		sigemptyset(&newset);
		sigaddset(&newset, SIGCHLD);
		sigaddset(&newset, SIGTERM);
		sigprocmask(SIG_BLOCK, &newset, &oldset);
		if ((pid = fork()) < 0) {
			msg(LOG_INFO, "Could not fork (%s)", strerror(errno));
			sigprocmask(SIG_SETMASK, &oldset, NULL);
			goto handle_connection_out;
		}
		if (pid > 0) { /* parent */
			pid_t *pidp;

			pidp = g_malloc(sizeof(pid_t));
			*pidp = pid;
			g_hash_table_insert(children, pidp, pidp);
			sigprocmask(SIG_SETMASK, &oldset, NULL);
			goto handle_connection_out;
		}
		/* child */
		signal(SIGCHLD, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
		sigprocmask(SIG_SETMASK, &oldset, NULL);

		g_hash_table_destroy(children);
		children = NULL;
		for(i=0;i<servers->len;i++) {
			close(g_array_index(servers, SERVER, i).socket);
		}
		/* FALSE does not free the
		   actual data. This is required,
		   because the client has a
		   direct reference into that
		   data, and otherwise we get a
		   segfault... */
		g_array_free(servers, FALSE);
		for(i=0;i<modernsocks->len;i++) {
			close(g_array_index(modernsocks, int, i));
		}
		g_array_free(modernsocks, TRUE);
	}

	msg(LOG_INFO, "Starting to serve");
	serveconnection(client);
	exit(EXIT_SUCCESS);

handle_connection_out:
	g_free(client);
	close(net);
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
                const SERVER server = g_array_index(servers, SERVER, i);

                if (strcmp(servename, server.servename) == 0)
                        return i;
        }

        return -1;
}

int setup_serve(SERVER *const serve, GError **const gerror);

/**
 * Parse configuration files and add servers to the array if they don't
 * already exist there. The existence is tested by comparing
 * servenames. A server is appended to the array only if its servename
 * is unique among all other servers.
 *
 * @param servers an array of servers
 * @return the number of new servers appended to the array, or -1 in
 *         case of an error
 **/
static int append_new_servers(GArray *const servers, GError **const gerror) {
        int i;
        GArray *new_servers;
        const int old_len = servers->len;
        int retval = -1;
        struct generic_conf genconf;

        new_servers = parse_cfile(config_file_pos, &genconf, true, gerror);
        if (!new_servers)
                goto out;

        for (i = 0; i < new_servers->len; ++i) {
                SERVER new_server = g_array_index(new_servers, SERVER, i);

                if (new_server.servename
                    && -1 == get_index_by_servename(new_server.servename,
                                                    servers)) {
                        if (setup_serve(&new_server, gerror) == -1)
                                goto out;
                        if (append_serve(&new_server, servers) == -1)
                                goto out;
                }
        }

        retval = servers->len - old_len;
out:
        g_array_free(new_servers, TRUE);

        return retval;
}

/**
 * Loop through the available servers, and serve them. Never returns.
 **/
void serveloop(GArray* servers) {
	int i;
	int max;
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
		int sock;
		if((sock=(g_array_index(servers, SERVER, i)).socket) >= 0) {
			FD_SET(sock, &mset);
			max=sock>max?sock:max;
		}
	}
	for(i=0;i<modernsocks->len;i++) {
		int sock = g_array_index(modernsocks, int, i);
		FD_SET(sock, &mset);
		max=sock>max?sock:max;
	}
	for(;;) {
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

                        n = append_new_servers(servers, &gerror);
                        if (n == -1)
                                msg(LOG_ERR, "failed to append new servers: %s",
                                    gerror->message);

                        for (i = servers->len - n; i < servers->len; ++i) {
                                const SERVER server = g_array_index(servers,
                                                                    SERVER, i);

                                if (server.socket >= 0) {
                                        FD_SET(server.socket, &mset);
                                        max = server.socket > max ? server.socket : max;
                                }

                                msg(LOG_INFO, "reconfigured new server: %s",
                                    server.servename);
                        }
                }

		memcpy(&rset, &mset, sizeof(fd_set));
		if(select(max+1, &rset, NULL, NULL, NULL)>0) {

			DEBUG("accept, ");
			for(i=0; i < modernsocks->len; i++) {
				int sock = g_array_index(modernsocks, int, i);
				if(!FD_ISSET(sock, &rset)) {
					continue;
				}

				handle_modern_connection(servers, sock);
			}
			for(i=0; i < servers->len; i++) {
				SERVER *serve;

				serve=&(g_array_index(servers, SERVER, i));
				if(serve->socket < 0) {
					continue;
				}
				if(FD_ISSET(serve->socket, &rset)) {
					handle_oldstyle_connection(servers, serve);
				}
			}
		}
	}
}
void serveloop(GArray* servers) G_GNUC_NORETURN;

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

/**
 * Connect a server's socket.
 *
 * @param serve the server we want to connect.
 **/
int setup_serve(SERVER *const serve, GError **const gerror) {
	struct addrinfo hints;
	struct addrinfo *ai = NULL;
	gchar *port = NULL;
	int e;
        int retval = -1;

        /* Without this, it's possible that socket == 0, even if it's
         * not initialized at all. And that would be wrong because 0 is
         * totally legal value for properly initialized descriptor. This
         * line is required to ensure that unused/uninitialized
         * descriptors are marked as such (new style configuration
         * case). Currently, servers are being initialized in multiple
         * places, and some of the them do the socket initialization
         * incorrectly. This is the only point common to all code paths,
         * and therefore setting -1 is put here. However, the whole
         * server initialization procedure should be extracted to its
         * own function and all code paths wanting to mess with servers
         * should initialize servers with that function.
         * 
         * TODO: fix server initialization */
        serve->socket = -1;

	if(!(glob_flags & F_OLDSTYLE)) {
		return serve->servename ? 1 : 0;
	}
	memset(&hints,'\0',sizeof(hints));
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG | AI_NUMERICSERV;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = serve->socket_family;

	port = g_strdup_printf("%d", serve->port);
	if (!port) {
                g_set_error(gerror, NBDS_ERR, NBDS_ERR_SYS,
                            "failed to open an export socket: "
                            "failed to convert a port number to a string: %s",
                            strerror(errno));
                goto out;
        }

	e = getaddrinfo(serve->listenaddr,port,&hints,&ai);

	g_free(port);

	if(e != 0) {
                g_set_error(gerror, NBDS_ERR, NBDS_ERR_GAI,
                            "failed to open an export socket: "
                            "failed to get address info: %s",
                            gai_strerror(e));
                goto out;
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
	if ((serve->socket = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0) {
                g_set_error(gerror, NBDS_ERR, NBDS_ERR_SOCKET,
                            "failed to open an export socket: "
                            "failed to create a socket: %s",
                            strerror(errno));
                goto out;
        }

	if (dosockopts(serve->socket, gerror) == -1) {
                g_prefix_error(gerror, "failed to open an export socket: ");
                goto out;
        }

	DEBUG("Waiting for connections... bind, ");
	e = bind(serve->socket, ai->ai_addr, ai->ai_addrlen);
	if (e != 0 && errno != EADDRINUSE) {
                g_set_error(gerror, NBDS_ERR, NBDS_ERR_BIND,
                            "failed to open an export socket: "
                            "failed to bind an address to a socket: %s",
                            strerror(errno));
                goto out;
        }
	DEBUG("listen, ");
	if (listen(serve->socket, 1) < 0) {
                g_set_error(gerror, NBDS_ERR, NBDS_ERR_BIND,
                            "failed to open an export socket: "
                            "failed to start listening on a socket: %s",
                            strerror(errno));
                goto out;
        }

        retval = serve->servename ? 1 : 0;
out:

        if (retval == -1 && serve->socket >= 0) {
                close(serve->socket);
                serve->socket = -1;
        }
	freeaddrinfo (ai);

        return retval;
}

int open_unix(const gchar *const sockname, GError **const gerror) {
	struct sockaddr_un sa;
	int sock=-1;
	int retval=-1;

	memset(&sa, 0, sizeof(struct sockaddr_un));
	sa.sun_family = AF_UNIX;
	strncpy(sa.sun_path, sockname, 107);
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
	struct addrinfo* ai_bak;
	struct sock_flags;
	int e;
        int retval = -1;
	int sock = -1;

	memset(&hints, '\0', sizeof(hints));
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	e = getaddrinfo(addr, port ? port : NBD_DEFAULT_PORT, &hints, &ai);
	ai_bak = ai;
	if(e != 0) {
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
			/* This is so wrong. 
			 * 
			 * Linux will return multiple entries for the
			 * same system when we ask it for something
			 * AF_UNSPEC, even though the first entry will
			 * listen to both protocols. Other systems will
			 * return multiple entries too, but we actually
			 * do need to open both. Sigh.
			 *
			 * Handle it by ignoring EADDRINUSE if we've
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
                   const gchar *const modernport, const gchar* unixsock) {
	int i;
	struct sigaction sa;
	int want_modern=0;

	for(i=0;i<servers->len;i++) {
                GError *gerror = NULL;
                SERVER *server = &g_array_index(servers, SERVER, i);
                int ret;

		ret = setup_serve(server, &gerror);
                if (ret == -1) {
                        msg(LOG_ERR, "failed to setup servers: %s",
                            gerror->message);
                        g_clear_error(&gerror);
                        exit(EXIT_FAILURE);
                }
                want_modern |= ret;
	}
	if(want_modern) {
                GError *gerror = NULL;
                if (open_modern(modernaddr, modernport, &gerror) == -1) {
                        msg(LOG_ERR, "failed to setup servers: %s",
                            gerror->message);
                        g_clear_error(&gerror);
                        exit(EXIT_FAILURE);
                }
	}
	if(unixsock != NULL) {
		GError* gerror = NULL;
		if(open_unix(unixsock, &gerror) == -1) {
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
}

/**
 * Go daemon (unless we specified at compile time that we didn't want this)
 * @param serve the first server of our configuration. If its port is zero,
 * 	then do not daemonize, because we're doing inetd then. This parameter
 * 	is only used to create a PID file of the form
 * 	/var/run/nbd-server.&lt;port&gt;.pid; it's not modified in any way.
 **/
#if !defined(NODAEMON)
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
	GError *err=NULL;
        struct generic_conf genconf;

        memset(&genconf, 0, sizeof(struct generic_conf));

	if (sizeof( struct nbd_request )!=28) {
		fprintf(stderr,"Bad size of structure. Alignment problems?\n");
		exit(EXIT_FAILURE) ;
	}

	memset(pidftemplate, '\0', 256);

	modernsocks = g_array_new(FALSE, FALSE, sizeof(int));

	logging(MY_NAME);
	config_file_pos = g_strdup(CFILE);
	serve=cmdline(argc, argv);

        servers = parse_cfile(config_file_pos, &genconf, true, &err);
	
        /* Update global variables with parsed values. This will be
         * removed once we get rid of global configuration variables. */
        glob_flags   |= genconf.flags;

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
			client->net=-1;
			client->exportsize=OFFT_MAX;
			if (set_peername(0, client))
				exit(EXIT_FAILURE);
			serveconnection(client);
			return 0;
		}
	}
    
	if(!servers || !servers->len) {
                if(err && !(err->domain == NBDS_ERR
                            && err->code == NBDS_ERR_CFILE_NOTFOUND)) {
			g_warning("Could not parse config file: %s", 
					err ? err->message : "Unknown error");
		}
	}
	if(serve) {
		g_warning("Specifying an export on the command line is deprecated.");
		g_warning("Please use a configuration file instead.");
	}

	if((!serve) && (!servers||!servers->len)) {
		if(err)
			g_message("No configured exports; quitting.");
		exit(EXIT_FAILURE);
	}
	if (!dontfork)
		daemonize(serve);
	setup_servers(servers, genconf.modernaddr, genconf.modernport,
			genconf.unixsock);
	dousers(genconf.user, genconf.group);

	serveloop(servers);
}
