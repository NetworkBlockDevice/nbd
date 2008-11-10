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

#include <glib.h>

/* used in cliserv.h, so must come first */
#define MY_NAME "nbd_server"
#include "cliserv.h"

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
#else
#define DEBUG( a )
#define DEBUG2( a,b ) 
#define DEBUG3( a,b,c ) 
#endif
#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION ""
#endif
/**
 * The highest value a variable of type off_t can reach.
 **/
/* This is starting to get ugly. If someone knows a better way to find
 * the maximum value of a signed type *without* relying on overflow
 * (doing so breaks on 64bit architectures), that would be nice.
 *
 * Actually, do we need this at all? Can't we just say '0 is autodetect', and
 * live with it? Or better yet, use an extra flag, or so?
 * Answer: yes, we need it, as the hunksize is defined to this when the
 * multiple file thingy isn't used.
 */
#define OFFT_MAX (((((off_t)1)<<((sizeof(off_t)-1)*8))-1)<<7)+127
#define LINELEN 256	  /**< Size of static buffer used to read the
			    authorization file (yuck) */
#define BUFSIZE (1024*1024) /**< Size of buffer that can hold requests */
#define GIGA (1*1024*1024*1024) /**< 1 Gigabyte. Used as hunksize when doing
				  the multiple file thingy. @todo: make this a
				  configuration option. */
#define DIFFPAGESIZE 4096 /**< diff file uses those chunks */
#define F_READONLY 1      /**< flag to tell us a file is readonly */
#define F_MULTIFILE 2	  /**< flag to tell us a file is exported using -m */
#define F_COPYONWRITE 4	  /**< flag to tell us a file is exported using
			    copyonwrite */
#define F_AUTOREADONLY 8  /**< flag to tell us a file is set to autoreadonly */
GHashTable *children;
char pidfname[256]; /**< name of our PID file */
char default_authname[] = "/etc/nbd_server.allow"; /**< default name of allow file */

/**
 * Variables associated with a server.
 **/
typedef struct {
	char* exportname;    /**< (unprocessed) filename of the file we're exporting */
	off_t hunksize;      /**< size of a hunk of an exported file */
	off_t expected_size; /**< size of the exported file as it was told to
			       us through configuration */
	unsigned int port;   /**< port we're exporting this file at */
	char* authname;      /**< filename of the authorization file */
	int flags;           /**< flags associated with this exported file */
	unsigned int timeout;/**< how long a connection may be idle
			       (0=forever) */
	int socket;	     /**< The socket of this server. */
} SERVER;

/**
 * Variables associated with a client socket.
 **/
typedef struct {
	off_t exportsize;    /**< size of the file we're exporting */
	char *clientname;    /**< peer */
	char *exportname;    /**< (processed) filename of the file we're exporting */
	GArray *export;    /**< array of filedescriptors of exported files;
			       only the first is actually used unless we're
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
 * Check whether a client is allowed to connect. Works with an authorization
 * file which contains one line per machine, no wildcards.
 *
 * @param name IP address of client trying to connect (in human-readable form)
 * @return 0 - authorization refused, 1 - OK
 **/
int authorized_client(CLIENT *opts) {
	FILE *f ;
   
	char line[LINELEN]; 

	if ((f=fopen(opts->server->authname,"r"))==NULL) {
		msg4(LOG_INFO,"Can't open authorization file %s (%s).",
		     opts->server->authname,strerror(errno)) ;
		return 1 ; 
	}
  
	while (fgets(line,LINELEN,f)!=NULL) {
		if (strncmp(line,opts->clientname,strlen(opts->clientname))==0) {
			fclose(f);
			return 1;
		}
	}
	fclose(f) ;
	return 0 ;
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
	printf("Usage: port file_to_export [size][kKmM] [-l authorize_file] [-r] [-m] [-c] [-a timeout_sec]\n"
	       "\t-r|--read-only\t\tread only\n"
	       "\t-m|--multi-file\t\tmultiple file\n"
	       "\t-c|--copy-on-write\tcopy on write\n"
	       "\t-l|--authorize-file\tfile with list of hosts that are allowed to\n\t\t\t\tconnect.\n"
	       "\t-a|--idle-time\t\tmaximum idle seconds; server terminates when\n\t\t\t\tidle time exceeded\n\n"
	       "\tif port is set to 0, stdin is used (for running from inetd)\n"
	       "\tif file_to_export contains '%%s', it is substituted with the IP\n"
	       "\t\taddress of the machine trying to connect\n" );
}

/**
 * Parse the command line.
 *
 * @todo getopt() is a great thing, and easy to use. Also, we want to
 * create a configuration file which nbd-server will read. Maybe do (as in,
 * parse) that here.
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
		{0,0,0,0}
	};
	SERVER *serve;
	off_t es;
	size_t last;
	char suffix;

	serve=g_malloc(sizeof(SERVER));
	serve->hunksize=OFFT_MAX;
	while((c=getopt_long(argc, argv, "-a:cl:mr", long_options, &i))>=0) {
		switch (c) {
		case 1:
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
			serve->hunksize = 1*GIGA;
			serve->authname = default_authname;
			break;
		case 'c': 
			serve->flags |=F_COPYONWRITE;
		        break;
		case 'l':
			serve->authname=optarg;
			break;
		case 'a': 
			serve->timeout=strtol(optarg, NULL, 0);
			break;
		default:
			usage();
			exit(0);
			break;
		}
	}
	/* What's left: the port to export, the name of the to be exported
	 * file, and, optionally, the size of the file, in that order. */
	if(nonspecial<2) {
		usage();
		exit(EXIT_FAILURE);
	}
	return serve;
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
	int done=0;

	while(!done && (pid=waitpid(-1, &status, WNOHANG)) > 0) {
		if(WIFEXITED(status)) {
			msg3(LOG_INFO, "Child exited with %d", WEXITSTATUS(status));
			msg3(LOG_INFO, "pid is %d", pid);
			done=1;
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
 * @param export An open filedescriptor
 * @return the size of the file, or OFFT_MAX if detection was
 * impossible.
 **/
off_t size_autodetect(int export) {
	off_t es;
	unsigned long sectors;
	struct stat stat_buf;
	int error;

#ifdef HAVE_SYS_MOUNT_H
#ifdef HAVE_SYS_IOCTL_H
#ifdef BLKGETSIZE
	DEBUG("looking for export size with ioctl BLKGETSIZE\n");
	if (!ioctl(export, BLKGETSIZE, &sectors) && sectors) {
		es = (off_t)sectors * (off_t)512;
		return es;
	}
#endif /* BLKGETSIZE */
#endif /* HAVE_SYS_IOCTL_H */
#endif /* HAVE_SYS_MOUNT_H */

	DEBUG("looking for export size with fstat\n");
	stat_buf.st_size = 0;
	error = fstat(export, &stat_buf);
	if (!error) {
		if(stat_buf.st_size > 0)
			return (off_t)stat_buf.st_size;
        } else {
                err("fstat failed: %m");
        }

	DEBUG("looking for export size with lseek SEEK_END\n");
	es = lseek(export, (off_t)0, SEEK_END);
	if (es > ((off_t)0)) {
		return es;
        } else {
                DEBUG2("lseek failed: %d", errno==EBADF?1:(errno==ESPIPE?2:(errno==EINVAL?3:4)));
        }

	err("Could not find size of exported block device: %m");
	return OFFT_MAX;
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
 * @return The number of bytes actually written, or -1 in case of an error
 **/
int rawexpwrite(off_t a, char *buf, size_t len, CLIENT *client) {
	ssize_t res;

	myseek(g_array_index(client->export, int, (int)(a/client->server->hunksize)), a%client->server->hunksize);
	;
	res = write(g_array_index(client->export, int, (int)((off_t)a/(off_t)(client->server->hunksize))), buf, len);
	return (res < 0 || (size_t)res != len);
}

/**
 * Read an amount of bytes at a given offset from the right file. This
 * abstracts the read-side of the multiple files option.
 *
 * @param a The offset where the read should start
 * @param buf A buffer to read into
 * @param len The size of buf
 * @return The number of bytes actually read, or -1 in case of an
 * error.
 **/
int rawexpread(off_t a, char *buf, size_t len, CLIENT *client) {
	ssize_t res;

	myseek(g_array_index(client->export,int,(int)a/client->server->hunksize),
			a%client->server->hunksize);
	res = read(g_array_index(client->export,int,(int)a/client->server->hunksize), buf, len);
	return (res < 0 || (size_t)res != len);
}

/**
 * Read an amount of bytes at a given offset from the right file. This
 * abstracts the read-side of the copyonwrite stuff, and calls
 * rawexpread() with the right parameters to do the actual work.
 * @param a The offset where the read should start
 * @param buf A buffer to read into
 * @param len The size of buf
 * @return The number of bytes actually read, or -1 in case of an error
 **/
int expread(off_t a, char *buf, size_t len, CLIENT *client) {
	off_t rdlen, offset;
	off_t mapcnt, mapl, maph, pagestart;

	if (!(client->server->flags & F_COPYONWRITE))
		return rawexpread(a, buf, len, client);
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
			if(rawexpread(a, buf, rdlen, client)) return -1;
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
 * @return The number of bytes actually written, or -1 in case of an error
 **/
int expwrite(off_t a, char *buf, size_t len, CLIENT *client) {
	char pagebuf[DIFFPAGESIZE];
	off_t mapcnt,mapl,maph;
	off_t wrlen,rdlen; 
	off_t pagestart;
	off_t offset;

	if (!(client->server->flags & F_COPYONWRITE))
		return(rawexpwrite(a,buf,len, client)); 
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
			client->difmap[mapcnt]=client->difffilelen++ ;
			DEBUG3("Page %Lu is not here, we put it at %lu\n",
			       (unsigned long long)mapcnt,
			       (unsigned long)(client->difmap[mapcnt]));
			rdlen=DIFFPAGESIZE ;
			if (rdlen+pagestart%(client->server->hunksize) >
					(client->server->hunksize)) 
				rdlen=client->server->hunksize -
					(pagestart%client->server->hunksize);
			if (rawexpread(pagestart, pagebuf, rdlen, client))
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
 * @param net A socket to do the negotiation over
 **/
void negotiate(CLIENT *client) {
	char zeros[300];
	u64 size_host;

	memset(zeros, 0, 290);
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
 * @param net A network socket, connected to an nbd client
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
			if(client->server->flags & F_COPYONWRITE) {
				if (client->difmap) g_free(client->difmap) ;
                		if (client->difffile>=0) { 
                			close(client->difffile);
					unlink(client->difffilename);
					free(client->difffilename);
				}
			}
			go_on=FALSE;
			continue;
		}

		len = ntohl(request.len);

		if (request.magic != htonl(NBD_REQUEST_MAGIC))
			err("Not enough magic.");
		if (len > BUFSIZE-sizeof(struct nbd_reply))
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

		if (((ssize_t)((off_t)request.from + len) > client->exportsize) ||
		    ((client->server->flags & F_READONLY) && request.type)) {
			DEBUG("[RANGE!]");
			readit(client->net, buf, len);
			ERROR(client, reply);
			continue;
		}

		if (request.type==NBD_CMD_WRITE) {
			DEBUG("wr: net->buf, ");
			readit(client->net, buf, len);
			DEBUG("buf->exp, ");
			if ((client->server->flags & F_AUTOREADONLY) ||
					expwrite(request.from, buf, len,
						client)) {
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
 * Split a single exportfile into multiple ones, if that was asked.
 * @return 0 on success, -1 on failure
 * @param client information on the client which we want to split
 **/
int splitexport(CLIENT* client) {
	off_t i;
	int fhandle;

	client->export = g_array_new(TRUE, TRUE, sizeof(int));
	for (i=0; i<client->exportsize; i+=client->server->hunksize) {
		gchar *tmpname;

		if(client->server->flags & F_MULTIFILE) {
			tmpname=g_strdup_printf("%s.%d", client->exportname,
					(int)(i/client->server->hunksize));
		} else {
			tmpname=g_strdup(client->exportname);
		}
		DEBUG2( "Opening %s\n", tmpname );
		if((fhandle = open(tmpname, (client->server->flags & F_READONLY) ? O_RDONLY : O_RDWR)) == -1) {
			/* Read WRITE ACCESS was requested by media is only read only */
			client->server->flags |= F_AUTOREADONLY;
			client->server->flags |= F_READONLY;
			if((fhandle = open(tmpname, O_RDONLY)) == -1)
				err("Could not open exported file: %m");
		}
		g_array_insert_val(client->export,i/client->server->hunksize,fhandle);
		g_free(tmpname);
	}
	return 0;
}
int copyonwrite_prepare(CLIENT* client)
{
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
 * @param net A network socket connected to an nbd client
 **/
void serveconnection(CLIENT *client) {
	splitexport(client);

	if (!client->server->expected_size) {
		client->exportsize = size_autodetect(g_array_index(client->export,int,0));
	} else {
		/* Perhaps we should check first. Not now. */
		client->exportsize = client->server->expected_size;
	}
	if (client->exportsize > OFFT_MAX) {
		/* uhm, well... In a parallel universe, this *might* be
		 * possible... */
		err("Size of exported file is too big\n");
	}
	else {
		msg3(LOG_INFO, "size of exported file/device is %Lu", (unsigned long long)client->exportsize);
	}

	if (client->server->flags & F_COPYONWRITE) {
		copyonwrite_prepare(client);
	}

	setmysockopt(client->net);

	mainloop(client);
}

/**
 * Find the name of the file we have to serve. This will use g_strdup_printf
 * to put the IP address of the client inside a filename containing
 * "%s". That name is then written to client->exportname.
 *
 * @param net A socket connected to an nbd client
 * @param client information about the client. The IP address in human-readable
 * format will be written to a new char* buffer, the address of which will be
 * stored in client->clientname.
 **/
void set_peername(int net, CLIENT *client) {
	struct sockaddr_in addrin;
	int addrinlen = sizeof( addrin );
	char *peername ;

	if (getpeername(net, (struct sockaddr *) &addrin, (socklen_t *)&addrinlen) < 0)
		err("getsockname failed: %m");
	peername = inet_ntoa(addrin.sin_addr);
	client->exportname=g_strdup_printf(client->server->exportname, peername);

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
 * 	then do not daemonize, because we're doing inetd then.
 **/
#if !defined(NODAEMON) && !defined(NOFORK)
void daemonize(SERVER* serve) {
	FILE*pidf;

	if((serve->port)) {
		if(daemon(0,0)<0) {
			err("daemon");
		}
		snprintf(pidfname, sizeof(char)*255, "/var/run/nbd-server.%d.pid", serve->port);
		pidf=fopen(pidfname, "w");
		if(pidf) {
			fprintf(pidf,"%d", (int)getpid());
			fclose(pidf);
		} else {
			perror("fopen");
			fprintf(stderr, "Not fatal; continuing");
		}
	}
}
#else
#define daemonize(serve)
#endif /* !defined(NODAEMON) && !defined(NOFORK) */

/**
 * Connect a server's socket.
 *
 * @todo modularize this giant beast. Preferably with a chainsaw. Also,
 * it has no business starting mainloop(), through serveconnection(); it
 * should connect, and be done with it.
 *
 * @param serve the server we want to connect.
 **/
void setup_serve(SERVER* serve) {
	struct sockaddr_in addrin;
	struct sigaction sa;
	int addrinlen = sizeof(addrin);
	int fhandle;
	int sock_flags;
#ifndef sun
	int yes=1;
#else
	char yes='1';
#endif /* sun */

	if (strstr(serve->exportname, "%s") == NULL) {
		/**
		 * verify the existence of the block device that
		 * this server instance will export
		 **/
		DEBUG2( "Opening %s\n", serve->exportname );
		if ((fhandle = open(serve->exportname,
				    (serve->flags & F_READONLY) ? O_RDONLY : O_RDWR)) == -1) {
			err("Could not open exported file: %m");
		}
		/**
		 * if the exported file's size can't be detected	   
		 * size_autodetect() will exit()... and export can be
		 * considered invalid
		 **/
		size_autodetect(fhandle);
		close(fhandle);
	}	
	daemonize(serve);
	
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
	children=g_hash_table_new_full(g_int_hash, g_int_equal, NULL, destroy_pid_t);
}

/**
 * Loop through the available servers, and serve them.
 *
 * Actually, right now we only handle one server. Will change that for
 * 2.9.
 **/
int serveloop(SERVER* serve) {
	struct sockaddr_in addrin;
	socklen_t addrinlen=sizeof(addrin);
	int max_fd = serve->socket;
	fd_set read_fds;

	for(;;) {
		FD_ZERO(&read_fds);
		FD_SET(serve->socket, &read_fds);

		DEBUG("select, ");
		/* use to select to tell us when a connection is ready to be
		 * accepted */
		if (select(max_fd+1, &read_fds, NULL, NULL, NULL) <= 0) {
			if (errno == EINTR)
				continue;
			msg2(LOG_ERR,"select: %m");
			continue;
		}

		if (FD_ISSET(serve->socket, &read_fds)) {
			/* accept the new client connection */
			CLIENT *client;
			int net;
			pid_t *pid;			

			DEBUG("accept, ");
			if ((net = accept(serve->socket, (struct sockaddr *) &addrin, &addrinlen)) < 0) {
				if(errno!=EAGAIN) {
					msg2(LOG_ERR,"accept: %m");
				}
				continue;
			}

			client = g_malloc(sizeof(CLIENT));
			client->server=serve;
			client->exportsize=OFFT_MAX;
			client->net=net;
			set_peername(net, client);
			if (!authorized_client(client)) {
				msg2(LOG_INFO,"Unauthorized client");
				close(net);
				continue;
			}
			msg2(LOG_INFO,"Authorized client");
			pid=g_malloc(sizeof(pid_t));
#ifndef NOFORK
			if ((*pid=fork())<0) {
				msg3(LOG_INFO,"Could not fork (%s)",strerror(errno));
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
			close(serve->socket);
#endif // NOFORK
			msg2(LOG_INFO,"Starting to serve");
			serveconnection(client);
			return 0;
		}
	}
}

/**
 * Main entry point...
 **/
int main(int argc, char *argv[]) {
	SERVER* serve;
	GArray* servers;

	if (sizeof( struct nbd_request )!=28) {
		fprintf(stderr,"Bad size of structure. Alignment problems?\n");
		exit(-1) ;
	}

	logging();
	serve=cmdline(argc, argv);
	servers=g_array_new(TRUE, FALSE, sizeof(SERVER*));

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
	setup_serve(serve);
	serveloop(serve);
	return 0 ;
}
