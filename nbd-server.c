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
 * Version 2.7 - Better build system (not released (yet?)).
 * 11/02/2004 - Doxygenified the source, modularized it a bit. Needs a 
 * 	lot more work, but this is a start. Wouter Verhelst
 * 	<wouter@debian.org>
 */

/* Includes LFS defines, which defines behaviours of some of the following
 * headers, so must come before those */
#include "config.h"
#include "lfs.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

/* used in cliserv.h, so must come first */
#define MY_NAME "nbd_server"
#include "cliserv.h"

/** how much space for child PIDs we have by default. Dynamically
   allocated, and will be realloc()ed if out of space, so this should
   probably be fair for most situations. */
#define DEFAULT_CHILD_ARRAY 256

/** Logging macros, now nothing goes to syslog unless you say ISSERVER */
#ifdef ISSERVER
#define msg2(a,b) syslog(a,"%s", b)
#define msg3(a,b,c) syslog(a,"%s %s", b,c)
#define msg4(a,b,c,d) syslog(a,"%s %s %s", b,c,d)
#else
#define msg2(a,b) do { fprintf(stderr,"%s\n", b) ; } while(0) 
#define msg3(a,b,c) do { fprintf(stderr,"%s %s\n", b,c); } while(0) 
#define msg4(a,b,c,d) do { fprintf(stderr,"%s %s %s\n", b,c,d); } while(0)
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
 */
#define OFFT_MAX (((((off_t)1)<<((sizeof(off_t)-1)*8))-1)<<7)+127
#define LINELEN 256	  /**< Size of static buffer used to read the
			    authorization file (yuck) */
#define BUFSIZE (1024*1024) /**< Size of buffer that can hold requests */
#define GIGA (1*1024*1024*1024) /**< 1 Gigabyte. Used as hunksize when doing
				  the multiple file thingy */
#define DIFFPAGESIZE 4096 /**< diff file uses those chunks */
#define F_READONLY 1      /**< flag to tell us a file is readonly */
#define F_MULTIFILE 2	  /**< flag to tell us a file is exported using -m */
#define F_COPYONWRITE 4	  /**< flag to tell us a file is exported using copyonwrite */
char difffilename[1024]; /**< filename of the copy-on-write file. Doesn't belong here! */
unsigned int timeout = 0; /**< disconnect timeout */
int autoreadonly = 0; /**< 1 = switch to readonly if opening readwrite isn't
			possible */
char *auth_file="nbd_server.allow"; /**< authorization file */
char exportname2[1024]; /**< File I'm exporting, with virtualhost resolved */
off_t lastpoint = (off_t)-1;	/**< keep track of where we are in the file, to
				  avoid an lseek if possible */
char pagebuf[DIFFPAGESIZE];	/**< when doing copyonwrite, this is
				  used as a temporary buffer to store
				  the exported block in. @todo this is
				  a great example of namespace
				  pollution. Throw it out. */
unsigned int port;		/**< Port I'm listening at */
char *exportname;		/**< File I'm exporting */
off_t exportsize = OFFT_MAX;	/**< length of file I'm exporting */
off_t hunksize = OFFT_MAX;      /**< size of each exported file in case of -m */
int flags = 0;			/**< flags associated with this exported file */
int export[1024];/**< array of filedescriptors of exported files; only first is
		   used unless -m option is activated */ 
int difffile=-1; /**< filedescriptor for copyonwrite file */
u32 difffilelen=0 ; /**< number of pages in difffile */
u32 *difmap=NULL ; /**< Determine whether a block is in the original file
		     (difmap[block]==-1) or in the copyonwrite file (in which
		     case it contains the offset where it is to be found in the
		     copyonwrite file). @todo the kernel knows about sparse
		     files, we should use those instead. Should also be off_t
		     instead of u32; copyonwrite is probably broken wrt LFS */
char clientname[256] ;
int child_arraysize=DEFAULT_CHILD_ARRAY; /**< number of available slots for
					   child array */
pid_t *children; /**< child array */
char pidfname[256]; /**< name of our PID file */

/**
 * Variables associated with a copyonwrite server. Not yet used.
 **/
typedef struct {
	char* difffilename;  /**< filename of the copy-on-write file */
	int difffile;	     /**< filedescriptor of copyonwrite file. @todo
			       shouldn't this be an array too? (cfr
			       nbd_server_opts::export) Or make -m and -c
			       mutually exclusive */
	u32 difffilelen;     /**< number of pages in difffile */
	u32 *difmap;	     /**< see comment on the global difmap for this one */
} cow_opts;

/**
 * Variables associated with a server. Not yet used. @todo modify the code to
 * use an instance of this struct instead of the heap of global variables.
 **/
typedef struct {
	char* exportname;    /**< filename of the file we're exporting */
	unsigned int port;            /**< port we're exporting this file at */
	char* authname;      /**< filename of the authorization file */
	off_t exportsize;    /**< size of the file we're exporting */
	off_t hunksize;      /**< size of a hunk of an exported file */
	int flags;           /**< flags associated with this exported file */
	char* clientname;          /**< peer */
	unsigned int timeout;/**< how long a connection may be idle
			       (0=forever) */
	int export[1024];    /**< array of filedescriptors of exported files;
			       only the first is actually used unless we're
			       doing the multiple file option */
	cow_opts* cow;	     /**< only used if (flags | F_COPYONWRITE) (NULL
			       otherwise) */
} nbd_server_opts;

/**
 * Check whether a client is allowed to connect. Works with an authorization
 * file which contains one line per machine, no wildcards.
 *
 * @param name IP address of client trying to connect (in human-readable form)
 * @return 0 - authorization refused, 1 - OK
 **/
int authorized_client(char *name)
{
	FILE *f ;
   
	char line[LINELEN] ; 

	if ((f=fopen(auth_file,"r"))==NULL) {
		msg4(LOG_INFO,"Can't open authorization file %s (%s).",
		     auth_file,strerror(errno)) ;
		return 1 ; 
	}
  
	while (fgets(line,LINELEN,f)!=NULL) {
		if (strncmp(line,name,strlen(name))==0) {
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
inline void readit(int f, void *buf, size_t len)
{
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
inline void writeit(int f, void *buf, size_t len)
{
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
 * Parse the command line.
 *
 * @todo getopt() is a great thing, and easy to use. Also, we want to
 * create a configuration file which nbd-server will read. Maybe do (as in,
 * parse) that here.
 *
 * @param argc the argc argument to main()
 * @param argv the argv argument to main()
 **/
void cmdline(int argc, char *argv[])
{
	int i;

	if (argc < 3) {
		printf("This is nbd-server version " VERSION "\n");	
		printf("Usage: port file_to_export [size][kKmM] [-r] [-m] [-c] [-a timeout_sec]\n"
		       "	-r read only\n"
		       "	-m multiple file\n"
		       "	-c copy on write\n"
		       "        -l file with list of hosts that are allowed to connect.\n"
		       "        -a maximum idle seconds, terminates when idle time exceeded\n"
		       "	if port is set to 0, stdin is used (for running from inetd)\n"
		       "	if file_to_export contains '%%s', it is substituted with IP\n"
		       "		address of machine trying to connect\n" );
		exit(0);
	}
	port = atoi(argv[1]);
	for (i = 3; i < argc; i++) {
		if (*argv[i] == '-') {
			switch (argv[i][1]) {
			case 'r':
				flags |= F_READONLY;
				break;
			case 'm':
				flags |= F_MULTIFILE;
				hunksize = 1*GIGA;
				break;
			case 'c': flags |=F_COPYONWRITE;
			        break;
			case 'l':
				if (i+1<argc) {
					auth_file=argv[++i];
				} else {
					fprintf(stderr, "host list file requires an argument");
				}
				break;
			case 'a': 
				if (i+1<argc) {
					timeout = atoi(argv[i+1]);
					i++;
				} else {
					fprintf(stderr, "timeout requires argument\n");
					exit(1);
				}
			}
		} else {
			off_t es;
			size_t last = strlen(argv[i])-1;
			char suffix = argv[i][last];
			if (suffix == 'k' || suffix == 'K' ||
			    suffix == 'm' || suffix == 'M')
				argv[i][last] = '\0';
			es = (off_t)atol(argv[i]);
			switch (suffix) {
				case 'm':
				case 'M':  es <<= 10;
				case 'k':
				case 'K':  es <<= 10;
				default :  break;
			}
			exportsize = es;
		}
	}

	exportname = argv[2];
	if(exportname[0] != '/') {
		fprintf(stderr, "%s requires an absolute path name to the exported file\n", argv[0]);
		exit(EXIT_FAILURE);
	}
}

/**
 * Signal handler for SIGCHLD
 * @param s the signal we're handling (must be SIGCHLD, or something
 * is severely wrong)
 **/
void sigchld_handler(int s)
{
        int* status=NULL;
	int i;
	char buf[80];
	pid_t pid;

	while((pid=wait(status)) > 0) {
		if(WIFEXITED(status)) {
			memset(buf,'\0', 80);
			snprintf(buf, 79, "%d", WEXITSTATUS(status));
			msg3(LOG_INFO, "Child exited with ", buf);
		}
		for(i=0;children[i]!=pid&&i<child_arraysize;i++);
		if(i>=child_arraysize) {
			memset(buf, '\0', 80);
			snprintf(buf, 79, "%ld", (long)pid);
			msg3(LOG_INFO, "SIGCHLD received for an unknown child with PID ", buf);
		} else {
			children[i]=(pid_t)0;
			DEBUG2("Removing %d from the list of children", pid);
		}
	}
}

/**
 * Handle SIGTERM and dispatch it to our children
 * @param s the signal we're handling (must be SIGTERM, or something
 * is severely wrong).
 **/
void sigterm_handler(int s) {
	int i;
	int parent=0;

	for(i=0;i<child_arraysize;i++) {
		if(children[i]) {
			kill(children[i], s);
			parent=1;
		}
	}

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
off_t size_autodetect(int export)
{
	off_t es;
	u32 es32;
	struct stat stat_buf;
	int error;

#ifdef HAVE_SYS_MOUNT_H
#ifdef HAVE_SYS_IOCTL_H
#ifdef BLKGETSIZE
	DEBUG("looking for export size with ioctl BLKGETSIZE\n");
	if (!ioctl(export, BLKGETSIZE, &es32) && es32) {
		es = (off_t)es32 * (off_t)512;
		return es;
	}
#endif /* BLKGETSIZE */
#endif /* HAVE_SYS_IOCTL_H */
#endif /* HAVE_SYS_MOUNT_H */

	DEBUG("looking for export size with fstat\n");
	stat_buf.st_size = 0;
	error = fstat(export, &stat_buf);
	if (!error && stat_buf.st_size > 0) {
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
 * Seek to a position in a file, unless we're already there.
 * @param handle a filedescriptor
 * @param a position to seek to
 **/
void maybeseek(int handle, off_t a) {
	if (a < 0 || a > exportsize) {
		err("Can not happen\n");
	}
	if (lastpoint != a) {
		if (lseek(handle, a, SEEK_SET) < 0) {
			err("Can not seek locally!\n");
		}
		lastpoint = a;
	} else {
		DEBUG("S");
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
int rawexpwrite(off_t a, char *buf, size_t len)
{
	ssize_t res;

	maybeseek(export[a/hunksize], a%hunksize);
	res = write(export[a/hunksize], buf, len);
	return (res < 0 || (size_t)res != len);
}

/**
 * seek to a position in a file, no matter what. Used when using maybeseek is a
 * bad idea (for instance, because we're reading the copyonwrite file instead
 * of the exported file).
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
 * Read an amount of bytes at a given offset from the right file. This
 * abstracts the read-side of the multiple files option.
 *
 * @param a The offset where the read should start
 * @param buf A buffer to read into
 * @param len The size of buf
 * @return The number of bytes actually read, or -1 in case of an
 * error.
 **/
int rawexpread(off_t a, char *buf, size_t len)
{
	ssize_t res;

	maybeseek(export[a/hunksize], a%hunksize);
	res = read(export[a/hunksize], buf, len);
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
int expread(off_t a, char *buf, size_t len)
{
	off_t rdlen, offset;
	off_t mapcnt, mapl, maph, pagestart;
 
	if (!(flags & F_COPYONWRITE))
		return rawexpread(a, buf, len);
	DEBUG3("Asked to read %d bytes at %Lu.\n", len, (unsigned long long)a);

	mapl=a/DIFFPAGESIZE; maph=(a+len-1)/DIFFPAGESIZE;

	for (mapcnt=mapl;mapcnt<=maph;mapcnt++) {
		pagestart=mapcnt*DIFFPAGESIZE;
		offset=a-pagestart;
		rdlen=(0<DIFFPAGESIZE-offset && len<(size_t)(DIFFPAGESIZE-offset)) ?
			len : (size_t)DIFFPAGESIZE-offset;
		if (difmap[mapcnt]!=(u32)(-1)) { /* the block is already there */
			DEBUG3("Page %Lu is at %lu\n", (unsigned long long)mapcnt,
			       (unsigned long)difmap[mapcnt]);
			myseek(difffile, difmap[mapcnt]*DIFFPAGESIZE+offset);
			if (read(difffile, buf, rdlen) != rdlen) return -1;
		} else { /* the block is not there */
			DEBUG2("Page %Lu is not here, we read the original one\n",
			       (unsigned long long)mapcnt);
			return rawexpread(a, buf, rdlen);
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
int expwrite(off_t a, char *buf, size_t len)
{
	off_t mapcnt,mapl,maph ;
	off_t wrlen,rdlen ; 
	off_t pagestart ;
	off_t offset ;

	if (!(flags & F_COPYONWRITE))
		return(rawexpwrite(a,buf,len)); 
	DEBUG3("Asked to write %d bytes at %Lu.\n", len, (unsigned long long)a);

	mapl=a/DIFFPAGESIZE ; maph=(a+len-1)/DIFFPAGESIZE ;

	for (mapcnt=mapl;mapcnt<=maph;mapcnt++) {
		pagestart=mapcnt*DIFFPAGESIZE ;
		offset=a-pagestart ;
		wrlen=(0<DIFFPAGESIZE-offset && len<(size_t)(DIFFPAGESIZE-offset)) ?
			len : (size_t)DIFFPAGESIZE-offset;

		if (difmap[mapcnt]!=(u32)(-1)) { /* the block is already there */
			DEBUG3("Page %Lu is at %lu\n", (unsigned long long)mapcnt,
			       (unsigned long)difmap[mapcnt]) ;
			myseek(difffile,difmap[mapcnt]*DIFFPAGESIZE+offset) ;
			if (write(difffile, buf, wrlen) != wrlen) return -1 ;
		} else { /* the block is not there */
			myseek(difffile,difffilelen*DIFFPAGESIZE) ;
			difmap[mapcnt]=difffilelen++ ;
			DEBUG3("Page %Lu is not here, we put it at %lu\n",
			       (unsigned long long)mapcnt,
			       (unsigned long)difmap[mapcnt]);
			rdlen=DIFFPAGESIZE ;
			if (rdlen+pagestart%hunksize>hunksize) 
				rdlen=hunksize-(pagestart%hunksize) ;
			if (rawexpread(pagestart,pagebuf,rdlen)) return -1 ;
			memcpy(pagebuf+offset,buf,wrlen) ;
			if (write(difffile,pagebuf,DIFFPAGESIZE)!=DIFFPAGESIZE) return -1 ;
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
void negotiate(int net) {
	char zeros[300];
	u64 size_host;

	memset(zeros, 0, 290);
	if (write(net, INIT_PASSWD, 8) < 0)
		err("Negotiation failed: %m");
	cliserv_magic = htonll(cliserv_magic);
	if (write(net, &cliserv_magic, sizeof(cliserv_magic)) < 0)
		err("Negotiation failed: %m");
	size_host = htonll((u64)exportsize);
	if (write(net, &size_host, 8) < 0)
		err("Negotiation failed: %m");
	if (write(net, zeros, 128) < 0)
		err("Negotiation failed: %m");
}

/** sending macro; not really required. Uses variables in the local
 * scope of mainloop(). Get rid of it. */
#define SEND writeit( net, &reply, sizeof( reply ));
/** error macro; not sure whether we really need this. Uses variables
 * in the local scope of mainloop(). Get rid of this beast. */
#define ERROR { reply.error = htonl(-1); SEND; reply.error = 0; lastpoint = -1; }
/**
 * Serve a file to a single client.
 *
 * @todo This beast needs to be split up in many tiny little manageable
 * pieces. Preferably with a chainsaw.
 *
 * @param net A network socket, connected to an nbd client
 * @return never
 **/
int mainloop(int net)
{
	struct nbd_request request;
	struct nbd_reply reply;
#ifdef DODBG
	int i = 0;
#endif
	negotiate(net);
	DEBUG("Entering request loop!\n");
	reply.magic = htonl(NBD_REPLY_MAGIC);
	reply.error = 0;
	while (1) {
		char buf[BUFSIZE];
		size_t len;
#ifdef DODBG
		i++;
		printf("%d: ", i);
#endif
		if (timeout) 
			alarm(timeout);
		readit(net, &request, sizeof(request));
		request.from = ntohll(request.from);
		request.type = ntohl(request.type);

		/* Disconnect request. 2.6 nbd.h defines NBD_CMD_DISC, which we
		 * will use (again) at some point in the future, but many
		 * people are still using 2.4-based systems, and they need to
		 * be able to compile as well.*/
		if (request.type==2) {
		  if (difmap) free(difmap) ;
                  if (difffile>=0) { 
                     close(difffile) ; unlink(difffilename) ; }
		  err("Disconnect request received.") ;
		}

		len = ntohl(request.len);

		if (request.magic != htonl(NBD_REQUEST_MAGIC))
			err("Not enough magic.");
		if (len > BUFSIZE)
			err("Request too big!");
#ifdef DODBG
		printf("%s from %Lu (%Lu) len %d, ", request.type ? "WRITE" :
				"READ", (unsigned long long)request.from,
				(unsigned long long)request.from / 512, len);
#endif
		memcpy(reply.handle, request.handle, sizeof(reply.handle));
		if ((request.from + len) > (OFFT_MAX)) {
		  DEBUG("[Number too large!]");
		  ERROR;
		  continue;
		}

		if (((ssize_t)((off_t)request.from + len) > exportsize) ||
		    ((flags & F_READONLY) && request.type)) {
			DEBUG("[RANGE!]");
			ERROR;
			continue;
		}

		if (request.type==1) {	/* WRITE */
			DEBUG("wr: net->buf, ");
			readit(net, buf, len);
			DEBUG("buf->exp, ");
			if ((autoreadonly == 1) || expwrite(request.from, buf, len)) {
				DEBUG("Write failed: %m" );
				ERROR;
				continue;
			}
			lastpoint += len;
			SEND;
			DEBUG("OK!\n");
			continue;
		}
		/* READ */

		DEBUG("exp->buf, ");
		if (expread(request.from, buf + sizeof(struct nbd_reply), len)) {
		 	lastpoint = -1;
			DEBUG("Read failed: %m");
			ERROR;
			continue;
		}
		lastpoint += len;

		DEBUG("buf->net, ");
		memcpy(buf, &reply, sizeof(struct nbd_reply));
		writeit(net, buf, len + sizeof(struct nbd_reply));
		DEBUG("OK!\n");
	}
}

/**
 * Split a single exportfile into multiple ones, if that was asked.
 * @return 0 on success, -1 on failure
 **/
int splitexport(void) {
	off_t i ;

	for (i=0; i<exportsize; i+=hunksize) {
		char exportname3[1024];

		if(flags & F_MULTIFILE) {
			snprintf(exportname3, 1024, "%s.%d", exportname2, (int)(i/hunksize));
		} else {
			strncpy(exportname3, exportname2, 1024);
		}
		exportname3[1023]='\0';
		printf( "Opening %s\n", exportname3 );
		if ((export[i/hunksize] = open(exportname3, (flags & F_READONLY) ? O_RDONLY : O_RDWR)) == -1) {
			/* Read WRITE ACCESS was requested by media is only read only */
			autoreadonly = 1;
			flags |= F_READONLY;
			if ((export[i/hunksize] = open(exportname3, O_RDONLY)) == -1) 
				err("Could not open exported file: %m");
		}
	}

	if (flags & F_COPYONWRITE) {
		snprintf(difffilename, 1024, "%s-%s-%d.diff",exportname2,clientname,
			(int)getpid()) ;
		difffilename[1023]='\0';
		msg3(LOG_INFO,"About to create map and diff file %s",difffilename) ;
		difffile=open(difffilename,O_RDWR | O_CREAT | O_TRUNC,0600) ;
		if (difffile<0) err("Could not create diff file (%m)") ;
		if ((difmap=calloc(exportsize/DIFFPAGESIZE,sizeof(u32)))==NULL)
			err("Could not allocate memory") ;
		for (i=0;i<exportsize/DIFFPAGESIZE;i++) difmap[i]=(u32)-1 ;
	}

	return 0;
}

/**
 * Serve a connection. 
 *
 * @todo allow for multithreading, perhaps use libevent.
 *
 * @param net A network socket connected to an nbd client
 **/
void serveconnection(int net) {
	char buf[80];
	splitexport();
	if (exportsize == OFFT_MAX) {
		exportsize = size_autodetect(export[0]);
	}
	if (exportsize > OFFT_MAX) {
		err("Size of exported file is too big\n");
	}
	else {
		memset(buf, '\0', 80);
		snprintf(buf, 79, "%Lu", (unsigned long long)exportsize);
		msg3(LOG_INFO, "size of exported file/device is ", buf);
	}

	setmysockopt(net);

	mainloop(net);
}

/**
 * Find the name of the file we have to serve. This will use snprintf()
 * to put the IP address of the client inside a filename containing
 * "%s". That name is then written to exportname2
 *
 * @param net A socket connected to an nbd client
 * @param clientname a buffer which must be at least 255+1 bytes long;
 * the IP address (in human-readable format) will be copied in there.
 **/
void set_peername(int net,char *clientname)
{
	struct sockaddr_in addrin;
	int addrinlen = sizeof( addrin );
	char *peername ;

	if (getpeername( net, (struct sockaddr *) &addrin, &addrinlen ) < 0)
		err("getsockname failed: %m");
	peername = inet_ntoa(addrin.sin_addr);
	snprintf(exportname2, 1024, exportname, peername);
	exportname2[1023]='\0';

	msg4(LOG_INFO, "connect from %s, assigned file is %s", 
	     peername, exportname2);
	strncpy(clientname,peername,255) ;
}

/**
 * Connect the socket, and start to serve. This function will fork()
 * if a connection from an authorized client is received, and will
 * start mainloop().
 *
 * @todo modularize this giant beast. Preferably with a chainsaw. Also,
 * it has no business starting mainloop(); it should connect, and be
 * done with it.
 *
 * @param port the port where we will listen
 **/
void connectme(unsigned int port)
{
	struct sockaddr_in addrin;
	struct sigaction sa;
	int addrinlen = sizeof(addrin);
	int net, sock, newpid, i;
#ifndef sun
	int yes=1;
#else
	char yes='1';
#endif /* sun */
#ifndef NODAEMON
#ifndef NOFORK
	FILE*pidf;

	if(port) {
		if(daemon(0,0)<0) {
			err("daemon");
		}
		snprintf(pidfname, sizeof(char)*255, "/var/run/nbd-server.%d.pid", port);
		pidf=fopen(pidfname, "w");
		if(pidf) {
			fprintf(pidf,"%d", (int)getpid());
			fclose(pidf);
		} else {
			perror("fopen");
			fprintf(stderr, "Not fatal; continuing");
		}
	}
#endif /* NOFORK */
#endif /* NODAEMON */

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		err("socket: %m");

	/* lose the pesky "Address already in use" error message */
	if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) {
	        err("setsockopt SO_REUSEADDR");
	}
	if (setsockopt(sock,SOL_SOCKET,SO_KEEPALIVE,&yes,sizeof(int)) == -1) {
		err("setsockopt SO_KEEPALIVE");
	}

	DEBUG("Waiting for connections... bind, ");
	addrin.sin_family = AF_INET;
	addrin.sin_port = htons(port);
	addrin.sin_addr.s_addr = 0;
	if (bind(sock, (struct sockaddr *) &addrin, addrinlen) < 0)
		err("bind: %m");
	DEBUG("listen, ");
	if (listen(sock, 1) < 0)
		err("listen: %m");
	DEBUG("accept, ");
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
	children=malloc(sizeof(pid_t)*child_arraysize);
	memset(children, 0, sizeof(pid_t)*DEFAULT_CHILD_ARRAY);
	for(;;) { /* infinite loop */
		if ((net = accept(sock, (struct sockaddr *) &addrin, &addrinlen)) < 0)
			err("accept: %m");
		
		set_peername(net,clientname);
		if (!authorized_client(clientname)) {
			msg2(LOG_INFO,"Unauthorized client") ;
			close(net) ;
			continue ;
		}
		msg2(LOG_INFO,"Authorized client") ;
		for(i=0;children[i]&&i<child_arraysize;i++);
		if(i>=child_arraysize) {
			pid_t*ptr;

			ptr=realloc(children, sizeof(pid_t)*child_arraysize);
			if(ptr) {
				children=ptr;
				memset(children+child_arraysize, 0, sizeof(pid_t)*DEFAULT_CHILD_ARRAY);
				i=child_arraysize+1;
				child_arraysize+=DEFAULT_CHILD_ARRAY;
			} else {
				msg2(LOG_INFO,"Not enough memory to store child PID");
				close(net);
				continue;
			}
		}
#ifndef NOFORK
		if ((children[i]=fork())<0) {
			msg3(LOG_INFO,"Could not fork (%s)",strerror(errno)) ;
			close(net) ;
			continue ;
		}
		if (children[i]>0) { /* parent */
			close(net) ; continue ; }
		/* child */
		realloc(children,0);
		child_arraysize=0;
		close(sock) ;
#endif // NOFORK
		msg2(LOG_INFO,"Starting to serve") ;
		serveconnection(net) ;        
	}
}

/**
 * Main entry point...
 **/
int main(int argc, char *argv[])
{
	if (sizeof( struct nbd_request )!=28) {
		fprintf(stderr,"Bad size of structure. Alignment problems?\n");
		exit(-1) ;
	}
	logging();
	cmdline(argc, argv);
	
	if (!port) return 1 ;
	connectme(port); /* serve infinitely */
	return 0 ;
}

