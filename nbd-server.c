/*
 * Network Block Device - server
 *
 * Copyright 1996-1998 Pavel Machek, distribute under GPL
 *  <pavel@atrey.karlin.mff.cuni.cz>
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
 */

#define VERSION "2.0"
#define GIGA (1*1024*1024*1024)

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

#define _IO(a,b)
// #define ISSERVER
#define MY_NAME "nbd_server"

/* Authorization file should contain lines with IP addresses of 
   clients authorized to use the server. If it does not exist,
   access is permitted. */
#define AUTH_FILE "nbd_server.allow"

#include "cliserv.h"
#undef _IO
/* Deep magic: ioctl.h defines _IO macro (at least on linux) */


/* Debugging macros, now nothing goes to syslog unless you say ISSERVER */
#ifdef ISSERVER
#define msg2(a,b) syslog(a,b)
#define msg3(a,b,c) syslog(a,b,c)
#define msg4(a,b,c,d) syslog(a,b,c,d)
#else
#define msg2(a,b) do { fprintf(stderr,b) ; fputs("\n",stderr) ; } while(0) 
#define msg3(a,b,c) do { fprintf(stderr,b,c); fputs("\n",stderr) ; } while(0) 
#define msg4(a,b,c,d) do { fprintf(stderr,b,c,d); fputs("\n",stderr) ; } while(0)
#endif


#include <sys/ioctl.h>
#include <sys/mount.h>		/* For BLKGETSIZE */

#ifdef	FS_32BIT
typedef u32		fsoffset_t;
#define htonll		htonl
#define ntohll		ntohl
#else
typedef u64		fsoffset_t;
#endif


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

#if	defined(HAVE_LLSEEK) && !defined(sun)
/* Solaris already has llseek defined in unistd.h */
extern long long llseek(unsigned int, long long, unsigned int);
#endif

void serveconnection(int net);
void set_peername(int net,char *clientname);

#define LINELEN 256 
char difffilename[256];
unsigned int timeout = 0;

int authorized_client(char *name)
/* 0 - authorization refused, 1 - OK 
  authorization file contains one line per machine, no wildcards
*/
{ FILE *f ;
   
  char line[LINELEN] ; 

  if ((f=fopen(AUTH_FILE,"r"))==NULL)
    { msg4(LOG_INFO,"Can't open authorization file %s (%s).",
	   AUTH_FILE,strerror(errno)) ;
      return 1 ; 
    }
  
  while (fgets(line,LINELEN,f)!=NULL) {
    if (strncmp(line,name,strlen(name))==0) { fclose(f)  ; return 1 ; }
  }
  fclose(f) ;
  return 0 ;
}


inline void readit(int f, void *buf, int len)
{
	int res;
	while (len > 0) {
		DEBUG("*");
		if ((res = read(f, buf, len)) <= 0)
			err("Read failed: %m");
		len -= res;
		buf += res;
	}
}

inline void writeit(int f, void *buf, int len)
{
	int res;
	while (len > 0) {
		DEBUG("+");
		if ((res = write(f, buf, len)) <= 0)
			err("Write failed: %m");
		len -= res;
		buf += res;
	}
}

int port;			/* Port I'm listening at */
char *exportname;		/* File I'm exporting */
fsoffset_t exportsize = (fsoffset_t)-1;	/* ...and its length */
fsoffset_t hunksize = (fsoffset_t)-1;
int flags = 0;
int export[1024];
int difffile=-1 ;
u32 difffilelen=0 ; /* number of pages in difffile */
u32 *difmap=NULL ;
char clientname[256] ;


#define DIFFPAGESIZE 4096 /* diff file uses those chunks */

#define F_READONLY 1
#define F_MULTIFILE 2 
#define F_COPYONWRITE 4

void cmdline(int argc, char *argv[])
{
	int i;

	if (argc < 3) {
		printf("This is nbd-server version " VERSION "\n");	
		printf("Usage: port file_to_export [size][kKmM] [-r] [-m] [-c] [-a timeout_sec]\n"
		       "	-r read only\n"
		       "	-m multiple file\n"
		       "	-c copy on write\n"
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
			fsoffset_t es;
			int last = strlen(argv[i])-1;
			char suffix = argv[i][last];
			if (suffix == 'k' || suffix == 'K' ||
			    suffix == 'm' || suffix == 'M')
				argv[i][last] = '\0';
			es = (fsoffset_t)atol(argv[i]);
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
}

void connectme(int port)
{
	struct sockaddr_in addrin;
	int addrinlen = sizeof(addrin);
	int net, sock, newpid;
#ifndef sun
	int yes=1;
#else
	char yes='1';
#endif

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		err("socket: %m");

	/* lose the pesky "Address already in use" error message */
	if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) {
	        err("setsockopt");
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
	for(;;) { /* infinite loop */
	  if ((net = accept(sock, (struct sockaddr *) &addrin, &addrinlen)) < 0)
	    err("accept: %m");

	  set_peername(net,clientname) ;
	  if (!authorized_client(clientname)) {
	    msg2(LOG_INFO,"Unauthorized client") ;
	    close(net) ;
	    continue ;
	  }
	  msg2(LOG_INFO,"Authorized client") ;
	  if ((newpid=fork())<0) {
	    msg3(LOG_INFO,"Could not fork (%s)",strerror(errno)) ;
	    close(net) ;
	    continue ;
	  }
	  if (newpid>0) { /* parent */
	    close(net) ; continue ; }
	  /* child */
	  close(sock) ;
	  msg2(LOG_INFO,"Starting to serve") ;
	  serveconnection(net) ;        
	}
}

#define SEND writeit( net, &reply, sizeof( reply ));
#define ERROR { reply.error = htonl(-1); SEND; reply.error = 0; lastpoint = -1; }

fsoffset_t lastpoint = (fsoffset_t)-1;

void maybeseek(int handle, fsoffset_t a)
{
	if (a > exportsize)
		err("Can not happen\n");
	if (lastpoint != a) {
#if	defined(HAVE_LLSEEK) && !defined(FS_32BIT)
		if (llseek(handle, a, SEEK_SET) < 0)
#else
		if (lseek(handle, (long)a, SEEK_SET) < 0)
#endif
			err("Can not seek locally!\n");
		lastpoint = a;
	} else {
		DEBUG("@");
	}
}

void myseek(int handle,fsoffset_t a)
{
#if HAVE_LLSEEK && !defined(FS_32BIT)
  if (llseek(handle, a, SEEK_SET) < 0)
#else
  if (lseek(handle, (long)a, SEEK_SET) < 0)
#endif 
    err("Can not seek locally!\n");
}

char pagebuf[DIFFPAGESIZE] ;


int rawexpread(fsoffset_t a, char *buf, int len)
{
  maybeseek(export[a/hunksize], a%hunksize);
  return (read(export[a/hunksize], buf, len) != len);
}

int expread(fsoffset_t a, char *buf, int len)
{
	int rdlen, offset;
	fsoffset_t mapcnt, mapl, maph, pagestart;
 
  if (flags & F_COPYONWRITE) {
    DEBUG3("Asked to read %d bytes at %Lu.\n", len, (unsigned long long)a);

    mapl=a/DIFFPAGESIZE ; maph=(a+len-1)/DIFFPAGESIZE ;

    for (mapcnt=mapl;mapcnt<=maph;mapcnt++) {
      pagestart=mapcnt*DIFFPAGESIZE ;
      offset=a-pagestart ;
      rdlen=(len<DIFFPAGESIZE-offset) ? len : DIFFPAGESIZE-offset ;
      if (difmap[mapcnt]!=(u32)(-1)) { /* the block is already there */
	DEBUG3("Page %Lu is at %lu\n", (unsigned long long)mapcnt,
			(unsigned long)difmap[mapcnt]);
	myseek(difffile,difmap[mapcnt]*DIFFPAGESIZE+offset) ;
	if (read(difffile, buf, rdlen) != rdlen) return -1 ;
      } else { /* the block is not there */
	DEBUG2("Page %Lu is not here, we read the original one\n",
			(unsigned long long)mapcnt) ;
	if (rawexpread(a,buf,rdlen)) return -1 ;
      }
      len-=rdlen ; a+=rdlen ; buf+=rdlen ;
    }
  } else return rawexpread(a,buf,len) ;
  return 0 ;
}

int rawexpwrite(fsoffset_t a, char *buf, int len)
{
	maybeseek(export[a/hunksize], a%hunksize);
	return (write(export[a/hunksize], buf, len) != len);
}


int expwrite(fsoffset_t a, char *buf, int len)
{  u32 mapcnt,mapl,maph ; int wrlen,rdlen ; 
   fsoffset_t pagestart ; int offset ;

  if (flags & F_COPYONWRITE) {
    DEBUG3("Asked to write %d bytes at %Lu.\n", len, (unsigned long long)a);

    mapl=a/DIFFPAGESIZE ; maph=(a+len-1)/DIFFPAGESIZE ;

    for (mapcnt=mapl;mapcnt<=maph;mapcnt++) {
      pagestart=mapcnt*DIFFPAGESIZE ;
      offset=a-pagestart ;
      wrlen=(len<DIFFPAGESIZE-offset) ? len : DIFFPAGESIZE-offset ;

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
  } else return(rawexpwrite(a,buf,len)); 
  return 0 ;
}

int mainloop(int net)
{
	struct nbd_request request;
	struct nbd_reply reply;
	char zeros[300];
	int i = 0;
	fsoffset_t size_host;

	memset(zeros, 0, 290);
	if (write(net, INIT_PASSWD, 8) < 0)
		err("Negotiation failed: %m");
#ifndef	FS_32BIT
	cliserv_magic = htonll(cliserv_magic);
#endif
	if (write(net, &cliserv_magic, sizeof(cliserv_magic)) < 0)
		err("Negotiation failed: %m");
	size_host = htonll(exportsize);
#ifdef	FS_32BIT
        if (write(net, zeros, 4) < 0 || write(net, &size_host, 4) < 0)
#else
	if (write(net, &size_host, 8) < 0)
#endif
		err("Negotiation failed: %m");
	if (write(net, zeros, 128) < 0)
		err("Negotiation failed: %m");

	DEBUG("Entering request loop!\n");
	reply.magic = htonl(NBD_REPLY_MAGIC);
	reply.error = 0;
	while (1) {
#define BUFSIZE (1024*1024)
		char buf[BUFSIZE];
		int len;

#ifdef DODBG
		i++;
		printf("%d: ", i);
#endif

		if (timeout) 
			alarm(timeout);
		readit(net, &request, sizeof(request));
		request.from = ntohll(request.from);
		request.type = ntohl(request.type);

		if (request.type==2) { /* Disconnect request */
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
		if (((request.from + len) > exportsize) ||
		    ((flags & F_READONLY) && request.type)) {
			DEBUG("[RANGE!]");
			ERROR;
			continue;
		}
		if (request.type==1) {	/* WRITE */
			DEBUG("wr: net->buf, ");
			readit(net, buf, len);
			DEBUG("buf->exp, ");
			if (expwrite(request.from, buf, len)) {
				DEBUG("Write failed: %m" );
				ERROR;
				continue;
			}
			lastpoint += len;
			SEND;
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

char exportname2[1024];

void set_peername(int net,char *clientname)
{
	struct sockaddr_in addrin;
	int addrinlen = sizeof( addrin );
	char *peername ;

	if (getpeername( net, (struct sockaddr *) &addrin, &addrinlen ) < 0)
		err("getsockname failed: %m");
	peername = inet_ntoa(addrin.sin_addr);
	sprintf(exportname2, exportname, peername);

	msg4(LOG_INFO, "connect from %s, assigned file is %s", peername, exportname2);
	strncpy(clientname,peername,255) ;
}

fsoffset_t size_autodetect(int export)
{
	fsoffset_t es;
	u32 es32;
	struct stat stat_buf;
	int error;

	DEBUG("looking for export size with lseek SEEK_END\n");
	es = (fsoffset_t)lseek(export, 0, SEEK_END);
	if ((signed long long)es > 0LL)
		return es;

	DEBUG("looking for export size with fstat\n");
	stat_buf.st_size = 0;
	error = fstat(export, &stat_buf);
	if (!error && stat_buf.st_size > 0)
		return (fsoffset_t)stat_buf.st_size;

#ifdef BLKGETSIZE
	DEBUG("looking for export size with ioctl BLKGETSIZE\n");
	if (!ioctl(export, BLKGETSIZE, &es32) && es32) {
		es = (fsoffset_t)es32 * (fsoffset_t)512;
		return es;
	}
#endif
	err("Could not find size of exported block device: %m");
	return (fsoffset_t)-1;
}

int main(int argc, char *argv[])
{
	int net;
	fsoffset_t i;

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


void serveconnection(int net) 
{   
  u64 i ;

  for (i=0; i<exportsize; i+=hunksize) {
    char exportname3[1024];
    
    sprintf(exportname3, exportname2, i/hunksize);
    printf( "Opening %s\n", exportname3 );
    if ((export[i/hunksize] = open(exportname3, (flags & F_READONLY) ? O_RDONLY : O_RDWR)) == -1)
      err("Could not open exported file: %m");
    }
	
    if (exportsize == (fsoffset_t)-1) {
	exportsize = size_autodetect(export[0]);
    }
    if (exportsize > ((fsoffset_t)-1 >> 1)) {
#ifdef HAVE_LLSEEK
	if ((exportsize >> 10) > ((fsoffset_t)-1 >> 1))
		msg3(LOG_INFO, "size of exported file/device is %LuMB",
				(unsigned long long)(exportsize >> 20));
	else
		msg3(LOG_INFO, "size of exported file/device is %LuKB",
				(unsigned long long)(exportsize >> 10));
    }
#else
	err("Size of exported file is too big\n");
    }
#endif
    else
	msg3(LOG_INFO, "size of exported file/device is %Lu",
			(unsigned long long)exportsize);

    if (flags & F_COPYONWRITE) {
      sprintf(difffilename,"%s-%s-%d.diff",exportname2,clientname,
	      (int)getpid()) ;
      msg3(LOG_INFO,"About to create map and diff file %s",difffilename) ;
      difffile=open(difffilename,O_RDWR | O_CREAT | O_TRUNC,0600) ;
      if (difffile<0) err("Could not create diff file (%m)") ;
      if ((difmap=calloc(exportsize/DIFFPAGESIZE,sizeof(u32)))==NULL)
	  err("Could not allocate memory") ;
      for (i=0;i<exportsize/DIFFPAGESIZE;i++) difmap[i]=(u32)-1 ;	  
    }
    
    setmysockopt(net);
      
    mainloop(net);
}
