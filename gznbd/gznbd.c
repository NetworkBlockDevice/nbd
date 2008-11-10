/* 
   (c) Marc Welz 2000, released under GPL, tested under Linux 2.2.17

   Most of the stuff cribbed from the nbd package written by Pavel Machek

   Unfortunately quite slow since zlib has to decompress all the stuff between
   seeks, so only suited to smaller files
   
   Could be a neat way to do userland encryption/steganography if you have 
   a crypto library which has a stdiolike interface to replace zlib

   Usage

     dd if=/dev/zero of=/tmp/image bs=1024 count=1024
     mke2fs -f /tmp/image
     mount -o loop /tmp/image /mnt/
     cp /bin/ls /mnt/
     umount /mnt
     sync
     gzip -9 /tmp/image
     gznbd /dev/nbd0 /tmp/image.gz

   gznbd does not background, from another terminal type

     mount -o ro,nocheck /dev/nbd0 /mnt/
     cd /mnt
     ls
     df

   ro is important, since writes will fail horribly and nochecks
   speeds the mount up nicely

 */

#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

/* asm/types defines __u??, at least on my system */
#include <asm/types.h>

#define MY_NAME "gznbd"

/* these headers take care of endianness */
#include "../config.h"
#include "../cliserv.h"

#define BLOCK 1024

/* don't ask me why this value, I only copied it */
#define CHUNK BLOCK*20


int main(int argc, char **argv)
{
  int pr[2];
  int sk;
  int nbd;
  gzFile *gz;
  int gzerr;

  char chunk[CHUNK];
  struct nbd_request request;
  struct nbd_reply reply;

  u64 size;
  u64 from;
  u32 len;

  if(argc<3){
    printf("Usage: %s nbdevice gzfile [size]\n",argv[0]);
    exit(1);
  }

  gz=gzopen(argv[2], "rb");
  if(gz==NULL){
    fprintf(stderr,"%s: unable open compressed file %s\n",argv[0],argv[2]);
    exit(1);
  }

  if(argc>3){
    size=atol(argv[3]);
    if((size==0)||(size%BLOCK)){
      fprintf(stderr,"%s: %s does not appear to be a valid size\n",argv[0],argv[3]);
      exit(1);
    }
    printf("%s: file=%s, size=%Ld\n",argv[0],argv[2],size);
  } else {
    char buffer[BLOCK];
    int result;

    size=0;
    printf("%s: file=%s, seeking, ",argv[0],argv[2]);
    fflush(stdout);

    /* expensive seek to get file size */
    while(BLOCK==(result=gzread(gz,buffer,BLOCK))){
      size+=BLOCK;
    }

    if(result==0){
      printf("size=%Ld\n",size);
    } else {
      printf("failed\n");
      if(result<0){
        fprintf(stderr,"%s: read failed: %s\n",argv[0],gzerror(gz,&gzerr));
      } else {
        fprintf(stderr,"%s: incomplete last read, file has to be a multiple of %d\n",argv[0],BLOCK);
      }
      exit(1);
    }

    if(gzrewind(gz)!=0){
      fprintf(stderr,"%s: unable to rewind gzfile\n",argv[0]);
      exit(1);
    }

  }

  if(socketpair(AF_UNIX, SOCK_STREAM, 0, pr)){
    fprintf(stderr,"%s: unable to create socketpair: %s\n",argv[0],strerror(errno));
    exit(1);
  }

  switch(fork()){
    case -1 :
      fprintf(stderr,"%s: unable to fork: %s\n",argv[0],strerror(errno));
      exit(1);
      break;
    case 0 : /* child */
      gzclose(gz);

      close(pr[0]);

      sk=pr[1];

      nbd=open(argv[1], O_RDWR);
      if(nbd<0){
        fprintf(stderr,"%s: unable to open %s: %s\n",argv[0],argv[1],strerror(errno));
        exit(1);
      }

      if(ioctl(nbd,NBD_SET_SIZE,size)<0){
        fprintf(stderr,"%s: failed to set size for %s: %s\n",argv[0],argv[1],strerror(errno));
        exit(1);
      }

      ioctl(nbd, NBD_CLEAR_SOCK);

      if(ioctl(nbd,NBD_SET_SOCK,sk)<0){
        fprintf(stderr,"%s: failed to set socket for %s: %s\n",argv[0],argv[1],strerror(errno));
        exit(1);
      }

      if(ioctl(nbd,NBD_DO_IT)<0){
        fprintf(stderr,"%s: block device %s terminated: %s\n",argv[0],argv[1],strerror(errno));
      }

      ioctl(nbd, NBD_CLEAR_QUE);
      ioctl(nbd, NBD_CLEAR_SOCK);

      exit(0);
      
      break;
  }

  /* only parent here, child always exits */

  close(pr[1]);
  sk=pr[0];

  reply.magic=htonl(NBD_REPLY_MAGIC);
  reply.error=htonl(0);

  while(1){

    if(read(sk,&request,sizeof(request))!=sizeof(request)){
      fprintf(stderr,"%s: incomplete request\n",argv[0]);
    }

    memcpy(reply.handle,request.handle,sizeof(reply.handle));

    len=ntohl(request.len);
    from=ntohll(request.from);

#ifdef TRACE
fprintf(stderr,"%s: len=%d, from=%Ld\n",argv[0],len,from);
#endif

    if(request.magic!=htonl(NBD_REQUEST_MAGIC)){
      fprintf(stderr,"%s: bad magic\n",argv[0]);
      reply.error=htonl(EIO); /* is that the right way of doing things ? */
    }

    if(ntohl(request.type)){
      fprintf(stderr,"%s: unsupported write request\n",argv[0]);
      reply.error=htonl(EROFS);
    }

    if(len+sizeof(struct nbd_reply)>CHUNK){
      fprintf(stderr,"%s: request too long\n",argv[0]);
      reply.error=htonl(EIO);
    }

    if(len+from>size){
      fprintf(stderr,"%s: request outside range\n",argv[0]);
      reply.error=htonl(EIO);
    }

    if(reply.error==htonl(0)){
      gzseek(gz,from,0);
      if(gzread(gz,chunk+sizeof(struct nbd_reply),len)!=len){
        fprintf(stderr,"%s: unable to read\n",argv[0]);
        reply.error=htonl(EIO);
        len=0;
      }
    } else {
      len=0;
    }

    memcpy(chunk,&reply,sizeof(struct nbd_reply));
    if(write(sk,chunk,len+sizeof(struct nbd_reply))!=(len+sizeof(struct nbd_reply))){
      fprintf(stderr,"%s: write failed: %s\n",argv[0],strerror(errno));
    }
  }

  gzclose(gz);

  return 0;
}
