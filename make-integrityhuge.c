/*
 * make-integrityhuge
 *
 * Make a file to test oversize writes
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include "config.h"
#include "cliserv.h"
#include "nbd.h"

const uint64_t filesize=50*1000*1000;
const uint64_t transactions = 250;

static inline void dowrite(int f, void *buf, size_t len) {
        ssize_t res;

        while(len>0) {
                if((res=write(f, buf, len)) <=0) {
			perror ("Error writing transactions");
			exit(1);
                }
                len-=res;
                buf+=res;
        }
}

static inline uint64_t getrandomuint64() {
	uint64_t r=0;
        int i;
	/* RAND_MAX may be as low as 2^15 */
	for (i= 1 ; i<=5; i++)
		r ^= random() ^ (r << 15); 
	return r;
}

int main(int argc, char**argv) {
	struct nbd_request req;
	struct nbd_reply rep;
	uint64_t handle;
	int writefd = 1; /*stdout*/

	req.magic = htonl(NBD_REQUEST_MAGIC);
	rep.magic = htonl(NBD_REPLY_MAGIC);
	rep.error = 0;

	for (handle = 0; handle < transactions; handle++)
	{
		uint64_t offset;
		uint64_t length;
		uint64_t flags;
		uint32_t command;

		/* make the length between 0x400 and the length of the disk -08x800, with all
		 * the bottom bits clear */
		length = ((getrandomuint64() % (filesize-0x800)) & ~((uint64_t)0x3ff)) + 0x400;
		/* generate an offset that will fit the length */
		offset = (getrandomuint64() % (filesize-length)) & ~((uint64_t)0x3ff);
		flags = getrandomuint64();

		command = (flags & 0x01)?NBD_CMD_READ:NBD_CMD_WRITE;

		if (!(flags & 0x0f))
			command = NBD_CMD_FLAG_FUA | NBD_CMD_WRITE;

		if (!(flags & 0xf0)) {
			offset = 0;
			length = 0;
			command = NBD_CMD_FLUSH;
		}

		*(uint64_t *)(req.handle) = htonll(handle);
		*(uint64_t *)(rep.handle) = htonll(handle);
		req.type = htonl(command);
		req.from = htonll(offset);
		req.len = htonl(length);

		dowrite(writefd, &req, sizeof(req));
		dowrite(writefd, &rep, sizeof(rep));
	}

	req.type = htonl(NBD_CMD_DISC);
	req.from = 0;
	req.len = 0;
	dowrite(writefd, &req, sizeof(req));
	
	return 0;
}
