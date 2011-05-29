/*
 * nbd-trdump.c
 *
 * Takes an nbd transaction log file on stdin and translates it into something
 * comprehensible
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdint.h>
#include <unistd.h>
#include "config.h"
/* We don't want to do syslog output in this program */
#undef ISSERVER
#include "cliserv.h"
#include "nbd.h"

static inline void doread(int f, void *buf, size_t len) {
        ssize_t res;

        while(len>0) {
                if((res=read(f, buf, len)) <=0) {
                        if (!res)
				exit(0);
			perror ("Error reading transactions");
			exit(1);
                }
                len-=res;
                buf+=res;
        }
}

int main(int argc, char**argv) {
	struct nbd_request req;
	struct nbd_reply rep;
	uint32_t magic;
	uint64_t handle;
	uint32_t error;
	uint32_t command;
	uint32_t len;
	uint64_t offset;
	char * ctext;
	int readfd = 0; /* stdin */

	if(argc > 1) {
		int retval=0;
		if(strcmp(argv[1], "--help") && strcmp(argv[1], "-h")) {
			printf("E: unknown option %s.\n", argv[1]);
			retval=1;
		}
		printf("This is nbd-trdump, part of nbd %s.\n", PACKAGE_VERSION);
		printf("Use: %s < transactionlog\n", argv[0]);
		return retval;
	}

	while (1) {
		/* Read a request or reply from the transaction file */
		doread(readfd, &magic, sizeof(magic));
		magic = ntohl(magic);
		switch (magic) {
		case NBD_REQUEST_MAGIC:
			doread(readfd, sizeof(magic)+(char *)(&req), sizeof(struct nbd_request)-sizeof(magic));
			handle = ntohll(*((long long int *)(req.handle)));
			offset = ntohll(req.from);
			len = ntohl(req.len);
			command = ntohl(req.type);
			
			switch (command & NBD_CMD_MASK_COMMAND) {
			case NBD_CMD_READ:
				ctext="NBD_CMD_READ";
				break;
			case NBD_CMD_WRITE:
				ctext="NBD_CMD_WRITE";
				break;
			case NBD_CMD_DISC:
				ctext="NBD_CMD_DISC";
				break;
			case NBD_CMD_FLUSH:
				ctext="NBD_CMD_FLUSH";
				break;
			default:
				ctext="UNKNOWN";
				break;
			}
			printf("> H=%016llx C=0x%08x (%13s+%4s) O=%016llx L=%08x\n",
			       (long long unsigned int) handle,
			       command,
			       ctext,
			       (command & NBD_CMD_FLAG_FUA)?"FUA":"NONE",
			       (long long unsigned int) offset,
			       len);
			
			break;
		case NBD_REPLY_MAGIC:
			doread(readfd, sizeof(magic)+(char *)(&rep), sizeof(struct nbd_reply)-sizeof(magic));
			handle = ntohll(*((long long int *)(rep.handle)));
			error = ntohl(rep.error);
			
			printf("< H=%016llx E=0x%08x\n",
			       (long long unsigned int) handle,
			       error);
			break;
			
		default:
			printf("? Unknown transaction type %08x\n",magic);
			break;
		}
		
	}
	/* never reached */
	return 0;
}
