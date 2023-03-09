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
#include <stdbool.h>
#include <unistd.h>
#include "config.h"
/* We don't want to do syslog output in this program */
#undef ISSERVER
#include "cliserv.h"
#include "nbd.h"
#include "nbd-helper.h"

#define BUFSIZE	131072
static char tmpbuf[BUFSIZE];

static bool g_with_datalog = false;

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
	uint64_t cookie;
	uint32_t error;
	uint32_t command;
	uint32_t len;
	uint64_t offset;
	const char * ctext;
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
			cookie = ntohll(req.cookie);
			offset = ntohll(req.from);
			len = ntohl(req.len);
			command = ntohl(req.type);
			
			ctext = getcommandname(command & NBD_CMD_MASK_COMMAND);

			printf("> H=%016llx C=0x%08x (%20s+%4s) O=%016llx L=%08x\n",
			       (long long unsigned int) cookie,
			       command,
			       ctext,
			       (command & NBD_CMD_FLAG_FUA)?"FUA":"NONE",
			       (long long unsigned int) offset,
			       len);
			if (((command & NBD_CMD_MASK_COMMAND) == NBD_CMD_WRITE) &&
					g_with_datalog) {
				while (len > 0) {
					uint32_t tmplen = len;

					if (tmplen > BUFSIZE)
						tmplen = BUFSIZE;
					doread(readfd, tmpbuf, tmplen);
					len -= tmplen;
				}
			}
			
			break;
		case NBD_REPLY_MAGIC:
			doread(readfd, sizeof(magic)+(char *)(&rep), sizeof(struct nbd_reply)-sizeof(magic));
			cookie = ntohll(rep.cookie);
			error = ntohl(rep.error);
			
			printf("< H=%016llx E=0x%08x\n",
			       (long long unsigned int) cookie,
			       error);
			break;
			
		case NBD_TRACELOG_MAGIC:
			doread(readfd, sizeof(magic)+(char *)(&req), sizeof(struct nbd_request)-sizeof(magic));
			cookie = ntohll(req.cookie);
			offset = ntohll(req.from);
			len = ntohl(req.len);
			command = ntohl(req.type);

			ctext = gettracelogname(command);

			printf("TRACE_OPTION C=0x%08x (%23s) O=%016llx L=%08x\n",
			       command,
			       ctext,
			       (long long unsigned int) offset,
			       len);
			if (offset == NBD_TRACELOG_FROM_MAGIC) {

				switch (command) {
				case NBD_TRACELOG_SET_DATALOG:
					g_with_datalog = !!len;
					printf("TRACE_OPTION DATALOG set to %d.\n", (int)g_with_datalog);
					break;
				default:
					printf("TRACE_OPTION ? Unknown type\n");
				}
			} else {
				printf("TRACE_OPTION ? Unknown FROM_MAGIC\n");
			}
			break;

		default:
			printf("? Unknown transaction type %08x\n",magic);
			break;
		}
		
	}
	/* never reached */
	return 0;
}
