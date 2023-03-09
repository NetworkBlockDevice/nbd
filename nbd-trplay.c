// SPDX-License-Identifier: GPL-2.0
/*
 * nbd-trplay.c
 *
 * Takes an nbd transaction log file and replays some/all of the write commands.
 *
 * Based on nbd-trdump
 * (C) Robert Bosch GmbH, 2021
 */

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
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
static char g_tmpbuf[BUFSIZE];

static bool g_with_datalog = false;

#define	VERBOSE_DEBUG	3
#define	VERBOSE_DETAILS	2
#define	VERBOSE_NORMAL	1
#define	VERBOSE_OFF	0

int g_verbose = 0;

unsigned long g_blocksize = 512;
unsigned long long g_cur_blocks = 0;
unsigned long long g_max_blocks = ULLONG_MAX;

static inline void doread(int f, char *buf, size_t len) {
        ssize_t res;

        while(len>0) {
                if((res=read(f, buf, len)) <=0) {
                        if (!res) {
				/* normal exit, end of transaction log. */
				printf("End of transaction log, total %llu blocks written.\n",
					(unsigned long long) g_cur_blocks);
				exit(0);
			}
			perror ("Error reading transactions");
			exit(1);
                }
                len-=res;
                buf+=res;
        }
}

static inline void dowriteimage(int imagefd, const char *buf, size_t len, off_t offset) {
	ssize_t res;

	if (g_verbose >= VERBOSE_DETAILS) {
		printf("block %llu (0x%llx): writing to offset %lld (0x%llx), len %lld (0x%llx).\n",
			g_cur_blocks, g_cur_blocks,
			(long long)offset, (long long) offset,
			(long long) len, (long long) len);
	}

	while(len>0) {
		if((res=pwrite(imagefd, buf, len, offset)) <=0) {
			if (!res)
				exit(0);
			perror ("Error writing to image file");
			exit(1);
		}
		len-=res;
		buf+=res;
		offset+=res;
	}
}


void process_command(uint32_t command, uint64_t offset, uint32_t len, int logfd, int imagefd)
{
	if (offset % g_blocksize != 0) {
		printf("  Got offset %llu (0x%llx), not a multiple of the block size %ld (0x%lx).\n",
				(unsigned long long)offset, (unsigned long long)offset, g_blocksize, g_blocksize);
		exit(1);
	}
	if (len % g_blocksize != 0) {
		printf("  Got len %lu (0x%lx), not a multiple of the block size %ld (0x%lx).\n",
				(unsigned long) len, (unsigned long) len, g_blocksize, g_blocksize);
		exit(1);
	}

	switch (command & NBD_CMD_MASK_COMMAND) {
	case NBD_CMD_READ:
	case NBD_CMD_DISC:
	case NBD_CMD_FLUSH:
		/* READ, DISCONNECT, FLUSH: nothing to do */
		break;
	case NBD_CMD_WRITE:
		if (!g_with_datalog) {
			printf("  NBD_CMD_WRITE without data log, replay impossible.\n");
			exit(1);
		}
		while (len > 0) {
			doread(logfd, g_tmpbuf, g_blocksize);
			dowriteimage(imagefd, g_tmpbuf, g_blocksize, offset);

			offset+=g_blocksize;
			len-=g_blocksize;
			g_cur_blocks++;

			if (g_cur_blocks == g_max_blocks) {
				printf("g_max_blocks (%llu, 0x%llx) reached!.\n", g_max_blocks, g_max_blocks);
				exit(0);
			}
		}
		break;
	case NBD_CMD_TRIM:
	case NBD_CMD_WRITE_ZEROES:
		while (len > 0) {
			memset(g_tmpbuf, 0, g_blocksize);
			dowriteimage(imagefd, g_tmpbuf, g_blocksize, offset);

			offset+=g_blocksize;
			len-=g_blocksize;
			g_cur_blocks++;

			if (g_cur_blocks == g_max_blocks) {
				printf("g_max_blocks (%llu, 0x%llx) reached!.\n", g_max_blocks, g_max_blocks);
				exit(0);
			}
		}
		break;
	default:
		printf("  Unexpected command %d (0x%x), replay impossible.\n",
			(unsigned int) command, (unsigned int) command);
		exit(1);
	}
}

int main_loop(int logfd, int imagefd) {
	struct nbd_request req;
	struct nbd_reply rep;
	uint32_t magic;
	uint64_t cookie;
	uint32_t error;
	uint32_t command;
	uint32_t len;
	uint64_t offset;
	const char * ctext;

	while (1) {
		/* Read a request or reply from the transaction file */
		doread(logfd, (char*) &magic, sizeof(magic));
		magic = ntohl(magic);
		switch (magic) {
		case NBD_REQUEST_MAGIC:
			doread(logfd, sizeof(magic)+(char *)(&req), sizeof(struct nbd_request)-sizeof(magic));
			cookie = ntohll(req.cookie);
			offset = ntohll(req.from);
			len = ntohl(req.len);
			command = ntohl(req.type);

			ctext = getcommandname(command & NBD_CMD_MASK_COMMAND);

			if (g_verbose >= VERBOSE_NORMAL) {
				printf("> H=%016llx C=0x%08x (%13s+%4s) O=%016llx L=%08x\n",
				       (long long unsigned int) cookie,
				       command,
				       ctext,
				       (command & NBD_CMD_FLAG_FUA)?"FUA":"NONE",
				       (long long unsigned int) offset,
				       len);
			}
			process_command(command, offset, len, logfd, imagefd);

			break;

		case NBD_REPLY_MAGIC:
			doread(logfd, sizeof(magic)+(char *)(&rep), sizeof(struct nbd_reply)-sizeof(magic));
			cookie = ntohll(rep.cookie);
			error = ntohl(rep.error);

			if (g_verbose >= VERBOSE_NORMAL) {
				printf("< H=%016llx E=0x%08x\n",
				       (long long unsigned int) cookie,
				       error);
			}
			break;

		case NBD_TRACELOG_MAGIC:
			doread(logfd, sizeof(magic)+(char *)(&req), sizeof(struct nbd_request)-sizeof(magic));
			cookie = ntohll(req.cookie);
			offset = ntohll(req.from);
			len = ntohl(req.len);
			command = ntohl(req.type);

			ctext = gettracelogname(command);

			if (g_verbose >= VERBOSE_NORMAL) {
				printf("TRACE_OPTION C=0x%08x (%23s) O=%016llx L=%08x\n",
				       command,
				       ctext,
				       (long long unsigned int) offset,
				       len);
			}
			if (offset == NBD_TRACELOG_FROM_MAGIC) {

				switch (command) {
				case NBD_TRACELOG_SET_DATALOG:
					g_with_datalog = !!len;
					if (g_verbose >= VERBOSE_NORMAL)
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
			printf("? Unknown transaction type %08x, replay impossible.\n", magic);
			exit(1);
		}

	}
	/* never reached */
	return 0;
}

static void show_help(const char *progname) {
	printf("\n");
	printf("This is nbd-trplay, part of nbd %s.\n", PACKAGE_VERSION);
	printf("Use: %s -i <image> -l <log> [-m <max blocks>] [-b <block size]\n", progname);
	printf(" Applies up to <max blocks> elements from file <log> to disk image <image>.\n");
	printf(" Command line parameters:\n");
	printf(" <image>: name of the initial image file.\n");
	printf(" <log>: nbd trace log. Must contain actual data (datalog=true).\n");
	printf(" <block size>: device block size. Default 512.\n");
	printf(" <max blocks>: where to stop the replay. Default all.\n");
	printf("  -v: Increase verbose level. Specify multiple times to increase further.\n");

}


int main(int argc, char **argv) {
	int opt;
	int imagefd = -1;
	int logfd = -1;

	printf("%s -i <image> -l <log> [-m <max blocks>] [-b <block size]\n", argv[0]);

	while ((opt = getopt(argc, argv, "i:l:m:b:hv")) != -1) {
		if (g_verbose >= VERBOSE_DEBUG) {
			printf("getopt: opt %c, optarg %s.\n", (char)opt, optarg);
		}
		switch(opt) {
		case 'v':
			g_verbose++;
			break;
		default:
		case '?':
		case 'h':
			show_help(argv[0]);
			return 0;
		case 'm':
			g_max_blocks = strtoull(optarg, NULL, 0);
			if (g_max_blocks == 0) {
				printf("  Invalid block count.\n");
				return 1;
			}
			break;
		case 'b':
			g_blocksize = strtoul(optarg, NULL, 0);
			if (g_blocksize == 0) {
				printf("  Invalid block size.\n");
				return 1;
			}
			if (g_blocksize > BUFSIZE) {
				printf(" block size is larger than %d, not supported.\n", (int)BUFSIZE);
				return 1;
			}
			break;
		case 'i':
			imagefd = open(optarg, O_RDWR, 0);
			if (imagefd == -1) {
				printf("  Opening disk image failed, errno %d.", errno);
				return 1;
			}
			break;
		case 'l':
			logfd = open(optarg, O_RDONLY, 0);
			if (logfd == -1) {
				printf("  Opening disk image failed, errno %d.", errno);
				return 1;
			}
			break;
		}
	}

	if (logfd == -1) {
		printf("  Log file not specified, this is mandatory.\n");
		return 1;
	}
	if (imagefd == -1) {
		printf("  Disk image not specified, this is mandatory.\n");
		return 1;
	}

	if (g_verbose >= VERBOSE_NORMAL) {
		printf(" block size: %ld bytes (0x%lx bytes).\n", g_blocksize, g_blocksize);
		printf(" max blocks to apply: %llu (0x%llx).\n", g_max_blocks, g_max_blocks);
	}
	main_loop(logfd, imagefd);

	return 0;
}
