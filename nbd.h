/*
 * 1999 Copyright (C) Pavel Machek, pavel@ucw.cz. This code is GPL.
 * 1999/11/04 Copyright (C) 1999 VMware, Inc. (Regis "HPReg" Duchesne)
 *            Made nbd_end_request() use the io_request_lock
 * 2001 Copyright (C) Steven Whitehouse
 *            New nbd_end_request() for compatibility with new linux block
 *            layer code.
 * 2003/06/24 Louis D. Langholtz <ldl@aros.net>
 *            Removed unneeded blksize_bits field from nbd_device struct.
 *            Cleanup PARANOIA usage & code.
 * 2004/02/19 Paul Clements
 *            Removed PARANOIA, plus various cleanup and comments
 */

#ifndef LINUX_NBD_H
#define LINUX_NBD_H

//#include <linux/types.h>

#define NBD_SET_SOCK	_IO( 0xab, 0 )
#define NBD_SET_BLKSIZE	_IO( 0xab, 1 )
#define NBD_SET_SIZE	_IO( 0xab, 2 )
#define NBD_DO_IT	_IO( 0xab, 3 )
#define NBD_CLEAR_SOCK	_IO( 0xab, 4 )
#define NBD_CLEAR_QUE	_IO( 0xab, 5 )
#define NBD_PRINT_DEBUG	_IO( 0xab, 6 )
#define NBD_SET_SIZE_BLOCKS	_IO( 0xab, 7 )
#define NBD_DISCONNECT  _IO( 0xab, 8 )
#define NBD_SET_TIMEOUT _IO( 0xab, 9 )
#define NBD_SET_FLAGS _IO( 0xab, 10 )

enum {
	NBD_CMD_READ = 0,
	NBD_CMD_WRITE = 1,
	NBD_CMD_DISC = 2,
	NBD_CMD_FLUSH = 3,
	NBD_CMD_TRIM = 4,
	NBD_CMD_CACHE = 5,
	NBD_CMD_WRITE_ZEROES = 6,
	NBD_CMD_BLOCK_STATUS = 7,
	NBD_CMD_RESIZE = 8
};

#define NBD_CMD_MASK_COMMAND 0x0000ffff
#define NBD_CMD_SHIFT (16)
#define NBD_CMD_FLAG_FUA ((1 << 0) << NBD_CMD_SHIFT)
#define NBD_CMD_FLAG_NO_HOLE ((1 << 1) << NBD_CMD_SHIFT)
#define NBD_CMD_FLAG_DF  ((1 << 2) << NBD_CMD_SHIFT)

/* values for flags field */
#define NBD_FLAG_HAS_FLAGS	(1 << 0)	/* Flags are there */
#define NBD_FLAG_READ_ONLY	(1 << 1)	/* Device is read-only */
#define NBD_FLAG_SEND_FLUSH	(1 << 2)	/* Send FLUSH */
#define NBD_FLAG_SEND_FUA	(1 << 3)	/* Send FUA (Force Unit Access) */
#define NBD_FLAG_ROTATIONAL	(1 << 4)	/* Use elevator algorithm - rotational media */
#define NBD_FLAG_SEND_TRIM	(1 << 5)	/* Send TRIM (discard) */
#define NBD_FLAG_SEND_WRITE_ZEROES (1 << 6) 	/* Send NBD_CMD_WRITE_ZEROES */
#define NBD_FLAG_SEND_DF	(1 << 7)	/* Send NBD_CMD_FLAG_DF */
#define NBD_FLAG_CAN_MULTI_CONN	(1 << 8)	/* multiple connections are okay */

#define nbd_cmd(req) ((req)->cmd[0])

/* userspace doesn't need the nbd_device structure */

/* These are sent over the network in the request/reply magic fields */

#define NBD_REQUEST_MAGIC 0x25609513
#define NBD_REPLY_MAGIC 0x67446698
#define NBD_STRUCTURED_REPLY_MAGIC 0x668e33ef

/* for the trace log, not part of the protocol, not sent over the wire */
#define NBD_TRACELOG_MAGIC 0x25609514

#define NBD_OPT_REPLY_MAGIC 0x3e889045565a9LL

#define NBD_REPLY_TYPE_NONE 		(0)
#define NBD_REPLY_TYPE_OFFSET_DATA	(1)
#define NBD_REPLY_TYPE_OFFSET_HOLE	(2)
#define NBD_REPLY_TYPE_BLOCK_STATUS	(3)

#define NBD_REPLY_TYPE_ERROR		((1 << 15) + 1)
#define NBD_REPLY_TYPE_ERROR_OFFSET	((1 << 15) + 2)

#define NBD_REPLY_FLAG_DONE		(1 << 0)

/*
 * This is the packet used for communication between client and
 * server. All data are in network byte order.
 */
struct nbd_request {
	uint32_t magic;
	uint32_t type;	/* == READ || == WRITE 	*/
	uint64_t cookie;
	uint64_t from;
	uint32_t len;
} __attribute__ ((packed));

/*
 * This is the reply packet that nbd-server sends back to the client after
 * it has completed an I/O request (or an error occurs).
 */
struct nbd_reply {
	uint32_t magic;
	uint32_t error;		/* 0 = ok, else error	*/
	uint64_t cookie;	/* cookie you got from request	*/
} __attribute__ ((packed));

/*
 * The reply packet for structured replies
 */
struct nbd_structured_reply {
	uint32_t magic;
	uint16_t flags;
	uint16_t type;
	uint64_t cookie;
	uint32_t paylen;
} __attribute__ ((packed));

struct nbd_structured_error_payload {
	uint32_t error;
	uint16_t msglen;
} __attribute__ ((packed));

#define NBD_EPERM 1
#define NBD_EIO 5
#define NBD_ENOMEM 12
#define NBD_EINVAL 22
#define NBD_ENOSPC 28
#define NBD_EOVERFLOW 75
#define NBD_ENOTSUP 95
#define NBD_ESHUTDOWN 108

#endif
