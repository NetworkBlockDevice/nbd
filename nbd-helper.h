#ifndef NBD_HELPER_H
#define NBD_HELPER_H

#include "nbd.h"

/* Constants and macros */

/*
 * Constants for nbd_request.magic == NBD_TRACELOG_MAGIC
 */
/* 1) stored in nbd_req.type */
enum {
	/* enable/disable logging actual data.
	 * nbd_request.len is the new value (true/false)
	 */
	NBD_TRACELOG_SET_DATALOG = 1
};

/* 2) Must be in nbd_req.from */
#define NBD_TRACELOG_FROM_MAGIC	0x4A93BA39A54F31B6ULL

/* Functions */

/**
 * Translate a command name into human readable form
 *
 * @param command The command number (after applying NBD_CMD_MASK_COMMAND)
 * @return pointer to the command name
 **/
#define ENUM2STR(x)	case x: return #x
static inline const char * getcommandname(uint32_t command) {
	switch (command) {
	ENUM2STR(NBD_CMD_READ);
	ENUM2STR(NBD_CMD_WRITE);
	ENUM2STR(NBD_CMD_DISC);
	ENUM2STR(NBD_CMD_FLUSH);
	ENUM2STR(NBD_CMD_TRIM);
	ENUM2STR(NBD_CMD_CACHE);
	ENUM2STR(NBD_CMD_WRITE_ZEROES);
	ENUM2STR(NBD_CMD_BLOCK_STATUS);
	ENUM2STR(NBD_CMD_RESIZE);
	default:
		return "UNKNOWN";
	}
}

/**
 * Translate a tracelog parameter name into human readable form
 *
 * @type tracelog parameter number from struct nbd_req.type
 * @return pointer to the name
 **/
static inline const char * gettracelogname(uint32_t type) {
	switch (type) {
	ENUM2STR(NBD_TRACELOG_SET_DATALOG);
	default:
		return "UNKNOWN";
	}
}

#undef ENUM2STR

#endif //NBD_HELPER_H
