#ifndef NBD_HELPER_H
#define NBD_HELPER_H

#include "nbd.h"

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
#undef ENUM2STR

#endif //NBD_HELPER_H
