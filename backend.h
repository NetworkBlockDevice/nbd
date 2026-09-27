#ifndef NBD_BACKEND_H
#define NBD_BACKEND_H

// On 32-bit systems, lfs.h changes the size of off_t, so it *must* be included
// before mentioning off_t, otherwise things go horribly wrong
#include "lfs.h"
void punch_hole(int fd, off_t off, off_t len);

#endif
