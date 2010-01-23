#ifndef LFS_H
#define LFS_H

#include "config.h"
#if NBD_LFS
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE_SOURCE
#endif /* NBD_LFS */

#endif /* LFS_H */
