#ifndef LFS_H
#define LFS_H

#include "config.h"
#if NBD_LFS
# define _FILE_OFFSET_BITS 64
# ifndef _LARGEFILE_SOURCE
#  define _LARGEFILE_SOURCE
# endif
# define PARAM_OFFT PARAM_INT64
#else
# define PARAM_OFFT PARAM_INT
#endif /* NBD_LFS */
#ifdef HAVE_SYNC_FILE_RANGE
# define USE_SYNC_FILE_RANGE
# define _GNU_SOURCE
#endif /* HAVE_SYNC_FILE_RANGE */

#endif /* LFS_H */
