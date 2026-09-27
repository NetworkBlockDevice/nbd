#ifndef NBD_TREEFILES_H
#define NBD_TREEFILES_H

#include <pthread.h>
#include <sys/types.h>

// On 32-bit systems, lfs.h changes the size of off_t, so it *must* be included
// before mentioning off_t, otherwise things go horribly wrong
#include "lfs.h"

#define TREEDIRSIZE  1024 /**< number of files per subdirectory (or subdirs per subdirectory) */
#define TREEPAGESIZE 4096 /**< tree (block) files uses those chunks */

void construct_path(char *name, int lenmax, off_t export_size, off_t pos, off_t *ppos);

void delete_treefile(const char *base_name, off_t export_size, off_t pos);

void mkdir_path(char *path);

int open_treefile(const char *export_name, mode_t mode, off_t size, off_t pos, pthread_mutex_t *mutex);

#endif
