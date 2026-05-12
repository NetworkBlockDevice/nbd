#ifndef NBD_TREEFILES_H
#define NBD_TREEFILES_H

#include <pthread.h>
#include <sys/types.h>

#define TREEDIRSIZE  1024 /**< number of files per subdirectory (or subdirs per subdirectory) */
#define TREEPAGESIZE 4096 /**< tree (block) files uses those chunks */

void construct_path(char *name, int lenmax, off_t size, off_t pos, off_t *ppos);
void delete_treefile(char *name, off_t size, off_t pos);
void mkdir_path(char *path);
int open_treefile(char *name, mode_t mode, off_t size, off_t pos, pthread_mutex_t *mutex);

#endif
