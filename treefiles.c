#include "lfs.h"
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <glib.h>

#include <backend.h>
#include <config.h>
#include <cliserv.h>
#include <treefiles.h>
#include <nbd-debug.h>
#include <nbdsrv.h>
/**
 * Tree structure helper functions
 */
void construct_path(char* name,int lenmax,off_t size, off_t pos, off_t * ppos) {
	if (lenmax<10)
		err("Char buffer overflow. This is likely a bug.");

	if (size<TREEDIRSIZE*TREEPAGESIZE) {
		// we are done, add filename
		snprintf(name,lenmax,"/FILE%04" PRIX64,(pos/TREEPAGESIZE) % TREEDIRSIZE);
		*ppos = pos / (TREEPAGESIZE*TREEDIRSIZE);
	} else {
		construct_path(name+9,lenmax-9,size/TREEDIRSIZE,pos,ppos);
		char buffer[10];
		snprintf(buffer,sizeof(buffer),"/TREE%04jX",(intmax_t)(*ppos % TREEDIRSIZE));
		memcpy(name,buffer,9); // copy into string without trailing zero
		*ppos/=TREEDIRSIZE;
	}
}

void delete_treefile(char* name,off_t size,off_t pos) {
	char filename[256+strlen(name)];
	strcpy(filename,name);
	off_t ppos;
	construct_path(filename+strlen(name),256,size,pos,&ppos);

	DEBUG("Deleting treefile: %s",filename);

	if (unlink(filename)==-1)
		DEBUG("Deleting failed : %s",strerror(errno));
}

void mkdir_path(char * path) {
	char *subpath=path+1;
	while ((subpath=strchr(subpath,'/'))) {
		*subpath='\0'; // path is modified in place with terminating null char instead of slash
		if (mkdir(path,0700)==-1) {
			if (errno!=EEXIST)
				err("Path access error! %m");
		}
		*subpath='/';
		subpath++;
	}
}

int open_treefile(char* name,mode_t mode,off_t size,off_t pos, pthread_mutex_t *mutex) {
	char filename[256+strlen(name)];
	strcpy(filename,name);
	off_t ppos;
	construct_path(filename+strlen(name),256,size,pos,&ppos);

	DEBUG("Accessing treefile %s ( offset %llu of %llu)",filename,(unsigned long long)pos,(unsigned long long)size);

	pthread_mutex_lock(mutex);
	int handle=open(filename, mode, 0600);
	if (handle<0 && errno==ENOENT) {
		if (mode & O_RDWR) {

			DEBUG("Creating new treepath");

			mkdir_path(filename);
			handle=open(filename, O_RDWR|O_CREAT, 0600);
			if (handle<0) {
				err("Error opening tree block file %m");
			}
		} else {

			DEBUG("Creating a dummy tempfile for reading");
			gchar * tmpname;
			tmpname = g_strdup_printf("dummy-XXXXXX");
			mode_t oldmode = umask(77);
			handle = mkstemp(tmpname);
			umask(oldmode);
			if (handle>0) {
				unlink(tmpname); /* File will stick around whilst FD open */
			} else {
				err("Error opening tree block file %m");
			}
			g_free(tmpname);
		}
		char *n = "\0";
		if(lseek(handle,TREEPAGESIZE-1, SEEK_SET) < 0) {
			err("Could not create tree file!\n");
		}
		ssize_t c = write(handle,n,1);
		if (c<1) {
			err("Error setting tree block file size %m");
		}
	}
	pthread_mutex_unlock(mutex);
	return handle;
}

