#include <assert.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>

#include <nbdsrv.h>
#include "macro.h"
#include "backend.h"

int g_fd;
int g_off;
int g_len;

void punch_hole(int fd, off_t off, off_t len) {
	g_fd = fd;
	g_off = off;
	g_len = len;
}

int main(void) {
	struct nbd_request req;
	SERVER srv;
	CLIENT cl;
	FILE_INFO export;
	int spair[2];

	req.magic = NBD_REQUEST_MAGIC;
	req.type = NBD_CMD_TRIM;
	req.from = 0;
	req.len = 1024*1024;

	srv.exportname = "dummy";
	srv.expected_size = 1024*1024*1024;
	srv.listenaddr = "0.0.0.0";
	srv.authname = NULL;
	srv.flags = 0;
	srv.virtstyle = VIRT_NONE;
	srv.cidrlen = 0;
	srv.prerun = NULL;
	srv.postrun = NULL;
	srv.servename = "dummy";
	srv.transactionlog = NULL;
	srv.cowdir = NULL;

	export.fhandle = 123;
	export.startoff = 0;

	cl.exportsize = 1024*1024*1024;
	cl.clientname = "127.0.0.1";
	cl.exportname = "dummy";
	cl.export = g_array_new(TRUE, TRUE, sizeof(FILE_INFO));
	g_array_append_val(cl.export, export);
	socketpair(AF_UNIX, SOCK_STREAM, AF_UNIX, spair);
	cl.net = spair[0];
	cl.server = &srv;
	cl.difffilename = NULL;
	cl.difffile = 0;
	cl.difffilelen = 0;
	cl.difmap = NULL;
	cl.modern = TRUE;
	cl.transactionlogfd = -1;
	cl.clientfeats = 0;
	pthread_mutex_init(&cl.lock, NULL);

	/* phew. Now test: */

	exptrim(&req, &cl);
	count_assert(g_fd == 123);
	count_assert(g_off == 0);
	count_assert(g_len == 1024*1024);

	req.from = 1024 * 1024 * 1024;
	req.len = 1024 * 1024;
	count_assert(exptrim(&req, &cl) == -1);
	count_assert(errno == EINVAL);
}
