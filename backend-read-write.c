#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <nbd-server.h>

ssize_t backend_send(int fh, int net, off_t offset, size_t len) {
	char *buf;
	ssize_t retval;

	buf=malloc(len);
	myseek(fh, offset);
	retval=read(fh, &buf, len);
	writeit(net, &buf, len);
	return retval;
}
