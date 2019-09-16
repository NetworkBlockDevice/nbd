#include <nbdsrv.h>
#include <stdlib.h>
#include <unistd.h>
#include "macro.h"

int main(void) {
	char filename[] = "/tmp/nbd.XXXXXX";
	int fd = mkstemp(filename);
	unlink(filename);

	count_assert(fd >= 0);
	count_assert(lseek(fd, 1023, SEEK_SET) == 1023);
	count_assert(write(fd, filename, 1) == 1);

	count_assert(size_autodetect(fd) == 1024);
	count_assert(size_autodetect(fd) != 1023);
}
