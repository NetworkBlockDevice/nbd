#include <nbdsrv.h>
#include <assert.h>
#include <string.h>
#include "macro.h"

int stringcmp(const char* a, const char* b) {
	if(a == NULL && b == NULL) {
		return 0;
	}
	if(a == NULL) {
		return 1;
	}
	if(b == NULL) {
		return -1;
	}
	return strcmp(a, b);
}

int main(void) {
	SERVER *srvd;
	SERVER srvs = {
		.exportname = "foo",
		.expected_size = 0,
		.listenaddr = "0.0.0.0",
		.authname = "/etc/foo",
		.flags = 0,
		.virtstyle = VIRT_CIDR,
		.cidrlen = 16,
		.prerun = NULL,
		.postrun = "/bin/bash",
		.servename = "test",
		.max_connections = 0,
		.transactionlog = "/etc/foo",
		.cowdir = "/tmp",
	};

	srvd = dup_serve(&srvs);

	count_assert(&srvs != srvd);
	count_assert(stringcmp(srvs.exportname, srvd->exportname) == 0);
	count_assert(srvs.expected_size == srvd->expected_size);
	count_assert(stringcmp(srvs.listenaddr, srvd->listenaddr) == 0);
	count_assert(stringcmp(srvs.authname, srvd->authname) == 0);
	count_assert(srvs.flags == srvd->flags);
	count_assert(srvs.virtstyle == srvd->virtstyle);
	count_assert(srvs.cidrlen == srvd->cidrlen);
	count_assert(stringcmp(srvs.prerun, srvd->prerun) == 0);
	count_assert(stringcmp(srvs.postrun, srvd->postrun) == 0);
	count_assert(stringcmp(srvs.servename, srvd->servename) == 0);
	count_assert(srvs.max_connections == srvd->max_connections);
	count_assert(stringcmp(srvs.transactionlog, srvd->transactionlog) == 0);
	count_assert(stringcmp(srvs.cowdir, srvd->cowdir) == 0);
}
