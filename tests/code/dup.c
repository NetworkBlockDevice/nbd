#include <nbdsrv.h>

int main(void) {
	SERVER *srvd;
	SERVER *srvs = {
		.exportname = "foo",
		.expected_size = 0,
		.listenaddr = "0.0.0.0",
		.port = 10809,
		.authname = "/etc/foo",
		.flags = 0,
		.socket = 1,
		.socket_family = AF_INET,
		.virtstyle = VIRT_CIDR,
		.cidrlen = 16,
		.prerun = NULL,
		.postrun = "/bin/bash",
		.servename = "test",
		.max_connections = 0,
		.transactionlog = "/etc/foo",
	};

	srvd = dup_serve(srvs);

	assert(srvs != srvd);
	assert(strcmp(srvs->exportname, srvd->exportname) == 0);
	assert(srvs->expected_size == srvd->expected_size);
	assert(strcmp(srvs->listenaddr, srvd->listenaddr) == 0);
	assert(srvs->port == srvd->port);
	assert(strcmp(srvs->authname, srvd->listenaddr) == 0);
	assert(srvs->flags == srvd->flags);
	assert(srvs->socket == srvd->socket);
	assert(srvs->socket_family == srvd->socket_family);
	assert(srvs->virtstyle == srvd->virtstyle);
	assert(srvs->cidrlen == srvd->cidrlen);
	assert(strcmp(srvs->prerun, srvd->prerun) == 0);
	assert(strcmp(srvs->postrun, srvs->postrun) == 0);
	assert(strcmp(srvs->servename, srvd->servename) == 0);
	assert(srvs->max_connections == srvd->max_connections);
	assert(strcmp(srvs->transactionlog, srvd->transactionlog) == 0);
}
