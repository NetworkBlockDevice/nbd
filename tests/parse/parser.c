#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "nbdtab_parser.tab.h"
#include <assert.h>
#include <nbdclt.h>

CLIENT client_empty;
CLIENT client_noopts = {
	.name = "test",
	.dev = "nbd0",
	.hostn = "localhost",
};

CLIENT client_singleopt = {
	.name = "test",
	.dev = "nbd0",
	.hostn = "localhost",
	.bs = 1024,
};

CLIENT client_multiopt = {
	.name = "test",
	.dev = "nbd0",
	.hostn = "localhost",
	.bs = 1024,
	.no_optgo = true,
};

CLIENT client_ipv6 = {
	.name = "test",
	.dev = "nbd0",
	.hostn = "2a01:4f8:200:91e8::2",
};

CLIENT client_ipv4 = {
	.name = "test",
	.dev = "nbd0",
	.hostn = "192.168.1.1",
};

CLIENT *cur_client;
bool seen_commit = false;

void nbdtab_set_property(char *property, char *val) {
	printf("property %s set to %s\n", property, val);
	assert(strcmp(property, "bs") == 0);
	assert(cur_client->bs == strtol(val, NULL, 10));
}

void nbdtab_set_flag(char *property) {
	printf("flag %s set\n", property);
	assert(strcmp(property, "no_optgo") == 0);
	assert(cur_client->no_optgo == true);
}

void nbdtab_commit_line(char *devn, char *hostn, char *exportname) {
	printf("finishing line with device %s, hostname %s, exportname %s\n", devn, hostn, exportname);
	assert(strcmp(cur_client->dev, devn) == 0);
	assert(strcmp(cur_client->hostn, hostn) == 0);
	assert(strcmp(cur_client->name, exportname) == 0);
	seen_commit = true;
}

void yyerror(char *s) {
	fprintf(stderr, "%s\n", s);
}

extern FILE *yyin, *yyout;

int main(int argc, char**argv) {
	printf("testing %s\n", argv[1]);
	yyin = fopen(argv[1], "r");
	yyout = fopen("/dev/null", "w");
	char *which = strrchr(argv[1], '/');
	if(which) {
		which++;
	} else {
		which = argv[1];
	}

#define KNOW_CONF(x) if(!strcmp(which, #x)) cur_client = &client_##x;

	KNOW_CONF(empty);
	KNOW_CONF(noopts);
	KNOW_CONF(singleopt);
	KNOW_CONF(multiopt);
	KNOW_CONF(ipv6);
	KNOW_CONF(ipv4);

#undef KNOW_CONF

	assert(cur_client != NULL);

	yyparse();

	assert(cur_client == &client_empty || seen_commit == true);
}
