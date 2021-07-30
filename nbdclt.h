#ifndef NBDCLT_H
#define NBDCLT_H

typedef struct {
	char *name;
	char *dev;
	char *hostn;
	char *port;
	char *cert;
	char *key;
	char *cacert;
	char *tlshostn;
	int bs;
	int timeout;
	int nconn;
	uint64_t force_size64;
	uint64_t size64;
	bool no_optgo;
	bool persist;
	bool swap;
	bool sdp;
	bool b_unix;
	bool preinit;
	bool force_ro;
	bool tls;
} CLIENT;

extern void nbdtab_set_property(char *property, char *val);
extern void nbdtab_set_flag(char *property);
extern void nbdtab_commit_line(char *devn, char *hostn, char *exportname);
extern void yyerror(char *msg);

#endif
