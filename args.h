#ifndef ARGS_H
#define ARGS_H

#include <stdbool.h>
#include <stdint.h>
#include "config.h"

// Include nbdclt.h to get CLIENT definition
#include "nbdclt.h"

// Argument parsing result structure
typedef struct {
    int exit_code;
    char error_msg[256];
    bool should_exit;
    bool check_conn;
    char *check_device;
    bool need_disconnect;
    bool list_exports;
    bool show_version;
#if HAVE_NETLINK
    char *identifier;
    bool nonetlink;
#endif
} parse_result_t;

// Function prototypes
parse_result_t parse_nbd_client_args(int argc, char *argv[], CLIENT *client);
void free_client_fields(CLIENT *client);
void init_client(CLIENT *client);

#endif // ARGS_H
