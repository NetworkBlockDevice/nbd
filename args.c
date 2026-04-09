#include "args.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include "config.h"

#define NBD_DEFAULT_PORT "10809"

void init_client(CLIENT *client) {
    memset(client, 0, sizeof(CLIENT));
    client->bs = 512;
    client->nconn = 1;
    client->port = NBD_DEFAULT_PORT;
}

void free_client_fields(CLIENT *client) {
    // Note: In a real implementation, we'd free allocated strings
    // For testing, we'll just reset pointers to avoid double-free issues
    memset(client, 0, sizeof(CLIENT));
    client->bs = 512;
    client->nconn = 1;
    client->port = NBD_DEFAULT_PORT;
}

static void usage_error(parse_result_t *result, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(result->error_msg, sizeof(result->error_msg), fmt, ap);
    va_end(ap);
    result->exit_code = 1;
    result->should_exit = true;
}

parse_result_t parse_nbd_client_args(int argc, char *argv[], CLIENT *client) {
    parse_result_t result = {0};
    int nonspecial = 0;
    char *port = NBD_DEFAULT_PORT;
    
    static const char *short_opts = "-B:b:c:d:gH:hlnN:PpRSst:uVxy:T:C"
#if HAVE_NETLINK
	"i:L"
#endif
	;
    
    static struct option long_options[] = {
        {"cacertfile", required_argument, NULL, 'A'},
        {"block-size", required_argument, NULL, 'b'},
        {"size", required_argument, NULL, 'B'},
        {"check", required_argument, NULL, 'c'},
        {"connections", required_argument, NULL, 'C'},
        {"disconnect", required_argument, NULL, 'd'},
        {"certfile", required_argument, NULL, 'F'},
        {"no-optgo", no_argument, NULL, 'g'},
        {"help", no_argument, NULL, 'h'},
        {"tlshostname", required_argument, NULL, 'H'},
#if HAVE_NETLINK
        {"identifier", required_argument, NULL, 'i'},
#endif
        {"keyfile", required_argument, NULL, 'K'},
        {"list", no_argument, NULL, 'l'},
#if HAVE_NETLINK
        {"nonetlink", no_argument, NULL, 'L'},
#endif
        {"systemd-mark", no_argument, NULL, 'm'},
        {"nofork", no_argument, NULL, 'n'},
        {"name", required_argument, NULL, 'N'},
        {"persist", no_argument, NULL, 'p'},
        {"preinit", no_argument, NULL, 'P'},
        {"readonly", no_argument, NULL, 'R'},
        {"swap", no_argument, NULL, 's'},
        {"timeout", required_argument, NULL, 't'},
        {"dead-timeout", required_argument, NULL, 'T'},
        {"unix", no_argument, NULL, 'u'},
        {"version", no_argument, NULL, 'V'},
        {"enable-tls", no_argument, NULL, 'x'},
        {"priority", required_argument, NULL, 'y'},
        {0, 0, 0, 0}
    };

    optind = 1; // Reset getopt
    
    int c;
    while((c = getopt_long_only(argc, argv, short_opts, long_options, NULL)) >= 0) {
        switch(c) {
        case 1:
            // non-option argument
            if(strchr(optarg, '=')) {
                // old-style 'bs=' or 'timeout=' argument
                fprintf(stderr, "WARNING: old-style command-line argument encountered. This is deprecated.\n");
                if(!strncmp(optarg, "bs=", 3)) {
                    optarg += 3;
                    goto blocksize;
                }
                if(!strncmp(optarg, "timeout=", 8)) {
                    optarg += 8;
                    goto timeout;
                }
                usage_error(&result, "unknown option %s encountered", optarg);
                return result;
            }
            switch(nonspecial++) {
                case 0:
                    // host
                    client->hostn = optarg;
                    break;
                case 1:
                    // port
                    if(!strtol(optarg, NULL, 0)) {
                        // not parseable as a number, assume it's the device
                        client->dev = optarg;
                        nonspecial++;
                    } else {
                        port = optarg;
                    }
                    break;
                case 2:
                    // device
                    client->dev = optarg;
                    break;
                default:
                    usage_error(&result, "too many non-option arguments specified");
                    return result;
            }
            break;
        case 'b':
blocksize:
            client->bs = (int)strtol(optarg, NULL, 0);
            if(client->bs == 0 || (client->bs % 512) != 0) {
                usage_error(&result, "blocksize is not a multiple of 512! This is not allowed");
                return result;
            }
            break;
        case 'B':
            client->force_size64 = (uint64_t)strtoull(optarg, NULL, 0);
            if(client->force_size64 == 0) {
                usage_error(&result, "Invalid size");
                return result;
            }
            break;
        case 'c':
            result.check_conn = true;
            result.check_device = optarg;
            break;
        case 'C':
            client->nconn = (int)strtol(optarg, NULL, 0);
            break;
        case 'd':
            result.need_disconnect = true;
            client->dev = optarg;
            break;
        case 'g':
            client->no_optgo = true;
            break;
        case 'h':
            usage_error(&result, NULL); // Will show help
            return result;
#if HAVE_NETLINK
        case 'i':
            // identifier - store for later use in nbd-client.c
            result.identifier = optarg;
            break;
#endif
        case 'l':
            result.list_exports = true;
            client->dev = "";
            break;
#if HAVE_NETLINK
        case 'L':
            // nonetlink - store for later use in nbd-client.c  
            result.nonetlink = true;
            break;
#endif
        case 'm':
            // systemd mark - ignore for parsing test
            break;
        case 'n':
            // nofork - ignore for parsing test
            break;
        case 'N':
            client->name = optarg;
            break;
        case 'p':
            client->persist = true;
            break;
        case 'P':
            client->preinit = true;
            break;
        case 'R':
            client->force_ro = true;
            break;
        case 's':
            client->swap = true;
            break;
        case 'T':
            client->dead_conn_timeout = strtol(optarg, NULL, 0);
            break;
        case 't':
timeout:
            client->timeout = strtol(optarg, NULL, 0);
            break;
        case 'u':
            client->b_unix = true;
            break;
        case 'V':
            result.show_version = true;
            return result;
        case 'x':
            client->tls = true;
            break;
        case 'F':
            client->cert = optarg;
            break;
        case 'K':
            client->key = optarg;
            break;
        case 'A':
            client->cacert = optarg;
            break;
        case 'H':
            client->tlshostn = optarg;
            break;
        case 'y':
            client->priority = optarg;
            break;
        default:
            usage_error(&result, "option eaten by 42 mice");
            return result;
        }
    }

    // Handle post-parsing logic for nbdtab functionality
    if(client->hostn) {
        if((!client->name || !client->dev) && !result.list_exports) {
            if(!strncmp(client->hostn, "nbd", 3) || !strncmp(client->hostn, "/dev/nbd", 8)) {
                client->dev = client->hostn;
                // In real implementation, this would call get_from_config()
                // For testing, we just note that this is the nbdtab case
            }
        }
    } else if (!result.check_conn && !result.need_disconnect && !result.list_exports && !result.show_version) {
        usage_error(&result, "no information specified");
        return result;
    }

    // Copy final port value
    if(port != NBD_DEFAULT_PORT) {
        client->port = port;
    }

    return result;
}
