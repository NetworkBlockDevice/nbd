#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>

/* Mock libnl structures and functions */
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/attr.h>
#include "../../nbd-netlink.h"

/* Real function pointers */
static int (*real_genl_connect)(struct nl_sock *sock) = NULL;
static int (*real_genl_ctrl_resolve)(struct nl_sock *sock, const char *name) = NULL;
static struct nl_sock *(*real_nl_socket_alloc)(void) = NULL;
static void (*real_nl_socket_free)(struct nl_sock *sock) = NULL;
static int (*real_nl_socket_modify_cb)(struct nl_sock *sock, enum nl_cb_type type, enum nl_cb_kind kind, nl_recvmsg_msg_cb_t func, void *arg) = NULL;
static struct nl_msg *(*real_nlmsg_alloc)(void) = NULL;
static void (*real_nlmsg_free)(struct nl_msg *msg) = NULL;
static void *(*real_genlmsg_put)(struct nl_msg *msg, uint32_t port, uint32_t seq, int family, int hdrlen, int flags, uint8_t cmd, uint8_t version) = NULL;
static struct nlmsghdr *(*real_nlmsg_hdr)(struct nl_msg *msg) = NULL;
static int (*real_nl_send_auto)(struct nl_sock *sock, struct nl_msg *msg) = NULL;
static int (*real_nl_wait_for_ack)(struct nl_sock *sock) = NULL;

/* Mock state */
static int mock_family_id = 42;
static int mock_connected = 0;
static struct nl_msg *last_sent_msg = NULL;

/* Initialize real function pointers */
static void init_real_functions(void) {
	if (!real_nl_socket_alloc) {
		real_nl_socket_alloc = dlsym(RTLD_NEXT, "nl_socket_alloc");
		real_nl_socket_free = dlsym(RTLD_NEXT, "nl_socket_free");
		real_genl_connect = dlsym(RTLD_NEXT, "genl_connect");
		real_genl_ctrl_resolve = dlsym(RTLD_NEXT, "genl_ctrl_resolve");
		real_nl_socket_modify_cb = dlsym(RTLD_NEXT, "nl_socket_modify_cb");
		real_nlmsg_alloc = dlsym(RTLD_NEXT, "nlmsg_alloc");
		real_nlmsg_free = dlsym(RTLD_NEXT, "nlmsg_free");
		real_genlmsg_put = dlsym(RTLD_NEXT, "genlmsg_put");
		real_nlmsg_hdr = dlsym(RTLD_NEXT, "nlmsg_hdr");
		real_nl_send_auto = dlsym(RTLD_NEXT, "nl_send_auto");
		real_nl_wait_for_ack = dlsym(RTLD_NEXT, "nl_wait_for_ack");
	}
}

/* Message validation functions */
static int validate_connect_message(struct nl_msg *msg) {
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnlh;
	struct nlattr *attrs[NBD_ATTR_MAX + 1];
	int ret;
	
	nlh = real_nlmsg_hdr(msg);
	if (!nlh) {
		fprintf(stderr, "MOCK: Failed to get netlink header\n");
		return -1;
	}
	
	gnlh = nlmsg_data(nlh);
	if (!gnlh) {
		fprintf(stderr, "MOCK: Failed to get genl header\n");
		return -1;
	}
	
	if (gnlh->cmd != NBD_CMD_CONNECT) {
		fprintf(stderr, "MOCK: Expected NBD_CMD_CONNECT, got %d\n", gnlh->cmd);
		return -1;
	}
	
	ret = genlmsg_parse(nlh, 0, attrs, NBD_ATTR_MAX, NULL);
	if (ret != 0) {
		fprintf(stderr, "MOCK: Failed to parse attributes: %d\n", ret);
		return -1;
	}
	
	/* Validate required attributes */
	if (!attrs[NBD_ATTR_SIZE_BYTES]) {
		fprintf(stderr, "MOCK: Missing required NBD_ATTR_SIZE_BYTES\n");
		return -1;
	}
	
	if (!attrs[NBD_ATTR_BLOCK_SIZE_BYTES]) {
		fprintf(stderr, "MOCK: Missing required NBD_ATTR_BLOCK_SIZE_BYTES\n");
		return -1;
	}
	
	if (!attrs[NBD_ATTR_SERVER_FLAGS]) {
		fprintf(stderr, "MOCK: Missing required NBD_ATTR_SERVER_FLAGS\n");
		return -1;
	}
	
	if (!attrs[NBD_ATTR_SOCKETS]) {
		fprintf(stderr, "MOCK: Missing required NBD_ATTR_SOCKETS\n");
		return -1;
	}
	
	/* Validate attribute values */
	uint64_t size = nla_get_u64(attrs[NBD_ATTR_SIZE_BYTES]);
	if (size == 0) {
		fprintf(stderr, "MOCK: Invalid size_bytes: %lu\n", size);
		return -1;
	}
	
	uint64_t block_size = nla_get_u64(attrs[NBD_ATTR_BLOCK_SIZE_BYTES]);
	if (block_size == 0 || (block_size & (block_size - 1)) != 0) {
		fprintf(stderr, "MOCK: Invalid block_size_bytes: %lu (must be power of 2)\n", block_size);
		return -1;
	}
	
	printf("MOCK: ✓ Connect message validation passed\n");
	printf("MOCK:   Size: %lu, Block size: %lu, Flags: %lu\n", 
	       size, block_size, nla_get_u64(attrs[NBD_ATTR_SERVER_FLAGS]));
	
	return 0;
}

static int validate_disconnect_message(struct nl_msg *msg) {
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnlh;
	struct nlattr *attrs[NBD_ATTR_MAX + 1];
	int ret;
	
	nlh = real_nlmsg_hdr(msg);
	if (!nlh) return -1;
	
	gnlh = nlmsg_data(nlh);
	if (!gnlh) return -1;
	
	if (gnlh->cmd != NBD_CMD_DISCONNECT) {
		fprintf(stderr, "MOCK: Expected NBD_CMD_DISCONNECT, got %d\n", gnlh->cmd);
		return -1;
	}
	
	ret = genlmsg_parse(nlh, 0, attrs, NBD_ATTR_MAX, NULL);
	if (ret != 0) return -1;
	
	if (!attrs[NBD_ATTR_INDEX]) {
		fprintf(stderr, "MOCK: Missing required NBD_ATTR_INDEX for disconnect\n");
		return -1;
	}
	
	printf("MOCK: ✓ Disconnect message validation passed\n");
	printf("MOCK:   Device index: %u\n", nla_get_u32(attrs[NBD_ATTR_INDEX]));
	
	return 0;
}

static int validate_status_message(struct nl_msg *msg) {
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnlh;
	
	nlh = real_nlmsg_hdr(msg);
	if (!nlh) return -1;
	
	gnlh = nlmsg_data(nlh);
	if (!gnlh) return -1;
	
	if (gnlh->cmd != NBD_CMD_STATUS) {
		fprintf(stderr, "MOCK: Expected NBD_CMD_STATUS, got %d\n", gnlh->cmd);
		return -1;
	}
	
	printf("MOCK: ✓ Status message validation passed\n");
	
	return 0;
}

/* Mock implementations */
struct nl_sock *nl_socket_alloc(void) {
	init_real_functions();
	return real_nl_socket_alloc();
}

void nl_socket_free(struct nl_sock *sock) {
	init_real_functions();
	real_nl_socket_free(sock);
}

int genl_connect(struct nl_sock *sock) {
	init_real_functions();
	mock_connected = 1;
	printf("MOCK: genl_connect() - success\n");
	return 0; /* Always succeed in mock */
}

int genl_ctrl_resolve(struct nl_sock *sock, const char *name) {
	init_real_functions();
	
	if (strcmp(name, "nbd") == 0) {
		printf("MOCK: genl_ctrl_resolve(nbd) - returning mock family ID %d\n", mock_family_id);
		return mock_family_id;
	}
	
	printf("MOCK: genl_ctrl_resolve(%s) - not found\n", name);
	return -ENOENT;
}

int nl_socket_modify_cb(struct nl_sock *sock, enum nl_cb_type type, enum nl_cb_kind kind, nl_recvmsg_msg_cb_t func, void *arg) {
	init_real_functions();
	printf("MOCK: nl_socket_modify_cb() - callback registered\n");
	return real_nl_socket_modify_cb(sock, type, kind, func, arg);
}

struct nl_msg *nlmsg_alloc(void) {
	init_real_functions();
	return real_nlmsg_alloc();
}

void nlmsg_free(struct nl_msg *msg) {
	init_real_functions();
	if (msg == last_sent_msg) {
		last_sent_msg = NULL;
	}
	real_nlmsg_free(msg);
}

void *genlmsg_put(struct nl_msg *msg, uint32_t port, uint32_t seq, int family, int hdrlen, int flags, uint8_t cmd, uint8_t version) {
	init_real_functions();
	return real_genlmsg_put(msg, port, seq, family, hdrlen, flags, cmd, version);
}

struct nlmsghdr *nlmsg_hdr(struct nl_msg *msg) {
	init_real_functions();
	return real_nlmsg_hdr(msg);
}

int nl_send_auto(struct nl_sock *sock, struct nl_msg *msg) {
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnlh;
	int validation_result = -1;
	
	init_real_functions();
	
	printf("MOCK: nl_send_auto() - intercepting message\n");
	
	/* Store the message for validation */
	if (last_sent_msg) {
		real_nlmsg_free(last_sent_msg);
	}
	last_sent_msg = msg;
	
	/* Validate the message */
	nlh = real_nlmsg_hdr(msg);
	if (nlh) {
		gnlh = nlmsg_data(nlh);
		if (gnlh) {
			switch (gnlh->cmd) {
			case NBD_CMD_CONNECT:
				validation_result = validate_connect_message(msg);
				break;
			case NBD_CMD_DISCONNECT:
				validation_result = validate_disconnect_message(msg);
				break;
			case NBD_CMD_STATUS:
				validation_result = validate_status_message(msg);
				break;
			default:
				printf("MOCK: Unknown command %d, skipping validation\n", gnlh->cmd);
				validation_result = 0;
				break;
			}
		}
	}
	
	if (validation_result != 0) {
		fprintf(stderr, "MOCK: Message validation failed!\n");
		return -EINVAL;
	}
	
	/* Don't actually send, just pretend it worked */
	printf("MOCK: nl_send_auto() - success (message not actually sent)\n");
	return 0;
}

int nl_wait_for_ack(struct nl_sock *sock) {
	init_real_functions();
	printf("MOCK: nl_wait_for_ack() - success (mock)\n");
	return 0; /* Always succeed in mock */
}
