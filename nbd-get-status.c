#include "config.h"
#include "lfs.h"

#include <stdio.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include "cliserv.h"
#include "nbd-netlink.h"

static struct nla_policy nbd_device_policy[NBD_DEVICE_ATTR_MAX + 1] = {
	[NBD_DEVICE_INDEX]		=	{ .type = NLA_U32 },
	[NBD_DEVICE_CONNECTED]		=	{ .type = NLA_U8 },
};

static struct nl_sock *get_nbd_socket(int *driver_id)
{
	struct nl_sock *socket;
	int id;

	socket = nl_socket_alloc();
	if (!socket)
		err("Couldn't allocate netlink socket\n");

	if (genl_connect(socket))
		err("Couldn't connect to the generic netlink socket\n");
	id = genl_ctrl_resolve(socket, "nbd");
	if (id < 0)
		err("Couldn't resolve the nbd netlink family, make sure the nbd module is loaded and your nbd driver supports the netlink interface.\n");
	if (driver_id)
		*driver_id = id;
	return socket;
}

static int callback(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *msg_attr[NBD_ATTR_MAX + 1];
	struct nlattr *attr;
	int ret, rem;

	ret = nla_parse(msg_attr, NBD_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
			genlmsg_attrlen(gnlh, 0), NULL);
	if (ret)
		err("Invalid response from get status?\n");

	nla_for_each_nested(attr, msg_attr[NBD_ATTR_DEVICE_LIST], rem) {
		struct nlattr *device[NBD_DEVICE_ATTR_MAX + 1];
		u32 index;
		uint8_t connected;

		if (nla_type(attr) != NBD_DEVICE_ITEM)
			err("Invalid attr type in the device list\n");
		ret = nla_parse_nested(device, NBD_DEVICE_ATTR_MAX, attr,
				       nbd_device_policy);
		if (ret)
			err("Invalid attr device attr\n");
		index = nla_get_u32(device[NBD_DEVICE_INDEX]);
		connected = nla_get_u8(device[NBD_DEVICE_CONNECTED]);
		printf("/dev/nbd%d: %s\n", (int)index,
		       connected ? "connected" : "disconnected");
	}
	return NL_OK;
}

int main(int argc, char **argv)
{
	struct nl_sock *socket;
	struct nlattr *sock_attr;
	struct nl_msg *msg;
	int driver_id;
	int index = -1;

	if (argc > 1) {
		if (sscanf(argv[1], "/dev/nbd%d", &index) != 1)
			err("Invalid nbd device target\n");
	}

	socket = get_nbd_socket(&driver_id);
	nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, callback, NULL);

	msg = nlmsg_alloc();
	if (!msg)
		err("Couldn't allocate netlink message\n");
	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
		    NBD_CMD_STATUS, 0);
	if (index >= 0)
		NLA_PUT_U32(msg, NBD_ATTR_INDEX, index);
	if (nl_send_sync(socket, msg) < 0)
		err("Failed to get status\n");
	return 0;
nla_put_failure:
	err("Failed to create netlink message\n");
}
