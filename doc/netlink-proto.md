# The NBD Netlink Control Protocol

NOTE: this documentation is AI-generated and still needs review. Use with
caution.

## Introduction

The NBD kernel driver provides a netlink-based control interface that allows userspace
tools to configure, manage, and monitor NBD devices. This interface is used by the
nbd-client utility to establish connections, configure devices, and query status.

The netlink protocol uses the generic netlink (genl) framework with family name "nbd"
and version 0x1. It supports both unicast commands/responses and multicast notifications
for link death events.

## Protocol Overview

### Family Information

- **Family Name**: `nbd`
- **Version**: `0x1`
- **Multicast Group**: `nbd_mc_group`

### Message Types

The protocol defines the following command types:

- `NBD_CMD_CONNECT` - Connect and configure an NBD device
- `NBD_CMD_DISCONNECT` - Disconnect an NBD device
- `NBD_CMD_RECONFIGURE` - Reconfigure an existing connection
- `NBD_CMD_STATUS` - Query device status
- `NBD_CMD_LINK_DEAD` - Multicast notification of link failure (kernel → userspace)

## Attributes

### Configuration Attributes

These attributes are used with various commands:

- `NBD_ATTR_INDEX` (u32) - NBD device index
- `NBD_ATTR_SIZE_BYTES` (u64) - Device size in bytes
- `NBD_ATTR_BLOCK_SIZE_BYTES` (u64) - Block size in bytes
- `NBD_ATTR_TIMEOUT` (u64) - Connection timeout
- `NBD_ATTR_SERVER_FLAGS` (u64) - Server flags from negotiation
- `NBD_ATTR_CLIENT_FLAGS` (u64) - Client flags
- `NBD_ATTR_SOCKETS` (nested) - Socket configuration
- `NBD_ATTR_DEAD_CONN_TIMEOUT` (u64) - Dead connection timeout
- `NBD_ATTR_DEVICE_LIST` (nested) - List of devices (for STATUS response)
- `NBD_ATTR_BACKEND_IDENTIFIER` (string) - Backend identifier

### Socket Attributes

Nested within `NBD_ATTR_SOCKETS`:

- `NBD_SOCK_ITEM` (nested) - Individual socket item
  - `NBD_SOCK_FD` (u32) - File descriptor for the socket

### Device List Attributes

Nested within `NBD_ATTR_DEVICE_LIST`:

- `NBD_DEVICE_ITEM` (nested) - Individual device item
  - `NBD_DEVICE_INDEX` (u32) - Device index
  - `NBD_DEVICE_CONNECTED` (u8) - Connection status (1 = connected, 0 = disconnected)

## Command Details

### NBD_CMD_CONNECT

Connect and configure an NBD device.

**Request Attributes:**
- `NBD_ATTR_INDEX` (optional) - Device index to use, kernel assigns if not specified
- `NBD_ATTR_SIZE_BYTES` (required) - Export size in bytes
- `NBD_ATTR_BLOCK_SIZE_BYTES` (required) - Block size in bytes
- `NBD_ATTR_SERVER_FLAGS` (required) - Flags from server negotiation
- `NBD_ATTR_TIMEOUT` (optional) - Connection timeout in seconds
- `NBD_ATTR_SOCKETS` (required) - Nested socket configuration
- `NBD_ATTR_DEAD_CONN_TIMEOUT` (optional) - Dead connection timeout
- `NBD_ATTR_BACKEND_IDENTIFIER` (optional) - Backend identifier string

**Response Attributes:**
- `NBD_ATTR_INDEX` - Assigned device index

**Example Request Structure:**
```
NBD_CMD_CONNECT
├── NBD_ATTR_SIZE_BYTES: 10737418240
├── NBD_ATTR_BLOCK_SIZE_BYTES: 4096
├── NBD_ATTR_SERVER_FLAGS: 0x123
├── NBD_ATTR_TIMEOUT: 30
└── NBD_ATTR_SOCKETS
    ├── NBD_SOCK_ITEM
    │   └── NBD_SOCK_FD: 5
    └── NBD_SOCK_ITEM
        └── NBD_SOCK_FD: 6
```

### NBD_CMD_DISCONNECT

Disconnect an NBD device.

**Request Attributes:**
- `NBD_ATTR_INDEX` (required) - Device index to disconnect

**Response Attributes:**
- None (success/failure indicated by return code)

### NBD_CMD_RECONFIGURE

Reconfigure an existing NBD connection.

**Request Attributes:**
- `NBD_ATTR_INDEX` (required) - Device index to reconfigure
- `NBD_ATTR_SOCKETS` (required) - New socket configuration
- `NBD_ATTR_DEAD_CONN_TIMEOUT` (optional) - New dead connection timeout

**Response Attributes:**
- None (success/failure indicated by return code)

### NBD_CMD_STATUS

Query the status of NBD devices.

**Request Attributes:**
- `NBD_ATTR_INDEX` (optional) - Specific device index, or all devices if not specified

**Response Attributes:**
- `NBD_ATTR_DEVICE_LIST` - Nested list of device statuses
  - `NBD_DEVICE_ITEM` (repeated)
    - `NBD_DEVICE_INDEX` - Device index
    - `NBD_DEVICE_CONNECTED` - Connection status

**Example Response Structure:**
```
NBD_CMD_STATUS Response
└── NBD_ATTR_DEVICE_LIST
    ├── NBD_DEVICE_ITEM
    │   ├── NBD_DEVICE_INDEX: 0
    │   └── NBD_DEVICE_CONNECTED: 1
    ├── NBD_DEVICE_ITEM
    │   ├── NBD_DEVICE_INDEX: 1
    │   └── NBD_DEVICE_CONNECTED: 0
    └── NBD_DEVICE_ITEM
        ├── NBD_DEVICE_INDEX: 2
        └── NBD_DEVICE_CONNECTED: 1
```

### NBD_CMD_LINK_DEAD

Multicast notification sent by kernel when a link dies.

**Message Attributes:**
- `NBD_ATTR_INDEX` - Device index whose link died

**Delivery:**
- Sent via multicast group `nbd_mc_group`
- No direct response expected

## Error Handling

Commands return standard netlink error codes:
- Success: 0
- Invalid parameters: `-EINVAL`
- Device not found: `-ENOENT`
- Device busy: `-EBUSY`
- Memory allocation failure: `-ENOMEM`
- Permission denied: `-EPERM`

## Implementation Notes

### Socket Management

The kernel expects file descriptors for already-connected sockets to be passed
via `NBD_ATTR_SOCKETS`. This allows userspace to handle:
- TCP connections
- TLS negotiations
- Authentication
- Connection establishment

The kernel takes ownership of these file descriptors and will close them
when the device is disconnected.

### Timeout Handling

Two timeout types are supported:
- `NBD_ATTR_TIMEOUT` - Initial connection timeout
- `NBD_ATTR_DEAD_CONN_TIMEOUT` - Timeout for detecting dead connections

### Multicast Notifications

Userspace applications can subscribe to the `nbd_mc_group` multicast group
to receive asynchronous notifications about link death events.

## Security Considerations

- Netlink communications require appropriate capabilities (typically CAP_NET_ADMIN)
- File descriptors passed to the kernel are validated
- Backend identifiers should be treated as opaque strings
- Timeout values should be reasonable to avoid resource exhaustion

## Protocol Evolution

The protocol version is 0x1. Future versions will maintain backward compatibility
where possible, with new attributes being optional. Unknown attributes should be
ignored by implementations.

## Usage Examples

### Connecting a Device

```c
// Create netlink message
struct nl_msg *msg = nlmsg_alloc();
genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
           NBD_CMD_CONNECT, 0);

// Add attributes
NLA_PUT_U64(msg, NBD_ATTR_SIZE_BYTES, size);
NLA_PUT_U64(msg, NBD_ATTR_BLOCK_SIZE_BYTES, blocksize);
NLA_PUT_U64(msg, NBD_ATTR_SERVER_FLAGS, flags);

// Add sockets
struct nlattr *socks = nla_nest_start(msg, NBD_ATTR_SOCKETS);
for (i = 0; i < num_sockets; i++) {
    struct nlattr *sock = nla_nest_start(msg, NBD_SOCK_ITEM);
    NLA_PUT_U32(msg, NBD_SOCK_FD, sock_fds[i]);
    nla_nest_end(msg, sock);
}
nla_nest_end(msg, socks);

// Send message
nl_send_sync(socket, msg);
```

### Querying Status

```c
struct nl_msg *msg = nlmsg_alloc();
genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
           NBD_CMD_STATUS, 0);

// Optional: query specific device
NLA_PUT_U32(msg, NBD_ATTR_INDEX, device_index);

nl_send_sync(socket, msg);
```

### Disconnecting a Device

```c
struct nl_msg *msg = nlmsg_alloc();
genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, driver_id, 0, 0,
           NBD_CMD_DISCONNECT, 0);
NLA_PUT_U32(msg, NBD_ATTR_INDEX, device_index);
nl_send_sync(socket, msg);
```
