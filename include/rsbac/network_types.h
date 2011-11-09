/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2009:           */
/*   Amon Ott <ao@rsbac.org>           */
/* Network access control data structs */
/* Last modified: 03/Feb/2009          */
/************************************* */

#ifndef __RSBAC_NETWORK_TYPES_H
#define __RSBAC_NETWORK_TYPES_H

#define RSBAC_NET_ANY 0
#define RSBAC_NET_NETLINK_PROTO_ANY 255

#define RSBAC_NET_UNKNOWN 0

#define RSBAC_NET_TEMP_VERSION 2
#define RSBAC_NET_TEMP_OLD_VERSION 1
#define RSBAC_NET_TEMP_KEY 0x815affe
#define RSBAC_NET_TEMP_NAME "nettemp"

typedef __u32 rsbac_net_temp_id_t;

#define RSBAC_NET_MAX_ADDRESS_LEN 128
#define RSBAC_NET_TEMP_NAMELEN 16

#define RSBAC_NET_MAX_PORT 65535

#define RSBAC_NET_NR_INET_ADDR 25
#define RSBAC_NET_NR_PORTS 10

struct rsbac_net_temp_port_range_t {
	__u16 min;
	__u16 max;
};

struct rsbac_net_temp_inet_addr_t {
	__u32 addr[RSBAC_NET_NR_INET_ADDR];
	__u8 valid_bits[RSBAC_NET_NR_INET_ADDR];
	__u8 nr_addr;
};

struct rsbac_net_temp_other_addr_t {
	char addr[RSBAC_NET_MAX_ADDRESS_LEN];
	__u8 valid_len;
};

struct rsbac_net_temp_ports_t {
	struct rsbac_net_temp_port_range_t ports[RSBAC_NET_NR_PORTS];
	__u8 nr_ports;
};

union rsbac_net_temp_addr_t {
	struct rsbac_net_temp_inet_addr_t inet;
	struct rsbac_net_temp_other_addr_t other;
};

struct rsbac_net_temp_data_t {
	/* must be first for alignment */
	union rsbac_net_temp_addr_t address;
	__u8 address_family;
	__u8 type;
	__u8 protocol;
	rsbac_netdev_id_t netdev;
	struct rsbac_net_temp_ports_t ports;	/* for those address families that support them */
	char name[RSBAC_NET_TEMP_NAMELEN];
};

struct rsbac_net_temp_old_data_t {
	/* must be first for alignment */
	char address[RSBAC_NET_MAX_ADDRESS_LEN];
	__u8 address_family;
	__u8 valid_len;		/* Bytes for AF_UNIX, Bits for all others */
	__u8 type;
	__u8 protocol;
	rsbac_netdev_id_t netdev;
	__u16 min_port;		/* for those address families that support them */
	__u16 max_port;
	char name[RSBAC_NET_TEMP_NAMELEN];
};

#define RSBAC_NET_TEMP_LNET_ID 100101
#define RSBAC_NET_TEMP_LNET_ADDRESS "127.0.0.0"
#define RSBAC_NET_TEMP_LAN_ID 100102
#define RSBAC_NET_TEMP_LAN_ADDRESS "192.168.0.0"
#define RSBAC_NET_TEMP_AUTO_ID 100105
#define RSBAC_NET_TEMP_AUTO_ADDRESS "0.0.0.0"
#define RSBAC_NET_TEMP_INET_ID 100110
#define RSBAC_NET_TEMP_ALL_ID ((rsbac_net_temp_id_t) -1)

/* default templates moved into aci_data_structures.c */

struct rsbac_net_description_t {
	__u8 address_family;
	void *address;
	__u8 address_len;
	__u8 type;
	__u8 protocol;
	rsbac_netdev_id_t netdev;
	__u16 port;
};

enum rsbac_net_temp_syscall_t {
	NTS_new_template,
	NTS_copy_template,
	NTS_delete_template,
	NTS_check_id,
	NTS_get_address,
	NTS_get_address_family,
	NTS_get_type,
	NTS_get_protocol,
	NTS_get_netdev,
	NTS_get_ports,
	NTS_get_name,
	NTS_set_address,
	NTS_set_address_family,
	NTS_set_type,
	NTS_set_protocol,
	NTS_set_netdev,
	NTS_set_ports,
	NTS_set_name,
	NTS_none
};

union rsbac_net_temp_syscall_data_t {
	rsbac_net_temp_id_t id;
	union rsbac_net_temp_addr_t address;
	__u8 address_family;
	__u8 type;
	__u8 protocol;
	rsbac_netdev_id_t netdev;
	struct rsbac_net_temp_ports_t ports;	/* for those address families that support them */
	char name[RSBAC_NET_TEMP_NAMELEN];
};

/*
 *      Display an IP address in readable format.
 */

#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define HIPQUAD(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#endif

#endif
