/*
 * net_helpers.c: Helper functions for the Network.
 *
 * Author and Copyright (C) 1999-2009 Amon Ott <ao@rsbac.org>
 *
 *      This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License as
 *      published by the Free Software Foundation, version 2.
 *
 * Last modified 03/Feb/2009.
 */

#include <rsbac/types.h>
#ifdef __KERNEL__
#include <rsbac/network.h>
#endif

static __u32 ipv4_mask[32] = {
  0x00000000, 0x00000080, 0x000000C0, 0x000000E0,
  0x000000F0, 0x000000F8, 0x000000FC, 0x000000FE,
  0x000000FF, 0x000080FF, 0x0000C0FF, 0x0000E0FF,
  0x0000F0FF, 0x0000F8FF, 0x0000FCFF, 0x0000FEFF,
  0x0000FFFF, 0x0080FFFF, 0x00C0FFFF, 0x00E0FFFF,
  0x00F0FFFF, 0x00F8FFFF, 0x00FCFFFF, 0x00FEFFFF,
  0x00FFFFFF, 0x80FFFFFF, 0xC0FFFFFF, 0xE0FFFFFF,
  0xF0FFFFFF, 0xF8FFFFFF, 0xFCFFFFFF, 0xFEFFFFFF
};

static inline __u32 rsbac_net_make_mask_u32(__u8 bits)
{                               
        if (bits >= 32)         
                return (__u32)-1UL;
        return ipv4_mask[bits];
}

#ifdef __KERNEL__
/* The lookup data param is always second, so we use it as description here! */
int rsbac_net_compare_data(void *data1, void *data2)
{
	struct rsbac_net_temp_data_t *temp = data1;
	struct rsbac_net_description_t *desc = data2;

	if (!temp || !desc)
		return 1;
	if ((temp->address_family != RSBAC_NET_ANY)
	    && (temp->address_family != desc->address_family)
	    )
		return 1;
	switch (desc->address_family) {
	case AF_INET:
		{
			__u32 mask;
			int i;

			if(temp->address.inet.nr_addr == 0)
				return 1;
			if ((temp->type != RSBAC_NET_ANY)
			    && (desc->type != temp->type)
			    )
				return 1;
			if ((temp->protocol != RSBAC_NET_ANY)
			    && (desc->protocol != temp->protocol)
			    )
				return 1;
			if(temp->ports.nr_ports > 0) {
				i=0;
				while(i < temp->ports.nr_ports) {
					if ((desc->port >= temp->ports.ports[i].min)
					&& (desc->port <= temp->ports.ports[i].max))
						break;
					i++;
				}
				if(i == temp->ports.nr_ports)
					return 1;
			}
			if (temp->netdev[0]
			    && (!desc->netdev[0]
				|| strncmp(desc->netdev, temp->netdev,
					   RSBAC_IFNAMSIZ))
			    )
				return 1;
			if (!desc->address)
				return 1;
			i=0;
			while(i < temp->address.inet.nr_addr) {
				mask = rsbac_net_make_mask_u32(temp->address.inet.valid_bits[i]);
				if ((((*(__u32 *) desc->address) & mask) ==
					(temp->address.inet.addr[i] & mask))
				    )
				    return 0;
				i++;
			}
			return 1;
		}

	case AF_NETLINK:
		if ((temp->type != RSBAC_NET_ANY)
		    && (desc->type != temp->type)
		    )
			return 1;
		if ((temp->protocol != RSBAC_NET_NETLINK_PROTO_ANY)
		    && (desc->protocol != temp->protocol)
		    )
			return 1;
		return 0;

		/* Other address families: only socket type checks for now */
	default:
		if ((temp->type != RSBAC_NET_ANY)
		    && (desc->type != temp->type)
		    )
			return 1;
		return 0;
	}
	return 1;
}
#endif
