/**************************************/
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2006:          */
/*   Amon Ott <ao@rsbac.org> */
/* Data structures / MAC              */
/* Last modified: 12/Jan/2006         */
/**************************************/

#ifndef __RSBAC_MAC_DATA_STRUC_H
#define __RSBAC_MAC_DATA_STRUC_H

#include <linux/types.h>
#include <rsbac/aci.h>
#include <rsbac/types.h>

/**********************************************/
/* Capability lists                           */
/**********************************************/

#define RSBAC_MAC_LIST_KEY 626281

#define RSBAC_MAC_P_LIST_VERSION 1
#define RSBAC_MAC_P_LIST_NAME "macptru"

#define RSBAC_MAC_FD_FILENAME "macfdtru"
#define RSBAC_MAC_FD_OLD_FILENAME "macfdtru."
#define RSBAC_MAC_NR_TRU_FD_LISTS 4
#define RSBAC_MAC_FD_LIST_VERSION 2
#define RSBAC_MAC_FD_OLD_LIST_VERSION 1

/* The list of devices is also a double linked list, so we define list    */
/* items and a list head.                                                 */

struct rsbac_mac_device_list_item_t {
	kdev_t id;		/* set to 0 before deletion */
	u_int mount_count;
	rsbac_list_handle_t handle;
	struct rsbac_mac_device_list_item_t *prev;
	struct rsbac_mac_device_list_item_t *next;
};

/* To provide consistency we use spinlocks for all list accesses. The     */
/* 'curr' entry is used to avoid repeated lookups for the same item.       */

struct rsbac_mac_device_list_head_t {
	struct rsbac_mac_device_list_item_t *head;
	struct rsbac_mac_device_list_item_t *tail;
	struct rsbac_mac_device_list_item_t *curr;
	spinlock_t lock;
	struct lock_class_key lock_class;
	u_int count;
};

#endif
