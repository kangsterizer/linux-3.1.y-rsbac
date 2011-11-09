/**************************************/
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2007:          */
/*   Amon Ott <ao@rsbac.org> */
/* Data structures / AUTH             */
/* Last modified: 16/Sep/2007         */
/**************************************/

#ifndef __RSBAC_AUTH_DATA_STRUC_H
#define __RSBAC_AUTH_DATA_STRUC_H

#include <linux/types.h>
#include <rsbac/aci.h>
#include <rsbac/types.h>

/**********************************************/
/* Capability lists                           */
/**********************************************/

#define RSBAC_AUTH_LIST_KEY 626281

#define RSBAC_AUTH_P_LIST_VERSION 1
#define RSBAC_AUTH_P_LIST_NAME "authproc"
#define RSBAC_AUTH_P_EFF_LIST_NAME "authproceff"
#define RSBAC_AUTH_P_FS_LIST_NAME "authprocfs"
#define RSBAC_AUTH_P_GROUP_LIST_NAME "authprocgr"
#define RSBAC_AUTH_P_GROUP_EFF_LIST_NAME "authprocgreff"
#define RSBAC_AUTH_P_GROUP_FS_LIST_NAME "authprocgrfs"

#define RSBAC_AUTH_FD_FILENAME "authfd"
#define RSBAC_AUTH_FD_EFF_FILENAME "authfde"
#define RSBAC_AUTH_FD_FS_FILENAME "authfdf"
#define RSBAC_AUTH_FD_GROUP_FILENAME "authfg"
#define RSBAC_AUTH_FD_GROUP_EFF_FILENAME "authfge"
#define RSBAC_AUTH_FD_GROUP_FS_FILENAME "authfgf"
#define RSBAC_AUTH_FD_OLD_FILENAME "authfd."
#define RSBAC_AUTH_FD_OLD_EFF_FILENAME "authfde."
#define RSBAC_AUTH_FD_OLD_FS_FILENAME "authfdf."
#define RSBAC_AUTH_FD_OLD_GROUP_FILENAME "authfg."
#define RSBAC_AUTH_FD_OLD_GROUP_EFF_FILENAME "authfge."
#define RSBAC_AUTH_FD_OLD_GROUP_FS_FILENAME "authfgf."
#define RSBAC_AUTH_NR_CAP_FD_LISTS 4
#define RSBAC_AUTH_NR_CAP_EFF_FD_LISTS 2
#define RSBAC_AUTH_NR_CAP_FS_FD_LISTS 2
#define RSBAC_AUTH_NR_CAP_GROUP_FD_LISTS 4
#define RSBAC_AUTH_NR_CAP_GROUP_EFF_FD_LISTS 2
#define RSBAC_AUTH_NR_CAP_GROUP_FS_FD_LISTS 2

#define RSBAC_AUTH_FD_LIST_VERSION 2
#define RSBAC_AUTH_FD_EFF_LIST_VERSION 2
#define RSBAC_AUTH_FD_FS_LIST_VERSION 2
#define RSBAC_AUTH_FD_GROUP_LIST_VERSION 2
#define RSBAC_AUTH_FD_GROUP_EFF_LIST_VERSION 2
#define RSBAC_AUTH_FD_GROUP_FS_LIST_VERSION 2
#define RSBAC_AUTH_FD_OLD_LIST_VERSION 1
#define RSBAC_AUTH_FD_EFF_OLD_LIST_VERSION 1
#define RSBAC_AUTH_FD_FS_OLD_LIST_VERSION 1
#define RSBAC_AUTH_FD_GROUP_OLD_LIST_VERSION 1
#define RSBAC_AUTH_FD_GROUP_EFF_OLD_LIST_VERSION 1
#define RSBAC_AUTH_FD_GROUP_FS_OLD_LIST_VERSION 1

/* The list of devices is also a double linked list, so we define list    */
/* items and a list head.                                                 */

struct rsbac_auth_device_list_item_t {
	kdev_t id;		/* set to 0 before deletion */
	u_int mount_count;
	rsbac_list_handle_t handle;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	rsbac_list_handle_t eff_handle;
	rsbac_list_handle_t fs_handle;
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
	rsbac_list_handle_t
	    group_handle;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	rsbac_list_handle_t
	    group_eff_handle;
	rsbac_list_handle_t
	    group_fs_handle;
#endif
#endif
	struct rsbac_auth_device_list_item_t *prev;
	struct rsbac_auth_device_list_item_t *next;
};

/* To provide consistency we use spinlocks for all list accesses. The     */
/* 'curr' entry is used to avoid repeated lookups for the same item.       */

struct rsbac_auth_device_list_head_t {
	struct rsbac_auth_device_list_item_t *head;
	struct rsbac_auth_device_list_item_t *tail;
	struct rsbac_auth_device_list_item_t *curr;
	u_int count;
};

#endif
