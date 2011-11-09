/**************************************/
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2007:          */
/*   Amon Ott <ao@rsbac.org>          */
/* Data structures / ACL              */
/* Last modified: 25/Sep/2007         */
/**************************************/

#ifndef __RSBAC_ACL_DATA_STRUC_H
#define __RSBAC_ACL_DATA_STRUC_H

#include <linux/types.h>
#include <rsbac/aci.h>
#include <rsbac/types.h>
#include <rsbac/lists.h>

#define RSBAC_ACL_LIST_KEY 0x815affe

#define RSBAC_ACL_GENERAL_FD_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     ( RSBAC_FD_REQUEST_VECTOR & RSBAC_READ_WRITE_REQUEST_VECTOR ) | RSBAC_EXECUTE_REQUEST_VECTOR | RSBAC_ACL_GEN_RIGHTS_VECTOR }

#define RSBAC_ACL_ACMAN_FD_ENTRY \
   { ACLS_USER, \
     RSBAC_SECOFF_UID, \
     ( RSBAC_FD_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_EXECUTE_REQUEST_VECTOR | RSBAC_SECURITY_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_ACMAN_RIGHTS_VECTOR }

#define RSBAC_ACL_SYSADM_FD_ENTRY \
   { ACLS_USER, \
     RSBAC_SYSADM_UID, \
     ( RSBAC_FD_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_EXECUTE_REQUEST_VECTOR | RSBAC_SYSTEM_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_SYSADM_RIGHTS_VECTOR }

#define RSBAC_ACL_GENERAL_DEV_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     ( RSBAC_DEV_REQUEST_VECTOR & RSBAC_READ_WRITE_REQUEST_VECTOR ) | RSBAC_ACL_GEN_RIGHTS_VECTOR }

#define RSBAC_ACL_ACMAN_DEV_ENTRY \
   { ACLS_USER, \
     RSBAC_SECOFF_UID, \
     ( RSBAC_DEV_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SECURITY_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_ACMAN_RIGHTS_VECTOR }

#define RSBAC_ACL_SYSADM_DEV_ENTRY \
   { ACLS_USER, \
     RSBAC_SYSADM_UID, \
     ( RSBAC_DEV_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SYSTEM_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_SYSADM_RIGHTS_VECTOR }

#define RSBAC_ACL_GENERAL_IPC_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     ( RSBAC_IPC_REQUEST_VECTOR & RSBAC_READ_WRITE_REQUEST_VECTOR ) | RSBAC_ACL_GEN_RIGHTS_VECTOR }

#define RSBAC_ACL_ACMAN_IPC_ENTRY \
   { ACLS_USER, \
     RSBAC_SECOFF_UID, \
     ( RSBAC_IPC_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SECURITY_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_ACMAN_RIGHTS_VECTOR }

#define RSBAC_ACL_SYSADM_IPC_ENTRY \
   { ACLS_USER, \
     RSBAC_SYSADM_UID, \
     ( RSBAC_IPC_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SYSTEM_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_SYSADM_RIGHTS_VECTOR }

#define RSBAC_ACL_GENERAL_SCD_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     ( RSBAC_SCD_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) ) \
     ) \
     | RSBAC_ACL_GEN_RIGHTS_VECTOR \
   }

#ifdef CONFIG_RSBAC_USER_MOD_IOPERM
#define RSBAC_ACL_GENERAL_SCD_IOPORTS_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) \
   }
#endif

#define RSBAC_ACL_GENERAL_SCD_OTHER_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
   }

#define RSBAC_ACL_GENERAL_SCD_NETWORK_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) \
   }

#define RSBAC_ACL_ACMAN_SCD_ENTRY \
   { ACLS_USER, \
     RSBAC_SECOFF_UID, \
     ( RSBAC_SCD_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SECURITY_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_ACMAN_RIGHTS_VECTOR }

#define RSBAC_ACL_ACMAN_SCD_OTHER_ENTRY \
   { ACLS_USER, \
     RSBAC_SECOFF_UID, \
     ( RSBAC_NONE_REQUEST_VECTOR & \
       ( \
          ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
        | ((rsbac_request_vector_t) 1 << R_MODIFY_ATTRIBUTE) \
        | ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) \
        | ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) \
        | ((rsbac_request_vector_t) 1 << R_READ_ATTRIBUTE) \
        | ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) \
        | ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) \
       ) \
     ) \
     | RSBAC_ACL_ACMAN_RIGHTS_VECTOR }

#define RSBAC_ACL_SYSADM_SCD_ENTRY \
   { ACLS_USER, \
     RSBAC_SYSADM_UID, \
     ( RSBAC_SCD_REQUEST_VECTOR & \
       ( \
          ((rsbac_request_vector_t) 1 << R_GET_PERMISSIONS_DATA) \
        | ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) \
        | ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) \
        | ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) \
        | ((rsbac_request_vector_t) 1 << R_WRITE) \
       ) \
     ) \
     | RSBAC_ACL_SYSADM_RIGHTS_VECTOR }

#define RSBAC_ACL_SYSADM_SCD_OTHER_ENTRY \
   { ACLS_USER, \
     RSBAC_SYSADM_UID, \
     ( RSBAC_NONE_REQUEST_VECTOR & \
       ( \
          ((rsbac_request_vector_t) 1 << R_ADD_TO_KERNEL) \
        | ((rsbac_request_vector_t) 1 << R_CHANGE_GROUP) \
        | ((rsbac_request_vector_t) 1 << R_CHANGE_OWNER) \
        | ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) \
        | ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
        | ((rsbac_request_vector_t) 1 << R_MOUNT) \
        | ((rsbac_request_vector_t) 1 << R_REMOVE_FROM_KERNEL) \
        | ((rsbac_request_vector_t) 1 << R_UMOUNT) \
        | ((rsbac_request_vector_t) 1 << R_SHUTDOWN) \
       ) \
     ) \
     | ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) \
     | RSBAC_ACL_SYSADM_RIGHTS_VECTOR }

#define RSBAC_ACL_AUDITOR_SCD_RSBACLOG_ENTRY \
   { ACLS_USER, \
     RSBAC_AUDITOR_UID, \
     ( RSBAC_SCD_REQUEST_VECTOR & \
       ( \
          ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) \
        | ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA) \
       ) \
     ) \
   }

#ifdef CONFIG_RSBAC_USER_MOD_IOPERM
#define RSBAC_ACL_SYSADM_SCD_KMEM_ENTRY \
   { ACLS_USER, \
     RSBAC_SYSADM_UID, \
     ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) \
   }
#endif

#define RSBAC_ACL_GENERAL_U_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     RSBAC_REQUEST_VECTOR(R_CHANGE_OWNER) | RSBAC_REQUEST_VECTOR(R_SEARCH) \
     | RSBAC_REQUEST_VECTOR(R_GET_STATUS_DATA) }

#define RSBAC_ACL_ACMAN_U_ENTRY \
   { ACLS_USER, \
     RSBAC_SECOFF_UID, \
     RSBAC_ACL_USER_RIGHTS_VECTOR \
     | RSBAC_ACL_ACMAN_RIGHTS_VECTOR }

#define RSBAC_ACL_SYSADM_U_ENTRY \
   { ACLS_USER, \
     RSBAC_SYSADM_UID, \
     RSBAC_REQUEST_VECTOR(R_CHANGE_OWNER) | RSBAC_ACL_RIGHTS_VECTOR(R_READ_ATTRIBUTE) \
     | RSBAC_REQUEST_VECTOR(R_SEARCH) | RSBAC_REQUEST_VECTOR(R_GET_STATUS_DATA) \
     | RSBAC_REQUEST_VECTOR(R_AUTHENTICATE) \
     | RSBAC_ACL_SYSADM_RIGHTS_VECTOR }

#define RSBAC_ACL_GENERAL_P_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     ( RSBAC_PROCESS_REQUEST_VECTOR & RSBAC_READ_WRITE_REQUEST_VECTOR ) | RSBAC_ACL_GEN_RIGHTS_VECTOR }

#define RSBAC_ACL_ACMAN_P_ENTRY \
   { ACLS_USER, \
     RSBAC_SECOFF_UID, \
     ( RSBAC_PROCESS_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SECURITY_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_ACMAN_RIGHTS_VECTOR }

#define RSBAC_ACL_SYSADM_P_ENTRY \
   { ACLS_USER, \
     RSBAC_SYSADM_UID, \
     ( RSBAC_PROCESS_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SYSTEM_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_SYSADM_RIGHTS_VECTOR }

#define RSBAC_ACL_GENERAL_G_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     RSBAC_REQUEST_VECTOR(R_SEARCH) | RSBAC_REQUEST_VECTOR(R_READ) }

#define RSBAC_ACL_ACMAN_G_ENTRY \
   { ACLS_USER, \
     RSBAC_SECOFF_UID, \
     ( RSBAC_GROUP_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SECURITY_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_ACMAN_RIGHTS_VECTOR }

#define RSBAC_ACL_SYSADM_G_ENTRY \
   { ACLS_USER, \
     RSBAC_SYSADM_UID, \
     RSBAC_REQUEST_VECTOR(R_SEARCH) | RSBAC_REQUEST_VECTOR(R_READ) }

#define RSBAC_ACL_GENERAL_NETDEV_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     ( RSBAC_NETDEV_REQUEST_VECTOR ) | RSBAC_ACL_GEN_RIGHTS_VECTOR }

#define RSBAC_ACL_ACMAN_NETDEV_ENTRY \
   { ACLS_USER, \
     RSBAC_SECOFF_UID, \
     ( RSBAC_NETDEV_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SECURITY_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_ACMAN_RIGHTS_VECTOR }

#define RSBAC_ACL_SYSADM_NETDEV_ENTRY \
   { ACLS_USER, \
     RSBAC_SYSADM_UID, \
     ( RSBAC_NETDEV_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SYSTEM_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_SYSADM_RIGHTS_VECTOR }

#define RSBAC_ACL_GENERAL_NETTEMP_NT_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     ( RSBAC_NETTEMP_REQUEST_VECTOR & RSBAC_READ_REQUEST_VECTOR ) | RSBAC_ACL_GEN_RIGHTS_VECTOR }

#define RSBAC_ACL_ACMAN_NETTEMP_NT_ENTRY \
   { ACLS_USER, \
     RSBAC_SECOFF_UID, \
     ( RSBAC_NETTEMP_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SECURITY_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_ACMAN_RIGHTS_VECTOR }

#define RSBAC_ACL_SYSADM_NETTEMP_NT_ENTRY \
   { ACLS_USER, \
     RSBAC_SYSADM_UID, \
     ( RSBAC_NETTEMP_REQUEST_VECTOR & \
       ( RSBAC_READ_REQUEST_VECTOR | RSBAC_SYSTEM_REQUEST_VECTOR ) ) \
     | RSBAC_ACL_SYSADM_RIGHTS_VECTOR }

#define RSBAC_ACL_GENERAL_NETOBJ_ENTRY \
   { ACLS_GROUP, \
     RSBAC_ACL_GROUP_EVERYONE, \
     ( RSBAC_NETOBJ_REQUEST_VECTOR & RSBAC_READ_WRITE_REQUEST_VECTOR ) \
     | RSBAC_REQUEST_VECTOR(R_MODIFY_SYSTEM_DATA) \
     | RSBAC_ACL_GEN_RIGHTS_VECTOR }

#define RSBAC_ACL_ACMAN_NETOBJ_ENTRY \
   { ACLS_USER, \
     RSBAC_SECOFF_UID, \
     ( RSBAC_NETOBJ_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SECURITY_REQUEST_VECTOR ) ) \
     | RSBAC_REQUEST_VECTOR(R_MODIFY_SYSTEM_DATA) \
     | RSBAC_ACL_ACMAN_RIGHTS_VECTOR }

#define RSBAC_ACL_SYSADM_NETOBJ_ENTRY \
   { ACLS_USER, \
     RSBAC_SYSADM_UID, \
     ( RSBAC_NETOBJ_REQUEST_VECTOR & \
       ( RSBAC_READ_WRITE_REQUEST_VECTOR | RSBAC_SYSTEM_REQUEST_VECTOR ) ) \
     | RSBAC_REQUEST_VECTOR(R_MODIFY_SYSTEM_DATA) \
     | RSBAC_ACL_SYSADM_RIGHTS_VECTOR }


/**********************************************/
/* Lists of ACL / General subitems            */
/**********************************************/

/* Each list represents sets of ACL entries, using a set-id and a sublist each */

#define RSBAC_ACL_VERSION 1

/**********************************************/
/* ACL and device entries for File/Dir ACL    */
/**********************************************/

#define RSBAC_ACL_FD_FILENAME "aclfd"
#define RSBAC_ACL_FD_OLD_FILENAME "aclfd."
#define RSBAC_ACL_DEF_FD_FILENAME "aclfd.df"
#define RSBAC_ACL_NR_FD_LISTS 4
#define RSBAC_ACL_FD_LIST_VERSION 3
#define RSBAC_ACL_DEF_FD_LIST_VERSION 3
#define RSBAC_ACL_FD_OLD_LIST_VERSION 2
#define RSBAC_ACL_DEF_FD_OLD_LIST_VERSION 2
#define RSBAC_ACL_FD_OLD_OLD_LIST_VERSION 1
#define RSBAC_ACL_DEF_FD_OLD_OLD_LIST_VERSION 1

/* The list of devices is also a double linked list, so we define list    */
/* items and a list head.                                                 */

struct rsbac_acl_device_list_item_t {
	kdev_t id;
	u_int mount_count;
	rsbac_list_handle_t handle;
	struct rsbac_acl_device_list_item_t *prev;
	struct rsbac_acl_device_list_item_t *next;
};

/* To provide consistency we use spinlocks for all list accesses. The     */
/* 'curr' entry is used to avoid repeated lookups for the same item.       */

struct rsbac_acl_device_list_head_t {
	struct rsbac_acl_device_list_item_t *head;
	struct rsbac_acl_device_list_item_t *tail;
	struct rsbac_acl_device_list_item_t *curr;
	u_int count;
};


/**********************************************/
/* ACL entries for Device ACL                 */
/**********************************************/

#define RSBAC_ACL_DEV_FILENAME "acldev"
#define RSBAC_ACL_DEV_MAJOR_FILENAME "acldevm"
#define RSBAC_ACL_DEV_LIST_VERSION 4
#define RSBAC_ACL_DEV_OLD_LIST_VERSION 3
#define RSBAC_ACL_DEV_OLD_OLD_LIST_VERSION 2
#define RSBAC_ACL_DEV_OLD_OLD_OLD_LIST_VERSION 1
#define RSBAC_ACL_DEF_DEV_FILENAME "acldev.df"
#define RSBAC_ACL_DEF_DEV_LIST_VERSION 3
#define RSBAC_ACL_DEF_DEV_OLD_LIST_VERSION 2
#define RSBAC_ACL_DEF_DEV_OLD_OLD_LIST_VERSION 1

/**********************************************/
/* ACL entries for IPC ACL                    */
/**********************************************/

#define RSBAC_ACL_DEF_IPC_FILENAME "aclipc.df"
#define RSBAC_ACL_DEF_IPC_LIST_VERSION 3
#define RSBAC_ACL_DEF_IPC_OLD_LIST_VERSION 2
#define RSBAC_ACL_DEF_IPC_OLD_OLD_LIST_VERSION 1

/**********************************************/
/* ACL entries for SCD ACL                    */
/**********************************************/

#define RSBAC_ACL_SCD_FILENAME "aclscd"
#define RSBAC_ACL_DEF_SCD_FILENAME "aclscd.df"
#define RSBAC_ACL_SCD_LIST_VERSION 3
#define RSBAC_ACL_SCD_OLD_LIST_VERSION 2
#define RSBAC_ACL_SCD_OLD_OLD_LIST_VERSION 1
#define RSBAC_ACL_DEF_SCD_LIST_VERSION 3
#define RSBAC_ACL_DEF_SCD_OLD_LIST_VERSION 2
#define RSBAC_ACL_DEF_SCD_OLD_OLD_LIST_VERSION 1

/**********************************************/
/* ACL entries for user ACL                   */
/**********************************************/

#define RSBAC_ACL_U_FILENAME "acluser"
#define RSBAC_ACL_U_LIST_VERSION 2
#define RSBAC_ACL_U_OLD_LIST_VERSION 1
#define RSBAC_ACL_DEF_U_FILENAME "acluser.df"
#define RSBAC_ACL_DEF_U_LIST_VERSION 3
#define RSBAC_ACL_DEF_U_OLD_LIST_VERSION 2
#define RSBAC_ACL_DEF_U_OLD_OLD_LIST_VERSION 1

/**********************************************/
/* ACL entries for process ACL                */
/**********************************************/

#define RSBAC_ACL_DEF_P_FILENAME "aclproc.df"
#define RSBAC_ACL_DEF_P_LIST_VERSION 3
#define RSBAC_ACL_DEF_P_OLD_LIST_VERSION 2
#define RSBAC_ACL_DEF_P_OLD_OLD_LIST_VERSION 1

/**********************************************/
/* ACL entries for Linux group ACL            */
/**********************************************/

#define RSBAC_ACL_G_FILENAME "acllgrp"
#define RSBAC_ACL_G_LIST_VERSION 2
#define RSBAC_ACL_G_OLD_LIST_VERSION 1
#define RSBAC_ACL_DEF_G_FILENAME "acllgrp.df"
#define RSBAC_ACL_DEF_G_LIST_VERSION 3
#define RSBAC_ACL_DEF_G_OLD_LIST_VERSION 2
#define RSBAC_ACL_DEF_G_OLD_OLD_LIST_VERSION 1

/**********************************************/
/* ACL entries for Network Device ACL         */
/**********************************************/

#define RSBAC_ACL_NETDEV_FILENAME "aclndev"
#define RSBAC_ACL_NETDEV_LIST_VERSION 3
#define RSBAC_ACL_NETDEV_OLD_LIST_VERSION 2
#define RSBAC_ACL_NETDEV_OLD_OLD_LIST_VERSION 1
#define RSBAC_ACL_DEF_NETDEV_FILENAME "aclndev.df"
#define RSBAC_ACL_DEF_NETDEV_LIST_VERSION 3
#define RSBAC_ACL_DEF_NETDEV_OLD_LIST_VERSION 2
#define RSBAC_ACL_DEF_NETDEV_OLD_OLD_LIST_VERSION 1

/**********************************************/
/* ACL entries for Network Template NT (template protection) ACL */
/**********************************************/

#define RSBAC_ACL_NETTEMP_NT_FILENAME "aclntnt"
#define RSBAC_ACL_NETTEMP_NT_LIST_VERSION 3
#define RSBAC_ACL_NETTEMP_NT_OLD_LIST_VERSION 2
#define RSBAC_ACL_NETTEMP_NT_OLD_OLD_LIST_VERSION 1
#define RSBAC_ACL_DEF_NETTEMP_NT_FILENAME "aclntnt.df"
#define RSBAC_ACL_DEF_NETTEMP_NT_LIST_VERSION 3
#define RSBAC_ACL_DEF_NETTEMP_NT_OLD_LIST_VERSION 2
#define RSBAC_ACL_DEF_NETTEMP_NT_OLD_OLD_LIST_VERSION 1

/**********************************************/
/* ACL entries for Network Object ACL         */
/**********************************************/

#define RSBAC_ACL_NETTEMP_FILENAME "aclnt"
#define RSBAC_ACL_NETTEMP_LIST_VERSION 3
#define RSBAC_ACL_NETTEMP_OLD_LIST_VERSION 2
#define RSBAC_ACL_NETTEMP_OLD_OLD_LIST_VERSION 1
#define RSBAC_ACL_NETOBJ_FILENAME "aclno"
#define RSBAC_ACL_NETOBJ_LIST_VERSION 3
#define RSBAC_ACL_NETOBJ_OLD_LIST_VERSION 2
#define RSBAC_ACL_NETOBJ_OLD_OLD_LIST_VERSION 1
#define RSBAC_ACL_DEF_NETOBJ_FILENAME "aclno.df"
#define RSBAC_ACL_DEF_NETOBJ_LIST_VERSION 3
#define RSBAC_ACL_DEF_NETOBJ_OLD_LIST_VERSION 2
#define RSBAC_ACL_DEF_NETOBJ_OLD_OLD_LIST_VERSION 1


/**********************************************/
/* Group Lists                                */
/**********************************************/

#define RSBAC_ACL_GROUP_FILENAME "aclgrp"
#define RSBAC_ACL_GM_FILENAME "aclgm"

/* In acl_types.h: #define RSBAC_ACL_GROUP_VERSION 2 */

#define RSBAC_ACL_GM_VERSION 2
#define RSBAC_ACL_GM_OLD_VERSION 1

#endif
