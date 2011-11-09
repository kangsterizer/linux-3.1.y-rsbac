/*********************************/
/* Rule Set Based Access Control */
/* Author and (c) 1999-2005:     */
/*   Amon Ott <ao@rsbac.org>     */
/* Data structures for Role      */
/* Compatibility module          */
/* Last modified: 21/Dec/2005    */
/*********************************/


#ifndef __RSBAC_RC_DATA_STRUC_H
#define __RSBAC_RC_DATA_STRUC_H

#ifdef __KERNEL__		/* only include in kernel code */
#include <linux/types.h>
#include <rsbac/types.h>
#endif				/* __KERNEL__ */

/* First of all we define dirname and filenames for saving the roles to disk. */
/* The path must be a valid single dir name! Each mounted device gets its    */
/* own file set, residing in 'DEVICE_ROOT/RSBAC_ACI_PATH/'.                  */
/* All user access to these files will be denied.                            */
/* Backups are kept in FILENAMEb.                                            */

#ifdef __KERNEL__
#define RSBAC_RC_LIST_KEY 77788855

#define RSBAC_RC_NR_ROLE_LISTS 4
#define RSBAC_RC_NR_TYPE_LISTS 4

/* roles */
#define RSBAC_RC_ROLE_FILENAME "rc_r"

/* roles we are compatible with ( = we can change to) */
#define RSBAC_RC_ROLE_RC_FILENAME "rc_rc"

/* roles we may administrate (replaces admin_type) */
#define RSBAC_RC_ROLE_ADR_FILENAME "rc_adr"

/* roles we may read and assign to users, if they were in one of these before. */
#define RSBAC_RC_ROLE_ASR_FILENAME "rc_asr"

/* file/dir/fifo/symlink types for new items, by parent efftype */
/* If not found, use old global value def_fd_create_type */
#define RSBAC_RC_ROLE_DFDC_FILENAME "rc_dfdc"

/* file/dir/fifo/symlink types and requests we are compatible with */
#define RSBAC_RC_ROLE_TCFD_FILENAME "rc_tcfd"

/* dev types and requests we are compatible with */
#define RSBAC_RC_ROLE_TCDV_FILENAME "rc_tcdv"

/* user types and requests we are compatible with */
#define RSBAC_RC_ROLE_TCUS_FILENAME "rc_tcus"

/* process types and requests we are compatible with */
#define RSBAC_RC_ROLE_TCPR_FILENAME "rc_tcpr"

/* IPC types and requests we are compatible with */
#define RSBAC_RC_ROLE_TCIP_FILENAME "rc_tcip"

/* SCD types and requests we are compatible with */
#define RSBAC_RC_ROLE_TCSC_FILENAME "rc_tcsc"

/* group types and requests we are compatible with */
#define RSBAC_RC_ROLE_TCGR_FILENAME "rc_tcgr"

/* NETDEV types and requests we are compatible with */
#define RSBAC_RC_ROLE_TCND_FILENAME "rc_tcnd"

/* NETTEMP types and requests we are compatible with */
#define RSBAC_RC_ROLE_TCNT_FILENAME "rc_tcnt"

/* NETOBJ types and requests we are compatible with */
#define RSBAC_RC_ROLE_TCNO_FILENAME "rc_tcno"

#define RSBAC_RC_ROLE_LIST_VERSION 5
#define RSBAC_RC_ROLE_OLD_LIST_VERSION 4
#define RSBAC_RC_ROLE_OLD_OLD_LIST_VERSION 3
#define RSBAC_RC_ROLE_OLD_OLD_OLD_LIST_VERSION 2
#define RSBAC_RC_ROLE_OLD_OLD_OLD_OLD_LIST_VERSION 1
#define RSBAC_RC_ROLE_RC_LIST_VERSION 1
#define RSBAC_RC_ROLE_ADR_LIST_VERSION 1
#define RSBAC_RC_ROLE_ASR_LIST_VERSION 1
#define RSBAC_RC_ROLE_DFDC_LIST_VERSION 1
#define RSBAC_RC_ROLE_TCFD_LIST_VERSION 2
#define RSBAC_RC_ROLE_TCDV_LIST_VERSION 2
#define RSBAC_RC_ROLE_TCUS_LIST_VERSION 2
#define RSBAC_RC_ROLE_TCPR_LIST_VERSION 2
#define RSBAC_RC_ROLE_TCIP_LIST_VERSION 2
#define RSBAC_RC_ROLE_TCSC_LIST_VERSION 2
#define RSBAC_RC_ROLE_TCGR_LIST_VERSION 2
#define RSBAC_RC_ROLE_TCND_LIST_VERSION 2
#define RSBAC_RC_ROLE_TCNT_LIST_VERSION 2
#define RSBAC_RC_ROLE_TCNO_LIST_VERSION 2
#define RSBAC_RC_ROLE_TCFD_OLD_LIST_VERSION 1
#define RSBAC_RC_ROLE_TCDV_OLD_LIST_VERSION 1
#define RSBAC_RC_ROLE_TCUS_OLD_LIST_VERSION 1
#define RSBAC_RC_ROLE_TCPR_OLD_LIST_VERSION 1
#define RSBAC_RC_ROLE_TCIP_OLD_LIST_VERSION 1
#define RSBAC_RC_ROLE_TCSC_OLD_LIST_VERSION 1
#define RSBAC_RC_ROLE_TCGR_OLD_LIST_VERSION 1
#define RSBAC_RC_ROLE_TCND_OLD_LIST_VERSION 1
#define RSBAC_RC_ROLE_TCNT_OLD_LIST_VERSION 1
#define RSBAC_RC_ROLE_TCNO_OLD_LIST_VERSION 1

#define RSBAC_RC_TYPE_FD_FILENAME "rc_tfd"
#define RSBAC_RC_TYPE_DEV_FILENAME "rc_tdv"
#define RSBAC_RC_TYPE_IPC_FILENAME "rc_tip"
#define RSBAC_RC_TYPE_USER_FILENAME "rc_tus"
#define RSBAC_RC_TYPE_PROCESS_FILENAME "rc_tpr"
#define RSBAC_RC_TYPE_GROUP_FILENAME "rc_tgr"
#define RSBAC_RC_TYPE_NETDEV_FILENAME "rc_tnd"
#define RSBAC_RC_TYPE_NETTEMP_FILENAME "rc_tnt"
#define RSBAC_RC_TYPE_NETOBJ_FILENAME "rc_tno"

#define RSBAC_RC_TYPE_FD_LIST_VERSION 1
#define RSBAC_RC_TYPE_DEV_LIST_VERSION 1
#define RSBAC_RC_TYPE_IPC_LIST_VERSION 1
#define RSBAC_RC_TYPE_USER_LIST_VERSION 1
#define RSBAC_RC_TYPE_PROCESS_LIST_VERSION 1
#define RSBAC_RC_TYPE_GROUP_LIST_VERSION 1
#define RSBAC_RC_TYPE_NETDEV_LIST_VERSION 1
#define RSBAC_RC_TYPE_NETTEMP_LIST_VERSION 1
#define RSBAC_RC_TYPE_NETOBJ_LIST_VERSION 1
#endif				/* __KERNEL__ */

/*
 * The following structures provide the role model data structures.
 * All RSBAC_RC_NR_ROLES roles and RSBAC_RC_NR_TYPES x target-no. types
 * and SCD-type definitions are kept in arrays and saved to disk as such.
 */

/***************************************
 *               Roles                 *
 ***************************************/

/* Caution: whenever role struct changes, version and old_version must be increased! */

struct rsbac_rc_role_entry_t {
	rsbac_enum_t admin_type;	/* role admin: none, system or role admin? */
	char name[RSBAC_RC_NAME_LEN];
	rsbac_rc_type_id_t def_fd_create_type;
	rsbac_rc_type_id_t def_user_create_type;
	rsbac_rc_type_id_t def_process_create_type;
	rsbac_rc_type_id_t def_process_chown_type;
	rsbac_rc_type_id_t def_process_execute_type;
	rsbac_rc_type_id_t def_ipc_create_type;
	rsbac_rc_type_id_t def_group_create_type;
	rsbac_rc_type_id_t def_unixsock_create_type;
	rsbac_enum_t boot_role;
	rsbac_enum_t req_reauth;
};

struct rsbac_rc_old_role_entry_t {
	rsbac_enum_t admin_type;	/* role admin: none, system or role admin? */
	char name[RSBAC_RC_NAME_LEN];
	rsbac_rc_type_id_t def_fd_create_type;
	rsbac_rc_type_id_t def_user_create_type;
	rsbac_rc_type_id_t def_process_create_type;
	rsbac_rc_type_id_t def_process_chown_type;
	rsbac_rc_type_id_t def_process_execute_type;
	rsbac_rc_type_id_t def_ipc_create_type;
	rsbac_rc_type_id_t def_group_create_type;
	rsbac_enum_t boot_role;
	rsbac_enum_t req_reauth;
};

struct rsbac_rc_old_old_role_entry_t {
	rsbac_enum_t admin_type;	/* role admin: none, system or role admin? */
	char name[RSBAC_RC_NAME_LEN];
	rsbac_rc_type_id_t def_fd_create_type;
	rsbac_rc_type_id_t def_user_create_type;
	rsbac_rc_type_id_t def_process_create_type;
	rsbac_rc_type_id_t def_process_chown_type;
	rsbac_rc_type_id_t def_process_execute_type;
	rsbac_rc_type_id_t def_ipc_create_type;
	rsbac_rc_type_id_t def_group_create_type;
	rsbac_enum_t boot_role;
};

struct rsbac_rc_old_old_old_role_entry_t {
	rsbac_enum_t admin_type;	/* role admin: none, system or role admin? */
	char name[RSBAC_RC_NAME_LEN];
	rsbac_rc_type_id_t def_fd_create_type;
	rsbac_rc_type_id_t def_user_create_type;
	rsbac_rc_type_id_t def_process_create_type;
	rsbac_rc_type_id_t def_process_chown_type;
	rsbac_rc_type_id_t def_process_execute_type;
	rsbac_rc_type_id_t def_ipc_create_type;
	rsbac_enum_t boot_role;
};

struct rsbac_rc_old_old_old_old_role_entry_t {
	rsbac_enum_t admin_type;	/* role admin: none, system or role admin? */
	char name[RSBAC_RC_NAME_LEN];
	rsbac_rc_type_id_t def_fd_create_type;
	rsbac_rc_type_id_t def_process_create_type;
	rsbac_rc_type_id_t def_process_chown_type;
	rsbac_rc_type_id_t def_process_execute_type;
	rsbac_rc_type_id_t def_ipc_create_type;
};

#define RSBAC_RC_NR_ROLE_ENTRY_ITEMS 25
#define RSBAC_RC_ROLE_ENTRY_ITEM_LIST { \
      RI_role_comp, \
      RI_admin_roles, \
      RI_assign_roles, \
      RI_type_comp_fd, \
      RI_type_comp_dev, \
      RI_type_comp_user, \
      RI_type_comp_process, \
      RI_type_comp_ipc, \
      RI_type_comp_scd, \
      RI_type_comp_group, \
      RI_type_comp_netdev, \
      RI_type_comp_nettemp, \
      RI_type_comp_netobj, \
      RI_admin_type, \
      RI_name, \
      RI_def_fd_create_type, \
      RI_def_fd_ind_create_type, \
      RI_def_user_create_type, \
      RI_def_process_create_type, \
      RI_def_process_chown_type, \
      RI_def_process_execute_type, \
      RI_def_ipc_create_type, \
      RI_def_group_create_type, \
      RI_boot_role, \
      RI_req_reauth \
      }

/***************************************
 *             Type names              *
 ***************************************/

/* Caution: whenever role struct changes, version and old_version must be increased! */

/* #define RSBAC_RC_OLD_TYPE_VERSION 1 */
#define RSBAC_RC_TYPE_VERSION 1

struct rsbac_rc_type_fd_entry_t {
	char name[RSBAC_RC_NAME_LEN];
	__u8 need_secdel;	/* rsbac_boolean_t */
};

#define RSBAC_RC_NR_TYPE_ENTRY_ITEMS 10
#define RSBAC_RC_TYPE_ENTRY_ITEM_LIST { \
      RI_type_fd_name, \
      RI_type_dev_name, \
      RI_type_ipc_name, \
      RI_type_scd_name, \
      RI_type_process_name, \
      RI_type_group_name, \
      RI_type_netdev_name, \
      RI_type_nettemp_name, \
      RI_type_netobj_name, \
      RI_type_fd_need_secdel \
      }

/**********************************************/
/*              Default values                */
/**********************************************/

#define RSBAC_RC_GENERAL_ROLE_ENTRY \
    { \
      .admin_type = RC_no_admin, \
      .name = "General User", \
      .def_fd_create_type = RC_type_inherit_parent, \
      .def_user_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_process_create_type = RC_type_inherit_parent, \
      .def_process_chown_type = RC_type_use_new_role_def_create, \
      .def_process_execute_type = RC_type_inherit_parent, \
      .def_ipc_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_group_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_unixsock_create_type = RC_type_use_fd, \
      .boot_role = FALSE, \
      .req_reauth = FALSE, \
    }

#define RSBAC_RC_ROLE_ADMIN_ROLE_ENTRY \
    { \
      .admin_type = RC_role_admin, \
      .name = "Role Admin", \
      .def_fd_create_type = RC_type_inherit_parent, \
      .def_user_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_process_create_type = RC_type_inherit_parent, \
      .def_process_chown_type = RC_type_use_new_role_def_create, \
      .def_process_execute_type = RC_type_inherit_parent, \
      .def_ipc_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_group_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_unixsock_create_type = RC_type_use_fd, \
      .boot_role = FALSE, \
      .req_reauth = FALSE, \
    }

#define RSBAC_RC_SYSTEM_ADMIN_ROLE_ENTRY \
    { \
      .admin_type = RC_system_admin, \
      .name = "System Admin", \
      .def_fd_create_type = RC_type_inherit_parent, \
      .def_user_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_process_create_type = RC_type_inherit_parent, \
      .def_process_chown_type = RC_type_use_new_role_def_create, \
      .def_process_execute_type = RC_type_inherit_parent, \
      .def_ipc_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_group_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_unixsock_create_type = RC_type_use_fd, \
      .boot_role = FALSE, \
      .req_reauth = FALSE, \
    }

#define RSBAC_RC_BOOT_ROLE_ENTRY \
    { \
      .admin_type = RC_no_admin, \
      .name = "System Boot", \
      .def_fd_create_type = RC_type_inherit_parent, \
      .def_user_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_process_create_type = RC_type_inherit_parent, \
      .def_process_chown_type = RC_type_use_new_role_def_create, \
      .def_process_execute_type = RC_type_inherit_parent, \
      .def_ipc_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_group_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_unixsock_create_type = RC_type_use_fd, \
      .boot_role = TRUE, \
      .req_reauth = FALSE, \
    }

#define RSBAC_RC_AUDITOR_ROLE_ENTRY \
    { \
      .admin_type = RC_no_admin, \
      .name = "Auditor", \
      .def_fd_create_type = RC_type_inherit_parent, \
      .def_user_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_process_create_type = RC_type_inherit_parent, \
      .def_process_chown_type = RC_type_use_new_role_def_create, \
      .def_process_execute_type = RC_type_inherit_parent, \
      .def_ipc_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_group_create_type = RSBAC_RC_GENERAL_TYPE, \
      .def_unixsock_create_type = RC_type_use_fd, \
      .boot_role = FALSE, \
      .req_reauth = FALSE, \
    }

/**********************************************/
/*              Declarations                  */
/**********************************************/

#ifdef __KERNEL__
#endif				/* __KERNEL__ */

#endif				/* __RSBAC_RC_DATA_STRUC_H */
