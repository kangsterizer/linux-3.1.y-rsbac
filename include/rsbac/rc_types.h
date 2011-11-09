/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2005: Amon Ott */
/* API: Data types for                */
/*    Role Compatibility Module       */
/* Last modified: 21/Dec/2005         */
/************************************ */

#ifndef __RSBAC_RC_TYPES_H
#define __RSBAC_RC_TYPES_H

#include <linux/types.h>

/***** RC *****/

#define RSBAC_RC_GENERAL_ROLE 0
#define RSBAC_RC_ROLE_ADMIN_ROLE 1
#define RSBAC_RC_SYSTEM_ADMIN_ROLE 2
#define RSBAC_RC_AUDITOR_ROLE 3
#define RSBAC_RC_BOOT_ROLE 999999
#define RSBAC_RC_GENERAL_TYPE 0
#define RSBAC_RC_SEC_TYPE 1
#define RSBAC_RC_SYS_TYPE 2
#define RSBAC_RC_KERNEL_P_TYPE 999999

#define RSBAC_RC_NAME_LEN 16
#define RSBAC_RC_ALL_REQUESTS ((rsbac_rc_request_vector_t) -1)

#define RSBAC_RC_OLD_SPECIAL_RIGHT_BASE 48
#define RSBAC_RC_SPECIAL_RIGHT_BASE 56

enum rsbac_rc_special_rights_t { RCR_ADMIN = RSBAC_RC_SPECIAL_RIGHT_BASE,
	RCR_ASSIGN,
	RCR_ACCESS_CONTROL,
	RCR_SUPERVISOR,
	RCR_MODIFY_AUTH,
	RCR_CHANGE_AUTHED_OWNER,
	RCR_SELECT,
	RCR_NONE
};

typedef __u64 rsbac_rc_rights_vector_t;

/* backwards compatibility only! */
typedef __u64 rsbac_rc_role_vector_t;

#define RSBAC_RC_RIGHTS_VECTOR(x) ((rsbac_rc_rights_vector_t) 1 << (x))
#define RSBAC_RC_ROLE_VECTOR(x) ((rsbac_rc_role_vector_t) 1 << (x))
#define RSBAC_RC_TYPE_VECTOR(x) ((rsbac_rc_type_vector_t) 1 << (x))

#define RSBAC_RC_SPECIAL_RIGHTS_VECTOR (\
  RSBAC_RC_RIGHTS_VECTOR(RCR_ADMIN) | \
  RSBAC_RC_RIGHTS_VECTOR(RCR_ASSIGN) | \
  RSBAC_RC_RIGHTS_VECTOR(RCR_ACCESS_CONTROL) | \
  RSBAC_RC_RIGHTS_VECTOR(RCR_SUPERVISOR) | \
  RSBAC_RC_RIGHTS_VECTOR(RCR_MODIFY_AUTH) | \
  RSBAC_RC_RIGHTS_VECTOR(RCR_CHANGE_AUTHED_OWNER) | \
  RSBAC_RC_RIGHTS_VECTOR(RCR_SELECT) \
  )

#define RSBAC_RC_SUPERVISOR_RIGHT_VECTOR (\
    RSBAC_RC_RIGHTS_VECTOR(RCR_SUPERVISOR) | \
  )

#define RSBAC_RC_ALL_RIGHTS_VECTOR (RSBAC_ALL_REQUEST_VECTOR | RSBAC_RC_SPECIAL_RIGHTS_VECTOR)

#define RSBAC_RC_PROCESS_RIGHTS_VECTOR (RSBAC_PROCESS_REQUEST_VECTOR | \
  RSBAC_RC_RIGHTS_VECTOR(R_CONNECT) | \
  RSBAC_RC_RIGHTS_VECTOR(R_ACCEPT) | \
  RSBAC_RC_RIGHTS_VECTOR(R_SEND) | \
  RSBAC_RC_RIGHTS_VECTOR(R_RECEIVE) \
)

#define RSBAC_RC_DEFAULT_RIGHTS_VECTOR 0

#define RSBAC_RC_GEN_RIGHTS_VECTOR RSBAC_RC_DEFAULT_RIGHTS_VECTOR

typedef __u32 rsbac_rc_role_id_t;
typedef __u32 rsbac_rc_type_id_t;
typedef rsbac_request_vector_t rsbac_rc_request_vector_t;

enum rsbac_rc_admin_type_t { RC_no_admin, RC_role_admin, RC_system_admin,
	    RC_none };

/*
 * System Control Types, including general SCD types
 * (start at 32 to allow future SCD types, max is 63)
 */
#define RST_min 32
enum rsbac_rc_scd_type_t { RST_auth_administration = RST_min,
	RST_none
};

/* what should always be there to keep system functional */
#ifdef CONFIG_RSBAC_USER_MOD_IOPERM
#define RSBAC_RC_GENERAL_COMP_SCD { \
                          0, \
                          0, \
                          0, \
                          0, \
         /* ST_ioports */ ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA), \
         /* ST_rlimit */ RSBAC_REQUEST_VECTOR(GET_STATUS_DATA) | RSBAC_REQUEST_VECTOR(MODIFY_SYSTEM_DATA), \
         /* ST_swap */              0, \
         /* ST_syslog */            0, \
         /* ST_rsbac */             0, \
         /* ST_rsbac_log */         0, \
         /* ST_other */             ( \
                                       ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
                                    ), \
         /* ST_kmem */              0, \
         /* ST_network */           ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA), \
         /* 13 = ST_none */         0 \
          }
#else
#define RSBAC_RC_GENERAL_COMP_SCD { \
                          0, \
                          0, \
                          0, \
                          0, \
                          0, \
         /* ST_rlimit */ RSBAC_REQUEST_VECTOR(GET_STATUS_DATA) | RSBAC_REQUEST_VECTOR(MODIFY_SYSTEM_DATA), \
         /* ST_swap */              0, \
         /* ST_syslog */            0, \
         /* ST_rsbac */             0, \
         /* ST_rsbac_log */         0, \
         /* ST_other */             ( \
                                       ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
                                    ), \
         /* ST_kmem */              0, \
         /* ST_network */           ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA), \
         /* ST_firewall */          0, \
         /* ST_priority */          0, \
         /* 15 = ST_none */         0 \
          }
#endif

#define RSBAC_RC_ROLEADM_COMP_SCD { \
         /* 0 = ST_time_structs */  0, \
         /* ST_clock */             0, \
         /* ST_host_id */           0, \
         /* ST_net_id */            0, \
         /* ST_ioports */           0, \
         /* ST_rlimit */            RSBAC_SCD_REQUEST_VECTOR | RSBAC_RC_SPECIAL_RIGHTS_VECTOR, \
         /* ST_swap */              0, \
         /* ST_syslog */            0, \
         /* ST_rsbac */             RSBAC_SCD_REQUEST_VECTOR | RSBAC_RC_SPECIAL_RIGHTS_VECTOR, \
         /* ST_rsbac_log */         RSBAC_SCD_REQUEST_VECTOR | RSBAC_RC_SPECIAL_RIGHTS_VECTOR, \
         /* ST_other */             ( \
                                       ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
                                     | ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) \
                                     | ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA) \
                                     | ((rsbac_request_vector_t) 1 << R_SWITCH_LOG) \
                                     | ((rsbac_request_vector_t) 1 << R_SWITCH_MODULE) \
                                    ) | RSBAC_RC_SPECIAL_RIGHTS_VECTOR, \
         /* ST_kmem */              0, \
         /* ST_network */           ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | RSBAC_RC_SPECIAL_RIGHTS_VECTOR, \
         /* ST_firewall */          ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | RSBAC_RC_SPECIAL_RIGHTS_VECTOR, \
         /* ST_nice */              0, \
         /* 15 = ST_none */         0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
         /* 20 */                   0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
         /* 30 */                   0, \
                                    0, \
         /* 32 = RST_auth_admin */  RSBAC_SCD_REQUEST_VECTOR | RSBAC_RC_SPECIAL_RIGHTS_VECTOR, \
         /* 33 = RST_none */        0 \
          }

#define RSBAC_RC_SYSADM_COMP_SCD { \
         /* 0 = ST_time_structs */  RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* ST_clock */             RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* ST_host_id */           RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* ST_net_id */            RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* ST_ioports */           RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* ST_rlimit */            RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* ST_swap */              RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* ST_syslog */            RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* ST_rsbac */             RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* ST_rsbac_log */         0, \
         /* ST_other */             ( \
                                       ((rsbac_request_vector_t) 1 << R_ADD_TO_KERNEL) \
                                     | ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) \
                                     | ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
                                     | ((rsbac_request_vector_t) 1 << R_MOUNT) \
                                     | ((rsbac_request_vector_t) 1 << R_REMOVE_FROM_KERNEL) \
                                     | ((rsbac_request_vector_t) 1 << R_UMOUNT) \
                                     | ((rsbac_request_vector_t) 1 << R_SHUTDOWN) \
                                    ), \
         /* ST_kmem */              RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* ST_network */           RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* ST_firewall */          RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* ST_priority */          RSBAC_SCD_REQUEST_VECTOR & RSBAC_SYSTEM_REQUEST_VECTOR, \
         /* 15 = ST_none */         0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
         /* 20 */                   0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
                                    0, \
         /* 30 */                   0, \
                                    0, \
         /* 32 = RST_auth_admin */  0, \
         /* 33 = RST_none */        0 \
          }
#ifdef CONFIG_RSBAC_USER_MOD_IOPERM
#define RSBAC_RC_AUDITOR_COMP_SCD { \
                          0, \
                          0, \
                          0, \
                          0, \
         /* ST_ioports */ ((rsbac_request_vector_t) 1 << R_MODIFY_PERMISSIONS_DATA), \
         /* ST_rlimit */  RSBAC_REQUEST_VECTOR(GET_STATUS_DATA) | RSBAC_REQUEST_VECTOR(MODIFY_SYSTEM_DATA), \
         /* ST_swap */              0, \
         /* ST_syslog */            0, \
         /* ST_rsbac */             0, \
         /* ST_rsbac_log */         ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA), \
         /* ST_other */             ( \
                                       ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
                                    ), \
         /* ST_kmem */              0, \
         /* ST_network */           ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA), \
         /* ST_firewall */          0, \
         /* ST_priority */          0, \
         /* 15 = ST_none */         0 \
          }
#else
#define RSBAC_RC_AUDITOR_COMP_SCD { \
                          0, \
                          0, \
                          0, \
                          0, \
                          0, \
         /* ST_rlimit */  RSBAC_REQUEST_VECTOR(GET_STATUS_DATA) | RSBAC_REQUEST_VECTOR(MODIFY_SYSTEM_DATA), \
         /* ST_swap */              0, \
         /* ST_syslog */            0, \
         /* ST_rsbac */             0, \
         /* ST_rsbac_log */         ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA) | ((rsbac_request_vector_t) 1 << R_MODIFY_SYSTEM_DATA), \
         /* ST_other */             ( \
                                       ((rsbac_request_vector_t) 1 << R_MAP_EXEC) \
                                    ), \
         /* ST_kmem */              0, \
         /* ST_network */           ((rsbac_request_vector_t) 1 << R_GET_STATUS_DATA), \
         /* ST_firewall */          0, \
         /* ST_priority */          0, \
         /* 15 = ST_none */         0 \
          }
#endif


#define RC_type_inherit_process ((rsbac_rc_type_id_t) -1)
#define RC_type_inherit_parent ((rsbac_rc_type_id_t) -2)
#define RC_type_no_create ((rsbac_rc_type_id_t) -3)
#define RC_type_no_execute ((rsbac_rc_type_id_t) -4)
#define RC_type_use_new_role_def_create ((rsbac_rc_type_id_t) -5)	/* for process chown (setuid) */
#define RC_type_no_chown ((rsbac_rc_type_id_t) -6)
#define RC_type_use_fd ((rsbac_rc_type_id_t) -7)
#define RC_type_min_special ((rsbac_rc_type_id_t) -7)
#define RC_type_max_value ((rsbac_rc_type_id_t) -32)

#define RC_role_inherit_user ((rsbac_rc_role_id_t) -1)
#define RC_role_inherit_process ((rsbac_rc_role_id_t) -2)
#define RC_role_inherit_parent ((rsbac_rc_role_id_t) -3)
#define RC_role_inherit_up_mixed ((rsbac_rc_role_id_t) -4)
#define RC_role_use_force_role ((rsbac_rc_role_id_t) -5)
#define RC_role_min_special ((rsbac_rc_role_id_t) -5)
#define RC_role_max_value ((rsbac_rc_role_id_t) -32)

#define RC_default_force_role RC_role_inherit_parent
#define RC_default_root_dir_force_role RC_role_inherit_up_mixed
#define RC_default_init_force_role RC_role_inherit_user
#define RC_default_initial_role RC_role_inherit_parent
#define RC_default_root_dir_initial_role RC_role_use_force_role

/****************************************************************************/
/* RC ACI types                                                             */
/****************************************************************************/

enum rsbac_rc_target_t { RT_ROLE, RT_TYPE, RT_NONE };

union rsbac_rc_target_id_t {
	rsbac_rc_role_id_t role;
	rsbac_rc_type_id_t type;
};

enum rsbac_rc_item_t { RI_role_comp,
	RI_admin_roles,
	RI_assign_roles,
	RI_type_comp_fd,
	RI_type_comp_dev,
	RI_type_comp_user,
	RI_type_comp_process,
	RI_type_comp_ipc,
	RI_type_comp_scd,
	RI_type_comp_group,
	RI_type_comp_netdev,
	RI_type_comp_nettemp,
	RI_type_comp_netobj,
	RI_admin_type,
	RI_name,
	RI_def_fd_create_type,
	RI_def_fd_ind_create_type,
	RI_def_user_create_type,
	RI_def_process_create_type,
	RI_def_process_chown_type,
	RI_def_process_execute_type,
	RI_def_ipc_create_type,
	RI_def_group_create_type,
	RI_def_unixsock_create_type,
	RI_boot_role,
	RI_req_reauth,
	RI_type_fd_name,
	RI_type_dev_name,
	RI_type_ipc_name,
	RI_type_user_name,
	RI_type_process_name,
	RI_type_group_name,
	RI_type_netdev_name,
	RI_type_nettemp_name,
	RI_type_netobj_name,
	RI_type_fd_need_secdel,
	RI_type_scd_name,	/* Pseudo, using get_rc_scd_name() */
	RI_remove_role,
	RI_def_fd_ind_create_type_remove,
	RI_type_fd_remove,
	RI_type_dev_remove,
	RI_type_ipc_remove,
	RI_type_user_remove,
	RI_type_process_remove,
	RI_type_group_remove,
	RI_type_netdev_remove,
	RI_type_nettemp_remove,
	RI_type_netobj_remove,
#ifdef __KERNEL__
#endif
	RI_none
};

union rsbac_rc_item_value_t {
	rsbac_rc_rights_vector_t rights;
	enum rsbac_rc_admin_type_t admin_type;
	char name[RSBAC_RC_NAME_LEN];
	rsbac_rc_role_id_t role_id;
	rsbac_rc_type_id_t type_id;
	rsbac_boolean_t need_secdel;
	rsbac_boolean_t comp;
	rsbac_boolean_t boot_role;
	rsbac_boolean_t req_reauth;
#ifdef __KERNEL__
#endif
	u_char u_char_dummy;
	int dummy;
	u_int u_dummy;
	long long_dummy;
	long long long_long_dummy;
};

#endif
