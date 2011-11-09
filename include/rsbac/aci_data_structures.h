/**************************************/
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2008: Amon Ott */
/* Data structures                    */
/* Last modified: 11/Sep/2008         */
/**************************************/

#ifndef __RSBAC_DATA_STRUC_H
#define __RSBAC_DATA_STRUC_H

#ifdef __KERNEL__		/* only include in kernel code */
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/semaphore.h>
#include <linux/sched.h>
#include <rsbac/types.h>
#include <linux/spinlock.h>
#include <rsbac/pm_types.h>
#include <rsbac/rc_types.h>
#include <rsbac/aci.h>
#include <rsbac/debug.h>
#include <rsbac/lists.h>
#endif				/* __KERNEL__ */

#ifdef __KERNEL__

/* List to keep mounts before init, so that we can rsbac_mount them at init */

struct rsbac_mount_list_t {
	struct vfsmount * mnt_p;
	struct rsbac_mount_list_t * next;
};

/* First of all we define dirname and filenames for saving the ACIs to disk. */
/* The path must be a valid single dir name! Each mounted device gets its    */
/* own file set, residing in 'DEVICE_ROOT/RSBAC_ACI_PATH/'.                  */
/* The dynamic data structures for PM, RC and ACL are kept in their own files.*/
/* All user access to these files will be denied.                            */
/* Backups are kept in FILENAMEb.                                            */

#define RSBAC_LOG_BUF_LEN (16384)

#define RSBAC_ACI_PATH          "rsbac.dat"

#define RSBAC_GEN_FD_NAME       "fd_gen"
#define RSBAC_GEN_OLD_FD_NAME   "fd_gen."
#define RSBAC_MAC_FD_NAME       "fd_mac"
#define RSBAC_MAC_OLD_FD_NAME   "fd_mac."
#define RSBAC_PM_FD_NAME        "fd_pm"
#define RSBAC_PM_OLD_FD_NAME    "fd_pm."
#define RSBAC_DAZ_FD_NAME       "fd_dazt"
#define RSBAC_DAZ_OLD_FD_NAME   "fd_dazt."
#define RSBAC_DAZ_SCANNED_FD_NAME "fd_dazs"
#define RSBAC_DAZ_SCANNED_OLD_FD_NAME "fd_dazs."
#define RSBAC_FF_FD_NAME        "fd_ff"
#define RSBAC_FF_OLD_FD_NAME    "fd_ff."
#define RSBAC_RC_FD_NAME        "fd_rc"
#define RSBAC_RC_OLD_FD_NAME    "fd_rc."
#define RSBAC_AUTH_FD_NAME      "fd_auth"
#define RSBAC_AUTH_OLD_FD_NAME  "fd_auth."
#define RSBAC_CAP_FD_NAME       "fd_cap"
#define RSBAC_CAP_OLD_FD_NAME   "fd_cap."
#define RSBAC_PAX_FD_NAME       "fd_pax"
#define RSBAC_PAX_OLD_FD_NAME   "fd_pax."
#define RSBAC_RES_FD_NAME       "fd_res"
#define RSBAC_RES_OLD_FD_NAME   "fd_res."

#define RSBAC_ACI_USER_NAME     "useraci"
/* dir creation mode for discretionary access control: no rights*/
#define RSBAC_ACI_DIR_MODE       (S_IFDIR)
/* file creation mode for discretionary access control: rw for user only*/
#define RSBAC_ACI_FILE_MODE      (S_IFREG | S_IRUSR | S_IWUSR)
/* minimal mem chunk size available to try write_partial_fd_list, else defer */
#define RSBAC_MIN_WRITE_FD_BUF_LEN 32768
/* max size for write_chunks */
#define RSBAC_MAX_WRITE_CHUNK ((1 << 15) - 1)

#define RSBAC_GEN_NR_FD_LISTS  2
#define RSBAC_MAC_NR_FD_LISTS  4
#define RSBAC_PM_NR_FD_LISTS   2
#define RSBAC_DAZ_NR_FD_LISTS   2
#define RSBAC_DAZ_SCANNED_NR_FD_LISTS 4
#define RSBAC_FF_NR_FD_LISTS   4
#define RSBAC_RC_NR_FD_LISTS   4
#define RSBAC_AUTH_NR_FD_LISTS 2
#define RSBAC_CAP_NR_FD_LISTS  2
#define RSBAC_PAX_NR_FD_LISTS  2
#define RSBAC_RES_NR_FD_LISTS  2

#ifdef CONFIG_RSBAC_INIT_THREAD
/* Check and set init timeout */
#if CONFIG_RSBAC_MAX_INIT_TIME >= 5
#define RSBAC_MAX_INIT_TIME CONFIG_RSBAC_MAX_INIT_TIME
#else
#define RSBAC_MAX_INIT_TIME 5
#endif
#endif				/* INIT_THREAD */

#endif				/* __KERNEL__ */

/* The following structures privide attributes for all possible targets.  */
/* The data structures are kept in double linked lists, and are optimized */
/* by hash functions.                                                     */

/* Only ATTRIBUTES are saved in those structures, that are saved to disk, */
/* because saving sublists means breaking up the structures for every     */
/* single list.                                                           */
/* If a list of policy dependant items is to be stored, this is done in   */
/* the policy dependant data structures. Here only an ID as a handle is   */
/* supported.                                                             */

/* OK, first we define the file/dir ACI, holding all file/dir information */
/* the ADF needs for decisions.                                           */

/* Caution: whenever ACI changes, version and old_version should be increased!            */

// #define CONFIG_RSBAC_FD_CACHE 1

#ifdef CONFIG_RSBAC_FD_CACHE
#define RSBAC_FD_CACHE_NAME       "fd_cache."
#define RSBAC_FD_CACHE_VERSION 1
#define RSBAC_FD_CACHE_KEY 3626114
//#define RSBAC_FD_CACHE_TTL 3600
struct rsbac_fd_cache_desc_t {
	__u32            device;
	rsbac_inode_nr_t inode;
};
#endif

#define RSBAC_GEN_FD_ACI_VERSION 8
#define RSBAC_GEN_FD_ACI_KEY 1001
struct rsbac_gen_fd_aci_t {
	rsbac_log_array_t log_array_low;	/* file/dir based logging, */
	rsbac_log_array_t log_array_high;	/* high and low bits */
	rsbac_request_vector_t log_program_based;	/* Program based logging */
	rsbac_enum_t symlink_add_remote_ip;
	rsbac_enum_t symlink_add_uid;
	rsbac_enum_t symlink_add_mac_level;
	rsbac_enum_t symlink_add_rc_role;
	rsbac_enum_t linux_dac_disable;
	rsbac_fake_root_uid_int_t fake_root_uid;
	rsbac_uid_t auid_exempt;
	rsbac_um_set_t vset;
};
#define DEFAULT_GEN_FD_ACI \
    { \
      .log_array_low = -1, \
      .log_array_high = -1, \
      .log_program_based = 0, \
      .symlink_add_uid = FALSE, \
      .symlink_add_mac_level = FALSE, \
      .symlink_add_rc_role = FALSE, \
      .linux_dac_disable = LDD_inherit, \
      .fake_root_uid = FR_off, \
      .auid_exempt = RSBAC_NO_USER, \
      .vset = RSBAC_UM_VIRTUAL_KEEP, \
    }

#define DEFAULT_GEN_ROOT_DIR_ACI \
    { \
      .log_array_low = -1, \
      .log_array_high = -1, \
      .log_program_based = 0, \
      .symlink_add_uid = FALSE, \
      .symlink_add_mac_level = FALSE, \
      .symlink_add_rc_role = FALSE, \
      .linux_dac_disable = LDD_false, \
      .fake_root_uid = FR_off, \
      .auid_exempt = RSBAC_NO_USER, \
      .vset = RSBAC_UM_VIRTUAL_KEEP, \
    }

#define RSBAC_GEN_FD_OLD_ACI_VERSION 7
struct rsbac_gen_fd_old_aci_t {
	rsbac_log_array_t log_array_low;	/* file/dir based logging, */
	rsbac_log_array_t log_array_high;	/* high and low bits */
	rsbac_request_vector_t log_program_based;	/* Program based logging */
	rsbac_enum_t symlink_add_remote_ip;
	rsbac_enum_t symlink_add_uid;
	rsbac_enum_t symlink_add_mac_level;
	rsbac_enum_t symlink_add_rc_role;
	rsbac_enum_t linux_dac_disable;
	rsbac_fake_root_uid_int_t fake_root_uid;
	rsbac_old_uid_t auid_exempt;
};
#define RSBAC_GEN_FD_OLD_OLD_ACI_VERSION 6
struct rsbac_gen_fd_old_old_aci_t {
	rsbac_log_array_t log_array_low;	/* file/dir based logging, */
	rsbac_log_array_t log_array_high;	/* high and low bits */
	rsbac_request_vector_t log_program_based;	/* Program based logging */
	rsbac_enum_t symlink_add_uid;
	rsbac_enum_t symlink_add_mac_level;
	rsbac_enum_t symlink_add_rc_role;
	rsbac_enum_t linux_dac_disable;
	rsbac_fake_root_uid_int_t fake_root_uid;
	rsbac_old_uid_t auid_exempt;
};

#define RSBAC_GEN_FD_OLD_OLD_OLD_ACI_VERSION 5
struct rsbac_gen_fd_old_old_old_aci_t {
	rsbac_log_array_t log_array_low;	/* file/dir based logging, */
	rsbac_log_array_t log_array_high;	/* high and low bits */
	rsbac_request_vector_t log_program_based;	/* Program based logging */
	rsbac_enum_t symlink_add_uid;
	rsbac_enum_t symlink_add_mac_level;
	rsbac_enum_t symlink_add_rc_role;
	rsbac_enum_t linux_dac_disable;
	rsbac_fake_root_uid_int_t fake_root_uid;
};

#if defined(CONFIG_RSBAC_MAC)
#define RSBAC_MAC_FD_ACI_VERSION 5
#define RSBAC_MAC_FD_ACI_KEY 1001
struct rsbac_mac_fd_aci_t {
	rsbac_security_level_t sec_level;	/* MAC */
	rsbac_mac_category_vector_t mac_categories;	/* MAC category set */
	rsbac_mac_auto_int_t mac_auto;	/* auto-adjust current level */
	rsbac_boolean_int_t mac_prop_trusted;	/* Keep trusted flag when executing this file */
	rsbac_mac_file_flags_t mac_file_flags;	/* allow write_up, read_up etc. to it */
};

#define RSBAC_MAC_FD_OLD_ACI_VERSION 4
struct rsbac_mac_fd_old_aci_t {
	rsbac_security_level_t sec_level;	/* MAC */
	rsbac_uid_t mac_trusted_for_user;	/* MAC (for FILE only) */
	rsbac_mac_category_vector_t mac_categories;	/* MAC category set */
	rsbac_mac_auto_int_t mac_auto;	/* auto-adjust current level */
	rsbac_boolean_int_t mac_prop_trusted;	/* Keep trusted flag when executing this file */
	rsbac_mac_file_flags_t mac_file_flags;	/* allow write_up, read_up etc. to it */
};

#define RSBAC_MAC_FD_OLD_OLD_ACI_VERSION 3
struct rsbac_mac_fd_old_old_aci_t {
	rsbac_security_level_t sec_level;	/* MAC */
	rsbac_uid_t mac_trusted_for_user;	/* MAC (for FILE only) */
	rsbac_mac_category_vector_t mac_categories;	/* MAC category set */
	rsbac_mac_auto_int_t mac_auto;	/* auto-adjust current level */
	rsbac_boolean_int_t mac_prop_trusted;	/* Keep trusted flag when executing this file */
	rsbac_boolean_int_t mac_shared;	/* Shared dir, i.e., allow write_up to it */
};

#define RSBAC_MAC_FD_OLD_OLD_OLD_ACI_VERSION 2
struct rsbac_mac_fd_old_old_old_aci_t {
	rsbac_security_level_t sec_level;	/* MAC */
	rsbac_uid_t mac_trusted_for_user;	/* MAC (for FILE only) */
	rsbac_mac_category_vector_t mac_categories;	/* MAC category set */
	rsbac_mac_auto_int_t mac_auto;	/* auto-adjust current level */
};

#define DEFAULT_MAC_FD_ACI_INH \
    { \
      .sec_level = SL_inherit, \
      .mac_categories = RSBAC_MAC_INHERIT_CAT_VECTOR, \
      .mac_auto = MA_inherit, \
      .mac_prop_trusted = FALSE, \
      .mac_file_flags = 0, \
    }
#define DEFAULT_MAC_FD_ACI_NO_INH \
    { \
      .sec_level = SL_unclassified, \
      .mac_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_auto = MA_yes, \
      .mac_prop_trusted = FALSE, \
      .mac_file_flags = 0, \
    }

#ifdef CONFIG_RSBAC_MAC_DEF_INHERIT
#define DEFAULT_MAC_FD_ACI DEFAULT_MAC_FD_ACI_INH
#else
#define DEFAULT_MAC_FD_ACI DEFAULT_MAC_FD_ACI_NO_INH
#endif				/* MAC_DEF_INHERIT */

#define DEFAULT_MAC_ROOT_DIR_ACI \
    { \
      .sec_level = SL_unclassified, \
      .mac_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_auto = MA_yes, \
      .mac_prop_trusted = FALSE, \
      .mac_file_flags = 0, \
    }
#endif

#if defined(CONFIG_RSBAC_PM)
#define RSBAC_PM_FD_ACI_VERSION 1
#define RSBAC_PM_FD_ACI_KEY 1001
struct rsbac_pm_fd_aci_t {
	rsbac_pm_object_class_id_t pm_object_class;	/* PM  */
	rsbac_pm_tp_id_t pm_tp;	/* PM (for FILE only) */
	rsbac_pm_object_type_int_t pm_object_type;	/* PM (enum rsbac_pm_object_type_t -> __u8) */
};

#define DEFAULT_PM_FD_ACI \
    { \
      .pm_object_class = 0, \
      .pm_tp = 0, \
      .pm_object_type = PO_none, \
    }
#endif

#if defined(CONFIG_RSBAC_DAZ)
#define RSBAC_DAZ_FD_ACI_VERSION 2
#define RSBAC_DAZ_FD_OLD_ACI_VERSION 1
#define RSBAC_DAZ_FD_ACI_KEY 10535
#define RSBAC_DAZ_CACHE_CLEANUP_INTERVAL 86400
#define RSBAC_DAZ_SCANNED_FD_ACI_VERSION 1
struct rsbac_daz_fd_aci_t            
  {
    rsbac_daz_scanner_t daz_scanner;       /* DAZ (for FILE only) */
    rsbac_daz_do_scan_t daz_do_scan;
  };

struct rsbac_daz_fd_old_aci_t            
  {
    rsbac_daz_scanner_t   daz_scanner;       /* DAZ (for FILE only) (boolean) */
  };

#define DEFAULT_DAZ_FD_ACI \
    { \
      .daz_scanner = FALSE, \
      .daz_do_scan = DEFAULT_DAZ_FD_DO_SCAN \
    }

#define DEFAULT_DAZ_ROOT_DIR_ACI \
    { \
      .daz_scanner = FALSE, \
      .daz_do_scan = DEFAULT_DAZ_FD_ROOT_DO_SCAN \
    }
#endif

#if defined(CONFIG_RSBAC_FF)
#define RSBAC_FF_FD_ACI_VERSION 1
#define RSBAC_FF_FD_ACI_KEY 1001
#endif

#if defined(CONFIG_RSBAC_RC)
#define RSBAC_RC_FD_ACI_VERSION 1
#define RSBAC_RC_FD_ACI_KEY 1001
struct rsbac_rc_fd_aci_t {
	rsbac_rc_type_id_t rc_type_fd;	/* RC */
	rsbac_rc_role_id_t rc_force_role;	/* RC */
	rsbac_rc_role_id_t rc_initial_role;	/* RC */
};

#define DEFAULT_RC_FD_ACI \
    { \
      .rc_type_fd = RC_type_inherit_parent, \
      .rc_force_role = RC_default_force_role, \
      .rc_initial_role = RC_default_initial_role, \
    }
#define DEFAULT_RC_ROOT_DIR_ACI \
    { \
      .rc_type_fd = RSBAC_RC_GENERAL_TYPE, \
      .rc_force_role = RC_default_root_dir_force_role, \
      .rc_initial_role = RC_default_root_dir_initial_role, \
    }
#endif

#if defined(CONFIG_RSBAC_AUTH)
#define RSBAC_AUTH_FD_ACI_VERSION 2
#define RSBAC_AUTH_FD_OLD_ACI_VERSION 1
#define RSBAC_AUTH_FD_ACI_KEY 1001
struct rsbac_auth_fd_aci_t {
	__u8 auth_may_setuid;	/* AUTH (enum) */
	__u8 auth_may_set_cap;	/* AUTH (boolean) */
	__u8 auth_learn;	/* AUTH (boolean) */
};

struct rsbac_auth_fd_old_aci_t {
	__u8 auth_may_setuid;	/* AUTH (boolean) */
	__u8 auth_may_set_cap;	/* AUTH (boolean) */
};

#define DEFAULT_AUTH_FD_ACI \
    { \
      .auth_may_setuid = FALSE, \
      .auth_may_set_cap = FALSE, \
      .auth_learn = FALSE, \
    }
#endif

#if defined(CONFIG_RSBAC_CAP)
#define RSBAC_CAP_FD_ACI_VERSION 3
#define RSBAC_CAP_FD_OLD_ACI_VERSION 2
#define RSBAC_CAP_FD_OLD_OLD_ACI_VERSION 1
#define RSBAC_CAP_FD_ACI_KEY 1001
struct rsbac_cap_fd_aci_t {
	rsbac_cap_vector_t min_caps;	/* Program forced minimum Linux capabilities */
	rsbac_cap_vector_t max_caps;	/* Program max Linux capabilities */
	rsbac_cap_ld_env_int_t cap_ld_env;
};

struct rsbac_cap_fd_old_aci_t {
        rsbac_cap_old_vector_t min_caps;    /* Program forced minimum Linux capabilities */
        rsbac_cap_old_vector_t max_caps;    /* Program max Linux capabilities */
        rsbac_cap_ld_env_int_t cap_ld_env;
};

struct rsbac_cap_fd_old_old_aci_t {
	rsbac_cap_old_vector_t min_caps;
	rsbac_cap_old_vector_t max_caps;
};

#define DEFAULT_CAP_FD_ACI \
    { \
      .min_caps.cap[0] = RSBAC_CAP_DEFAULT_MIN, \
      .max_caps.cap[0] = RSBAC_CAP_DEFAULT_MAX, \
      .min_caps.cap[1] = RSBAC_CAP_DEFAULT_MIN, \
      .max_caps.cap[1] = RSBAC_CAP_DEFAULT_MAX, \
      .cap_ld_env = LD_keep, \
    }
#endif

#if defined(CONFIG_RSBAC_PAX)
#define RSBAC_PAX_FD_ACI_VERSION 1
#define RSBAC_PAX_FD_ACI_KEY 100112
#endif

#if defined(CONFIG_RSBAC_RES)
#define RSBAC_RES_FD_ACI_VERSION 1
#define RSBAC_RES_FD_ACI_KEY 1002
struct rsbac_res_fd_aci_t {
	rsbac_res_array_t res_min;
	rsbac_res_array_t res_max;
};
#define DEFAULT_RES_FD_ACI \
    { \
      .res_min = { \
        RSBAC_RES_UNSET,           /* cpu time */ \
        RSBAC_RES_UNSET,           /* file size */ \
        RSBAC_RES_UNSET,           /* process data segment size */ \
        RSBAC_RES_UNSET,           /* stack size */ \
        RSBAC_RES_UNSET,           /* core dump size */ \
        RSBAC_RES_UNSET,           /* resident memory set size */ \
        RSBAC_RES_UNSET,           /* number of processes for this user */ \
        RSBAC_RES_UNSET,           /* number of files */ \
        RSBAC_RES_UNSET,           /* locked-in-memory address space */ \
        RSBAC_RES_UNSET,           /* address space (virtual memory) limit */ \
        RSBAC_RES_UNSET            /* maximum file locks */ \
      }, \
      .res_max = { \
        RSBAC_RES_UNSET,           /* cpu time */ \
        RSBAC_RES_UNSET,           /* file size */ \
        RSBAC_RES_UNSET,           /* process data segment size */ \
        RSBAC_RES_UNSET,           /* stack size */ \
        RSBAC_RES_UNSET,           /* core dump size */ \
        RSBAC_RES_UNSET,           /* resident memory set size */ \
        RSBAC_RES_UNSET,           /* number of processes for this user */ \
        RSBAC_RES_UNSET,           /* number of files */ \
        RSBAC_RES_UNSET,           /* locked-in-memory address space */ \
        RSBAC_RES_UNSET,           /* address space (virtual memory) limit */ \
        RSBAC_RES_UNSET            /* maximum file locks */ \
      } \
    }
#endif

#define RSBAC_FD_NR_ATTRIBUTES 34
#define RSBAC_FD_ATTR_LIST { \
      A_security_level, \
      A_mac_categories, \
      A_mac_auto, \
      A_mac_prop_trusted, \
      A_mac_file_flags, \
      A_pm_object_class, \
      A_pm_tp, \
      A_pm_object_type, \
      A_daz_scanner, \
      A_ff_flags, \
      A_rc_type_fd, \
      A_rc_force_role, \
      A_rc_initial_role, \
      A_auth_may_setuid, \
      A_auth_may_set_cap, \
      A_auth_learn, \
      A_log_array_low, \
      A_log_array_high, \
      A_log_program_based, \
      A_symlink_add_remote_ip, \
      A_symlink_add_uid, \
      A_symlink_add_mac_level, \
      A_symlink_add_rc_role, \
      A_linux_dac_disable, \
      A_min_caps, \
      A_max_caps, \
      A_cap_ld_env, \
      A_res_min, \
      A_res_max, \
      A_pax_flags, \
      A_fake_root_uid, \
      A_auid_exempt, \
      A_daz_do_scan, \
      A_vset \
      }

#ifdef __KERNEL__
struct rsbac_fd_list_handles_t {
	rsbac_list_handle_t gen;
#if defined(CONFIG_RSBAC_MAC)
	rsbac_list_handle_t mac;
#endif
#if defined(CONFIG_RSBAC_PM)
	rsbac_list_handle_t pm;
#endif
#if defined(CONFIG_RSBAC_DAZ)
	rsbac_list_handle_t daz;
#if defined(CONFIG_RSBAC_DAZ_CACHE)
	rsbac_list_handle_t dazs;
#endif
#endif
#if defined(CONFIG_RSBAC_FF)
	rsbac_list_handle_t ff;
#endif
#if defined(CONFIG_RSBAC_RC)
	rsbac_list_handle_t rc;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	rsbac_list_handle_t auth;
#endif
#if defined(CONFIG_RSBAC_CAP)
	rsbac_list_handle_t cap;
#endif
#if defined(CONFIG_RSBAC_PAX)
	rsbac_list_handle_t pax;
#endif
#if defined(CONFIG_RSBAC_RES)
	rsbac_list_handle_t res;
#endif
};

/* The list of devices is also a double linked list, so we define list    */
/* items and a list head.                                                 */

/* Hash size. Must be power of 2. */

#define RSBAC_NR_DEVICE_LISTS 8

struct rsbac_device_list_item_t {
	kdev_t id;
	u_int mount_count;
	struct rsbac_fd_list_handles_t handles;
	struct dentry *rsbac_dir_dentry_p;
	struct vfsmount *mnt_p;
	rsbac_inode_nr_t rsbac_dir_inode;
	struct rsbac_device_list_item_t *prev;
	struct rsbac_device_list_item_t *next;
};

/* To provide consistency we use spinlocks for all list accesses. The     */
/* 'curr' entry is used to avoid repeated lookups for the same item.       */

struct rsbac_device_list_head_t {
	struct rsbac_device_list_item_t *head;
	struct rsbac_device_list_item_t *tail;
	struct rsbac_device_list_item_t *curr;
	u_int count;
};

#endif				/* __KERNEL__ */

/******************************/
/* OK, now we define the block/char device ACI, holding all dev information */
/* the ADF needs for decisions.                                           */

#define RSBAC_GEN_ACI_DEV_NAME       "dev_gen"
#define RSBAC_MAC_ACI_DEV_NAME       "dev_mac"
#define RSBAC_PM_ACI_DEV_NAME        "dev_pm"
#define RSBAC_RC_ACI_DEV_MAJOR_NAME  "devm_rc"
#define RSBAC_RC_ACI_DEV_NAME        "dev_rc"

/* Caution: whenever ACI changes, version should be increased!            */

#define RSBAC_GEN_DEV_ACI_VERSION 2
#define RSBAC_GEN_DEV_OLD_ACI_VERSION 1
#define RSBAC_GEN_DEV_ACI_KEY 1001

struct rsbac_gen_dev_aci_t {
	rsbac_log_array_t log_array_low;	/* dev based logging, */
	rsbac_log_array_t log_array_high;	/* high and low bits */
};
#define DEFAULT_GEN_DEV_ACI \
    { \
      .log_array_low = -1, \
      .log_array_high = -1, \
    }

#if defined(CONFIG_RSBAC_MAC)
#define RSBAC_MAC_DEV_ACI_VERSION 2
#define RSBAC_MAC_DEV_OLD_ACI_VERSION 1
#define RSBAC_MAC_DEV_ACI_KEY 1001
struct rsbac_mac_dev_aci_t {
	rsbac_security_level_t sec_level;	/* MAC */
	rsbac_mac_category_vector_t mac_categories;	/* MAC category set */
	__u8 mac_check;		/* MAC (boolean) */
};
#define DEFAULT_MAC_DEV_ACI \
    { \
      .sec_level = SL_unclassified, \
      .mac_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_check = FALSE, \
    }
#endif

#if defined(CONFIG_RSBAC_PM)
#define RSBAC_PM_DEV_ACI_VERSION 2
#define RSBAC_PM_DEV_OLD_ACI_VERSION 1
#define RSBAC_PM_DEV_ACI_KEY 1001
struct rsbac_pm_dev_aci_t {
	rsbac_pm_object_type_int_t pm_object_type;	/* PM (enum rsbac_pm_object_type_t) */
	rsbac_pm_object_class_id_t pm_object_class;	/* dev only */
};

#define DEFAULT_PM_DEV_ACI \
    { \
      .pm_object_type = PO_none, \
      .pm_object_class = 0, \
    }
#endif

#if defined(CONFIG_RSBAC_RC)
#define RSBAC_RC_DEV_ACI_VERSION 2
#define RSBAC_RC_DEV_OLD_ACI_VERSION 1
#define RSBAC_RC_DEV_ACI_KEY 1001
#endif

#define RSBAC_DEV_NR_ATTRIBUTES 8
#define RSBAC_DEV_ATTR_LIST { \
      A_security_level, \
      A_mac_categories, \
      A_mac_check, \
      A_pm_object_type, \
      A_pm_object_class, \
      A_rc_type, \
      A_log_array_low, \
      A_log_array_high \
      }

#ifdef __KERNEL__
struct rsbac_dev_handles_t {
	rsbac_list_handle_t gen;
#if defined(CONFIG_RSBAC_MAC)
	rsbac_list_handle_t mac;
#endif
#if defined(CONFIG_RSBAC_PM)
	rsbac_list_handle_t pm;
#endif
#if defined(CONFIG_RSBAC_RC)
	rsbac_list_handle_t rc;
#endif
};
#endif				/* __KERNEL__ */

/**************************************************************************/
/* Next we define the ipc ACI, holding all ipc information                */
/* the ADF needs for decisions.                                           */

#define RSBAC_MAC_ACI_IPC_NAME   "ipc_mac"
#define RSBAC_PM_ACI_IPC_NAME    "ipc_pm"
#define RSBAC_RC_ACI_IPC_NAME    "ipc_rc"
#define RSBAC_JAIL_ACI_IPC_NAME  "ipc_jai"

#if defined(CONFIG_RSBAC_MAC)
#define RSBAC_MAC_IPC_ACI_VERSION 1
#define RSBAC_MAC_IPC_ACI_KEY 1001
struct rsbac_mac_ipc_aci_t {
	rsbac_security_level_t sec_level;	/* enum old_rsbac_security_level_t / __u8 */
	rsbac_mac_category_vector_t mac_categories;	/* MAC category set */
};
#define DEFAULT_MAC_IPC_ACI \
    { \
      .sec_level = SL_unclassified, \
      .mac_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
    }
#endif

#if defined(CONFIG_RSBAC_PM)
#define RSBAC_PM_IPC_ACI_VERSION 1
#define RSBAC_PM_IPC_ACI_KEY 1001
struct rsbac_pm_ipc_aci_t {
	rsbac_pm_object_class_id_t pm_object_class;	/* ipc only */
	rsbac_pm_purpose_id_t pm_ipc_purpose;
	rsbac_pm_object_type_int_t pm_object_type;	/* enum rsbac_pm_object_type_t */
};
#define DEFAULT_PM_IPC_ACI \
    { \
      .pm_object_class = RSBAC_PM_IPC_OBJECT_CLASS_ID, \
      .pm_ipc_purpose = 0, \
      .pm_object_type = PO_ipc, \
    }
#endif

#if defined(CONFIG_RSBAC_RC)
#define RSBAC_RC_IPC_ACI_VERSION 1
#define RSBAC_RC_IPC_ACI_KEY 1001
#endif

#if defined(CONFIG_RSBAC_JAIL)
#define RSBAC_JAIL_IPC_ACI_VERSION 1
#define RSBAC_JAIL_IPC_ACI_KEY 1001
#endif

#define RSBAC_IPC_NR_ATTRIBUTES 7
#define RSBAC_IPC_ATTR_LIST { \
      A_security_level, \
      A_mac_categories, \
      A_pm_object_class, \
      A_pm_ipc_purpose, \
      A_pm_object_type, \
      A_rc_type, \
      A_jail_id \
      }

#ifdef __KERNEL__
struct rsbac_ipc_handles_t {
#if defined(CONFIG_RSBAC_MAC)
	rsbac_list_handle_t mac;
#endif
#if defined(CONFIG_RSBAC_PM)
	rsbac_list_handle_t pm;
#endif
#if defined(CONFIG_RSBAC_RC)
	rsbac_list_handle_t rc;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	rsbac_list_handle_t jail;
#endif
};
#endif				/* __KERNEL__ */

/*************************************/
/* The user ACI holds all user information the ADF needs. */

#define RSBAC_GEN_ACI_USER_NAME   "u_gen"
#define RSBAC_MAC_ACI_USER_NAME   "u_mac"
#define RSBAC_PM_ACI_USER_NAME    "u_pm"
#define RSBAC_DAZ_ACI_USER_NAME    "u_daz"
#define RSBAC_FF_ACI_USER_NAME    "u_ff"
#define RSBAC_RC_ACI_USER_NAME    "u_rc"
#define RSBAC_AUTH_ACI_USER_NAME  "u_auth"
#define RSBAC_CAP_ACI_USER_NAME   "u_cap"
#define RSBAC_JAIL_ACI_USER_NAME  "u_jail"
#define RSBAC_PAX_ACI_USER_NAME   "u_pax"
#define RSBAC_RES_ACI_USER_NAME   "u_res"

#define RSBAC_GEN_USER_ACI_VERSION 2
#define RSBAC_GEN_USER_OLD_ACI_VERSION 1
#define RSBAC_GEN_USER_ACI_KEY 1001
struct rsbac_gen_user_aci_t {
	rsbac_pseudo_t pseudo;
	rsbac_request_vector_t log_user_based;	/* User based logging */
};
#define DEFAULT_GEN_U_ACI \
    { \
      .pseudo = (rsbac_pseudo_t) 0, \
      .log_user_based = 0, \
    }

#if defined(CONFIG_RSBAC_MAC)
#define RSBAC_MAC_USER_ACI_VERSION 5
#define RSBAC_MAC_USER_OLD_ACI_VERSION 4
#define RSBAC_MAC_USER_OLD_OLD_ACI_VERSION 3
#define RSBAC_MAC_USER_OLD_OLD_OLD_ACI_VERSION 2
#define RSBAC_MAC_USER_OLD_OLD_OLD_OLD_ACI_VERSION 1
#define RSBAC_MAC_USER_ACI_KEY 1001
struct rsbac_mac_user_aci_t {
	rsbac_security_level_t security_level;	/* maximum level */
	rsbac_security_level_t initial_security_level;	/* maximum level */
	rsbac_security_level_t min_security_level;	/* minimum level / __u8 */
	rsbac_mac_category_vector_t mac_categories;	/* MAC max category set */
	rsbac_mac_category_vector_t mac_initial_categories;	/* MAC max category set */
	rsbac_mac_category_vector_t mac_min_categories;	/* MAC min category set */
	rsbac_system_role_int_t system_role;	/* enum rsbac_system_role_t */
	rsbac_mac_user_flags_t mac_user_flags;	/* flags (override, trusted, allow_auto etc.) */
};
struct rsbac_mac_user_old_aci_t {
	rsbac_security_level_t access_appr;	/* maximum level */
	rsbac_security_level_t min_access_appr;	/* minimum level / __u8 */
	rsbac_mac_category_vector_t mac_categories;	/* MAC max category set */
	rsbac_mac_category_vector_t mac_min_categories;	/* MAC min category set */
	rsbac_system_role_int_t system_role;	/* enum rsbac_system_role_t */
	rsbac_boolean_int_t mac_allow_auto;	/* allow to auto-adjust current level */
};
struct rsbac_mac_user_old_old_aci_t {
	rsbac_security_level_t access_appr;	/* maximum level */
	rsbac_security_level_t min_access_appr;	/* minimum level / __u8 */
	rsbac_mac_category_vector_t mac_categories;	/* MAC max category set */
	rsbac_mac_category_vector_t mac_min_categories;	/* MAC min category set */
	rsbac_system_role_int_t system_role;	/* enum rsbac_system_role_t */
};
struct rsbac_mac_user_old_old_old_aci_t {
	rsbac_security_level_t access_appr;	/* enum old_rsbac_security_level_t / __u8 */
	rsbac_mac_category_vector_t mac_categories;	/* MAC category set */
	rsbac_system_role_int_t system_role;	/* enum rsbac_system_role_t */
};
#define DEFAULT_MAC_U_ACI \
    { \
      .security_level = SL_unclassified, \
      .initial_security_level = SL_unclassified, \
      .min_security_level = SL_unclassified, \
      .mac_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_initial_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_min_categories = RSBAC_MAC_MIN_CAT_VECTOR, \
      .system_role = SR_user, \
      .mac_user_flags = RSBAC_MAC_DEF_U_FLAGS, \
    }
#define DEFAULT_MAC_U_SYSADM_ACI \
    { \
      .security_level = SL_unclassified, \
      .initial_security_level = SL_unclassified, \
      .min_security_level = SL_unclassified, \
      .mac_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_initial_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_min_categories = RSBAC_MAC_MIN_CAT_VECTOR, \
      .system_role = SR_administrator, \
      .mac_user_flags = RSBAC_MAC_DEF_SYSADM_U_FLAGS, \
    }
#define DEFAULT_MAC_U_SECOFF_ACI \
    { \
      .security_level = SL_unclassified, \
      .initial_security_level = SL_unclassified, \
      .min_security_level = SL_unclassified, \
      .mac_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_initial_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_min_categories = RSBAC_MAC_MIN_CAT_VECTOR, \
      .system_role = SR_security_officer, \
      .mac_user_flags = RSBAC_MAC_DEF_SECOFF_U_FLAGS, \
    }
#define DEFAULT_MAC_U_AUDITOR_ACI \
    { \
      .security_level = SL_unclassified, \
      .initial_security_level = SL_unclassified, \
      .min_security_level = SL_unclassified, \
      .mac_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_initial_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_min_categories = RSBAC_MAC_MIN_CAT_VECTOR, \
      .system_role = SR_auditor, \
      .mac_user_flags = RSBAC_MAC_DEF_U_FLAGS, \
    }
#endif

#if defined(CONFIG_RSBAC_PM)
#define RSBAC_PM_USER_ACI_VERSION 2
#define RSBAC_PM_USER_OLD_ACI_VERSION 1
#define RSBAC_PM_USER_ACI_KEY 1001
struct rsbac_pm_user_aci_t {
	rsbac_pm_task_set_id_t pm_task_set;
	rsbac_pm_role_int_t pm_role;	/* enum rsbac_pm_role_t */
};
#define DEFAULT_PM_U_ACI \
    { \
      .pm_task_set = 0, \
      .pm_role = PR_user, \
    }
#define DEFAULT_PM_U_SYSADM_ACI \
    { \
      .pm_task_set = 0, \
      .pm_role = PR_system_admin, \
    }
#define DEFAULT_PM_U_SECOFF_ACI \
    { \
      .pm_task_set = 0, \
      .pm_role = PR_security_officer, \
    }
#define DEFAULT_PM_U_DATAPROT_ACI \
    { \
      .pm_task_set = 0, \
      .pm_role = PR_data_protection_officer, \
    }
#define DEFAULT_PM_U_TPMAN_ACI \
    { \
      .pm_task_set = 0, \
      .pm_role = PR_tp_manager, \
    }
#endif

#if defined(CONFIG_RSBAC_DAZ)
#define RSBAC_DAZ_USER_ACI_VERSION 2
#define RSBAC_DAZ_USER_OLD_ACI_VERSION 1
#define RSBAC_DAZ_USER_ACI_KEY 1001
#endif

#if defined(CONFIG_RSBAC_FF)
#define RSBAC_FF_USER_ACI_VERSION 2
#define RSBAC_FF_USER_OLD_ACI_VERSION 1
#define RSBAC_FF_USER_ACI_KEY 1001
#endif

#if defined(CONFIG_RSBAC_RC)
#define RSBAC_RC_USER_ACI_VERSION 3
#define RSBAC_RC_USER_OLD_ACI_VERSION 2
#define RSBAC_RC_USER_OLD_OLD_ACI_VERSION 1
#define RSBAC_RC_USER_ACI_KEY 1001
struct rsbac_rc_user_aci_t {
	rsbac_rc_role_id_t rc_role;
	rsbac_rc_type_id_t rc_type;
};
#define DEFAULT_RC_U_ACI \
    { \
      .rc_role = RSBAC_RC_GENERAL_ROLE, \
      .rc_type = RSBAC_RC_GENERAL_TYPE, \
    }
#define DEFAULT_RC_U_SYSADM_ACI \
    { \
      .rc_role = RSBAC_RC_SYSTEM_ADMIN_ROLE, /* rc_role (RC) */ \
      .rc_type = RSBAC_RC_SYS_TYPE, \
    }
#define DEFAULT_RC_U_SECOFF_ACI \
    { \
      .rc_role = RSBAC_RC_ROLE_ADMIN_ROLE, /* rc_role (RC) */ \
      .rc_type = RSBAC_RC_SEC_TYPE, \
    }
#define DEFAULT_RC_U_AUDITOR_ACI \
    { \
      .rc_role = RSBAC_RC_AUDITOR_ROLE, /* rc_role (RC) */ \
      .rc_type = RSBAC_RC_SEC_TYPE, \
    }
#endif

#if defined(CONFIG_RSBAC_AUTH)
#define RSBAC_AUTH_USER_ACI_VERSION 2
#define RSBAC_AUTH_USER_OLD_ACI_VERSION 1
#define RSBAC_AUTH_USER_ACI_KEY 1001

#endif				/* AUTH */

#if defined(CONFIG_RSBAC_CAP)
#define RSBAC_CAP_USER_ACI_VERSION 4
#define RSBAC_CAP_USER_OLD_ACI_VERSION 3
#define RSBAC_CAP_USER_OLD_OLD_ACI_VERSION 2
#define RSBAC_CAP_USER_OLD_OLD_OLD_ACI_VERSION 1
#define RSBAC_CAP_USER_ACI_KEY 1001
struct rsbac_cap_user_aci_t {
	rsbac_system_role_int_t cap_role;	/* System role for CAP administration */
	rsbac_cap_vector_t min_caps;	        /* User forced minimum Linux capabilities */
	rsbac_cap_vector_t max_caps;	        /* User max Linux capabilities */
        rsbac_cap_ld_env_int_t cap_ld_env;
};

struct rsbac_cap_user_old_aci_t {
	rsbac_system_role_int_t cap_role;       /* System role for CAP administration */
	rsbac_cap_old_vector_t min_caps;            /* User forced minimum Linux capabilities */
	rsbac_cap_old_vector_t max_caps;            /* User max Linux capabilities */
	rsbac_cap_ld_env_int_t cap_ld_env;
};

struct rsbac_cap_user_old_old_aci_t {
	rsbac_system_role_int_t cap_role;	/* System role for CAP administration */
	rsbac_cap_old_vector_t min_caps;	        /* User forced minimum Linux capabilities */
	rsbac_cap_old_vector_t max_caps;	        /* User max Linux capabilities */
        rsbac_cap_ld_env_int_t cap_ld_env;
};

struct rsbac_cap_user_old_old_old_aci_t {
	rsbac_system_role_int_t cap_role;       /* System role for CAP administration */
	rsbac_cap_old_vector_t min_caps;        /* User forced minimum Linux capabilities */
	rsbac_cap_old_vector_t max_caps;        /* User max Linux capabilities */
};

#define DEFAULT_CAP_U_ACI \
    { \
      .cap_role = SR_user, \
      .min_caps.cap[0] = RSBAC_CAP_DEFAULT_MIN, \
      .max_caps.cap[0] = RSBAC_CAP_DEFAULT_MAX, \
      .min_caps.cap[1] = RSBAC_CAP_DEFAULT_MIN, \
      .max_caps.cap[1] = RSBAC_CAP_DEFAULT_MAX, \
      .cap_ld_env = LD_keep, \
    }
#define DEFAULT_CAP_U_SYSADM_ACI \
    { \
      .cap_role = SR_administrator, \
      .min_caps.cap[0] = RSBAC_CAP_DEFAULT_MIN, \
      .max_caps.cap[0] = RSBAC_CAP_DEFAULT_MAX, \
      .min_caps.cap[1] = RSBAC_CAP_DEFAULT_MIN, \
      .max_caps.cap[1] = RSBAC_CAP_DEFAULT_MAX, \
      .cap_ld_env = LD_keep, \
    }
#define DEFAULT_CAP_U_SECOFF_ACI \
    { \
      .cap_role = SR_security_officer, \
      .min_caps.cap[0] = RSBAC_CAP_DEFAULT_MIN, \
      .max_caps.cap[0] = RSBAC_CAP_DEFAULT_MAX, \
      .min_caps.cap[1] = RSBAC_CAP_DEFAULT_MIN, \
      .max_caps.cap[1] = RSBAC_CAP_DEFAULT_MAX, \
      .cap_ld_env = LD_keep, \
    }
#define DEFAULT_CAP_U_AUDITOR_ACI \
    { \
      .cap_role = SR_auditor, \
      .min_caps.cap[0] = RSBAC_CAP_DEFAULT_MIN, \
      .max_caps.cap[0] = RSBAC_CAP_DEFAULT_MAX, \
      .min_caps.cap[1] = RSBAC_CAP_DEFAULT_MIN, \
      .max_caps.cap[1] = RSBAC_CAP_DEFAULT_MAX, \
      .cap_ld_env = LD_keep, \
    }
#endif

#if defined(CONFIG_RSBAC_JAIL)
#define RSBAC_JAIL_USER_ACI_VERSION 2
#define RSBAC_JAIL_USER_OLD_ACI_VERSION 1
#define RSBAC_JAIL_USER_ACI_KEY 1001
#endif

#if defined(CONFIG_RSBAC_PAX)
#define RSBAC_PAX_USER_ACI_VERSION 2
#define RSBAC_PAX_USER_OLD_ACI_VERSION 1
#define RSBAC_PAX_USER_ACI_KEY 1001221
#endif

#if defined(CONFIG_RSBAC_RES)
#define RSBAC_RES_USER_ACI_VERSION 2
#define RSBAC_RES_USER_OLD_ACI_VERSION 1
#define RSBAC_RES_USER_ACI_KEY 1002
struct rsbac_res_user_aci_t {
	rsbac_system_role_int_t res_role;	/* System role for RES administration */
	rsbac_res_array_t res_min;
	rsbac_res_array_t res_max;
};
#define DEFAULT_RES_U_ACI \
    { \
      .res_role = SR_user, \
      .res_min = { \
        RSBAC_RES_UNSET,           /* cpu time */ \
        RSBAC_RES_UNSET,           /* file size */ \
        RSBAC_RES_UNSET,           /* process data segment size */ \
        RSBAC_RES_UNSET,           /* stack size */ \
        RSBAC_RES_UNSET,           /* core dump size */ \
        RSBAC_RES_UNSET,           /* resident memory set size */ \
        RSBAC_RES_UNSET,           /* number of processes for this user */ \
        RSBAC_RES_UNSET,           /* number of files */ \
        RSBAC_RES_UNSET,           /* locked-in-memory address space */ \
        RSBAC_RES_UNSET,           /* address space (virtual memory) limit */ \
        RSBAC_RES_UNSET            /* maximum file locks */ \
      }, \
      .res_max = { \
        RSBAC_RES_UNSET,           /* cpu time */ \
        RSBAC_RES_UNSET,           /* file size */ \
        RSBAC_RES_UNSET,           /* process data segment size */ \
        RSBAC_RES_UNSET,           /* stack size */ \
        RSBAC_RES_UNSET,           /* core dump size */ \
        RSBAC_RES_UNSET,           /* resident memory set size */ \
        RSBAC_RES_UNSET,           /* number of processes for this user */ \
        RSBAC_RES_UNSET,           /* number of files */ \
        RSBAC_RES_UNSET,           /* locked-in-memory address space */ \
        RSBAC_RES_UNSET,           /* address space (virtual memory) limit */ \
        RSBAC_RES_UNSET            /* maximum file locks */ \
      }, \
    }
#define DEFAULT_RES_U_SYSADM_ACI \
    { \
      .res_role = SR_administrator, \
      .res_min = { \
        RSBAC_RES_UNSET,           /* cpu time */ \
        RSBAC_RES_UNSET,           /* file size */ \
        RSBAC_RES_UNSET,           /* process data segment size */ \
        RSBAC_RES_UNSET,           /* stack size */ \
        RSBAC_RES_UNSET,           /* core dump size */ \
        RSBAC_RES_UNSET,           /* resident memory set size */ \
        RSBAC_RES_UNSET,           /* number of processes for this user */ \
        RSBAC_RES_UNSET,           /* number of files */ \
        RSBAC_RES_UNSET,           /* locked-in-memory address space */ \
        RSBAC_RES_UNSET,           /* address space (virtual memory) limit */ \
        RSBAC_RES_UNSET            /* maximum file locks */ \
      }, \
      .res_max = { \
        RSBAC_RES_UNSET,           /* cpu time */ \
        RSBAC_RES_UNSET,           /* file size */ \
        RSBAC_RES_UNSET,           /* process data segment size */ \
        RSBAC_RES_UNSET,           /* stack size */ \
        RSBAC_RES_UNSET,           /* core dump size */ \
        RSBAC_RES_UNSET,           /* resident memory set size */ \
        RSBAC_RES_UNSET,           /* number of processes for this user */ \
        RSBAC_RES_UNSET,           /* number of files */ \
        RSBAC_RES_UNSET,           /* locked-in-memory address space */ \
        RSBAC_RES_UNSET,           /* address space (virtual memory) limit */ \
        RSBAC_RES_UNSET            /* maximum file locks */ \
      } \
    }
#define DEFAULT_RES_U_SECOFF_ACI \
    { \
      .res_role = SR_security_officer, \
      .res_min = { \
        RSBAC_RES_UNSET,           /* cpu time */ \
        RSBAC_RES_UNSET,           /* file size */ \
        RSBAC_RES_UNSET,           /* process data segment size */ \
        RSBAC_RES_UNSET,           /* stack size */ \
        RSBAC_RES_UNSET,           /* core dump size */ \
        RSBAC_RES_UNSET,           /* resident memory set size */ \
        RSBAC_RES_UNSET,           /* number of processes for this user */ \
        RSBAC_RES_UNSET,           /* number of files */ \
        RSBAC_RES_UNSET,           /* locked-in-memory address space */ \
        RSBAC_RES_UNSET,           /* address space (virtual memory) limit */ \
        RSBAC_RES_UNSET            /* maximum file locks */ \
      }, \
      .res_max = { \
        RSBAC_RES_UNSET,           /* cpu time */ \
        RSBAC_RES_UNSET,           /* file size */ \
        RSBAC_RES_UNSET,           /* process data segment size */ \
        RSBAC_RES_UNSET,           /* stack size */ \
        RSBAC_RES_UNSET,           /* core dump size */ \
        RSBAC_RES_UNSET,           /* resident memory set size */ \
        RSBAC_RES_UNSET,           /* number of processes for this user */ \
        RSBAC_RES_UNSET,           /* number of files */ \
        RSBAC_RES_UNSET,           /* locked-in-memory address space */ \
        RSBAC_RES_UNSET,           /* address space (virtual memory) limit */ \
        RSBAC_RES_UNSET            /* maximum file locks */ \
      } \
    }
#define DEFAULT_RES_U_AUDITOR_ACI \
    { \
      .res_role = SR_auditor, \
      .res_min = { \
        RSBAC_RES_UNSET,           /* cpu time */ \
        RSBAC_RES_UNSET,           /* file size */ \
        RSBAC_RES_UNSET,           /* process data segment size */ \
        RSBAC_RES_UNSET,           /* stack size */ \
        RSBAC_RES_UNSET,           /* core dump size */ \
        RSBAC_RES_UNSET,           /* resident memory set size */ \
        RSBAC_RES_UNSET,           /* number of processes for this user */ \
        RSBAC_RES_UNSET,           /* number of files */ \
        RSBAC_RES_UNSET,           /* locked-in-memory address space */ \
        RSBAC_RES_UNSET,           /* address space (virtual memory) limit */ \
        RSBAC_RES_UNSET            /* maximum file locks */ \
      }, \
      .res_max = { \
        RSBAC_RES_UNSET,           /* cpu time */ \
        RSBAC_RES_UNSET,           /* file size */ \
        RSBAC_RES_UNSET,           /* process data segment size */ \
        RSBAC_RES_UNSET,           /* stack size */ \
        RSBAC_RES_UNSET,           /* core dump size */ \
        RSBAC_RES_UNSET,           /* resident memory set size */ \
        RSBAC_RES_UNSET,           /* number of processes for this user */ \
        RSBAC_RES_UNSET,           /* number of files */ \
        RSBAC_RES_UNSET,           /* locked-in-memory address space */ \
        RSBAC_RES_UNSET,           /* address space (virtual memory) limit */ \
        RSBAC_RES_UNSET            /* maximum file locks */ \
      } \
    }
#endif

#define RSBAC_USER_NR_ATTRIBUTES 24
#define RSBAC_USER_ATTR_LIST { \
      A_pseudo, \
      A_log_user_based, \
      A_security_level, \
      A_initial_security_level, \
      A_min_security_level, \
      A_mac_categories, \
      A_mac_initial_categories, \
      A_mac_min_categories, \
      A_mac_role, \
      A_mac_user_flags, \
      A_daz_role, \
      A_ff_role, \
      A_auth_role, \
      A_pm_task_set, \
      A_pm_role, \
      A_rc_def_role, \
      A_rc_type, \
      A_min_caps, \
      A_max_caps, \
      A_cap_role, \
      A_cap_ld_env, \
      A_jail_role, \
      A_res_role, \
      A_pax_role \
      }

#ifdef __KERNEL__
struct rsbac_user_handles_t {
	rsbac_list_handle_t gen;
#if defined(CONFIG_RSBAC_MAC)
	rsbac_list_handle_t mac;
#endif
#if defined(CONFIG_RSBAC_PM)
	rsbac_list_handle_t pm;
#endif
#if defined(CONFIG_RSBAC_DAZ)
	rsbac_list_handle_t daz;
#endif
#if defined(CONFIG_RSBAC_FF)
	rsbac_list_handle_t ff;
#endif
#if defined(CONFIG_RSBAC_RC)
	rsbac_list_handle_t rc;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	rsbac_list_handle_t auth;
#endif
#if defined(CONFIG_RSBAC_CAP)
	rsbac_list_handle_t cap;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	rsbac_list_handle_t jail;
#endif
#if defined(CONFIG_RSBAC_PAX)
	rsbac_list_handle_t pax;
#endif
#if defined(CONFIG_RSBAC_RES)
	rsbac_list_handle_t res;
#endif
};
#endif

/********************************/
/* Process ACI. */

#define RSBAC_GEN_ACI_PROCESS_NAME   "process_gen"
#define RSBAC_MAC_ACI_PROCESS_NAME   "process_mac"
#define RSBAC_PM_ACI_PROCESS_NAME    "process_pm"
#define RSBAC_DAZ_ACI_PROCESS_NAME    "process_daz"
#define RSBAC_RC_ACI_PROCESS_NAME    "process_rc"
#define RSBAC_AUTH_ACI_PROCESS_NAME    "process_auth"
#define RSBAC_CAP_ACI_PROCESS_NAME    "process_cap"
#define RSBAC_JAIL_ACI_PROCESS_NAME    "process_jail"

#define RSBAC_GEN_PROCESS_ACI_VERSION 3
#define RSBAC_GEN_PROCESS_ACI_KEY 1001
struct rsbac_gen_process_aci_t {
	rsbac_request_vector_t log_program_based;
	rsbac_fake_root_uid_int_t fake_root_uid;
	rsbac_uid_t audit_uid;
	rsbac_uid_t auid_exempt;
	__u32 remote_ip;
	rsbac_boolean_t kernel_thread;
	rsbac_um_set_t vset;
#if defined(CONFIG_RSBAC_AUTH_LEARN) || defined(CONFIG_RSBAC_CAP_LEARN)
	struct rsbac_fs_file_t program_file;
#endif
};
#if defined(CONFIG_RSBAC_AUTH_LEARN) || defined(CONFIG_RSBAC_CAP_LEARN)
#define DEFAULT_GEN_P_ACI \
    { \
      .log_program_based = 0, \
      .fake_root_uid = FR_off, \
      .audit_uid = RSBAC_NO_USER, \
      .auid_exempt = RSBAC_NO_USER, \
      .remote_ip = 0, \
      .kernel_thread = 0, \
      .vset = 0, \
      .program_file = { RSBAC_ZERO_DEV, 0, NULL }, \
    }
#else
#define DEFAULT_GEN_P_ACI \
    { \
      .log_program_based = 0, \
      .fake_root_uid = FR_off, \
      .audit_uid = RSBAC_NO_USER, \
      .auid_exempt = RSBAC_NO_USER, \
      .remote_ip = 0, \
      .kernel_thread = 0, \
      .vset = 0, \
    }
#endif


#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_MAC_MAINT)
#define RSBAC_MAC_PROCESS_ACI_VERSION 1
#define RSBAC_MAC_PROCESS_ACI_KEY 1001
struct rsbac_mac_process_aci_t {
	rsbac_security_level_t owner_sec_level;	/* enum old_rsbac_security_level_t */
	rsbac_security_level_t owner_initial_sec_level;	/* enum old_rsbac_security_level_t */
	rsbac_security_level_t owner_min_sec_level;	/* enum old_rsbac_security_level_t */
	rsbac_mac_category_vector_t mac_owner_categories;	/* MAC category set */
	rsbac_mac_category_vector_t mac_owner_initial_categories;	/* MAC category set */
	rsbac_mac_category_vector_t mac_owner_min_categories;	/* MAC category set */
	rsbac_security_level_t current_sec_level;	/* enum rsbac_security_level_t */
	rsbac_mac_category_vector_t mac_curr_categories;	/* MAC current category set */
	rsbac_security_level_t min_write_open;	/* for *-property, enum rsbac_security_level_t */
	rsbac_mac_category_vector_t min_write_categories;	/* MAC, for *-property */
	rsbac_security_level_t max_read_open;	/* for *-property, enum rsbac_security_level_t */
	rsbac_mac_category_vector_t max_read_categories;	/* MAC, for *-property */
	rsbac_mac_process_flags_t mac_process_flags;	/* flags (override, trusted, auto etc.) */
};
#define DEFAULT_MAC_P_ACI \
    { \
      .owner_sec_level = SL_unclassified, \
      .owner_initial_sec_level = SL_unclassified, \
      .owner_min_sec_level = SL_unclassified, \
      .mac_owner_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_owner_initial_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_owner_min_categories = RSBAC_MAC_MIN_CAT_VECTOR, \
      .current_sec_level = SL_unclassified, \
      .mac_curr_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .min_write_open = SL_max, \
      .min_write_categories = RSBAC_MAC_MAX_CAT_VECTOR, \
      .max_read_open = SL_unclassified, \
      .max_read_categories = RSBAC_MAC_MIN_CAT_VECTOR, \
      .mac_process_flags = RSBAC_MAC_DEF_P_FLAGS, \
    }
#define DEFAULT_MAC_P_INIT_ACI \
    { \
      .owner_sec_level = SL_unclassified, \
      .owner_initial_sec_level = SL_unclassified, \
      .owner_min_sec_level = SL_unclassified, \
      .mac_owner_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_owner_initial_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .mac_owner_min_categories = RSBAC_MAC_MIN_CAT_VECTOR, \
      .current_sec_level = SL_unclassified, \
      .mac_curr_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
      .min_write_open = SL_max, \
      .min_write_categories = RSBAC_MAC_MAX_CAT_VECTOR, \
      .max_read_open = SL_unclassified, \
      .max_read_categories = RSBAC_MAC_MIN_CAT_VECTOR, \
      .mac_process_flags = RSBAC_MAC_DEF_INIT_P_FLAGS, \
    }
#endif

#if defined(CONFIG_RSBAC_PM)
#define RSBAC_PM_PROCESS_ACI_VERSION 1
#define RSBAC_PM_PROCESS_ACI_KEY 1001
struct rsbac_pm_process_aci_t {
	rsbac_pm_tp_id_t pm_tp;
	rsbac_pm_task_id_t pm_current_task;
	rsbac_pm_process_type_int_t pm_process_type;	/* enum rsbac_pm_process_type_t */
};
#define DEFAULT_PM_P_ACI \
    { \
      .pm_tp = 0, \
      .pm_current_task = 0, \
      .pm_process_type = PP_none, \
    }
#endif

#if defined(CONFIG_RSBAC_DAZ)
#define RSBAC_DAZ_PROCESS_ACI_VERSION 1
#define RSBAC_DAZ_PROCESS_ACI_KEY 1001
struct rsbac_daz_process_aci_t {
	rsbac_boolean_int_t daz_scanner;	/* DAZ, boolean */
};
#define DEFAULT_DAZ_P_ACI \
    { \
      .daz_scanner = FALSE, \
    }
#endif

#if defined(CONFIG_RSBAC_RC)
#define RSBAC_RC_PROCESS_ACI_VERSION 1
#define RSBAC_RC_PROCESS_ACI_KEY 1001
struct rsbac_rc_process_aci_t {
	rsbac_rc_role_id_t rc_role;	/* RC */
	rsbac_rc_type_id_t rc_type;	/* RC */
	rsbac_rc_role_id_t rc_force_role;	/* RC */
	rsbac_rc_type_id_t rc_select_type; /* RC */
};
#define DEFAULT_RC_P_ACI \
    { \
      .rc_role = RSBAC_RC_GENERAL_ROLE, \
      .rc_type = RSBAC_RC_GENERAL_TYPE, \
      .rc_force_role = RC_default_force_role, \
      .rc_select_type = RC_type_use_fd, \
    }
#define DEFAULT_RC_P_INIT_ACI \
    { \
      .rc_role = RSBAC_RC_SYSTEM_ADMIN_ROLE, \
      .rc_type = RSBAC_RC_GENERAL_TYPE, \
      .rc_force_role = RC_default_force_role, \
      .rc_select_type = RC_type_use_fd, \
    }
#define DEFAULT_RC_P_KERNEL_ACI \
    { \
      .rc_role = RSBAC_RC_SYSTEM_ADMIN_ROLE, \
      .rc_type = CONFIG_RSBAC_RC_KERNEL_PROCESS_TYPE, \
      .rc_force_role = RC_default_force_role, \
      .rc_select_type = RC_type_use_fd, \
    }
#endif

#if defined(CONFIG_RSBAC_AUTH)
#define RSBAC_AUTH_PROCESS_ACI_VERSION 1
#define RSBAC_AUTH_PROCESS_ACI_KEY 1001
struct rsbac_auth_process_aci_t {
	__u8 auth_may_setuid;	/* AUTH (boolean) */
	__u8 auth_may_set_cap;	/* AUTH (boolean) */
	rsbac_uid_t auth_last_auth;
#if defined(CONFIG_RSBAC_AUTH_LEARN)
	rsbac_uid_t auth_start_uid;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
	rsbac_uid_t auth_start_euid;
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
	rsbac_gid_t auth_start_gid;
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
	rsbac_gid_t auth_start_egid;
#endif
#endif
	__u8 auth_learn;	/* AUTH (boolean) */
#endif
};

#if defined(CONFIG_RSBAC_AUTH_LEARN)
#define DEFAULT_AUTH_P_ACI \
    { \
      .auth_may_setuid = FALSE, \
      .auth_may_set_cap = FALSE, \
      .auth_last_auth = RSBAC_NO_USER, \
      .auth_start_uid = 0, \
      .auth_learn = 0, \
    }
#else
#define DEFAULT_AUTH_P_ACI \
    { \
      .auth_may_setuid = FALSE, \
      .auth_may_set_cap = FALSE, \
      .auth_last_auth = RSBAC_NO_USER, \
    }
#endif
#endif


#if defined(CONFIG_RSBAC_CAP)
#define RSBAC_CAP_PROCESS_ACI_VERSION 2
#define RSBAC_CAP_PROCESS_ACI_KEY 10013283
struct rsbac_cap_process_aci_t {
	rsbac_cap_process_hiding_int_t cap_process_hiding;
#if defined(CONFIG_RSBAC_CAP_LOG_MISSING) || defined(CONFIG_RSBAC_CAP_LEARN)
	rsbac_cap_vector_t max_caps_user;
	rsbac_cap_vector_t max_caps_program;
#endif
	rsbac_cap_ld_env_int_t cap_ld_env;
};

#ifdef CONFIG_RSBAC_CAP_LOG_MISSING
#define DEFAULT_CAP_P_ACI \
    { \
      .cap_process_hiding = PH_off, \
      .max_caps_user.cap[0] = RSBAC_CAP_DEFAULT_MAX, \
      .max_caps_user.cap[1] = RSBAC_CAP_DEFAULT_MAX, \
      .max_caps_program.cap[0] = RSBAC_CAP_DEFAULT_MAX, \
      .max_caps_program.cap[1] = RSBAC_CAP_DEFAULT_MAX, \
      .cap_ld_env = LD_allow, \
    }
#else
#define DEFAULT_CAP_P_ACI \
    { \
      .cap_process_hiding = PH_off, \
      .cap_ld_env = LD_allow, \
    }
#endif
#endif

#if defined(CONFIG_RSBAC_JAIL)
#define RSBAC_JAIL_PROCESS_ACI_VERSION 1
#define RSBAC_JAIL_PROCESS_ACI_KEY 1001
struct rsbac_jail_process_aci_t {
	rsbac_jail_id_t id;
	rsbac_jail_id_t parent;
	rsbac_jail_ip_t ip;
	rsbac_jail_flags_t flags;
	rsbac_cap_vector_t max_caps;	/* Program max Linux capabilities */
	rsbac_jail_scd_vector_t scd_get;	/* SCD targets GET_STATUS_DATA */
	rsbac_jail_scd_vector_t scd_modify;	/* SCD targets MODIFY_SYSTEM_DATA */
};
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#define DEFAULT_JAIL_P_ACI \
    { \
      .id = 0, \
      .parent = 0, \
      .ip = 0, \
      .flags = 0, \
      .max_caps.cap[0] = -1, \
      .max_caps.cap[1] = -1, \
      .scd_get = 0, \
      .scd_modify = 0, \
    }
#else
#define DEFAULT_JAIL_P_ACI \
    { \
      .id = 0, \
      .parent = 0, \
      .ip = 0, \
      .flags = 0, \
      .max_caps = -1, \
      .scd_get = 0, \
      .scd_modify = 0, \
    }
#endif
#endif

#define RSBAC_PROCESS_NR_ATTRIBUTES 39
#define RSBAC_PROCESS_ATTR_LIST { \
      A_security_level, \
      A_min_security_level, \
      A_mac_categories, \
      A_mac_min_categories, \
      A_current_sec_level, \
      A_mac_curr_categories, \
      A_min_write_open, \
      A_min_write_categories, \
      A_max_read_open, \
      A_max_read_categories, \
      A_mac_process_flags, \
      A_pm_tp, \
      A_pm_current_task, \
      A_pm_process_type, \
      A_daz_scanner, \
      A_rc_role, \
      A_rc_type, \
      A_rc_force_role, \
      A_rc_select_type, \
      A_auth_may_setuid, \
      A_auth_may_set_cap, \
      A_auth_learn, \
      A_cap_process_hiding, \
      A_max_caps_user, \
      A_max_caps_program, \
      A_cap_ld_env, \
      A_jail_id, \
      A_jail_ip, \
      A_jail_flags, \
      A_jail_max_caps, \
      A_jail_scd_get, \
      A_jail_scd_modify, \
      A_log_program_based, \
      A_fake_root_uid, \
      A_audit_uid, \
      A_auid_exempt, \
      A_auth_last_auth, \
      A_remote_ip, \
      A_vset \
      }

#ifdef __KERNEL__
struct rsbac_process_handles_t {
	rsbac_list_handle_t gen;
#if defined(CONFIG_RSBAC_MAC)
	rsbac_list_handle_t mac;
#endif
#if defined(CONFIG_RSBAC_PM)
	rsbac_list_handle_t pm;
#endif
#if defined(CONFIG_RSBAC_DAZ)
	rsbac_list_handle_t daz;
#endif
#if defined(CONFIG_RSBAC_RC)
	rsbac_list_handle_t rc;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	rsbac_list_handle_t auth;
#endif
#if defined(CONFIG_RSBAC_CAP)
	rsbac_list_handle_t cap;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	rsbac_list_handle_t jail;
#endif
};
#endif				/* __KERNEL__ */


/******************************/
/* OK, now we define the UM group ACI, holding all information */
/* the ADF needs for decisions.                                */

#define RSBAC_RC_ACI_GROUP_NAME    "grouprc"

/* Caution: whenever ACI changes, version should be increased!            */

#if defined(CONFIG_RSBAC_RC_UM_PROT)
#define RSBAC_RC_GROUP_ACI_VERSION 1
#define RSBAC_RC_GROUP_ACI_KEY 13276142
#endif

#define RSBAC_GROUP_NR_ATTRIBUTES 1
#define RSBAC_GROUP_ATTR_LIST { \
      A_rc_type \
      }

#ifdef __KERNEL__
struct rsbac_group_handles_t {
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	rsbac_list_handle_t rc;
#endif
};
#endif				/* __KERNEL__ */

/********************************/
/* NETDEV ACI */

#define RSBAC_GEN_ACI_NETDEV_NAME   "nd_gen"
#define RSBAC_RC_ACI_NETDEV_NAME    "nd_rc"

#define RSBAC_GEN_NETDEV_ACI_VERSION 1
#define RSBAC_GEN_NETDEV_ACI_KEY 1001
struct rsbac_gen_netdev_aci_t {
	rsbac_log_array_t log_array_low;	/* netdev based logging, */
	rsbac_log_array_t log_array_high;	/* high and low bits */
};
#define DEFAULT_GEN_NETDEV_ACI \
    { \
      .log_array_low = -1, \
      .log_array_high = -1, \
    }

#if defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_RC_MAINT)
#define RSBAC_RC_NETDEV_ACI_VERSION 1
#define RSBAC_RC_NETDEV_ACI_KEY 1001
#endif

#define RSBAC_NETDEV_NR_ATTRIBUTES 3
#define RSBAC_NETDEV_ATTR_LIST { \
      A_rc_type, \
      A_log_array_low, \
      A_log_array_high \
      }

#ifdef __KERNEL__
struct rsbac_netdev_handles_t {
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	rsbac_list_handle_t gen;
#endif
#if defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_RC_MAINT)
	rsbac_list_handle_t rc;
#endif
};
#endif				/* __KERNEL__ */

/********************************/
/* NETTEMP ACI */

#define RSBAC_GEN_ACI_NETTEMP_NAME   "nt_gen"
#define RSBAC_MAC_ACI_NETTEMP_NAME   "nt_mac"
#define RSBAC_PM_ACI_NETTEMP_NAME    "nt_pm"
#define RSBAC_RC_ACI_NETTEMP_NAME    "nt_rc"

#define RSBAC_MAC_ACI_LNETOBJ_NAME   "lnetobj_mac"
#define RSBAC_PM_ACI_LNETOBJ_NAME    "lnetobj_pm"
#define RSBAC_RC_ACI_LNETOBJ_NAME    "lnetobj_rc"
#define RSBAC_MAC_ACI_RNETOBJ_NAME   "rnetobj_mac"
#define RSBAC_PM_ACI_RNETOBJ_NAME    "rnetobj_pm"
#define RSBAC_RC_ACI_RNETOBJ_NAME    "rnetobj_rc"

#define RSBAC_GEN_NETOBJ_ACI_VERSION 1
#define RSBAC_GEN_NETOBJ_ACI_KEY 1001
struct rsbac_gen_netobj_aci_t {
	rsbac_log_array_t log_array_low;	/* nettemp/netobj based logging, */
	rsbac_log_array_t log_array_high;	/* high and low bits */
};
#define DEFAULT_GEN_NETOBJ_ACI \
    { \
      .log_array_low = -1, \
      .log_array_high = -1, \
    }

#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_MAC_MAINT)
#define RSBAC_MAC_NETOBJ_ACI_VERSION 1
#define RSBAC_MAC_NETOBJ_ACI_KEY 1001
struct rsbac_mac_netobj_aci_t {
	rsbac_security_level_t sec_level;	/* enum old_rsbac_security_level_t / __u8 */
	rsbac_mac_category_vector_t mac_categories;	/* MAC category set */
};
#define DEFAULT_MAC_NETOBJ_ACI \
    { \
      .sec_level = SL_unclassified,  /* security_level (MAC) */ \
      .mac_categories = RSBAC_MAC_DEF_CAT_VECTOR, \
    }
#endif

#if defined(CONFIG_RSBAC_PM) || defined(CONFIG_RSBAC_PM_MAINT)
#define RSBAC_PM_NETOBJ_ACI_VERSION 1
#define RSBAC_PM_NETOBJ_ACI_KEY 1001
struct rsbac_pm_netobj_aci_t {
	rsbac_pm_object_class_id_t pm_object_class;	/* netobj only */
	rsbac_pm_purpose_id_t pm_ipc_purpose;
	rsbac_pm_object_type_int_t pm_object_type;	/* enum rsbac_pm_object_type_t */
};
#define DEFAULT_PM_NETOBJ_ACI \
    { \
      .pm_object_class = RSBAC_PM_IPC_OBJECT_CLASS_ID, \
      .pm_ipc_purpose = 0, \
      .pm_object_type = PO_ipc, \
    }
#endif

#if defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_RC_MAINT)
#define RSBAC_RC_NETOBJ_ACI_VERSION 1
#define RSBAC_RC_NETOBJ_ACI_KEY 1001
#define RSBAC_RC_NETTEMP_ACI_VERSION 1
#define RSBAC_RC_NETTEMP_ACI_KEY 1002

struct rsbac_rc_nettemp_aci_t {
	rsbac_rc_type_id_t netobj_type;	/* type inherited to netobj */
	rsbac_rc_type_id_t nettemp_type;	/* type of this tenplate */
};
#define DEFAULT_RC_NETTEMP_ACI \
    { \
      .netobj_type = RSBAC_RC_GENERAL_TYPE, \
      .nettemp_type = RSBAC_RC_GENERAL_TYPE, \
    }
#endif

#define RSBAC_NETTEMP_NR_ATTRIBUTES 9
#define RSBAC_NETTEMP_ATTR_LIST { \
      A_security_level, \
      A_mac_categories, \
      A_pm_object_class, \
      A_pm_ipc_purpose, \
      A_pm_object_type, \
      A_rc_type, \
      A_rc_type_nt, \
      A_log_array_low, \
      A_log_array_high \
      }

#define RSBAC_NETOBJ_NR_ATTRIBUTES 16
#define RSBAC_NETOBJ_ATTR_LIST { \
      A_local_sec_level, \
      A_remote_sec_level, \
      A_local_mac_categories, \
      A_remote_mac_categories, \
      A_local_pm_object_class, \
      A_remote_pm_object_class, \
      A_local_pm_ipc_purpose, \
      A_remote_pm_ipc_purpose, \
      A_local_pm_object_type, \
      A_remote_pm_object_type, \
      A_local_rc_type, \
      A_remote_rc_type, \
      A_local_log_array_low, \
      A_remote_log_array_low, \
      A_local_log_array_high, \
      A_remote_log_array_high \
      }

#ifdef __KERNEL__
struct rsbac_nettemp_handles_t {
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
	rsbac_list_handle_t gen;
#endif
#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_MAC_MAINT)
	rsbac_list_handle_t mac;
#endif
#if defined(CONFIG_RSBAC_PM) || defined(CONFIG_RSBAC_PM_MAINT)
	rsbac_list_handle_t pm;
#endif
#if defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_RC_MAINT)
	rsbac_list_handle_t rc;
#endif
};

struct rsbac_lnetobj_handles_t {
#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_MAC_MAINT)
	rsbac_list_handle_t mac;
#endif
#if defined(CONFIG_RSBAC_PM) || defined(CONFIG_RSBAC_PM_MAINT)
	rsbac_list_handle_t pm;
#endif
#if defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_RC_MAINT)
	rsbac_list_handle_t rc;
#endif
};
struct rsbac_rnetobj_handles_t {
#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_MAC_MAINT)
	rsbac_list_handle_t mac;
#endif
#if defined(CONFIG_RSBAC_PM) || defined(CONFIG_RSBAC_PM_MAINT)
	rsbac_list_handle_t pm;
#endif
#if defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_RC_MAINT)
	rsbac_list_handle_t rc;
#endif
};
#endif				/* __KERNEL__ */


/**********************************************/
/*              Declarations                  */
/**********************************************/

#ifdef __KERNEL__
extern kdev_t rsbac_root_dev;

int rsbac_read_open(char *, struct file **,	/* file */
		    kdev_t);

int rsbac_write_open(char *, struct file **,	/* file */
		     kdev_t);

void rsbac_read_close(struct file *);

void rsbac_write_close(struct file *);

extern struct semaphore rsbac_write_sem;

#endif				/* __KERNEL__ */

/**********************************************/
/*          External Declarations             */
/**********************************************/

#ifdef __KERNEL__

static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget(dentry->d_parent);

	mutex_lock(&dir->d_inode->i_mutex);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}

static inline void double_mutex_lock(struct mutex *m1, struct mutex *m2)
{
	if (m1 != m2) {
		if ((unsigned long) m1 < (unsigned long) m2) {
			struct mutex *tmp = m2;
			m2 = m1;
			m1 = tmp;
		}
		mutex_lock(m1);
	}
	mutex_lock(m2);
}

static inline void double_mutex_unlock(struct mutex *m1, struct mutex *m2)
{
	mutex_unlock(m1);
	if (m1 != m2)
		mutex_unlock(m2);
}

static inline void double_lock(struct dentry *d1, struct dentry *d2)
{
	double_mutex_lock(&d1->d_inode->i_mutex, &d2->d_inode->i_mutex);
}

static inline void double_unlock(struct dentry *d1, struct dentry *d2)
{
	double_mutex_unlock(&d1->d_inode->i_mutex, &d2->d_inode->i_mutex);
	dput(d1);
	dput(d2);
}

#ifdef CONFIG_RSBAC_DEBUG
static inline unsigned long rsbac_stack_free_space(void)
{
	unsigned long *n = (unsigned long *)(current + 1);
	while (!*n)
		n++;
	return (unsigned long)n - (unsigned long)(current + 1);
}
#else
#define rsbac_stack_free_space() 0
#endif

#endif				/* __KERNEL__ */

#endif
