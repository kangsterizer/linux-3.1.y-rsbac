/*********************************** */
/* Rule Set Based Access Control     */
/* Author and (c)1999-2011:          */
/*   Amon Ott <ao@rsbac.org>         */
/* API: Data types for attributes    */
/*      and standard module calls    */
/* Last modified: 12/Jul/2011        */
/*********************************** */

#ifndef __RSBAC_TYPES_H
#define __RSBAC_TYPES_H


/* trigger module dependency for EXPORT_SYMBOL */
#ifdef CONFIG_MODULES
#endif

#define RSBAC_VERSION "1.4.6"
#define RSBAC_VERSION_MAJOR 1
#define RSBAC_VERSION_MID 4
#define RSBAC_VERSION_MINOR 6
#define RSBAC_VERSION_NR \
 ((RSBAC_VERSION_MAJOR << 16) | (RSBAC_VERSION_MID << 8) | RSBAC_VERSION_MINOR)
#define RSBAC_VERSION_MAKE_NR(x,y,z) \
 ((x << 16) | (y << 8) | z)

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/capability.h>
#include <linux/resource.h>
#else
#include <asm/types.h>
#include <sys/types.h>
#endif

typedef __u32 rsbac_version_t;
typedef __u64 rsbac_uid_t;           /* High 32 Bit virtual set, low uid */
typedef __u64 rsbac_gid_t;           /* High 32 Bit virtual set, low gid */
typedef __u32 rsbac_old_uid_t;       /* Same as user in Linux kernel */
typedef __u32 rsbac_uid_num_t;       /* Same as user in Linux kernel */
typedef __u32 rsbac_old_gid_t;       /* Same as group in Linux kernel */
typedef __u32 rsbac_gid_num_t;       /* Same as user in Linux kernel */
typedef __u32 rsbac_um_set_t;
typedef __u32 rsbac_time_t;          /* Same as time_t in Linux kernel */
typedef kernel_cap_t rsbac_cap_vector_t;    /* Same as kernel_cap_t in Linux kernel */
typedef __u32 rsbac_cap_old_vector_t;    /* Same as kernel_cap_t in Linux kernel */

#define RSBAC_UID_SET(x) ((rsbac_um_set_t) (x >> 32))
#define RSBAC_UID_NUM(x) ((rsbac_uid_num_t) (x & (rsbac_uid_num_t) -1))
#define RSBAC_GEN_UID(x,y) ((rsbac_uid_t) x << 32 | RSBAC_UID_NUM(y))
#define RSBAC_GID_SET(x) ((rsbac_um_set_t) (x >> 32))
#define RSBAC_GID_NUM(x) ((rsbac_gid_num_t) (x & (rsbac_gid_num_t) -1))
#define RSBAC_GEN_GID(x,y) ((rsbac_gid_t) x << 32 | RSBAC_GID_NUM(y))
#define RSBAC_UM_VIRTUAL_KEEP ((rsbac_um_set_t) -1)
#define RSBAC_UM_VIRTUAL_ALL ((rsbac_um_set_t) -2)
#define RSBAC_UM_VIRTUAL_MAX ((rsbac_um_set_t) -10)

typedef __u32 rsbac_list_ta_number_t;

struct rsbac_nanotime_t
    {
      rsbac_time_t sec;
      __u32 nsec;
    };

#ifdef __KERNEL__
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/pipe_fs_i.h>
#include <linux/kdev_t.h>

/* version checks */
#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,19)
#error "RSBAC: unsupported kernel version"
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <linux/pid.h>
#endif
#define RSBAC_MAJOR MAJOR
#define RSBAC_MINOR MINOR
#define RSBAC_MKDEV(major,minor) MKDEV(major,minor)
static inline rsbac_time_t rsbac_current_time(void)
  {
    struct timespec ts = CURRENT_TIME;
    return ts.tv_sec;
  }
static inline void rsbac_get_current_nanotime(struct rsbac_nanotime_t * nanotime)
  {
    struct timespec ts = CURRENT_TIME;
    nanotime->sec = ts.tv_sec;
    nanotime->nsec = ts.tv_nsec;
  }
#ifndef kdev_t
#define kdev_t dev_t
#endif
#define RSBAC_CURRENT_TIME (rsbac_current_time())


#define RSBAC_ZERO_DEV RSBAC_MKDEV(0,0)
#define RSBAC_AUTO_DEV RSBAC_MKDEV(99,99)
#define RSBAC_IS_ZERO_DEV(kdev) (!RSBAC_MAJOR(kdev) && !RSBAC_MINOR(kdev))
#define RSBAC_IS_AUTO_DEV(kdev) ((RSBAC_MAJOR(kdev) == 99) && (RSBAC_MINOR(kdev) == 99))

#ifdef CONFIG_RSBAC_INIT_DELAY
#define R_INIT
#else
#define R_INIT __init
#endif

#endif

/* General */

#ifndef NULL
#define NULL ((void *) 0)
#endif

#define rsbac_min(a,b) (((a)<(b))?(a):(b))
#define rsbac_max(a,b) (((a)>(b))?(a):(b))

#define RSBAC_OLD_NO_USER 65533
#define RSBAC_OLD_ALL_USERS 65532
#define RSBAC_NO_USER ((rsbac_uid_num_t) -3)
#define RSBAC_ALL_USERS ((rsbac_uid_num_t) -4)
#define RSBAC_NO_GROUP ((rsbac_gid_num_t) -3)
#define RSBAC_ALL_GROUPS ((rsbac_gid_num_t) -4)

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

typedef u_int rsbac_boolean_t;

typedef __u8 rsbac_boolean_int_t;

#define RSBAC_IFNAMSIZ 16
typedef u_char rsbac_netdev_id_t[RSBAC_IFNAMSIZ + 1];

#define RSBAC_SEC_DEL_CHUNK_SIZE 65536

/* Adjust these, if you have to, but if you do, adjust them all! */
/* Note: no / allowed, file must be exactly in second level! */
#define RSBAC_AUTH_LOGIN_PATH "/bin/login"
#define RSBAC_AUTH_LOGIN_PATH_DIR "bin"
#define RSBAC_AUTH_LOGIN_PATH_FILE "login"

/* These data structures work parallel to the Linux data structures, */
/* so all data for RSBAC decisions is maintained seperately.         */
/* Any change to RSBAC data will NOT modify any other linux data,    */
/* e.g. userlists, process lists or inodes.                          */

/* Special generic lists time-to-live (ttl) value to keep old setting */
#define RSBAC_LIST_TTL_KEEP ((rsbac_time_t) -1)

typedef __u8 rsbac_enum_t; /* internally used for all enums */

#define RSBAC_SYSADM_UID   0
#define RSBAC_BIN_UID      1
#ifdef CONFIG_RSBAC_SECOFF_UID
#define RSBAC_SECOFF_UID   CONFIG_RSBAC_SECOFF_UID
#else
#define RSBAC_SECOFF_UID 400
#endif
#define RSBAC_DATAPROT_UID (RSBAC_SECOFF_UID+1)
#define RSBAC_TPMAN_UID    (RSBAC_SECOFF_UID+2)
#define RSBAC_AUDITOR_UID  (RSBAC_SECOFF_UID+4)

typedef __u32 rsbac_pseudo_t;               /* For Pseudonymic Logging */
typedef __kernel_pid_t rsbac_upid_t;         /* Same as pid in Linux < 2.6.24 */

typedef struct pid * rsbac_pid_t;         /* use new pid struct */

typedef __u32 rsbac_ta_number_t;

typedef __u8 rsbac_security_level_t;
#define SL_max            252
#define SL_min            0
// #define SL_rsbac_internal 253
#define SL_inherit        254
#define SL_none           255
enum    rsbac_old_security_level_t {SL_unclassified, SL_confidential, SL_secret,
                                    SL_top_secret, SL_old_rsbac_internal,
                                    SL_old_inherit, SL_old_none};
                                             /* MAC security levels   */
typedef __u64 rsbac_mac_category_vector_t;   /* MAC category sets */
#define RSBAC_MAC_GENERAL_CATEGORY 0
#define RSBAC_MAC_DEF_CAT_VECTOR ((rsbac_mac_category_vector_t) 1)
  /* 1 << GENERAL_CAT */
#define RSBAC_MAC_MAX_CAT_VECTOR ((rsbac_mac_category_vector_t) -1)
  /* all bits set */
#define RSBAC_MAC_MIN_CAT_VECTOR ((rsbac_mac_category_vector_t) 0)
  /* no bits set */
#define RSBAC_MAC_INHERIT_CAT_VECTOR ((rsbac_mac_category_vector_t) 0)
  /* for fd: no bits set */
#define RSBAC_MAC_NR_CATS 64
#define RSBAC_MAC_MAX_CAT 63

#define RSBAC_MAC_CAT_VECTOR(x) ((rsbac_mac_category_vector_t) 1 << (x))

typedef u_int rsbac_cwi_relation_id_t;

/* For MAC, FF, AUTH */
enum    rsbac_system_role_t {SR_user, SR_security_officer, SR_administrator,
                             SR_auditor, SR_none};
typedef rsbac_enum_t rsbac_system_role_int_t;

/* For all models */
enum    rsbac_fake_root_uid_t {FR_off, FR_uid_only, FR_euid_only, FR_both,
                              FR_none};
typedef rsbac_enum_t rsbac_fake_root_uid_int_t;

enum    rsbac_scd_type_t {ST_time_strucs, ST_clock, ST_host_id,
                          ST_net_id, ST_ioports, ST_rlimit,
                          ST_swap, ST_syslog, ST_rsbac, ST_rsbac_log,
                          ST_other, ST_kmem, ST_network, ST_firewall,
                          ST_priority, ST_sysfs, ST_rsbac_remote_log,
                          ST_quota, ST_sysctl, ST_nfsd, ST_ksyms,
                          ST_mlock, ST_capability, ST_kexec, ST_videomem,
                          ST_none};

typedef __u32 rsbac_scd_vector_t;
#define RSBAC_SCD_VECTOR(x) ((rsbac_scd_vector_t) 1 << (x))

enum    rsbac_dev_type_t {D_block, D_char, D_block_major, D_char_major, D_none};


enum    rsbac_ipc_type_t {I_sem, I_msg, I_shm, I_anonpipe, I_mqueue,
				I_anonunix, I_none};
union   rsbac_ipc_id_t
  {
    u_long id_nr;
  };

typedef __u32 rsbac_inode_nr_t;

enum    rsbac_linux_dac_disable_t {LDD_false, LDD_true, LDD_inherit, LDD_none};
typedef rsbac_enum_t rsbac_linux_dac_disable_int_t;

#ifdef __KERNEL__
/* We need unique identifiers for each file/dir. inode means inode in */
/* the file system.                                                   */
struct rsbac_fs_file_t
    {
      kdev_t               device;
      rsbac_inode_nr_t     inode;
      struct dentry      * dentry_p;  /* used for inheritance recursion */
    };

struct rsbac_dev_t
    {
      enum  rsbac_dev_type_t     type;
            kdev_t               id;
    };
#endif /* __KERNEL */

/* We need unique ids for dev objects */
struct rsbac_dev_desc_t
    {
      __u32 type;
      __u32 major;
      __u32 minor;
    };

static inline struct rsbac_dev_desc_t
  rsbac_mkdev_desc(__u32 type, __u32 major, __u32 minor)
  {
    struct rsbac_dev_desc_t dev_desc;

    dev_desc.type = type;
    dev_desc.major = major;
    dev_desc.minor = minor;
    return dev_desc;
  }

#define RSBAC_ZERO_DEV_DESC rsbac_mkdev_desc(D_none, 0, 0)
#define RSBAC_AUTO_DEV_DESC rsbac_mkdev_desc(D_none, 99, 99)
#define RSBAC_IS_ZERO_DEV_DESC(dev) ((dev.type == D_none) && !dev.major && !dev.minor)
#define RSBAC_IS_AUTO_DEV_DESC(dev) ((dev.type == D_none) && (dev.major == 99) && (dev.minor == 99))

/* And we need unique ids for ipc objects */
struct rsbac_ipc_t
    {
      enum  rsbac_ipc_type_t     type;
      union rsbac_ipc_id_t       id;
    };

/* log levels: nothing, denied requests only, all, refer to request log level */
enum    rsbac_log_level_t {LL_none, LL_denied, LL_full, LL_request, LL_invalid};
typedef __u64 rsbac_log_array_t;

/* request bitvectors */
typedef __u64 rsbac_request_vector_t;
#define RSBAC_REQUEST_VECTOR(x) ((rsbac_request_vector_t) 1 << (x))

/* The max length of each filename is kept in a macro */
#define RSBAC_MAXNAMELEN     256

#define RSBAC_LIST_TA_MAX_NAMELEN 32
#define RSBAC_LIST_TA_MAX_PASSLEN 36

/* MAC */

typedef __u8 rsbac_mac_user_flags_t;
typedef __u16 rsbac_mac_process_flags_t;
typedef __u8 rsbac_mac_file_flags_t;
typedef struct rsbac_fs_file_t rsbac_mac_file_t;
#define RSBAC_MAC_MAX_MAXNUM 1000000

#define MAC_override		1
#define MAC_auto		2
#define MAC_trusted     	4
#define MAC_write_up		8
#define MAC_read_up		16
#define MAC_write_down		32
#define MAC_allow_auto		64
#define MAC_prop_trusted	128
#define MAC_program_auto	256

#define RSBAC_MAC_U_FLAGS (MAC_override | MAC_trusted | MAC_write_up | MAC_read_up | MAC_write_down | MAC_allow_auto)
#define RSBAC_MAC_P_FLAGS (MAC_override | MAC_auto | MAC_trusted | MAC_write_up | MAC_read_up | MAC_write_down | MAC_prop_trusted | MAC_program_auto)
#define RSBAC_MAC_F_FLAGS (MAC_auto | MAC_trusted | MAC_write_up | MAC_read_up | MAC_write_down)

#define RSBAC_MAC_DEF_U_FLAGS 0
#define RSBAC_MAC_DEF_SYSADM_U_FLAGS MAC_allow_auto
#define RSBAC_MAC_DEF_SECOFF_U_FLAGS MAC_override

#define RSBAC_MAC_DEF_P_FLAGS 0
#define RSBAC_MAC_DEF_INIT_P_FLAGS MAC_auto

typedef rsbac_enum_t rsbac_mac_auto_int_t;
enum    rsbac_mac_auto_t {MA_no, MA_yes, MA_inherit};

/* PM */

#include <rsbac/pm_types.h>

/* DAZ */
typedef __u8 rsbac_daz_scanned_t;
#define DAZ_unscanned 0
#define DAZ_infected 1
#define DAZ_clean 2
#define DAZ_max 2
#define DEFAULT_DAZ_FD_SCANNED DAZ_unscanned
typedef __u8 rsbac_daz_scanner_t;
typedef __u8 rsbac_daz_do_scan_t;
#define DAZ_never 0
#define DAZ_registered 1
#define DAZ_always 2
#define DAZ_inherit 3
#define DAZ_max_do_scan 3
#define DEFAULT_DAZ_FD_DO_SCAN DAZ_inherit
#define DEFAULT_DAZ_FD_ROOT_DO_SCAN DAZ_registered

/* FF */

typedef __u16 rsbac_ff_flags_t;
#define FF_read_only       1
#define FF_execute_only    2
#define FF_search_only     4
#define FF_write_only      8
#define FF_secure_delete  16
#define FF_no_execute     32
#define FF_no_delete_or_rename 64
#define FF_append_only   256
#define FF_no_mount      512
#define FF_no_search     1024

#define FF_add_inherited 128

#define RSBAC_FF_DEF FF_add_inherited
#define RSBAC_FF_ROOT_DEF 0

/***** RC *****/

#include <rsbac/rc_types.h>

/**** AUTH ****/
/* special cap value, replaced by process owner at execute time */
#define RSBAC_AUTH_MAX_MAXNUM 1000000
#define RSBAC_AUTH_OWNER_F_CAP ((rsbac_uid_num_t) -3)
#define RSBAC_AUTH_DAC_OWNER_F_CAP ((rsbac_uid_num_t) -4)
#define RSBAC_AUTH_MAX_RANGE_UID ((rsbac_uid_num_t) -10)
#define RSBAC_AUTH_GROUP_F_CAP ((rsbac_uid_num_t) -3)
#define RSBAC_AUTH_DAC_GROUP_F_CAP ((rsbac_uid_num_t) -4)
#define RSBAC_AUTH_MAX_RANGE_GID ((rsbac_uid_num_t) -10)
typedef struct rsbac_fs_file_t rsbac_auth_file_t;
struct rsbac_auth_cap_range_t
  {
    rsbac_uid_t first;
    rsbac_uid_t last;
  };
struct rsbac_auth_old_cap_range_t
  {
    rsbac_old_uid_t first;
    rsbac_old_uid_t last;
  };
enum    rsbac_auth_cap_type_t {ACT_real, ACT_eff, ACT_fs, 
                               ACT_group_real, ACT_group_eff, ACT_group_fs,
                               ACT_none};
typedef rsbac_enum_t rsbac_auth_cap_type_int_t;

enum    rsbac_auth_may_setuid_t {AMS_off, AMS_full, AMS_last_auth_only, 
                               AMS_last_auth_and_gid, AMS_none};

typedef rsbac_enum_t rsbac_auth_may_setuid_int_t;

/**** ACL ****/
/* include at end of types.h */

/**** CAP ****/
enum    rsbac_cap_process_hiding_t {PH_off, PH_from_other_users, PH_full,
                              PH_none};
typedef rsbac_enum_t rsbac_cap_process_hiding_int_t;

enum rsbac_cap_ld_env_t { LD_deny, LD_allow, LD_keep, LD_inherit };
typedef rsbac_enum_t rsbac_cap_ld_env_int_t;

#define RSBAC_CAP_DEFAULT_MIN (__u32) 0
#define RSBAC_CAP_DEFAULT_MAX (__u32) -1

#include <linux/capability.h>
#define CAP_NONE 34
#define RSBAC_CAP_MAX CAP_NONE

/**** JAIL ****/

#define RSBAC_JAIL_VERSION 1

typedef __u32 rsbac_jail_id_t;
#define RSBAC_JAIL_DEF_ID 0
typedef __u32 rsbac_jail_ip_t;
typedef __u32 rsbac_jail_scd_vector_t;

typedef __u32 rsbac_jail_flags_t;
#define JAIL_allow_external_ipc 1
#define JAIL_allow_all_net_family 2
#define JAIL_allow_inet_raw 8
#define JAIL_auto_adjust_inet_any 16
#define JAIL_allow_inet_localhost 32
#define JAIL_allow_dev_get_status 128
#define JAIL_allow_dev_mod_system 256
#define JAIL_allow_dev_read 512
#define JAIL_allow_dev_write 1024
#define JAIL_allow_tty_open 2048
#define JAIL_allow_parent_ipc 4096
#define JAIL_allow_suid_files 8192
#define JAIL_allow_mount 16384
#define JAIL_this_is_syslog 32768
#define JAIL_allow_ipc_to_syslog 65536
#define JAIL_allow_netlink 131072

#define RSBAC_JAIL_LOCALHOST ((1 << 24) | 127)

/**** PAX ****/

typedef unsigned long rsbac_pax_flags_t;

/* for PaX defines */
#ifdef __KERNEL__
#include <linux/elf.h>
#include <linux/random.h>
#endif
#ifndef PF_PAX_PAGEEXEC
#define PF_PAX_PAGEEXEC	0x01000000	/* Paging based non-executable pages */
#define PF_PAX_EMUTRAMP	0x02000000	/* Emulate trampolines */
#define PF_PAX_MPROTECT	0x04000000	/* Restrict mprotect() */
#define PF_PAX_RANDMMAP	0x08000000	/* Randomize mmap() base */
#define PF_PAX_RANDEXEC	0x10000000	/* Randomize ET_EXEC base */
#define PF_PAX_SEGMEXEC	0x20000000	/* Segmentation based non-executable pages */
#endif

#define RSBAC_PAX_DEF_FLAGS (PF_PAX_SEGMEXEC | PF_PAX_PAGEEXEC | PF_PAX_MPROTECT | PF_PAX_RANDMMAP)
#define RSBAC_PAX_ALL_FLAGS ((rsbac_pax_flags_t) 255 << 24)

/**** UM User management ****/
/* Included from um_types.h */

/**** RES ****/

typedef __u32 rsbac_res_limit_t;
#define RSBAC_RES_UNSET 0

#define RSBAC_RES_MAX 10 /* RLIMIT_LOCKS in 2.4.x kernels */
#define RSBAC_RES_NONE 11

typedef rsbac_res_limit_t rsbac_res_array_t[RSBAC_RES_MAX + 1];

/**** REG ****/
typedef __s32 rsbac_reg_handle_t;


/****************************************************************************/
/* ADF types                                                                */
/****************************************************************************/

#include <rsbac/network_types.h>

#ifdef __KERNEL__
    typedef struct socket * rsbac_net_obj_id_t;
#else
    typedef void * rsbac_net_obj_id_t;
#endif

struct rsbac_net_obj_desc_t
  {
    rsbac_net_obj_id_t sock_p;
    void * local_addr;
    u_int  local_len;
    void * remote_addr;
    u_int  remote_len;
    rsbac_net_temp_id_t local_temp;
    rsbac_net_temp_id_t remote_temp;
  };

#define RSBAC_ADF_REQUEST_ARRAY_VERSION 2

enum  rsbac_adf_request_t {
                        R_ADD_TO_KERNEL,
                        R_ALTER,
                        R_APPEND_OPEN,
                        R_CHANGE_GROUP,
                        R_CHANGE_OWNER,
                        R_CHDIR,
                        R_CLONE,
                        R_CLOSE,
                        R_CREATE,
                        R_DELETE,
                        R_EXECUTE,
                        R_GET_PERMISSIONS_DATA,
                        R_GET_STATUS_DATA,
                        R_LINK_HARD,
                        R_MODIFY_ACCESS_DATA,
                        R_MODIFY_ATTRIBUTE,
                        R_MODIFY_PERMISSIONS_DATA,
                        R_MODIFY_SYSTEM_DATA,
                        R_MOUNT,
                        R_READ,
                        R_READ_ATTRIBUTE,
                        R_READ_WRITE_OPEN,
                        R_READ_OPEN,
                        R_REMOVE_FROM_KERNEL,
                        R_RENAME,
                        R_SEARCH,
                        R_SEND_SIGNAL,
                        R_SHUTDOWN,
                        R_SWITCH_LOG,
                        R_SWITCH_MODULE,
                        R_TERMINATE,
                        R_TRACE,
                        R_TRUNCATE,
                        R_UMOUNT,
                        R_WRITE,
                        R_WRITE_OPEN,
                        R_MAP_EXEC,
                        R_BIND,
                        R_LISTEN,
                        R_ACCEPT,
                        R_CONNECT,
                        R_SEND,
                        R_RECEIVE,
                        R_NET_SHUTDOWN,
                        R_CHANGE_DAC_EFF_OWNER,
                        R_CHANGE_DAC_FS_OWNER,
                        R_CHANGE_DAC_EFF_GROUP,
                        R_CHANGE_DAC_FS_GROUP,
                        R_IOCTL,
                        R_LOCK,
                        R_AUTHENTICATE,
                        R_NONE
                      };

typedef rsbac_enum_t rsbac_adf_request_int_t;

#include <rsbac/request_groups.h>

/* This type is returned from the rsbac_adf_request() function. Since a */
/* decision of undefined means an error, it is never returned.          */

enum  rsbac_adf_req_ret_t {NOT_GRANTED,GRANTED,DO_NOT_CARE,UNDEFINED};

/****************************************************************************/
/* ACI types                                                                */
/****************************************************************************/

/* For switching adf-modules */
enum  rsbac_switch_target_t {SW_GEN,SW_MAC,SW_PM,SW_DAZ,SW_FF,SW_RC,SW_AUTH,
			SW_REG,SW_ACL,SW_CAP,SW_JAIL,SW_RES,SW_PAX,SW_SOFTMODE,
			SW_DAC_DISABLE,SW_UM,SW_FREEZE,SW_NONE};
#define RSBAC_MAX_MOD (SW_SOFTMODE - 1)
typedef rsbac_enum_t rsbac_switch_target_int_t;

/****************************************************************************/
/* For objects, users and processes all manipulation is encapsulated by the */
/* function calls rsbac_set_attr, rsbac_get_attr and rsbac_remove_target.   */

/* For those, we declare some extra types to specify target and attribute.  */

enum   rsbac_target_t {T_FILE, T_DIR, T_FIFO, T_SYMLINK, T_DEV, T_IPC, T_SCD, T_USER, T_PROCESS,
                       T_NETDEV, T_NETTEMP, T_NETOBJ, T_NETTEMP_NT, T_GROUP,
                       T_FD, T_UNIXSOCK,
                       T_NONE};

union  rsbac_target_id_t
       {
#ifdef __KERNEL__
          struct rsbac_fs_file_t    file;
          struct rsbac_fs_file_t    dir;
          struct rsbac_fs_file_t    fifo;
          struct rsbac_fs_file_t    symlink;
          struct rsbac_fs_file_t    unixsock;
#endif
          struct rsbac_dev_desc_t   dev;
          struct rsbac_ipc_t        ipc;
          rsbac_enum_t              scd;
          rsbac_uid_t               user;
          rsbac_gid_t               group;
          rsbac_pid_t               process; /* new struct pid * */
          rsbac_upid_t              uprocess; /* old fashioned pid from user space */
          rsbac_netdev_id_t         netdev;
          rsbac_net_temp_id_t       nettemp;
          struct rsbac_net_obj_desc_t netobj;
          int                       dummy;
       };

#ifdef __KERNEL__
typedef rsbac_enum_t rsbac_log_entry_t[T_NONE+1];
typedef rsbac_enum_t rsbac_old_log_entry_t[T_NONE];

struct rsbac_create_data_t
  {
    enum   rsbac_target_t   target;
    struct dentry         * dentry_p;
           int              mode;
           kdev_t           device; /* for mknod etc. */
  };

struct rsbac_rlimit_t
  {
           u_int            resource;
    struct rlimit           limit;
  };
#endif

enum rsbac_attribute_t
  {
    A_pseudo,
    A_security_level,
    A_initial_security_level,
    A_local_sec_level,
    A_remote_sec_level,
    A_min_security_level,
    A_mac_categories,
    A_mac_initial_categories,
    A_local_mac_categories,
    A_remote_mac_categories,
    A_mac_min_categories,
    A_mac_user_flags,
    A_mac_process_flags,
    A_mac_file_flags,
    A_system_role,
    A_mac_role,
    A_daz_role,
    A_ff_role,
    A_auth_role,
    A_cap_role,
    A_jail_role,
    A_pax_role,
    A_current_sec_level,
    A_mac_curr_categories,
    A_min_write_open,
    A_min_write_categories,
    A_max_read_open,
    A_max_read_categories,
    A_mac_auto,
    A_mac_check,
    A_mac_prop_trusted,
    A_pm_role,
    A_pm_process_type,
    A_pm_current_task,
    A_pm_object_class,
    A_local_pm_object_class,
    A_remote_pm_object_class,
    A_pm_ipc_purpose,
    A_local_pm_ipc_purpose,
    A_remote_pm_ipc_purpose,
    A_pm_object_type,
    A_local_pm_object_type,
    A_remote_pm_object_type,
    A_pm_program_type,
    A_pm_tp,
    A_pm_task_set,
    A_daz_scanned,
    A_daz_scanner,
    A_ff_flags,
    A_rc_type,
    A_rc_select_type,
    A_local_rc_type,
    A_remote_rc_type,
    A_rc_type_fd,
    A_rc_type_nt,
    A_rc_force_role,
    A_rc_initial_role,
    A_rc_role,
    A_rc_def_role,
    A_auth_may_setuid,
    A_auth_may_set_cap,
    A_auth_learn,
    A_min_caps,
    A_max_caps,
    A_max_caps_user,
    A_max_caps_program,
    A_jail_id,
    A_jail_parent,
    A_jail_ip,
    A_jail_flags,
    A_jail_max_caps,
    A_jail_scd_get,
    A_jail_scd_modify,
    A_pax_flags,
    A_res_role,
    A_res_min,
    A_res_max,
    A_log_array_low,
    A_local_log_array_low,
    A_remote_log_array_low,
    A_log_array_high,
    A_local_log_array_high,
    A_remote_log_array_high,
    A_log_program_based,
    A_log_user_based,
    A_symlink_add_remote_ip,
    A_symlink_add_uid,
    A_symlink_add_mac_level,
    A_symlink_add_rc_role,
    A_linux_dac_disable,
    A_cap_process_hiding,
    A_fake_root_uid,
    A_audit_uid,
    A_auid_exempt,
    A_auth_last_auth,
    A_remote_ip,
    A_cap_ld_env,
    A_daz_do_scan,
    A_vset,
#ifdef __KERNEL__
    /* adf-request helpers */
    A_owner,
    A_group,
    A_signal,
    A_mode,
    A_nlink,
    A_switch_target,
    A_mod_name,
    A_request,
    A_trace_request,
    A_auth_add_f_cap,
    A_auth_remove_f_cap,
    A_auth_get_caplist,
    A_prot_bits,
    A_internal,
    /* used with CREATE on DIR */
    A_create_data,
    A_new_object,
    A_rlimit,
    A_new_dir_dentry_p,
    A_program_file,
    A_auth_start_uid,
    A_auth_start_euid,
    A_auth_start_gid,
    A_auth_start_egid,
    A_acl_learn,
    A_priority,
    A_pgid,
    A_kernel_thread,
    A_open_flag,
    A_reboot_cmd,
    A_setsockopt_level,
    A_ioctl_cmd,
    A_f_mode,
    A_process,
    A_sock_type,
    A_pagenr,
    A_cap_learn,
    A_rc_learn,
#endif
    A_none};

union rsbac_attribute_value_t
  {
         rsbac_uid_t                 owner;           /* process owner */
         rsbac_pseudo_t              pseudo;
         rsbac_system_role_int_t     system_role;
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_MAC)
         rsbac_security_level_t      security_level;
         rsbac_mac_category_vector_t mac_categories;
         rsbac_security_level_t      current_sec_level;
         rsbac_security_level_t      min_write_open;
         rsbac_security_level_t      max_read_open;
         rsbac_mac_user_flags_t      mac_user_flags;
         rsbac_mac_process_flags_t   mac_process_flags;
         rsbac_mac_file_flags_t      mac_file_flags;
         rsbac_mac_auto_int_t        mac_auto;
         rsbac_boolean_t             mac_check;
         rsbac_boolean_t             mac_prop_trusted;
#endif
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_PM)
         rsbac_pm_role_int_t         pm_role;
         rsbac_pm_process_type_int_t pm_process_type;
         rsbac_pm_task_id_t          pm_current_task;
         rsbac_pm_object_class_id_t  pm_object_class;
         rsbac_pm_purpose_id_t       pm_ipc_purpose;
         rsbac_pm_object_type_int_t  pm_object_type;
         rsbac_pm_program_type_int_t pm_program_type;
         rsbac_pm_tp_id_t            pm_tp;
         rsbac_pm_task_set_id_t      pm_task_set;
#endif
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_DAZ)
         rsbac_daz_scanned_t         daz_scanned;
         rsbac_daz_scanner_t         daz_scanner;
         rsbac_daz_do_scan_t         daz_do_scan;
#endif
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_FF)
         rsbac_ff_flags_t            ff_flags;
#endif
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_RC)
         rsbac_rc_type_id_t          rc_type;
         rsbac_rc_type_id_t          rc_type_fd;
         rsbac_rc_role_id_t          rc_force_role;
         rsbac_rc_role_id_t          rc_initial_role;
         rsbac_rc_role_id_t          rc_role;
         rsbac_rc_role_id_t          rc_def_role;
         rsbac_rc_type_id_t          rc_select_type;
#endif
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_AUTH)
         rsbac_auth_may_setuid_int_t auth_may_setuid;
         rsbac_boolean_t             auth_may_set_cap;
         rsbac_pid_t                 auth_p_capset;
         rsbac_inode_nr_t            auth_f_capset;
         rsbac_boolean_t             auth_learn;
         rsbac_uid_t                 auth_last_auth;
#endif
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_CAP)
         rsbac_cap_vector_t          min_caps;
         rsbac_cap_vector_t          max_caps;
         rsbac_cap_vector_t          max_caps_user;
         rsbac_cap_vector_t          max_caps_program;
         rsbac_cap_process_hiding_int_t cap_process_hiding;
         rsbac_cap_ld_env_int_t      cap_ld_env;
#endif
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_JAIL)
         rsbac_jail_id_t             jail_id;
         rsbac_jail_id_t             jail_parent;
         rsbac_jail_ip_t             jail_ip;
         rsbac_jail_flags_t          jail_flags;
         rsbac_jail_scd_vector_t     jail_scd_get;
         rsbac_jail_scd_vector_t     jail_scd_modify;
         rsbac_cap_vector_t          jail_max_caps;
#endif
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_PAX)
         rsbac_pax_flags_t           pax_flags;
#endif
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_RES)
         rsbac_res_array_t           res_array;
#endif
         rsbac_log_array_t           log_array_low;
         rsbac_log_array_t           log_array_high;
         rsbac_request_vector_t      log_program_based;
         rsbac_request_vector_t      log_user_based;
         rsbac_enum_t                symlink_add_remote_ip;
         rsbac_boolean_t             symlink_add_uid;
         rsbac_boolean_t             symlink_add_mac_level;
         rsbac_boolean_t             symlink_add_rc_role;
         rsbac_linux_dac_disable_int_t linux_dac_disable;
//         rsbac_net_temp_id_t         net_temp;
         rsbac_fake_root_uid_int_t   fake_root_uid;
         rsbac_uid_t                 audit_uid;
         rsbac_uid_t                 auid_exempt;
         __u32                       remote_ip;
         rsbac_um_set_t              vset;
#ifdef __KERNEL__
         rsbac_gid_t     	     group;        /* process/fd group */
    struct sockaddr                * sockaddr_p; /* socket address */
         long                        signal;        /* signal for kill */
         int                         mode;    /* mode for create/mount */
         int                         nlink;       /* for DELETE/unlink */
    enum rsbac_switch_target_t       switch_target; /* for SWITCH_MODULE */
         char                      * mod_name;    /* for ADD_TO_KERNEL */
    enum rsbac_adf_request_t         request;        /* for SWITCH_LOG */
         long                        trace_request; /* request for sys_trace */
    struct rsbac_auth_cap_range_t    auth_cap_range;
    	 int                         prot_bits;/* prot bits for mmap()/mprotect() */
         rsbac_boolean_t             internal;
    /* used with CREATE on DIR */
    struct rsbac_create_data_t       create_data;
    /* newly created object in OPEN requests? */
         rsbac_boolean_t             new_object;
    struct rsbac_rlimit_t            rlimit;
         struct dentry             * new_dir_dentry_p;
         struct rsbac_fs_file_t      program_file; /* for learning mode */
         rsbac_uid_t                 auth_start_uid;
         rsbac_uid_t                 auth_start_euid;
         rsbac_gid_t                 auth_start_gid;
         rsbac_gid_t                 auth_start_egid;
         rsbac_boolean_t             acl_learn;
         int                         priority;
         rsbac_pid_t                 pgid;
         rsbac_boolean_t             kernel_thread;
         u_int                       open_flag;
         u_int                       reboot_cmd;
         int                         setsockopt_level;
         u_int                       ioctl_cmd;
         mode_t                      f_mode;
         rsbac_pid_t                 process;
         short                       sock_type;
         u_int                       pagenr;
         rsbac_boolean_t             cap_learn;
         rsbac_boolean_t             rc_learn;
#endif
         u_char                      u_char_dummy;
         u_short                     u_short_dummy;
         int                         dummy;
         u_int                       u_dummy;
         long                        long_dummy;
         u_long                      u_long_dummy;
       };

/* List all values possibly used in FD Cache to find data size */

#ifdef CONFIG_RSBAC_FD_CACHE
union rsbac_attribute_value_cache_t
  {
         rsbac_uid_t                 owner;           /* process owner */
         rsbac_pseudo_t              pseudo;
         rsbac_system_role_int_t     system_role;
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_MAC)
         rsbac_security_level_t      security_level;
         rsbac_mac_category_vector_t mac_categories;
         rsbac_security_level_t      current_sec_level;
         rsbac_security_level_t      min_write_open;
         rsbac_security_level_t      max_read_open;
         rsbac_mac_user_flags_t      mac_user_flags;
         rsbac_mac_process_flags_t   mac_process_flags;
         rsbac_mac_file_flags_t      mac_file_flags;
         rsbac_mac_auto_int_t        mac_auto;
         rsbac_boolean_t             mac_check;
         rsbac_boolean_t             mac_prop_trusted;
#endif
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_DAZ)
         rsbac_daz_scanned_t         daz_scanned;
         rsbac_daz_scanner_t         daz_scanner;
         rsbac_daz_do_scan_t         daz_do_scan;
#endif
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_FF)
         rsbac_ff_flags_t            ff_flags;
#endif
#if !defined(__KERNEL__) || defined(CONFIG_RSBAC_RC)
         rsbac_rc_type_id_t          rc_type;
         rsbac_rc_type_id_t          rc_type_fd;
         rsbac_rc_role_id_t          rc_force_role;
         rsbac_rc_role_id_t          rc_initial_role;
         rsbac_rc_role_id_t          rc_role;
         rsbac_rc_role_id_t          rc_def_role;
         rsbac_rc_type_id_t          rc_select_type;
#endif
         rsbac_log_array_t           log_array_low;
         rsbac_log_array_t           log_array_high;
         rsbac_request_vector_t      log_program_based;
         rsbac_request_vector_t      log_user_based;
         rsbac_enum_t                symlink_add_remote_ip;
         rsbac_boolean_t             symlink_add_uid;
         rsbac_boolean_t             symlink_add_mac_level;
         rsbac_boolean_t             symlink_add_rc_role;
         rsbac_linux_dac_disable_int_t linux_dac_disable;
//         rsbac_net_temp_id_t         net_temp;
         rsbac_fake_root_uid_int_t   fake_root_uid;
         rsbac_uid_t                 audit_uid;
         rsbac_uid_t                 auid_exempt;
         __u32                       remote_ip;
         rsbac_um_set_t              vset;
         u_char                      u_char_dummy;
         u_short                     u_short_dummy;
         int                         dummy;
         u_int                       u_dummy;
         long                        long_dummy;
         u_long                      u_long_dummy;
       };
#endif

/**** ACL + UM ****/

#include <rsbac/acl_types.h>
#include <rsbac/um_types.h>

/* not aligned, yet */
struct rsbac_rw_req {
	enum  rsbac_target_t rsbac_target;
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_target_id_t rsbac_new_target_id;
	enum  rsbac_attribute_t rsbac_attribute;
	union rsbac_attribute_value_t rsbac_attribute_value;
	enum rsbac_adf_request_t rsbac_request;
};

int rsbac_handle_rw_req(const struct file *file, struct rsbac_rw_req *rsbac_rw_req_obj);
int rsbac_handle_rw_up(struct rsbac_rw_req *rsbac_rw_req_obj);

#endif

