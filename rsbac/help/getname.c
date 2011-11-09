/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2009:           */
/*   Amon Ott <ao@rsbac.org>           */
/* Helper functions for all parts      */
/* Last modified: 05/Oct/2009          */
/************************************* */

#include <rsbac/types.h>
#include <rsbac/getname.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>
#include <rsbac/pax_getname.h>

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <rsbac/rkmem.h>
#include <rsbac/network.h>
#include <rsbac/net_getname.h>
#else
#include <string.h>
#include <stdio.h>
#include <errno.h>
#endif

static char request_list[R_NONE + 1][24] = {
	"ADD_TO_KERNEL",
	"ALTER",
	"APPEND_OPEN",
	"CHANGE_GROUP",
	"CHANGE_OWNER",
	"CHDIR",
	"CLONE",
	"CLOSE",
	"CREATE",
	"DELETE",
	"EXECUTE",
	"GET_PERMISSIONS_DATA",
	"GET_STATUS_DATA",
	"LINK_HARD",
	"MODIFY_ACCESS_DATA",
	"MODIFY_ATTRIBUTE",
	"MODIFY_PERMISSIONS_DATA",
	"MODIFY_SYSTEM_DATA",
	"MOUNT",
	"READ",
	"READ_ATTRIBUTE",
	"READ_WRITE_OPEN",
	"READ_OPEN",
	"REMOVE_FROM_KERNEL",
	"RENAME",
	"SEARCH",
	"SEND_SIGNAL",
	"SHUTDOWN",
	"SWITCH_LOG",
	"SWITCH_MODULE",
	"TERMINATE",
	"TRACE",
	"TRUNCATE",
	"UMOUNT",
	"WRITE",
	"WRITE_OPEN",
	"MAP_EXEC",
	"BIND",
	"LISTEN",
	"ACCEPT",
	"CONNECT",
	"SEND",
	"RECEIVE",
	"NET_SHUTDOWN",
	"CHANGE_DAC_EFF_OWNER",
	"CHANGE_DAC_FS_OWNER",
	"CHANGE_DAC_EFF_GROUP",
	"CHANGE_DAC_FS_GROUP",
	"IOCTL",
	"LOCK",
	"AUTHENTICATE",
	"NONE"
};

static char result_list[UNDEFINED + 1][12] = {
	"NOT_GRANTED",
	"GRANTED",
	"DO_NOT_CARE",
	"UNDEFINED"
};

static rsbac_switch_target_int_t attr_mod_list[A_none + 1] = {
	SW_GEN,			/* pseudo */
	SW_MAC,			/* security_level */
	SW_MAC,			/* initial_security_level */
	SW_MAC,			/* local_sec_level */
	SW_MAC,			/* remote_sec_level */
	SW_MAC,			/* min_security_level */
	SW_MAC,			/* mac_categories */
	SW_MAC,			/* mac_initial_categories */
	SW_MAC,			/* local_mac_categories */
	SW_MAC,			/* remote_mac_categories */
	SW_MAC,			/* mac_min_categories */
	SW_MAC,			/* mac_user_flags */
	SW_MAC,			/* mac_process_flags */
	SW_MAC,			/* mac_file_flags */
	SW_NONE,		/* system_role */
	SW_MAC,			/* mac_role */
	SW_DAZ,			/* daz_role */
	SW_FF,			/* ff_role */
	SW_AUTH,			/* auth_role */
	SW_CAP,			/* cap_role */
	SW_JAIL,			/* jail_role */
	SW_PAX,			/* pax_role */
	SW_MAC,			/* current_sec_level */
	SW_MAC,			/* mac_curr_categories */
	SW_MAC,			/* min_write_open */
	SW_MAC,			/* min_write_categories */
	SW_MAC,			/* max_read_open */
	SW_MAC,			/* max_read_categories */
	SW_MAC,			/* mac_auto */
	SW_MAC,			/* mac_check */
	SW_MAC,			/* mac_prop_trusted */
	SW_PM,			/* pm_role */
	SW_PM,			/* pm_process_type */
	SW_PM,			/* pm_current_task */
	SW_PM,			/* pm_object_class */
	SW_PM,			/* local_pm_object_class */
	SW_PM,			/* remote_pm_object_class */
	SW_PM,			/* pm_ipc_purpose */
	SW_PM,			/* local_pm_ipc_purpose */
	SW_PM,			/* remote_pm_ipc_purpose */
	SW_PM,			/* pm_object_type */
	SW_PM,			/* local_pm_object_type */
	SW_PM,			/* remote_pm_object_type */
	SW_PM,			/* pm_program_type */
	SW_PM,			/* pm_tp */
	SW_PM,			/* pm_task_set */
	SW_DAZ,			/* daz_scanned */
	SW_DAZ,			/* daz_scanner */
	SW_FF,			/* ff_flags */
	SW_RC,			/* rc_type */
        SW_RC,                  /* rc_select_type */
	SW_RC,			/* local_rc_type */
	SW_RC,			/* remote_rc_type */
	SW_RC,			/* rc_type_fd */
	SW_RC,			/* rc_type_nt */
	SW_RC,			/* rc_force_role */
	SW_RC,			/* rc_initial_role */
	SW_RC,			/* rc_role */
	SW_RC,			/* rc_def_role */
	SW_AUTH,			/* auth_may_setuid */
	SW_AUTH,			/* auth_may_set_cap */
	SW_AUTH,			/* auth_learn */
	SW_CAP,			/* min_caps */
	SW_CAP,			/* max_caps */
	SW_CAP,			/* max_caps_user */
	SW_CAP,			/* max_caps_program */
	SW_JAIL,			/* jail_id */
	SW_JAIL,			/* jail_parent */
	SW_JAIL,			/* jail_ip */
	SW_JAIL,			/* jail_flags */
	SW_JAIL,			/* jail_max_caps */
	SW_JAIL,			/* jail_scd_get */
	SW_JAIL,			/* jail_scd_modify */
	SW_PAX,			/* pax_flags */
	SW_RES,			/* res_role */
	SW_RES,			/* res_min */
	SW_RES,			/* res_max */
	SW_GEN,			/* log_array_low */
	SW_GEN,			/* local_log_array_low */
	SW_GEN,			/* remote_log_array_low */
	SW_GEN,			/* log_array_high */
	SW_GEN,			/* local_log_array_high */
	SW_GEN,			/* remote_log_array_high */
	SW_GEN,			/* log_program_based */
	SW_GEN,			/* log_user_based */
	SW_GEN,			/* symlink_add_remote_ip */
	SW_GEN,			/* symlink_add_uid */
	SW_GEN,			/* symlink_add_mac_level */
	SW_GEN,			/* symlink_add_rc_role */
	SW_GEN,			/* linux_dac_disable */
	SW_CAP,			/* cap_process_hiding */
	SW_GEN,			/* fake_root_uid */
	SW_GEN,			/* audit_uid */
	SW_GEN,			/* auid_exempt */
	SW_AUTH,			/* auth_last_auth */
	SW_GEN,			/* remote_ip */
	SW_CAP,                 /* cap_ld_env */
	SW_DAZ,                 /* daz_do_scan */
	SW_GEN,			/* vset */
#ifdef __KERNEL__
	/* adf-request helpers */
	SW_NONE,		/* group */
	SW_NONE,		/* signal */
	SW_NONE,		/* mode */
	SW_NONE,		/* nlink */
	SW_NONE,		/* switch_target */
	SW_NONE,		/* mod_name */
	SW_NONE,		/* request */
	SW_NONE,		/* trace_request */
	SW_NONE,		/* auth_add_f_cap */
	SW_NONE,		/* auth_remove_f_cap */
	SW_NONE,		/* auth_get_caplist */
	SW_NONE,		/* prot_bits */
	SW_NONE,		/* internal */
	SW_NONE,		/* create_data */
	SW_NONE,		/* new_object */
	SW_NONE,		/* rlimit */
	SW_NONE,		/* new_dir_dentry_p */
	SW_NONE,		/* auth_program_file */
	SW_NONE,		/* auth_start_uid */
	SW_NONE,		/* auth_start_euid */
	SW_NONE,		/* auth_start_gid */
	SW_NONE,		/* auth_start_egid */
	SW_NONE,		/* acl_learn */
	SW_NONE,		/* priority */
	SW_NONE,		/* pgid */
	SW_NONE,		/* kernel_thread */
	SW_NONE,		/* open_flag */
	SW_NONE,		/* reboot_cmd */
	SW_NONE,		/* setsockopt_level */
	SW_NONE,		/* ioctl_cmd */
	SW_NONE,		/* f_mode */
	SW_NONE,		/* process */
	SW_NONE,		/* sock_type */
	SW_NONE,		/* pagenr */
#endif
	SW_NONE /* none */
};

static char attribute_list[A_none + 1][23] = {
	"pseudo",
	"security_level",
	"initial_security_level",
	"local_sec_level",
	"remote_sec_level",
	"min_security_level",
	"mac_categories",
	"mac_initial_categories",
	"local_mac_categories",
	"remote_mac_categories",
	"mac_min_categories",
	"mac_user_flags",
	"mac_process_flags",
	"mac_file_flags",
	"system_role",
	"mac_role",
	"daz_role",
	"ff_role",
	"auth_role",
	"cap_role",
	"jail_role",
	"pax_role",
	"current_sec_level",
	"mac_curr_categories",
	"min_write_open",
	"min_write_categories",
	"max_read_open",
	"max_read_categories",
	"mac_auto",
	"mac_check",
	"mac_prop_trusted",
	"pm_role",
	"pm_process_type",
	"pm_current_task",
	"pm_object_class",
	"local_pm_object_class",
	"remote_pm_object_class",
	"pm_ipc_purpose",
	"local_pm_ipc_purpose",
	"remote_pm_ipc_purpose",
	"pm_object_type",
	"local_pm_object_type",
	"remote_pm_object_type",
	"pm_program_type",
	"pm_tp",
	"pm_task_set",
	"daz_scanned",
	"daz_scanner",
	"ff_flags",
	"rc_type",
	"rc_select_type",
	"local_rc_type",
	"remote_rc_type",
	"rc_type_fd",
	"rc_type_nt",
	"rc_force_role",
	"rc_initial_role",
	"rc_role",
	"rc_def_role",
	"auth_may_setuid",
	"auth_may_set_cap",
	"auth_learn",
	"min_caps",
	"max_caps",
	"max_caps_user",
	"max_caps_program",
	"jail_id",
	"jail_parent",
	"jail_ip",
	"jail_flags",
	"jail_max_caps",
	"jail_scd_get",
	"jail_scd_modify",
	"pax_flags",
	"res_role",
	"res_min",
	"res_max",
	"log_array_low",
	"local_log_array_low",
	"remote_log_array_low",
	"log_array_high",
	"local_log_array_high",
	"remote_log_array_high",
	"log_program_based",
	"log_user_based",
	"symlink_add_remote_ip",
	"symlink_add_uid",
	"symlink_add_mac_level",
	"symlink_add_rc_role",
	"linux_dac_disable",
	"cap_process_hiding",
	"fake_root_uid",
	"audit_uid",
	"auid_exempt",
	"auth_last_auth",
	"remote_ip",
	"cap_ld_env",
	"daz_do_scan",
	"vset",
#ifdef __KERNEL__
	/* adf-request helpers */
	"owner",
	"group",
	"signal",
	"mode",
	"nlink",
	"switch_target",
	"mod_name",
	"request",
	"trace_request",
	"auth_add_f_cap",
	"auth_remove_f_cap",
	"auth_get_caplist",
	"prot_bits",
	"internal",
	"create_data",
	"new_object",
	"rlimit",
	"new_dir_dentry_p",
	"program_file",
	"auth_start_uid",
	"auth_start_euid",
	"auth_start_gid",
	"auth_start_egid",
	"acl_learn",
	"priority",
	"pgid",
	"kernel_thread",
	"open_flag",
	"reboot_cmd",
	"setsockopt_level",
	"ioctl_cmd",
	"f_mode",
	"process",
	"sock_type",
	"pagenr",
	"cap_learn",
	"rc_learn",
#endif
	"none"
};

static char target_list[T_NONE + 1][11] = {
	"FILE",
	"DIR",
	"FIFO",
	"SYMLINK",
	"DEV",
	"IPC",
	"SCD",
	"USER",
	"PROCESS",
	"NETDEV",
	"NETTEMP",
	"NETOBJ",
	"NETTEMP_NT",
	"GROUP",
	"FD",
	"UNIXSOCK",
	"NONE"
};

static char ipc_target_list[I_none + 1][9] = {
	"sem",
	"msg",
	"shm",
	"anonpipe",
	"mqueue",
	"anonunix",
	"none"
};

static char switch_target_list[SW_NONE + 1][12] = {
	"GEN",
	"MAC",
	"PM",
	"DAZ",
	"FF",
	"RC",
	"AUTH",
	"REG",
	"ACL",
	"CAP",
	"JAIL",
	"RES",
	"PAX",
	"SOFTMODE",
	"DAC_DISABLE",
	"UM",
	"FREEZE",
	"NONE"
};

static char error_list[RSBAC_EMAX][26] = {
	"RSBAC_EPERM",
	"RSBAC_EACCESS",
	"RSBAC_EREADFAILED",
	"RSBAC_EWRITEFAILED",
	"RSBAC_EINVALIDPOINTER",
	"RSBAC_ENOROOTDIR",
	"RSBAC_EPATHTOOLONG",
	"RSBAC_ENOROOTDEV",
	"RSBAC_ENOTFOUND",
	"RSBAC_ENOTINITIALIZED",
	"RSBAC_EREINIT",
	"RSBAC_ECOULDNOTADDDEVICE",
	"RSBAC_ECOULDNOTADDITEM",
	"RSBAC_ECOULDNOTCREATEPATH",
	"RSBAC_EINVALIDATTR",
	"RSBAC_EINVALIDDEV",
	"RSBAC_EINVALIDTARGET",
	"RSBAC_EINVALIDVALUE",
	"RSBAC_EEXISTS",
	"RSBAC_EINTERNONLY",
	"RSBAC_EINVALIDREQUEST",
	"RSBAC_ENOTWRITABLE",
	"RSBAC_EMALWAREDETECTED",
	"RSBAC_ENOMEM",
	"RSBAC_EDECISIONMISMATCH",
	"RSBAC_EINVALIDVERSION",
	"RSBAC_EINVALIDMODULE",
	"RSBAC_EEXPIRED",
	"RSBAC_EMUSTCHANGE",
	"RSBAC_EBUSY",
	"RSBAC_EINVALIDTRANSACTION",
	"RSBAC_EWEAKPASSWORD",
	"RSBAC_EINVALIDLIST",
	"RSBAC_EFROMINTERRUPT"
};

static char scd_type_list[ST_none + 1][17] = {
	"time_strucs",
	"clock",
	"host_id",
	"net_id",
	"ioports",
	"rlimit",
	"swap",
	"syslog",
	"rsbac",
	"rsbac_log",
	"other",
	"kmem",
	"network",
	"firewall",
	"priority",
	"sysfs",
	"rsbac_remote_log",
	"quota",
	"sysctl",
	"nfsd",
	"ksyms",
	"mlock",
	"capability",
	"kexec",
	"videomem",
	"none"
};

/* Attribute types */

#ifndef __KERNEL__
static char attribute_param_list[A_none + 1][194] = {
	"user-pseudo (positive long integer)", /* pseudo */
	"0 = unclassified, 1 = confidential, 2 = secret,\n\t3 = top secret, 254 = inherit, max. level 252", /* security_level */
	"0 = unclassified, 1 = confidential, 2 = secret,\n\t3 = top secret, 254 = inherit, max. level 252", /* initial_security_level */
	"0 = unclassified, 1 = confidential, 2 = secret,\n\t3 = top secret, 254 = inherit, max. level 252", /* local_sec_level */
	"0 = unclassified, 1 = confidential, 2 = secret,\n\t3 = top secret, 254 = inherit, max. level 252", /* remote_sec_level */
	"0 = unclassified, 1 = confidential, 2 = secret,\n\t3 = top secret, 254 = inherit, max. level 252", /* min_security_level */
	"Bit Set String of length 64 for all categories", /* mac_categories */
	"Bit Set String of length 64 for all categories", /* mac_initial_categories */
	"Bit Set String of length 64 for all categories", /* local_mac_categories */
	"Bit Set String of length 64 for all categories", /* remote_mac_categories */
	"Bit Set String of length 64 for all categories", /* mac_min_categories */
	"1 = override, 4 = trusted, 8 = write_up, 16 = read_up,\n\t32 = write_down, 64 = allow_mac_auto", /* mac_user_flags */
	"1 = override, 2 = auto, 4 = trusted, 8 = write_up,\n\t16 = read_up, 32 = write_down, 128 = prop_trusted", /* mac_process_flags */
	"2 = auto, 4 = trusted, 8 = write_up, 16 = read_up,\n\t32 = write_down", /* mac_file_flags */
	"0 = user, 1 = security officer, 2 = administrator,\n\t3 = auditor", /* system_role */
	"0 = user, 1 = security officer, 2 = administrator,\n\t3 = auditor", /* mac_role */
	"0 = user, 1 = security officer, 2 = administrator,\n\t3 = auditor", /* daz_role */
	"0 = user, 1 = security officer, 2 = administrator,\n\t3 = auditor", /* ff_role */
	"0 = user, 1 = security officer, 2 = administrator,\n\t3 = auditor", /* auth_role */
	"0 = user, 1 = security officer, 2 = administrator,\n\t3 = auditor", /* cap_role */
	"0 = user, 1 = security officer, 2 = administrator,\n\t3 = auditor", /* jail_role */
	"0 = user, 1 = security officer, 2 = administrator,\n\t3 = auditor", /* pax_role */
	"0 = unclassified, 1 = confidential, 2 = secret,\n\t3 = top secret, max. level 252", /* current_sec_level */
	"Bit Set String of length 64 for all categories", /* mac_curr_categories */
	"0 = unclassified, 1 = confidential, 2 = secret,\n\t3 = top secret, max. level 252", /* min_write_open */
	"Bit Set String of length 64 for all categories", /* min_write_categories */
	"0 = unclassified, 1 = confidential, 2 = secret,\n\t3 = top secret, max. level 252", /* max_read_open */
	"Bit Set String of length 64 for all categories", /* max_read_categories */
	"0 = no, 1 = yes, 2 = inherit (default value)", /* mac_auto */
	"0 = false, 1 = true", /* mac_check */
	"0 = false, 1 = true", /* mac_prop_trusted */
	"0 = user, 1 = security officer, 2 = data protection officer,\n\t3 = TP-manager, 4 = system-admin", /* pm_role */
	"0 = none, 1 = TP", /* pm_process_type */
	"Task-ID (positive integer)", /* pm_current_task */
	"Class-ID (positive integer)", /* pm_object_class */
	"Class-ID (positive integer)", /* local_pm_object_class */
	"Class-ID (positive integer)", /* remote_pm_object_class */
	"Purpose-ID (positive integer)", /* pm_ipc_purpose */
	"Purpose-ID (positive integer)", /* local_pm_ipc_purpose */
	"Purpose-ID (positive integer)", /* remote_pm_ipc_purpose */
	"0 = none, 1 = TP, 2 = personal data, 3 = non-personal data,\n\t4 = ipc, 5 = dir", /* pm_object_type */
	"0 = none, 1 = TP, 2 = personal data, 3 = non-personal data,\n\t4 = ipc, 5 = dir", /* local_pm_object_type */
	"0 = none, 1 = TP, 2 = personal data, 3 = non-personal data,\n\t4 = ipc, 5 = dir", /* remote_pm_object_type */
	"0 = none, 1 = TP", /* pm_program_type */
	"TP-ID (positive integer)", /* pm_tp */
	"pm-task-list-ID (positive integer)", /* pm_task_set */
	"0 = unscanned, 1 = infected, 2 = clean", /* daz_scanned */
	"0 = FALSE, 1 = TRUE", /* daz_scanner */
	"1 = read_only, 2 = execute_only, 4 = search_only, 8 = write_only,\n\t16 = secure_delete, 32 = no_execute, 64 = no_delete_or_rename,\n\t128 = add_inherited (or'd), 256 = append_only, 512 = no_mount", /* ff_flags */
	"RC-type-id", /* rc_type */
        "RC-type-id (-7 = use fd)", /* rc_select_type */
	"RC-type-id", /* local_rc_type */
	"RC-type-id", /* remote_rc_type */
	"RC-type-id (-2 = inherit from parent)", /* rc_type_fd */
	"RC-type-id", /* rc_type_nt */
	"RC-role-id (-1 = inherit_user, -2 = inherit_process (keep),\n\t-3 = inherit_parent (def.),\n\t-4 = inherit_user_on_chown_only (root default)", /* rc_force_role */
	"RC-role-id (-3 = inherit_parent (default),\n\t-5 = use_force_role (root default)", /* rc_initial_role */
	"RC-role-id", /* rc_role */
	"RC-role-id", /* rc_def_role */
	"0 = off, 1 = full, 2 = last_auth_only, 3 = last_auth_and_gid", /* auth_may_setuid */
	"0 = false, 1 = true", /* auth_may_set_cap */
	"0 = false, 1 = true", /* auth_learn */
	"Bit-Vector value or name list of desired caps", /* min_caps */
	"Bit-Vector value or name list of desired caps", /* max_caps */
	"Bit-Vector value or name list of desired caps", /* max_caps_user */
	"Bit-Vector value or name list of desired caps", /* max_caps_program */
	"JAIL ID (0 = off)", /* jail_id */
	"JAIL ID (0 = no parent jail)", /* jail_parent */
	"JAIL IP address a.b.c.d", /* jail_ip */
	"JAIL flags (or'd, 1 = allow external IPC, 2 = allow all net families,\n\t4 = allow_rlimit, 8 = allow raw IP, 16 = auto adjust IP,\n\t32 = allow localhost, 64 = allow scd clock)", /* jail_flags */
	"Bit-Vector value or name list of desired caps", /* jail_max_caps */
	"List of SCD targets", /* jail_scd_get */
	"List of SCD targets", /* jail_scd_modify */
	"PAX flags with capital=on, non-capital=off, e.g. PeMRxS", /* pax_flags */
	"0 = user, 1 = security officer, 2 = administrator", /* res_role */
	"array of non-negative integer values, all 0 for unset", /* res_min */
	"array of non-negative integer values, all 0 for unset", /* res_max */
	"Bit-String for all Requests, low bit", /* log_array_low */
	"Bit-String for all Requests, low bit", /* local_log_array_low */
	"Bit-String for all Requests, low bit", /* remote_log_array_low */
	"Bit-String for all Requests, high bit (l=0,h=0 = none, l=1,h=0 = denied,\n\tl=0,h=1 = full, l=1,h=1 = request based)", /* log_array_high */
	"Bit-String for all Requests, high bit (l=0,h=0 = none, l=1,h=0 = denied,\n\tl=0,h=1 = full, l=1,h=1 = request based)", /* local_log_array_high */
	"Bit-String for all Requests, high bit (l=0,h=0 = none, l=1,h=0 = denied,\n\tl=0,h=1 = full, l=1,h=1 = request based)", /* remote_log_array_high */
	"Bit-String for all Requests", /* log_program_based */
	"Bit-String for all Requests", /* log_user_based */
	"Number of bytes to add, 0 to turn off", /* symlink_add_remote_ip */
	"0 = false, 1 = true", /* symlink_add_uid */
	"0 = false, 1 = true", /* symlink_add_mac_level */
	"0 = false, 1 = true", /* symlink_add_rc_role */
	"0 = false, 1 = true, 2 = inherit (default)", /* linux_dac_disable */
	"0 = off (default), 1 = from other users, 2 = full", /* cap_process_hiding */
	"0 = off (default), 1 = uid_only, 2 = euid_only, 3 = both", /* fake_root_uid */
	"-3 = unset, uid otherwise", /* audit_uid */
	"-3 = unset, uid otherwise", /* auid_exempt */
	"-3 = unset, uid otherwise", /* auth_last_auth */
	"32 Bit value in network byte order", /* remote_ip */
	"0 = disallow executing of program file with LD_ variables set,\n\t1 = do not care (default)", /* cap_ld_env */
	"0 = never, 1 = registered, 2 = always, 3 = inherit", /* daz_do_scan */
	"non-negative virtual set number, 0 = default main set",
	"INVALID!"
};
#endif

static char log_level_list[LL_invalid + 1][9] = {
	"none",
	"denied",
	"full",
	"request",
	"invalid!"
};

static char cap_list[RSBAC_CAP_MAX + 1][17] = {
	"CHOWN",
	"DAC_OVERRIDE",
	"DAC_READ_SEARCH",
	"FOWNER",
	"FSETID",
	"KILL",
	"SETGID",
	"SETUID",
	"SETPCAP",
	"LINUX_IMMUTABLE",
	"NET_BIND_SERVICE",
	"NET_BROADCAST",
	"NET_ADMIN",
	"NET_RAW",
	"IPC_LOCK",
	"IPC_OWNER",
	"SYS_MODULE",
	"SYS_RAWIO",
	"SYS_CHROOT",
	"SYS_PTRACE",
	"SYS_PACCT",
	"SYS_ADMIN",
	"SYS_BOOT",
	"SYS_NICE",
	"SYS_RESOURCE",
	"SYS_TIME",
	"SYS_TTY_CONFIG",
	"MKNOD",
	"LEASE",
	"AUDIT_WRITE",
	"AUDIT_CONTROL",
	"SETFCAP",
	"MAC_OVERRIDE",
	"MAC_ADMIN",
	"NONE"
};

#ifdef CONFIG_RSBAC_XSTATS
static char syscall_list[RSYS_none + 1][30] = {
    "version",
    "stats",
    "check",
    "get_attr",
    "get_attr_n",
    "set_attr",
    "set_attr_n",
    "remove_target",
    "remove_target_n",
    "net_list_all_netdev",
    "net_template",
    "net_list_all_template",
    "switch",
    "get_switch",
    "adf_log_switch",
    "get_adf_log",
    "write",
    "log",
    "mac_set_curr_level",
    "mac_get_curr_level",
    "mac_get_max_level",
    "mac_get_min_level",
    "mac_add_p_tru",
    "mac_remove_p_tru",
    "mac_add_f_tru",
    "mac_remove_f_tru",
    "mac_get_f_trulist",
    "mac_get_p_trulist",
    "stats_pm",
    "pm",
    "pm_change_current_task",
    "pm_create_file",
    "daz_flush_cache",
    "rc_copy_role",
    "rc_copy_type",
    "rc_get_item",
    "rc_set_item",
    "rc_change_role",
    "rc_get_eff_rights_n",
    "rc_get_list",
    "auth_add_p_cap",
    "auth_remove_p_cap",
    "auth_add_f_cap",
    "auth_remove_f_cap",
    "auth_get_f_caplist",
    "auth_get_p_caplist",
    "acl",
    "acl_n",
    "acl_get_rights",
    "acl_get_rights_n",
    "acl_get_tlist",
    "acl_get_tlist_n",
    "acl_get_mask",
    "acl_get_mask_n",
    "acl_group",
    "reg",
    "jail",
    "init",
    "rc_get_current_role",
    "um_auth_name",
    "um_auth_uid",
    "um_add_user",
    "um_add_group",
    "um_add_gm",
    "um_mod_user",
    "um_mod_group",
    "um_get_user_item",
    "um_get_group_item",
    "um_remove_user",
    "um_remove_group",
    "um_remove_gm",
    "um_user_exists",
    "um_group_exists",
    "um_get_next_user",
    "um_get_user_list",
    "um_get_gm_list",
    "um_get_gm_user_list",
    "um_get_group_list",
    "um_get_uid",
    "um_get_gid",
    "um_set_pass",
    "um_set_pass_name",
    "um_set_group_pass",
    "um_check_account",
    "um_check_account_name",
    "list_ta_begin",
    "list_ta_refresh",
    "list_ta_commit",
    "list_ta_forget",
    "list_all_dev",
    "acl_list_all_dev",
    "list_all_user",
    "acl_list_all_user",
    "list_all_group",
    "acl_list_all_group",
    "list_all_ipc",
    "rc_select_fd_create_type",
    "um_select_vset",
    "um_add_onetime",
    "um_add_onetime_name",
    "um_remove_all_onetime",
    "um_remove_all_onetime_name",
    "um_count_onetime",
    "um_count_onetime_name",
    "list_ta_begin_name",
    "um_get_max_history",
    "um_get_max_history_name",
    "um_set_max_history",
    "um_set_max_history_name",
    "none"
};

char *get_syscall_name(char *syscall_name,
		       enum rsbac_syscall_t syscall)
{
	if (!syscall_name)
		return (NULL);
	if (syscall >= RSYS_none)
		strcpy(syscall_name, "ERROR!");
	else
		strcpy(syscall_name, syscall_list[syscall]);
	return (syscall_name);
}
#endif

/*****************************************/

#ifdef __KERNEL__
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(get_request_name);
#endif
#endif

char *get_request_name(char *request_name,
		       enum rsbac_adf_request_t request)
{
	if (!request_name)
		return (NULL);
	if (request >= R_NONE)
		strcpy(request_name, "ERROR!");
	else
		strcpy(request_name, request_list[request]);
	return (request_name);
}

enum rsbac_adf_request_t get_request_nr(const char *request_name)
{
	enum rsbac_adf_request_t i;

	if (!request_name)
		return (R_NONE);
	for (i = 0; i < R_NONE; i++) {
		if (!strcmp(request_name, request_list[i])) {
			return (i);
		}
	}
	return (R_NONE);
}


char *get_result_name(char *res_name, enum rsbac_adf_req_ret_t res)
{
	if (!res_name)
		return (NULL);
	if (res > UNDEFINED)
		strcpy(res_name, "ERROR!");
	else
		strcpy(res_name, result_list[res]);
	return (res_name);
}

enum rsbac_adf_req_ret_t get_result_nr(const char *res_name)
{
	enum rsbac_adf_req_ret_t i;

	if (!res_name)
		return (UNDEFINED);
	for (i = 0; i < UNDEFINED; i++) {
		if (!strcmp(res_name, result_list[i])) {
			return (i);
		}
	}
	return (UNDEFINED);
}


enum rsbac_switch_target_t get_attr_module(enum rsbac_attribute_t attr)
{
	if (attr > A_none)
		return SW_NONE;
	else
		return attr_mod_list[attr];
}

#ifdef __KERNEL__
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(get_attribute_name);
#endif
#endif

char *get_attribute_name(char *attr_name, enum rsbac_attribute_t attr)
{
	if (!attr_name)
		return (NULL);
	if (attr > A_none)
		strcpy(attr_name, "ERROR!");
	else
		strcpy(attr_name, attribute_list[attr]);
	return (attr_name);
}

enum rsbac_attribute_t get_attribute_nr(const char *attr_name)
{
	enum rsbac_attribute_t i;

	if (!attr_name)
		return (A_none);
	for (i = 0; i < A_none; i++) {
		if (!strcmp(attr_name, attribute_list[i])) {
			return (i);
		}
	}
	return (A_none);
}

#ifdef __KERNEL__
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(get_attribute_value_name);
#endif
#endif

char *get_attribute_value_name(char *attr_val_name,
			       enum rsbac_attribute_t attr,
			       union rsbac_attribute_value_t *attr_val_p)
{
	if (!attr_val_name)
		return (NULL);
	if (attr > A_none)
		strcpy(attr_val_name, "ERROR!");
	else
		switch (attr) {
		case A_none:
			strcpy(attr_val_name, "none");
			break;
#ifdef __KERNEL__
		case A_create_data:
			{
				char *tmp =
				    rsbac_kmalloc(RSBAC_MAXNAMELEN);

				if (tmp) {
					if (attr_val_p->create_data.
					    dentry_p)
						snprintf(attr_val_name,
							 RSBAC_MAXNAMELEN -
							 1,
							 "%s %s, mode %o",
							 get_target_name_only
							 (tmp,
							  attr_val_p->
							  create_data.
							  target),
							 attr_val_p->
							 create_data.
							 dentry_p->d_name.
							 name,
							 attr_val_p->
							 create_data.
							 mode & S_IALLUGO);
					else
						snprintf(attr_val_name,
							 RSBAC_MAXNAMELEN -
							 1, "%s, mode %o",
							 get_target_name_only
							 (tmp,
							  attr_val_p->
							  create_data.
							  target),
							 attr_val_p->
							 create_data.
							 mode & S_IALLUGO);
					rsbac_kfree(tmp);
				}
			}
			break;
		case A_mode:
			sprintf(attr_val_name, "%o", attr_val_p->mode);
			break;
		case A_rlimit:
			sprintf(attr_val_name, "%u:%lu:%lu",
			        attr_val_p->rlimit.resource,
			        attr_val_p->rlimit.limit.rlim_cur,
			        attr_val_p->rlimit.limit.rlim_max);
			break;
#ifdef CONFIG_RSBAC_UM_VIRTUAL
		case A_owner:
			if(RSBAC_UID_SET(attr_val_p->owner))
				sprintf(attr_val_name, "%u/%u",
					RSBAC_UID_SET(attr_val_p->owner),
					RSBAC_UID_NUM(attr_val_p->owner));
			else
				sprintf(attr_val_name, "%u",
					RSBAC_UID_NUM(attr_val_p->owner));
			break;
		case A_group:
			if(RSBAC_GID_SET(attr_val_p->group))
				sprintf(attr_val_name, "%u/%u",
					RSBAC_GID_SET(attr_val_p->group),
					RSBAC_GID_NUM(attr_val_p->group));
			else
				sprintf(attr_val_name, "%u",
					RSBAC_GID_NUM(attr_val_p->group));
			break;
#endif
		case A_priority:
			sprintf(attr_val_name, "%i", attr_val_p->priority);
			break;
		case A_process:
		case A_pgid:
			{
				struct task_struct *task_p;

				read_lock(&tasklist_lock);
				task_p = pid_task(attr_val_p->process, PIDTYPE_PID);
				if (task_p) {
					if(task_p->parent)
						sprintf(attr_val_name, "%u(%s,parent=%u(%s))", task_p->pid, task_p->comm, task_p->parent->pid, task_p->parent->comm);
					else
						sprintf(attr_val_name, "%u(%s)", task_p->pid, task_p->comm);
				}
				else
					sprintf(attr_val_name, "%u", pid_nr(attr_val_p->process));
				read_unlock(&tasklist_lock);
			}
			break;
		case A_mod_name:
			if (attr_val_p->mod_name)
				strncpy(attr_val_name,
					attr_val_p->mod_name,
					RSBAC_MAXNAMELEN - 1);
			else
				strcpy(attr_val_name, "unknown");
			attr_val_name[RSBAC_MAXNAMELEN - 1] = 0;
			break;
		case A_auth_add_f_cap:
		case A_auth_remove_f_cap:
#ifdef CONFIG_RSBAC_UM_VIRTUAL
			if(   RSBAC_UID_SET(attr_val_p->auth_cap_range.first)
			   || RSBAC_UID_SET(attr_val_p->auth_cap_range.last)
			  )
			  sprintf(attr_val_name, "%u/%u:%u/%u",
				RSBAC_UID_SET(attr_val_p->auth_cap_range.first),
				RSBAC_UID_NUM(attr_val_p->auth_cap_range.first),
				RSBAC_UID_SET(attr_val_p->auth_cap_range.last),
				RSBAC_UID_NUM(attr_val_p->auth_cap_range.last));
			else
#endif
			sprintf(attr_val_name, "%u:%u",
				RSBAC_UID_NUM(attr_val_p->auth_cap_range.first),
				RSBAC_UID_NUM(attr_val_p->auth_cap_range.last));
			break;
		case A_switch_target:
			get_switch_target_name(attr_val_name,
					       attr_val_p->switch_target);
			break;
		case A_request:
			get_request_name(attr_val_name,
					 attr_val_p->request);
			break;
		case A_sock_type:
			rsbac_get_net_type_name(attr_val_name,
					attr_val_p->sock_type);
			break;
#endif
#if defined(CONFIG_RSBAC_PAX) || !defined(__KERNEL__)
		case A_pax_flags:
			pax_print_flags(attr_val_name,
					attr_val_p->pax_flags);
			break;
#endif
#if defined(CONFIG_RSBAC_AUTH) || !defined(__KERNEL__)
		case A_auth_last_auth:
#if defined(CONFIG_RSBAC_AUTH_LEARN) && defined(__KERNEL__)
		case A_auth_start_uid:
		case A_auth_start_euid:
#endif
#ifdef CONFIG_RSBAC_UM_VIRTUAL
			if(RSBAC_UID_SET(attr_val_p->auth_last_auth))
			  sprintf(attr_val_name, "%u/%u",
				RSBAC_UID_SET(attr_val_p->auth_last_auth),
				RSBAC_UID_NUM(attr_val_p->auth_last_auth));
			else
#endif
			sprintf(attr_val_name, "%u",
				RSBAC_UID_NUM(attr_val_p->auth_last_auth));
			break;
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
		case A_auth_start_gid:
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
		case A_auth_start_egid:
#endif
#ifdef CONFIG_RSBAC_UM_VIRTUAL
			if(RSBAC_GID_SET(attr_val_p->auth_last_auth))
			  sprintf(attr_val_name, "%u/%u",
				RSBAC_GID_SET(attr_val_p->auth_last_auth),
				RSBAC_GID_NUM(attr_val_p->auth_last_auth));
			else
#endif
			sprintf(attr_val_name, "%u",
				RSBAC_GID_NUM(attr_val_p->auth_start_gid));
			break;
#endif
		default:
			snprintf(attr_val_name, RSBAC_MAXNAMELEN - 1, "%u",
				 attr_val_p->u_dummy);
		}
	return (attr_val_name);
}


#ifdef __KERNEL__
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(get_scd_type_name);
#endif
#endif

char *get_scd_type_name(char *res_name, enum rsbac_scd_type_t res)
{
	if (!res_name)
		return (NULL);
	if (res > ST_none)
		strcpy(res_name, "ERROR!");
	else
		strcpy(res_name, scd_type_list[res]);
	return (res_name);
}

enum rsbac_scd_type_t get_scd_type_nr(const char *res_name)
{
	enum rsbac_scd_type_t i;

	if (!res_name)
		return (ST_none);
	for (i = 0; i < ST_none; i++) {
		if (!strcmp(res_name, scd_type_list[i])) {
			return (i);
		}
	}
	return (ST_none);
}


#ifdef __KERNEL__
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(get_target_name);
#endif
#endif

char *get_target_name(char *target_type_name,
		      enum rsbac_target_t target,
		      char *target_id_name, union rsbac_target_id_t tid)
{
#ifdef __KERNEL__
	char *help_name;
#else
	char help_name[RSBAC_MAXNAMELEN + 4];
#endif

#ifdef __KERNEL__
#ifdef CONFIG_RSBAC_LOG_FULL_PATH
	help_name = rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN + 4);
#else
	help_name = rsbac_kmalloc(RSBAC_MAXNAMELEN + 4);
#endif
	if (!help_name)
		return NULL;
#endif

	switch (target) {
#ifdef __KERNEL__
	case T_FD:
		if(target_type_name)
			strcpy(target_type_name, "FD");
		if (!target_id_name)
			break;
		sprintf(target_id_name, "Device %02u:%02u Inode %u",
			RSBAC_MAJOR(tid.file.device),
			RSBAC_MINOR(tid.file.device), tid.file.inode);
		if (tid.file.dentry_p && tid.file.dentry_p->d_name.name
		    && tid.file.dentry_p->d_name.len) {
#ifdef CONFIG_RSBAC_LOG_FULL_PATH
			if (rsbac_get_full_path
			    (tid.file.dentry_p, help_name,
			     CONFIG_RSBAC_MAX_PATH_LEN) > 0) {
				strcat(target_id_name, " Path ");
				strcat(target_id_name, help_name);
			}
#else
			int namelen =
			    rsbac_min(tid.file.dentry_p->d_name.len,
				      RSBAC_MAXNAMELEN);

			strcat(target_id_name, " Name ");
			strncpy(help_name, tid.file.dentry_p->d_name.name,
				namelen);
			help_name[namelen] = 0;
			strcat(target_id_name, help_name);
#endif
		}
		break;
	case T_FILE:
		if(target_type_name)
			strcpy(target_type_name, "FILE");
		if (!target_id_name)
			break;
		sprintf(target_id_name, "Device %02u:%02u Inode %u",
			RSBAC_MAJOR(tid.file.device),
			RSBAC_MINOR(tid.file.device), tid.file.inode);
		if (tid.file.dentry_p && tid.file.dentry_p->d_name.name
		    && tid.file.dentry_p->d_name.len) {
#ifdef CONFIG_RSBAC_LOG_FULL_PATH
			if (rsbac_get_full_path
			    (tid.file.dentry_p, help_name,
			     CONFIG_RSBAC_MAX_PATH_LEN) > 0) {
				strcat(target_id_name, " Path ");
				strcat(target_id_name, help_name);
			}
#else
			int namelen =
			    rsbac_min(tid.file.dentry_p->d_name.len,
				      RSBAC_MAXNAMELEN);

			strcat(target_id_name, " Name ");
			strncpy(help_name, tid.file.dentry_p->d_name.name,
				namelen);
			help_name[namelen] = 0;
			strcat(target_id_name, help_name);
#endif
		}
		break;
	case T_DIR:
		if(target_type_name)
			strcpy(target_type_name, "DIR");
		if (!target_id_name)
			break;
		sprintf(target_id_name, "Device %02u:%02u Inode %u",
			RSBAC_MAJOR(tid.file.device),
			RSBAC_MINOR(tid.file.device), tid.dir.inode);
		if (tid.dir.dentry_p && tid.dir.dentry_p->d_name.name
		    && tid.dir.dentry_p->d_name.len) {
#ifdef CONFIG_RSBAC_LOG_FULL_PATH
			if (rsbac_get_full_path
			    (tid.dir.dentry_p, help_name,
			     CONFIG_RSBAC_MAX_PATH_LEN) > 0) {
				strcat(target_id_name, " Path ");
				strcat(target_id_name, help_name);
			}
#else
			int namelen =
			    rsbac_min(tid.dir.dentry_p->d_name.len,
				      RSBAC_MAXNAMELEN);

			strcat(target_id_name, " Name ");
			strncpy(help_name, tid.dir.dentry_p->d_name.name,
				namelen);
			help_name[namelen] = 0;
			strcat(target_id_name, help_name);
#endif
		}
		break;
	case T_FIFO:
		if(target_type_name)
			strcpy(target_type_name, "FIFO");
		if (!target_id_name)
			break;
		sprintf(target_id_name, "Device %02u:%02u Inode %u",
			RSBAC_MAJOR(tid.file.device),
			RSBAC_MINOR(tid.file.device), tid.fifo.inode);
		if (tid.fifo.dentry_p && tid.fifo.dentry_p->d_name.name
		    && tid.fifo.dentry_p->d_name.len) {
#ifdef CONFIG_RSBAC_LOG_FULL_PATH
			if (rsbac_get_full_path
			    (tid.fifo.dentry_p, help_name,
			     CONFIG_RSBAC_MAX_PATH_LEN) > 0) {
				strcat(target_id_name, " Path ");
				strcat(target_id_name, help_name);
			}
#else
			int namelen =
			    rsbac_min(tid.fifo.dentry_p->d_name.len,
				      RSBAC_MAXNAMELEN);

			strcat(target_id_name, " Name ");
			strncpy(help_name, tid.fifo.dentry_p->d_name.name,
				namelen);
			help_name[namelen] = 0;
			strcat(target_id_name, help_name);
#endif
		}
		break;
	case T_SYMLINK:
		if(target_type_name)
			strcpy(target_type_name, "SYMLINK");
		if (!target_id_name)
			break;
		sprintf(target_id_name, "Device %02u:%02u Inode %u",
			RSBAC_MAJOR(tid.symlink.device),
			RSBAC_MINOR(tid.symlink.device), tid.symlink.inode);
		if (tid.symlink.dentry_p
		    && tid.symlink.dentry_p->d_name.name
		    && tid.symlink.dentry_p->d_name.len) {
#ifdef CONFIG_RSBAC_LOG_FULL_PATH
			if (rsbac_get_full_path
			    (tid.symlink.dentry_p, help_name,
			     CONFIG_RSBAC_MAX_PATH_LEN) > 0) {
				strcat(target_id_name, " Path ");
				strcat(target_id_name, help_name);
			}
#else
			int namelen =
			    rsbac_min(tid.symlink.dentry_p->d_name.len,
				      RSBAC_MAXNAMELEN);

			strcat(target_id_name, " Name ");
			strncpy(help_name,
				tid.symlink.dentry_p->d_name.name,
				namelen);
			help_name[namelen] = 0;
			strcat(target_id_name, help_name);
#endif
		}
		break;
	case T_UNIXSOCK:
		if(target_type_name)
			strcpy(target_type_name, "UNIXSOCK");
		if (!target_id_name)
			break;
		sprintf(target_id_name, "Device %02u:%02u Inode %u",
			RSBAC_MAJOR(tid.unixsock.device),
			RSBAC_MINOR(tid.unixsock.device), tid.unixsock.inode);
		if (tid.symlink.dentry_p
		    && tid.unixsock.dentry_p->d_name.name
		    && tid.unixsock.dentry_p->d_name.len) {
#ifdef CONFIG_RSBAC_LOG_FULL_PATH
			if (rsbac_get_full_path
			    (tid.unixsock.dentry_p, help_name,
			     CONFIG_RSBAC_MAX_PATH_LEN) > 0) {
				strcat(target_id_name, " Path ");
				strcat(target_id_name, help_name);
			}
#else
			int namelen =
			    rsbac_min(tid.unixsock.dentry_p->d_name.len,
				      RSBAC_MAXNAMELEN);

			strcat(target_id_name, " Name ");
			strncpy(help_name,
				tid.unixsock.dentry_p->d_name.name,
				namelen);
			help_name[namelen] = 0;
			strcat(target_id_name, help_name);
#endif
		}
		break;
	case T_DEV:
		if(target_type_name)
			strcpy(target_type_name, "DEV");
		if (!target_id_name)
			break;
		switch (tid.dev.type) {
		case D_block:
			sprintf(target_id_name, "block %02u:%02u",
				tid.dev.major, tid.dev.minor);
			break;
		case D_char:
			sprintf(target_id_name, "char %02u:%02u",
				tid.dev.major, tid.dev.minor);
			break;
		case D_block_major:
			sprintf(target_id_name, "block major %02u",
				tid.dev.major);
			break;
		case D_char_major:
			sprintf(target_id_name, "char major %02u",
				tid.dev.major);
			break;
		default:
			sprintf(target_id_name, "*unknown* %02u:%02u",
				tid.dev.major, tid.dev.minor);
		}
		break;
	case T_NETOBJ:
		if(target_type_name)
			strcpy(target_type_name, "NETOBJ");
		if (!target_id_name)
			break;
#ifdef CONFIG_NET
		if (tid.netobj.sock_p
		    && tid.netobj.sock_p->ops && tid.netobj.sock_p->sk) {
			char type_name[RSBAC_MAXNAMELEN];

			switch (tid.netobj.sock_p->ops->family) {
			case AF_INET:
				{
					__u32 saddr;
					__u16 sport;
					__u32 daddr;
					__u16 dport;
					struct net_device *dev;
					char ldevname[RSBAC_IFNAMSIZ + 10];
					char rdevname[RSBAC_IFNAMSIZ + 10];

					if (tid.netobj.local_addr) {
						struct sockaddr_in *addr =
						    tid.netobj.local_addr;

						saddr =
						    addr->sin_addr.s_addr;
						sport =
						    ntohs(addr->sin_port);
					} else {
						saddr =
						    inet_sk(tid.netobj.
							    sock_p->sk)->
						    inet_saddr;
						sport =
						    inet_sk(tid.netobj.
							    sock_p->sk)->
						    inet_num;
					}
					if (tid.netobj.remote_addr) {
						struct sockaddr_in *addr =
						    tid.netobj.remote_addr;

						daddr =
						    addr->sin_addr.s_addr;
						dport =
						    ntohs(addr->sin_port);
					} else {
						daddr =
						    inet_sk(tid.netobj.
							    sock_p->sk)->
						    inet_daddr;
						dport =
						    ntohs(inet_sk
							  (tid.netobj.
							   sock_p->sk)->
							  inet_dport);
					}
					dev = ip_dev_find(&init_net, saddr);

					if (dev) {
						sprintf(ldevname, "%s:",
							dev->name);
						dev_put(dev);
					} else
						ldevname[0] = 0;
					dev = ip_dev_find(&init_net, daddr);
					if (dev) {
						sprintf(rdevname, "%s:",
							dev->name);
						dev_put(dev);
					} else
						rdevname[0] = 0;
					sprintf(target_id_name,
						"%p INET %s proto %s local %s%u.%u.%u.%u:%u remote %s%u.%u.%u.%u:%u",
						tid.netobj.sock_p,
						rsbac_get_net_type_name
						(type_name,
						 tid.netobj.sock_p->type),
						rsbac_get_net_protocol_name
						(help_name,
						 tid.netobj.sock_p->sk->
						 sk_protocol),
						ldevname,
						NIPQUAD(saddr),
						sport,
						rdevname,
						NIPQUAD(daddr), dport);
				}
				break;
			case AF_NETLINK:
				if (tid.netobj.local_addr || tid.netobj.remote_addr) {
					struct sockaddr_nl *addr;

					if(tid.netobj.local_addr)
						addr = tid.netobj.local_addr;
					else
						addr = tid.netobj.remote_addr;

					sprintf(target_id_name,
						"%p NETLINK %s %s %u",
						tid.netobj.sock_p,
						rsbac_get_net_type_name
						(type_name,
						 tid.netobj.sock_p->type),
						rsbac_get_net_netlink_family_name(
							help_name,
							tid.netobj.sock_p->sk->sk_protocol),
						addr->nl_pid);
				} else {
					sprintf(target_id_name,
						"%p NETLINK %s %s",
						tid.netobj.sock_p,
						rsbac_get_net_type_name
						(type_name,
						 tid.netobj.sock_p->type),
						rsbac_get_net_netlink_family_name(
							help_name,
							tid.netobj.sock_p->sk->sk_protocol));
				}
				break;
			default:
				sprintf(target_id_name, "%p %s %s",
					tid.netobj.sock_p,
					rsbac_get_net_family_name
					(help_name,
					 tid.netobj.sock_p->ops->family),
					rsbac_get_net_type_name(type_name,
								tid.netobj.
								sock_p->
								type));
			}
		} else
#endif				/* CONFIG_NET */
		{
			sprintf(target_id_name, "%p", tid.netobj.sock_p);
		}
		break;
#endif				/* __KERNEL__ */
	case T_IPC:
		if(target_type_name)
			strcpy(target_type_name, "IPC");
		if (!target_id_name)
			break;
		switch (tid.ipc.type) {
		case I_sem:
			strcpy(target_id_name, "Sem-ID ");
			break;
		case I_msg:
			strcpy(target_id_name, "Msg-ID ");
			break;
		case I_shm:
			strcpy(target_id_name, "Shm-ID ");
			break;
		case I_anonpipe:
			strcpy(target_id_name, "AnonPipe-ID ");
			break;
		case I_mqueue:
			strcpy(target_id_name, "Mqueue-ID ");
			break;
		case I_anonunix:
			strcpy(target_id_name, "AnonUnix-ID ");
			break;
		default:
			strcpy(target_id_name, "ID ");
			break;
		};
		sprintf(help_name, "%lu", tid.ipc.id.id_nr);
		strcat(target_id_name, help_name);
		break;
	case T_SCD:
		if(target_type_name)
			strcpy(target_type_name, "SCD");
		if (target_id_name)
			get_scd_type_name(target_id_name, tid.scd);
		break;
	case T_USER:
		if(target_type_name)
			strcpy(target_type_name, "USER");
		if (target_id_name) {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
			if(RSBAC_UID_SET(tid.user))
			  sprintf(target_id_name, "%u/%u",
				RSBAC_UID_SET(tid.user),
				RSBAC_UID_NUM(tid.user));
			else
#endif
			sprintf(target_id_name, "%u", RSBAC_UID_NUM(tid.user));
		}
		break;
	case T_PROCESS:
		if(target_type_name)
			strcpy(target_type_name, "PROCESS");
		if (target_id_name) {
			struct task_struct *task_p;

			read_lock(&tasklist_lock);
			task_p = pid_task(tid.process, PIDTYPE_PID);
			if (task_p) {
				if(task_p->parent)
					sprintf(target_id_name, "%u(%s,parent=%u(%s))", task_p->pid, task_p->comm, task_p->parent->pid, task_p->parent->comm);
				else
					sprintf(target_id_name, "%u(%s)", task_p->pid, task_p->comm);
			}
			else
				sprintf(target_id_name, "%u", pid_nr(tid.process));
			read_unlock(&tasklist_lock);
		}
		break;
	case T_GROUP:
		if(target_type_name)
			strcpy(target_type_name, "GROUP");
		if (target_id_name) {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
			if(RSBAC_GID_SET(tid.group))
			  sprintf(target_id_name, "%u/%u",
				RSBAC_GID_SET(tid.group),
				RSBAC_GID_NUM(tid.group));
			else
#endif
			sprintf(target_id_name, "%u", RSBAC_GID_NUM(tid.group));
		}
		break;
	case T_NETDEV:
		if(target_type_name)
			strcpy(target_type_name, "NETDEV");
		if (!target_id_name)
			break;
		strncpy(target_id_name, tid.netdev, RSBAC_IFNAMSIZ);
		target_id_name[RSBAC_IFNAMSIZ] = 0;
		break;
	case T_NETTEMP:
		if(target_type_name)
			strcpy(target_type_name, "NETTEMP");
		if (target_id_name)
			sprintf(target_id_name, "%u", tid.nettemp);
		break;
	case T_NETTEMP_NT:
		if(target_type_name)
			strcpy(target_type_name, "NETTEMP_NT");
		if (target_id_name)
			sprintf(target_id_name, "%u", tid.nettemp);
		break;
	case T_NONE:
		if(target_type_name)
			strcpy(target_type_name, "NONE");
		if (target_id_name)
			strcpy(target_id_name, "NONE");
		break;
	default:
		if(target_type_name)
			strcpy(target_type_name, "ERROR!!!");
		if (target_id_name)
			sprintf(target_id_name, "%u", target);
	}
#ifdef __KERNEL__
	rsbac_kfree(help_name);
#endif
	if(target_type_name)
		return target_type_name;
	else
		return target_id_name;
}

char *get_target_name_only(char *target_type_name,
			   enum rsbac_target_t target)
{
	if (!target_type_name)
		return (NULL);

	switch (target) {
	case T_FILE:
		strcpy(target_type_name, "FILE");
		break;
	case T_DIR:
		strcpy(target_type_name, "DIR");
		break;
	case T_FIFO:
		strcpy(target_type_name, "FIFO");
		break;
	case T_SYMLINK:
		strcpy(target_type_name, "SYMLINK");
		break;
	case T_UNIXSOCK:
		strcpy(target_type_name, "UNIXSOCK");
		break;
	case T_FD:
		strcpy(target_type_name, "FD");
		break;
	case T_DEV:
		strcpy(target_type_name, "DEV");
		break;
	case T_NETOBJ:
		strcpy(target_type_name, "NETOBJ");
		break;
	case T_IPC:
		strcpy(target_type_name, "IPC");
		break;
	case T_SCD:
		strcpy(target_type_name, "SCD");
		break;
	case T_USER:
		strcpy(target_type_name, "USER");
		break;
	case T_PROCESS:
		strcpy(target_type_name, "PROCESS");
		break;
	case T_GROUP:
		strcpy(target_type_name, "GROUP");
		break;
	case T_NETDEV:
		strcpy(target_type_name, "NETDEV");
		break;
	case T_NETTEMP:
		strcpy(target_type_name, "NETTEMP");
		break;
	case T_NETTEMP_NT:
		strcpy(target_type_name, "NETTEMP_NT");
		break;
	case T_NONE:
		strcpy(target_type_name, "NONE");
		break;
	default:
		strcpy(target_type_name, "ERROR!!!");
	}
	return (target_type_name);
}

enum rsbac_target_t get_target_nr(const char *target_name)
{
	enum rsbac_target_t i;

	if (!target_name)
		return (T_NONE);
	for (i = 0; i < T_NONE; i++) {
		if (!strcmp(target_name, target_list[i])) {
			return (i);
		}
	}
	return (T_NONE);
}

char *get_ipc_target_name(char *ipc_name, enum rsbac_ipc_type_t target)
{
	if (!ipc_name)
		return (NULL);
	if (target > I_none)
		strcpy(ipc_name, "ERROR!");
	else
		strcpy(ipc_name, ipc_target_list[target]);
	return (ipc_name);
}

enum rsbac_ipc_type_t get_ipc_target_nr(const char *ipc_name)
{
	enum rsbac_ipc_type_t i;

	if (!ipc_name)
		return (I_none);
	for (i = 0; i < I_none; i++) {
		if (!strcmp(ipc_name, ipc_target_list[i])) {
			return (i);
		}
	}
	return (I_none);
}


#ifdef __KERNEL__
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(get_switch_target_name);
#endif
#endif

char *get_switch_target_name(char *switch_name,
			     enum rsbac_switch_target_t target)
{
	if (!switch_name)
		return (NULL);
	if (target > SW_NONE)
		strcpy(switch_name, "ERROR!");
	else
		strcpy(switch_name, switch_target_list[target]);
	return (switch_name);
}

enum rsbac_switch_target_t get_switch_target_nr(const char *switch_name)
{
	enum rsbac_switch_target_t i;

	if (!switch_name)
		return (SW_NONE);
	for (i = 0; i < SW_NONE; i++) {
#ifdef __KERNEL__
		if (!strncmp
		    (switch_name, switch_target_list[i],
		     strlen(switch_target_list[i])))
#else
		if (!strcmp(switch_name, switch_target_list[i]))
#endif
		{
			return (i);
		}
	}
	return (SW_NONE);
}


#ifdef __KERNEL__
#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
EXPORT_SYMBOL(get_error_name);
#endif
#endif

char *get_error_name(char *error_name, int error)
{
	if (!error_name)
		return (NULL);
#ifndef __KERNEL__
	if((error == -1) && RSBAC_ERROR(-errno))
		error = -errno;
#endif
	if (RSBAC_ERROR(error))
		strcpy(error_name, error_list[(-error) - RSBAC_EPERM]);
	else
#ifdef __KERNEL__
		inttostr(error_name, error);
#else
		strcpy(error_name, strerror(errno));
#endif
	return (error_name);
}

#ifndef __KERNEL__
char *get_attribute_param(char *attr_name, enum rsbac_attribute_t attr)
{
	if (!attr_name)
		return (NULL);
	if (attr > A_none)
		strcpy(attr_name, "ERROR!");
	else
		strcpy(attr_name, attribute_param_list[attr]);
	return (attr_name);
}
#endif

char *get_log_level_name(char *ll_name, enum rsbac_log_level_t target)
{
	if (!ll_name)
		return (NULL);
	if (target > LL_invalid)
		strcpy(ll_name, "ERROR!");
	else
		strcpy(ll_name, log_level_list[target]);
	return (ll_name);
}

enum rsbac_log_level_t get_log_level_nr(const char *ll_name)
{
	enum rsbac_log_level_t i;

	if (!ll_name)
		return (LL_invalid);
	for (i = 0; i < LL_invalid; i++) {
		if (!strcmp(ll_name, log_level_list[i])) {
			return (i);
		}
	}
	return (LL_invalid);
}

char *get_cap_name(char *name, u_int value)
{
	if (!name)
		return (NULL);
	if (value > CAP_NONE)
		strcpy(name, "ERROR!");
	else
		strcpy(name, cap_list[value]);
	return (name);
}

int get_cap_nr(const char *name)
{
	int i;

	if (!name)
		return (RT_NONE);
	for (i = 0; i < CAP_NONE; i++) {
		if (!strcmp(name, cap_list[i])) {
			return (i);
		}
	}
	return (CAP_NONE);
}
