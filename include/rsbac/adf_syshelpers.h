/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2005:          */
/*   Amon Ott <ao@rsbac.org>          */
/*                                    */
/* Helper Prototypes for model        */
/* specific system calls              */
/* Last modified: 02/Aug/2005         */
/************************************ */

#ifndef __RSBAC_ADF_SYSHELPERS_H
#define __RSBAC_ADF_SYSHELPERS_H

/* #include <linux/sched.h> */
#include <rsbac/types.h>

/***************************************************/
/*              Global Variables                   */
/***************************************************/

/***************************************************/
/*              General Prototypes                 */
/***************************************************/

/***************************************************/
/*              Module Prototypes                  */
/***************************************************/

/******* MAC ********/

#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_MAC_MAINT)
int  rsbac_mac_set_curr_level(rsbac_security_level_t level,
                              rsbac_mac_category_vector_t categories);

int  rsbac_mac_get_curr_level(rsbac_security_level_t * level_p,
                              rsbac_mac_category_vector_t * categories_p);

int  rsbac_mac_get_max_level(rsbac_security_level_t * level_p,
                             rsbac_mac_category_vector_t * categories_p);

int  rsbac_mac_get_min_level(rsbac_security_level_t * level_p,
                             rsbac_mac_category_vector_t * categories_p);

int rsbac_mac_add_p_tru(
  rsbac_list_ta_number_t ta_number,
  rsbac_pid_t pid,
  rsbac_uid_t uid,
  rsbac_time_t ttl);

int rsbac_mac_remove_p_tru(
  rsbac_list_ta_number_t ta_number,
  rsbac_pid_t pid,
  rsbac_uid_t uid);

int rsbac_mac_add_f_tru(
  rsbac_list_ta_number_t ta_number,
  rsbac_mac_file_t file,
  rsbac_uid_t uid,
  rsbac_time_t ttl);

int rsbac_mac_remove_f_tru(
  rsbac_list_ta_number_t ta_number,
  rsbac_mac_file_t file,
  rsbac_uid_t uid);

#endif  /* MAC */


/******* PM ********/

#if defined(CONFIG_RSBAC_PM) || defined(CONFIG_RSBAC_PM_MAINT)
/* This function is called via sys_rsbac_pm() system call                    */
/* and serves as a dispatcher for all PM dependant system calls.             */

int rsbac_pm(
        rsbac_list_ta_number_t ta_number,
  enum  rsbac_pm_function_type_t,
  union rsbac_pm_function_param_t,
        rsbac_pm_tkt_id_t);

int rsbac_pm_change_current_task(rsbac_pm_task_id_t);

int rsbac_pm_create_file(const char *,                /* filename */
                         int,                         /* creation mode */
                         rsbac_pm_object_class_id_t); /* class for file */
#endif  /* PM */

/******* FF ********/

/******* RC ********/

#if defined(CONFIG_RSBAC_RC) || defined(CONFIG_RSBAC_RC_MAINT)
/* These functions in adf/rc/syscalls.c are called via sys_* system calls    */
/* and check for validity before passing the call to the rc_data_structures. */

/* All roles are always there, so instead of creation, we supply a copy for */
/* initialization. There is always the well-defined role general to copy    */
extern int rsbac_rc_sys_copy_role (
  rsbac_list_ta_number_t ta_number,
  rsbac_rc_role_id_t from_role,
  rsbac_rc_role_id_t to_role);

extern int rsbac_rc_sys_copy_type (
        rsbac_list_ta_number_t ta_number,
  enum  rsbac_rc_target_t      target,
        rsbac_rc_type_id_t     from_type,
        rsbac_rc_type_id_t     to_type);

/* Getting item values */
extern int rsbac_rc_sys_get_item (
  rsbac_list_ta_number_t ta_number,
  enum  rsbac_rc_target_t       target,
  union rsbac_rc_target_id_t    tid,
  union rsbac_rc_target_id_t    subtid,
  enum  rsbac_rc_item_t         item,
  union rsbac_rc_item_value_t * value_p,
        rsbac_time_t          * ttl_p);

/* Setting item values */
extern int rsbac_rc_sys_set_item (
  rsbac_list_ta_number_t ta_number,
  enum  rsbac_rc_target_t       target,
  union rsbac_rc_target_id_t    tid,
  union rsbac_rc_target_id_t    subtid,
  enum  rsbac_rc_item_t         item,
  union rsbac_rc_item_value_t   value,
        rsbac_time_t            ttl);

/* Set own role, if allowed ( = in role_comp vector of current role) */
extern int rsbac_rc_sys_change_role (rsbac_rc_role_id_t role, char * pass);

/* Getting own effective rights */
int rsbac_rc_sys_get_eff_rights (
  rsbac_list_ta_number_t ta_number,
  enum  rsbac_target_t       target,
  union rsbac_target_id_t    tid,
        rsbac_rc_request_vector_t * request_vector,
        rsbac_time_t          * ttl_p);

int rsbac_rc_sys_get_current_role (rsbac_rc_role_id_t * role_p);

#endif  /* RC || RC_MAINT */

/****** AUTH *******/

#if defined(CONFIG_RSBAC_AUTH) || defined(CONFIG_RSBAC_AUTH_MAINT)
/* This function is called via sys_rsbac_auth_add_p_cap() system call */
int rsbac_auth_add_p_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_pid_t pid,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range,
         rsbac_time_t ttl);

/* This function is called via sys_rsbac_auth_remove_p_cap() system call */
int rsbac_auth_remove_p_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_pid_t pid,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range);

/* This function is called via sys_rsbac_auth_add_f_cap() system call */
int rsbac_auth_add_f_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_auth_file_t file,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range,
         rsbac_time_t ttl);

/* This function is called via sys_rsbac_auth_remove_f_cap() system call */
int rsbac_auth_remove_f_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_auth_file_t file,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range);

#endif  /* AUTH || AUTH_MAINT */

/****** REG *******/

#if defined(CONFIG_RSBAC_REG) || defined(CONFIG_RSBAC_REG_MAINT)
/*
 * System call dispatcher
 * Returns 0 on success or -EINVALIDTARGET, if handle is invalid.
 */

int rsbac_reg_syscall(rsbac_reg_handle_t handle,
                      void * arg);
#endif /* REG || REG_MAINT */

/****** ACL *******/

#if defined(CONFIG_RSBAC_ACL) || defined(CONFIG_RSBAC_ACL_MAINT)
int rsbac_acl_sys_set_acl_entry(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
  enum   rsbac_acl_subject_type_t    subj_type,
         rsbac_acl_subject_id_t      subj_id,
         rsbac_acl_rights_vector_t   rights,
         rsbac_time_t                ttl);

int rsbac_acl_sys_remove_acl_entry(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
  enum   rsbac_acl_subject_type_t    subj_type,
         rsbac_acl_subject_id_t      subj_id);

int rsbac_acl_sys_remove_acl(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid);

int rsbac_acl_sys_add_to_acl_entry(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
  enum   rsbac_acl_subject_type_t    subj_type,
         rsbac_acl_subject_id_t      subj_id,
         rsbac_acl_rights_vector_t   rights,
         rsbac_time_t                ttl);

int rsbac_acl_sys_remove_from_acl_entry(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
  enum   rsbac_acl_subject_type_t    subj_type,
         rsbac_acl_subject_id_t      subj_id,
         rsbac_acl_rights_vector_t   rights);

int rsbac_acl_sys_set_mask(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
         rsbac_acl_rights_vector_t   mask);

int rsbac_acl_sys_remove_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid);

int rsbac_acl_sys_get_mask(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
         rsbac_acl_rights_vector_t * mask_p);


int rsbac_acl_sys_get_rights(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
  enum   rsbac_acl_subject_type_t    subj_type,
         rsbac_acl_subject_id_t      subj_id,
         rsbac_acl_rights_vector_t * rights_p,
         rsbac_boolean_t             inherit);

int rsbac_acl_sys_get_tlist(
         rsbac_list_ta_number_t    ta_number,
  enum   rsbac_target_t            target,
  union  rsbac_target_id_t         tid,
  struct rsbac_acl_entry_t      ** entry_pp,
         rsbac_time_t           ** ttl_pp);

int rsbac_acl_sys_group(
        rsbac_list_ta_number_t         ta_number,
  enum  rsbac_acl_group_syscall_type_t call,
  union rsbac_acl_group_syscall_arg_t  arg);

#endif  /* ACL || ACL_MAINT */

/****** JAIL *******/

#if defined(CONFIG_RSBAC_JAIL)
/* This function is called via sys_rsbac_jail() system call */
int rsbac_jail_sys_jail(rsbac_version_t version,
                        char * path,
                        rsbac_jail_ip_t ip,
                        rsbac_jail_flags_t flags,
                        rsbac_cap_vector_t max_caps,
                        rsbac_jail_scd_vector_t scd_get,
                        rsbac_jail_scd_vector_t scd_modify);
#endif

#endif /* End of adf_syshelpers.h */
