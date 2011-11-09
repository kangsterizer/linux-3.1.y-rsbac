/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2011:           */
/*   Amon Ott <ao@rsbac.org>           */
/* Syscall wrapper functions for all   */
/* parts                               */
/* Last modified: 19/Apr/2011          */
/************************************* */

#ifndef __RSBAC_SYSCALLS_H
#define __RSBAC_SYSCALLS_H

#include <linux/unistd.h>
#include <rsbac/types.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>

enum rsbac_syscall_t
  {
    RSYS_version,
    RSYS_stats,
    RSYS_check,
    RSYS_get_attr,
    RSYS_get_attr_n,
    RSYS_set_attr,
    RSYS_set_attr_n,
    RSYS_remove_target,
    RSYS_remove_target_n,
    RSYS_net_list_all_netdev,
    RSYS_net_template,
    RSYS_net_list_all_template,
    RSYS_switch,
    RSYS_get_switch,
    RSYS_adf_log_switch,
    RSYS_get_adf_log,
    RSYS_write,
    RSYS_log,
    RSYS_mac_set_curr_level,
    RSYS_mac_get_curr_level,
    RSYS_mac_get_max_level,
    RSYS_mac_get_min_level,
    RSYS_mac_add_p_tru,
    RSYS_mac_remove_p_tru,
    RSYS_mac_add_f_tru,
    RSYS_mac_remove_f_tru,
    RSYS_mac_get_f_trulist,
    RSYS_mac_get_p_trulist,
    RSYS_stats_pm,
    RSYS_pm,
    RSYS_pm_change_current_task,
    RSYS_pm_create_file,
    RSYS_daz_flush_cache,
    RSYS_rc_copy_role,
    RSYS_rc_copy_type,
    RSYS_rc_get_item,
    RSYS_rc_set_item,
    RSYS_rc_change_role,
    RSYS_rc_get_eff_rights_n,
    RSYS_rc_get_list,
    RSYS_auth_add_p_cap,
    RSYS_auth_remove_p_cap,
    RSYS_auth_add_f_cap,
    RSYS_auth_remove_f_cap,
    RSYS_auth_get_f_caplist,
    RSYS_auth_get_p_caplist,
    RSYS_acl,
    RSYS_acl_n,
    RSYS_acl_get_rights,
    RSYS_acl_get_rights_n,
    RSYS_acl_get_tlist,
    RSYS_acl_get_tlist_n,
    RSYS_acl_get_mask,
    RSYS_acl_get_mask_n,
    RSYS_acl_group,
    RSYS_reg,
    RSYS_jail,
    RSYS_init,
    RSYS_rc_get_current_role,
    RSYS_um_auth_name,
    RSYS_um_auth_uid,
    RSYS_um_add_user,
    RSYS_um_add_group,
    RSYS_um_add_gm,
    RSYS_um_mod_user,
    RSYS_um_mod_group,
    RSYS_um_get_user_item,
    RSYS_um_get_group_item,
    RSYS_um_remove_user,
    RSYS_um_remove_group,
    RSYS_um_remove_gm,
    RSYS_um_user_exists,
    RSYS_um_group_exists,
    RSYS_um_get_next_user,
    RSYS_um_get_user_list,
    RSYS_um_get_gm_list,
    RSYS_um_get_gm_user_list,
    RSYS_um_get_group_list,
    RSYS_um_get_uid,
    RSYS_um_get_gid,
    RSYS_um_set_pass,
    RSYS_um_set_pass_name,
    RSYS_um_set_group_pass,
    RSYS_um_check_account,
    RSYS_um_check_account_name,
    RSYS_list_ta_begin,
    RSYS_list_ta_refresh,
    RSYS_list_ta_commit,
    RSYS_list_ta_forget,
    RSYS_list_all_dev,
    RSYS_acl_list_all_dev,
    RSYS_list_all_user,
    RSYS_acl_list_all_user,
    RSYS_list_all_group,
    RSYS_acl_list_all_group,
    RSYS_list_all_ipc,
    RSYS_rc_select_fd_create_type,
    RSYS_um_select_vset,
    RSYS_um_add_onetime,
    RSYS_um_add_onetime_name,
    RSYS_um_remove_all_onetime,
    RSYS_um_remove_all_onetime_name,
    RSYS_um_count_onetime,
    RSYS_um_count_onetime_name,
    RSYS_list_ta_begin_name,
    RSYS_um_get_max_history,
    RSYS_um_get_max_history_name,
    RSYS_um_set_max_history,
    RSYS_um_set_max_history_name,
    RSYS_none
  };


struct rsys_check_t
  {
    int correct;
    int check_inode;
  };

struct rsys_get_attr_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t module;
          rsbac_enum_t target;
    union rsbac_target_id_t * tid;
          rsbac_enum_t attr;
    union rsbac_attribute_value_t * value;
          int inherit;
  };

struct rsys_get_attr_n_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t module;
          rsbac_enum_t target;
          char * t_name;
          rsbac_enum_t attr;
    union rsbac_attribute_value_t * value;
          int inherit;
  };

struct rsys_set_attr_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t module;
          rsbac_enum_t target;
    union rsbac_target_id_t * tid;
          rsbac_enum_t attr;
    union rsbac_attribute_value_t * value;
  };

struct rsys_set_attr_n_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t module;
          rsbac_enum_t target;
          char * t_name;
          rsbac_enum_t attr;
    union rsbac_attribute_value_t * value;
  };

struct rsys_remove_target_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
    union rsbac_target_id_t * tid;
  };

struct rsys_remove_target_n_t
  {
         rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
         char * t_name;
  };

struct rsys_net_list_all_netdev_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_netdev_id_t * id_p;
    u_long maxnum;
  };

struct rsys_net_template_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t call;
          rsbac_net_temp_id_t id;
    union rsbac_net_temp_syscall_data_t * data_p;
  };

struct rsys_net_list_all_template_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_net_temp_id_t * id_p;
    u_long maxnum;
  };

struct rsys_switch_t
  {
    rsbac_enum_t module;
    int value;
  };

struct rsys_get_switch_t
  {
    rsbac_enum_t module;
    int * value_p;
    int * switchable_p;
  };

struct rsys_adf_log_switch_t
  {
    rsbac_enum_t request;
    rsbac_enum_t target;
    u_int        value;
  };

struct rsys_get_adf_log_t
  {
    rsbac_enum_t   request;
    rsbac_enum_t   target;
    u_int        * value_p;
  };

struct rsys_log_t
  {
    int type;
    char * buf;
    int len;
  };

struct rsys_mac_set_curr_level_t
  {
    rsbac_security_level_t level;
    rsbac_mac_category_vector_t * categories_p;
  };

struct rsys_mac_get_curr_level_t
  {
    rsbac_security_level_t      * level_p;
    rsbac_mac_category_vector_t * categories_p;
  };

struct rsys_mac_get_max_level_t
  {
    rsbac_security_level_t      * level_p;
    rsbac_mac_category_vector_t * categories_p;
  };

struct rsys_mac_get_min_level_t
  {
    rsbac_security_level_t      * level_p;
    rsbac_mac_category_vector_t * categories_p;
  };

struct rsys_mac_add_p_tru_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_upid_t pid;
    rsbac_uid_t uid;
    rsbac_time_t ttl;
  };

struct rsys_mac_remove_p_tru_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_upid_t pid;
    rsbac_uid_t uid;
  };

struct rsys_mac_add_f_tru_t
  {
    rsbac_list_ta_number_t ta_number;
    char * filename;
    rsbac_uid_t uid;
    rsbac_time_t ttl;
  };

struct rsys_mac_remove_f_tru_t
  {
    rsbac_list_ta_number_t ta_number;
    char * filename;
    rsbac_uid_t uid;
  };

struct rsys_mac_get_f_trulist_t
  {
    rsbac_list_ta_number_t ta_number;
    char * filename;
    rsbac_uid_t * trulist;
    rsbac_time_t * ttllist;
    u_int maxnum;
  };

struct rsys_mac_get_p_trulist_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_upid_t pid;
    rsbac_uid_t * trulist;
    rsbac_time_t * ttllist;
    u_int maxnum;
  };

struct rsys_pm_t
  {
    rsbac_list_ta_number_t ta_number;
          rsbac_enum_t function;
    union rsbac_pm_function_param_t * param_p;
          rsbac_pm_tkt_id_t ticket;
  };

struct rsys_pm_change_current_task_t
  {
    rsbac_pm_task_id_t task;
  };

struct rsys_pm_create_file_t
  {
    const char * filename;
    int mode;
    rsbac_pm_object_class_id_t object_class;
  };

struct rsys_rc_copy_role_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_rc_role_id_t from_role;
    rsbac_rc_role_id_t to_role;
  };

struct rsys_rc_copy_type_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_enum_t target;
    rsbac_rc_type_id_t from_type;
    rsbac_rc_type_id_t to_type;
  };

struct rsys_rc_get_item_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
    union rsbac_rc_target_id_t * tid_p;
    union rsbac_rc_target_id_t * subtid_p;
          rsbac_enum_t item;
    union rsbac_rc_item_value_t * value_p;
          rsbac_time_t * ttl_p;
  };

struct rsys_rc_set_item_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
    union rsbac_rc_target_id_t * tid_p;
    union rsbac_rc_target_id_t * subtid_p;
          rsbac_enum_t item;
    union rsbac_rc_item_value_t * value_p;
          rsbac_time_t ttl;
  };

struct rsys_rc_get_list_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t target;
    union rsbac_rc_target_id_t * tid_p;
          rsbac_enum_t item;
          u_int maxnum;
          __u32 * array_p;
          rsbac_time_t * ttl_array_p;
  };

struct rsys_rc_change_role_t
  {
    rsbac_rc_role_id_t role;
    char * pass;
  };

struct rsys_rc_get_eff_rights_n_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_enum_t target;
    char * t_name;
    rsbac_rc_request_vector_t * request_vector_p;
    rsbac_time_t * ttl_p;
  };

struct rsys_rc_get_current_role_t
  {
    rsbac_rc_role_id_t * role_p;
  };

struct rsys_auth_add_p_cap_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_upid_t pid;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_t cap_range;
           rsbac_time_t ttl;
  };

struct rsys_auth_remove_p_cap_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_upid_t pid;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_t cap_range;
  };

struct rsys_auth_add_f_cap_t
  {
           rsbac_list_ta_number_t ta_number;
           char * filename;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_t cap_range;
           rsbac_time_t ttl;
  };

struct rsys_auth_remove_f_cap_t
  {
           rsbac_list_ta_number_t ta_number;
           char * filename;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_t cap_range;
  };

struct rsys_auth_get_f_caplist_t
  {
           rsbac_list_ta_number_t ta_number;
           char * filename;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_t * caplist;
           rsbac_time_t * ttllist;
           u_int maxnum;
  };

struct rsys_auth_get_p_caplist_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_upid_t pid;
           rsbac_enum_t cap_type;
    struct rsbac_auth_cap_range_t * caplist;
           rsbac_time_t * ttllist;
           u_int maxnum;
  };

struct rsys_acl_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t call;
    struct rsbac_acl_syscall_arg_t * arg;
  };

struct rsys_acl_n_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t call;
    struct rsbac_acl_syscall_n_arg_t * arg;
  };

struct rsys_acl_get_rights_t
  {
           rsbac_list_ta_number_t ta_number;
    struct rsbac_acl_syscall_arg_t * arg;
           rsbac_acl_rights_vector_t * rights_p;
           u_int effective;
  };

struct rsys_acl_get_rights_n_t
  {
           rsbac_list_ta_number_t ta_number;
    struct rsbac_acl_syscall_n_arg_t * arg;
           rsbac_acl_rights_vector_t * rights_p;
           u_int effective;
  };

struct rsys_acl_get_tlist_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t target;
    union  rsbac_target_id_t * tid;
    struct rsbac_acl_entry_t * entry_array;
           rsbac_time_t * ttl_array;
           u_int maxnum;
  };

struct rsys_acl_get_tlist_n_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t target;
           char * t_name;
    struct rsbac_acl_entry_t * entry_array;
           rsbac_time_t * ttl_array;
           u_int maxnum;
  };

struct rsys_acl_get_mask_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t target;
    union  rsbac_target_id_t * tid;
           rsbac_acl_rights_vector_t * mask_p;
  };

struct rsys_acl_get_mask_n_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_enum_t target;
           char * t_name;
           rsbac_acl_rights_vector_t * mask_p;
  };

struct rsys_acl_group_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_enum_t call;
    union rsbac_acl_group_syscall_arg_t * arg_p;
  };

struct rsys_reg_t
  {
    long handle;
    void * arg;
  };

struct rsys_jail_t
  {
    rsbac_version_t      version;
    char               * path;
    rsbac_jail_ip_t      ip;
    rsbac_jail_flags_t   flags;
    rsbac_cap_vector_t   max_caps;
    rsbac_jail_scd_vector_t scd_get;
    rsbac_jail_scd_vector_t scd_modify;
  };

struct rsys_init_t
  {
    char * root_dev;
  };

struct rsys_um_auth_name_t
  {
    char * name;
    char * pass;
  };

struct rsys_um_auth_uid_t
  {
    rsbac_uid_t   uid;
    char        * pass;
  };

struct rsys_um_add_user_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_uid_t             uid;
    struct rsbac_um_user_entry_t * entry_p;
           char                  * pass;
           rsbac_time_t            ttl;
  };

struct rsys_um_add_group_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_gid_t              gid;
    struct rsbac_um_group_entry_t * entry_p;
           char                   * pass;
           rsbac_time_t             ttl;
  };

struct rsys_um_add_gm_t
  {
           rsbac_list_ta_number_t ta_number;
           rsbac_uid_t  uid;
           rsbac_gid_num_t  gid;
           rsbac_time_t ttl;
  };

struct rsys_um_mod_user_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t           uid;
          rsbac_enum_t          mod;
    union rsbac_um_mod_data_t * data_p;
  };

struct rsys_um_mod_group_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_t           gid;
          rsbac_enum_t          mod;
    union rsbac_um_mod_data_t * data_p;
  };

struct rsys_um_get_user_item_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t           uid;
          rsbac_enum_t          mod;
    union rsbac_um_mod_data_t * data_p;
  };

struct rsys_um_get_group_item_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_t           gid;
          rsbac_enum_t          mod;
    union rsbac_um_mod_data_t * data_p;
  };

struct rsys_um_remove_user_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t           uid;
  };

struct rsys_um_remove_group_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_t           gid;
  };

struct rsys_um_remove_gm_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t  uid;
          rsbac_gid_num_t  gid;
  };

struct rsys_um_user_exists_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t uid;
  };

struct rsys_um_group_exists_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_t gid;
  };

struct rsys_um_get_next_user_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t   old_user;
          rsbac_uid_t * next_user_p;
  };

struct rsys_um_get_user_list_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_um_set_t vset;
          rsbac_uid_t * user_array;
          u_int         maxnum;
  };

struct rsys_um_get_gm_list_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_uid_t   user;
          rsbac_gid_num_t * group_array;
          u_int         maxnum;
  };

struct rsys_um_get_gm_user_list_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_gid_t   group;
          rsbac_uid_num_t * user_array;
          u_int         maxnum;
  };

struct rsys_um_get_group_list_t
  {
          rsbac_list_ta_number_t ta_number;
          rsbac_um_set_t vset;
          rsbac_gid_t * group_array;
          u_int         maxnum;
  };

struct rsys_um_get_uid_t
  {
    rsbac_list_ta_number_t ta_number;
    char        * name;
    rsbac_uid_t * uid_p;
  };

struct rsys_um_get_gid_t
  {
    rsbac_list_ta_number_t ta_number;
    char        * name;
    rsbac_gid_t * gid_p;
  };

struct rsys_um_set_pass_t
  {
    rsbac_uid_t   uid;
    char        * old_pass;
    char        * new_pass;
  };

struct rsys_um_set_pass_name_t
  {
    char * name;
    char * old_pass;
    char * new_pass;
  };

struct rsys_um_add_onetime_t
  {
    rsbac_uid_t   uid;
    char        * old_pass;
    char        * new_pass;
    rsbac_time_t  ttl;
  };

struct rsys_um_add_onetime_name_t
  {
    char * name;
    char * old_pass;
    char * new_pass;
    rsbac_time_t ttl;
  };

struct rsys_um_remove_all_onetime_t
  {
    rsbac_uid_t   uid;
    char        * old_pass;
  };

struct rsys_um_remove_all_onetime_name_t
  {
    char * name;
    char * old_pass;
  };

struct rsys_um_count_onetime_t
  {
    rsbac_uid_t   uid;
    char        * old_pass;
  };

struct rsys_um_count_onetime_name_t
  {
    char * name;
    char * old_pass;
  };

struct rsys_um_set_group_pass_t
  {
    rsbac_gid_t   gid;
    char        * new_pass;
  };

struct rsys_um_check_account_t
  {
    rsbac_uid_t   uid;
  };

struct rsys_um_check_account_name_t
  {
    char * name;
  };

struct rsys_um_get_max_history_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_uid_t   uid;
  };

struct rsys_um_get_max_history_name_t
  {
    rsbac_list_ta_number_t ta_number;
    char * name;
  };

struct rsys_um_set_max_history_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_uid_t   uid;
    __u8          max_history;
  };

struct rsys_um_set_max_history_name_t
  {
    rsbac_list_ta_number_t ta_number;
    char * name;
    __u8   max_history;
  };

struct rsys_um_select_vset_t
  {
    rsbac_um_set_t vset;
  };

struct rsys_list_ta_begin_t
  {
    rsbac_time_t ttl;
    rsbac_list_ta_number_t * ta_number_p;
    rsbac_uid_t commit_uid;
    char * password;
  };

struct rsys_list_ta_begin_name_t
  {
    rsbac_time_t ttl;
    rsbac_list_ta_number_t * ta_number_p;
    rsbac_uid_t commit_uid;
    char * name;
    char * password;
  };

struct rsys_list_ta_refresh_t
  {
    rsbac_time_t ttl;
    rsbac_list_ta_number_t ta_number;
    char * password;
  };

struct rsys_list_ta_commit_t
  {
    rsbac_list_ta_number_t ta_number;
    char * password;
  };

struct rsys_list_ta_forget_t
  {
    rsbac_list_ta_number_t ta_number;
    char * password;
  };

struct rsys_list_all_dev_t
  {
    rsbac_list_ta_number_t ta_number;
    struct rsbac_dev_desc_t * id_p;
    u_long maxnum;
  };

struct rsys_acl_list_all_dev_t
  {
    rsbac_list_ta_number_t ta_number;
    struct rsbac_dev_desc_t * id_p;
    u_long maxnum;
  };

struct rsys_list_all_user_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_uid_t * id_p;
    u_long maxnum;
  };

struct rsys_acl_list_all_user_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_uid_t * id_p;
    u_long maxnum;
  };

struct rsys_list_all_group_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_gid_t * id_p;
    u_long maxnum;
  };

struct rsys_acl_list_all_group_t
  {
    rsbac_list_ta_number_t ta_number;
    rsbac_gid_t * id_p;
    u_long maxnum;
  };

struct rsys_list_all_ipc_t {
       rsbac_list_ta_number_t ta_number;
       struct rsbac_ipc_t *id_p;
       u_long maxnum;
};

struct rsys_rc_select_fd_create_type_t {
	rsbac_rc_type_id_t type;
};


union rsbac_syscall_arg_t
  {
    struct rsys_check_t check;
    struct rsys_get_attr_t get_attr;
    struct rsys_get_attr_n_t get_attr_n;
    struct rsys_set_attr_t set_attr;
    struct rsys_set_attr_n_t set_attr_n;
    struct rsys_remove_target_t remove_target;
    struct rsys_remove_target_n_t remove_target_n;
    struct rsys_net_list_all_netdev_t net_list_all_netdev;
    struct rsys_net_template_t net_template;
    struct rsys_net_list_all_template_t net_list_all_template;
    struct rsys_switch_t switch_module;
    struct rsys_get_switch_t get_switch_module;
    struct rsys_adf_log_switch_t adf_log_switch;
    struct rsys_get_adf_log_t get_adf_log;
    struct rsys_log_t log;
    struct rsys_mac_set_curr_level_t mac_set_curr_level;
    struct rsys_mac_get_curr_level_t mac_get_curr_level;
    struct rsys_mac_get_max_level_t mac_get_max_level;
    struct rsys_mac_get_min_level_t mac_get_min_level;
    struct rsys_mac_add_p_tru_t mac_add_p_tru;
    struct rsys_mac_remove_p_tru_t mac_remove_p_tru;
    struct rsys_mac_add_f_tru_t mac_add_f_tru;
    struct rsys_mac_remove_f_tru_t mac_remove_f_tru;
    struct rsys_mac_get_f_trulist_t mac_get_f_trulist;
    struct rsys_mac_get_p_trulist_t mac_get_p_trulist;
    struct rsys_pm_t pm;
    struct rsys_pm_change_current_task_t pm_change_current_task;
    struct rsys_pm_create_file_t pm_create_file;
    struct rsys_rc_copy_role_t rc_copy_role;
    struct rsys_rc_copy_type_t rc_copy_type;
    struct rsys_rc_get_item_t rc_get_item;
    struct rsys_rc_set_item_t rc_set_item;
    struct rsys_rc_get_list_t rc_get_list;
    struct rsys_rc_change_role_t rc_change_role;
    struct rsys_rc_get_eff_rights_n_t rc_get_eff_rights_n;
    struct rsys_rc_get_current_role_t rc_get_current_role;
    struct rsys_auth_add_p_cap_t auth_add_p_cap;
    struct rsys_auth_remove_p_cap_t auth_remove_p_cap;
    struct rsys_auth_add_f_cap_t auth_add_f_cap;
    struct rsys_auth_remove_f_cap_t auth_remove_f_cap;
    struct rsys_auth_get_f_caplist_t auth_get_f_caplist;
    struct rsys_auth_get_p_caplist_t auth_get_p_caplist;
    struct rsys_acl_t acl;
    struct rsys_acl_n_t acl_n;
    struct rsys_acl_get_rights_t acl_get_rights;
    struct rsys_acl_get_rights_n_t acl_get_rights_n;
    struct rsys_acl_get_tlist_t acl_get_tlist;
    struct rsys_acl_get_tlist_n_t acl_get_tlist_n;
    struct rsys_acl_get_mask_t acl_get_mask;
    struct rsys_acl_get_mask_n_t acl_get_mask_n;
    struct rsys_acl_group_t acl_group;
    struct rsys_reg_t reg;
    struct rsys_jail_t jail;
    struct rsys_init_t init;
    struct rsys_um_auth_name_t um_auth_name;
    struct rsys_um_auth_uid_t um_auth_uid;
    struct rsys_um_add_user_t um_add_user;
    struct rsys_um_add_group_t um_add_group;
    struct rsys_um_add_gm_t um_add_gm;
    struct rsys_um_mod_user_t um_mod_user;
    struct rsys_um_mod_group_t um_mod_group;
    struct rsys_um_get_user_item_t um_get_user_item;
    struct rsys_um_get_group_item_t um_get_group_item;
    struct rsys_um_remove_user_t um_remove_user;
    struct rsys_um_remove_group_t um_remove_group;
    struct rsys_um_remove_gm_t um_remove_gm;
    struct rsys_um_user_exists_t um_user_exists;
    struct rsys_um_group_exists_t um_group_exists;
    struct rsys_um_get_next_user_t um_get_next_user;
    struct rsys_um_get_user_list_t um_get_user_list;
    struct rsys_um_get_gm_list_t um_get_gm_list;
    struct rsys_um_get_gm_user_list_t um_get_gm_user_list;
    struct rsys_um_get_group_list_t um_get_group_list;
    struct rsys_um_get_uid_t um_get_uid;
    struct rsys_um_get_gid_t um_get_gid;
    struct rsys_um_set_pass_t um_set_pass;
    struct rsys_um_set_pass_name_t um_set_pass_name;
    struct rsys_um_add_onetime_t um_add_onetime;
    struct rsys_um_add_onetime_name_t um_add_onetime_name;
    struct rsys_um_remove_all_onetime_t um_remove_all_onetime;
    struct rsys_um_remove_all_onetime_name_t um_remove_all_onetime_name;
    struct rsys_um_count_onetime_t um_count_onetime;
    struct rsys_um_count_onetime_name_t um_count_onetime_name;
    struct rsys_um_set_group_pass_t um_set_group_pass;
    struct rsys_um_check_account_t um_check_account;
    struct rsys_um_check_account_name_t um_check_account_name;
    struct rsys_um_get_max_history_t um_get_max_history;
    struct rsys_um_get_max_history_name_t um_get_max_history_name;
    struct rsys_um_set_max_history_t um_set_max_history;
    struct rsys_um_set_max_history_name_t um_set_max_history_name;
    struct rsys_list_ta_begin_t list_ta_begin;
    struct rsys_list_ta_begin_name_t list_ta_begin_name;
    struct rsys_list_ta_refresh_t list_ta_refresh;
    struct rsys_list_ta_commit_t list_ta_commit;
    struct rsys_list_ta_forget_t list_ta_forget;
    struct rsys_list_all_dev_t list_all_dev;
    struct rsys_acl_list_all_dev_t acl_list_all_dev;
    struct rsys_list_all_user_t list_all_user;
    struct rsys_acl_list_all_user_t acl_list_all_user;
    struct rsys_list_all_group_t list_all_group;
    struct rsys_acl_list_all_group_t acl_list_all_group;
    struct rsys_list_all_ipc_t list_all_ipc;
    struct rsys_rc_select_fd_create_type_t rc_select_fd_create_type;
    struct rsys_um_select_vset_t um_select_vset;
           int dummy;
  };

#ifndef __KERNEL__
int rsbac_version(void);

int rsbac_stats(void);

int rsbac_check(int correct, int check_inode);

int rsbac_write(void);

int rsbac_get_attr(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_switch_target_t module,
  enum rsbac_target_t target,
  union rsbac_target_id_t * tid,
  enum rsbac_attribute_t attr,
  union rsbac_attribute_value_t * value,
  int inherit);

int rsbac_get_attr_n(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_switch_target_t module,
  enum rsbac_target_t target,
  char * t_name,
  enum rsbac_attribute_t attr,
  union rsbac_attribute_value_t * value,
  int inherit);

int rsbac_set_attr(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_switch_target_t module,
  enum rsbac_target_t target,
  union rsbac_target_id_t * tid,
  enum rsbac_attribute_t attr,
  union rsbac_attribute_value_t * value);


int rsbac_set_attr_n(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_switch_target_t module,
  enum rsbac_target_t target,
  char * t_name,
  enum rsbac_attribute_t attr,
  union rsbac_attribute_value_t * value);

int rsbac_remove_target(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_target_t target,
  union rsbac_target_id_t * tid);

int rsbac_remove_target_n(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_target_t target,
  char * t_name);

int rsbac_net_list_all_netdev(
  rsbac_list_ta_number_t ta_number,
  rsbac_netdev_id_t * id_p,
  u_long maxnum);

int rsbac_net_template(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_net_temp_syscall_t call,
  rsbac_net_temp_id_t id,
  union rsbac_net_temp_syscall_data_t * data_p);

int rsbac_net_list_all_template(
  rsbac_list_ta_number_t ta_number,
  rsbac_net_temp_id_t * id_p,
  u_long maxnum);

int rsbac_switch(enum rsbac_switch_target_t module, int value);

int rsbac_get_switch(enum rsbac_switch_target_t module, int * value_p, int * switchable_p);

/************** MAC ***************/

int rsbac_mac_set_curr_level(rsbac_security_level_t level,
                             rsbac_mac_category_vector_t * categories_p);

int rsbac_mac_get_curr_level(rsbac_security_level_t      * level_p,
                             rsbac_mac_category_vector_t * categories_p);

int rsbac_mac_get_max_level(rsbac_security_level_t      * level_p,
                            rsbac_mac_category_vector_t * categories_p);

int rsbac_mac_get_min_level(rsbac_security_level_t      * level_p,
                            rsbac_mac_category_vector_t * categories_p);

int rsbac_mac_add_p_tru(
  rsbac_list_ta_number_t ta_number,
  rsbac_upid_t pid,
  rsbac_uid_t uid,
  rsbac_time_t ttl);

int rsbac_mac_remove_p_tru(
  rsbac_list_ta_number_t ta_number,
  rsbac_upid_t pid,
  rsbac_uid_t uid);

int rsbac_mac_add_f_tru(
  rsbac_list_ta_number_t ta_number,
  char * filename,
  rsbac_uid_t uid,
  rsbac_time_t ttl);

int rsbac_mac_remove_f_tru(
  rsbac_list_ta_number_t ta_number,
  char * filename,
  rsbac_uid_t uid);

/* trulist must have space for maxnum rsbac_uid_t entries! */
int rsbac_mac_get_f_trulist(
  rsbac_list_ta_number_t ta_number,
  char * filename,
  rsbac_uid_t trulist[],
  rsbac_time_t ttllist[],
  u_int maxnum);

int rsbac_mac_get_p_trulist(
  rsbac_list_ta_number_t ta_number,
  rsbac_upid_t pid,
  rsbac_uid_t trulist[],
  rsbac_time_t ttllist[],
  u_int maxnum);

/************** PM ***************/

int rsbac_stats_pm(void);

int rsbac_pm(
        rsbac_list_ta_number_t ta_number,
  enum  rsbac_pm_function_type_t    function,
  union rsbac_pm_function_param_t * param_p,
        rsbac_pm_tkt_id_t           ticket);

int rsbac_pm_change_current_task(rsbac_pm_task_id_t task);

int rsbac_pm_create_file(const char * filename,
                             int mode,
                             rsbac_pm_object_class_id_t object_class);

/************** DAZ **************/

int rsbac_daz_flush_cache(void);

/************** RC ***************/

int rsbac_rc_copy_role(
  rsbac_list_ta_number_t ta_number,
  rsbac_rc_role_id_t from_role,
  rsbac_rc_role_id_t to_role);

int rsbac_rc_copy_type(
       rsbac_list_ta_number_t ta_number,
  enum rsbac_target_t         target,
       rsbac_rc_type_id_t     from_type,
       rsbac_rc_type_id_t     to_type);

int rsbac_rc_get_item(
        rsbac_list_ta_number_t  ta_number,
  enum  rsbac_rc_target_t       target,
  union rsbac_rc_target_id_t  * tid_p,
  union rsbac_rc_target_id_t  * subtid_p,
  enum  rsbac_rc_item_t         item,
  union rsbac_rc_item_value_t * value_p,
        rsbac_time_t          * ttl_p);

/* Setting values */
int rsbac_rc_set_item(
        rsbac_list_ta_number_t  ta_number,
  enum  rsbac_rc_target_t       target,
  union rsbac_rc_target_id_t  * tid_p,
  union rsbac_rc_target_id_t  * subtid_p,
  enum  rsbac_rc_item_t         item,
  union rsbac_rc_item_value_t * value_p,
        rsbac_time_t            ttl);

int rsbac_rc_get_list(
        rsbac_list_ta_number_t  ta_number,
  enum  rsbac_rc_target_t       target,
  union rsbac_rc_target_id_t  * tid_p,
  enum  rsbac_rc_item_t         item,
        u_int maxnum,
        __u32  * array_p,
        rsbac_time_t * ttl_array_p);

int rsbac_rc_change_role (rsbac_rc_role_id_t role, char * pass);

int rsbac_rc_get_eff_rights_n(
        rsbac_list_ta_number_t ta_number,
  enum  rsbac_target_t   target,
        char           * t_name,
        rsbac_rc_request_vector_t * request_vector_p,
        rsbac_time_t          * ttl_p);

int rsbac_rc_get_current_role (rsbac_rc_role_id_t * role_p);

int rsbac_rc_select_fd_create_type(rsbac_rc_type_id_t type);

/************** AUTH ***************/

/* Provide means for adding and removing of capabilities */
int rsbac_auth_add_p_cap(
  rsbac_list_ta_number_t ta_number,
  rsbac_upid_t pid,
  enum rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range,
  rsbac_time_t ttl);

int rsbac_auth_remove_p_cap(
  rsbac_list_ta_number_t ta_number,
  rsbac_upid_t pid,
  enum rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range);

int rsbac_auth_add_f_cap(
  rsbac_list_ta_number_t ta_number,
  char * filename,
  enum rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range,
  rsbac_time_t ttl);

int rsbac_auth_remove_f_cap(
  rsbac_list_ta_number_t ta_number,
  char * filename,
  enum rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range);

/* caplist must have space for maxnum cap_range entries - first and last each! */
int rsbac_auth_get_f_caplist(
  rsbac_list_ta_number_t ta_number,
  char * filename,
  enum rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t caplist[],
  rsbac_time_t ttllist[],
  u_int maxnum);

int rsbac_auth_get_p_caplist(
  rsbac_list_ta_number_t ta_number,
  rsbac_upid_t pid,
  enum rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t caplist[],
  rsbac_time_t ttllist[],
  u_int maxnum);

/**********************************/
/************** REG ***************/

int rsbac_reg(rsbac_reg_handle_t handle,
              void * arg);


/**********************************/
/************** ACL ***************/

int rsbac_acl(
  rsbac_list_ta_number_t ta_number,
  enum   rsbac_acl_syscall_type_t call,
  struct rsbac_acl_syscall_arg_t * arg);

int rsbac_acl_n(
  rsbac_list_ta_number_t ta_number,
  enum   rsbac_acl_syscall_type_t call,
  struct rsbac_acl_syscall_n_arg_t * arg);

int rsbac_acl_get_rights(
  rsbac_list_ta_number_t ta_number,
  struct rsbac_acl_syscall_arg_t   * arg,
  rsbac_acl_rights_vector_t * rights_p,
  u_int                     effective);


int rsbac_acl_get_rights_n(
  rsbac_list_ta_number_t ta_number,
  struct rsbac_acl_syscall_n_arg_t * arg,
  rsbac_acl_rights_vector_t * rights_p,
  u_int                     effective);

int rsbac_acl_get_tlist (
  rsbac_list_ta_number_t     ta_number,
  enum   rsbac_target_t      target,
  union  rsbac_target_id_t * tid,
  struct rsbac_acl_entry_t   entry_array[],
         rsbac_time_t        ttl_array[],
         u_int               maxnum);

int rsbac_acl_get_tlist_n(
  rsbac_list_ta_number_t     ta_number,
  enum   rsbac_target_t      target,
         char              * t_name,
  struct rsbac_acl_entry_t   entry_array[],
         rsbac_time_t        ttl_array[],
         u_int               maxnum);

int rsbac_acl_get_mask (
  rsbac_list_ta_number_t     ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t         * tid,
         rsbac_acl_rights_vector_t * mask_p);

int rsbac_acl_get_mask_n(
       rsbac_list_ta_number_t      ta_number,
  enum rsbac_target_t              target,
       char                      * t_name,
       rsbac_acl_rights_vector_t * mask_p);

/********  ACL groups *********/

int rsbac_acl_group(
        rsbac_list_ta_number_t           ta_number,
  enum  rsbac_acl_group_syscall_type_t   call,
  union rsbac_acl_group_syscall_arg_t  * arg_p);


/**********************************/
/************** JAIL **************/

int rsbac_jail(rsbac_version_t version,
               char * path,
               rsbac_jail_ip_t ip,
               rsbac_jail_flags_t flags,
               rsbac_cap_vector_t max_caps,
               rsbac_jail_scd_vector_t scd_get,
               rsbac_jail_scd_vector_t scd_modify
               );

int rsbac_list_all_ipc(rsbac_list_ta_number_t ta_number,
                       struct rsbac_ipc_t * id_p, u_long maxnum);

/**********************************/
/**************  UM  **************/

int rsbac_um_auth_name(char * name,
                       char * pass);

int rsbac_um_auth_uid(rsbac_uid_t uid,
                      char * pass);

int rsbac_um_add_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid,
  struct rsbac_um_user_entry_t * entry_p,
  char * pass,
  rsbac_time_t ttl);

int rsbac_um_add_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t gid,
  struct rsbac_um_group_entry_t * entry_p,
  char * pass,
  rsbac_time_t ttl);

int rsbac_um_add_gm(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid,
  rsbac_gid_num_t gid,
  rsbac_time_t ttl);

int rsbac_um_mod_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid,
  enum rsbac_um_mod_t mod,
  union rsbac_um_mod_data_t * data_p);

int rsbac_um_mod_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t gid,
  enum rsbac_um_mod_t mod,
  union rsbac_um_mod_data_t * data_p);

int rsbac_um_get_user_item(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid,
  enum rsbac_um_mod_t mod,
  union rsbac_um_mod_data_t * data_p);

int rsbac_um_get_group_item(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t gid,
  enum rsbac_um_mod_t mod,
  union rsbac_um_mod_data_t * data_p);

int rsbac_um_remove_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid);

int rsbac_um_remove_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t gid);

int rsbac_um_remove_gm(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid,
  rsbac_gid_num_t gid);

int rsbac_um_user_exists(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid);

int rsbac_um_group_exists(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t gid);

int rsbac_um_get_next_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t old_user,
  rsbac_uid_t * next_user_p);

int rsbac_um_get_user_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_um_set_t vset,
  rsbac_uid_t user_array[],
  u_int       maxnum);

int rsbac_um_get_gm_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t user,
  rsbac_gid_num_t group_array[],
  u_int       maxnum);

int rsbac_um_get_gm_user_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t group,
  rsbac_uid_num_t user_array[],
  u_int       maxnum);

int rsbac_um_get_group_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_um_set_t vset,
  rsbac_gid_t group_array[],
  u_int       maxnum);

int rsbac_um_get_uid(
  rsbac_list_ta_number_t ta_number,
  char * name,
  rsbac_uid_t * uid_p);

int rsbac_um_get_gid(
  rsbac_list_ta_number_t ta_number,
  char * name,
  rsbac_gid_t * gid_p);

int rsbac_um_set_pass(rsbac_uid_t uid,
                      char * old_pass,
                      char * new_pass);

int rsbac_um_set_pass_name(char * name,
                      char * old_pass,
                      char * new_pass);

int rsbac_um_add_onetime(rsbac_uid_t uid,
                      char * old_pass,
                      char * new_pass,
                      rsbac_time_t ttl);

int rsbac_um_add_onetime_name(char * name,
                      char * old_pass,
                      char * new_pass,
                      rsbac_time_t ttl);

int rsbac_um_remove_all_onetime(rsbac_uid_t uid,
                      char * old_pass);

int rsbac_um_remove_all_onetime_name(char * name,
                      char * old_pass);

int rsbac_um_count_onetime(rsbac_uid_t uid,
                      char * old_pass);

int rsbac_um_count_onetime_name(char * name,
                      char * old_pass);

int rsbac_um_set_group_pass(rsbac_gid_t gid,
                            char * new_pass);

int rsbac_um_check_account(rsbac_uid_t uid);

int rsbac_um_check_account_name(char * name);

int rsbac_um_get_max_history(rsbac_list_ta_number_t ta_number, rsbac_uid_t uid);

int rsbac_um_get_max_history_name(rsbac_list_ta_number_t ta_number, char * name);

int rsbac_um_set_max_history(rsbac_list_ta_number_t ta_number, rsbac_uid_t uid, __u8 max_history);

int rsbac_um_set_max_history_name(rsbac_list_ta_number_t ta_number, char * name, __u8 max_history);

int rsbac_um_select_vset(rsbac_um_set_t vset);

int rsbac_list_ta_begin(rsbac_time_t ttl,
                        rsbac_list_ta_number_t * ta_number_p,
                        rsbac_uid_t commit_uid,
                        char * password);

int rsbac_list_ta_begin_name(rsbac_time_t ttl,
                        rsbac_list_ta_number_t * ta_number_p,
                        rsbac_uid_t commit_uid,
                        char * name,
                        char * password);

int rsbac_list_ta_refresh(rsbac_time_t ttl,
                          rsbac_list_ta_number_t ta_number,
                          char * password);

int rsbac_list_ta_commit(rsbac_list_ta_number_t ta_number,
                         char * password);

int rsbac_list_ta_forget(rsbac_list_ta_number_t ta_number,
                         char * password);

int rsbac_list_all_dev(
  rsbac_list_ta_number_t ta_number,
  struct rsbac_dev_desc_t * id_p,
  u_long maxnum);

int rsbac_acl_list_all_dev(
  rsbac_list_ta_number_t ta_number,
  struct rsbac_dev_desc_t * id_p,
  u_long maxnum);

int rsbac_list_all_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t * id_p,
  u_long maxnum);

int rsbac_acl_list_all_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t * id_p,
  u_long maxnum);

int rsbac_list_all_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t * id_p,
  u_long maxnum);

int rsbac_acl_list_all_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t * id_p,
  u_long maxnum);

/************************************************* */
/*             DEBUG/LOG functions                 */
/************************************************* */

int rsbac_adf_log_switch(enum rsbac_adf_request_t request,
                         enum rsbac_target_t      target,
                         u_int value);

int rsbac_get_adf_log(enum rsbac_adf_request_t   request,
                      enum rsbac_target_t        target,
                      u_int                    * value_p);

/*
 * Commands to rsbac_log:
 *
 * 	0 -- Close the log.  Currently a NOP.
 * 	1 -- Open the log. Currently a NOP.
 * 	2 -- Read from the log.
 * 	3 -- Read up to the last 4k of messages in the ring buffer.
 * 	4 -- Read and clear last 4k of messages in the ring buffer
 * 	5 -- Clear ring buffer.
 */
int rsbac_log(int type,
                  char * buf,
                  int len);

int rsbac_init(char * root_dev);

#endif /* ifndef __KERNEL__ */

#endif
