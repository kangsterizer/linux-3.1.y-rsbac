/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - Authentification module          */
/* File: rsbac/adf/auth/syscalls.c                   */
/*                                                   */
/* Author and (c) 1999-2008: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 26/Feb/2008                        */
/*************************************************** */

#include <linux/string.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/error.h>
#include <rsbac/auth.h>
#include <rsbac/debug.h>
#include <rsbac/helpers.h>
#include <rsbac/adf_main.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

int rsbac_auth_add_p_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_pid_t pid,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range,
         rsbac_time_t ttl)
  {
/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_AUTH
    if(rsbac_switch_auth)
#endif
      {
        union rsbac_target_id_t       i_tid;
        union rsbac_attribute_value_t i_attr_val1;

        /* check auth_may_set_cap of calling process */
        i_tid.process = task_pid(current);
        if (rsbac_get_attr(SW_AUTH,
                           T_PROCESS,
                           i_tid,
                           A_auth_may_set_cap,
                           &i_attr_val1,
                           FALSE))
          {
            rsbac_pr_get_error(A_auth_may_set_cap);
            return -RSBAC_EREADFAILED;
          }
        /* if auth_may_set_cap is not set, then reject */
        if (!i_attr_val1.auth_may_set_cap)
          {
            rsbac_printk(KERN_INFO
                   "rsbac_auth_add_p_cap(): adding AUTH cap %u:%u to process %u denied for process %u!\n",
                   cap_range.first,
                   cap_range.last,
                   pid,
                   task_pid(current));
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_AUTH]
            #endif
              )
            #endif
              return(-EPERM);
          }
      }
#endif

    /* OK, check passed. Add the capability. */
    return rsbac_auth_add_to_p_capset(ta_number, pid, cap_type, cap_range, ttl);
  }

int rsbac_auth_remove_p_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_pid_t pid,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range)
  {
/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_AUTH
    if(rsbac_switch_auth)
#endif
      {
        union rsbac_target_id_t       i_tid;
        union rsbac_attribute_value_t i_attr_val1;

        /* check auth_may_set_cap of calling process */
        i_tid.process = task_pid(current);
        if (rsbac_get_attr(SW_AUTH,
                           T_PROCESS,
                           i_tid,
                           A_auth_may_set_cap,
                           &i_attr_val1,
                           FALSE))
          {
            rsbac_pr_get_error(A_auth_may_set_cap);
            return -RSBAC_EREADFAILED;
          }
        /* if auth_may_set_cap is not set, then reject */
        if (!i_attr_val1.auth_may_set_cap)
          {
            rsbac_printk(KERN_INFO
                   "rsbac_auth_remove_p_cap(): removing AUTH cap %u:%u from process %u denied for process %u!\n",
                   cap_range.first,
                   cap_range.last,
                   pid,
                   task_pid(current));
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_AUTH]
            #endif
              )
            #endif
              return(-EPERM);
          }
      }
#endif

    /* OK, check passed. Try to remove the capability. */
    return rsbac_auth_remove_from_p_capset(ta_number, pid, cap_type, cap_range);
  }

int rsbac_auth_add_f_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_auth_file_t file,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range,
         rsbac_time_t ttl)
  {
    /* check has been done in help/syscalls.c: sys_rsbac_auth_add_f_cap */
    return rsbac_auth_add_to_f_capset(ta_number, file, cap_type, cap_range, ttl);
  }

int rsbac_auth_remove_f_cap(
         rsbac_list_ta_number_t ta_number,
         rsbac_auth_file_t file,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range)
  {
    /* check has been done in help/syscalls.c: sys_rsbac_auth_remove_f_cap */
    return rsbac_auth_remove_from_f_capset(ta_number, file, cap_type, cap_range);
  }

/* end of rsbac/adf/auth/syscalls.c */
