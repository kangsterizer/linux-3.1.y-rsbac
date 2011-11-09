/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - Mandatory Access Control         */
/* File: rsbac/adf/mac/syscalls.c                    */
/*                                                   */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 12/Jul/2011                        */
/*************************************************** */

#include <linux/string.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/mac.h>
#include <rsbac/adf_main.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/debug.h>
#include <rsbac/rkmem.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

#ifndef CONFIG_RSBAC_MAINT
static int
  mac_sys_check_role(enum rsbac_system_role_t role)
  {
    union rsbac_target_id_t i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    i_tid.user = current_uid();
    if (rsbac_get_attr(SW_MAC,
                       T_USER,
                       i_tid,
                       A_mac_role,
                       &i_attr_val1,
                       TRUE))
      {
        rsbac_ds_get_error("mac_sys_check_role", A_mac_role);
        return -EPERM;
      }
    /* if correct role, then grant */
    if (i_attr_val1.system_role == role)
      return 0;
    else
      return -EPERM;
  }
#endif

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

/*****************************************************************************/
/* This function allows processes to set their own current security level    */
/* via sys_rsbac_mac_set_curr_seclevel() system call.                        */
/* The level must keep within the min_write_open/max_read_open-boundary and  */
/* must not be greater than owner_sec_level. Setting current_sec_level by    */
/* this function also turns off auto-levelling via mac_auto.                 */

int  rsbac_mac_set_curr_level(rsbac_security_level_t level,
                              rsbac_mac_category_vector_t categories)
  {
    union rsbac_target_id_t       tid;
    union rsbac_attribute_value_t attr_val1;
#ifndef CONFIG_RSBAC_MAINT
    rsbac_mac_process_flags_t     flags;
#endif

    if(   (level > SL_max)
       && (level != SL_none)
      )
      return -RSBAC_EINVALIDVALUE;
    
    tid.process = task_pid(current);

#ifndef CONFIG_RSBAC_MAINT
    /* check flags */
    if (rsbac_get_attr(SW_MAC,
                       T_PROCESS,
                       tid,
                       A_mac_process_flags,
                       &attr_val1,
                       FALSE))
      { /* failed! */
        rsbac_ds_get_error("rsbac_mac_set_curr_level", A_none);
        return(-RSBAC_EREADFAILED);
      }
    flags = attr_val1.mac_process_flags;
    if(   !(flags & MAC_auto)
       && !(flags & MAC_trusted)
       && !(flags & MAC_override)
      )
      {
        rsbac_printk(KERN_INFO
                     "rsbac_mac_set_curr_level(): uid %u, pid %u/%.15s: no auto, trusted or override -> not granted \n",
                     current_uid(),
                     current->pid,
                     current->comm);
        #ifdef CONFIG_RSBAC_SOFTMODE
        if(   !rsbac_softmode
        #ifdef CONFIG_RSBAC_SOFTMODE_IND
           && !rsbac_ind_softmode[SW_MAC]
        #endif
          )
        #endif
          return -EPERM;
      }

    /* override allows full range */
    if(!(flags & MAC_override))
      {
        if(level != SL_none)
          {
            /* get maximum security level */
            tid.process = task_pid(current);
            if (rsbac_get_attr(SW_MAC,
                               T_PROCESS,
                               tid,
                               A_security_level,
                               &attr_val1,
                               FALSE))
              { /* failed! */
                rsbac_ds_get_error("rsbac_mac_set_curr_level", A_none);
                return(-RSBAC_EREADFAILED);
              }
            /* if level is too high -> error */
            if (level > attr_val1.security_level)
              {
                rsbac_printk(KERN_INFO
                             "rsbac_mac_set_curr_level(): uid %u, pid %u/%.15s: requested level %u over max level %u, no override -> not granted \n",
                             current_uid(),
                             current->pid,
                             current->comm,
                             level,
                             attr_val1.security_level);
                #ifdef CONFIG_RSBAC_SOFTMODE
                if(   !rsbac_softmode
                #ifdef CONFIG_RSBAC_SOFTMODE_IND
                   && !rsbac_ind_softmode[SW_MAC]
                #endif
                  )
                #endif
                  return -EPERM;
              }
            /* get minimum security level */
            tid.process = task_pid(current);
            if (rsbac_get_attr(SW_MAC,
                               T_PROCESS,
                               tid,
                               A_min_security_level,
                               &attr_val1,
                               FALSE))
              { /* failed! */
                rsbac_ds_get_error("rsbac_mac_set_curr_level", A_none);
                return(-RSBAC_EREADFAILED);
              }
            /* if level is too low -> error */
            if (level < attr_val1.security_level)
              {
                rsbac_printk(KERN_INFO
                             "rsbac_mac_set_curr_level(): uid %u, pid %u/%.15s: requested level %u under min level %u, no override -> not granted \n",
                             current_uid(),
                             current->pid,
                             current->comm,
                             level,
                             attr_val1.security_level);
                #ifdef CONFIG_RSBAC_SOFTMODE
                if(   !rsbac_softmode
                #ifdef CONFIG_RSBAC_SOFTMODE_IND
                   && !rsbac_ind_softmode[SW_MAC]
                #endif
                  )
                #endif
                  return -EPERM;
              }

            /* auto needed? -> stay inside boundaries */
            if(!(flags & MAC_trusted))
              {
                /* check against upper/write boundary */ 
                if (rsbac_get_attr(SW_MAC,
                                   T_PROCESS,
                                   tid,
                                   A_min_write_open,
                                   &attr_val1,
                                   FALSE))
                  { /* failed! */
                    rsbac_ds_get_error("rsbac_mac_set_curr_level", A_none);
                    return(-RSBAC_EREADFAILED);
                  }
                if (level > attr_val1.min_write_open)
                  {
                    rsbac_printk(KERN_INFO
                                 "rsbac_mac_set_curr_level(): uid %u, pid %u/%.15s: requested level %u over min_write_open %u, no override or trusted -> not granted \n",
                                 current_uid(),
                                 current->pid,
                                 current->comm,
                                 level,
                                 attr_val1.min_write_open);
                    #ifdef CONFIG_RSBAC_SOFTMODE
                    if(   !rsbac_softmode
                    #ifdef CONFIG_RSBAC_SOFTMODE_IND
                       && !rsbac_ind_softmode[SW_MAC]
                    #endif
                      )
                    #endif
                      return -EPERM;
                  }

                /* check against lower/read boundary */ 
                if (rsbac_get_attr(SW_MAC,
                                   T_PROCESS,
                                   tid,
                                   A_max_read_open,
                                   &attr_val1,
                                   FALSE))
                  { /* failed! */
                    rsbac_ds_get_error("rsbac_mac_set_curr_level", A_none);
                    return(-RSBAC_EREADFAILED);
                  }
                if (level < attr_val1.max_read_open)
                  return(-EPERM);
              }
          }
        if(categories != RSBAC_MAC_MIN_CAT_VECTOR)
          {
            /* get maximum categories */
            tid.process = task_pid(current);
            if (rsbac_get_attr(SW_MAC,
                               T_PROCESS,
                               tid,
                               A_mac_categories,
                               &attr_val1,
                               FALSE))
              { /* failed! */
                rsbac_ds_get_error("rsbac_mac_set_curr_level", A_none);
                return(-RSBAC_EREADFAILED);
              }
            /* if categories are no subset -> error */
            if ((categories & attr_val1.mac_categories) != categories)
              {
                char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

                if(tmp)
                  {
                    char * tmp2 = rsbac_kmalloc(RSBAC_MAXNAMELEN);

                    if(tmp2)
                      {
                        rsbac_printk(KERN_INFO
                                     "rsbac_mac_set_curr_level(): uid %u, pid %u/%.15s: requested categories %s over max categories %s, no override -> not granted \n",
                                     current_uid(),
                                     current->pid,
                                     current->comm,
                                     u64tostrmac(tmp, categories),
                                     u64tostrmac(tmp2, attr_val1.mac_categories));
                        rsbac_kfree(tmp2);
                      }
                    rsbac_kfree(tmp);
                  }
                #ifdef CONFIG_RSBAC_SOFTMODE
                if(   !rsbac_softmode
                #ifdef CONFIG_RSBAC_SOFTMODE_IND
                   && !rsbac_ind_softmode[SW_MAC]
                #endif
                  )
                #endif
                  return -EPERM;
              }
            /* get minimum categories */
            tid.process = task_pid(current);
            if (rsbac_get_attr(SW_MAC,
                               T_PROCESS,
                               tid,
                               A_mac_min_categories,
                               &attr_val1,
                               FALSE))
              { /* failed! */
                rsbac_ds_get_error("rsbac_mac_set_curr_level", A_none);
                return(-RSBAC_EREADFAILED);
              }
            /* if level is too low -> error */
            if ((categories & attr_val1.mac_categories) != attr_val1.mac_categories)
              {
                char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

                if(tmp)
                  {
                    char * tmp2 = rsbac_kmalloc(RSBAC_MAXNAMELEN);

                    if(tmp2)
                      {
                        rsbac_printk(KERN_INFO
                                     "rsbac_mac_set_curr_level(): uid %u, pid %u/%.15s: requested categories %s under min categories %s, no override -> not granted \n",
                                     current_uid(),
                                     current->pid,
                                     current->comm,
                                     u64tostrmac(tmp, categories),
                                     u64tostrmac(tmp2, attr_val1.mac_categories));
                        rsbac_kfree(tmp2);
                      }
                    rsbac_kfree(tmp);
                  }
                #ifdef CONFIG_RSBAC_SOFTMODE
                if(   !rsbac_softmode
                #ifdef CONFIG_RSBAC_SOFTMODE_IND
                   && !rsbac_ind_softmode[SW_MAC]
                #endif
                  )
                #endif
                  return -EPERM;
              }

            /* auto needed? -> stay inside boundaries */
            if(!(flags & MAC_trusted))
              {
                /* check against upper/write boundary */ 
                if (rsbac_get_attr(SW_MAC,
                                   T_PROCESS,
                                   tid,
                                   A_min_write_categories,
                                   &attr_val1,
                                   FALSE))
                  { /* failed! */
                    rsbac_ds_get_error("rsbac_mac_set_curr_level", A_none);
                    return(-RSBAC_EREADFAILED);
                  }
                if ((categories & attr_val1.mac_categories) != categories)
                  {
                    char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

                    if(tmp)
                      {
                        char * tmp2 = rsbac_kmalloc(RSBAC_MAXNAMELEN);

                        if(tmp2)
                          {
                            rsbac_printk(KERN_INFO
                                         "rsbac_mac_set_curr_level(): uid %u, pid %u/%.15s: requested categories %s over min_write categories %s, no override or trusted -> not granted \n",
                                         current_uid(),
                                         current->pid,
                                         current->comm,
                                         u64tostrmac(tmp, categories),
                                         u64tostrmac(tmp2, attr_val1.mac_categories));
                            rsbac_kfree(tmp2);
                          }
                        rsbac_kfree(tmp);
                      }
                    #ifdef CONFIG_RSBAC_SOFTMODE
                    if(   !rsbac_softmode
                    #ifdef CONFIG_RSBAC_SOFTMODE_IND
                       && !rsbac_ind_softmode[SW_MAC]
                    #endif
                      )
                    #endif
                      return -EPERM;
                  }
                /* check against lower/read boundary */ 
                if (rsbac_get_attr(SW_MAC,
                                   T_PROCESS,
                                   tid,
                                   A_max_read_categories,
                                   &attr_val1,
                                   FALSE))
                  { /* failed! */
                    rsbac_ds_get_error("rsbac_mac_set_curr_level", A_none);
                    return(-RSBAC_EREADFAILED);
                  }
                if ((categories & attr_val1.mac_categories) != attr_val1.mac_categories)
                  {
                    char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

                    if(tmp)
                      {
                        char * tmp2 = rsbac_kmalloc(RSBAC_MAXNAMELEN);

                        if(tmp2)
                          {
                            rsbac_printk(KERN_INFO
                                         "rsbac_mac_set_curr_level(): uid %u, pid %u/%.15s: requested categories %s under max_read categories %s, no override or trusted -> not granted \n",
                                         current_uid(),
                                         current->pid,
                                         current->comm,
                                         u64tostrmac(tmp, categories),
                                         u64tostrmac(tmp2, attr_val1.mac_categories));
                            rsbac_kfree(tmp2);
                          }
                        rsbac_kfree(tmp);
                      }
                    #ifdef CONFIG_RSBAC_SOFTMODE
                    if(   !rsbac_softmode
                    #ifdef CONFIG_RSBAC_SOFTMODE_IND
                       && !rsbac_ind_softmode[SW_MAC]
                    #endif
                      )
                    #endif
                      return -EPERM;
                  }
              }
          }
      }
#endif /* ifndef CONFIG_RSBAC_MAINT */

    /* OK, checks passed: set values */
    if(level != SL_none)
      {
        attr_val1.current_sec_level = level;
        if (rsbac_set_attr(SW_MAC,
                           T_PROCESS,
                           tid,
                           A_current_sec_level,
                           attr_val1))
          { /* failed! */
            rsbac_ds_set_error("rsbac_mac_set_curr_level", A_none);
            return(-RSBAC_EWRITEFAILED);
          }
      }
    if(categories != RSBAC_MAC_MIN_CAT_VECTOR)
      {
        attr_val1.mac_categories = categories;
        if (rsbac_set_attr(SW_MAC,
                           T_PROCESS,
                           tid,
                           A_mac_curr_categories,
                           attr_val1))
          { /* failed! */
            rsbac_ds_set_error("rsbac_mac_set_curr_level", A_none);
            return(-RSBAC_EWRITEFAILED);
          }
      }
    return(0);
  }

/*  getting own levels as well - no restrictions */
int  rsbac_mac_get_curr_level(rsbac_security_level_t * level_p,
                              rsbac_mac_category_vector_t * categories_p)
  {
    union rsbac_target_id_t       tid;
    union rsbac_attribute_value_t attr_val;

    tid.process = task_pid(current);
    if(level_p)
      {
        if (rsbac_get_attr(SW_MAC,
                           T_PROCESS,
                           tid,
                           A_current_sec_level,
                           &attr_val,
                           FALSE))
          { /* failed! */
            rsbac_ds_get_error("rsbac_mac_get_curr_level", A_none);
            return(-RSBAC_EREADFAILED);
          }
        *level_p = attr_val.current_sec_level;
      }
    if(categories_p)
      {
        if (rsbac_get_attr(SW_MAC,
                           T_PROCESS,
                           tid,
                           A_mac_curr_categories,
                           &attr_val,
                           FALSE))
          { /* failed! */
            rsbac_ds_get_error("rsbac_mac_get_curr_level", A_none);
            return(-RSBAC_EREADFAILED);
          }
        *categories_p = attr_val.mac_categories;
      }
    return 0;
  }

int  rsbac_mac_get_max_level(rsbac_security_level_t * level_p,
                              rsbac_mac_category_vector_t * categories_p)
  {
    union rsbac_target_id_t       tid;
    union rsbac_attribute_value_t attr_val;

    tid.process = task_pid(current);
    if(level_p)
      {
        if (rsbac_get_attr(SW_MAC,
                           T_PROCESS,
                           tid,
                           A_security_level,
                           &attr_val,
                           FALSE))
          { /* failed! */
            rsbac_ds_get_error("rsbac_mac_get_max_level", A_none);
            return(-RSBAC_EREADFAILED);
          }
        *level_p = attr_val.security_level;
      }
    if(categories_p)
      {
        if (rsbac_get_attr(SW_MAC,
                           T_PROCESS,
                           tid,
                           A_mac_categories,
                           &attr_val,
                           FALSE))
          { /* failed! */
            rsbac_ds_get_error("rsbac_mac_get_max_level", A_none);
            return(-RSBAC_EREADFAILED);
          }
        *categories_p = attr_val.mac_categories;
      }
    return 0;
  }


int  rsbac_mac_get_min_level(rsbac_security_level_t * level_p,
                              rsbac_mac_category_vector_t * categories_p)
  {
    union rsbac_target_id_t       tid;
    union rsbac_attribute_value_t attr_val;

    tid.process = task_pid(current);
    if(level_p)
      {
        if (rsbac_get_attr(SW_MAC,
                           T_PROCESS,
                           tid,
                           A_min_security_level,
                           &attr_val,
                           FALSE))
          { /* failed! */
            rsbac_ds_get_error("rsbac_mac_get_min_level", A_none);
            return(-RSBAC_EREADFAILED);
          }
        *level_p = attr_val.security_level;
      }
    if(categories_p)
      {
        if (rsbac_get_attr(SW_MAC,
                           T_PROCESS,
                           tid,
                           A_mac_min_categories,
                           &attr_val,
                           FALSE))
          { /* failed! */
            rsbac_ds_get_error("rsbac_mac_get_min_level", A_none);
            return(-RSBAC_EREADFAILED);
          }
        *categories_p = attr_val.mac_categories;
      }
    return 0;
  }

int rsbac_mac_add_p_tru(
  rsbac_list_ta_number_t ta_number,
  rsbac_pid_t pid,
  rsbac_uid_t uid,
  rsbac_time_t ttl)
  {
/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_MAC
    if(rsbac_switch_mac)
#endif
      {
        if(mac_sys_check_role(SR_security_officer))
          {
            rsbac_printk(KERN_INFO
                   "rsbac_mac_add_p_tru(): adding MAC trusted user %u to process %u denied for process %u!\n",
                   uid,
                   pid,
                   current->pid);
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_MAC]
            #endif
              )
            #endif
              return(-EPERM);
          }
      }
#endif

    /* OK, check passed. Add the truability. */
    if(rsbac_mac_add_to_p_truset(ta_number, pid, uid, ttl))
      {
        rsbac_printk(KERN_WARNING
               "rsbac_mac_add_p_tru(): rsbac_mac_add_to_p_truset() returned error!\n");
        return(-RSBAC_EWRITEFAILED);
      }
    return 0;
  }

int rsbac_mac_remove_p_tru(
  rsbac_list_ta_number_t ta_number,
  rsbac_pid_t pid,
  rsbac_uid_t uid)
  {
/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_MAC
    if(rsbac_switch_mac)
#endif
      {
        if(mac_sys_check_role(SR_security_officer))
          {
            rsbac_printk(KERN_INFO
                   "rsbac_mac_remove_p_tru(): removing MAC trusted user %u from process %u denied for process %u!\n",
                   uid,
                   pid,
                   current->pid);
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_MAC]
            #endif
              )
            #endif
              return(-EPERM);
          }
      }
#endif
    /* OK, check passed. Try to remove the trusted user */
    return(rsbac_mac_remove_from_p_truset(ta_number, pid, uid));
  }

int rsbac_mac_add_f_tru(
  rsbac_list_ta_number_t ta_number,
  rsbac_mac_file_t file,
  rsbac_uid_t uid,
  rsbac_time_t ttl)
  {
/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_MAC
    if(rsbac_switch_mac)
#endif
      {
        if(mac_sys_check_role(SR_security_officer))
          {
            rsbac_printk(KERN_INFO
                   "rsbac_mac_add_f_tru(): adding MAC trusted user %u to file %u on device %02u:%02u denied for process %u!\n",
                   uid,
                   file.inode,
                   MAJOR(file.device),
                   MINOR(file.device),
                   current->pid);
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_MAC]
            #endif
              )
            #endif
              return(-EPERM);
          }
      }
#endif

    if(rsbac_mac_add_to_f_truset(ta_number, file, uid, ttl))
      {
        rsbac_printk(KERN_WARNING
               "rsbac_mac_add_f_tru(): rsbac_mac_add_to_f_truset() returned error!\n");
        return(-RSBAC_EWRITEFAILED);
      }
    return 0;
  }

int rsbac_mac_remove_f_tru(
  rsbac_list_ta_number_t ta_number,
  rsbac_mac_file_t file,
  rsbac_uid_t uid)
  {
/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_MAC
    if(rsbac_switch_mac)
#endif
      {
        if(mac_sys_check_role(SR_security_officer))
          {
            rsbac_printk(KERN_INFO
                   "rsbac_mac_remove_f_tru(): removing MAC trusted user %u from file %u on device %02u:%02u denied for process %u!\n",
                   uid,
                   file.inode,
                   MAJOR(file.device),
                   MINOR(file.device),
                   current->pid);
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_MAC]
            #endif
              )
            #endif
              return(-EPERM);
          }
      }
#endif

    return(rsbac_mac_remove_from_f_truset(ta_number, file, uid));
  }


/* end of rsbac/adf/mac/syscalls.c */
