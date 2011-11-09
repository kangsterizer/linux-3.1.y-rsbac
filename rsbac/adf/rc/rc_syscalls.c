/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - Role Compatibility               */
/* File: rsbac/adf/rc/syscalls.c                     */
/*                                                   */
/* Author and (c) 1999-2009: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 29/Jan/2009                        */
/*************************************************** */

#include <linux/string.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/rc.h>
#include <rsbac/adf_main.h>
#include <rsbac/error.h>
#include <rsbac/debug.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/rc_getname.h>
#include <rsbac/rkmem.h>
#include <rsbac/um.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

/************************************************* */
/*           Declarations                          */
/************************************************* */

#if !defined(CONFIG_RSBAC_MAINT)
/* from rsbac/adf/rc/main.c */
int rsbac_rc_test_role_admin(rsbac_boolean_t modify);

int rsbac_rc_test_admin_roles(rsbac_rc_role_id_t t_role, rsbac_boolean_t modify);

enum rsbac_adf_req_ret_t
         rsbac_rc_check_type_comp(enum  rsbac_target_t          target,
                                  rsbac_rc_type_id_t      type,
                            enum  rsbac_adf_request_t     request,
                                  rsbac_pid_t             caller_pid);
#endif

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

/* Here we only check access rights and pass on to rc_data_structures */
int rsbac_rc_sys_copy_role(
  rsbac_list_ta_number_t ta_number,
  rsbac_rc_role_id_t from_role,
  rsbac_rc_role_id_t to_role)
  {
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_RC
    if(rsbac_switch_rc)
#endif
      {
        int                           err;
        /* source role must be in admin roles or caller must be role_admin */
        if (   (err=rsbac_rc_test_admin_roles(from_role, TRUE))
            && rsbac_rc_test_role_admin(TRUE)
           )
          {
            if(err == -EPERM)
              {
                rsbac_uid_t user;

                if(!rsbac_get_owner(&user))
                  {
                    rsbac_printk(KERN_INFO
                                 "rsbac_rc_sys_copy_role(): copying of role %u denied for pid %u, user %u - not in admin_roles!\n",
                                 from_role,
                                 current->pid,
                                 user);
                  }
                #ifdef CONFIG_RSBAC_SOFTMODE
                if(   !rsbac_softmode
                #ifdef CONFIG_RSBAC_SOFTMODE_IND
                   && !rsbac_ind_softmode[SW_RC]
                #endif
                  )
                #endif
                  return err;
              }
            else
              return err;
          }
        /* only role_admins may copy to existing targets */
        if (   rsbac_rc_role_exists(ta_number, to_role)
            && rsbac_rc_test_role_admin(TRUE)
           )
          {
            rsbac_uid_t user;

            if(!rsbac_get_owner(&user))
              {
                rsbac_printk(KERN_INFO
                             "rsbac_rc_sys_copy_role(): overwriting of existing role %u denied for pid %u, user %u - no role_admin!\n",
                             to_role,
                             current->pid,
                             user);
              }
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_RC]
            #endif
              )
            #endif
              return -EPERM;
          }
      }
#endif /* !MAINT */

    /* pass on */
    return(rsbac_rc_copy_role(ta_number, from_role, to_role));
  }

/* Here we only check access rights and pass on to rc_data_structures */
int rsbac_rc_sys_copy_type (
        rsbac_list_ta_number_t ta_number,
  enum  rsbac_target_t      target,
        rsbac_rc_type_id_t     from_type,
        rsbac_rc_type_id_t     to_type)
  {
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_RC
    if(rsbac_switch_rc)
#endif
      {
        int err;

        switch(target)
          {
            case T_FILE:
            case T_DIR:
            case T_FIFO:
            case T_SYMLINK:
              target = T_FD;
              break;
            case T_FD:
            case T_DEV:
            case T_USER:
            case T_PROCESS:
            case T_IPC:
            case T_GROUP:
            case T_NETDEV:
            case T_NETTEMP:
            case T_NETOBJ:
              break;

            default:
              return -RSBAC_EINVALIDTARGET;
          }
        /* need ADMIN right to source type or caller must be role_admin */
        if(   (rsbac_rc_check_type_comp(target, from_type, RCR_ADMIN, 0) != GRANTED)
           && (err=rsbac_rc_test_role_admin(FALSE))
          )
          {
            if(err == -EPERM)
              {
                rsbac_uid_t user;

                if(!rsbac_get_owner(&user))
                  {
                    char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

                    if(tmp)
                      {
                        rsbac_printk(KERN_INFO
                                     "rsbac_rc_sys_copy_type(): copying of %s type %u denied for pid %u, user %u - not in admin_roles!\n",
                                     get_target_name_only(tmp, target),
                                     from_type,
                                     current->pid,
                                     user);
                        rsbac_kfree(tmp);
                      }
                  }
                #ifdef CONFIG_RSBAC_SOFTMODE
                if(   !rsbac_softmode
                #ifdef CONFIG_RSBAC_SOFTMODE_IND
                   && !rsbac_ind_softmode[SW_RC]
                #endif
                  )
                #endif
                  return err;
              }
            else
              return err;
          }
        /* only role_admins may copy to existing targets */
        if (   rsbac_rc_type_exists(ta_number, target, to_type)
            && rsbac_rc_test_role_admin(TRUE)
           )
          {
            rsbac_uid_t user;

            if(!rsbac_get_owner(&user))
              {
                char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

                if(tmp)
                  {
                    rsbac_printk(KERN_INFO
                                 "rsbac_rc_sys_copy_type(): overwriting of existing %s type %u denied for pid %u, user %u - no role_admin!\n",
                                 get_target_name_only(tmp, target),
                                 to_type,
                                 current->pid,
                                 user);
                    rsbac_kfree(tmp);
                  }
              }
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_RC]
            #endif
              )
            #endif
              return -EPERM;
          }
      }
#endif /* !MAINT */

    /* pass on */
    return(rsbac_rc_copy_type(ta_number, target, from_type, to_type));
  }

/* Getting values */
int rsbac_rc_sys_get_item(
        rsbac_list_ta_number_t ta_number,
  enum  rsbac_rc_target_t       target,
  union rsbac_rc_target_id_t    tid,
  union rsbac_rc_target_id_t    subtid,
  enum  rsbac_rc_item_t         item,
  union rsbac_rc_item_value_t * value_p,
        rsbac_time_t          * ttl_p)
  {
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_RC
    if(rsbac_switch_rc)
#endif
      {
        int                           err;

        switch(item)
          {
            case RI_name:
            case RI_type_fd_name:
            case RI_type_dev_name:
            case RI_type_ipc_name:
            case RI_type_user_name:
            case RI_type_process_name:
            case RI_type_scd_name:
            case RI_type_group_name:
            case RI_type_netdev_name:
            case RI_type_nettemp_name:
            case RI_type_netobj_name:
              /* getting names is always allowed */
              break;

            case RI_type_fd_need_secdel:
              if(target != RT_TYPE)
                return -RSBAC_EINVALIDTARGET;
              if(   (err=rsbac_rc_check_type_comp(T_FILE, tid.type, RCR_ADMIN, 0))
                 && (err=rsbac_rc_test_role_admin(FALSE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_get_item(): reading fd_need_secdel of type %u denied for pid %u, user %u - no ADMIN right!\n",
                                       tid.type,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;

            default:
              if(target != RT_ROLE)
                return -RSBAC_EINVALIDATTR;
              /* test admin_roles or admin_type of process' role / no modify */
              if (   (err=rsbac_rc_test_admin_roles(tid.role, FALSE))
                  && (err=rsbac_rc_test_role_admin(FALSE))
                 )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_get_item(): getting item of role %u denied for pid %u, user %u - not in admin_roles!\n",
                                       tid.role,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
          }
      }
#endif /* !MAINT */

    /* pass on */
    return(rsbac_rc_get_item(ta_number,target, tid, subtid, item, value_p, ttl_p));
  }

/* Setting values */
int rsbac_rc_sys_set_item(
        rsbac_list_ta_number_t ta_number,
  enum  rsbac_rc_target_t       target,
  union rsbac_rc_target_id_t    tid,
  union rsbac_rc_target_id_t    subtid,
  enum  rsbac_rc_item_t         item,
  union rsbac_rc_item_value_t   value,
        rsbac_time_t            ttl)
  {
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_RC
    if(rsbac_switch_rc)
#endif
      {
        int                           err;

        switch(item)
          {
          /* type targets */
            case RI_type_fd_name:
            case RI_type_fd_need_secdel:
            case RI_type_fd_remove:
              if(target != RT_TYPE)
                return -RSBAC_EINVALIDTARGET;
              if(   (rsbac_rc_check_type_comp(T_FILE, tid.type, RCR_ADMIN, 0) == NOT_GRANTED)
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;
                      char tmp[80];

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing %s of FD type %u denied for pid %u, user %u - no ADMIN right!\n",
                                       get_rc_item_name(tmp, item),
                                       tid.type,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;
            case RI_type_dev_name:
            case RI_type_dev_remove:
              if(target != RT_TYPE)
                return -RSBAC_EINVALIDTARGET;
              if(   (rsbac_rc_check_type_comp(T_DEV, tid.type, RCR_ADMIN, 0) == NOT_GRANTED)
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing name or removing of DEV type %u denied for pid %u, user %u - no ADMIN right!\n",
                                       tid.type,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;
            case RI_type_ipc_name:
            case RI_type_ipc_remove:
              if(target != RT_TYPE)
                return -RSBAC_EINVALIDTARGET;
              if(   (rsbac_rc_check_type_comp(T_IPC, tid.type, RCR_ADMIN, 0) == NOT_GRANTED)
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing name or removing of IPC type %u denied for pid %u, user %u - no ADMIN right!\n",
                                       tid.type,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;
            case RI_type_user_name:
            case RI_type_user_remove:
              if(target != RT_TYPE)
                return -RSBAC_EINVALIDTARGET;
              if(   (rsbac_rc_check_type_comp(T_USER, tid.type, RCR_ADMIN, 0) == NOT_GRANTED)
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing name or removing of USER type %u denied for pid %u, user %u - no ADMIN right!\n",
                                       tid.type,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;
            case RI_type_process_name:
            case RI_type_process_remove:
              if(target != RT_TYPE)
                return -RSBAC_EINVALIDTARGET;
              if(   (rsbac_rc_check_type_comp(T_PROCESS, tid.type, RCR_ADMIN, 0) == NOT_GRANTED)
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing name or removing of process type %u denied for pid %u, user %u - no ADMIN right!\n",
                                       tid.type,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;
            case RI_type_scd_name:
              if(target != RT_TYPE)
                return -RSBAC_EINVALIDTARGET;
              if(   (rsbac_rc_check_type_comp(T_SCD, tid.type, RCR_ADMIN, 0) == NOT_GRANTED)
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing name or removing of SCD type %u denied for pid %u, user %u - no ADMIN right!\n",
                                       tid.type,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;
            case RI_type_group_name:
            case RI_type_group_remove:
              if(target != RT_TYPE)
                return -RSBAC_EINVALIDTARGET;
              if(   (rsbac_rc_check_type_comp(T_GROUP, tid.type, RCR_ADMIN, 0) == NOT_GRANTED)
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing name or removing of GROUP type %u denied for pid %u, user %u - no ADMIN right!\n",
                                       tid.type,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;
            case RI_type_netdev_name:
            case RI_type_netdev_remove:
              if(target != RT_TYPE)
                return -RSBAC_EINVALIDTARGET;
              if(   (rsbac_rc_check_type_comp(T_NETDEV, tid.type, RCR_ADMIN, 0) == NOT_GRANTED)
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing name or removing of NETDEV type %u denied for pid %u, user %u - no ADMIN right!\n",
                                       tid.type,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;
            case RI_type_nettemp_name:
            case RI_type_nettemp_remove:
              if(target != RT_TYPE)
                return -RSBAC_EINVALIDTARGET;
              if(   (rsbac_rc_check_type_comp(T_NETTEMP, tid.type, RCR_ADMIN, 0) == NOT_GRANTED)
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing name or removing of NETTEMP type %u denied for pid %u, user %u - no ADMIN right!\n",
                                       tid.type,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;
            case RI_type_netobj_name:
            case RI_type_netobj_remove:
              if(target != RT_TYPE)
                return -RSBAC_EINVALIDTARGET;
              if(   (rsbac_rc_check_type_comp(T_NETOBJ, tid.type, RCR_ADMIN, 0) == NOT_GRANTED)
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing name or removing of NETOBJ type %u denied for pid %u, user %u - no ADMIN right!\n",
                                       tid.type,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;

          /* roles only from here */
            case RI_role_comp:
              /* need admin for this role, assign for changed compatible roles */
              {
                union rsbac_target_id_t       i_tid;
                union rsbac_attribute_value_t i_attr_val1;

                if(target != RT_ROLE)
                  return -RSBAC_EINVALIDATTR;
                if(!rsbac_rc_test_role_admin(TRUE))
                  break;
                /* test admin_role of process / modify */
                if((err=rsbac_rc_test_admin_roles(tid.role, TRUE)))
                  {
                    if(err == -EPERM)
                      {
                        rsbac_uid_t user;

                        if(!rsbac_get_owner(&user))
                          {
                            rsbac_printk(KERN_INFO
                                         "rsbac_rc_sys_set_item(): changing role_comp of role %u denied for pid %u, user %u - not in admin_roles!\n",
                                         tid.role,
                                         current->pid,
                                         user);
                          }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                  }
                /* now check assign for changed comp role. */
                /* get rc_role of process */
                i_tid.process = task_pid(current);
                if ((err=rsbac_get_attr(SW_RC, T_PROCESS,
                                        i_tid,
                                        A_rc_role,
                                        &i_attr_val1,
                                        TRUE)))
                  {
                    rsbac_pr_get_error(A_rc_role);
                    return -RSBAC_EREADFAILED;
                  }
                /* check assign_roles of role */
                if (!rsbac_rc_check_comp(i_attr_val1.rc_role,
                                         tid,
                                         RI_assign_roles,
                                         R_NONE))
                  {
                    rsbac_uid_t user;
                    if(!rsbac_get_owner(&user))
                      {
                        rsbac_printk(KERN_INFO
                                     "rsbac_rc_sys_set_item(): changing role_comp for role %u denied for user %u, role %u - not in assign_roles!\n",
                                     tid.role,
                                     user,
                                     i_attr_val1.rc_role);
                      }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                      return -EPERM;
                  }
              }
              break;

            case RI_admin_type:
            case RI_admin_roles:
            case RI_assign_roles:
            case RI_boot_role:
	    case RI_req_reauth:
              /* admin_type role_admin */
              if((err=rsbac_rc_test_role_admin(TRUE)))
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;
                      char tmp[80];

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing %s of role %u denied for pid %u, user %u - no Role Admin!\n",
                                       get_rc_item_name(tmp, item),
                                       tid.role,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;
            case RI_name:
              /* admin for this role */
              /* test admin_role of process / modify */
              if(   (err=rsbac_rc_test_admin_roles(tid.role, TRUE))
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing name of role %u denied for pid %u, user %u - not in admin_roles!\n",
                                       tid.role,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;

            case RI_remove_role:
              /* test admin_role of process role / modify */
              if((err=rsbac_rc_test_role_admin(TRUE)))
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): removing of role %u denied for pid %u, user %u - not in admin_roles!\n",
                                       tid.role,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;

            case RI_def_fd_create_type:
            case RI_def_fd_ind_create_type:
              /* admin for this role and assign for target type */
              /* test admin_role of process / modify */
              if(   (err=rsbac_rc_test_admin_roles(tid.role, TRUE))
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing def_fd_[ind_]create_type of role %u denied for pid %u, user %u - not in admin_roles!\n",
                                       tid.role,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              else
                {
                  enum rsbac_adf_req_ret_t result;

                  result = rsbac_rc_check_type_comp(T_FILE, value.type_id, RCR_ASSIGN, 0);
                  if(   (   (result == NOT_GRANTED)
                         || (result == UNDEFINED)
                        )
                     && (err=rsbac_rc_test_role_admin(TRUE))
                    )
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing def_fd_[ind_]create_type for role %u to %u denied for user %u - no ASSIGN right for type!\n",
                                       tid.role,
                                       value.type_id,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return -EPERM;
                    }
                }
              break;

            case RI_def_fd_ind_create_type_remove:
              /* test admin_role of process / modify */
              if(   (err=rsbac_rc_test_admin_roles(tid.role, TRUE))
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing def_fd_[ind_]create_type of role %u denied for pid %u, user %u - not in admin_roles!\n",
                                       tid.role,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              break;

            case RI_def_user_create_type:
              /* admin for this role and assign for target type */
              /* test admin_role of process / modify */
              if(   (err=rsbac_rc_test_admin_roles(tid.role, TRUE))
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing def_user_create_type of role %u denied for pid %u, user %u - not in admin_roles!\n",
                                       tid.role,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              else
                {
                  enum rsbac_adf_req_ret_t result;

                  result = rsbac_rc_check_type_comp(T_USER, value.type_id, RCR_ASSIGN, 0);
                  if(   (   (result == NOT_GRANTED)
                         || (result == UNDEFINED)
                        )
                     && (err=rsbac_rc_test_role_admin(TRUE))
                    )
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing def_user_create_type for role %u to %u denied for user %u - no ASSIGN right for type!\n",
                                       tid.role,
                                       value.type_id,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return -EPERM;
                    }
                }
              break;

            case RI_def_process_create_type:
            case RI_def_process_chown_type:
            case RI_def_process_execute_type:
              /* admin for this role and assign for target type */
              /* test admin_role of process / modify */
              if(   (err=rsbac_rc_test_admin_roles(tid.role, TRUE))
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;
                      char tmp[80];

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing %s of role %u denied for pid %u, user %u - not in admin_roles!\n",
                                       get_rc_item_name(tmp, item),
                                       tid.role,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              else
                {
                  enum rsbac_adf_req_ret_t result;

                  result = rsbac_rc_check_type_comp(T_PROCESS, value.type_id, RCR_ASSIGN, 0);
                  if(   (   (result == NOT_GRANTED)
                         || (result == UNDEFINED)
                        )
                     && (err=rsbac_rc_test_role_admin(TRUE))
                    )
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing def_process_*_type for role %u to %u denied for user %u - no ASSIGN right for type!\n",
                                       tid.role,
                                       value.type_id,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return -EPERM;
                    }
                }
              break;
            case RI_def_ipc_create_type:
              /* admin for this role and assign for target type */
              /* test admin_role of process / modify */
              if(   (err=rsbac_rc_test_admin_roles(tid.role, TRUE))
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing def_ipc_create_type of role %u denied for pid %u, user %u - not in admin_roles!\n",
                                       tid.role,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              else
                {
                  enum rsbac_adf_req_ret_t result;

                  result = rsbac_rc_check_type_comp(T_IPC, value.type_id, RCR_ASSIGN, 0);
                  if(   (   (result == NOT_GRANTED)
                         || (result == UNDEFINED)
                        )
                     && (err=rsbac_rc_test_role_admin(TRUE))
                    )
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing def_ipc_create_type for role %u to %u denied for user %u - no ASSIGN right for type!\n",
                                       tid.role,
                                       value.type_id,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return -EPERM;
                    }
                }
              break;
            case RI_def_group_create_type:
              /* admin for this role and assign for target type */
              /* test admin_role of process / modify */
              if(   (err=rsbac_rc_test_admin_roles(tid.role, TRUE))
                 && (err=rsbac_rc_test_role_admin(TRUE))
                )
                {
                  if(err == -EPERM)
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing def_group_create_type of role %u denied for pid %u, user %u - not in admin_roles!\n",
                                       tid.role,
                                       current->pid,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return err;
                    }
                  else
                    return err;
                }
              else
                {
                  enum rsbac_adf_req_ret_t result;

                  result = rsbac_rc_check_type_comp(T_GROUP, value.type_id, RCR_ASSIGN, 0);
                  if(   (   (result == NOT_GRANTED)
                         || (result == UNDEFINED)
                        )
                     && (err=rsbac_rc_test_role_admin(TRUE))
                    )
                    {
                      rsbac_uid_t user;

                      if(!rsbac_get_owner(&user))
                        {
                          rsbac_printk(KERN_INFO
                                       "rsbac_rc_sys_set_item(): changing def_group_create_type for role %u to %u denied for user %u - no ASSIGN right for type!\n",
                                       tid.role,
                                       value.type_id,
                                       user);
                        }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                        return -EPERM;
                    }
                }
              break;
            case RI_def_unixsock_create_type:
			/* admin for this role and assign for target type */
			/* test admin_role of process / modify */
			if ((err =
			     rsbac_rc_test_admin_roles(tid.role, TRUE))
			    && (err = rsbac_rc_test_role_admin(TRUE))
			    ) {
				if (err == -EPERM) {
					rsbac_uid_t user;

					if (!rsbac_get_owner(&user)) {
						rsbac_printk(KERN_INFO "rsbac_rc_sys_set_item(): changing def_unixsock_create_type of role %u denied for pid %u, user %u - not in admin_roles\n",
							     tid.role,
							     current->pid,
							     user);
					}
#ifdef CONFIG_RSBAC_SOFTMODE
					if (!rsbac_softmode
#ifdef CONFIG_RSBAC_SOFTMODE_IND
					    && !rsbac_ind_softmode[SW_RC]
#endif
					    )
#endif
						return err;
				} else
					return err;
			} else {
				enum rsbac_adf_req_ret_t result;

				result =
				    rsbac_rc_check_type_comp(T_UNIXSOCK,
							     value.type_id,
							     RCR_ASSIGN,
							     0);
				if (((result == NOT_GRANTED)
				     || (result == UNDEFINED)
				    )
				    && (err =
					rsbac_rc_test_role_admin(TRUE))
				    ) {
					rsbac_uid_t user;

					if (!rsbac_get_owner(&user)) {
						rsbac_printk(KERN_INFO "rsbac_rc_sys_set_item(): changing def_unixsock_create_type for role %u to %u denied for user %u - no ASSIGN right for type\n",
							     tid.role,
							     value.type_id,
							     user);
					}
#ifdef CONFIG_RSBAC_SOFTMODE
					if (!rsbac_softmode
#ifdef CONFIG_RSBAC_SOFTMODE_IND
					    && !rsbac_ind_softmode[SW_RC]
#endif
					    )
#endif
						return -EPERM;
				}
			}
			break;


            case RI_type_comp_fd:
            case RI_type_comp_dev:
            case RI_type_comp_user:
            case RI_type_comp_process:
            case RI_type_comp_ipc:
            case RI_type_comp_scd:
            case RI_type_comp_group:
            case RI_type_comp_netdev:
            case RI_type_comp_nettemp:
            case RI_type_comp_netobj:
              {
                union rsbac_rc_item_value_t old_value, my_value;
                union rsbac_target_id_t       i_tid;
                union rsbac_attribute_value_t i_attr_val1;
                union rsbac_rc_target_id_t    i_rc_tid;

                if(target != RT_ROLE)
                  return -RSBAC_EINVALIDATTR;
                if(!rsbac_rc_test_role_admin(TRUE))
                  break;
                /* test admin_role of process / modify */
                if((err=rsbac_rc_test_admin_roles(tid.role, TRUE)))
                  {
                    if(err == -EPERM)
                      {
                        rsbac_uid_t user;
                        char tmp[80];

                        if(!rsbac_get_owner(&user))
                          {
                            rsbac_printk(KERN_INFO
                                         "rsbac_rc_sys_set_item(): changing %s of role %u denied for pid %u, user %u - not in admin_roles!\n",
                                         get_rc_item_name(tmp, item),
                                         tid.role,
                                         current->pid,
                                         user);
                          }
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   !rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         && !rsbac_ind_softmode[SW_RC]
                      #endif
                        )
                      #endif
                          return err;
                      }
                    else
                      return err;
                  }
                /* test caller's RCR_ACCESS_CONTROL for the type, if we change normal access */
                /* and caller's RCR_SUPERVISOR for the type, if we change special rights */
                /* first get old setting */
                err = rsbac_rc_get_item(ta_number, target, tid, subtid, item, &old_value, NULL);
                if(err)
                  return(err);

                /* get rc_role of process */
                i_tid.process = task_pid(current);
                if ((err=rsbac_get_attr(SW_RC, T_PROCESS,
                                        i_tid,
                                        A_rc_role,
                                        &i_attr_val1,
                                        TRUE)))
                  {
                    rsbac_pr_get_error(A_rc_role);
                    return err;
                  }
                /* get item of process role */
                i_rc_tid.role = i_attr_val1.rc_role;
                if ((err=rsbac_rc_get_item(ta_number,
                                           RT_ROLE,
                                           i_rc_tid,
                                           subtid,
                                           item,
                                           &my_value,
                                           NULL)))
                  {
                    rsbac_rc_pr_get_error(item);
                    return err;
                  }

                /* check planned changes for type */
                if(   /* Want to change normal rights to this type? Need RCR_ACCESS_CONTROL. */
                      (   (   (old_value.rights & RSBAC_ALL_REQUEST_VECTOR)
                           != (value.rights & RSBAC_ALL_REQUEST_VECTOR)
                          )
                       && (!(my_value.rights & RSBAC_RC_RIGHTS_VECTOR(RCR_ACCESS_CONTROL)))
                      )
                   ||    
                      /* Want to change special rights to this type? Need RCR_SUPERVISOR. */
                      (   (   (old_value.rights & RSBAC_RC_SPECIAL_RIGHTS_VECTOR)
                           != (value.rights & RSBAC_RC_SPECIAL_RIGHTS_VECTOR)
                          )
                       && (!(my_value.rights & RSBAC_RC_RIGHTS_VECTOR(RCR_SUPERVISOR)))
                      )
                  )
                  {
                    /* check failed. Last resort: Classical admin_type. */
                    if((err=rsbac_rc_test_role_admin(TRUE)))
                      {
                        if(err == -EPERM)
                          {
                            rsbac_uid_t user;
                            char tmp[80];

                            if(!rsbac_get_owner(&user))
                              {
                                rsbac_printk(KERN_INFO
                                             "rsbac_rc_sys_set_item(): changing %s of role %u denied for pid %u, user %u, role %u - insufficent rights!\n",
                                             get_rc_item_name(tmp, item),
                                             tid.role,
                                             current->pid,
                                             user,
                                             i_attr_val1.rc_role);
                              }
                            #ifdef CONFIG_RSBAC_SOFTMODE
                            if(   !rsbac_softmode
                            #ifdef CONFIG_RSBAC_SOFTMODE_IND
                               && !rsbac_ind_softmode[SW_RC]
                            #endif
                              )
                            #endif
                              return err;
                          }
                        else
                          return err;
                      }
                  }
              }
              break;

            default:
              return -RSBAC_EINVALIDATTR;
          }
      }
#endif /* !MAINT */

    /* pass on */
    return(rsbac_rc_set_item(ta_number, target, tid, subtid, item, value, ttl));
  }

/* Set own role, if allowed ( = in role_comp vector of current role) */
int rsbac_rc_sys_change_role(rsbac_rc_role_id_t role, char *pass)
{
	int err;
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_UM
	union rsbac_rc_item_value_t i_rc_item_val1;
	char *k_pass;
#endif
#endif

#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_RC
	if (rsbac_switch_rc)
#endif
	{
		union rsbac_rc_target_id_t i_rc_subtid;

		i_tid.process = task_pid(current);
		/* get rc_role of process */
		if ((err = rsbac_get_attr(SW_RC,
					  T_PROCESS,
					  i_tid,
					  A_rc_role,
					  &i_attr_val1, TRUE))) {
			rsbac_printk(KERN_WARNING "rsbac_rc_sys_change_role(): rsbac_get_attr() returned error %i\n",
				     err);
			goto out;
		}

		/* check role_comp of role */
		i_rc_subtid.role = role;
		if (!rsbac_rc_check_comp(i_attr_val1.rc_role,
					 i_rc_subtid, RI_role_comp, 0)) {
			rsbac_uid_t user;

			if (!rsbac_get_owner(&user)) {
				rsbac_printk(KERN_INFO "rsbac_rc_sys_change_role(): changing from role %u to %u denied for pid %u, user %u, role %u - roles not compatible\n",
					     i_attr_val1.rc_role,
					     role,
					     pid_nr(i_tid.process),
					     user, i_attr_val1.rc_role);
			}
#ifdef CONFIG_RSBAC_SOFTMODE
			if (!rsbac_softmode
#ifdef CONFIG_RSBAC_SOFTMODE_IND
			    && !rsbac_ind_softmode[SW_RC]
#endif
			    )
#endif
			{
				err = -EPERM;
				goto out;
			}
		}
#ifdef CONFIG_RSBAC_UM
		/* need to make sure UM is compilled in and active
		* XXX what to do about softmode here
		*/
		if ((err = rsbac_rc_get_item(0, RT_ROLE, i_rc_subtid, i_rc_subtid,	
					     RI_req_reauth,
					     &i_rc_item_val1, NULL))) {
			rsbac_printk(KERN_WARNING "rsbac_rc_sys_change_role(): rsbac_rc_get_item() returned error %i\n",
				     err);
			err = -EPERM;
			goto out;
		}
		if (i_rc_item_val1.req_reauth) {
			rsbac_uid_t user;

			if (!pass) {
				rsbac_printk(KERN_WARNING "rsbac_rc_sys_change_role(): password required for switching to role %u\n",
					     role);
				err = -EPERM;
				goto out;
			}
			k_pass = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (!k_pass) {
				err = -RSBAC_ENOMEM;
				goto out;
			}
			err =
			    rsbac_get_user(k_pass, pass, RSBAC_MAXNAMELEN);
			if (err)
				goto out_free;
			k_pass[RSBAC_MAXNAMELEN - 1] = 0;
			err = rsbac_get_owner(&user);
			if (err) {
				rsbac_printk(KERN_WARNING "rsbac_rc_sys_change_role(): rsbac_rc_get_item() returned error %i\n",
					     err);
				goto out_free;
			}
			err = rsbac_um_check_pass(user, k_pass);
			if (err) {
				goto out_free;
			}
		}
#endif

	}
#endif

	/* OK, check passed. Set role. */
	i_tid.process = task_pid(current);
	i_attr_val1.rc_role = role;
	if (rsbac_set_attr(SW_RC, T_PROCESS, i_tid, A_rc_role, i_attr_val1)) {	/* failed! */
		rsbac_printk(KERN_WARNING "rsbac_rc_sys_change_role(): rsbac_set_attr() returned error\n");
		err = -RSBAC_EWRITEFAILED;
	}
	else
		err = 0;

#if !defined(CONFIG_RSBAC_MAINT)
out:
#endif
	return err;

#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_UM
out_free:
	memset(k_pass, 0, RSBAC_MAXNAMELEN);
	rsbac_kfree(k_pass);
	goto out;
#endif
#endif
}

/* Getting own effective rights */
int rsbac_rc_sys_get_eff_rights(
        rsbac_list_ta_number_t ta_number,
  enum  rsbac_target_t       target,
  union rsbac_target_id_t    tid,
        rsbac_rc_request_vector_t * request_vector,
        rsbac_time_t       * ttl_p)
  {
    union rsbac_target_id_t       i_tid;
    enum  rsbac_attribute_t       i_attr = A_none;
    union rsbac_attribute_value_t i_attr_val1;
    union rsbac_attribute_value_t i_attr_val2;
    int                           err;
    enum  rsbac_rc_item_t         i_rc_item;
    union rsbac_rc_target_id_t    i_rc_tid;
    union rsbac_rc_target_id_t    i_rc_subtid;
    union rsbac_rc_item_value_t   i_rc_item_val1;

    i_tid.process = task_pid(current);
    /* get rc_role of process */
    if ((err=rsbac_get_attr(SW_RC, T_PROCESS,
                       i_tid,
                       A_rc_role,
                       &i_attr_val1,
                       TRUE)))
      {
        rsbac_printk(KERN_WARNING
               "rsbac_rc_sys_get_eff_rights(): rsbac_get_attr() returned error %i!\n",err);
        return -RSBAC_EREADFAILED;
      }

    switch(target)
      {
        case T_FILE:
        case T_DIR:
        case T_FIFO:
        case T_SYMLINK:
          i_attr = A_rc_type_fd;
          i_rc_item = RI_type_comp_fd;
          break;
        case T_DEV:
          i_attr = A_rc_type;
          i_rc_item = RI_type_comp_dev;
          break;
        case T_IPC:
          i_attr = A_rc_type;
          i_rc_item = RI_type_comp_ipc;
          break;
        case T_PROCESS:
          i_attr = A_rc_type;
          i_rc_item = RI_type_comp_process;
          break;
        case T_SCD: /* special case! */
          if(tid.scd >= RST_none)
            return -RSBAC_EINVALIDTARGET;
          i_rc_item = RI_type_comp_scd;
          break;
        case T_GROUP:
          i_attr = A_rc_type;
          i_rc_item = RI_type_comp_group;
          break;
        case T_NETDEV:
          i_attr = A_rc_type;
          i_rc_item = RI_type_comp_netdev;
          break;
        case T_NETTEMP:
          i_attr = A_rc_type_nt;
          i_rc_item = RI_type_comp_nettemp;
          break;
        case T_NETOBJ:
          i_attr = A_rc_type;
          i_rc_item = RI_type_comp_netobj;
          break;
        default:
          return -RSBAC_EINVALIDTARGET;
      }
    /* get rc_type of target */
    if(target == T_SCD)
      {
        i_attr_val2.rc_type = tid.scd;
      }
    else
      {
        if ((err=rsbac_get_attr(SW_RC,
                                target,
                                tid,
                                i_attr,
                                &i_attr_val2,
                                TRUE)))
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_rc_sys_get_eff_rights(): rsbac_get_attr() returned error %i!\n",err);
            return -RSBAC_EREADFAILED;
          }
      }
    /* get type_comp_xxx of role for type and target */
    i_rc_tid.role = i_attr_val1.rc_role;
    i_rc_subtid.type = i_attr_val2.rc_type;
    if ((err=rsbac_rc_get_item(ta_number,
                                RT_ROLE,
                                i_rc_tid,
                                i_rc_subtid,
                                i_rc_item,
                                &i_rc_item_val1,
                                ttl_p)))
      {
        rsbac_printk(KERN_WARNING
               "rsbac_rc_sys_get_eff_rights(): rsbac_rc_get_item() returned error %i!\n",err);
        return -RSBAC_EREADFAILED;
      }
    /* extract value */
    *request_vector = i_rc_item_val1.rights;
    /* Ready. */
    return 0;
  }

int rsbac_rc_sys_get_current_role(rsbac_rc_role_id_t * role_p)
  {
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    int err;

    /* get rc_role of process */
    i_tid.process = task_pid(current);
    if ((err=rsbac_get_attr(SW_RC, T_PROCESS,
                       i_tid,
                       A_rc_role,
                       &i_attr_val1,
                       TRUE)))
      {
        rsbac_printk(KERN_WARNING
               "rsbac_rc_sys_get_current_role(): rsbac_get_attr() returned error %i!\n",err);
        return -RSBAC_EREADFAILED;
      }
    *role_p = i_attr_val1.rc_role;
    /* Ready. */
    return 0;
  }

int rsbac_rc_select_fd_create_type(rsbac_rc_type_id_t type)
{

	int res;

	union rsbac_target_id_t tid;
	union rsbac_attribute_value_t attr_val;

	/* sanity checks */
	if (type != RC_type_use_fd) {
		if (!rsbac_rc_type_exists(0, T_FILE, type))
			return -RSBAC_EINVALIDVALUE;
#ifndef CONFIG_RSBAC_MAINT
		if (!rsbac_rc_check_type_comp(T_FILE, type, RCR_SELECT, task_pid(current))) {
#ifdef CONFIG_RSBAC_SOFTMODE
			if(   !rsbac_softmode
#ifdef CONFIG_RSBAC_SOFTMODE_IND
			   && !rsbac_ind_softmode[SW_RC]
#endif
			)
#endif
				return -EPERM;
		}
#endif
	}

	tid.process = task_pid(current);
	attr_val.rc_select_type = type;
	if ((res = rsbac_set_attr(SW_RC,
				  T_PROCESS,
				  tid,
				  A_rc_select_type,
				  attr_val))) {
		rsbac_printk(KERN_WARNING "rsbac_rc_select_fd_create_type(): rsbac_set_attr() returned error %i\n", res);
		return -EPERM;
	}

	return 0;
}

/* end of rsbac/adf/rc/syscalls.c */
