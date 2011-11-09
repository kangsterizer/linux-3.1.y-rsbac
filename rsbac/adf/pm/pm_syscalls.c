/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - Privacy Model                    */
/* File: rsbac/adf/pm/syscalls.c                     */
/*                                                   */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 12/Jul/2011                        */
/*************************************************** */

#include <linux/string.h>
#include <rsbac/aci.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/syscalls.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <rsbac/pm_types.h>
#include <rsbac/pm.h>
#include <rsbac/pm_getname.h>
#include <rsbac/error.h>
#include <rsbac/debug.h>
#include <rsbac/helpers.h>
#include <rsbac/adf.h>
#include <rsbac/adf_main.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

/************************************************* */
/*           Declarations                          */
/************************************************* */


/************************************************* */
/*          Internal Help functions                */
/************************************************* */

static int pm_get_file(const char * name,
                    enum rsbac_target_t * target_p,
                    union rsbac_target_id_t * tid_p)
  {
    int error = 0;
    struct dentry * dentry_p;
    struct path path;

    /* get file dentry */
    if ((error = user_lpath(name, &path)))
      {
#ifdef CONFIG_RSBAC_DEBUG
        if (rsbac_debug_aef_pm)
          rsbac_printk(KERN_DEBUG "pm_get_file(): call to user_lpath() returned %i\n", error);
#endif
        return -RSBAC_EINVALIDTARGET;
      }
      dentry_p = path.dentry;
    if (!dentry_p->d_inode)
      {
#ifdef CONFIG_RSBAC_DEBUG
        if (rsbac_debug_aef_pm)
          rsbac_printk(KERN_DEBUG
                 "pm_get_file(): file not found\n");
#endif
        return -RSBAC_EINVALIDTARGET;
      }
    if(S_ISREG(dentry_p->d_inode->i_mode))
      {
        /* copy device and inode */
        tid_p->file.device = dentry_p->d_sb->s_dev;
        tid_p->file.inode = dentry_p->d_inode->i_ino;
        tid_p->file.dentry_p = dentry_p;
        *target_p = T_FILE;
      }
    else if(S_ISFIFO(dentry_p->d_inode->i_mode))
      {
        /* copy device and inode */
        tid_p->file.device = dentry_p->d_sb->s_dev;
        tid_p->file.inode = dentry_p->d_inode->i_ino;
        tid_p->file.dentry_p = dentry_p;
        *target_p = T_FIFO;
      }
    else if(S_ISBLK(dentry_p->d_inode->i_mode))
      {
        /* copy dev data */
        tid_p->dev.type = D_block;
        tid_p->dev.major = RSBAC_MAJOR(dentry_p->d_inode->i_rdev);
        tid_p->dev.minor = RSBAC_MINOR(dentry_p->d_inode->i_rdev);
        *target_p = T_DEV;
      }
    else if(S_ISCHR(dentry_p->d_inode->i_mode))
      {
        /* copy dev data */
        tid_p->dev.type = D_char;
        tid_p->dev.major = RSBAC_MAJOR(dentry_p->d_inode->i_rdev);
        tid_p->dev.minor = RSBAC_MINOR(dentry_p->d_inode->i_rdev);
        *target_p = T_DEV;
      }
    else
        error = -RSBAC_EINVALIDTARGET;
    /* and free inode */
    dput(dentry_p);
    /* return */
    return error;
  }
  
/************************************************** */
/*          Externally visible functions           */
/************************************************* */

/*****************************************************************************/
/* This function is called via sys_rsbac_pm() system call                    */
/* and serves as a dispatcher for all PM dependant system calls.             */

int rsbac_pm(
        rsbac_list_ta_number_t      ta_number,
  enum  rsbac_pm_function_type_t    function,
  union rsbac_pm_function_param_t   param,
        rsbac_pm_tkt_id_t           tkt)
  {
    union  rsbac_pm_all_data_value_t     all_data;
    enum  rsbac_target_t                 target;
    union rsbac_target_id_t              tid;
    union rsbac_attribute_value_t        attr_val;
    union rsbac_pm_target_id_t           pm_tid;
    union rsbac_pm_target_id_t           pm_tid2;
    union rsbac_pm_data_value_t          data_val;
    int                                  error = 0;
    rsbac_uid_t                          owner;
    enum rsbac_pm_role_t                 role;
    struct rsbac_pm_purpose_list_item_t  pp_set;
    union rsbac_pm_set_id_t              pm_set_id;
    union rsbac_pm_set_member_t          pm_set_member;
    union rsbac_pm_tkt_internal_function_param_t tkt_i_function_param;
    struct rsbac_fs_file_t               file;
    struct rsbac_dev_desc_t              dev;
    char                                 tmp[80];
    struct timespec                      now = CURRENT_TIME;
    rsbac_boolean_t                      class_exists = FALSE;
    
/* No processing possible before init (called at boot time) */
    if (!rsbac_is_initialized())
      return -RSBAC_ENOTINITIALIZED;

    get_pm_function_type_name(tmp,function);
#ifdef CONFIG_RSBAC_DEBUG
    if(rsbac_debug_ds_pm)
      rsbac_printk(KERN_DEBUG
             "rsbac_pm(): called for function %s (No.%i)\n",
             tmp,function);
#endif
    /* Getting basic information about caller */
    /* only useful for real process, not idle or init */
    if (current->pid > 1)
      owner = current_uid();
    else  /* caller_pid <= 1  -> kernel or init are always owned by root */
      owner = 0;

    /* getting owner's pm_role from rsbac system */
    tid.user = owner;
    error = rsbac_ta_get_attr(ta_number,SW_PM,T_USER,tid,A_pm_role,&attr_val,TRUE);
    if (error)
      {
        rsbac_printk(KERN_WARNING
          "rsbac_pm(): rsbac_get_attr() for pm_role returned error %i",
          error);
        return -RSBAC_EREADFAILED;  /* something weird happened */
      }
    role = attr_val.pm_role;

    switch(function)
      {
        case PF_create_ticket:
          /* check, whether this ticket id already exists */
          pm_tid.tkt = param.create_ticket.id;
          if(rsbac_pm_exists(ta_number,
                             PMT_TKT,
                             pm_tid))
            return -RSBAC_EEXISTS;

            /* Check caller's pm_role, if needed, get file id for filename from */
            /* param.x.filename, and copy params to tkt_internal_func_params. */
            /* This part depends on the function the ticket shall be for. */
            switch(param.create_ticket.function_type)
              { 
                case PTF_add_na:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.add_na
                    = param.create_ticket.function_param.add_na;
                  break;
                
                case PTF_delete_na:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.delete_na
                    = param.create_ticket.function_param.delete_na;
                  break;
                
                case PTF_add_task:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.add_task
                    = param.create_ticket.function_param.add_task;
                  break;
                
                case PTF_delete_task:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.delete_task
                    = param.create_ticket.function_param.delete_task;
                  break;
                
                case PTF_add_object_class:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  /* class-id 0, IPC and DEV are used internally, reject */ 
                  if(   !param.create_ticket.function_param.add_object_class.id
                     || (param.create_ticket.function_param.add_object_class.id
                           == RSBAC_PM_IPC_OBJECT_CLASS_ID)
                     || (param.create_ticket.function_param.add_object_class.id
                           == RSBAC_PM_DEV_OBJECT_CLASS_ID))
                    {
                      rsbac_printk(KERN_DEBUG
                             "rsbac_pm(): add_object_class: reserved class-id 0, %u or %u requested!\n",
                             RSBAC_PM_IPC_OBJECT_CLASS_ID,
                             RSBAC_PM_DEV_OBJECT_CLASS_ID);
                      return -RSBAC_EINVALIDVALUE;
                    }
                  /* copy class-id */
                  tkt_i_function_param.tkt_add_object_class.id
                    = param.create_ticket.function_param.add_object_class.id;
                  /* init pp_set-id for this ticket to 0 */
                  tkt_i_function_param.tkt_add_object_class.pp_set
                    = 0;
                  /* get purposes from user space and add them to set */
                  if(param.create_ticket.function_param.add_object_class.pp_list_p)
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if(rsbac_debug_ds_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_pm(): getting pp_list from user space\n");
#endif
                      /* set a unique pp_set-id for this ticket (negative tkt-id) */
                      pm_set_id.pp_set = -param.create_ticket.id;
                      if((error = rsbac_pm_create_set(ta_number,PS_PP,pm_set_id)))
                        {
                          rsbac_printk(KERN_WARNING
                                 "rsbac_pm(): rsbac_pm_create_set() for PP returned error %i",
                                 error);
                          return -RSBAC_EWRITEFAILED;
                        }
                      rsbac_get_user((u_char *) &pp_set,
                                     (u_char *) param.create_ticket.function_param.add_object_class.pp_list_p,
                                     sizeof(pp_set));
                      pm_set_member.pp = pp_set.id;
                      if((error = rsbac_pm_add_to_set(ta_number,PS_PP,pm_set_id,pm_set_member)))
                        {
                          rsbac_printk(KERN_WARNING
                                 "rsbac_pm(): rsbac_pm_add_to_set() for PP returned error %i",
                                 error);
                          rsbac_pm_remove_set(ta_number,PS_PP,pm_set_id);
                          return -RSBAC_EWRITEFAILED;
                        }
               
                      while(pp_set.next)
                        {
                          rsbac_get_user((u_char *) &pp_set,
                                         (u_char *) pp_set.next,
                                         sizeof(pp_set));
                          pm_set_member.pp = pp_set.id;
                          if((error = rsbac_pm_add_to_set(ta_number,PS_PP,pm_set_id,pm_set_member)))
                            {
                              rsbac_printk(KERN_WARNING
                                     "rsbac_pm(): rsbac_pm_add_to_set() for PP returned error %i",
                                     error);
                              rsbac_pm_remove_set(ta_number,PS_PP,pm_set_id);
                              return -RSBAC_EWRITEFAILED;
                            }
                        }
                      tkt_i_function_param.tkt_add_object_class.pp_set
                        = -param.create_ticket.id;
                    }
                  break;
                
                case PTF_delete_object_class:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.delete_object_class
                    = param.create_ticket.function_param.delete_object_class;
                  break;
                
                case PTF_add_authorized_tp:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.add_authorized_tp
                    = param.create_ticket.function_param.add_authorized_tp;
                  break;
                
                case PTF_delete_authorized_tp:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.delete_authorized_tp
                    = param.create_ticket.function_param.delete_authorized_tp;
                  break;
                
                case PTF_add_consent:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  /* get file id */
                  if ((error = pm_get_file(param.create_ticket.function_param.add_consent.filename,
                                        &target,
                                        &tid)))
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if (rsbac_debug_aef_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_pm(): call to pm_get_file() returned error %i\n",
                               error);
#endif
                      return -RSBAC_EINVALIDTARGET;
                    }
                  /* target must be file */
                  if(target != T_FILE)
                    return -RSBAC_EINVALIDTARGET;
                  tkt_i_function_param.tkt_add_consent.file = tid.file;
                  tkt_i_function_param.tkt_add_consent.purpose
                    = param.create_ticket.function_param.add_consent.purpose;
                  break;
                      
                case PTF_delete_consent:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  /* get file id */
                  if ((error = pm_get_file(param.create_ticket.function_param.delete_consent.filename,
                                        &target,
                                        &tid)))
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if (rsbac_debug_aef_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_pm(): call to pm_get_file() returned error %i\n",
                               error);
#endif
                      return -RSBAC_EINVALIDTARGET;
                    }
                  /* target must be file */
                  if(target != T_FILE)
                    return -RSBAC_EINVALIDTARGET;
                  tkt_i_function_param.tkt_delete_consent.file = tid.file;
                  tkt_i_function_param.tkt_delete_consent.purpose
                    = param.create_ticket.function_param.delete_consent.purpose;
                  break;
                      
                case PTF_add_purpose:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.add_purpose
                    = param.create_ticket.function_param.add_purpose;
                  break;
                
                case PTF_delete_purpose:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.delete_purpose
                    = param.create_ticket.function_param.delete_purpose;
                  break;
                
                case PTF_add_responsible_user:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.add_responsible_user
                    = param.create_ticket.function_param.add_responsible_user;
                  break;
                
                case PTF_delete_responsible_user:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.delete_responsible_user
                    = param.create_ticket.function_param.delete_responsible_user;
                  break;
                
                case PTF_delete_user_aci:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.delete_user_aci.id
                    = param.create_ticket.function_param.delete_user_aci.id;
                  break;
                
                case PTF_set_role:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.set_role
                    = param.create_ticket.function_param.set_role;
                  break;
                
                case PTF_set_object_class:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  /* get file id */
                  if ((error = pm_get_file(param.create_ticket.function_param.set_object_class.filename,
                                        &target,
                                        &tid)))
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if (rsbac_debug_aef_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_pm(): call to pm_get_file() returned error %i\n",
                               error);
#endif
                      return -RSBAC_EINVALIDTARGET;
                    }
                  /* target must be file */
                  if(   (target != T_FILE)
                     && (target != T_FIFO)
                    )
                    return -RSBAC_EINVALIDTARGET;
                  tkt_i_function_param.tkt_set_object_class.file = tid.file;
                  tkt_i_function_param.tkt_set_object_class.object_class
                    = param.create_ticket.function_param.set_object_class.object_class;
                  break;

#ifdef CONFIG_RSBAC_SWITCH_PM
                case PTF_switch_pm:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.switch_pm
                    = param.create_ticket.function_param.switch_pm;
                  break;
#endif
#ifdef CONFIG_RSBAC_SWITCH_AUTH
                case PTF_switch_auth:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  tkt_i_function_param.switch_auth
                    = param.create_ticket.function_param.switch_auth;
                  break;
#endif
                
                case PTF_set_device_object_type:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  /* get file id */
                  if ((error = pm_get_file(param.create_ticket.function_param.set_device_object_type.filename,
                                        &target,
                                        &tid)))
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if (rsbac_debug_aef_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_pm(): call to pm_get_file() returned error %i\n",
                               error);
#endif
                      return -RSBAC_EINVALIDTARGET;
                    }
                  /* target must be dev */
                  if(target != T_DEV)
                    return -RSBAC_EINVALIDTARGET;
                  tkt_i_function_param.tkt_set_device_object_type.dev = tid.dev;
                  tkt_i_function_param.tkt_set_device_object_type.object_type
                    = param.create_ticket.function_param.set_device_object_type.object_type;
                  tkt_i_function_param.tkt_set_device_object_type.object_class
                    = param.create_ticket.function_param.set_device_object_type.object_class;
                  break;

                case PTF_set_auth_may_setuid:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  /* get file id */
                  if ((error = pm_get_file(param.create_ticket.function_param.set_auth_may_setuid.filename,
                                        &target,
                                        &tid)))
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if (rsbac_debug_aef_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_pm(): call to pm_get_file() returned error %i\n",
                               error);
#endif
                      return -RSBAC_EINVALIDTARGET;
                    }
                  /* target must be file */
                  if(target != T_FILE)
                    return -RSBAC_EINVALIDTARGET;
                  tkt_i_function_param.tkt_set_auth_may_setuid.file = tid.file;
                  tkt_i_function_param.tkt_set_auth_may_setuid.value
                    = param.create_ticket.function_param.set_auth_may_setuid.value;
                  break;

                case PTF_set_auth_may_set_cap:
                  if(role != PR_data_protection_officer)
                    return -RSBAC_EPERM;
                  /* get file id */
                  if ((error = pm_get_file(param.create_ticket.function_param.set_auth_may_set_cap.filename,
                                        &target,
                                        &tid)))
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if (rsbac_debug_aef_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_pm(): call to pm_get_file() returned error %i\n",
                               error);
#endif
                      return -RSBAC_EINVALIDTARGET;
                    }
                  /* target must be dev */
                  if(target != T_FILE)
                    return -RSBAC_EINVALIDTARGET;
                  tkt_i_function_param.tkt_set_auth_may_set_cap.file = tid.file;
                  tkt_i_function_param.tkt_set_auth_may_set_cap.value
                    = param.create_ticket.function_param.set_auth_may_set_cap.value;
                  break;

                case PTF_add_authorized_task:
                case PTF_delete_authorized_task:
                  /* copy parameters */
                  if(param.create_ticket.function_type
                      == PTF_add_authorized_task)
                    {
                      tkt_i_function_param.add_authorized_task
                        = param.create_ticket.function_param.add_authorized_task;
                    }
                  else
                    {
                      tkt_i_function_param.delete_authorized_task
                        = param.create_ticket.function_param.delete_authorized_task;
                    }
                  /* DPOs are OK */
                  if(role == PR_data_protection_officer)
                    break;
                  /* if not DPO: */
                  /* is process owner responsible user for target task? */
                  /* get ru_set_id for target task */
                  if(param.create_ticket.function_type
                      == PTF_add_authorized_task)
                    {
                      pm_tid.task
                        = param.create_ticket.function_param.add_authorized_task.task;
                    }
                  else
                    {
                      pm_tid.task
                        = param.create_ticket.function_param.delete_authorized_task.task;
                    }
                  if((error = rsbac_pm_get_data(ta_number,
                                                PMT_TASK,
                                                pm_tid,
                                                PD_ru_set,
                                                &data_val)))
                    return -RSBAC_EREADFAILED;
                  /* if ru_set is 0, there is no responsible user -> error */
                  if(!data_val.ru_set)
                    return -RSBAC_EPERM;
                  /* check, whether owner is responsible user for this task */
                  pm_set_id.ru_set = data_val.ru_set;
                  pm_set_member.ru = owner;
                  if(!rsbac_pm_set_member(ta_number,PS_RU,pm_set_id,pm_set_member))
                    {
                      /* illegal issuer -> delete ticket */
                      rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
                      return -RSBAC_EPERM;
                    }
                  /* OK, test passed */
                  break;

                default:
                  /* anything else should never be issued */
                  return -RSBAC_EINVALIDVALUE;
              }

          /* all checks passed -> add ticket */
          all_data.tkt.id     = param.create_ticket.id;
          all_data.tkt.issuer = owner;
          all_data.tkt.function_type  = param.create_ticket.function_type;
          all_data.tkt.function_param = tkt_i_function_param;
          all_data.tkt.valid_until    = param.create_ticket.valid_for + now.tv_sec;
          error = rsbac_pm_add_target(ta_number,
                                      PMT_TKT,
                                      all_data);
          if(error && (param.create_ticket.function_type == PTF_add_object_class))
            {
              rsbac_pm_remove_set(ta_number,PS_PP,pm_set_id);
            }
          return error;
          /* end of create_ticket */

        case PF_add_na:
          if(role != PR_security_officer)
            return -RSBAC_EPERM;
          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_add_na)
             || (all_data.tkt.function_param.add_na.task
                  != param.add_na.task)
             || (all_data.tkt.function_param.add_na.object_class
                  != param.add_na.object_class)
             || (all_data.tkt.function_param.add_na.tp
                  != param.add_na.tp)
             || (all_data.tkt.function_param.add_na.accesses
                  != param.add_na.accesses) )
            return -RSBAC_EPERM;

          /* check, whether task exists */
          pm_tid2.task = param.add_na.task;
          if(!rsbac_pm_exists(ta_number,
                              PMT_TASK,
                              pm_tid2))
            return -RSBAC_EINVALIDVALUE;
          /* check, whether class exists (not for IPC, DEV and NIL) */
          if(   param.add_na.object_class
             && (param.add_na.object_class != RSBAC_PM_IPC_OBJECT_CLASS_ID)
             && (param.add_na.object_class != RSBAC_PM_DEV_OBJECT_CLASS_ID))
            {
              pm_tid2.object_class = param.add_na.object_class;
              if(!rsbac_pm_exists(ta_number,
                                  PMT_CLASS,
                                  pm_tid2))
                return -RSBAC_EINVALIDVALUE;
            }
          /* check, whether tp exists */
          pm_tid2.tp = param.add_na.tp;
          if(!rsbac_pm_exists(ta_number,
                              PMT_TP,
                              pm_tid2))
            return -RSBAC_EINVALIDVALUE;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
              
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> remove target */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
          
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* check: lookup NA accesses for this id */
          pm_tid.na.task = param.add_na.task;
          pm_tid.na.object_class = param.add_na.object_class;
          pm_tid.na.tp = param.add_na.tp;
          error = rsbac_pm_get_data(ta_number,
                                    PMT_NA,
                                    pm_tid,
                                    PD_accesses,
                                    &data_val);
          switch(error)
            { /* if 0 -> found -> set accesses to new value */
              case 0:
                data_val.accesses = param.add_na.accesses;
                rsbac_pm_set_data(ta_number,
                                  PMT_NA,
                                  pm_tid,
                                  PD_accesses,
                                  data_val);
                return 0;
                
              /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found -> add */
              case -RSBAC_EINVALIDTARGET:
              case -RSBAC_ENOTFOUND:
                all_data.na.task = param.add_na.task;
                all_data.na.object_class = param.add_na.object_class;
                all_data.na.tp = param.add_na.tp;
                all_data.na.accesses = param.add_na.accesses;
                if((error = rsbac_pm_add_target(ta_number,
                                                PMT_NA,
                                                all_data)))
                  {
                    rsbac_printk(KERN_WARNING
                           "rsbac_pm(): rsbac_pm_add_target() for NA returned error %i",
                           error);
                    return error;  /* execution failed */
                  }
                return 0;

              default:
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_data() for NA/accesses returned error %i",
                       error);
                return -RSBAC_EREADFAILED;  /* execution failed */
            }
              
        case PF_delete_na:
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_delete_na)
             || (all_data.tkt.function_param.delete_na.task
                  != param.delete_na.task)
             || (all_data.tkt.function_param.delete_na.object_class
                  != param.delete_na.object_class)
             || (all_data.tkt.function_param.delete_na.tp
                  != param.delete_na.tp)
             || (all_data.tkt.function_param.delete_na.accesses
                  != param.delete_na.accesses) )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
          
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> remove target */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
          
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
          /* remove NA */
          pm_tid.na.task = param.delete_na.task;
          pm_tid.na.object_class = param.delete_na.object_class;
          pm_tid.na.tp = param.delete_na.tp;
          return(rsbac_pm_remove_target(ta_number,
                                        PMT_NA,
                                        pm_tid));
            
        case PF_add_task:
          /* task-id 0 is used internally, reject */ 
          if(!param.add_task.id)
            return -RSBAC_EINVALIDVALUE;
          /* purpose-id 0 is invalid, reject */ 
          if(!param.add_task.purpose)
            return -RSBAC_EINVALIDVALUE;

          if(role != PR_security_officer)
            return -RSBAC_EPERM;
          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_add_task)
             || (all_data.tkt.function_param.add_task.id
                  != param.add_task.id)
             || (all_data.tkt.function_param.add_task.purpose
                  != param.add_task.purpose) )
            return -RSBAC_EPERM;

          /* check, whether purpose exists */
          pm_tid2.pp = param.add_task.purpose;
          if(!rsbac_pm_exists(ta_number,
                              PMT_PP,
                              pm_tid2))
            return -RSBAC_EINVALIDVALUE;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
          
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> remove target */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
          
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* try to add task */
          all_data.task.id = param.add_task.id;
          all_data.task.purpose = param.add_task.purpose;
          all_data.task.tp_set = 0;
          all_data.task.ru_set = 0;
          return(rsbac_pm_add_target(ta_number,
                                     PMT_TASK,
                                     all_data));
            
        case PF_delete_task:
          /* task-id 0 is used internally, reject */ 
          if(!param.add_task.id)
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;
          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_delete_task)
             || (all_data.tkt.function_param.delete_task.id
                  != param.delete_task.id) )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> remove target */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* try to delete task */
          pm_tid.task = param.delete_task.id;
          return(rsbac_pm_remove_target(ta_number,
                                        PMT_TASK,
                                        pm_tid));
            
        case PF_add_object_class:
          /* class-id 0/NIL, IPC and DEV are used internally, reject */ 
          if(   !param.add_object_class.id
             || (param.add_object_class.id == RSBAC_PM_IPC_OBJECT_CLASS_ID)
             || (param.add_object_class.id == RSBAC_PM_DEV_OBJECT_CLASS_ID))
            {
              rsbac_printk(KERN_DEBUG
                     "rsbac_pm(): add_object_class: reserved class-id 0, %u or %u requested!\n",
                     RSBAC_PM_IPC_OBJECT_CLASS_ID,
                     RSBAC_PM_DEV_OBJECT_CLASS_ID);
              return -RSBAC_EINVALIDVALUE;
            }
          if(role != PR_security_officer)
            return -RSBAC_EPERM;
          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_add_object_class)
             || (all_data.tkt.function_param.tkt_add_object_class.id
                  != param.add_object_class.id) )
            return -RSBAC_EPERM;
          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
              
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> remove target */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }

          /* check purposes in ticket against those provided */
          if(param.add_object_class.pp_list_p)
            {
              if(!all_data.tkt.function_param.tkt_add_object_class.pp_set)
                {
                  rsbac_printk(KERN_DEBUG
                         "rsbac_pm(): add_object_class: no purpose in tkt\n");
                  return -RSBAC_EINVALIDVALUE;
                }
              pm_set_id.pp_set = all_data.tkt.function_param.tkt_add_object_class.pp_set;
              rsbac_get_user((u_char *) &pp_set,
                             (u_char *) param.add_object_class.pp_list_p,
                             sizeof(pp_set));
              pm_set_member.pp = pp_set.id;
              if(!rsbac_pm_set_member(ta_number,PS_PP,pm_set_id,pm_set_member))
                {
                  rsbac_printk(KERN_DEBUG
                         "rsbac_pm(): add_object_class: first purpose-id %i not in tkt-set\n",
                         pp_set.id);
                  return -RSBAC_EINVALIDVALUE;
                }
               
              while(pp_set.next)
                {
                  rsbac_get_user((u_char *) &pp_set,
                                 (u_char *) pp_set.next,
                                 sizeof(pp_set));
                  pm_set_member.pp = pp_set.id;
                  if(!rsbac_pm_set_member(ta_number,PS_PP,pm_set_id,pm_set_member))
                    {
                      rsbac_printk(KERN_DEBUG
                             "rsbac_pm(): add_object_class: purpose-id %i not in tkt-set\n",
                             pp_set.id);
                      return -RSBAC_EINVALIDVALUE;
                    }
                }
            }
              
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated */
          /* calls and memory waste. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* check, whether class exists */
          pm_tid.object_class = param.add_object_class.id;
          class_exists = rsbac_pm_exists(ta_number,PMT_CLASS, pm_tid);
          if(!class_exists)
            {
              /* try to add class */
              all_data.object_class.id = param.add_object_class.id;
              all_data.object_class.pp_set = 0;
              if((error = rsbac_pm_add_target(ta_number,
                                              PMT_CLASS,
                                              all_data)))
                return error;
            }
           
          /* get purposes from user space and add them to set */
          if(param.add_object_class.pp_list_p)
            {
              pm_set_id.pp_set = param.add_object_class.id;
              if(!class_exists)
                {
                  if(rsbac_pm_create_set(ta_number,PS_PP,pm_set_id))
                    return -RSBAC_EWRITEFAILED;
                }
              else
                {
                  if(rsbac_pm_clear_set(ta_number,PS_PP,pm_set_id))
                    return -RSBAC_EWRITEFAILED;
                }
                
              rsbac_get_user((u_char *) &pp_set,
                             (u_char *) param.add_object_class.pp_list_p,
                             sizeof(pp_set));
              pm_set_member.pp = pp_set.id;
              if(rsbac_pm_add_to_set(ta_number,PS_PP,pm_set_id,pm_set_member))
                {
                  rsbac_printk(KERN_DEBUG
                         "rsbac_pm(): add_object_class: could not add first purpose-id %i to pp_set\n",
                         pp_set.id);
                  return -RSBAC_EWRITEFAILED;
                }
               
              while(pp_set.next)
                {
                  rsbac_get_user((u_char *) &pp_set,
                                 (u_char *) pp_set.next,
                                 sizeof(pp_set));
                  pm_set_member.pp = pp_set.id;
                  if(rsbac_pm_add_to_set(ta_number,PS_PP,pm_set_id,pm_set_member))
                    {
                      rsbac_printk(KERN_DEBUG
                             "rsbac_pm(): add_object_class: could not add purpose-id %i to pp_set\n",
                             pp_set.id);
                      return -RSBAC_EWRITEFAILED;
                    }
                }
              /* notify class item of its pp_set_id */
              pm_tid.object_class = param.add_object_class.id;
              data_val.pp_set = param.add_object_class.id;
              if((error = rsbac_pm_set_data(ta_number,
                                            PMT_CLASS,
                                            pm_tid,
                                            PD_pp_set,
                                            data_val)))
                {
                  rsbac_printk(KERN_DEBUG
                         "rsbac_pm(): add_object_class: could not set pp_set_id for class\n");
                  return -RSBAC_EWRITEFAILED;
                }
            }
          /* ready */
          return 0;
            
        case PF_delete_object_class:
          /* class-id 0/NIL, IPC and DEV are used internally, reject */ 
          if(   !param.delete_object_class.id
             || (param.delete_object_class.id == RSBAC_PM_IPC_OBJECT_CLASS_ID)
             || (param.delete_object_class.id == RSBAC_PM_DEV_OBJECT_CLASS_ID))
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;
          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_delete_object_class)
             || (all_data.tkt.function_param.delete_object_class.id
                  != param.delete_object_class.id) )
            return -RSBAC_EPERM;
          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }

          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> remove target */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }

          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* try to delete class */
          pm_tid.object_class = param.delete_object_class.id;
          return(rsbac_pm_remove_target(ta_number,
                                        PMT_CLASS,
                                        pm_tid));

        case PF_add_authorized_tp:
          /* task-id 0 and tp-id 0 are used internally, reject */ 
          if(!param.add_authorized_tp.task || !param.add_authorized_tp.tp)
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_add_authorized_tp)
             || (all_data.tkt.function_param.add_authorized_tp.task
                  != param.add_authorized_tp.task)
             || (all_data.tkt.function_param.add_authorized_tp.tp
                  != param.add_authorized_tp.tp) )
            return -RSBAC_EPERM;

          /* check, whether task exists */
          pm_tid2.task = param.add_authorized_tp.task;
          if(!rsbac_pm_exists(ta_number,
                              PMT_TASK,
                              pm_tid2))
            return -RSBAC_EINVALIDVALUE;
          /* check, whether tp exists */
          pm_tid2.tp = param.add_authorized_tp.tp;
          if(!rsbac_pm_exists(ta_number,
                              PMT_TP,
                              pm_tid2))
            return -RSBAC_EINVALIDVALUE;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
                {
                  /* illegal issuer -> remove target */
                  rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
                  return -RSBAC_EPERM;
                }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* try to add tp to tp_set of task */
          /* lookup tp_set_id for this task */
          pm_tid.task = param.add_authorized_tp.task;
          if((error = rsbac_pm_get_data(ta_number,
                                        PMT_TASK,
                                        pm_tid,
                                        PD_tp_set,
                                        &data_val)))
            return -RSBAC_EREADFAILED;
          /* if tp_set is 0, it must be created and notified to task-data */
          if(!data_val.tp_set)
            {
              pm_set_id.tp_set = param.add_authorized_tp.task;
              if((error = rsbac_pm_create_set(ta_number,
                                              PS_TP,
                                              pm_set_id)))
                return error;
              data_val.tp_set = param.add_authorized_tp.task;
              if((error = rsbac_pm_set_data(ta_number,
                                            PMT_TASK,
                                            pm_tid,
                                            PD_tp_set,
                                            data_val)))
                return -RSBAC_EWRITEFAILED;
            }
         
         /* now that we know the set exists, try to add tp to it */
         pm_set_id.tp_set = data_val.tp_set;
         pm_set_member.tp = param.add_authorized_tp.tp;
         if(rsbac_pm_add_to_set(ta_number,PS_TP,pm_set_id,pm_set_member))
           return -RSBAC_EWRITEFAILED;
         else
          /* ready */
          return 0;
            
        case PF_delete_authorized_tp:
          /* task-id 0 and tp-id 0 are used internally, reject */ 
          if(!param.delete_authorized_tp.task || !param.delete_authorized_tp.tp)
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_delete_authorized_tp)
             || (all_data.tkt.function_param.delete_authorized_tp.task
                  != param.delete_authorized_tp.task)
             || (all_data.tkt.function_param.delete_authorized_tp.tp
                  != param.delete_authorized_tp.tp) )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
                {
                  /* illegal issuer -> remove target */
                  rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
                  return -RSBAC_EPERM;
                }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* try to remove tp from tp_set of task */
          /* lookup tp_set_id for this task */
          pm_tid.task = param.delete_authorized_tp.task;
          if((error = rsbac_pm_get_data(ta_number,
                                        PMT_TASK,
                                        pm_tid,
                                        PD_tp_set,
                                        &data_val)))
            return -RSBAC_EREADFAILED;
          /* if tp_set is 0, there are no tps to delete -> return */
          if(!data_val.tp_set)
            return -RSBAC_EINVALIDVALUE;
         
         /* now that we know the set exists, try to remove tp from it */
         pm_set_id.tp_set = data_val.tp_set;
         pm_set_member.tp = param.delete_authorized_tp.tp;
         if(rsbac_pm_remove_from_set(ta_number,PS_TP,pm_set_id,pm_set_member))
           return -RSBAC_EWRITEFAILED;
         else
          /* ready */
          return 0;
            
        case PF_add_consent:
          /* purpose_id 0 is used internally, reject */ 
          if(!param.add_consent.purpose)
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* get file id */
          if ((error = pm_get_file(param.add_consent.filename, &target, &tid)) < 0)
            {
#ifdef CONFIG_RSBAC_DEBUG
              if (rsbac_debug_aef_pm)
                rsbac_printk(KERN_DEBUG
                       "rsbac_pm(): call to pm_get_file() returned error %i\n",
                       error);
#endif
              return -RSBAC_EINVALIDTARGET;
            }
          /* target must be file */
          if(target != T_FILE)
            return -RSBAC_EINVALIDTARGET;
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_add_consent)
             || (RSBAC_MAJOR(all_data.tkt.function_param.tkt_add_consent.file.device)
                  != RSBAC_MAJOR(tid.file.device))
             || (RSBAC_MINOR(all_data.tkt.function_param.tkt_add_consent.file.device)
                  != RSBAC_MINOR(tid.file.device))
             || (all_data.tkt.function_param.tkt_add_consent.file.inode
                  != tid.file.inode)
             || (all_data.tkt.function_param.tkt_add_consent.purpose
                  != param.add_consent.purpose) )
            return -RSBAC_EPERM;
          file = tid.file;
          /* check, whether purpose exists */
          pm_tid2.pp = param.add_consent.purpose;
          if(!rsbac_pm_exists(ta_number,
                              PMT_PP,
                              pm_tid2))
            return -RSBAC_EINVALIDVALUE;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> remove target */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* check, whether this consent exists */
          pm_tid.cs.file = file;
          pm_tid.cs.purpose = param.add_consent.purpose;
          if(rsbac_pm_exists(ta_number,
                             PMT_CS,
                             pm_tid))
            return -RSBAC_EEXISTS;
          /* consent does not exist, try to add it */
          all_data.cs.file = file;
          all_data.cs.purpose = param.add_consent.purpose;
          return(rsbac_pm_add_target(ta_number,PMT_CS,all_data));
            
        case PF_delete_consent:
          /* purpose_id 0 is used internally, reject */ 
          if(!param.delete_consent.purpose)
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* get file id */
          if ((error = pm_get_file(param.add_consent.filename, &target, &tid)) < 0)
            {
#ifdef CONFIG_RSBAC_DEBUG
              if (rsbac_debug_aef_pm)
                rsbac_printk(KERN_DEBUG
                       "rsbac_pm(): call to pm_get_file() returned error %i\n",
                       error);
#endif
              return -RSBAC_EINVALIDTARGET;
            }
          /* target must be file */
          if(target != T_FILE)
            return -RSBAC_EINVALIDTARGET;
          file=tid.file;
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_delete_consent)
             || (RSBAC_MAJOR(all_data.tkt.function_param.tkt_delete_consent.file.device)
                  != RSBAC_MAJOR(file.device))
             || (RSBAC_MINOR(all_data.tkt.function_param.tkt_delete_consent.file.device)
                  != RSBAC_MINOR(file.device))
             || (all_data.tkt.function_param.tkt_delete_consent.file.inode
                  != file.inode)
             || (all_data.tkt.function_param.tkt_delete_consent.purpose
                  != param.delete_consent.purpose) )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }

          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> remove target */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* try to delete this consent */
          pm_tid.cs.file = file;
          pm_tid.cs.purpose = param.delete_consent.purpose;
          return(rsbac_pm_remove_target(ta_number,
                                        PMT_CS,
                                        pm_tid));
            
        case PF_add_purpose:
          /* purpose_id 0, classes 0, IPC and DEV are used internally, reject */ 
          if(   !param.add_purpose.id
             || !param.add_purpose.def_class
             || (param.add_purpose.def_class
                  == RSBAC_PM_IPC_OBJECT_CLASS_ID)
             || (param.add_purpose.def_class
                  == RSBAC_PM_DEV_OBJECT_CLASS_ID) )
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_add_purpose)
             || (all_data.tkt.function_param.add_purpose.id
                  != param.add_purpose.id) 
             || (all_data.tkt.function_param.add_purpose.def_class
                  != param.add_purpose.def_class) )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> remove target */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* if def_class does not exist, try to create it */
          pm_tid.object_class = param.add_purpose.def_class;
          if(!rsbac_pm_exists(ta_number,
                              PMT_CLASS,
                              pm_tid))
            {
              /* try to add class */
              all_data.object_class.id = param.add_purpose.def_class;
              all_data.object_class.pp_set = 0;
              if((error = rsbac_pm_add_target(ta_number,
                                              PMT_CLASS,
                                              all_data)))
                return error;
            }
          
          /* try to add purpose */
          all_data.pp.id = param.add_purpose.id;
          all_data.pp.def_class = param.add_purpose.def_class;
          if((error = rsbac_pm_add_target(ta_number,
                                          PMT_PP,
                                          all_data)))
            return error;

          /* add purpose to purpose-set of class */
          /* lookup pp_set_id for this class */
          pm_tid.object_class = param.add_purpose.def_class;
          if((error = rsbac_pm_get_data(ta_number,
                                        PMT_CLASS,
                                        pm_tid,
                                        PD_pp_set,
                                        &data_val)))
            return -RSBAC_EREADFAILED;
          /* if no pp-set: create it and set it in class structure */
          if(!data_val.pp_set)
            {
              pm_set_id.pp_set = param.add_purpose.def_class;
              if(rsbac_pm_create_set(ta_number,PS_PP,pm_set_id))
                return -RSBAC_EWRITEFAILED;
              data_val.pp_set = param.add_purpose.def_class;
              if((error = rsbac_pm_set_data(ta_number,
                                            PMT_CLASS,
                                            pm_tid,
                                            PD_pp_set,
                                            data_val)))
                return -RSBAC_EWRITEFAILED;
            }
         /* now that we know the set exists, try to add purpose to it */
         pm_set_id.pp_set = data_val.pp_set;
         pm_set_member.pp = param.add_purpose.id;
         if(rsbac_pm_add_to_set(ta_number,PS_PP,pm_set_id,pm_set_member))
           return -RSBAC_EWRITEFAILED;
         else
           /* ready */
           return 0;
            
        case PF_delete_purpose:
          /* purpose_id 0 is used internally, reject */ 
          if(!param.delete_purpose.id)
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_delete_purpose)
             || (all_data.tkt.function_param.delete_purpose.id
                  != param.delete_purpose.id) )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> delete ticket */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* try to delete this purpose */
          pm_tid.pp = param.delete_purpose.id;
          return(rsbac_pm_remove_target(ta_number,
                                        PMT_PP,
                                        pm_tid));
            
        case PF_add_responsible_user:
          /* task_id 0 is used internally, reject */ 
          if(!param.add_responsible_user.task)
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_add_responsible_user)
             || (all_data.tkt.function_param.add_responsible_user.user
                  != param.add_responsible_user.user)
             || (all_data.tkt.function_param.add_responsible_user.task
                  != param.add_responsible_user.task) )
            return -RSBAC_EPERM;

          /* check, whether task exists */
          pm_tid2.task = param.add_responsible_user.task;
          if(!rsbac_pm_exists(ta_number,
                              PMT_TASK,
                              pm_tid2))
            return -RSBAC_EINVALIDVALUE;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> delete ticket */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* try to add user to ru_set of task */

          /* lookup ru_set_id for this task */
          pm_tid.task = param.add_responsible_user.task;
          if((error = rsbac_pm_get_data(ta_number,
                                        PMT_TASK,
                                        pm_tid,
                                        PD_ru_set,
                                        &data_val)))
            return -RSBAC_EREADFAILED;
          /* if ru_set is 0, it must be created and notified to task-data */
          if(!data_val.ru_set)
            {
              pm_set_id.ru_set = param.add_responsible_user.task;
              if((error = rsbac_pm_create_set(ta_number,
                                              PS_RU,
                                              pm_set_id)))
              return error;
              data_val.ru_set = param.add_responsible_user.task;
              if((error = rsbac_pm_set_data(ta_number,
                                            PMT_TASK,
                                            pm_tid,
                                            PD_ru_set,
                                            data_val)))
                return -RSBAC_EWRITEFAILED;
            }
         
         /* now that we know the set exists, try to add ru to it */
         pm_set_id.ru_set = data_val.ru_set;
         pm_set_member.ru = param.add_responsible_user.user;
         if(rsbac_pm_add_to_set(ta_number,PS_RU,pm_set_id,pm_set_member))
           return -RSBAC_EWRITEFAILED;
         else
           /* ready */
           return 0;

        case PF_delete_responsible_user:
          /* task_id 0 is used internally, reject */ 
          if(!param.delete_responsible_user.task)
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_delete_responsible_user)
             || (all_data.tkt.function_param.delete_responsible_user.user
                  != param.delete_responsible_user.user)
             || (all_data.tkt.function_param.delete_responsible_user.task
                  != param.delete_responsible_user.task) )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> delete ticket */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
          /* try to add user to ru_set of task */
          /* lookup ru_set_id for this task */
          pm_tid.task = param.delete_responsible_user.task;
          if((error = rsbac_pm_get_data(ta_number,
                                        PMT_TASK,
                                        pm_tid,
                                        PD_ru_set,
                                        &data_val)))
            return -RSBAC_EREADFAILED;
          /* if ru_set is 0, there is nothing to delete */
          if(!data_val.ru_set)
            return -RSBAC_EINVALIDVALUE;
         
          /* now that we know the set exists, try to remove ru from it */
          pm_set_id.ru_set = data_val.ru_set;
          pm_set_member.ru = param.delete_responsible_user.user;
          if(rsbac_pm_remove_from_set(ta_number,PS_RU,pm_set_id,pm_set_member))
            return -RSBAC_EWRITEFAILED;
          else
            /* ready */
            return 0;

        case PF_delete_user_aci:
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_delete_user_aci)
             || (all_data.tkt.function_param.delete_user_aci.id
                  != param.delete_user_aci.id) )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> delete ticket */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
           
          /* OK, all checks done. Now remove aci. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
          tid.user = param.delete_user_aci.id;
          rsbac_ta_remove_target(ta_number,T_USER,tid);
          return 0;
            
        case PF_set_role:
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_set_role)
             || (all_data.tkt.function_param.set_role.user
                  != param.set_role.user)
             || (all_data.tkt.function_param.set_role.role
                  != param.set_role.role) )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> delete ticket */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* try to set role */
          tid.user = param.set_role.user;
          attr_val.pm_role = param.set_role.role;
          return(rsbac_ta_set_attr(ta_number,
                                   SW_PM,
                                   T_USER,
                                   tid,
                                   A_pm_role,
                                   attr_val));
            
        case PF_set_object_class:
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* get file id */
          if ((error = pm_get_file(param.set_object_class.filename, &target, &tid)) < 0)
            {
#ifdef CONFIG_RSBAC_DEBUG
              if (rsbac_debug_aef_pm)
                rsbac_printk(KERN_DEBUG
                       "rsbac_pm(): call to pm_get_file() returned error %i\n",
                       error);
#endif
              return -RSBAC_EINVALIDTARGET;
            }
          /* target must be file */
          if(   (target != T_FILE)
             && (target != T_FIFO)
            )
            return -RSBAC_EINVALIDTARGET;
          file=tid.file;
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_set_object_class)
             || (RSBAC_MAJOR(all_data.tkt.function_param.tkt_set_object_class.file.device)
                  != RSBAC_MAJOR(file.device))
             || (RSBAC_MINOR(all_data.tkt.function_param.tkt_set_object_class.file.device)
                  != RSBAC_MINOR(file.device))
             || (all_data.tkt.function_param.tkt_set_object_class.file.inode
                  != file.inode)
             || (all_data.tkt.function_param.tkt_set_object_class.object_class
                  != param.set_object_class.object_class) )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> delete ticket */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }

          /* get old pm_object_type */
          tid.file = file;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        target,
                                        tid,
                                        A_pm_object_type,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for FILE/FIFO/pm_object_type returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }

          switch(attr_val.pm_object_type)
            {
              case PO_personal_data:
              case PO_none:
              case PO_non_personal_data:
                break;
              default:
                return -RSBAC_EPERM;
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* set new pm_object_type */
          if(param.set_object_class.object_class)
            attr_val.pm_object_type = PO_personal_data;
          else
            attr_val.pm_object_type = PO_non_personal_data;
          if((error = rsbac_ta_set_attr(ta_number,
                                        SW_PM,
                                        target,
                                        tid,
                                        A_pm_object_type,
                                        attr_val)))
            { 
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_set_attr() for FILE/pm_object_type returned error %i",
                     error);
              return -RSBAC_EWRITEFAILED;
            }
          /* set new pm_object_class */
          attr_val.pm_object_class = param.set_object_class.object_class;
          if((error = rsbac_ta_set_attr(ta_number,
                                        SW_PM,
                                        target,
                                        tid,
                                        A_pm_object_class,
                                        attr_val)))
            { 
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_set_attr() for FILE/pm_object_type returned error %i",
                     error);
              return -RSBAC_EWRITEFAILED;
            }
          /* ready */ 
          return 0;

#ifdef CONFIG_RSBAC_SWITCH_PM
        case PF_switch_pm:
          /* only values 0 and 1 are allowed */
          if(param.switch_pm.value && (param.switch_pm.value != 1))
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_switch_pm)
             || (all_data.tkt.function_param.switch_pm.value
                  != param.switch_pm.value))
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> delete ticket */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* switch pm-module */
          rsbac_printk(KERN_WARNING "sys_rsbac_switch(): switching RSBAC module PM (No. %i) to %i!\n",
                 SW_PM, param.switch_pm.value);
          rsbac_switch_pm = param.switch_pm.value;
          return 0; 

#endif
#ifdef CONFIG_RSBAC_SWITCH_AUTH
        case PF_switch_auth:
          /* only values 0 and 1 are allowed */
          if(param.switch_auth.value && (param.switch_auth.value != 1))
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_switch_auth)
             || (all_data.tkt.function_param.switch_auth.value
                  != param.switch_auth.value))
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> delete ticket */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
           
          /* OK, all own checks done. Call ADF for other modules. */
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef_pm)
            rsbac_printk(KERN_DEBUG "rsbac_pm(): calling ADF int\n");
#endif
          tid.dummy = 0;
          attr_val.switch_target = SW_AUTH;
          if (!rsbac_adf_request_int(R_SWITCH_MODULE,
                                     task_pid(current),
                                     T_NONE,
                                     &tid,
                                     A_switch_target,
                                     &attr_val,
                                     SW_PM))
             {
               return -EPERM;
             }

          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* switch auth module */
          rsbac_printk(KERN_WARNING "sys_rsbac_pm/switch(): switching RSBAC module AUTH (No. %i) to %i!\n",
                 SW_AUTH, param.switch_auth.value);
          rsbac_switch_auth = param.switch_auth.value;
          return 0; 
#endif /* SWITCH_AUTH */

        case PF_set_device_object_type:
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* get file id */
          if ((error = pm_get_file(param.set_device_object_type.filename, &target, &tid)) < 0)
            {
#ifdef CONFIG_RSBAC_DEBUG
              if (rsbac_debug_aef_pm)
                rsbac_printk(KERN_DEBUG
                       "rsbac_pm(): call to pm_get_file() returned error %i\n",
                       error);
#endif
              return -RSBAC_EINVALIDTARGET;
            }
          /* target must be dev */
          if(target != T_DEV)
            return -RSBAC_EINVALIDTARGET;
          dev=tid.dev;
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_set_device_object_type)
             || (all_data.tkt.function_param.tkt_set_device_object_type.dev.type
                  != dev.type)
             || (all_data.tkt.function_param.tkt_set_device_object_type.dev.major
                  != dev.major)
             || (all_data.tkt.function_param.tkt_set_device_object_type.dev.minor
                  != dev.minor)
             || (all_data.tkt.function_param.tkt_set_device_object_type.object_type
                  != param.set_device_object_type.object_type)
             || (all_data.tkt.function_param.tkt_set_device_object_type.object_class
                  != param.set_device_object_type.object_class) )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> delete ticket */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }

          switch(param.set_device_object_type.object_type)
            {
              case PO_personal_data:
              case PO_none:
              case PO_TP:
              case PO_non_personal_data:
                break;
              default:
                return -RSBAC_EINVALIDVALUE;
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* set new pm_object_type */
          tid.dev = dev;
          attr_val.pm_object_type = param.set_device_object_type.object_type;
          if((error = rsbac_ta_set_attr(ta_number,
                                        SW_PM,
                                        T_DEV,
                                        tid,
                                        A_pm_object_type,
                                        attr_val)))
            { 
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_set_attr() for DEV/pm_object_type returned error %i",
                     error);
              return -RSBAC_EWRITEFAILED;
            }
          /* set new pm_object_class */
          attr_val.pm_object_class = param.set_device_object_type.object_class;
          if((error = rsbac_ta_set_attr(ta_number,
                                        SW_PM,
                                        T_DEV,
                                        tid,
                                        A_pm_object_class,
                                        attr_val)))
            { 
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_set_attr() for DEV/pm_object_class returned error %i",
                     error);
              return -RSBAC_EWRITEFAILED;
            }
          /* ready */ 
          return 0;

#ifdef CONFIG_RSBAC_AUTH
        case PF_set_auth_may_setuid:
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* get file id */
          if ((error = pm_get_file(param.set_auth_may_setuid.filename, &target, &tid)) < 0)
            {
#ifdef CONFIG_RSBAC_DEBUG
              if (rsbac_debug_aef_pm)
                rsbac_printk(KERN_DEBUG
                       "rsbac_pm(): call to pm_get_file() returned error %i\n",
                       error);
#endif
              return -RSBAC_EINVALIDTARGET;
            }
          /* target must be file */
          if(   (target != T_FILE)
             && (target != T_FIFO)
            )
            return -RSBAC_EINVALIDTARGET;
          file=tid.file;
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_set_auth_may_setuid)
             || (RSBAC_MAJOR(all_data.tkt.function_param.tkt_set_auth_may_setuid.file.device)
                  != RSBAC_MAJOR(file.device))
             || (RSBAC_MINOR(all_data.tkt.function_param.tkt_set_auth_may_setuid.file.device)
                  != RSBAC_MINOR(file.device))
             || (all_data.tkt.function_param.tkt_set_auth_may_setuid.file.inode
                  != file.inode)
             || (all_data.tkt.function_param.tkt_set_auth_may_setuid.value
                  != param.set_auth_may_setuid.value)
            )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> delete ticket */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }

          switch(param.set_auth_may_setuid.value)
            {
              case FALSE:
              case TRUE:
                break;
              default:
                return -RSBAC_EINVALIDVALUE;
            }
          /* OK, all own checks done. Call ADF for other modules. */
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef_pm)
            rsbac_printk(KERN_DEBUG "rsbac_pm(): calling ADF int\n");
#endif
          tid.file = file;
          attr_val.auth_may_setuid = param.set_auth_may_setuid.value;
          if (!rsbac_adf_request_int(R_MODIFY_ATTRIBUTE,
                                     task_pid(current),
                                     T_FILE,
                                     &tid,
                                     A_auth_may_setuid,
                                     &attr_val,
                                     SW_PM))
             {
               return -EPERM;
             }

          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* set new auth_may_setuid */
          if((error = rsbac_ta_set_attr(ta_number,
                                        SW_AUTH,
                                        T_FILE,
                                        tid,
                                        A_auth_may_setuid,
                                        attr_val)))
            { 
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_set_attr() for FILE/auth_may_setuid returned error %i",
                     error);
              return -RSBAC_EWRITEFAILED;
            }
          /* ready */ 
          return 0;

        case PF_set_auth_may_set_cap:
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* get file id */
          if ((error = pm_get_file(param.set_auth_may_set_cap.filename, &target, &tid)) < 0)
            {
#ifdef CONFIG_RSBAC_DEBUG
              if (rsbac_debug_aef_pm)
                rsbac_printk(KERN_DEBUG
                       "rsbac_pm(): call to pm_get_file() returned error %i\n",
                       error);
#endif
              return -RSBAC_EINVALIDTARGET;
            }
          /* target must be file */
          if(target != T_FILE)
            return -RSBAC_EINVALIDTARGET;
          file=tid.file;
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_set_auth_may_set_cap)
             || (RSBAC_MAJOR(all_data.tkt.function_param.tkt_set_auth_may_set_cap.file.device)
                  != RSBAC_MAJOR(file.device))
             || (RSBAC_MINOR(all_data.tkt.function_param.tkt_set_auth_may_set_cap.file.device)
                  != RSBAC_MINOR(file.device))
             || (all_data.tkt.function_param.tkt_set_auth_may_set_cap.file.inode
                  != file.inode)
             || (all_data.tkt.function_param.tkt_set_auth_may_set_cap.value
                  != param.set_auth_may_set_cap.value)
            )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> delete ticket */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }

          switch(param.set_auth_may_set_cap.value)
            {
              case FALSE:
              case TRUE:
                break;
              default:
                return -RSBAC_EINVALIDVALUE;
            }
          /* OK, all own checks done. Call ADF for other modules. */
#ifdef CONFIG_RSBAC_DEBUG
          if (rsbac_debug_aef_pm)
            rsbac_printk(KERN_DEBUG "rsbac_pm(): calling ADF int\n");
#endif
          tid.file = file;
          attr_val.auth_may_set_cap = param.set_auth_may_set_cap.value;
          if (!rsbac_adf_request_int(R_MODIFY_ATTRIBUTE,
                                     task_pid(current),
                                     T_FILE,
                                     &tid,
                                     A_auth_may_set_cap,
                                     &attr_val,
                                     SW_PM))
             {
               return -EPERM;
             }

          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);

          /* set new auth_may_set_cap */
          if((error = rsbac_ta_set_attr(ta_number,
                                        SW_AUTH,
                                        T_FILE,
                                        tid,
                                        A_auth_may_set_cap,
                                        attr_val)))
            { 
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_set_attr() for FILE/auth_may_set_cap returned error %i",
                     error);
              return -RSBAC_EWRITEFAILED;
            }
          /* ready */ 
          return 0;
#endif /* CONFIG_RSBAC_AUTH */

/************/

        case PF_add_authorized_task:
          /* task_id 0 is used internally, reject */ 
          if(!param.add_authorized_task.task)
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            {
#ifdef CONFIG_RSBAC_DEBUG
              if(rsbac_debug_aef_pm)
                rsbac_printk(KERN_DEBUG
                       "rsbac_pm(): caller of add_authorized_task is not SO\n");
#endif
              return -RSBAC_EPERM;
            }

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i\n",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_add_authorized_task)
             || (all_data.tkt.function_param.add_authorized_task.user
                  != param.add_authorized_task.user)
             || (all_data.tkt.function_param.add_authorized_task.task
                  != param.add_authorized_task.task) )
            {
#ifdef CONFIG_RSBAC_DEBUG
              if(rsbac_debug_aef_pm)
                {
                  rsbac_printk(KERN_DEBUG
                         "rsbac_pm(): calling add_authorized_task with invalid ticket\n");
                  rsbac_printk(KERN_DEBUG
                         "rsbac_pm(): tkt-task: %i, tkt-user: %i, call-task: %i, call-user: %i\n",
                         all_data.tkt.function_param.add_authorized_task.user,
                         all_data.tkt.function_param.add_authorized_task.task,
                         param.add_authorized_task.task,
                         param.add_authorized_task.user);
                }
#endif
              return -RSBAC_EPERM;
            }

          /* check, whether task exists */
          pm_tid2.task = param.add_authorized_task.task;
          if(!rsbac_pm_exists(ta_number,
                              PMT_TASK,
                              pm_tid2))
            {
#ifdef CONFIG_RSBAC_DEBUG
              if(rsbac_debug_aef_pm)
                rsbac_printk(KERN_DEBUG
                       "rsbac_pm(): calling add_authorized_task with invalid task id\n");
#endif
              return -RSBAC_EINVALIDVALUE;
            }

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i\n",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            { /* no dpo? -> responsible user? */
              /* get ru_set_id for this task */
              pm_tid.task = param.add_authorized_task.task;
              if((error = rsbac_pm_get_data(ta_number,
                                            PMT_TASK,
                                            pm_tid,
                                            PD_ru_set,
                                            &data_val)))
                return -RSBAC_EREADFAILED;
              /* if ru_set is 0, there is no responsible user -> error */
              if(!data_val.ru_set)
                {
                  /* illegal issuer -> delete ticket */
                  rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
#ifdef CONFIG_RSBAC_DEBUG
                  if(rsbac_debug_aef_pm)
                    rsbac_printk(KERN_DEBUG
                           "rsbac_pm(): calling add_authorized_task with invalid ticket issuer (no set)\n");
#endif
                  return -RSBAC_EPERM;
                }
              /* check, whether issuer is responsible user for this task */
              pm_set_id.ru_set = data_val.ru_set;
              pm_set_member.ru = all_data.tkt.issuer;
              if(!rsbac_pm_set_member(ta_number,PS_RU,pm_set_id,pm_set_member))
                {
                  /* illegal issuer -> delete ticket */
                  rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
#ifdef CONFIG_RSBAC_DEBUG
                  if(rsbac_debug_aef_pm)
                    rsbac_printk(KERN_DEBUG
                           "rsbac_pm(): calling add_authorized_task with invalid ticket issuer\n");
#endif
                  return -RSBAC_EPERM;
                }
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
          /* try to add task to task_set of user */
          /* lookup task_set_id for this user */
          tid.user = param.add_authorized_task.user;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_task_set,
                                        &attr_val,
                                        TRUE)))
            return -RSBAC_EREADFAILED;
          /* if pm_task_set is 0, it must be created and notified to task-data */
          if(!attr_val.pm_task_set)
            { /* set task_set_id to user-id */
              pm_set_id.task_set = param.add_authorized_task.user;
              /* 0 is reserved -> take another one for root */
              if(!pm_set_id.task_set)
                pm_set_id.task_set = RSBAC_PM_ROOT_TASK_SET_ID;
              if((error = rsbac_pm_create_set(ta_number,
                                              PS_TASK,
                                              pm_set_id)))
                return error;
              attr_val.pm_task_set = pm_set_id.task_set;
              if((error = rsbac_ta_set_attr(ta_number,
                                            SW_PM,
                                            T_USER,
                                            tid,
                                            A_pm_task_set,
                                            attr_val)))
                return -RSBAC_EWRITEFAILED;
            }
         
         /* now that we know the set exists, try to add task to it */
         pm_set_id.task_set = attr_val.pm_task_set;
         pm_set_member.task = param.add_authorized_task.task;
         if(rsbac_pm_add_to_set(ta_number,PS_TASK,pm_set_id,pm_set_member))
           return -RSBAC_EWRITEFAILED;
         else
          /* ready */
          return 0;

        case PF_delete_authorized_task:
          /* task_id 0 is used internally, reject */ 
          if(!param.delete_authorized_task.task)
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_security_officer)
            return -RSBAC_EPERM;

          /* get ticket data, deny, if not found */
          pm_tid.tkt = tkt;
          if((error = rsbac_pm_get_all_data(ta_number,
                                            PMT_TKT,
                                            pm_tid,
                                            &all_data)))
            { /* returns error -RSBAC_EINVALIDTARGET (old ds) or ENOTFOUND, if not found */
              if(   (error != -RSBAC_EINVALIDTARGET)
                 && (error != -RSBAC_ENOTFOUND)
                )
                rsbac_printk(KERN_WARNING
                       "rsbac_pm(): rsbac_pm_get_all_data() for ticket returned error %i",
                       error);
              return -RSBAC_EPERM;  /* execution denied */
            }
          /* check ticket entries */
          if(   (all_data.tkt.function_type != PTF_delete_authorized_task)
             || (all_data.tkt.function_param.delete_authorized_task.user
                  != param.delete_authorized_task.user)
             || (all_data.tkt.function_param.delete_authorized_task.task
                  != param.delete_authorized_task.task) )
            return -RSBAC_EPERM;

          /* get ticket issuer role */
          tid.user = all_data.tkt.issuer;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_role,
                                        &attr_val,
                                        TRUE)))
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_pm(): rsbac_get_attr() for USER/pm_role returned error %i",
                     error);
              return -RSBAC_EREADFAILED;  /* execution denied */
            }
            
          if(attr_val.pm_role != PR_data_protection_officer)
            {
              /* illegal issuer -> delete ticket */
              rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
              return -RSBAC_EPERM;
            }
           
          /* OK, all checks done. Now change data. */
          /* First remove ticket to prevent repeated calls. */
          rsbac_pm_remove_target(ta_number,PMT_TKT,pm_tid);
          /* try to remove task from task_set of user */
          /* lookup task_set_id for this user */
          tid.user = param.delete_authorized_task.user;
          if((error = rsbac_ta_get_attr(ta_number,
                                        SW_PM,
                                        T_USER,
                                        tid,
                                        A_pm_task_set,
                                        &attr_val,
                                        TRUE)))
            return -RSBAC_EREADFAILED;
          /* if pm_task_set is 0, there is no task to be deleted -> error */
          if(!attr_val.pm_task_set)
            return -RSBAC_EINVALIDVALUE;
         
         /* now that we know the set exists, try to remove task from it */
         pm_set_id.task_set = attr_val.pm_task_set;
         pm_set_member.task = param.delete_authorized_tp.task;
         if(rsbac_pm_remove_from_set(ta_number,PS_TASK,pm_set_id,pm_set_member))
           return -RSBAC_EWRITEFAILED;
         else
          /* ready */
          return 0;


/************/

        case PF_create_tp:
          /* tp_id 0 is used internally, reject */ 
          if(!param.create_tp.id)
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_tp_manager)
            return -RSBAC_EPERM;

          /* OK, all checks done. Now change data. */
          /* try to add tp */
          all_data.tp.id = param.create_tp.id;
          return(rsbac_pm_add_target(ta_number,PMT_TP,all_data));
            
        case PF_delete_tp:
          /* tp_id 0 is used internally, reject */ 
          if(!param.delete_tp.id)
            return -RSBAC_EINVALIDVALUE;
          if(role != PR_tp_manager)
            return -RSBAC_EPERM;

          /* OK, all checks done. Now change data. */

          /* try to delete tp */
          pm_tid.tp = param.delete_tp.id;
          return(rsbac_pm_remove_target(ta_number,PMT_TP,pm_tid));
            
        case PF_set_tp:
          /* tp_id 0 means set to non-tp, do NOT reject here */ 
          if(role != PR_tp_manager)
            return -RSBAC_EPERM;

          /* if tp != 0, check, whether it is valid */
          if(param.set_tp.tp)
            {
              pm_tid.tp = param.set_tp.tp;
              if(!rsbac_pm_exists(ta_number,PMT_TP,pm_tid))
                return -RSBAC_EINVALIDVALUE;
            }
          
          /* get file id */
          if ((error = pm_get_file(param.set_tp.filename,
                                &target,
                                &tid)))
            {
#ifdef CONFIG_RSBAC_DEBUG
              if (rsbac_debug_aef_pm)
                rsbac_printk(KERN_DEBUG
                       "rsbac_pm(): call to pm_get_file() returned error %i\n",
                       error);
#endif
              return -RSBAC_EINVALIDTARGET;
            }
          /* target must be file */
          if(target != T_FILE)
            return -RSBAC_EINVALIDTARGET;
          file=tid.file;
          /* get old object_type */
          if (rsbac_ta_get_attr(ta_number,
                                SW_PM,
                                T_FILE,
                                tid,
                                A_pm_object_type,
                                &attr_val,
                                TRUE))
            {
              rsbac_printk(KERN_WARNING "rsbac_pm(): rsbac_get_attr() returned error!\n");
              return -RSBAC_EREADFAILED;
            }
          /* if old OT is not to be changed here -> do not allow */
          if(   (attr_val.pm_object_type != PO_TP)
             && (attr_val.pm_object_type != PO_none)
             && (attr_val.pm_object_type != PO_non_personal_data))
            return -RSBAC_EINVALIDTARGET;

          /* OK, all checks done. Now change data. */
          /* try to set OT*/
          if(param.set_tp.tp)
            attr_val.pm_object_type = PO_TP;
          else
            attr_val.pm_object_type = PO_none;
          if(rsbac_ta_set_attr(ta_number,
                               SW_PM,
                               T_FILE,
                               tid,
                               A_pm_object_type,
                               attr_val))
            {
              rsbac_printk(KERN_WARNING "rsbac_pm(): rsbac_set_attr() returned error!\n");
              return -RSBAC_EWRITEFAILED;
            }
          /* try to set tp-id*/
          attr_val.pm_tp = param.set_tp.tp;
          if (rsbac_ta_set_attr(ta_number,
                                SW_PM,
                                T_FILE,
                                tid,
                                A_pm_tp,
                                attr_val))
            {
              rsbac_printk(KERN_WARNING "rsbac_pm(): rsbac_set_attr() returned error!\n");
              return -RSBAC_EWRITEFAILED;
            }
          return 0;

/************/

        default:
          return -RSBAC_EINVALIDREQUEST;
      }
  } /* end of rsbac_pm() */

/***************************************************************************/

int rsbac_pm_change_current_task(rsbac_pm_task_id_t task)
  {
    union rsbac_target_id_t          tid;
    union rsbac_attribute_value_t    attr_val;
    int                              error = 0;
    rsbac_uid_t                      owner;
    union rsbac_pm_set_id_t          pm_set_id;
    union rsbac_pm_set_member_t      pm_set_member;
    
/* No processing possible before init (called at boot time) */
    if (!rsbac_is_initialized())
      return -RSBAC_ENOTINITIALIZED;

      if(!task)
        return -RSBAC_EINVALIDVALUE;
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef_pm)
      rsbac_printk(KERN_DEBUG
             "rsbac_pm_change_current_task(): called for task %i!\n",
             task);
#endif
    /* getting current_tp of calling process from rsbac system */
    tid.process = task_pid(current);
    if((error = rsbac_get_attr(SW_PM,T_PROCESS,
                               tid,
                               A_pm_tp,
                               &attr_val,
                               FALSE)))
      {
        rsbac_printk(KERN_WARNING
          "rsbac_pm_change_current_task(): rsbac_get_attr() for pm_tp returned error %i",
          error);
        return -RSBAC_EREADFAILED;  /* something weird happened */
      }
    /* changing current_task for a tp is forbidden -> error */
    if(attr_val.pm_tp)
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "rsbac_pm_change_current_task(): tried to change current_task for tp-process\n");
#endif
        return -RSBAC_EPERM;
      }
      
    /* Getting basic information about caller */
    /* only useful for real process, not idle or init */
    if (current->pid > 1)
      owner = current_uid();
    else  /* caller_pid <= 1  -> kernel or init are always owned by root */
      owner = 0;

    /* getting owner's task_set_id (authorized tasks) from rsbac system */
    tid.user = owner;
    if((error = rsbac_get_attr(SW_PM,T_USER,
                               tid,
                               A_pm_task_set,
                               &attr_val,
                               TRUE)))
      {
        rsbac_printk(KERN_WARNING
          "rsbac_pm_change_current_task(): rsbac_get_attr() for pm_task_set returned error %i",
          error);
        return -RSBAC_EREADFAILED;  /* something weird happened */
      }
    
    /* if there is no set of authorized tasks for owner: deny */
    if(!attr_val.pm_task_set)
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "rsbac_pm_change_current_task(): process owner has no authorized task\n");
#endif
        return -RSBAC_EPERM;
      }

    /* check, whether owner is authorized for this task */
    pm_set_id.task_set = attr_val.pm_task_set;
    pm_set_member.task = task;
    if(!rsbac_pm_set_member(0,PS_TASK,pm_set_id,pm_set_member))
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "rsbac_pm_change_current_task(): process owner is not authorized for task\n");
#endif
        return -RSBAC_EPERM;
      }
      
    /* OK, checks are passed. Change current_task for process. */    
    tid.process = task_pid(current);
    attr_val.pm_current_task = task;
    if((error = rsbac_set_attr(SW_PM,T_PROCESS,
                               tid,
                               A_pm_current_task,
                               attr_val)))
      {
        rsbac_printk(KERN_WARNING
          "rsbac_pm_change_current_task(): rsbac_set_attr() for pm_current_task returned error %i",
          error);
        return -RSBAC_EWRITEFAILED;  /* something weird happened */
      }
    return 0;
  }

int rsbac_pm_create_file(const char * filename,
                         int mode,
                         rsbac_pm_object_class_id_t object_class)
  {
    union rsbac_target_id_t          tid;
    union rsbac_attribute_value_t    attr_val;
    union rsbac_attribute_value_t    attr_val2;
    union rsbac_pm_target_id_t       pm_tid;
    union rsbac_pm_data_value_t      data_val;
    union rsbac_pm_data_value_t      data_val2;
    int                              error = 0;
    union rsbac_pm_set_id_t          pm_set_id;
    union rsbac_pm_set_member_t      pm_set_member;
  
#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef_pm)
      rsbac_printk(KERN_DEBUG
             "sys_rsbac_pm_create_file(): called with class %i, mode %o!\n",
             object_class, mode);
#endif
    /* do not allow IPC or DEV class */
    if(   (object_class == RSBAC_PM_IPC_OBJECT_CLASS_ID)
       || (object_class == RSBAC_PM_DEV_OBJECT_CLASS_ID))
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "rsbac_pm_create_file(): Class-ID is IPC or DEV\n");
#endif
        return -RSBAC_EINVALIDVALUE;
      }

    /* is mode for regular file? */
    if(mode & ~S_IRWXUGO)
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "rsbac_pm_create_file(): illegal creation mode\n");
#endif
        return -RSBAC_EINVALIDVALUE;
      }

    /* does class exist (NIL always exists)? */
    if(object_class)
      {
        pm_tid.object_class = object_class;
        if(!rsbac_pm_exists(0,
                            PMT_CLASS,
                            pm_tid))
          {
#ifdef CONFIG_RSBAC_DEBUG
            if(rsbac_debug_adf_pm)
              rsbac_printk(KERN_DEBUG
                     "rsbac_pm_create_file(): non-existent class\n");
#endif
            return -RSBAC_EINVALIDVALUE;
          }
      }

    /* getting current_task of calling process from rsbac system */
    tid.process = task_pid(current);
    if((error = rsbac_get_attr(SW_PM,T_PROCESS,
                               tid,
                               A_pm_current_task,
                               &attr_val,
                               FALSE)))
      {
        rsbac_printk(KERN_WARNING
          "rsbac_pm_create_file(): rsbac_get_attr() for pm_current_task returned error %i",
          error);
        return -RSBAC_EREADFAILED;  /* something weird happened */
      }

    /* getting current_tp of calling process from rsbac system */
    if((error = rsbac_get_attr(SW_PM,T_PROCESS,
                               tid,
                               A_pm_tp,
                               &attr_val2,
                               FALSE)))
      {
        rsbac_printk(KERN_WARNING
          "rsbac_pm_create_file(): rsbac_get_attr() for pm_tp returned error %i",
          error);
        return -RSBAC_EREADFAILED;  /* something weird happened */
      }
      
    /* getting neccessary accesses for task, class, tp from PM-data */
    pm_tid.na.task = attr_val.pm_current_task;
    pm_tid.na.object_class = object_class;
    pm_tid.na.tp = attr_val2.pm_tp;
    if((error = rsbac_pm_get_data(0,
                                  PMT_NA,
                                  pm_tid,
                                  PD_accesses,
                                  &data_val)))
      {
        if(   (error != -RSBAC_EINVALIDTARGET)
           && (error != -RSBAC_ENOTFOUND)
          )
          rsbac_printk(KERN_WARNING
                 "rsbac_pm_create_file(): rsbac_pm_get_data() for NA/accesses returned error %i",
                 error);
#ifdef CONFIG_RSBAC_DEBUG
        else if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "rsbac_pm_create_file(): NA/accesses (%i,%i,%i) not found\n",
                 pm_tid.na.task, object_class, pm_tid.na.tp);
#endif
        return -RSBAC_EPERM;  /* deny */
      }

    /* is create necessary? if not -> error */
    if(!(data_val.accesses & RSBAC_PM_A_CREATE))
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "rsbac_pm_create_file(): create is not necessary\n");
#endif
        return -RSBAC_EPERM;
      }

    /* get purpose for current_task */     
    pm_tid.task = attr_val.pm_current_task;
    if((error = rsbac_pm_get_data(0,
                                  PMT_TASK,
                                  pm_tid,
                                  PD_purpose,
                                  &data_val)))
      {
        if(   (error != -RSBAC_EINVALIDTARGET)
           && (error != -RSBAC_ENOTFOUND)
          )
          rsbac_printk(KERN_WARNING
                 "rsbac_pm_create_file(): rsbac_get_data() for TASK/purpose returned error %i",
                 error);
        return -RSBAC_EPERM;  /* deny */
      }

    /* further checks only, if there is a purpose defined */
    if(data_val.purpose)
      {
        /* get purpose_set_id for class */     
        pm_tid.object_class = object_class;
        if((error = rsbac_pm_get_data(0,
                                      PMT_CLASS,
                                      pm_tid,
                                      PD_pp_set,
                                      &data_val2)))
          {
            if(   (error == -RSBAC_EINVALIDTARGET)
               || (error == -RSBAC_ENOTFOUND)
              )
              {
#ifdef CONFIG_RSBAC_DEBUG
                if(rsbac_debug_adf_pm)
                  rsbac_printk(KERN_DEBUG
                         "rsbac_pm_create_file(): non-existent class\n");
#endif
                return -RSBAC_EINVALIDVALUE;
              }
            rsbac_printk(KERN_WARNING
                   "rsbac_pm_create_file(): rsbac_get_data() for TASK/purpose returned error %i",
                   error);
            return -RSBAC_EREADFAILED;  /* deny */
          }
        /* if there is no purpose set for this class, deny */
        if(!data_val2.pp_set)
          {
#ifdef CONFIG_RSBAC_DEBUG
            if(rsbac_debug_adf_pm)
              rsbac_printk(KERN_DEBUG
                     "rsbac_pm_create_file(): current_task has purpose, class not\n");
#endif
            return -RSBAC_EPERM;
          }
      
        /* last check: is our task's purpose in the set of purposes for our class? */
        pm_set_id.pp_set = data_val2.pp_set;
        pm_set_member.pp = data_val.purpose;
        if(!rsbac_pm_set_member(0,PS_PP,pm_set_id,pm_set_member))
          /* our task's purpose does not match with class purposes -> deny */
          {
#ifdef CONFIG_RSBAC_DEBUG
            if(rsbac_debug_adf_pm)
              rsbac_printk(KERN_DEBUG
                     "rsbac_pm_create_file(): purpose of current_task is not in purpose set of class\n");
#endif
            return -RSBAC_EPERM;
          }
      }

    /* try to create object using standard syscalls, leading to general rsbac */
    /* checks via ADF-Request */
    /* we are not using sys_creat(), because alpha kernels don't know it */
    error = sys_open(filename, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (error < 0)
      return error;

    /* setting class for new object */
    rcu_read_lock();
    tid.file.device = current->files->fdt->fd[error]->f_vfsmnt->mnt_sb->s_dev;
    tid.file.inode  = current->files->fdt->fd[error]->f_dentry->d_inode->i_ino;
    tid.file.dentry_p = current->files->fdt->fd[error]->f_dentry;
    rcu_read_unlock();
    attr_val.pm_object_class = object_class;
    if(rsbac_set_attr(SW_PM,T_FILE,
                      tid,
                      A_pm_object_class,
                      attr_val))
      {
        rsbac_printk(KERN_WARNING
          "rsbac_pm_create_file(): rsbac_set_attr() for pm_object_class returned error");
      }
    return error;
  }


/* end of rsbac/adf/pm/syscalls.c */
