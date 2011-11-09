/**************************************************** */
/* Rule Set Based Access Control                      */
/* Implementation of the Access Control Decision      */
/* Facility (ADF) - Authorization module              */
/* File: rsbac/adf/auth/main.c                        */
/*                                                    */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org>  */
/*                                                    */
/* Last modified: 12/Jul/2011                         */
/**************************************************** */

#include <linux/string.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/auth.h>
#include <rsbac/adf_main.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/debug.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

static int  rsbac_replace_auth_cap(rsbac_pid_t caller_pid,
                                   enum rsbac_auth_cap_type_t cap_type,
                                   rsbac_uid_t from,
                                   rsbac_uid_t to)
  {
    if(rsbac_auth_p_capset_member(caller_pid, cap_type, from))
      {
        struct rsbac_auth_cap_range_t cap_range;

        /* remove it and set cap for 'to' */
        cap_range.first = to;
        cap_range.last  = to;
        if (rsbac_auth_add_to_p_capset(0, caller_pid, cap_type, cap_range, 0))
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_adf_set_attr_auth(): rsbac_auth_add_to_p_capset() returned error!\n");
            return -RSBAC_EWRITEFAILED;
          }
        cap_range.first = from;
        cap_range.last  = from;
        if (rsbac_auth_remove_from_p_capset(0, caller_pid, cap_type, cap_range))
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_adf_set_attr_auth(): rsbac_auth_remove_from_p_capset() returned error!\n");
            return -RSBAC_EWRITEFAILED;
          }
      }
    return 0; /* success */
  }

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

inline enum rsbac_adf_req_ret_t
   rsbac_adf_request_auth (enum  rsbac_adf_request_t     request,
                                rsbac_pid_t             caller_pid,
                          enum  rsbac_target_t          target,
                          union rsbac_target_id_t       tid,
                          enum  rsbac_attribute_t       attr,
                          union rsbac_attribute_value_t attr_val,
                                rsbac_uid_t             owner)
  {
    enum  rsbac_adf_req_ret_t result = DO_NOT_CARE;
    union rsbac_attribute_value_t i_attr_val1;
    union rsbac_target_id_t       i_tid;

    switch (request)
      {
#if defined(CONFIG_RSBAC_AUTH_UM_PROT) || defined(CONFIG_RSBAC_AUTH_GROUP)
        case R_CHANGE_GROUP:
            switch(target)
              {
#if defined(CONFIG_RSBAC_AUTH_UM_PROT)
                case T_USER:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_AUTH,
                                     T_USER,
                                     i_tid,
                                     A_auth_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_pr_get_error(A_auth_role);
                      return NOT_GRANTED;
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return GRANTED;
                  else
                    return NOT_GRANTED;
#endif /* AUTH_UM_PROT */

#if defined(CONFIG_RSBAC_AUTH_GROUP)
                case T_PROCESS:
                  if(attr != A_group)
                    return NOT_GRANTED;
#if defined(CONFIG_RSBAC_AUTH_ALLOW_SAME)
                  if(attr_val.group == RSBAC_GEN_GID(RSBAC_UID_SET(owner),current_gid()))
                    return DO_NOT_CARE;
#endif
                  /* check auth_may_setuid of process */
                  if (rsbac_get_attr(SW_AUTH,
                                     T_PROCESS,
                                     tid,
                                     A_auth_may_setuid,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_pr_get_error(A_auth_may_setuid);
                      return NOT_GRANTED;
                    }
                  /* if auth_may_setuid is full or and_gid, then grant */
                  if(   (i_attr_val1.auth_may_setuid == AMS_full)
                     || (i_attr_val1.auth_may_setuid == AMS_last_auth_and_gid)
                    )
                    return GRANTED;

                  /* check, if the target uid is in capset, grant, if yes, deny, if not. */
                  if(rsbac_auth_p_capset_member(caller_pid, ACT_group_real, attr_val.group))
                    return GRANTED;
                  else
                    return NOT_GRANTED;
#endif /* AUTH_GROUP */

                /* We do not care about */
                /* all other cases */
                default:
                  return DO_NOT_CARE;
              }
#endif /* AUTH_UM_PROT || AUTH_GROUP */

#if defined(CONFIG_RSBAC_AUTH_UM_PROT)
        case R_CREATE:
        case R_DELETE:
        case R_GET_PERMISSIONS_DATA:
        case R_RENAME:
        case R_WRITE:
            switch(target)
              {
                case T_USER:
                case T_GROUP:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_AUTH,
                                     T_USER,
                                     i_tid,
                                     A_auth_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_pr_get_error(A_auth_role);
                      return NOT_GRANTED;
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return GRANTED;
                  else
                    return NOT_GRANTED;
                /* We do not care about */
                /* all other cases */
                default: return DO_NOT_CARE;
              }
#endif

        case R_CHANGE_OWNER:
            switch(target)
              {
                case T_PROCESS:
                  if(attr != A_owner)
                    return NOT_GRANTED;
#if defined(CONFIG_RSBAC_AUTH_ALLOW_SAME)
                  if(attr_val.owner == owner)
                    return DO_NOT_CARE;
#endif
                  /* check auth_may_setuid of process */
                  if (rsbac_get_attr(SW_AUTH,
                                     T_PROCESS,
                                     tid,
                                     A_auth_may_setuid,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_pr_get_error(A_auth_may_setuid);
                      return NOT_GRANTED;
                    }
                  switch(i_attr_val1.auth_may_setuid)
                    {
                      case AMS_off:
                        break;
                      case AMS_full:
                        return GRANTED;
                      case AMS_last_auth_only:
                      case AMS_last_auth_and_gid:
                        if(attr_val.owner == RSBAC_NO_USER)
                          return NOT_GRANTED;
                        if (rsbac_get_attr(SW_AUTH,
                                           T_PROCESS,
                                           tid,
                                           A_auth_last_auth,
                                           &i_attr_val1,
                                           FALSE))
                          {
                            rsbac_pr_get_error(A_auth_last_auth);
                            return NOT_GRANTED;
                          }
                        if(i_attr_val1.auth_last_auth == attr_val.owner)
                          return GRANTED;
                        break;

                      default:
                        rsbac_printk(KERN_INFO
                                     "rsbac_adf_request_auth(): auth_may_setuid of process %u an invalid value %u!\n",
                                     tid.process, i_attr_val1.auth_may_setuid);
                        return NOT_GRANTED;
                    }
                  /* check, if the target uid is in capset, grant, if yes, deny, if not. */
                  if(rsbac_auth_p_capset_member(caller_pid, ACT_real, attr_val.owner))
                    return GRANTED;
                  else
                    return NOT_GRANTED;

                /* all other cases are not checked */
                default:
                  return DO_NOT_CARE;
              }

#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
        case R_CHANGE_DAC_EFF_OWNER:
            switch(target)
              {
                case T_PROCESS:
                  if(attr != A_owner)
                    return NOT_GRANTED;
                  if(attr_val.owner == owner)
                    return DO_NOT_CARE;
#if defined(CONFIG_RSBAC_AUTH_ALLOW_SAME)
                  if(attr_val.owner == current_euid())
                    return DO_NOT_CARE;
#endif
                  /* check auth_may_setuid of process */
                  if (rsbac_get_attr(SW_AUTH,
                                     T_PROCESS,
                                     tid,
                                     A_auth_may_setuid,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_pr_get_error(A_auth_may_setuid);
                      return NOT_GRANTED;
                    }
                  switch(i_attr_val1.auth_may_setuid)
                    {
                      case AMS_off:
                        break;
                      case AMS_full:
                        return GRANTED;
                      case AMS_last_auth_only:
                      case AMS_last_auth_and_gid:
                        if(attr_val.owner == RSBAC_NO_USER)
                          return NOT_GRANTED;
                        if (rsbac_get_attr(SW_AUTH,
                                           T_PROCESS,
                                           tid,
                                           A_auth_last_auth,
                                           &i_attr_val1,
                                           FALSE))
                          {
                            rsbac_pr_get_error(A_auth_last_auth);
                            return NOT_GRANTED;
                          }
                        if(i_attr_val1.auth_last_auth == attr_val.owner)
                          return GRANTED;
                        break;

                      default:
                        rsbac_printk(KERN_INFO
                                     "rsbac_adf_request_auth(): auth_may_setuid of process %u has invalid value %u!\n",
                                     tid.process, i_attr_val1.auth_may_setuid);
                        return NOT_GRANTED;
                    }
                  /* check, if the target uid is in capset, grant, if yes, deny, if not. */
                  if(rsbac_auth_p_capset_member(caller_pid, ACT_eff, attr_val.owner))
                    return GRANTED;
                  else
                    return NOT_GRANTED;

                /* all other cases are not checked */
                default:
                  return DO_NOT_CARE;
              }
        case R_CHANGE_DAC_FS_OWNER:
            switch(target)
              {
                case T_PROCESS:
                  if(attr != A_owner)
                    return NOT_GRANTED;
                  if(attr_val.owner == owner)
                    return DO_NOT_CARE;
#if defined(CONFIG_RSBAC_AUTH_ALLOW_SAME)
                  if(attr_val.owner == current_fsuid())
                    return DO_NOT_CARE;
#endif
                  /* check auth_may_setuid of process */
                  if (rsbac_get_attr(SW_AUTH,
                                     T_PROCESS,
                                     tid,
                                     A_auth_may_setuid,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_pr_get_error(A_auth_may_setuid);
                      return NOT_GRANTED;
                    }
                  switch(i_attr_val1.auth_may_setuid)
                    {
                      case AMS_off:
                        break;
                      case AMS_full:
                        return GRANTED;
                      case AMS_last_auth_only:
                      case AMS_last_auth_and_gid:
                        if(attr_val.owner == RSBAC_NO_USER)
                          return NOT_GRANTED;
                        if (rsbac_get_attr(SW_AUTH,
                                           T_PROCESS,
                                           tid,
                                           A_auth_last_auth,
                                           &i_attr_val1,
                                           FALSE))
                          {
                            rsbac_pr_get_error(A_auth_last_auth);
                            return NOT_GRANTED;
                          }
                        if(i_attr_val1.auth_last_auth == attr_val.owner)
                          return GRANTED;
                        break;

                      default:
                        rsbac_printk(KERN_INFO
                                     "rsbac_adf_request_auth(): auth_may_setuid of process %u has an invalid value!\n",
                                     tid.process);
                        return NOT_GRANTED;
                    }
                  /* check, if the target uid is in capset, grant, if yes, deny, if not. */
                  if(rsbac_auth_p_capset_member(caller_pid, ACT_fs, attr_val.owner))
                    return GRANTED;
                  else
                    return NOT_GRANTED;

                /* all other cases are not checked */
                default:
                  return DO_NOT_CARE;
              }
#endif

#ifdef CONFIG_RSBAC_AUTH_GROUP
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
        case R_CHANGE_DAC_EFF_GROUP:
            switch(target)
              {
                case T_PROCESS:
                  if(attr != A_group)
                    return NOT_GRANTED;
                  if(attr_val.group == RSBAC_GEN_GID(RSBAC_UID_SET(owner),current_gid()))
                    return DO_NOT_CARE;
#if defined(CONFIG_RSBAC_AUTH_ALLOW_SAME)
                  if(attr_val.group == RSBAC_GEN_GID(RSBAC_UID_SET(owner),current_egid()))
                    return DO_NOT_CARE;
#endif
                  /* check auth_may_setuid of process */
                  if (rsbac_get_attr(SW_AUTH,
                                     T_PROCESS,
                                     tid,
                                     A_auth_may_setuid,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_pr_get_error(A_auth_may_setuid);
                      return NOT_GRANTED;
                    }
                  /* if auth_may_setuid is set, then grant */
                  if(   (i_attr_val1.auth_may_setuid == AMS_full)
                     || (i_attr_val1.auth_may_setuid == AMS_last_auth_and_gid)
                    )
                    return GRANTED;

                  /* check, if the target uid is in capset, grant, if yes, deny, if not. */
                  if(rsbac_auth_p_capset_member(caller_pid, ACT_group_eff, attr_val.group))
                    return GRANTED;
                  else
                    return NOT_GRANTED;

                /* all other cases are not checked */
                default:
                  return DO_NOT_CARE;
              }
        case R_CHANGE_DAC_FS_GROUP:
            switch(target)
              {
                case T_PROCESS:
                  if(attr != A_group)
                    return NOT_GRANTED;
                  if(attr_val.group == RSBAC_GEN_GID(RSBAC_UID_SET(owner),current_gid()))
                    return DO_NOT_CARE;
#if defined(CONFIG_RSBAC_AUTH_ALLOW_SAME)
                  if(attr_val.group == RSBAC_GEN_GID(RSBAC_UID_SET(owner),current_fsgid()))
                    return DO_NOT_CARE;
#endif
                  /* check auth_may_setuid of process */
                  if (rsbac_get_attr(SW_AUTH,
                                     T_PROCESS,
                                     tid,
                                     A_auth_may_setuid,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_pr_get_error(A_auth_may_setuid);
                      return NOT_GRANTED;
                    }
                  /* if auth_may_setuid is set, then grant */
                  if(   (i_attr_val1.auth_may_setuid == AMS_full)
                     || (i_attr_val1.auth_may_setuid == AMS_last_auth_and_gid)
                    )
                    return GRANTED;

                  /* check, if the target uid is in capset, grant, if yes, deny, if not. */
                  if(rsbac_auth_p_capset_member(caller_pid, ACT_group_fs, attr_val.group))
                    return GRANTED;
                  else
                    return NOT_GRANTED;

                /* all other cases are not checked */
                default:
                  return DO_NOT_CARE;
              }
#endif
#endif /* AUTH_GROUP */

        case R_MODIFY_ATTRIBUTE:
            switch(attr)
              {
                /* Only protect itself, if asked to by configuration */
                #ifdef CONFIG_RSBAC_AUTH_AUTH_PROT
                case A_system_role:
                case A_auth_role:
                case A_auth_may_setuid:
                case A_auth_may_set_cap:
                case A_auth_start_uid:
                case A_auth_start_euid:
                case A_auth_start_gid:
                case A_auth_start_egid:
                case A_auth_learn:
                case A_program_file:
                case A_auth_add_f_cap:
                case A_auth_remove_f_cap:
                /* All attributes (remove target!) */
                case A_none:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_AUTH,
                                     T_USER,
                                     i_tid,
                                     A_auth_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_pr_get_error(A_auth_role);
                      return NOT_GRANTED;
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return GRANTED;
                  else
                    return NOT_GRANTED;
                #endif

                case A_auth_last_auth:
                  if(target != T_PROCESS)
                    return DO_NOT_CARE;
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
                                   "rsbac_adf_request_auth(): changing auth_last_auth of process %u to %u denied for process %u!\n",
                                   tid.process,
                                   attr_val.auth_last_auth,
                                   task_pid(current));
                      return NOT_GRANTED;
                    }

                default:
                  return DO_NOT_CARE;
              }

/* Only protect itself, if asked to by configuration */
#ifdef CONFIG_RSBAC_AUTH_AUTH_PROT
        case R_GET_STATUS_DATA:
            switch(target)
              {
                case T_SCD:
                  /* target rsbac_log? only for secoff */
                  if (tid.scd != ST_rsbac_log)
                    return GRANTED;
                  /* Secoff or Auditor? */
                  i_tid.user = owner;
                  if ((rsbac_get_attr(SW_AUTH,
                                     T_USER,
                                     i_tid,
                                     A_auth_role,
                                     &i_attr_val1,
                                     TRUE)))
                    {
                      rsbac_pr_get_error(A_auth_role);
                      return NOT_GRANTED;
                    }
                  /* grant only for secoff */
                  if (   (i_attr_val1.system_role == SR_security_officer)
                      || (i_attr_val1.system_role == SR_auditor)
                     )
                    return GRANTED;
                  else
                    return NOT_GRANTED;

                default:
                  return DO_NOT_CARE;
               };

        case R_MODIFY_PERMISSIONS_DATA:
            switch(target)
              {
                case T_SCD:
                  #ifdef CONFIG_RSBAC_USER_MOD_IOPERM
                  if(tid.scd == ST_ioports)
                    return GRANTED;
                  #endif
                  /* fall through */
                #if defined(CONFIG_RSBAC_AUTH_UM_PROT)
                case T_USER:
                case T_GROUP:
                #endif
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_AUTH,
                                     T_USER,
                                     i_tid,
                                     A_auth_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_pr_get_error(A_auth_role);
                      return NOT_GRANTED;
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return GRANTED;
                  /* For booting: if administrator and ioports, then grant */
                  if (
                      #if defined(CONFIG_RSBAC_AUTH_UM_PROT)
                         (target == T_SCD) &&
                      #endif
                         (i_attr_val1.system_role == SR_administrator)
                      && (tid.scd == ST_ioports) )
                    return GRANTED;
                  else
                    return NOT_GRANTED;
                  
#ifdef CONFIG_RSBAC_ALLOW_DAC_DISABLE
                /* switching Linux DAC */
                case T_NONE:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_AUTH,
                                     T_USER,
                                     i_tid,
                                     A_auth_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_pr_get_error(A_auth_role);
                      return NOT_GRANTED;
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return GRANTED;
                  else
                    return NOT_GRANTED;
#endif

                /* all other cases are not checked */
                default: return DO_NOT_CARE;
              }

        case R_MODIFY_SYSTEM_DATA:
            switch(target)
              {
                case T_SCD:
                  /* target not rsbac_log? no problem -> grant */
                  switch(tid.scd)
                    {
                      case ST_rsbac_log:
                      case ST_rsbac_remote_log:
                        break;
                      case ST_kmem:
                        return NOT_GRANTED;
                      default:
                        return GRANTED;
                    }
                  /* Get role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_AUTH,
                                     T_USER,
                                     i_tid,
                                     A_auth_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_pr_get_error(A_auth_role);
                      return NOT_GRANTED;
                    }
                  /* grant only for secoff and auditor */
                  if (   (i_attr_val1.system_role == SR_security_officer)
                      || (i_attr_val1.system_role == SR_auditor)
                     )
                    return GRANTED;
                  else
                    return NOT_GRANTED;
                  
                /* all other cases are not checked */
                default: return DO_NOT_CARE;
              }

        case R_SWITCH_LOG:
            switch(target)
              {
                case T_NONE:
                  /* test owner's auth_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_AUTH,
                                     T_USER,
                                     i_tid,
                                     A_auth_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_pr_get_error(A_auth_role);
                      return NOT_GRANTED;
                    }
                  /* security officer? -> grant  */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return GRANTED;
                  else
                    return NOT_GRANTED;

                /* all other cases are not checked */
                default: return DO_NOT_CARE;
              }

        case R_SWITCH_MODULE:
            switch(target)
              {
                case T_NONE:
                  /* we need the switch_target */
                  if(attr != A_switch_target)
                    return NOT_GRANTED;
#ifndef CONFIG_RSBAC_AUTH_OTHER_PROT
                  /* do not care for other modules */
                  if(   (attr_val.switch_target != SW_AUTH)
                     #ifdef CONFIG_RSBAC_SOFTMODE
                     && (attr_val.switch_target != SW_SOFTMODE)
                     #endif
                     #ifdef CONFIG_RSBAC_FREEZE
                     && (attr_val.switch_target != SW_FREEZE)
                     #endif
                    )
                    return DO_NOT_CARE;
#endif
                  /* test owner's auth_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_AUTH,
                                     T_USER,
                                     i_tid,
                                     A_auth_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_pr_get_error(A_auth_role);
                      return NOT_GRANTED;
                    }
                  /* security officer? -> grant  */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return GRANTED;
                  else
                    return NOT_GRANTED;

                /* all other cases are not checked */
                default: return DO_NOT_CARE;
              }
#endif

/*********************/
        default: return DO_NOT_CARE;
      }

    return result;
  } /* end of rsbac_adf_request_auth() */


/*****************************************************************************/
/* If the request returned granted and the operation is performed,           */
/* the following function can be called by the AEF to get all aci set        */
/* correctly. For write accesses that are performed fully within the kernel, */
/* this is usually not done to prevent extra calls, including R_CLOSE for    */
/* cleaning up.                                                              */
/* The second instance of target specification is the new target, if one has */
/* been created, otherwise its values are ignored.                           */
/* On success, 0 is returned, and an error from rsbac/error.h otherwise.     */

inline int  rsbac_adf_set_attr_auth(
                      enum  rsbac_adf_request_t     request,
                            rsbac_pid_t             caller_pid,
                      enum  rsbac_target_t          target,
                      union rsbac_target_id_t       tid,
                      enum  rsbac_target_t          new_target,
                      union rsbac_target_id_t       new_tid,
                      enum  rsbac_attribute_t       attr,
                      union rsbac_attribute_value_t attr_val,
                            rsbac_uid_t             owner)
  {
    int error;
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    union rsbac_attribute_value_t i_attr_val2;
    #if defined(CONFIG_RSBAC_AUTH_LEARN)
    union rsbac_attribute_value_t i_attr_val3;
    union rsbac_attribute_value_t i_attr_val4;
    #endif

    switch (request)
      {
        case R_CLONE:
            if (target == T_PROCESS)
              {
                /* Get auth_may_setuid from first process */
                if (rsbac_get_attr(SW_AUTH,
                                   T_PROCESS,
                                   tid,
                                   A_auth_may_setuid,
                                   &i_attr_val1,
                                   FALSE))
                  {
                    rsbac_pr_get_error(A_auth_may_setuid);
                    return -RSBAC_EREADFAILED;
                  }
                /* Get auth_may_set_cap from first process */
                if (rsbac_get_attr(SW_AUTH,
                                   T_PROCESS,
                                   tid,
                                   A_auth_may_set_cap,
                                   &i_attr_val2,
                                   FALSE))
                  {
                    rsbac_pr_get_error(A_auth_may_set_cap);
                    return -RSBAC_EREADFAILED;
                  }
                #if defined(CONFIG_RSBAC_AUTH_LEARN)
                if (rsbac_get_attr(SW_AUTH,
                                   T_PROCESS,
                                   tid,
                                   A_auth_start_uid,
                                   &i_attr_val3,
                                   FALSE))
                  {
                    rsbac_pr_get_error(A_auth_start_uid);
                    return -RSBAC_EREADFAILED;
                  }
                if (rsbac_get_attr(SW_AUTH,
                                   T_PROCESS,
                                   tid,
                                   A_auth_learn,
                                   &i_attr_val4,
                                   FALSE))
                  {
                    rsbac_pr_get_error(A_auth_learn);
                    return -RSBAC_EREADFAILED;
                  }
                #endif
                /* Set auth_may_setuid for new process */
                if (rsbac_set_attr(SW_AUTH,
                                   T_PROCESS,
                                   new_tid,
                                   A_auth_may_setuid,
                                   i_attr_val1))
                  {
                    rsbac_pr_set_error(A_auth_may_setuid);
                    return -RSBAC_EWRITEFAILED;
                  }
                /* Set auth_may_set_cap for new process */
                if (rsbac_set_attr(SW_AUTH,
                                   T_PROCESS,
                                   new_tid,
                                   A_auth_may_set_cap,
                                   i_attr_val2))
                  {
                    rsbac_pr_set_error(A_auth_may_set_cap);
                    return -RSBAC_EWRITEFAILED;
                  }
                #if defined(CONFIG_RSBAC_AUTH_LEARN)
                if (rsbac_set_attr(SW_AUTH,
                                   T_PROCESS,
                                   new_tid,
                                   A_auth_start_uid,
                                   i_attr_val3))
                  {
                    rsbac_pr_set_error(A_auth_start_uid);
                    return -RSBAC_EWRITEFAILED;
                  }
                if (rsbac_set_attr(SW_AUTH,
                                   T_PROCESS,
                                   new_tid,
                                   A_auth_learn,
                                   i_attr_val4))
                  {
                    rsbac_pr_set_error(A_auth_learn);
                    return -RSBAC_EWRITEFAILED;
                  }
                #ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
                if (rsbac_get_attr(SW_AUTH,
                                   T_PROCESS,
                                   tid,
                                   A_auth_start_euid,
                                   &i_attr_val4,
                                   FALSE))
                  {
                    rsbac_pr_get_error(A_auth_start_uid);
                    return -RSBAC_EREADFAILED;
                  }
                if (rsbac_set_attr(SW_AUTH,
                                   T_PROCESS,
                                   new_tid,
                                   A_auth_start_euid,
                                   i_attr_val4))
                  {
                    rsbac_pr_set_error(A_auth_start_uid);
                    return -RSBAC_EWRITEFAILED;
                  }
                #endif
                #ifdef CONFIG_RSBAC_AUTH_GROUP
                if (rsbac_get_attr(SW_AUTH,
                                   T_PROCESS,
                                   tid,
                                   A_auth_start_gid,
                                   &i_attr_val4,
                                   FALSE))
                  {
                    rsbac_pr_get_error(A_auth_start_uid);
                    return -RSBAC_EREADFAILED;
                  }
                if (rsbac_set_attr(SW_AUTH,
                                   T_PROCESS,
                                   new_tid,
                                   A_auth_start_gid,
                                   i_attr_val4))
                  {
                    rsbac_pr_set_error(A_auth_start_uid);
                    return -RSBAC_EWRITEFAILED;
                  }
                #ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
                if (rsbac_get_attr(SW_AUTH,
                                   T_PROCESS,
                                   tid,
                                   A_auth_start_egid,
                                   &i_attr_val4,
                                   FALSE))
                  {
                    rsbac_pr_get_error(A_auth_start_uid);
                    return -RSBAC_EREADFAILED;
                  }
                if (rsbac_set_attr(SW_AUTH,
                                   T_PROCESS,
                                   new_tid,
                                   A_auth_start_egid,
                                   i_attr_val4))
                  {
                    rsbac_pr_set_error(A_auth_start_uid);
                    return -RSBAC_EWRITEFAILED;
                  }
                #endif
                #endif
                #endif
                /* copy auth_last_auth */
                if (rsbac_get_attr(SW_AUTH,
                                   T_PROCESS,
                                   tid,
                                   A_auth_last_auth,
                                   &i_attr_val1,
                                   FALSE))
                  {
                    rsbac_pr_get_error(A_auth_last_auth);
                    return -RSBAC_EREADFAILED;
                  }
                if (rsbac_set_attr(SW_AUTH,
                                   T_PROCESS,
                                   new_tid,
                                   A_auth_last_auth,
                                   i_attr_val1))
                  {
                    rsbac_pr_set_error(A_auth_last_auth);
                    return -RSBAC_EWRITEFAILED;
                  }
                /* copy capability list */
                if(rsbac_auth_copy_pp_capset(tid.process,new_tid.process))
                  {
                    rsbac_printk(KERN_WARNING
                           "rsbac_adf_set_attr_auth(): rsbac_auth_copy_pp_capset() returned error!\n");
                    return -RSBAC_EWRITEFAILED;
                  }
                return 0;
              }
            else
              return 0;

        case R_EXECUTE:
            switch(target)
              {
                case T_FILE:
                  /* reset auth_may_setuid and auth_may_set_cap for process */
                  i_tid.process = caller_pid;
                  /* First, set auth_may_setuid to program file's auth_may_setuid */
                  if (rsbac_get_attr(SW_AUTH,
                                     T_FILE,
                                     tid,
                                     A_auth_may_setuid,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_pr_get_error(A_auth_may_setuid);
                      return -RSBAC_EREADFAILED;
                    }
                  if (rsbac_set_attr(SW_AUTH,
                                     T_PROCESS,
                                     i_tid,
                                     A_auth_may_setuid,
                                     i_attr_val1))
                    {
                      rsbac_pr_set_error(A_auth_may_setuid);
                      return -RSBAC_EWRITEFAILED;
                    }
                  /* Next, set auth_may_set_cap to program file's auth_may_set_cap */
                  if (rsbac_get_attr(SW_AUTH,
                                     T_FILE,
                                     tid,
                                     A_auth_may_set_cap,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_pr_get_error(A_auth_may_set_cap);
                      return -RSBAC_EREADFAILED;
                    }
                  if (rsbac_set_attr(SW_AUTH,
                                     T_PROCESS,
                                     i_tid,
                                     A_auth_may_set_cap,
                                     i_attr_val1))
                    {
                      rsbac_pr_set_error(A_auth_may_set_cap);
                      return -RSBAC_EWRITEFAILED;
                    }
                  /* reset auth_last_auth for process */
                  i_attr_val1.auth_last_auth = RSBAC_NO_USER;
                  if (rsbac_set_attr(SW_AUTH,
                                     T_PROCESS,
                                     i_tid,
                                     A_auth_last_auth,
                                     i_attr_val1))
                    {
                      rsbac_pr_set_error(A_auth_last_auth);
                    }

                  /* copy file capability list from file to process */
                  if (rsbac_auth_copy_fp_capset(tid.file, caller_pid))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_set_attr_auth(): rsbac_auth_copy_fp_capset() returned error!\n");
                      return -RSBAC_EWRITEFAILED;
                    }
                  /* replace RSBAC_AUTH_OWNER_F_CAP by current owner */
                  error = rsbac_replace_auth_cap(caller_pid,
                                                 ACT_real,
                                                 RSBAC_AUTH_OWNER_F_CAP,
                                                 owner);
                  if(error)
                    return error;
                  #ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
                  error = rsbac_replace_auth_cap(caller_pid,
                                                 ACT_eff,
                                                 RSBAC_AUTH_OWNER_F_CAP,
                                                 owner);
                  if(error)
                    return error;
                  error = rsbac_replace_auth_cap(caller_pid,
                                                 ACT_eff,
                                                 RSBAC_AUTH_DAC_OWNER_F_CAP,
                                                 current_euid());
                  if(error)
                    return error;
                  error = rsbac_replace_auth_cap(caller_pid,
                                                 ACT_fs,
                                                 RSBAC_AUTH_OWNER_F_CAP,
                                                 owner);
                  if(error)
                    return error;
                  error = rsbac_replace_auth_cap(caller_pid,
                                                 ACT_fs,
                                                 RSBAC_AUTH_DAC_OWNER_F_CAP,
                                                 current_fsuid());
                  if(error)
                    return error;
                  #endif
                  #ifdef CONFIG_RSBAC_AUTH_GROUP
                  error = rsbac_replace_auth_cap(caller_pid,
                                                 ACT_group_real,
                                                 RSBAC_AUTH_GROUP_F_CAP,
                                                 current_gid());
                  if(error)
                    return error;
                  #ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
                  error = rsbac_replace_auth_cap(caller_pid,
                                                 ACT_group_eff,
                                                 RSBAC_AUTH_GROUP_F_CAP,
                                                 current_gid());
                  if(error)
                    return error;
                  error = rsbac_replace_auth_cap(caller_pid,
                                                 ACT_group_eff,
                                                 RSBAC_AUTH_DAC_GROUP_F_CAP,
                                                 current_egid());
                  if(error)
                    return error;
                  error = rsbac_replace_auth_cap(caller_pid,
                                                 ACT_group_fs,
                                                 RSBAC_AUTH_GROUP_F_CAP,
                                                 current_gid());
                  if(error)
                    return error;
                  error = rsbac_replace_auth_cap(caller_pid,
                                                 ACT_group_fs,
                                                 RSBAC_AUTH_DAC_GROUP_F_CAP,
                                                 current_fsgid());
                  if(error)
                    return error;
                  #endif
                  #endif

                  #if defined(CONFIG_RSBAC_AUTH_LEARN)
                  /* Set auth_learn to program file's auth_learn */
                  if (rsbac_get_attr(SW_AUTH,
                                     T_FILE,
                                     tid,
                                     A_auth_learn,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_pr_get_error(A_auth_learn);
                      return -RSBAC_EREADFAILED;
                    }
                  if (rsbac_set_attr(SW_AUTH,
                                     T_PROCESS,
                                     i_tid,
                                     A_auth_learn,
                                     i_attr_val1))
                    {
                      rsbac_pr_set_error(A_auth_learn);
                      return -RSBAC_EWRITEFAILED;
                    }
                  /* remember caller */
                  i_attr_val1.auth_start_uid = owner;
                  if (rsbac_set_attr(SW_AUTH,
                                     T_PROCESS,
                                     i_tid,
                                     A_auth_start_uid,
                                     i_attr_val1))
                    {
                      rsbac_pr_set_error(A_auth_start_uid);
                      return -RSBAC_EWRITEFAILED;
                    }
                  #ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
                  i_attr_val1.auth_start_euid = current_euid();
                  if (rsbac_set_attr(SW_AUTH,
                                     T_PROCESS,
                                     i_tid,
                                     A_auth_start_euid,
                                     i_attr_val1))
                    {
                      rsbac_pr_set_error(A_auth_start_euid);
                      return -RSBAC_EWRITEFAILED;
                    }
                  #endif
                  #ifdef CONFIG_RSBAC_AUTH_GROUP
                  i_attr_val1.auth_start_gid = current_gid();
                  if (rsbac_set_attr(SW_AUTH,
                                     T_PROCESS,
                                     i_tid,
                                     A_auth_start_gid,
                                     i_attr_val1))
                    {
                      rsbac_pr_set_error(A_auth_start_gid);
                      return -RSBAC_EWRITEFAILED;
                    }
                  #ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
                  i_attr_val1.auth_start_egid = current_egid();
                  if (rsbac_set_attr(SW_AUTH,
                                     T_PROCESS,
                                     i_tid,
                                     A_auth_start_egid,
                                     i_attr_val1))
                    {
                      rsbac_pr_set_error(A_auth_start_egid);
                      return -RSBAC_EWRITEFAILED;
                    }
                  #endif
                  #endif
                  #endif
                  return 0;

                /* all other cases are unknown */
                default:
                  return 0;
              }

/* Only protect itself, if asked to by configuration */
#ifdef CONFIG_RSBAC_AUTH_AUTH_PROT
        /* remove all file capabilities on all changing requests to files */
        case R_APPEND_OPEN:
        case R_CHANGE_GROUP:
        case R_DELETE:
        case R_LINK_HARD:
        case R_MODIFY_ACCESS_DATA:
        case R_READ_WRITE_OPEN:
        case R_RENAME:
        case R_TRUNCATE:
        case R_WRITE_OPEN:
            switch(target)
              {
                case T_FILE:
                  /* remove cap set */
                  if(rsbac_auth_remove_f_capsets(tid.file))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_set_attr_auth(): rsbac_auth_remove_f_capsets() returned error!\n");
                      return -RSBAC_EWRITEFAILED;
                    }
                  return 0;

                /* all other cases are not handled */
                default: return 0;
              }
#endif

/*********************/
        default: return 0;
      }

    return 0;
  } /* end of rsbac_adf_set_attr_auth() */

/* end of rsbac/adf/auth/main.c */
