/**************************************************** */
/* Rule Set Based Access Control                      */
/* Implementation of the Access Control Decision      */
/* Facility (ADF) - Access Control Lists (ACL)        */
/* File: rsbac/adf/acl/acl_main.c                     */
/*                                                    */
/* Author and (c) 1999-2009: Amon Ott <ao@rsbac.org>  */
/*                                                    */
/* Last modified: 16/Nov/2009                         */
/**************************************************** */

#include <linux/string.h>
#include <rsbac/aci.h>
#include <rsbac/acl.h>
#include <rsbac/adf_main.h>
#include <rsbac/adf_syshelpers.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/rkmem.h>
#include <rsbac/debug.h>
#include <rsbac/lists.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

#if defined(CONFIG_RSBAC_ACL_LEARN)
#ifdef CONFIG_RSBAC_ACL_LEARN_TA
rsbac_list_ta_number_t acl_learn_ta = CONFIG_RSBAC_ACL_LEARN_TA;
#else
rsbac_list_ta_number_t acl_learn_ta = 0;
#endif
#endif

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

/* in acl_syscalls.c */
rsbac_boolean_t rsbac_acl_check_super(enum  rsbac_target_t target,
                              union rsbac_target_id_t tid,
                                    rsbac_uid_t user);

rsbac_boolean_t rsbac_acl_check_right(enum  rsbac_target_t target,
                              union rsbac_target_id_t tid,
                                    rsbac_uid_t user,
                                    rsbac_pid_t caller_pid,
                              enum  rsbac_adf_request_t request)
  {
    rsbac_boolean_t                   result = FALSE;
    int                       err=0, tmperr;
    int                       i;
    rsbac_acl_group_id_t    * group_p;
    #if defined(CONFIG_RSBAC_RC)
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    #endif

    /* Only check implemented targets */
    switch(target)
      {
        case T_FILE:
        case T_DIR:
        case T_FIFO:
        case T_SYMLINK:
        case T_UNIXSOCK:
        case T_DEV:
        case T_IPC:
        case T_SCD:
        case T_USER:
        case T_PROCESS:
#ifdef CONFIG_RSBAC_ACL_UM_PROT
        case T_GROUP:
#endif
#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
        case T_NETDEV:
#endif
#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
        case T_NETTEMP_NT:
        case T_NETTEMP:
        case T_NETOBJ:
#endif
          break;
        default:
          return TRUE;
      }
    /* inherited own rights */
    err = rsbac_acl_get_single_right(target,
                                     tid,
                                     ACLS_USER,
                                     (rsbac_acl_subject_id_t) user,
                                     request,
                                     &result);
    if(err)
      {
        char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_check_right(): rsbac_acl_get_single_right() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
        return FALSE;
      }
    if(result)
      return TRUE;

    /* add group and role rights */
    /* group everyone */
    err = rsbac_acl_get_single_right(target,
                                     tid,
                                     ACLS_GROUP,
                                     RSBAC_ACL_GROUP_EVERYONE,
                                     request,
                                     &result);
    if(err)
      {
        char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_check_right(): rsbac_acl_get_single_right() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
        return FALSE;
      }
    if(result)
      return TRUE;

    #if defined(CONFIG_RSBAC_RC)
    /* use process role */
    /* first get role */
    i_tid.process = caller_pid;
    if (rsbac_get_attr(SW_RC,
                       T_PROCESS,
                       i_tid,
                       A_rc_role,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_printk(KERN_WARNING
               "rsbac_acl_check_right(): rsbac_get_attr() for process rc_role returned error!\n");
      }
    else
      {
        err = rsbac_acl_get_single_right(target,
                                         tid,
                                         ACLS_ROLE,
                                         i_attr_val1.rc_role,
                                         request,
                                         &result);
        if(err)
          {
            char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

            if(tmp)
              {
                get_error_name(tmp,err);
                rsbac_printk(KERN_WARNING
                       "rsbac_acl_check_right(): rsbac_acl_get_single_right() returned error %s!\n",
                       tmp);
                rsbac_kfree(tmp);
              }
            return FALSE;
          }
        if(result)
          return TRUE;
      }
    #endif

    /* other groups */
    /* first get user groups */
    group_p = NULL;
    err = rsbac_acl_get_user_groups(0, user, &group_p, NULL);
    if(err<0)
      {
        char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_check_right(): rsbac_acl_get_user_groups() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
        return err;
      }
    for(i=0; i<err; i++)
      {
        tmperr = rsbac_acl_get_single_right(target,
                                            tid,
                                            ACLS_GROUP,
                                            group_p[i],
                                            request,
                                            &result);
        if(tmperr)
          {
            char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

            if(tmp)
              {
                rsbac_printk(KERN_WARNING
                       "rsbac_acl_check_right(): rsbac_acl_get_single_right() returned error %s!\n",
                       get_error_name(tmp, tmperr));
                rsbac_kfree(tmp);
              }
            if(group_p)
              rsbac_kfree(group_p);
            return FALSE;
          }
        if(result)
          {
            if(group_p)
              rsbac_kfree(group_p);
            return TRUE;
          }
      }
    if(group_p)
      rsbac_kfree(group_p);

    /* SUPERVISOR? */
#ifdef CONFIG_RSBAC_ACL_LEARN
    result = rsbac_acl_check_super(target, tid, user);
    if(   !result
       && (request < R_NONE)
      )
      {
        switch(target)
          {
            case T_FILE:
            case T_DIR:
            case T_FIFO:
            case T_SYMLINK:
            case T_UNIXSOCK:
              if(rsbac_acl_learn_fd)
                {
                  char * tmp;
                  enum rsbac_acl_subject_type_t  subj_type;
                       rsbac_acl_subject_id_t    subj_id;
                       rsbac_acl_rights_vector_t rights;
                       rsbac_time_t              ttl;

#ifdef CONFIG_RSBAC_ACL_LEARN_TA
		  if (!rsbac_list_ta_exist(acl_learn_ta))
			rsbac_list_ta_begin(CONFIG_RSBAC_LIST_TRANS_MAX_TTL,
					&acl_learn_ta,
					RSBAC_ALL_USERS,
					RSBAC_ACL_LEARN_TA_NAME,
					NULL);
#endif
                  tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
                  if(tmp)
                    {
                      char * target_type_name;

                      target_type_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
                      if(target_type_name)
                        {
                          char * target_id_name;

                          #ifdef CONFIG_RSBAC_LOG_FULL_PATH
                          target_id_name
                           = rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
                          /* max. path name len + some extra */
                          #else
                          target_id_name = rsbac_kmalloc(2 * RSBAC_MAXNAMELEN);
                          /* max. file name len + some extra */
                          #endif
                          if(target_id_name)
                            {
                              get_request_name(tmp,request);
                              get_target_name(target_type_name, target, target_id_name, tid);
                              rsbac_printk(KERN_INFO
                                           "rsbac_acl_check_right(): auto_learn_fd: granting right %s for user %u to target_type %s, tid %s, transaction %u!\n",
                                           tmp,
                                           user,
                                           target_type_name,
                                           target_id_name,
                                           acl_learn_ta);
                              rsbac_kfree(target_id_name);
                            }
                          rsbac_kfree(target_type_name);
                        }
                    }
                  subj_type = ACLS_USER;
                  subj_id = user;
                  rights = RSBAC_REQUEST_VECTOR(request);
                  ttl = 0;
                  err = rsbac_acl_add_to_acl_entry(acl_learn_ta, target, tid, subj_type, subj_id, rights, ttl);
                  if(tmp)
                    {
                      if(err)
                        {
                          rsbac_printk(KERN_WARNING
                                       "rsbac_acl_check_right(): rsbac_acl_add_to_acl_entry() returned error %s!\n",
                                       get_error_name(tmp,err));
                        }
                      rsbac_kfree(tmp);
                    }
                  result = TRUE;
                }
              break;

            default:
              break;
          }
      }
    return result;
#else
    return rsbac_acl_check_super(target, tid, user);
#endif
  }

rsbac_boolean_t rsbac_acl_check_forward(enum  rsbac_target_t target,
                                union rsbac_target_id_t tid,
                                      rsbac_uid_t user,
                                      rsbac_acl_rights_vector_t rights)
  {
    rsbac_acl_rights_vector_t i_rights = 0;
    rsbac_acl_rights_vector_t i_rvec = ((rsbac_acl_rights_vector_t) 1 << ACLR_FORWARD) | rights;
    int                       err=0;


    /* Only check implemented targets */
    switch(target)
      {
        case T_FILE:
        case T_DIR:
        case T_FIFO:
        case T_SYMLINK:
        case T_UNIXSOCK:
        case T_DEV:
        case T_IPC:
        case T_SCD:
        case T_USER:
        case T_PROCESS:
#ifdef CONFIG_RSBAC_ACL_UM_PROT
        case T_GROUP:
#endif
#ifdef CONFIG_RSBAC_ACL_NET_DEV_PROT
        case T_NETDEV:
#endif
#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
        case T_NETTEMP_NT:
        case T_NETTEMP:
        case T_NETOBJ:
#endif
          break;
        default:
          return TRUE;
      }
    /* get effective rights */
    err = rsbac_acl_sys_get_rights(0, target, tid, ACLS_USER, (rsbac_acl_subject_id_t) user, &i_rights, TRUE);
    if(err)
      {
        char * tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_check_forward(): rsbac_acl_sys_get_rights() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
        return FALSE;
      }
    if((i_rights & i_rvec) == i_rvec)
      return TRUE;
    else
      return FALSE;
  }

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

inline enum rsbac_adf_req_ret_t
   rsbac_adf_request_acl (enum  rsbac_adf_request_t     request,
                                rsbac_pid_t             caller_pid,
                          enum  rsbac_target_t          target,
                          union rsbac_target_id_t       tid,
                          enum  rsbac_attribute_t       attr,
                          union rsbac_attribute_value_t attr_val,
                                rsbac_uid_t             owner)
  {
    switch (request)
      {
        case R_READ_ATTRIBUTE:
        case R_MODIFY_ATTRIBUTE:
            switch(attr)
              { /* owner must be changed by other request to prevent inconsistency */
                case A_owner:
                  if(request == R_READ_ATTRIBUTE)
                    return GRANTED;
                  else
                    return NOT_GRANTED;

                /* Only protect AUTH, if asked to by configuration */
                #ifdef CONFIG_RSBAC_ACL_AUTH_PROT
                case A_auth_may_setuid:
                case A_auth_may_set_cap:
                case A_auth_start_uid:
                case A_auth_start_euid:
                case A_auth_start_gid:
                case A_auth_start_egid:
                case A_auth_learn:
                case A_auth_add_f_cap:
                case A_auth_remove_f_cap:
                  tid.scd = AST_auth_administration;
                  if (rsbac_acl_check_right(T_SCD, tid, owner, caller_pid, request))
                    return GRANTED;
                  else
                    return NOT_GRANTED;
                #endif

                #ifdef CONFIG_RSBAC_ACL_GEN_PROT
                case A_pseudo:
                case A_log_array_low:
                case A_log_array_high:
                case A_log_program_based:
                case A_log_user_based:
                case A_symlink_add_remote_ip:
                case A_symlink_add_uid:
                case A_symlink_add_rc_role:
                case A_linux_dac_disable:
                case A_fake_root_uid:
                case A_audit_uid:
                case A_auid_exempt:
                case A_remote_ip:
                case A_vset:
                case A_program_file:
                  if (!rsbac_acl_check_right(target, tid, owner, caller_pid, request))
                    return NOT_GRANTED;
                  else
                    return GRANTED;
                #endif

                #ifdef CONFIG_RSBAC_ACL_LEARN
                case A_acl_learn:
                  /* check supervisor on target */
                  if(rsbac_acl_check_super(target,
                                           tid,
                                           owner))
                    return GRANTED;
                  else
                    return NOT_GRANTED;
                #endif

                /* All attributes (remove target!) */
                case A_none:
                  if (!rsbac_acl_check_right(target, tid, owner, caller_pid, request))
                    return NOT_GRANTED;
                  #ifdef CONFIG_RSBAC_ACL_AUTH_PROT
                  tid.scd = AST_auth_administration;
                  if (!rsbac_acl_check_right(T_SCD, tid, owner, caller_pid, request))
                    return NOT_GRANTED;
                  #endif
                  return GRANTED;

                default:
                  return DO_NOT_CARE;
              }

        case R_SWITCH_MODULE:
            switch(target)
              {
                case T_NONE:
                    if(   (attr_val.switch_target != SW_ACL)
                       #ifdef CONFIG_RSBAC_SOFTMODE
                       && (attr_val.switch_target != SW_SOFTMODE)
                       #endif
                       #ifdef CONFIG_RSBAC_FREEZE
                       && (attr_val.switch_target != SW_FREEZE)
                       #endif
                       #ifdef CONFIG_RSBAC_ACL_AUTH_PROT
                       && (attr_val.switch_target != SW_AUTH)
                       #endif
                      )
                      return DO_NOT_CARE;

                    tid.scd = ST_other;
                    if (rsbac_acl_check_right(T_SCD, tid, owner, caller_pid, request))
                      return GRANTED;
                    else
                      return NOT_GRANTED;

                /* all other cases are unknown */
                default:
                  return DO_NOT_CARE;
              }

/*********************/
        default:
          if(target == T_NONE)
            {
              target = T_SCD;
              tid.scd = ST_other;
            }
          if (rsbac_acl_check_right(target, tid, owner, caller_pid, request))
            return GRANTED;
          else
            return NOT_GRANTED;
      }
  } /* end of rsbac_adf_request_acl() */

/* end of rsbac/adf/acl/main.c */
