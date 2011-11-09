/**************************************************** */
/* Rule Set Based Access Control                      */
/* Implementation of the Access Control Decision      */
/* Facility (ADF) - Linux Capabilities (CAP)          */
/* File: rsbac/adf/cap/main.c                         */
/*                                                    */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org>  */
/*                                                    */
/* Last modified: 12/Jul/2011                         */
/**************************************************** */

#include <linux/string.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
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

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

inline enum rsbac_adf_req_ret_t
   rsbac_adf_request_cap (enum  rsbac_adf_request_t     request,
                                rsbac_pid_t             caller_pid,
                          enum  rsbac_target_t          target,
                          union rsbac_target_id_t       tid,
                          enum  rsbac_attribute_t       attr,
                          union rsbac_attribute_value_t attr_val,
                                rsbac_uid_t             owner)
  {
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;

    switch (request)
      {
        case R_MODIFY_ATTRIBUTE:
            switch(attr)
              {
                case A_system_role:
                case A_cap_role:
                case A_min_caps:
                case A_max_caps:
                case A_max_caps_user:
                case A_max_caps_program:
                case A_cap_process_hiding:
                case A_cap_learn:
                #ifdef CONFIG_RSBAC_CAP_AUTH_PROT
                case A_auth_may_setuid:
                case A_auth_may_set_cap:
                case A_auth_start_uid:
                case A_auth_start_euid:
                case A_auth_start_gid:
                case A_auth_start_egid:
                case A_auth_learn:
                case A_auth_add_f_cap:
                case A_auth_remove_f_cap:
                #endif
                /* All attributes (remove target!) */
                case A_none:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_CAP,
                                     T_USER,
                                     i_tid,
                                     A_cap_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_cap()", A_cap_role);
                      return(NOT_GRANTED);
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                default:
                  return(DO_NOT_CARE);
              }

        case R_READ_ATTRIBUTE:
            switch(attr)
              {
                case A_system_role:
                case A_cap_role:
                case A_min_caps:
                case A_max_caps:
                case A_max_caps_user:
                case A_max_caps_program:
                case A_cap_process_hiding:
                /* All attributes (remove target!) */
                case A_none:
                  /* Security Officer or Admin? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_CAP,
                                     T_USER,
                                     i_tid,
                                     A_cap_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_cap()", A_cap_role);
                      return(NOT_GRANTED);
                    }
                  /* if sec_officer, then grant */
                  if(   (i_attr_val1.system_role == SR_security_officer)
                     || (i_attr_val1.system_role == SR_administrator)
                    )
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                default:
                  return(DO_NOT_CARE);
              }

        case R_SWITCH_LOG:
            switch(target)
              {
                case T_NONE:
                  /* test owner's cap_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_CAP,
                                     T_USER,
                                     i_tid,
                                     A_cap_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_cap()", A_cap_role);
                      return(NOT_GRANTED);
                    }
                  /* security officer? -> grant  */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                /* all other cases are unknown */
                default: return(DO_NOT_CARE);
              }

        case R_SWITCH_MODULE:
            switch(target)
              {
                case T_NONE:
                  /* we need the switch_target */
                  if(attr != A_switch_target)
                    return NOT_GRANTED;
                  /* do not care for other modules */
                  if(   (attr_val.switch_target != SW_CAP)
                     #ifdef CONFIG_RSBAC_CAP_AUTH_PROT
                     && (attr_val.switch_target != SW_AUTH)
                     #endif
                     #ifdef CONFIG_RSBAC_SOFTMODE
                     && (attr_val.switch_target != SW_SOFTMODE)
                     #endif
                     #ifdef CONFIG_RSBAC_FREEZE
                     && (attr_val.switch_target != SW_FREEZE)
                     #endif
                    )
                    return(DO_NOT_CARE);
                  /* test owner's cap_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_CAP,
                                     T_USER,
                                     i_tid,
                                     A_cap_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_cap()", A_cap_role);
                      return(NOT_GRANTED);
                    }
                  /* security officer? -> grant  */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                /* all other cases are unknown */
                default:
                  return DO_NOT_CARE;
              }

#ifdef CONFIG_RSBAC_CAP_PROC_HIDE
        case R_CHANGE_GROUP:
        case R_GET_STATUS_DATA:
        case R_MODIFY_SYSTEM_DATA:
        case R_SEND_SIGNAL:
        case R_TRACE:
          switch(target)
            {
              case T_PROCESS:
                if(caller_pid == tid.process)
                  return GRANTED;
                if (rsbac_get_attr(SW_CAP,
                                   target,
                                   tid,
                                   A_cap_process_hiding,
                                   &i_attr_val1,
                                   TRUE))
                  {
                    rsbac_ds_get_error("rsbac_adf_request_cap()", A_cap_process_hiding);
                    return(NOT_GRANTED);  /* something weird happened */
                  }
                switch(i_attr_val1.cap_process_hiding)
                  {
                    case PH_full:
                        /* Security Officer or Admin? */
                        i_tid.user = owner;
                        if (rsbac_get_attr(SW_CAP,
                                           T_USER,
                                           i_tid,
                                           A_cap_role,
                                           &i_attr_val1,
                                           TRUE))
                          {
                            rsbac_ds_get_error("rsbac_adf_request_cap()", A_cap_role);
                            return(NOT_GRANTED);
                          }
                        /* if sec_officer, then grant */
                        if(i_attr_val1.system_role == SR_security_officer)
                          return(GRANTED);
                        else
                          return(NOT_GRANTED);
                    case PH_from_other_users:
                      {
                        struct task_struct * task_p;
                        enum rsbac_adf_req_ret_t result;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
                        if (rsbac_get_attr(SW_GEN,
                                           T_PROCESS,
                                           tid,
                                           A_vset,
                                           &i_attr_val1,
                                           TRUE))
                          {
                            rsbac_ds_get_error("rsbac_adf_request_cap()", A_vset);
                            return(NOT_GRANTED);
                          }
                        if (i_attr_val1.vset == RSBAC_UID_SET(owner))
#endif
                        {
                          read_lock(&tasklist_lock);
                          task_p = pid_task(tid.process, PIDTYPE_PID);
                          if(   task_p
                             && (task_uid(task_p) != RSBAC_UID_NUM(owner))
                            )
                            result = NOT_GRANTED;
                          else
                            result = GRANTED;
                          read_unlock(&tasklist_lock);
                          if(result == GRANTED)
                            return GRANTED;
                        }
                        /* Security Officer or Admin? */
                        i_tid.user = owner;
                        if (rsbac_get_attr(SW_CAP,
                                           T_USER,
                                           i_tid,
                                           A_cap_role,
                                           &i_attr_val1,
                                           TRUE))
                          {
                            rsbac_ds_get_error("rsbac_adf_request_cap()", A_cap_role);
                            return(NOT_GRANTED);
                          }
                        /* if sec_officer or admin, then grant */
                        if(   (i_attr_val1.system_role == SR_security_officer)
                           || (i_attr_val1.system_role == SR_administrator)
                          )
                          return(GRANTED);
                        else
                          return(NOT_GRANTED);
                      }
                    default:
                      return DO_NOT_CARE;
                  }

              default:
                return DO_NOT_CARE;
            }
#endif

/*********************/
        default: return DO_NOT_CARE;
      }

    return DO_NOT_CARE;
  } /* end of rsbac_adf_request_cap() */


/*****************************************************************************/
/* If the request returned granted and the operation is performed,           */
/* the following function can be called by the AEF to get all aci set        */
/* correctly. For write accesses that are performed fully within the kernel, */
/* this is usually not done to prevent extra calls, including R_CLOSE for    */
/* cleaning up.                                                              */
/* The second instance of target specification is the new target, if one has */
/* been created, otherwise its values are ignored.                           */
/* On success, 0 is returned, and an error from rsbac/error.h otherwise.     */

inline int rsbac_adf_set_attr_cap(
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
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;

    switch (request)
      {
        case R_CHANGE_OWNER:
            switch(target)
              {
                case T_PROCESS:
                  if(attr != A_owner)
                    return(-RSBAC_EINVALIDATTR);
			i_tid.user = attr_val.owner;
			if (rsbac_get_attr(SW_CAP,
					T_USER,
					i_tid,
					A_cap_ld_env,
					&i_attr_val1, TRUE)) {
				rsbac_ds_get_error
					("rsbac_adf_set_attr_cap()",
					 A_max_caps);
			} else {
				if (i_attr_val1.cap_ld_env == LD_keep) {
					i_tid.process = caller_pid;
					if (rsbac_get_attr(SW_CAP,
							T_PROCESS,
							i_tid,
							A_cap_ld_env,
							&i_attr_val1, FALSE)) {
						rsbac_ds_set_error
							("rsbac_adf_set_attr_cap()",
							 A_cap_ld_env);
					} else {
						if (rsbac_set_attr(SW_CAP,
								T_PROCESS,
								tid,
								A_cap_ld_env,
								i_attr_val1)) {
							rsbac_ds_set_error
								("rsbac_adf_set_attr_cap()",
								 A_cap_ld_env);
						}
					}
				}
			}
                  /* Adjust Linux caps */
                  i_tid.user = attr_val.owner;
                  if (rsbac_get_attr(SW_CAP,
                                     T_USER,
                                     i_tid,
                                     A_max_caps,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr_cap()", A_max_caps);
                    }
                  else
                    {
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         || rsbac_ind_softmode[SW_CAP]
                      #endif
                        )
                        { /* Warn */
                          if((i_attr_val1.max_caps.cap[0] != RSBAC_CAP_DEFAULT_MAX) || (i_attr_val1.max_caps.cap[1] != RSBAC_CAP_DEFAULT_MAX))
                            {
                              rsbac_printk(KERN_NOTICE
                                           "rsbac_adf_set_attr_cap(): running in softmode, max_caps of user %u not applied to process %u(%.15s)!\n",
                                           owner,
                                           pid_nr(caller_pid),
                                           current->comm);
                            }
                        }
                      else
                      #endif
                        {
                          /* set caps for process */
				  struct cred *override_cred;
				  override_cred = prepare_creds();
				  if (!override_cred)
					  return -ENOMEM;
				  override_cred->cap_permitted.cap[0] &= i_attr_val1.max_caps.cap[0];
				  override_cred->cap_effective.cap[0] &= i_attr_val1.max_caps.cap[0];
				  override_cred->cap_inheritable.cap[0] &= i_attr_val1.max_caps.cap[0];
				  override_cred->cap_permitted.cap[1] &= i_attr_val1.max_caps.cap[1];
				  override_cred->cap_effective.cap[1] &= i_attr_val1.max_caps.cap[1];
				  override_cred->cap_inheritable.cap[1] &= i_attr_val1.max_caps.cap[1];
				  commit_creds(override_cred);

#ifdef CONFIG_RSBAC_CAP_LOG_MISSING
                          /* set max_caps_user for process */
                          if (rsbac_set_attr(SW_CAP,
                                             target,
                                             tid,
                                             A_max_caps_user,
                                             i_attr_val1))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr_cap()", A_max_caps_user);
                            }
#endif
                        }
                    }
                  if (rsbac_get_attr(SW_CAP,
                                     T_USER,
                                     i_tid,
                                     A_min_caps,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr_cap()", A_min_caps);
                    }
                  else
                    {
                      /* set caps for process */
		      {
      				  struct cred *override_cred;
				  override_cred = prepare_creds();
				  if (!override_cred)
					  return -ENOMEM;

			      override_cred->cap_permitted.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_effective.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_inheritable.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_permitted.cap[1] |= i_attr_val1.min_caps.cap[1];
			      override_cred->cap_effective.cap[1] |= i_attr_val1.min_caps.cap[1];
			      override_cred->cap_inheritable.cap[1] |= i_attr_val1.min_caps.cap[1];
			      commit_creds(override_cred);
		      }
                    }
                  return 0;

                /* all other cases are unknown */
                default:
                  return 0;
              }
            break;

#if defined (CONFIG_RSBAC_CAP_PROC_HIDE) || defined(CONFIG_RSBAC_CAP_LOG_MISSING)
        case R_CLONE:
            switch(target)
              {
                case T_PROCESS:
			i_tid.process = caller_pid;
			if (rsbac_get_attr(SW_CAP,
					   target,
					   i_tid,
					   A_cap_ld_env,
					   &i_attr_val1, FALSE)) {
				rsbac_ds_get_error
					("rsbac_adf_set_attr_cap()",
					 A_cap_ld_env);
			} else {
				if (rsbac_set_attr(SW_CAP,
				    		   new_target,
						   new_tid,
						   A_cap_ld_env,
						   i_attr_val1)) {
						rsbac_ds_get_error
							("rsbac_adf_set_attr_cap()",
							 A_cap_ld_env);
						   }
			}
#ifdef CONFIG_RSBAC_CAP_PROC_HIDE
                  /* get process hiding from old process */
                  if (rsbac_get_attr(SW_CAP,
                                     target,
                                     tid,
                                     A_cap_process_hiding,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr_cap()", A_cap_process_hiding);
                    }
                  else
                    { /* only set, of not default value 0 */
                      if(i_attr_val1.cap_process_hiding)
                        {
                          /* set program based log for new process */
                          if (rsbac_set_attr(SW_CAP,
                                             new_target,
                                             new_tid,
                                             A_cap_process_hiding,
                                             i_attr_val1))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr_cap()", A_cap_process_hiding);
                            }
                        }
                    }
#endif
#ifdef CONFIG_RSBAC_CAP_LOG_MISSING
                  /* get max_caps_user from old process */
                  if (rsbac_get_attr(SW_CAP,
                                     target,
                                     tid,
                                     A_max_caps_user,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr_cap():CLONE", A_max_caps_user);
                    }
                  else
                    { /* only set, of not default value */
                      if((i_attr_val1.max_caps_user.cap[0] != RSBAC_CAP_DEFAULT_MAX) || (i_attr_val1.max_caps_user.cap[1] != RSBAC_CAP_DEFAULT_MAX))
                        {
                          if (rsbac_set_attr(SW_CAP,
                                             new_target,
                                             new_tid,
                                             A_max_caps_user,
                                             i_attr_val1))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr_cap():CLONE", A_max_caps_user);
                            }
                        }
                    }
                  /* get max_caps_program from old process */
                  if (rsbac_get_attr(SW_CAP,
                                     target,
                                     tid,
                                     A_max_caps_program,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr_cap():CLONE", A_max_caps_program);
                    }
                  else
                    { /* only set, of not default value */
                      if((i_attr_val1.max_caps_program.cap[0] != RSBAC_CAP_DEFAULT_MAX) || (i_attr_val1.max_caps_program.cap[1] != RSBAC_CAP_DEFAULT_MAX))
                        {
                          if (rsbac_set_attr(SW_CAP,
                                             new_target,
                                             new_tid,
                                             A_max_caps_program,
                                             i_attr_val1))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr_cap():CLONE", A_max_caps_program);
                            }
                        }
                    }
#endif
                  return 0;

                /* all other cases are unknown */
                default:
                  return 0;
              }
#endif /* PROC_HIDE || LOG_MISSING */

        case R_EXECUTE:
            switch(target)
              {
                case T_FILE:
			i_tid.user = owner;
			if (rsbac_get_attr(SW_CAP,
					   T_USER,
					   i_tid,
					   A_cap_ld_env,
					   &i_attr_val1, TRUE)) {
				rsbac_ds_get_error("rsbac_adf_set_attr_cap()",A_cap_ld_env);
			} else {
				if (i_attr_val1.cap_ld_env == LD_keep) {
					i_tid.process = caller_pid;
					if (rsbac_get_attr(SW_CAP,
							   T_PROCESS,
							   i_tid,
							   A_cap_ld_env,
							   &i_attr_val1, FALSE)) {
					rsbac_ds_get_error("rsbac_adf_set_attr_cap()",
							A_cap_ld_env);
					}
				i_tid.process = caller_pid;
				if (rsbac_set_attr(SW_CAP,
						   T_PROCESS,
						   i_tid,
						   A_cap_ld_env,
						   i_attr_val1)) {
					rsbac_ds_get_error("rsbac_adf_set_attr_cap()",
							A_cap_ld_env);
				}
			     }
			}
                  /* Adjust Linux caps - first user, then program based */
                  /* User must be redone, because caps are cleared by Linux kernel */
		  i_tid.user = owner;
                  if (rsbac_get_attr(SW_CAP,
                                     T_USER,
                                     i_tid,
                                     A_max_caps,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr_cap()", A_max_caps);
                    }
                  else
                    {
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         || rsbac_ind_softmode[SW_CAP]
                      #endif
                        )
                        { /* Warn */
                          if((i_attr_val1.max_caps.cap[0] != RSBAC_CAP_DEFAULT_MAX) || (i_attr_val1.max_caps.cap[1] != RSBAC_CAP_DEFAULT_MAX))
                            {
                              rsbac_printk(KERN_NOTICE
                                           "rsbac_adf_set_attr_cap(): running in softmode, max_caps of user %u not applied to process %u(%.15s)!\n",
                                           owner,
                                           pid_nr(caller_pid),
                                           current->comm);
                            }
                        }
                      else
                      #endif
                        {
				  struct cred *override_cred;
				  override_cred = prepare_creds();
				  if (!override_cred)
					  return -ENOMEM;
				  override_cred->cap_permitted.cap[0] &= i_attr_val1.max_caps.cap[0];
				  override_cred->cap_effective.cap[0] &= i_attr_val1.max_caps.cap[0];
				  override_cred->cap_inheritable.cap[0] &= i_attr_val1.max_caps.cap[0];
				  override_cred->cap_permitted.cap[1] &= i_attr_val1.max_caps.cap[1];
				  override_cred->cap_effective.cap[1] &= i_attr_val1.max_caps.cap[1];
				  override_cred->cap_inheritable.cap[1] &= i_attr_val1.max_caps.cap[1];
			      	  commit_creds(override_cred);
                        }
                    }
                  if (rsbac_get_attr(SW_CAP,
                                     T_USER,
                                     i_tid,
                                     A_min_caps,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr_cap()", A_min_caps);
                    }
                  else
                    {
                      /* set caps for process */
				  struct cred *override_cred;
				  override_cred = prepare_creds();
				  if (!override_cred)
					  return -ENOMEM;
			      override_cred->cap_permitted.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_effective.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_inheritable.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_bset.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_permitted.cap[1] |= i_attr_val1.min_caps.cap[1];
			      override_cred->cap_effective.cap[1] |= i_attr_val1.min_caps.cap[1];
			      override_cred->cap_inheritable.cap[1] |= i_attr_val1.min_caps.cap[1];
			      override_cred->cap_bset.cap[1] |= i_attr_val1.min_caps.cap[1];
			      commit_creds(override_cred);
                    }
                  if (rsbac_get_attr(SW_CAP,
                                     target,
                                     tid,
                                     A_max_caps,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr_cap()", A_max_caps);
                    }
                  else
                    {
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         || rsbac_ind_softmode[SW_CAP]
                      #endif
                        )
                        { /* Warn */
                          if((i_attr_val1.max_caps.cap[0] != RSBAC_CAP_DEFAULT_MAX) || (i_attr_val1.max_caps.cap[1] != RSBAC_CAP_DEFAULT_MAX))
                            {
                              rsbac_printk(KERN_NOTICE
                                           "rsbac_adf_set_attr_cap(): running in softmode, max_caps of program not applied to process %u(%.15s)!\n",
                                           pid_nr(caller_pid),
                                           current->comm);
                            }
                        }
                      else
                      #endif
                        {
				  struct cred *override_cred;
				  override_cred = prepare_creds();
				  if (!override_cred)
					  return -ENOMEM;
				  override_cred->cap_permitted.cap[0] &= i_attr_val1.max_caps.cap[0];
				  override_cred->cap_effective.cap[0] &= i_attr_val1.max_caps.cap[0];
				  override_cred->cap_inheritable.cap[0] &= i_attr_val1.max_caps.cap[0];
				  override_cred->cap_permitted.cap[1] &= i_attr_val1.max_caps.cap[1];
				  override_cred->cap_effective.cap[1] &= i_attr_val1.max_caps.cap[1];
				  override_cred->cap_inheritable.cap[1] &= i_attr_val1.max_caps.cap[1];
			          commit_creds(override_cred);

#ifdef CONFIG_RSBAC_CAP_LOG_MISSING
                          i_tid.process = caller_pid;
                          /* set max_caps_program for process */
                          if (rsbac_set_attr(SW_CAP,
                                             T_PROCESS,
                                             i_tid,
                                             A_max_caps_program,
                                             i_attr_val1))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr_cap():EXECUTE", A_max_caps_program);
                            }
#endif
                        }
                    }
                  if (rsbac_get_attr(SW_CAP,
                                     target,
                                     tid,
                                     A_min_caps,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr_cap()", A_min_caps);
                    }
                  else
                    {
                      /* set caps for process */
				  struct cred *override_cred;
				  override_cred = prepare_creds();
				  if (!override_cred)
					  return -ENOMEM;
			      override_cred->cap_permitted.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_effective.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_inheritable.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_bset.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_permitted.cap[1] |= i_attr_val1.min_caps.cap[1];
			      override_cred->cap_effective.cap[1] |= i_attr_val1.min_caps.cap[1];
			      override_cred->cap_inheritable.cap[1] |= i_attr_val1.min_caps.cap[1];
			      override_cred->cap_bset.cap[1] |= i_attr_val1.min_caps.cap[1];
			      commit_creds(override_cred);
                    }
                  return 0;

                /* all other cases are unknown */
                default:
                  return 0;
              }
            break;

        case R_MODIFY_SYSTEM_DATA:
            switch(target)
              {
                case T_SCD:
                  if (tid.scd != ST_capability)
                    return 0;

                  /* Adjust Linux caps - user only */
                  /* User must be redone, because caps have been changed by sys_capset() */
		  i_tid.user = owner;
                  if (rsbac_get_attr(SW_CAP,
                                     T_USER,
                                     i_tid,
                                     A_max_caps,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr_cap()", A_max_caps);
                    }
                  else
                    {
                      #ifdef CONFIG_RSBAC_SOFTMODE
                      if(   rsbac_softmode
                      #ifdef CONFIG_RSBAC_SOFTMODE_IND
                         || rsbac_ind_softmode[SW_CAP]
                      #endif
                        )
                        { /* Warn */
                          if((i_attr_val1.max_caps.cap[0] != RSBAC_CAP_DEFAULT_MAX) || (i_attr_val1.max_caps.cap[1] != RSBAC_CAP_DEFAULT_MAX))
                            {
                              rsbac_printk(KERN_NOTICE
                                           "rsbac_adf_set_attr_cap(): running in softmode, max_caps of user %u not applied to process %u(%.15s)!\n",
                                           owner,
                                           pid_nr(caller_pid),
                                           current->comm);
                            }
                        }
                      else
                      #endif
                        {
                          /* set caps for process */
				  struct cred *override_cred;
				  override_cred = prepare_creds();
				  if (!override_cred)
					  return -ENOMEM;
				  override_cred->cap_permitted.cap[0] &= i_attr_val1.max_caps.cap[0];
				  override_cred->cap_effective.cap[0] &= i_attr_val1.max_caps.cap[0];
				  override_cred->cap_inheritable.cap[0] &= i_attr_val1.max_caps.cap[0];
				  override_cred->cap_permitted.cap[1] &= i_attr_val1.max_caps.cap[1];
				  override_cred->cap_effective.cap[1] &= i_attr_val1.max_caps.cap[1];
				  override_cred->cap_inheritable.cap[1] &= i_attr_val1.max_caps.cap[1];
			      	  commit_creds(override_cred);
                        }
                    }
                  if (rsbac_get_attr(SW_CAP,
                                     T_USER,
                                     i_tid,
                                     A_min_caps,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr_cap()", A_min_caps);
                    }
                  else
                    {
                      /* set caps for process */
				  struct cred *override_cred;
				  override_cred = prepare_creds();
				  if (!override_cred)
					  return -ENOMEM;
			      override_cred->cap_permitted.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_effective.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_inheritable.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_bset.cap[0] |= i_attr_val1.min_caps.cap[0];
			      override_cred->cap_permitted.cap[1] |= i_attr_val1.min_caps.cap[1];
			      override_cred->cap_effective.cap[1] |= i_attr_val1.min_caps.cap[1];
			      override_cred->cap_inheritable.cap[1] |= i_attr_val1.min_caps.cap[1];
			      override_cred->cap_bset.cap[1] |= i_attr_val1.min_caps.cap[1];
			      commit_creds(override_cred);
                    }
                  return 0;

                /* all other cases are unknown */
                default:
                  return 0;
              }
            break;

/*********************/
        default: return 0;
      }

    return 0;
  } /* end of rsbac_adf_set_attr_cap() */

/* end of rsbac/adf/cap/main.c */
