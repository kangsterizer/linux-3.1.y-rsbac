/**************************************************** */
/* Rule Set Based Access Control                      */
/* Implementation of the Access Control Decision      */
/* Facility (ADF) - System Resources (RES)            */
/* File: rsbac/adf/res/main.c                         */
/*                                                    */
/* Author and (c) 2002-2009: Amon Ott <ao@rsbac.org>  */
/*                                                    */
/* Last modified: 14/Jan/2009                         */
/**************************************************** */

#include <linux/string.h>
#include <linux/version.h>
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

enum rsbac_adf_req_ret_t
   rsbac_adf_request_res (enum  rsbac_adf_request_t     request,
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
                case A_res_role:
                case A_res_min:
                case A_res_max:
                /* All attributes (remove target!) */
                case A_none:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_RES,
                                     T_USER,
                                     i_tid,
                                     A_res_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_res()", A_res_role);
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
                case A_res_role:
                case A_res_min:
                case A_res_max:
                /* All attributes (remove target!) */
                case A_none:
                  /* Security Officer or Admin? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_RES,
                                     T_USER,
                                     i_tid,
                                     A_res_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_res()", A_res_role);
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
                  /* test owner's res_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_RES,
                                     T_USER,
                                     i_tid,
                                     A_res_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_res()", A_res_role);
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
                  if(   (attr_val.switch_target != SW_RES)
                     #ifdef CONFIG_RSBAC_SOFTMODE
                     && (attr_val.switch_target != SW_SOFTMODE)
                     #endif
                     #ifdef CONFIG_RSBAC_FREEZE
                     && (attr_val.switch_target != SW_FREEZE)
                     #endif
                    )
                    return(DO_NOT_CARE);
                  /* test owner's res_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_RES,
                                     T_USER,
                                     i_tid,
                                     A_res_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_res()", A_res_role);
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


/*********************/
        default: return DO_NOT_CARE;
      }

    return DO_NOT_CARE;
  } /* end of rsbac_adf_request_res() */


/*****************************************************************************/
/* If the request returned granted and the operation is performed,           */
/* the following function can be called by the AEF to get all aci set        */
/* correctly. For write accesses that are performed fully within the kernel, */
/* this is usually not done to prevent extra calls, including R_CLOSE for    */
/* cleaning up.                                                              */
/* The second instance of target specification is the new target, if one has */
/* been created, otherwise its values are ignored.                           */
/* On success, 0 is returned, and an error from rsbac/error.h otherwise.     */

int  rsbac_adf_set_attr_res(
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
                  /* Adjust Linux resources */
                  i_tid.user = attr_val.owner;
#ifdef CONFIG_RSBAC_SOFTMODE
                  if(   !rsbac_softmode
#ifdef CONFIG_RSBAC_SOFTMODE_IND
                     && !rsbac_ind_softmode[SW_RES]
#endif
                    )
#endif
                    {
                      int maxval = rsbac_min(RLIM_NLIMITS - 1, RSBAC_RES_MAX);
                      int i;

                      if (rsbac_get_attr(SW_RES,
                                         T_USER,
                                         i_tid,
                                         A_res_max,
                                         &i_attr_val1,
                                         TRUE))
                        {
                          rsbac_ds_get_error("rsbac_adf_set_attr_res()", A_res_max);
                          return -RSBAC_EREADFAILED;
                        }
                      for(i = 0; i <= maxval ; i++)
                        {
                          if(i_attr_val1.res_array[i])
                            {
                              task_lock(current->group_leader);
                              if(current->signal->rlim[i].rlim_max > i_attr_val1.res_array[i])
                                current->signal->rlim[i].rlim_max = i_attr_val1.res_array[i];
                              if(current->signal->rlim[i].rlim_cur > i_attr_val1.res_array[i])
                                current->signal->rlim[i].rlim_cur = i_attr_val1.res_array[i];
                              task_unlock(current->group_leader);
                            }
                        }
                      if (rsbac_get_attr(SW_RES,
                                         T_USER,
                                         i_tid,
                                         A_res_min,
                                         &i_attr_val1,
                                         TRUE))
                        {
                          rsbac_ds_get_error("rsbac_adf_set_attr_res()", A_res_min);
                          return -RSBAC_EREADFAILED;
                        }
                      if(i_attr_val1.res_array[RLIMIT_NOFILE] > sysctl_nr_open)
                        i_attr_val1.res_array[RLIMIT_NOFILE] = sysctl_nr_open;
                      for(i = 0; i <= maxval ; i++)
                        {
                          if(i_attr_val1.res_array[i])
                            {
                              task_lock(current->group_leader);
                              if(current->signal->rlim[i].rlim_max < i_attr_val1.res_array[i])
                                current->signal->rlim[i].rlim_max = i_attr_val1.res_array[i];
                              if(current->signal->rlim[i].rlim_cur < i_attr_val1.res_array[i])
                                current->signal->rlim[i].rlim_cur = i_attr_val1.res_array[i];
                              task_unlock(current->group_leader);
                            }
                        }
                    }
                  return 0;

                /* all other cases are unknown */
                default:
                  return(0);
              }
            break;

        case R_EXECUTE:
            switch(target)
              {
                case T_FILE:
#ifdef CONFIG_RSBAC_SOFTMODE
                  if(   !rsbac_softmode
#ifdef CONFIG_RSBAC_SOFTMODE_IND
                     && !rsbac_ind_softmode[SW_RES]
#endif
                    )
#endif
                    {
                      int maxval = rsbac_min(RLIM_NLIMITS - 1, RSBAC_RES_MAX);
                      int i;

                      if (rsbac_get_attr(SW_RES,
                                         target,
                                         tid,
                                         A_res_max,
                                         &i_attr_val1,
                                         TRUE))
                        {
                          rsbac_ds_get_error("rsbac_adf_set_attr_res()", A_res_max);
                          return -RSBAC_EREADFAILED;
                        }
                      for(i = 0; i <= maxval ; i++)
                        {
                          if(i_attr_val1.res_array[i])
                            {
                              task_lock(current->group_leader);
                              if(current->signal->rlim[i].rlim_max > i_attr_val1.res_array[i])
                                current->signal->rlim[i].rlim_max = i_attr_val1.res_array[i];
                              if(current->signal->rlim[i].rlim_cur > i_attr_val1.res_array[i])
                                current->signal->rlim[i].rlim_cur = i_attr_val1.res_array[i];
                              task_unlock(current->group_leader);
                            }
                        }
                      if (rsbac_get_attr(SW_RES,
                                         target,
                                         tid,
                                         A_res_min,
                                         &i_attr_val1,
                                         TRUE))
                        {
                          rsbac_ds_get_error("rsbac_adf_set_attr_res()", A_res_min);
                          return -RSBAC_EREADFAILED;
                        }
                      for(i = 0; i <= maxval ; i++)
                        {
                          if(i_attr_val1.res_array[i])
                            {
                              task_lock(current->group_leader);
                              if(current->signal->rlim[i].rlim_max < i_attr_val1.res_array[i])
                                current->signal->rlim[i].rlim_max = i_attr_val1.res_array[i];
                              if(current->signal->rlim[i].rlim_cur < i_attr_val1.res_array[i])
                                current->signal->rlim[i].rlim_cur = i_attr_val1.res_array[i];
                              task_unlock(current->group_leader);
                            }
                        }
                    }
                  return 0;

                /* all other cases are unknown */
                default:
                  return 0;
              }
            break;

        case R_MODIFY_SYSTEM_DATA:
            if (   (target == T_SCD)
                && (tid.scd == ST_rlimit)
               )
              {
                  /* Adjust Linux resources */
                  i_tid.user = owner;
#ifdef CONFIG_RSBAC_SOFTMODE
                  if(   !rsbac_softmode
#ifdef CONFIG_RSBAC_SOFTMODE_IND
                     && !rsbac_ind_softmode[SW_RES]
#endif
                    )
#endif
                    {
                      int maxval = rsbac_min(RLIM_NLIMITS - 1, RSBAC_RES_MAX);
                      int i;

                      if (rsbac_get_attr(SW_RES,
                                         T_USER,
                                         i_tid,
                                         A_res_max,
                                         &i_attr_val1,
                                         TRUE))
                        {
                          rsbac_ds_get_error("rsbac_adf_set_attr_res()", A_res_max);
                          return -RSBAC_EREADFAILED;
                        }
                      for(i = 0; i <= maxval ; i++)
                        {
                          if(i_attr_val1.res_array[i])
                            {
                              task_lock(current->group_leader);
                              if(current->signal->rlim[i].rlim_max > i_attr_val1.res_array[i])
                                current->signal->rlim[i].rlim_max = i_attr_val1.res_array[i];
                              if(current->signal->rlim[i].rlim_cur > i_attr_val1.res_array[i])
                                current->signal->rlim[i].rlim_cur = i_attr_val1.res_array[i];
                              task_unlock(current->group_leader);
                            }
                        }
                      if (rsbac_get_attr(SW_RES,
                                         T_USER,
                                         i_tid,
                                         A_res_min,
                                         &i_attr_val1,
                                         TRUE))
                        {
                          rsbac_ds_get_error("rsbac_adf_set_attr_res()", A_res_min);
                          return -RSBAC_EREADFAILED;
                        }
                      if(i_attr_val1.res_array[RLIMIT_NOFILE] > sysctl_nr_open)
                        i_attr_val1.res_array[RLIMIT_NOFILE] = sysctl_nr_open;
                      for(i = 0; i <= maxval ; i++)
                        {
                          if(i_attr_val1.res_array[i])
                            {
                              task_lock(current->group_leader);
                              if(current->signal->rlim[i].rlim_max < i_attr_val1.res_array[i])
                                current->signal->rlim[i].rlim_max = i_attr_val1.res_array[i];
                              if(current->signal->rlim[i].rlim_cur < i_attr_val1.res_array[i])
                                current->signal->rlim[i].rlim_cur = i_attr_val1.res_array[i];
                              task_unlock(current->group_leader);
                            }
                        }
                    }
                  return 0;
              }
            break;

/*********************/
        default: return 0;
      }

    return 0;
  } /* end of rsbac_adf_set_attr_res() */

/* end of rsbac/adf/res/main.c */
