/**************************************************** */
/* Rule Set Based Access Control                      */
/* Implementation of the Access Control Decision      */
/* Facility (ADF) - PAX                               */
/* File: rsbac/adf/pax/pax_main.c                     */
/*                                                    */
/* Author and (c) 1999-2008: Amon Ott <ao@rsbac.org>  */
/*                                                    */
/* Last modified: 26/Feb/2008                         */
/**************************************************** */

#include <linux/string.h>
#include <linux/mm.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/adf_main.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/pax_getname.h>
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

/**** PaX set flags func ****/
#if defined(CONFIG_RSBAC_PAX) && (defined(CONFIG_PAX_HAVE_ACL_FLAGS) || defined(CONFIG_PAX_HOOK_ACL_FLAGS))

#include <linux/binfmts.h>

#if defined(CONFIG_PAX_HAVE_ACL_FLAGS)
void pax_set_initial_flags(struct linux_binprm * bprm)
#else
void rsbac_pax_set_flags_func(struct linux_binprm * bprm)
#endif
  {
    int err;
    union rsbac_target_id_t tid;
    union rsbac_attribute_value_t attr_val;

    if(!rsbac_is_initialized())
      return;
    tid.file.device = bprm->file->f_dentry->d_sb->s_dev;
    tid.file.inode = bprm->file->f_dentry->d_inode->i_ino;
    tid.file.dentry_p = bprm->file->f_dentry;
    err = rsbac_get_attr(SW_PAX,
                         T_FILE,
                         tid,
                         A_pax_flags,
                         &attr_val,
                         TRUE);
    if(!err)
      {
        pax_check_flags(&attr_val.pax_flags);
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pax)
          {
            rsbac_printk(KERN_DEBUG
                   "rsbac_pax_set_flags_func(): changing flags for process %u from %lx to %lx from device %02u:%02u inode %u\n",
                   current->pid,
                   current->flags & RSBAC_PAX_ALL_FLAGS,
                   attr_val.pax_flags,
                   MAJOR(tid.file.device),MINOR(tid.file.device),
                   tid.file.inode);
          }
#endif
        /* Set flags for process */
        current->mm->pax_flags = (current->mm->pax_flags & ~RSBAC_PAX_ALL_FLAGS) | attr_val.pax_flags;
      }
    else
      {
        rsbac_printk(KERN_WARNING
               "rsbac_pax_set_flags_func(): get_data for device %02u:%02u, inode %u returned error %i!\n",
               MAJOR(tid.file.device),
               MINOR(tid.file.device),
               tid.file.inode,
               err);
      }
  }
#endif


inline enum rsbac_adf_req_ret_t
   rsbac_adf_request_pax (enum  rsbac_adf_request_t     request,
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
                case A_pax_role:
                case A_pax_flags:
                /* All attributes (remove target!) */
                case A_none:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PAX,
                                     T_USER,
                                     i_tid,
                                     A_pax_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_pax()", A_pax_role);
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
                case A_pax_role:
                case A_pax_flags:
                /* All attributes (remove target!) */
                case A_none:
                  /* Security Officer or Admin? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PAX,
                                     T_USER,
                                     i_tid,
                                     A_pax_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_pax()", A_pax_role);
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
                  /* test owner's pax_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PAX,
                                     T_USER,
                                     i_tid,
                                     A_pax_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_pax()", A_pax_role);
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
                  if(   (attr_val.switch_target != SW_PAX)
                     #ifdef CONFIG_RSBAC_SOFTMODE
                     && (attr_val.switch_target != SW_SOFTMODE)
                     #endif
                     #ifdef CONFIG_RSBAC_FREEZE
                     && (attr_val.switch_target != SW_FREEZE)
                     #endif
                    )
                    return(DO_NOT_CARE);
                  /* test owner's pax_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PAX,
                                     T_USER,
                                     i_tid,
                                     A_pax_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_pax()", A_pax_role);
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
  } /* end of rsbac_adf_request_pax() */


/* end of rsbac/adf/pax/pax_main.c */
