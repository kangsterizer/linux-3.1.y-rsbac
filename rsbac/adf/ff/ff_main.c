/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - File Flags                       */
/* File: rsbac/adf/ff/main.c                         */
/*                                                   */
/* Author and (c) 1999-2009: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 12/Oct/2009                        */
/*************************************************** */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <rsbac/aci.h>
#include <rsbac/adf_main.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/debug.h>

#include <asm/uaccess.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

/************************************************* */
/*          Internal Help functions                */
/************************************************* */


static enum rsbac_adf_req_ret_t
  check_flags_ff(enum rsbac_target_t target,
                 union rsbac_target_id_t tid,
                 rsbac_ff_flags_t flags)
  {
    union rsbac_attribute_value_t i_attr_val1;

    /* get target's file flags */
    if (rsbac_get_attr(SW_FF, target,
                       tid,
                       A_ff_flags,
                       &i_attr_val1,
                       TRUE))
      {
        rsbac_printk(KERN_WARNING "check_flags_ff(): rsbac_get_attr() returned error!\n");
        return(NOT_GRANTED);
      }
      
    /* Access is granted, if none of the flags in argument flags is set */
    if (i_attr_val1.ff_flags & flags)
      return(NOT_GRANTED);
    else
      return(GRANTED);
  }

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

inline enum rsbac_adf_req_ret_t
   rsbac_adf_request_ff (enum  rsbac_adf_request_t     request,
                                rsbac_pid_t             caller_pid,
                          enum  rsbac_target_t          target,
                          union rsbac_target_id_t       tid,
                          enum  rsbac_attribute_t       attr,
                          union rsbac_attribute_value_t attr_val,
                                rsbac_uid_t             owner)
  {
    enum  rsbac_adf_req_ret_t result = DO_NOT_CARE;
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    int err=0;

    switch (request)
      {
        case R_GET_STATUS_DATA:
            switch(target)
              {
                case T_SCD:
                  switch(tid.scd)
                    {
                      case ST_rsbac_log:
                      case ST_rsbac_remote_log:
                        break;
                      default:
                        return GRANTED;
                    }
                  i_tid.user = owner;
                  if ((err=rsbac_get_attr(SW_FF, T_USER,
                                     i_tid,
                                     A_ff_role,
                                     &i_attr_val1,
                                     TRUE)))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_ff(): rsbac_get_attr() returned error %i!\n",err);
                      return(NOT_GRANTED);
                    }
                  if (   (i_attr_val1.system_role == SR_security_officer)
                      || (i_attr_val1.system_role == SR_auditor)
                     )
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);
                default:
                  return(DO_NOT_CARE);
               }

#if defined(CONFIG_RSBAC_FF_UM_PROT)
        case R_GET_PERMISSIONS_DATA:
            switch(target)
              {
                case T_USER:
                case T_GROUP:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_FF,
                                     T_USER,
                                     i_tid,
                                     A_ff_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_ff()", A_ff_role);
                      return(NOT_GRANTED);
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                /* We do not care about */
                /* all other cases */
                default: return(DO_NOT_CARE);
              }
#endif

        case R_READ:
            switch(target)
              {
                case T_DIR: 
                  return(check_flags_ff(target,tid,
                                        FF_search_only));

#ifdef CONFIG_RSBAC_RW
                case T_FILE:
                case T_FIFO:
                case T_UNIXSOCK:
                  return(check_flags_ff(target,tid,
                                        FF_write_only));
#endif

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_READ_OPEN:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                case T_UNIXSOCK:
                  return(check_flags_ff(target,tid,
                                        FF_execute_only | FF_write_only));
                case T_DIR:
                  return(check_flags_ff(target,tid,
                                        FF_search_only));

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_MAP_EXEC:
        case R_EXECUTE:
            switch(target)
              {
                case T_FILE:
                  return(check_flags_ff(target,tid,
                                        FF_write_only | FF_no_execute | FF_append_only));

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_APPEND_OPEN:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                case T_UNIXSOCK:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_execute_only));

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_READ_WRITE_OPEN:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                case T_UNIXSOCK:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_execute_only
                                         | FF_write_only | FF_append_only));

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_CHDIR:
            switch(target)
              {
                case T_DIR: 
                  return(check_flags_ff(target,tid,
                                        FF_search_only));

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        /* Creating dir or (pseudo) file IN target dir! */
        case R_CREATE:
            switch(target)
              {
                case T_DIR: 
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_search_only));

#if defined(CONFIG_RSBAC_FF_UM_PROT)
                case T_USER:
                case T_GROUP:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_FF,
                                     T_USER,
                                     i_tid,
                                     A_ff_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_ff()", A_ff_role);
                      return(NOT_GRANTED);
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);
#endif

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_DELETE:
        case R_RENAME:
            switch(target)
              {
                case T_FILE: 
                case T_FIFO:
                case T_SYMLINK:
                case T_UNIXSOCK:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_execute_only | FF_no_delete_or_rename
                                         | FF_append_only));
                case T_DIR: 
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_search_only | FF_no_delete_or_rename));

#if defined(CONFIG_RSBAC_FF_UM_PROT)
                case T_USER:
                case T_GROUP:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_FF,
                                     T_USER,
                                     i_tid,
                                     A_ff_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_ff()", A_ff_role);
                      return(NOT_GRANTED);
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);
#endif

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_CHANGE_GROUP:
        case R_MODIFY_PERMISSIONS_DATA:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                case T_SYMLINK:
                case T_UNIXSOCK:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_execute_only | FF_append_only));
                case T_DIR:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_search_only));

#if defined(CONFIG_RSBAC_FF_UM_PROT)
                case T_USER:
                case T_GROUP:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_FF,
                                     T_USER,
                                     i_tid,
                                     A_ff_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_ff()", A_ff_role);
                      return(NOT_GRANTED);
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);
#endif

                /* all other cases are undefined */
                default:
                  return(DO_NOT_CARE);
              }

        case R_CHANGE_OWNER:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                case T_SYMLINK:
                case T_UNIXSOCK:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_execute_only | FF_append_only));
                case T_DIR:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_search_only));
                /* all other cases are undefined */
                default:
                  return(DO_NOT_CARE);
              }

	case R_SEARCH:
	    switch(target)
	    {
		case T_FILE:
		case T_DIR:
		case T_SYMLINK:
		case T_FIFO:
		case T_UNIXSOCK:
			i_tid.user = owner;
			if ((err = rsbac_get_attr(SW_FF, T_USER,
							i_tid,
							A_ff_role,
							&i_attr_val1, TRUE))) {
				rsbac_printk(KERN_WARNING "rsbac_adf_request_ff(): rsbac_get_attr() returned error %i!\n",err);
				return (NOT_GRANTED);
			}
			if (i_attr_val1.system_role == (SR_security_officer || SR_auditor))
					return (GRANTED);
					else
		  return(check_flags_ff(target,tid,
					  FF_no_search));
		default:
		  return(DO_NOT_CARE);
	    }

	case R_LINK_HARD:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                case T_SYMLINK:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_execute_only));

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_MODIFY_ACCESS_DATA:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                case T_SYMLINK:
                case T_UNIXSOCK:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_execute_only | FF_append_only));
                case T_DIR:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_search_only));

                /* all other cases are undefined */
                default:
                  return(DO_NOT_CARE);
              }

        case R_MODIFY_ATTRIBUTE:
            switch(attr)
              {
                case A_ff_flags:
                case A_system_role:
                case A_ff_role:
                #ifdef CONFIG_RSBAC_FF_AUTH_PROT
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
                #ifdef CONFIG_RSBAC_FF_GEN_PROT
                case A_log_array_low:
                case A_log_array_high:
                case A_log_program_based:
                case A_log_user_based:
                case A_symlink_add_remote_ip:
                case A_symlink_add_uid:
                case A_symlink_add_rc_role:
                case A_linux_dac_disable:
                case A_pseudo:
                case A_fake_root_uid:
                case A_audit_uid:
                case A_auid_exempt:
                case A_remote_ip:
                case A_vset:
                case A_program_file:
                #endif
                /* All attributes (remove target!) */
                case A_none:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_FF, T_USER,
                                     i_tid,
                                     A_ff_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_ff(): rsbac_get_attr() returned error!\n");
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

        case R_MODIFY_SYSTEM_DATA:
            switch(target)
              {
                case T_SCD:
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
                  if (rsbac_get_attr(SW_FF, T_USER,
                                     i_tid,
                                     A_ff_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_ff(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* grant only for secoff */
                  if (   (i_attr_val1.system_role == SR_security_officer)
                      || (i_attr_val1.system_role == SR_auditor)
                     )
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);
                  
                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_MOUNT:
        case R_UMOUNT:
            switch(target)
              {
                case T_FILE: 
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_execute_only
                                         | FF_write_only | FF_append_only | FF_no_mount));
                case T_DIR: 
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_search_only | FF_no_mount));

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_SWITCH_LOG:
            switch(target)
              {
                case T_NONE:
                  /* test owner's ff_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_FF, T_USER,
                                     i_tid,
                                     A_ff_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_request_ff(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* security officer? -> grant  */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                /* all other cases are undefined */
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
                  if(   (attr_val.switch_target != SW_FF)
                     #ifdef CONFIG_RSBAC_SOFTMODE
                     && (attr_val.switch_target != SW_SOFTMODE)
                     #endif
                     #ifdef CONFIG_RSBAC_FREEZE
                     && (attr_val.switch_target != SW_FREEZE)
                     #endif
                     #ifdef CONFIG_RSBAC_FF_AUTH_PROT
                     && (attr_val.switch_target != SW_AUTH)
                     #endif
                    )
                    return(DO_NOT_CARE);
                  /* test owner's ff_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_FF, T_USER,
                                     i_tid,
                                     A_ff_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_request_ff(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* security officer? -> grant  */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_TRUNCATE:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_execute_only | FF_append_only));

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_WRITE_OPEN:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                case T_UNIXSOCK:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_execute_only | FF_append_only));

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_WRITE:
            switch(target)
              {
                case T_DIR: 
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_search_only));

#ifdef CONFIG_RSBAC_RW
                case T_FILE:
                case T_FIFO:
                case T_UNIXSOCK:
                  return(check_flags_ff(target,tid,
                                        FF_read_only | FF_execute_only));
#endif
#if defined(CONFIG_RSBAC_FF_UM_PROT)
                case T_USER:
                case T_GROUP:
                  /* Security Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_FF,
                                     T_USER,
                                     i_tid,
                                     A_ff_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_ds_get_error("rsbac_adf_request_ff()", A_ff_role);
                      return(NOT_GRANTED);
                    }
                  /* if sec_officer, then grant */
                  if (i_attr_val1.system_role == SR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);
#endif

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }


/*********************/
        default: return DO_NOT_CARE;
      }

    return result;
  } /* end of rsbac_adf_request_ff() */


/******************************************/
#ifdef CONFIG_RSBAC_SECDEL
inline rsbac_boolean_t rsbac_need_overwrite_ff(struct dentry * dentry_p)
  {
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;

    if(   !dentry_p
       || !dentry_p->d_inode)
      return FALSE;

    i_tid.file.device = dentry_p->d_sb->s_dev;
    i_tid.file.inode = dentry_p->d_inode->i_ino;
    i_tid.file.dentry_p = dentry_p;
    /* get target's file flags */
    if (rsbac_get_attr(SW_FF, T_FILE,
                       i_tid,
                       A_ff_flags,
                       &i_attr_val1,
                       TRUE))
      {
        rsbac_printk(KERN_WARNING "rsbac_need_overwrite_ff(): rsbac_get_attr() returned error!\n");
        return FALSE;
      }

    /* overwrite, if secure_delete is set */
    if (i_attr_val1.ff_flags & FF_secure_delete)
      return TRUE;
    else
      return FALSE;
  }
#endif

/* end of rsbac/adf/ff/main.c */
