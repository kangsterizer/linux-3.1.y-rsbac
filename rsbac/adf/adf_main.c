/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - Main file main.c                 */
/*                                                   */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 12/Jul/2011                        */
/*************************************************** */

#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/adf.h>
#include <rsbac/adf_main.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/cap_getname.h>
#include <rsbac/jail_getname.h>
#include <rsbac/rkmem.h>
#include <rsbac/network.h>
#if defined(CONFIG_RSBAC_UM_EXCL)
#include <rsbac/um.h>
#endif

#ifdef CONFIG_RSBAC_NO_DECISION_ON_NETMOUNT
#include <linux/magic.h>
#endif

#ifdef CONFIG_RSBAC_SECDEL
#include <linux/types.h>
#include <linux/dcache.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
extern void wait_on_retry_sync_kiocb(struct kiocb *iocb);
#endif /* SECDEL */

/************************************************* */
/*           Global Variables                      */
/************************************************* */

__u64 rsbac_adf_request_count[T_NONE+1] = {0,0,0,0,0,0,0,0};
__u64 rsbac_adf_set_attr_count[T_NONE+1] = {0,0,0,0,0,0,0,0};
#ifdef CONFIG_RSBAC_XSTATS
__u64 rsbac_adf_request_xcount[T_NONE+1][R_NONE];
__u64 rsbac_adf_set_attr_xcount[T_NONE+1][R_NONE];
#endif

/******* MAC ********/
#ifdef CONFIG_RSBAC_SWITCH_MAC
rsbac_boolean_t rsbac_switch_mac = TRUE;
#endif  /* MAC */

/******* PM ********/
#ifdef CONFIG_RSBAC_SWITCH_PM
rsbac_boolean_t rsbac_switch_pm = TRUE;
#endif  /* PM */

/******* DAZ ********/
#ifdef CONFIG_RSBAC_SWITCH_DAZ
rsbac_boolean_t rsbac_switch_daz = TRUE;
#endif  /* DAZ */

/******* FF ********/
#ifdef CONFIG_RSBAC_SWITCH_FF
rsbac_boolean_t rsbac_switch_ff = TRUE;
#endif  /* FF */

/******* RC ********/
#ifdef CONFIG_RSBAC_SWITCH_RC
rsbac_boolean_t rsbac_switch_rc = TRUE;
#endif  /* RC */

/****** AUTH *******/
#ifdef CONFIG_RSBAC_SWITCH_AUTH
rsbac_boolean_t rsbac_switch_auth = TRUE;
#endif  /* AUTH */

/****** ACL *******/
#ifdef CONFIG_RSBAC_SWITCH_ACL
rsbac_boolean_t rsbac_switch_acl = TRUE;
#endif  /* ACL */

/****** CAP *******/
#ifdef CONFIG_RSBAC_SWITCH_CAP
rsbac_boolean_t rsbac_switch_cap = TRUE;
#endif  /* CAP */

/****** JAIL *******/
#ifdef CONFIG_RSBAC_SWITCH_JAIL
rsbac_boolean_t rsbac_switch_jail = TRUE;
#endif  /* JAIL */

/****** PAX ********/
#ifdef CONFIG_RSBAC_SWITCH_PAX
rsbac_boolean_t rsbac_switch_pax = TRUE;
#endif  /* PAX */

/****** RES *******/
#ifdef CONFIG_RSBAC_SWITCH_RES
rsbac_boolean_t rsbac_switch_res = TRUE;
#endif  /* RES */

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

/* Init function, calls inits for all sub-modules  */

#ifdef CONFIG_RSBAC_INIT_DELAY
void rsbac_init_adf(void)
#else
void __init rsbac_init_adf(void)
#endif
  {
    #if defined(CONFIG_RSBAC_REG)
    rsbac_reg_init();
    #endif
  }

enum rsbac_adf_req_ret_t
    adf_and_plus(enum rsbac_adf_req_ret_t res1,
                 enum rsbac_adf_req_ret_t res2)
  {
    switch (res1)
      {
        case DO_NOT_CARE: return (res2);
        case GRANTED:     if (res2 == DO_NOT_CARE)
                            return (GRANTED);
                          else
                            return (res2);
        case NOT_GRANTED: if (res2 == UNDEFINED)
                            return (UNDEFINED);
                          else
                            return (NOT_GRANTED);
        default:          return (UNDEFINED);
      }
  }

/*
 * rsbac_adf_request_int()
 * This function is the main decision function, called though the
 * rsbac_adf_request wrapper from the AEF.
 */

EXPORT_SYMBOL(rsbac_adf_request_int);
enum rsbac_adf_req_ret_t
   rsbac_adf_request_int(enum  rsbac_adf_request_t     request,
                               rsbac_pid_t             caller_pid,
                         enum  rsbac_target_t          target,
                         union rsbac_target_id_t     * tid_p,
                         enum  rsbac_attribute_t       attr,
                         union rsbac_attribute_value_t * attr_val_p,
                         enum  rsbac_switch_target_t   ignore_module)
  {
    union rsbac_target_id_t        i_tid;
    union rsbac_attribute_value_t  i_attr_val;
          rsbac_uid_t              owner=0;
    int tmperr=0;
    rsbac_request_vector_t	request_vector;
    enum rsbac_adf_req_ret_t   result = DO_NOT_CARE;
#ifdef CONFIG_RSBAC_SOFTMODE_IND
    enum rsbac_adf_req_ret_t   ret_result = DO_NOT_CARE;
#endif
#ifndef CONFIG_RSBAC_MAINT
    rsbac_enum_t mod_result[SW_NONE + 1] = {
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE,
                                   DO_NOT_CARE
                                 };
#endif
    rsbac_boolean_t do_log = FALSE;
    rsbac_boolean_t log_on_request = TRUE;
/* only if individual logging is enabled */
#if defined(CONFIG_RSBAC_IND_LOG) || defined(CONFIG_RSBAC_IND_NETDEV_LOG) || defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
    union rsbac_attribute_value_t  i_attr_val2;
    enum rsbac_log_level_t log_level;
#endif
    struct vfsmount * mnt_p;
#ifdef CONFIG_RSBAC_SOFTMODE
    rsbac_boolean_t rsbac_internal = FALSE;
#endif

/* No decision possible before init (called at boot time) -> don't care */
    if (!rsbac_is_initialized())
      return DO_NOT_CARE;

/* Always granted for kernel (pid 0) and logging daemon */
    if (   !pid_nr(caller_pid)
        #if defined(CONFIG_RSBAC_LOG_REMOTE)
        || (pid_nr(caller_pid) == pid_nr(rsbaclogd_pid))
        #endif
       )
      return GRANTED;

/* Checking base values */
    if(   request >= R_NONE
       || target > T_NONE
       || attr > A_none)
      {
        rsbac_printk(KERN_WARNING
               "rsbac_adf_request_int(): called with invalid request, target or attribute\n");
        return NOT_GRANTED;
      }
    request_vector = RSBAC_REQUEST_VECTOR(request);

    if (in_interrupt())
      {
        char * request_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);

        if(request_name)
          {
            get_request_name(request_name, request);
            printk(KERN_WARNING "rsbac_adf_request_int(): called from interrupt: request %s, pid %u(%s), attr_val %u!\n",
                   request_name, pid_nr(caller_pid), current->comm, attr_val_p->dummy);
            rsbac_kfree(request_name);
          }
        else
          {
            printk(KERN_WARNING "rsbac_adf_request_int(): called from interrupt: request %u, pid %u(%s)!\n",
                   request, pid_nr(caller_pid), current->comm);
          }
        dump_stack();
        return DO_NOT_CARE;
      }

/* Getting basic information about this request */

    /* only useful for real process, not idle or init */
    if (pid_nr(caller_pid) > 1)
      {
        tmperr = rsbac_get_owner(&owner);
        if(tmperr)
          {
            rsbac_printk(KERN_DEBUG
                   "rsbac_adf_request_int(): caller_pid %i, RSBAC not initialized, returning DO_NOT_CARE\n",
                   pid_nr(caller_pid));
            return DO_NOT_CARE;      /* Startup-Sequence (see above) */
          }
      }
    else  /* caller_pid = 1 -> init, always owned by root */
    {
      owner = 0;
    }

#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if ((attr == A_owner) && (RSBAC_UID_SET(attr_val_p->owner) > RSBAC_UM_VIRTUAL_MAX))
      attr_val_p->owner = RSBAC_GEN_UID(RSBAC_UID_SET(owner), attr_val_p->owner);
    else
    if ((attr == A_group) && (RSBAC_GID_SET(attr_val_p->group) > RSBAC_UM_VIRTUAL_MAX))
      attr_val_p->group = RSBAC_GEN_GID(RSBAC_UID_SET(owner), attr_val_p->group);
#else
    if (attr == A_owner)
      attr_val_p->owner = RSBAC_UID_NUM(attr_val_p->owner);
    else
    if (attr == A_group)
      attr_val_p->group = RSBAC_GID_NUM(attr_val_p->group);
#endif

/******************************************************/
/* General work for all modules - before module calls */
    /* test target on rsbac_internal */
    switch(target)
      {
        case T_FILE:
        case T_DIR:
        case T_FIFO:
        case T_SYMLINK:
#ifdef CONFIG_RSBAC_NO_DECISION_ON_NETMOUNT
          if (   ((mnt_p = rsbac_get_vfsmount(tid_p->file.device)))
              && (   (mnt_p->mnt_sb->s_magic == NFS_SUPER_MAGIC)
                  || (mnt_p->mnt_sb->s_magic == CODA_SUPER_MAGIC)
                  || (mnt_p->mnt_sb->s_magic == NCP_SUPER_MAGIC)
                  || (mnt_p->mnt_sb->s_magic == SMB_SUPER_MAGIC)
                 )
             )
            {
              result = DO_NOT_CARE;
              goto log;
            }
#endif
          /* No decision on pseudo pipefs */
          if(   (target == T_FIFO)
             && ((mnt_p = rsbac_get_vfsmount(tid_p->file.device)))
             && (mnt_p->mnt_sb->s_magic == PIPEFS_MAGIC)
            )
            return DO_NOT_CARE;

          switch(request)
            {
              case R_GET_STATUS_DATA:
              case R_GET_PERMISSIONS_DATA:
              case R_READ_ATTRIBUTE:
#ifdef CONFIG_RSBAC_DAT_VISIBLE
              case R_SEARCH:
              case R_READ:
              case R_CLOSE:
              case R_CHDIR:
#endif
                break;

              default:
                if ((tmperr = rsbac_get_attr(SW_GEN,
                                             target,
                                             *tid_p,
                                             A_internal,
                                             &i_attr_val,
                                             TRUE) ))
                  {
                    if(tmperr == -RSBAC_EINVALIDDEV)
                      {
//                        rsbac_ds_get_error_num("rsbac_adf_request()", A_internal, tmperr);
                        return DO_NOT_CARE;  /* last calls on shutdown */
                      }
                    else
                      {
                        rsbac_ds_get_error_num("rsbac_adf_request()", A_internal, tmperr);
                        return NOT_GRANTED;  /* something weird happened */
                      }
                  }
                /* no access to rsbac_internal objects is granted in any case */
                if (i_attr_val.internal)
                  {
                    rsbac_printk(KERN_WARNING
                           "rsbac_adf_request(): trial to access object declared RSBAC-internal!\n");
                    result = NOT_GRANTED;
                    #ifndef CONFIG_RSBAC_MAINT
                    mod_result[SW_NONE] = NOT_GRANTED;
                    #endif
                    #ifdef CONFIG_RSBAC_SOFTMODE
                    #ifdef CONFIG_RSBAC_SOFTMODE_IND
                    ret_result = NOT_GRANTED;
                    #endif
                    rsbac_internal = TRUE;
                    #endif
                  }
            }

#if defined(CONFIG_RSBAC_UM_VIRTUAL_ISOLATE)
          if (attr == A_vset && (RSBAC_UID_SET(owner))) {
            result = adf_and_plus(result, NOT_GRANTED);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
            ret_result = adf_and_plus(ret_result, NOT_GRANTED);
#endif
          }
#endif

          break;

#if defined(CONFIG_RSBAC_UM_EXCL) || defined(CONFIG_RSBAC_UM_VIRTUAL_ISOLATE)
        case T_PROCESS:
#if defined(CONFIG_RSBAC_UM_EXCL)
          switch(request)
            {
              case R_CHANGE_OWNER:
#ifdef CONFIG_RSBAC_DAC_OWNER
              case R_CHANGE_DAC_EFF_OWNER:
              case R_CHANGE_DAC_FS_OWNER:
#endif
                if(   (attr == A_owner)
                   && !rsbac_um_no_excl
                   && !rsbac_um_user_exists(0, attr_val_p->owner)
                  )
                  {
                    rsbac_printk(KERN_INFO
                                 "rsbac_adf_request(): uid %u not known to RSBAC User Management!\n",
                                 attr_val_p->owner);
                    result = adf_and_plus(result, NOT_GRANTED);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
                    ret_result = adf_and_plus(ret_result, NOT_GRANTED);
#endif
                  }
                break;

              case R_CHANGE_GROUP:
#ifdef CONFIG_RSBAC_DAC_OWNER
              case R_CHANGE_DAC_EFF_GROUP:
              case R_CHANGE_DAC_FS_GROUP:
#endif
                if(   (attr == A_group)
                   && !rsbac_um_no_excl
                   && !rsbac_um_group_exists(0, attr_val_p->group)
                  )
                  {
                    rsbac_printk(KERN_INFO
                                 "rsbac_adf_request(): gid %u not known to RSBAC User Management!\n",
                                 attr_val_p->group);
                    result = adf_and_plus(result, NOT_GRANTED);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
                    ret_result = adf_and_plus(ret_result, NOT_GRANTED);
#endif
                  }
                break;

              default:
                break;
            }
#endif
#if defined(CONFIG_RSBAC_UM_VIRTUAL_ISOLATE)
          if (attr == A_vset && (RSBAC_UID_SET(owner))) {
            result = adf_and_plus(result, NOT_GRANTED);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
            ret_result = adf_and_plus(ret_result, NOT_GRANTED);
#endif
          }
#endif
          break;
#endif /* UM_EXCL || UM_VIRTUAL_ISOLATE */

#if defined(CONFIG_RSBAC_UM_VIRTUAL_ISOLATE)
        case T_USER:
          if(   RSBAC_UID_SET(owner)
             && (RSBAC_UID_SET(owner) != RSBAC_UID_SET(tid_p->user))
            ) {
                    if (RSBAC_UID_SET(tid_p->user) == RSBAC_UM_VIRTUAL_ALL)
                            tid_p->user = RSBAC_GEN_UID(RSBAC_UID_SET(owner), tid_p->user);
                    else {
                            result = adf_and_plus(result, NOT_GRANTED);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
                            ret_result = adf_and_plus(ret_result, NOT_GRANTED);
#endif
                    }
          }
          break;
        case T_GROUP:
          if(   RSBAC_UID_SET(owner)
             && (RSBAC_UID_SET(owner) != RSBAC_GID_SET(tid_p->group))
            ) {
                    if (RSBAC_UID_SET(tid_p->user) == RSBAC_UM_VIRTUAL_ALL)
                            tid_p->user = RSBAC_GEN_UID(RSBAC_UID_SET(owner), tid_p->user);
                    else {
                            result = adf_and_plus(result, NOT_GRANTED);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
                            ret_result = adf_and_plus(ret_result, NOT_GRANTED);
#endif
                    }
          }
          break;
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG) || defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_PM) || defined(CONFIG_RSBAC_RC)
	case T_NETOBJ:
		if(rsbac_net_remote_request(request)) {
			tid_p->netobj.local_temp = 0;
			rsbac_ta_net_lookup_templates(0,
						      &tid_p->
						      netobj, NULL,
						      &tid_p->netobj.remote_temp);
		} else {
			tid_p->netobj.remote_temp = 0;
			rsbac_ta_net_lookup_templates(0,
						      &tid_p->
						      netobj,
						      &tid_p->netobj.local_temp,
						      NULL);
		}
#endif
#endif

        default:
          break;
      }
      
/**********************************************************/
/* calling all decision modules, building a common result */

#ifdef CONFIG_RSBAC_DEBUG
/* first, check for valid request/target combination      */
/* (undefined should only happen in _check and means a real bug!) */
  result = adf_and_plus(result,rsbac_adf_request_check(request,
                                                       caller_pid,
                                                       target,
                                                       tid_p,
                                                       attr,
                                                       attr_val_p,
                                                       owner) );
#endif

#if !defined(CONFIG_RSBAC_MAINT)
/******* MAC ********/
#if defined(CONFIG_RSBAC_MAC)
#ifdef CONFIG_RSBAC_SWITCH_MAC
if (rsbac_switch_mac)
#endif
  /* no need to call module, if to be ignored */
  if(ignore_module != SW_MAC && (request_vector & RSBAC_MAC_REQUEST_VECTOR)) {
        mod_result[SW_MAC] = rsbac_adf_request_mac(request,
                                              caller_pid,
                                              target,
                                              *tid_p,
                                              attr,
                                              *attr_val_p,
                                              owner);
        result = adf_and_plus(result, mod_result[SW_MAC]);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
        if(!rsbac_ind_softmode[SW_MAC])
          ret_result = adf_and_plus(ret_result, mod_result[SW_MAC]);
#endif
    }
#endif  /* MAC */

/******* PM ********/
#if defined(CONFIG_RSBAC_PM)
#ifdef CONFIG_RSBAC_SWITCH_PM
if (rsbac_switch_pm)
#endif
  /* no need to call module, if to be ignored */
  if(ignore_module != SW_PM && (request_vector & RSBAC_PM_REQUEST_VECTOR))
    {
      mod_result[SW_PM]  = rsbac_adf_request_pm (request,
                                              caller_pid,
                                              target,
                                              *tid_p,
                                              attr,
                                              *attr_val_p,
                                              owner);
      result = adf_and_plus(result, mod_result[SW_PM]);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
      if(!rsbac_ind_softmode[SW_PM])
        ret_result = adf_and_plus(ret_result, mod_result[SW_PM]);
#endif
    }
#endif  /* PM */

/******* DAZ ********/
#if defined(CONFIG_RSBAC_DAZ)
#ifdef CONFIG_RSBAC_SWITCH_DAZ
if (rsbac_switch_daz)
#endif
  /* no need to call module, if to be ignored */
  if(ignore_module != SW_DAZ && (request_vector & RSBAC_DAZ_REQUEST_VECTOR))
    {
      mod_result[SW_DAZ]  = rsbac_adf_request_daz (request,
                                              caller_pid,
                                              target,
                                              *tid_p,
                                              attr,
                                              *attr_val_p,
                                              owner);
      result = adf_and_plus(result, mod_result[SW_DAZ]);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
      if(!rsbac_ind_softmode[SW_DAZ])
        ret_result = adf_and_plus(ret_result, mod_result[SW_DAZ]);
#endif
    }
#endif  /* DAZ */

/******* FF ********/
#if defined(CONFIG_RSBAC_FF)
#ifdef CONFIG_RSBAC_SWITCH_FF
if (rsbac_switch_ff)
#endif
  /* no need to call module, if to be ignored */
  if(ignore_module != SW_FF && (request_vector & RSBAC_FF_REQUEST_VECTOR))
    {
      mod_result[SW_FF]  = rsbac_adf_request_ff (request,
                                              caller_pid,
                                              target,
                                              *tid_p,
                                              attr,
                                              *attr_val_p,
                                              owner);
      result = adf_and_plus(result, mod_result[SW_FF]);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
      if(!rsbac_ind_softmode[SW_FF])
        ret_result = adf_and_plus(ret_result, mod_result[SW_FF]);
#endif
    }
#endif  /* FF */

/******* RC ********/
#if defined(CONFIG_RSBAC_RC)
#ifdef CONFIG_RSBAC_SWITCH_RC
if (rsbac_switch_rc)
#endif
  /* no need to call module, if to be ignored */
  if(ignore_module != SW_RC)
    {
      mod_result[SW_RC]  = rsbac_adf_request_rc (request,
                                              caller_pid,
                                              target,
                                              *tid_p,
                                              attr,
                                              *attr_val_p,
                                              owner);
      result = adf_and_plus(result, mod_result[SW_RC]);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
      if(!rsbac_ind_softmode[SW_RC])
        ret_result = adf_and_plus(ret_result, mod_result[SW_RC]);
#endif
    }
#endif  /* RC */

/****** AUTH *******/
#if defined(CONFIG_RSBAC_AUTH)
#ifdef CONFIG_RSBAC_SWITCH_AUTH
if (rsbac_switch_auth)
#endif
  /* no need to call module, if to be ignored */
  if(ignore_module != SW_AUTH && (request_vector & RSBAC_AUTH_REQUEST_VECTOR))
    {
      mod_result[SW_AUTH]= rsbac_adf_request_auth(request,
                                              caller_pid,
                                              target,
                                              *tid_p,
                                              attr,
                                              *attr_val_p,
                                              owner);
      result = adf_and_plus(result, mod_result[SW_AUTH]);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
      if(!rsbac_ind_softmode[SW_AUTH])
        ret_result = adf_and_plus(ret_result, mod_result[SW_AUTH]);
#endif
    }
#endif  /* AUTH */

/****** ACL *******/
#if defined(CONFIG_RSBAC_ACL)
#ifdef CONFIG_RSBAC_SWITCH_ACL
if (rsbac_switch_acl)
#endif
  /* no need to call module, if to be ignored */
  if(ignore_module != SW_ACL)
    {
      mod_result[SW_ACL] = rsbac_adf_request_acl(request,
                                              caller_pid,
                                              target,
                                              *tid_p,
                                              attr,
                                              *attr_val_p,
                                              owner);
      result = adf_and_plus(result, mod_result[SW_ACL]);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
      if(!rsbac_ind_softmode[SW_ACL])
        ret_result = adf_and_plus(ret_result, mod_result[SW_ACL]);
#endif
    }
#endif  /* ACL */

/****** CAP *******/
#if defined(CONFIG_RSBAC_CAP)
#ifdef CONFIG_RSBAC_SWITCH_CAP
if (rsbac_switch_cap)
#endif
  /* no need to call module, if to be ignored */
  if(ignore_module != SW_CAP && (request_vector & RSBAC_CAP_REQUEST_VECTOR))
    {
      mod_result[SW_CAP] = rsbac_adf_request_cap(request,
                                              caller_pid,
                                              target,
                                              *tid_p,
                                              attr,
                                              *attr_val_p,
                                              owner);
      result = adf_and_plus(result, mod_result[SW_CAP]);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
      if(!rsbac_ind_softmode[SW_CAP])
        ret_result = adf_and_plus(ret_result, mod_result[SW_CAP]);
#endif
    }
#endif  /* CAP */

/****** JAIL *******/
#if defined(CONFIG_RSBAC_JAIL)
#ifdef CONFIG_RSBAC_SWITCH_JAIL
if (rsbac_switch_jail)
#endif
  /* no need to call module, if to be ignored */
  if(ignore_module != SW_JAIL && (request_vector & RSBAC_JAIL_REQUEST_VECTOR))
    {
      mod_result[SW_JAIL]= rsbac_adf_request_jail(request,
                                              caller_pid,
                                              target,
                                              *tid_p,
                                              attr,
                                              *attr_val_p,
                                              owner);
      result = adf_and_plus(result, mod_result[SW_JAIL]);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
      if(!rsbac_ind_softmode[SW_JAIL])
        ret_result = adf_and_plus(ret_result, mod_result[SW_JAIL]);
#endif
    }
#endif  /* JAIL */

/******* PAX ********/
#if defined(CONFIG_RSBAC_PAX)
#ifdef CONFIG_RSBAC_SWITCH_PAX
if (rsbac_switch_pax)
#endif
  /* no need to call module, if to be ignored */
  if(ignore_module != SW_PAX && (request_vector & RSBAC_PAX_REQUEST_VECTOR))
    {
      mod_result[SW_PAX]  = rsbac_adf_request_pax (request,
                                              caller_pid,
                                              target,
                                              *tid_p,
                                              attr,
                                              *attr_val_p,
                                              owner);
      result = adf_and_plus(result, mod_result[SW_PAX]);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
      if(!rsbac_ind_softmode[SW_PAX])
        ret_result = adf_and_plus(ret_result, mod_result[SW_PAX]);
#endif
    }
#endif  /* PAX */

/****** RES *******/
#if defined(CONFIG_RSBAC_RES)
#ifdef CONFIG_RSBAC_SWITCH_RES
if (rsbac_switch_res)
#endif
  /* no need to call module, if to be ignored */
  if(ignore_module != SW_RES && (request_vector & RSBAC_RES_REQUEST_VECTOR))
    {
      mod_result[SW_RES] = rsbac_adf_request_res(request,
                                              caller_pid,
                                              target,
                                              *tid_p,
                                              attr,
                                              *attr_val_p,
                                              owner);
      result = adf_and_plus(result, mod_result[SW_RES]);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
      if(!rsbac_ind_softmode[SW_RES])
        ret_result = adf_and_plus(ret_result, mod_result[SW_RES]);
#endif
    }
#endif  /* RES */

/****** REG *******/
#if defined(CONFIG_RSBAC_REG)
if(ignore_module != SW_REG)
  {
    mod_result[SW_REG]= rsbac_adf_request_reg (request,
                                            caller_pid,
                                            target,
                                            *tid_p,
                                            attr,
                                            *attr_val_p,
                                            owner);
    result = adf_and_plus(result, mod_result[SW_REG]);
#ifdef CONFIG_RSBAC_SOFTMODE_IND
    if(!rsbac_ind_softmode[SW_REG])
      ret_result = adf_and_plus(ret_result, mod_result[SW_REG]);
#endif
  }
#endif  /* REG */

#endif /* !MAINT */

/****************************/

#if defined(CONFIG_RSBAC_DEBUG) && defined(CONFIG_RSBAC_NET)
    if(    rsbac_debug_adf_net
       && (   (target == T_NETDEV)
           || (target == T_NETTEMP)
           || (target == T_NETOBJ)
          )
      )
      do_log = TRUE;
#endif

/* log based on process owner */
#ifdef CONFIG_RSBAC_IND_USER_LOG
    i_tid.user = owner;
    if (rsbac_get_attr(SW_GEN,
                       T_USER,
                       i_tid,
                       A_log_user_based,
                       &i_attr_val,
                       FALSE))
      {
        rsbac_ds_get_error("rsbac_adf_request()", A_log_user_based);
      }
    else
      {
        if(((rsbac_request_vector_t) 1 << request) & i_attr_val.log_user_based)
          do_log = TRUE;
      }
#endif /* CONFIG_RSBAC_IND_USER_LOG */

/* log based on program */
#ifdef CONFIG_RSBAC_IND_PROG_LOG
    if(!do_log)
      {
        i_tid.process = caller_pid;
        if (rsbac_get_attr(SW_GEN,
                           T_PROCESS,
                           i_tid,
                           A_log_program_based,
                           &i_attr_val,
                           FALSE))
          {
            rsbac_ds_get_error("rsbac_adf_request()", A_log_program_based);
          }
        else
          {
            if(((rsbac_request_vector_t) 1 << request) & i_attr_val.log_program_based) 
              do_log = TRUE;
          }
      }
#endif /* CONFIG_RSBAC_IND_PROG_LOG */

/*****************************************************/
/* General work for all modules - after module calls */
/* Note: the process' individual logging attributes are needed above */
    switch(request)
      {
        case R_TERMINATE:
            if (target == T_PROCESS)
              rsbac_remove_target(T_PROCESS,*tid_p);
            break;

#ifdef CONFIG_RSBAC_USER_CHOWN
	case R_CHANGE_OWNER:
		if (target == T_PROCESS) {
			i_tid.user = attr_val_p->owner;
			i_attr_val.process = tid_p->process;
			result = adf_and_plus(result,
				rsbac_adf_request_int(request,
					caller_pid,
					T_USER,
					&i_tid,
					A_process,
					&i_attr_val,
					ignore_module));
		}
		break;
#endif

        default:
            break;
      }

/* logging request on info level, if requested by file/dir/dev attributes */
/* log_array_low/high, or, if that is requested, if enabled for this request */
/* type (attributes state level, or that request based level is to be taken) */
/* loglevel 2: log everything */
/* loglevel 1: log, if denied */
/* loglevel 0: log nothing */

#ifdef CONFIG_RSBAC_IND_LOG /* only if individual logging is enabled */
    /* if file/dir/dev, depend log on log_arrays */
    /* (but not for file.device = 0) */
    /* log_on_request is TRUE */
    if(   !do_log
       && (   (   (   (target == T_FILE)
                   || (target == T_DIR)
                   || (target == T_FIFO)
                   || (target == T_SYMLINK)
                   || (target == T_UNIXSOCK)
                  )
               && RSBAC_MAJOR(tid_p->file.device)
               && RSBAC_MINOR(tid_p->file.device)
              )
           || (target == T_DEV)
          )
      )
      {
        if (rsbac_get_attr(SW_GEN,
                           target,
                           *tid_p,
                           A_log_array_low,
                           &i_attr_val,
                           FALSE))
          {
            rsbac_ds_get_error("rsbac_adf_request()", A_log_array_low);
          }
        else
          {
            if (rsbac_get_attr(SW_GEN,
                               target,
                               *tid_p,
                               A_log_array_high,
                               &i_attr_val2,
                               FALSE))
              {
                rsbac_ds_get_error("rsbac_adf_request()", A_log_array_high);
              }
            else
              { /* ll = low-bit for request | (high-bit for request as bit 1) */
                /* WARNING: we deal with u64 here, only logical operations and */
                /* shifts work correctly! */
                log_level =   ((i_attr_val.log_array_low   >> request) & 1)
                          | ( ((i_attr_val2.log_array_high >> request) & 1) << 1);
                if (   log_level == LL_full
                    || (   log_level == LL_denied
                        && (result == NOT_GRANTED
                            || result == UNDEFINED)) )
                  {
                    do_log = TRUE;
                  }
                if(log_level != LL_request)
                  log_on_request = FALSE;
              }
          }
      }
#endif /* CONFIG_RSBAC_IND_LOG */

#ifdef CONFIG_RSBAC_IND_NETDEV_LOG /* only if individual logging for netdev is enabled */
    /* if netdev, depend log on log_arrays */
    /* log_on_request is TRUE */
    if(   !do_log
       && (target == T_NETDEV)
      )
      {
        if (rsbac_get_attr(SW_GEN,
                           target,
                           *tid_p,
                           A_log_array_low,
                           &i_attr_val,
                           FALSE))
          {
            rsbac_ds_get_error("rsbac_adf_request()", A_log_array_low);
          }
        else
          {
            if (rsbac_get_attr(SW_GEN,
                               target,
                               *tid_p,
                               A_log_array_high,
                               &i_attr_val2,
                               FALSE))
              {
                rsbac_ds_get_error("rsbac_adf_request()", A_log_array_high);
              }
            else
              { /* ll = low-bit for request | (high-bit for request as bit 1) */
                /* WARNING: we deal with u64 here, only logical operations and */
                /* shifts work correctly! */
                log_level =   ((i_attr_val.log_array_low   >> request) & 1)
                          | ( ((i_attr_val2.log_array_high >> request) & 1) << 1);
                if (   log_level == LL_full
                    || (   log_level == LL_denied
                        && (result == NOT_GRANTED
                            || result == UNDEFINED)) )
                  {
                    do_log = TRUE;
                  }
                if(log_level != LL_request)
                  log_on_request = FALSE;
              }
          }
      }
#endif /* CONFIG_RSBAC_IND_NETDEV_LOG */

#ifdef CONFIG_RSBAC_IND_NETOBJ_LOG /* only if individual logging for net objects is enabled */
    /* if nettemp, netobj, depend log on log_arrays */
    /* (but not for file.device = 0) */
    /* log_on_request is TRUE */
    if(   !do_log
       && (   (target == T_NETTEMP)
           || (target == T_NETOBJ)
          )
      )
      {
        enum rsbac_attribute_t i_attr1, i_attr2;

        if(target == T_NETOBJ)
          {
            if(rsbac_net_remote_request(request))
              {
                i_attr1 = A_remote_log_array_low;
                i_attr2 = A_remote_log_array_high;
              }
            else
              {
                i_attr1 = A_local_log_array_low;
                i_attr2 = A_local_log_array_high;
              }
          }
        else
          {
            i_attr1 = A_log_array_low;
            i_attr2 = A_log_array_high;
          }
        if (rsbac_get_attr(SW_GEN,
                           target,
                           *tid_p,
                           i_attr1,
                           &i_attr_val,
                           FALSE))
          {
            rsbac_ds_get_error("rsbac_adf_request()", i_attr1);
          }
        else
          {
            if (rsbac_get_attr(SW_GEN,
                               target,
                               *tid_p,
                               i_attr2,
                               &i_attr_val2,
                               FALSE))
              {
                rsbac_ds_get_error("rsbac_adf_request()", i_attr2);
              }
            else
              { /* ll = low-bit for request | (high-bit for request as bit 1) */
                /* WARNING: we deal with u64 here, only logical operations and */
                /* shifts work correctly! */
                log_level =   ((i_attr_val.log_array_low   >> request) & 1)
                          | ( ((i_attr_val2.log_array_high >> request) & 1) << 1);
                if (   log_level == LL_full
                    || (   log_level == LL_denied
                        && (result == NOT_GRANTED
                            || result == UNDEFINED)) )
                  {
                    do_log = TRUE;
                  }
                if(log_level != LL_request)
                  log_on_request = FALSE;
              }
          }
      }
#endif /* CONFIG_RSBAC_IND_NETOBJ_LOG */

#ifdef CONFIG_RSBAC_NO_DECISION_ON_NETMOUNT
log:
#endif
    /* if enabled, try request based log level */
    if (   !do_log
        && log_on_request
        && (   rsbac_log_levels[request][target] == LL_full
            || (   rsbac_log_levels[request][target] == LL_denied
                && (result == NOT_GRANTED
                    || result == UNDEFINED)) ) )
      do_log = TRUE;

    if(do_log)
      {
        char * request_name;
        char * res_name;
        char * res_mods;
        char * target_type_name;
        char * target_id_name;
        char * attr_name;
        char * attr_val_name;
#ifdef CONFIG_RSBAC_NET_OBJ
        char * remote_ip_name;
#else
        char remote_ip_name[1];
#endif
        char * audit_uid_name;
        char  command[17];
        rsbac_pid_t parent_pid = 0;
        rsbac_uid_t audit_uid;
#ifdef CONFIG_RSBAC_LOG_PSEUDO
        rsbac_pseudo_t  pseudo = 0;
#endif
        char * program_path;

	/* parent pid */
	if(current->parent)
 	  parent_pid = task_pid(current->parent);

        /* rsbac_kmalloc all memory */
        request_name = rsbac_kmalloc(32);
        res_name = rsbac_kmalloc(32);
        res_mods = rsbac_kmalloc(RSBAC_MAXNAMELEN);
        target_type_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
        #ifdef CONFIG_RSBAC_LOG_FULL_PATH
        target_id_name
         = rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
           /* max. path name len + some extra */
        #else
        target_id_name = rsbac_kmalloc(2 * RSBAC_MAXNAMELEN);
           /* max. file name len + some extra */
        #endif
        #ifdef CONFIG_RSBAC_LOG_PROGRAM_FILE
        #ifdef CONFIG_RSBAC_LOG_FULL_PATH
        program_path
         = rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
           /* max. path name len + some extra */
        #else
        program_path = rsbac_kmalloc(2 * RSBAC_MAXNAMELEN);
           /* max. file name len + some extra */
        #endif
        #else
        program_path = rsbac_kmalloc(2);
        #endif
        attr_name = rsbac_kmalloc(32);
        attr_val_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
#ifdef CONFIG_RSBAC_NET_OBJ
        remote_ip_name = rsbac_kmalloc(32);
#endif
        audit_uid_name = rsbac_kmalloc(32);

        request_name[0] = (char) 0;
        target_type_name[0] = (char) 0;
        target_id_name[0] = (char) 0;
        program_path[0] = (char) 0;
        attr_name[0] = (char) 0;
        attr_val_name[0] = (char) 0;
        remote_ip_name[0] = (char) 0;
        audit_uid_name[0] = (char) 0;
        res_name[0] = (char) 0;
        res_mods[0] = (char) 0;
        command[0] = (char) 0;
        get_request_name(request_name, request);
    #if !defined(CONFIG_RSBAC_MAINT)
/*
        if(result == mod_result[SW_NONE])
          {
            strcat(res_mods, " SW_GEN");
          }
*/
    #if defined(CONFIG_RSBAC_MAC)
        if(result == mod_result[SW_MAC])
          {
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
            if(rsbac_ind_softmode[SW_MAC])
              strcat(res_mods, " MAC(Softmode)");
            else
            #endif
              strcat(res_mods, " MAC");
          }
    #endif
    #if defined(CONFIG_RSBAC_PM)
        if(result == mod_result[SW_PM])
          {
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
            if(rsbac_ind_softmode[SW_PM])
              strcat(res_mods, " PM(Softmode)");
            else
            #endif
              strcat(res_mods, " PM");
          }
    #endif
    #if defined(CONFIG_RSBAC_DAZ)
        if(result == mod_result[SW_DAZ])
          {
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
            if(rsbac_ind_softmode[SW_DAZ])
              strcat(res_mods, " DAZ(Softmode)");
            else
            #endif
              strcat(res_mods, " DAZ");
          }
    #endif
    #ifdef CONFIG_RSBAC_FF
        if(result == mod_result[SW_FF])
          {
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
            if(rsbac_ind_softmode[SW_FF])
              strcat(res_mods, " FF(Softmode)");
            else
            #endif
              strcat(res_mods, " FF");
          }
    #endif
    #ifdef CONFIG_RSBAC_RC
        if(result == mod_result[SW_RC])
          {
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
            if(rsbac_ind_softmode[SW_RC])
              strcat(res_mods, " RC(Softmode)");
            else
            #endif
              strcat(res_mods, " RC");
          }
    #endif
    #ifdef CONFIG_RSBAC_AUTH
        if(result == mod_result[SW_AUTH])
          {
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
            if(rsbac_ind_softmode[SW_AUTH])
              strcat(res_mods, " AUTH(Softmode)");
            else
            #endif
              strcat(res_mods, " AUTH");
          }
    #endif
    #ifdef CONFIG_RSBAC_ACL
        if(result == mod_result[SW_ACL])
          {
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
            if(rsbac_ind_softmode[SW_ACL])
              strcat(res_mods, " ACL(Softmode)");
            else
            #endif
              strcat(res_mods, " ACL");
          }
    #endif
    #ifdef CONFIG_RSBAC_CAP
        if(result == mod_result[SW_CAP])
          {
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
            if(rsbac_ind_softmode[SW_CAP])
              strcat(res_mods, " CAP(Softmode)");
            else
            #endif
              strcat(res_mods, " CAP");
          }
    #endif
    #ifdef CONFIG_RSBAC_JAIL
        if(result == mod_result[SW_JAIL])
          {
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
            if(rsbac_ind_softmode[SW_JAIL])
              strcat(res_mods, " JAIL(Softmode)");
            else
            #endif
              strcat(res_mods, " JAIL");
          }
    #endif
    #ifdef CONFIG_RSBAC_RES
        if(result == mod_result[SW_RES])
          {
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
            if(rsbac_ind_softmode[SW_RES])
              strcat(res_mods, " RES(Softmode)");
            else
            #endif
              strcat(res_mods, " RES");
          }
    #endif
    #ifdef CONFIG_RSBAC_REG
        if(result == mod_result[SW_REG])
          {
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
            if(rsbac_ind_softmode[SW_REG])
              strcat(res_mods, " REG(Softmode)");
            else
            #endif
              strcat(res_mods, " REG");
          }
    #endif
    #endif /* !MAINT */
        if(!res_mods[0])
          strcat(res_mods, " ADF");

        /* Get process audit_uid */
        i_tid.process = caller_pid;
        if (rsbac_get_attr(SW_GEN,T_PROCESS,i_tid,A_audit_uid,&i_attr_val,FALSE))
          {
            rsbac_ds_get_error("rsbac_adf_request()", A_audit_uid);
            return NOT_GRANTED;  /* something weird happened */
          }
        audit_uid = i_attr_val.audit_uid;
        if(audit_uid == RSBAC_NO_USER)
          audit_uid = owner;
        else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
          if (RSBAC_UID_SET(audit_uid))
            sprintf(audit_uid_name, "audit uid %u/%u, ",
                    RSBAC_UID_SET(audit_uid),
                    RSBAC_UID_NUM(audit_uid));
          else
#endif
          sprintf(audit_uid_name, "audit uid %u, ", RSBAC_UID_NUM(audit_uid));
        }
#ifdef CONFIG_RSBAC_LOG_PSEUDO
        /* Get owner's logging pseudo */
        i_tid.user = audit_uid;
        if (rsbac_get_attr(SW_GEN,T_USER,i_tid,A_pseudo,&i_attr_val,FALSE))
          {
            rsbac_ds_get_error("rsbac_adf_request()", A_pseudo);
            return NOT_GRANTED;  /* something weird happened */
          }
        /* if pseudo is not registered, return attribute value is 0 (see later) */
        pseudo = i_attr_val.pseudo;
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
        /* Get process remote_ip */
        i_tid.process = caller_pid;
        if (rsbac_get_attr(SW_GEN,T_PROCESS,i_tid,A_remote_ip,&i_attr_val,FALSE))
          {
            rsbac_ds_get_error("rsbac_adf_request()", A_remote_ip);
            return NOT_GRANTED;  /* something weird happened */
          }
        if(i_attr_val.remote_ip)
          sprintf(remote_ip_name, "remote ip %u.%u.%u.%u, ", NIPQUAD(i_attr_val.remote_ip));
#endif

        #ifdef CONFIG_RSBAC_LOG_PROGRAM_FILE
        {
          struct mm_struct * mm;
          struct vm_area_struct * vma;
          struct dentry * dentry_p = NULL;

          mm = current->mm;
          if(mm)
            {
              atomic_inc(&mm->mm_users);
              if(!down_read_trylock(&mm->mmap_sem))
                goto down_failed;
              vma = mm->mmap;
              while (vma)
                {
                  if(   (vma->vm_flags & VM_EXECUTABLE)
                     && vma->vm_file)
                    {
                      dentry_p = dget(vma->vm_file->f_dentry);
                      break;
                    }
                  vma = vma->vm_next;
                }
              up_read(&mm->mmap_sem);
              if(dentry_p)
                {
                  char * p = program_path;

                  p += sprintf(program_path, ", prog_file ");
                  #ifdef CONFIG_RSBAC_LOG_FULL_PATH
                  rsbac_get_full_path(dentry_p, p, CONFIG_RSBAC_MAX_PATH_LEN);
                  #else
                  int namelen = rsbac_min(dentry_p->d_name.len, RSBAC_MAXNAMELEN);

                  strncpy(p, dentry_p->d_name.name, namelen);
                  p[namelen]=0;
                  #endif
                  dput(dentry_p);
                }
down_failed:
              mmput_nosleep(mm);
            }
        }
        #endif
        get_target_name(target_type_name, target, target_id_name, *tid_p);
        get_attribute_name(attr_name, attr);
        get_attribute_value_name(attr_val_name, attr, attr_val_p);
        get_result_name(res_name, result);
        if ((current) && (current->comm))
          {
            strncpy(command,current->comm,16);          
            command[16] = (char) 0;
          }

#ifdef CONFIG_RSBAC_LOG_PSEUDO
        /* if pseudo is set, its value is != 0, else -> use id */
        if (pseudo)
          {
    #ifdef CONFIG_RSBAC_SOFTMODE
            if(rsbac_softmode)
              rsbac_printk(KERN_INFO "rsbac_adf_request(): request %s, pid %u, ppid %u, prog_name %s%s, pseudo %u, %starget_type %s, tid %s, attr %s, value %s, result %s (Softmode) by%s\n",
                           request_name, pid_nr(caller_pid), parent_pid, command, program_path, pseudo, remote_ip_name, target_type_name, target_id_name, attr_name, attr_val_name, res_name, res_mods);
            else
    #endif
              rsbac_printk(KERN_INFO "rsbac_adf_request(): request %s, pid %u, ppid %u, prog_name %s%s, pseudo %u, %starget_type %s, tid %s, attr %s, value %s, result %s by%s\n",
                           request_name, pid_nr(caller_pid), parent_pid, command, program_path, pseudo, remote_ip_name, target_type_name, target_id_name, attr_name, attr_val_name, res_name, res_mods);
          }
        else
#endif
          {
            char * owner_name;
                    
            owner_name = rsbac_kmalloc(32);
#ifdef CONFIG_RSBAC_UM_VIRTUAL
            if (RSBAC_UID_SET(owner))
              sprintf(owner_name, "%u/%u",
                      RSBAC_UID_SET(owner),
                      RSBAC_UID_NUM(owner));
            else
#endif
              sprintf(owner_name, "%u", RSBAC_UID_NUM(owner));
    #ifdef CONFIG_RSBAC_SOFTMODE
            if(rsbac_softmode)
              rsbac_printk(KERN_INFO "rsbac_adf_request(): request %s, pid %u, ppid %u, prog_name %s%s, uid %s, %s%starget_type %s, tid %s, attr %s, value %s, result %s (Softmode) by%s\n",
                           request_name, pid_nr(caller_pid), pid_nr(parent_pid), command, program_path, owner_name, audit_uid_name, remote_ip_name, target_type_name, target_id_name, attr_name, attr_val_name, res_name, res_mods);
            else
    #endif
              rsbac_printk(KERN_INFO "rsbac_adf_request(): request %s, pid %u, ppid %u, prog_name %s%s, uid %s, %s%starget_type %s, tid %s, attr %s, value %s, result %s by%s\n",
                           request_name, pid_nr(caller_pid), pid_nr(parent_pid), command, program_path, owner_name, audit_uid_name, remote_ip_name, target_type_name, target_id_name, attr_name, attr_val_name, res_name, res_mods);
            rsbac_kfree(owner_name);
          }
        /* rsbac_kfree all helper mem */
        rsbac_kfree(request_name);
        rsbac_kfree(res_name);
        rsbac_kfree(res_mods);
        rsbac_kfree(target_type_name);
        rsbac_kfree(target_id_name);
        rsbac_kfree(program_path);
        rsbac_kfree(attr_name);
        rsbac_kfree(attr_val_name);
#ifdef CONFIG_RSBAC_NET_OBJ
        rsbac_kfree(remote_ip_name);
#endif
        rsbac_kfree(audit_uid_name);
      }

/* UNDEFINED must never be returned -> change result */
    if(result == UNDEFINED)
      result = NOT_GRANTED;

/* count */
    rsbac_adf_request_count[target]++;
#ifdef CONFIG_RSBAC_XSTATS
    rsbac_adf_request_xcount[target][request]++;
#endif

/* return result */
    #ifdef CONFIG_RSBAC_SOFTMODE
    if(rsbac_softmode && !rsbac_internal)
      return DO_NOT_CARE;
    else
    #endif
    #ifdef CONFIG_RSBAC_SOFTMODE_IND
      return ret_result;
    #else
      return result; /* change for debugging! */
    #endif
  } /* end of rsbac_adf_request_int() */


/*****************************************************************************/
/* If the request returned granted and the operation is performed,           */
/* the following function is called by the AEF to get all aci set correctly. */
/* The second instance of target specification is the new target, if one has */
/* been created, otherwise its values are ignored.                           */
/* It returns 0 on success and an error from error.h otherwise.              */

EXPORT_SYMBOL(rsbac_adf_set_attr);
int  rsbac_adf_set_attr(
                      enum  rsbac_adf_request_t     request,
                            rsbac_pid_t             caller_pid,
                      enum  rsbac_target_t          target,
                      union rsbac_target_id_t       tid,
                      enum  rsbac_target_t          new_target,
                      union rsbac_target_id_t       new_tid,
                      enum  rsbac_attribute_t       attr,
                      union rsbac_attribute_value_t attr_val)
  {
    union rsbac_target_id_t i_tid;
    rsbac_uid_t owner;
    int   error = 0;
    rsbac_request_vector_t	request_vector;
    rsbac_boolean_t do_log = FALSE;
    rsbac_boolean_t log_on_request = TRUE;
    union rsbac_attribute_value_t i_attr_val;
#ifdef CONFIG_RSBAC_IND_LOG
    union rsbac_attribute_value_t i_attr_val2;
    enum rsbac_log_level_t log_level;
#endif
#ifdef CONFIG_RSBAC_NO_DECISION_ON_NETMOUNT
    struct vfsmount * mnt_p;
#endif

/* No attribute setting possible before init (called at boot time) */

   if (!rsbac_is_initialized())
      return 0;

/* kernel (pid 0) is ignored */
    if (   !pid_nr(caller_pid)
        #if defined(CONFIG_RSBAC_LOG_REMOTE)
        || (caller_pid == rsbaclogd_pid)
        #endif
       )
      return 0;
/* Checking base values */
    if(   request >= R_NONE
       || target > T_NONE
       || new_target > T_NONE
       || attr > A_none)
      {
        rsbac_printk(KERN_WARNING
               "rsbac_adf_set_attr(): called with invalid request, target or attribute\n");
        return(-RSBAC_EINVALIDVALUE);
      }

    if (in_interrupt())
      {
        char * request_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);

        if(request_name)
          {
            get_request_name(request_name, request);
            printk(KERN_WARNING "rsbac_adf_set_attr(): called from interrupt: request %s, pid %u(%s), attr_val %u!\n",
                   request_name, pid_nr(caller_pid), current->comm, attr_val.dummy);
            rsbac_kfree(request_name);
          }
        else
          {
            printk(KERN_WARNING "rsbac_adf_set_attr(): called from interrupt: request %u, pid %u(%s)!\n",
                   request, pid_nr(caller_pid), current->comm);
          }
        dump_stack();
        return -RSBAC_EFROMINTERRUPT;
      }

    request_vector = RSBAC_REQUEST_VECTOR(request);

/* Getting basic information about this adf_set_attr-call */

    owner = RSBAC_NO_USER;
    /* only useful for real process, not idle or init */
    if (pid_nr(caller_pid) > 1)
      {
        error = rsbac_get_owner(&owner);
        if(error)
          {
            rsbac_printk(KERN_DEBUG
                   "rsbac_adf_set_attr(): caller_pid %i, RSBAC not initialized, returning 0",
                   pid_nr(caller_pid));
            return 0;      /* Startup-Sequence (see above) */
          }
      }
    else /* caller_pid = 1  -> init -> owner = root */
      owner = 0;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
    if ((attr == A_owner) && (RSBAC_UID_SET(attr_val.owner) > RSBAC_UM_VIRTUAL_MAX))
      attr_val.owner = RSBAC_GEN_UID(RSBAC_UID_SET(owner), attr_val.owner);
    else
    if ((attr == A_group) && (RSBAC_GID_SET(attr_val.group) > RSBAC_UM_VIRTUAL_MAX))
      attr_val.group = RSBAC_GEN_GID(RSBAC_UID_SET(owner), attr_val.group);
#else
    if (attr == A_owner)
      attr_val.owner = RSBAC_UID_NUM(attr_val.owner);
    else
    if (attr == A_group)
      attr_val.group = RSBAC_GID_NUM(attr_val.group);
#endif

/*************************************************/
/* General work for all modules - before modules */
#if defined(CONFIG_RSBAC_NO_DECISION_ON_NETMOUNT) || defined(CONFIG_RSBAC_FD_CACHE)
    switch (target) {
      case T_DIR:
#if defined(CONFIG_RSBAC_NO_DECISION_ON_NETMOUNT)
        if ((mnt_p = rsbac_get_vfsmount(tid.file.device))
            && (   (mnt_p->mnt_sb->s_magic == NFS_SUPER_MAGIC)
                || (mnt_p->mnt_sb->s_magic == CODA_SUPER_MAGIC)
                || (mnt_p->mnt_sb->s_magic == NCP_SUPER_MAGIC)
                || (mnt_p->mnt_sb->s_magic == SMB_SUPER_MAGIC)
               )
        ) {
          error = 0;
          goto log;
        }
#endif
        /* Ensure that there are no leftover attributes */
        if (request == R_CREATE) {
          rsbac_remove_target(new_target, new_tid);
#if defined(CONFIG_RSBAC_FD_CACHE)
          rsbac_fd_cache_invalidate(&new_tid.file);
#endif
        }
#if defined(CONFIG_RSBAC_FD_CACHE)
        else
          if (request == R_RENAME)
            rsbac_fd_cache_invalidate_all();
#endif
        break;

      case T_FILE:
      case T_FIFO:
      case T_SYMLINK:
      case T_UNIXSOCK:
#if defined(CONFIG_RSBAC_NO_DECISION_ON_NETMOUNT)
        if ((mnt_p = rsbac_get_vfsmount(tid.file.device))
            && (   (mnt_p->mnt_sb->s_magic == NFS_SUPER_MAGIC)
                || (mnt_p->mnt_sb->s_magic == CODA_SUPER_MAGIC)
                || (mnt_p->mnt_sb->s_magic == NCP_SUPER_MAGIC)
                || (mnt_p->mnt_sb->s_magic == SMB_SUPER_MAGIC)
               )
          ) {
          error = 0;
          goto log;
        }
#endif
#if defined(CONFIG_RSBAC_FD_CACHE)
        if (request == R_RENAME)
          rsbac_fd_cache_invalidate(&tid.file);
#endif
        break;

      case T_PROCESS:
        if (   (request == R_CLONE)
            && !new_tid.process
           ) {
		rsbac_printk(KERN_WARNING "rsbac_adf_set_attr(): tid for new process in CLONE is NULL!\n");
		return -RSBAC_EINVALIDTARGET;
        }
        break;

      default:
        break;
    }
#endif

/**********************************************************/
/* calling all decision modules, building a common result */


#ifdef CONFIG_RSBAC_DEBUG
/* first, check for valid request/target combination      */
error |= rsbac_adf_set_attr_check(request,
                                  caller_pid,
                                  target,
                                  tid,
                                  new_target,
                                  new_tid,
                                  attr,
                                  attr_val,
                                  owner);
if(error)
  goto general_work;
#endif

#if !defined(CONFIG_RSBAC_MAINT)
/******* MAC ********/
#if defined(CONFIG_RSBAC_MAC)
#ifdef CONFIG_RSBAC_SWITCH_MAC
if (rsbac_switch_mac)
#endif
  if(request_vector & RSBAC_MAC_SET_ATTR_VECTOR)
    error |= rsbac_adf_set_attr_mac(request,
                                  caller_pid,
                                  target,
                                  tid,
                                  new_target,
                                  new_tid,
                                  attr,
                                  attr_val,
                                  owner);
#endif  /* MAC */

/******* PM ********/
#ifdef CONFIG_RSBAC_PM
#ifdef CONFIG_RSBAC_SWITCH_PM
if (rsbac_switch_pm)
#endif
  if(request_vector & RSBAC_PM_SET_ATTR_VECTOR)
    error |= rsbac_adf_set_attr_pm (request,
                                  caller_pid,
                                  target,
                                  tid,
                                  new_target,
                                  new_tid,
                                  attr,
                                  attr_val,
                                  owner);
#endif  /* PM */

/******* DAZ ********/
#ifdef CONFIG_RSBAC_DAZ
#ifdef CONFIG_RSBAC_SWITCH_DAZ
if (rsbac_switch_daz)
#endif
  if(request_vector & RSBAC_DAZ_SET_ATTR_VECTOR)
    error |= rsbac_adf_set_attr_daz (request,
                                  caller_pid,
                                  target,
                                  tid,
                                  new_target,
                                  new_tid,
                                  attr,
                                  attr_val,
                                  owner);
#endif  /* DAZ */

/******* RC ********/
#ifdef CONFIG_RSBAC_RC
#ifdef CONFIG_RSBAC_SWITCH_RC
if (rsbac_switch_rc)
#endif
  error |= rsbac_adf_set_attr_rc (request,
                                  caller_pid,
                                  target,
                                  tid,
                                  new_target,
                                  new_tid,
                                  attr,
                                  attr_val,
                                  owner);
#endif  /* RC */

/****** AUTH *******/
#ifdef CONFIG_RSBAC_AUTH
#ifdef CONFIG_RSBAC_SWITCH_AUTH
if (rsbac_switch_auth)
#endif
  if(request_vector & RSBAC_AUTH_SET_ATTR_VECTOR)
    error |= rsbac_adf_set_attr_auth(request,
                                   caller_pid,
                                   target,
                                   tid,
                                   new_target,
                                   new_tid,
                                   attr,
                                   attr_val,
                                   owner);
#endif  /* AUTH */

/****** CAP *******/
#ifdef CONFIG_RSBAC_CAP
#ifdef CONFIG_RSBAC_SWITCH_CAP
if (rsbac_switch_cap)
#endif
  if(request_vector & RSBAC_CAP_SET_ATTR_VECTOR)
    error |= rsbac_adf_set_attr_cap (request,
                                   caller_pid,
                                   target,
                                   tid,
                                   new_target,
                                   new_tid,
                                   attr,
                                   attr_val,
                                   owner);
#endif  /* CAP */

/****** JAIL *******/
#ifdef CONFIG_RSBAC_JAIL
#ifdef CONFIG_RSBAC_SWITCH_JAIL
if (rsbac_switch_jail)
#endif
  if(request_vector & RSBAC_JAIL_SET_ATTR_VECTOR)
    error |= rsbac_adf_set_attr_jail(request,
                                   caller_pid,
                                   target,
                                   tid,
                                   new_target,
                                   new_tid,
                                   attr,
                                   attr_val,
                                   owner);
#endif  /* JAIL */

/****** RES *******/
#ifdef CONFIG_RSBAC_RES
#ifdef CONFIG_RSBAC_SWITCH_RES
if (rsbac_switch_res)
#endif
  if(request_vector & RSBAC_RES_SET_ATTR_VECTOR)
    error |= rsbac_adf_set_attr_res (request,
                                   caller_pid,
                                   target,
                                   tid,
                                   new_target,
                                   new_tid,
                                   attr,
                                   attr_val,
                                   owner);
#endif  /* RES */

/****** REG *******/
#ifdef CONFIG_RSBAC_REG
  error |= rsbac_adf_set_attr_reg (request,
                                   caller_pid,
                                   target,
                                   tid,
                                   new_target,
                                   new_tid,
                                   attr,
                                   attr_val,
                                   owner);
#endif  /* REG */
#endif /* !MAINT */

/* General work for all modules (after set_attr call) */
#ifdef CONFIG_RSBAC_DEBUG
general_work:
#endif
    switch(request)
      {
        /* remove deleted item from rsbac data */
        case R_DELETE :
            switch (target)
              {
                case T_FILE:
                case T_FIFO:
                case T_SYMLINK:
                  /* Only remove file/fifo target on deletion of last link */
                  if (   (attr == A_nlink)
                      && (attr_val.nlink > 1)
                     )
                     break;
                  /* fall through */
                case T_DIR:
                  rsbac_remove_target(target,tid);
                  break;
                case T_IPC:
                  /* shm removal delayed and removed directly, when destroyed */
                  if(tid.ipc.type != I_shm)
                    rsbac_remove_target(target,tid);
                  break;
                default:
                  break;
              }
            break;

        case R_CLONE:
            switch (target)
              {
                case T_PROCESS:
                  #if defined(CONFIG_RSBAC_IND_PROG_LOG)
                  /* get program based log from old process */
                  if (rsbac_get_attr(SW_GEN,
                                     target,
                                     tid,
                                     A_log_program_based,
                                     &i_attr_val,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr()", A_log_program_based);
                    }
                  else
                    { /* only set, if not default value 0 */
                      if(i_attr_val.log_program_based)
                        {
                          /* set program based log for new process */
                          if (rsbac_set_attr(SW_GEN, new_target,
                                             new_tid,
                                             A_log_program_based,
                                             i_attr_val))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr()", A_log_program_based);
                            }
                        }
                    }
                  #endif
                  #if defined(CONFIG_RSBAC_FAKE_ROOT_UID)
                  /* get fake_root_uid from old process */
                  if (rsbac_get_attr(SW_GEN,
                                     target,
                                     tid,
                                     A_fake_root_uid,
                                     &i_attr_val,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr()", A_fake_root_uid);
                    }
                  else
                    { /* only set, of not default value 0 */
                      if(i_attr_val.fake_root_uid)
                        {
                          /* set program based log for new process */
                          if (rsbac_set_attr(SW_GEN, new_target,
                                             new_tid,
                                             A_fake_root_uid,
                                             i_attr_val))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr()", A_fake_root_uid);
                            }
                        }
                    }
                  #endif
                  #if defined(CONFIG_RSBAC_NET)
                  /* get remote_ip from old process */
                  if (rsbac_get_attr(SW_GEN,
                                     target,
                                     tid,
                                     A_remote_ip,
                                     &i_attr_val,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr()", A_remote_ip);
                    }
                  else
                    { /* only set, of not default value 0 */
                      if(i_attr_val.remote_ip)
                        {
                          /* set program based log for new process */
                          if (rsbac_set_attr(SW_GEN, new_target,
                                             new_tid,
                                             A_remote_ip,
                                             i_attr_val))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr()", A_remote_ip);
                            }
                        }
                    }
                  #endif
			/* get kernel_thread from old process */
			if (rsbac_get_attr(SW_GEN,
					target,
					tid,
					A_kernel_thread,
					&i_attr_val, FALSE)) {
				rsbac_ds_get_error("rsbac_adf_set_attr()",
						A_kernel_thread);
			} else {
				if (i_attr_val.kernel_thread) {
					if (rsbac_set_attr(SW_GEN, new_target,
							new_tid,
							A_kernel_thread,
							i_attr_val)) {
						rsbac_ds_set_error
							("rsbac_adf_set_attr()",
							 A_kernel_thread);
					}
				}
			}

                  /* get audit_uid from old process */
                  if (rsbac_get_attr(SW_GEN,
                                     target,
                                     tid,
                                     A_audit_uid,
                                     &i_attr_val,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr()", A_audit_uid);
                    }
                  else
                    { /* only set, of not default value NO_USER */
                      if(i_attr_val.audit_uid != RSBAC_NO_USER)
                        {
                          /* set audit uid for new process */
                          if (rsbac_set_attr(SW_GEN,
                                             new_target,
                                             new_tid,
                                             A_audit_uid,
                                             i_attr_val))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr()", A_audit_uid);
                            }
                        }
                    }
                  /* get auid_exempt from old process */
                  if (rsbac_get_attr(SW_GEN,
                                     target,
                                     tid,
                                     A_auid_exempt,
                                     &i_attr_val,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr()", A_auid_exempt);
                    }
                  else
                    { /* only set, of not default value NO_USER */
                      if(i_attr_val.auid_exempt != RSBAC_NO_USER)
                        {
                          /* set program based log for new process */
                          if (rsbac_set_attr(SW_GEN,
                                             new_target,
                                             new_tid,
                                             A_auid_exempt,
                                             i_attr_val))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr()", A_auid_exempt);
                            }
                        }
                    }
                  #ifdef CONFIG_RSBAC_UM_VIRTUAL
                  /* set vset of new process */
                  i_attr_val.vset = RSBAC_UID_SET(owner);
                  if(i_attr_val.vset)
                    {
                      /* set vset for new process */
                      if (rsbac_set_attr(SW_GEN, new_target,
                                         new_tid,
                                         A_vset,
                                         i_attr_val))
                        {
                          rsbac_ds_set_error("rsbac_adf_set_attr()", A_vset);
                        }
                    }
                  #endif
#if defined(CONFIG_RSBAC_AUTH_LEARN) || defined(CONFIG_RSBAC_CAP_LEARN)
                  /* copy program_file */
                  if (rsbac_get_attr(SW_GEN,
                                     target,
                                     tid,
                                     A_program_file,
                                     &i_attr_val,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr()", A_program_file);
                    }
                  else
                    { /* set program based log for new process */
                      if (rsbac_set_attr(SW_GEN, new_target,
                                         new_tid,
                                         A_program_file,
                                         i_attr_val))
                        {
                          rsbac_ds_set_error("rsbac_adf_set_attr()", A_program_file);
                        }
                    }
#endif
                  break;

                default:
                  break;
              }
            break;

	case R_CLOSE:
		switch (target) {
#if 0
		case T_IPC:
			if(   (tid.ipc.type == I_anonunix)
                           && (   (attr != A_nlink)
                               || (attr_val.nlink <= 1)
                              )
                          )
				rsbac_remove_target(target, tid);
			break;
#endif
#ifdef CONFIG_RSBAC_NET_OBJ
		case T_NETOBJ:
			rsbac_remove_target(target, tid);
			break;
#endif
		default:
			break;
		}
		break;

#if 0
	case R_CREATE:
		switch (target) {
		case T_IPC:
			if((tid.ipc.type != I_sem) && !tid.ipc.id.id_nr)
				error |= -RSBAC_EINVALIDVALUE;
			break;
		default:
			break;
		}
		break;
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
        case R_ACCEPT:
            switch (target)
              {
                case T_NETOBJ:
                  /* store remote IP */
                  if(   tid.netobj.sock_p
                     && tid.netobj.sock_p->ops
                     && tid.netobj.sock_p->sk
                     && (tid.netobj.sock_p->ops->family == AF_INET)
                    )
                    {
                      i_tid.process = caller_pid;
                      i_attr_val.remote_ip = inet_sk(tid.netobj.sock_p->sk)->inet_daddr;
                      /* set program based log for new process */
                      if (rsbac_set_attr(SW_GEN,
                                         T_PROCESS,
                                         i_tid,
                                         A_remote_ip,
                                         i_attr_val))
                        {
                          rsbac_ds_set_error("rsbac_adf_set_attr()", A_remote_ip);
                        }
                    }
                  break;

                default:
                  break;
              }
            break;
#endif /* CONFIG_RSBAC_NET_OBJ */

        case R_EXECUTE :
            switch (target)
              {
                case T_FILE:
                  #if defined(CONFIG_RSBAC_IND_PROG_LOG)
                  /* get program based log from file */
                  if (rsbac_get_attr(SW_GEN,
                                     target,
                                     tid,
                                     A_log_program_based,
                                     &i_attr_val,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr()", A_log_program_based);
                    }
                  else
                    {
                      /* set program based log for process */
                      i_tid.process = caller_pid;
                      if (rsbac_set_attr(SW_GEN, T_PROCESS,
                                         i_tid,
                                         A_log_program_based,
                                         i_attr_val))
                        {
                          rsbac_ds_set_error("rsbac_adf_set_attr()", A_log_program_based);
                        }
                    }
                  #endif
                  #if defined(CONFIG_RSBAC_FAKE_ROOT_UID)
                  /* get fake_root_uid from file */
                  if (rsbac_get_attr(SW_GEN,
                                     target,
                                     tid,
                                     A_fake_root_uid,
                                     &i_attr_val,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr()", A_fake_root_uid);
                    }
                  else
                    {
                      /* set fake_root_uid for process */
                      if(i_attr_val.fake_root_uid)
                        {
                          i_tid.process = caller_pid;
                          if (rsbac_set_attr(SW_GEN, T_PROCESS,
                                             i_tid,
                                             A_fake_root_uid,
                                             i_attr_val))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr()", A_fake_root_uid);
                            }
                        }
                    }
                  #endif
                  #ifdef CONFIG_RSBAC_UM_VIRTUAL
                  /* get vset from file */
                  if (rsbac_get_attr(SW_GEN,
                                     target,
                                     tid,
                                     A_vset,
                                     &i_attr_val,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr()", A_vset);
                    }
                  else
                    {
                      /* set vset for process */
                      if(i_attr_val.vset != RSBAC_UM_VIRTUAL_KEEP)
                        {
                          i_tid.process = caller_pid;
                          if (rsbac_set_attr(SW_GEN, T_PROCESS,
                                             i_tid,
                                             A_vset,
                                             i_attr_val))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr()", A_fake_root_uid);
                            }
                        }
                    }
                  #endif
#if defined(CONFIG_RSBAC_AUTH_LEARN) || defined(CONFIG_RSBAC_CAP_LEARN)
                  /* remember executed file */
                  i_tid.process = caller_pid;
                  i_attr_val.program_file = tid.file;
                  if (rsbac_set_attr(SW_GEN,
                                     T_PROCESS,
                                     i_tid,
                                     A_program_file,
                                     i_attr_val))
                    {
                      rsbac_pr_set_error(A_program_file);
                    }
#endif
                  /* get auid_exempt from file */
                  if (rsbac_get_attr(SW_GEN,
                                     target,
                                     tid,
                                     A_auid_exempt,
                                     &i_attr_val,
                                     FALSE))
                    {
                      rsbac_ds_get_error("rsbac_adf_set_attr()", A_auid_exempt);
                    }
                  else
                    {
                      if(i_attr_val.auid_exempt != RSBAC_NO_USER)
                        {
                          /* set auid_exempt for process */
                          i_tid.process = caller_pid;
                          if (rsbac_set_attr(SW_GEN, T_PROCESS,
                                             i_tid,
                                             A_auid_exempt,
                                             i_attr_val))
                            {
                              rsbac_ds_set_error("rsbac_adf_set_attr()", A_auid_exempt);
                            }
                        }
                    }
                  break;

                default:
                  break;
              }
            break;

        default:
            break;
      }

#if defined(CONFIG_RSBAC_DEBUG) && defined(CONFIG_RSBAC_NET)
    if(    rsbac_debug_adf_net
       && (   (target == T_NETDEV)
           || (target == T_NETTEMP)
           || (target == T_NETOBJ)
          )
      )
      do_log = TRUE;
#endif

/* log based on process owner */
#ifdef CONFIG_RSBAC_IND_USER_LOG
    i_tid.user = owner;
    if (rsbac_get_attr(SW_GEN,
                       T_USER,
                       i_tid,
                       A_log_user_based,
                       &i_attr_val,
                       FALSE))
      {
        rsbac_ds_get_error("rsbac_adf_set_attr()", A_log_user_based);
      }
    else
      {
        if(((rsbac_request_vector_t) 1 << request) & i_attr_val.log_user_based) 
          do_log = TRUE;
      }
#endif /* CONFIG_RSBAC_IND_USER_LOG */

/* log based on program */
#ifdef CONFIG_RSBAC_IND_PROG_LOG
    if(!do_log)
      {
        i_tid.process = caller_pid;
        if (rsbac_get_attr(SW_GEN,
                           T_PROCESS,
                           i_tid,
                           A_log_program_based,
                           &i_attr_val,
                           FALSE))
          {
            rsbac_ds_get_error("rsbac_adf_set_attr()", A_log_program_based);
          }
        else
          {
            if(((rsbac_request_vector_t) 1 << request) & i_attr_val.log_program_based) 
              do_log = TRUE;
          }
      }
#endif /* CONFIG_RSBAC_IND_PROG_LOG */


/* logging request on info level, if requested by file/dir/dev attributes */
/* log_array_low/high, or, if that is requested, if enabled for this request */
/* type (attributes state level, or that request based level is to be taken) */
/* loglevel 2: log everything */
/* loglevel 1: log, if denied */
/* loglevel 0: log nothing */

#ifdef CONFIG_RSBAC_IND_LOG /* only if individual logging is enabled */
    /* if file/dir/dev, depend log on log_arrays */
    /* (but not for file.device = 0) */
    /* log_on_request is TRUE */
    if(!do_log)
      {
        if(   (   (   (target == T_FILE)
                   || (target == T_DIR)
                   || (target == T_FIFO)
                   || (target == T_SYMLINK)
                  )
               && RSBAC_MAJOR(tid.file.device)
               && RSBAC_MINOR(tid.file.device)
              )
           || (target == T_DEV)
          )
          {
            if (rsbac_get_attr(SW_GEN,
                               target,
                               tid,
                               A_log_array_low,
                               &i_attr_val,
                               FALSE))
              {
                rsbac_ds_get_error("rsbac_adf_set_attr()", A_log_array_low);
              }
            else
              {
                if (rsbac_get_attr(SW_GEN,
                                   target,
                                   tid,
                                   A_log_array_high,
                                   &i_attr_val2,
                                   FALSE))
                  {
                    rsbac_ds_get_error("rsbac_adf_set_attr()", A_log_array_high);
                  }
                else
                  { /* ll = low-bit for request | (high-bit for request as bit 1) */
                    log_level =   ((i_attr_val.log_array_low   >> request) & 1)
                              | ( ((i_attr_val2.log_array_high >> request) & 1) << 1);
                    if (   log_level == LL_full
                        || (   log_level == LL_denied
                            && error) )
                      {
                        do_log = TRUE;
                      }
                    if(log_level != LL_request)
                      log_on_request = FALSE;
                  }
              }
          }
      }
#endif /* CONFIG_RSBAC_IND_LOG */

#ifdef CONFIG_RSBAC_NO_DECISION_ON_NETMOUNT
log:
#endif
    /* if enabled, try request based log level */
    if (log_on_request
        && (   rsbac_log_levels[request][target] == LL_full
            || (   rsbac_log_levels[request][target] == LL_denied
                && error) ) )
      do_log = TRUE;

    if(do_log)
      {
        char * request_name;
        char * target_type_name;
        char * new_target_type_name;
        char * target_id_name;
        char * new_target_id_name;
        char * attr_name;
        rsbac_uid_t audit_uid;
        char * audit_uid_name;
#ifdef CONFIG_RSBAC_LOG_PSEUDO
        rsbac_pseudo_t  pseudo = 0;
#endif

        /* Get process audit_uid */
        i_tid.process = caller_pid;
        if (rsbac_get_attr(SW_GEN,T_PROCESS,i_tid,A_audit_uid,&i_attr_val,FALSE))
          {
            rsbac_ds_get_error("rsbac_adf_set_attr()", A_audit_uid);
            return -RSBAC_EREADFAILED;  /* something weird happened */
          }
        audit_uid_name = rsbac_kmalloc(32);
        audit_uid = i_attr_val.audit_uid;
        if(audit_uid == RSBAC_NO_USER) {
          audit_uid_name[0] = 0;
          audit_uid = owner;
        } else {
#ifdef CONFIG_RSBAC_UM_VIRTUAL
          if (RSBAC_UID_SET(audit_uid))
            sprintf(audit_uid_name, "audit uid %u/%u, ",
                    RSBAC_UID_SET(audit_uid),
                    RSBAC_UID_NUM(audit_uid));
          else
#endif
          sprintf(audit_uid_name, "audit uid %u, ", RSBAC_UID_NUM(audit_uid));
        }
#ifdef CONFIG_RSBAC_LOG_PSEUDO
        /* Get owner's logging pseudo */
        i_tid.user = audit_uid;
        if (rsbac_get_attr(SW_GEN,T_USER,i_tid,A_pseudo,&i_attr_val,FALSE))
          {
            rsbac_ds_get_error("rsbac_adf_set_attr()", A_pseudo);
            return -RSBAC_EREADFAILED;  /* something weird happened */
          }
        /* if pseudo is not registered, return attribute value is 0 (see later) */
        pseudo = i_attr_val.pseudo;
#endif

        /* rsbac_kmalloc all memory */
        request_name = rsbac_kmalloc(32);
        target_type_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
        new_target_type_name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
        #ifdef CONFIG_RSBAC_LOG_FULL_PATH
        target_id_name
         = rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
        new_target_id_name
         = rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
           /* max. path name len + some extra */
        #else
        target_id_name = rsbac_kmalloc(2 * RSBAC_MAXNAMELEN);
        new_target_id_name = rsbac_kmalloc(2 * RSBAC_MAXNAMELEN);
           /* max. file name len + some extra */
        #endif
        attr_name = rsbac_kmalloc(32);

        /* Getting basic information about this request */
        request_name[0] = (char) 0;
        target_type_name[0] = (char) 0;
        target_id_name[0] = (char) 0;
        new_target_type_name[0] = (char) 0;
        new_target_id_name[0] = (char) 0;
        attr_name[0] = (char) 0;
        get_request_name(request_name, request);
        get_target_name(target_type_name, target, target_id_name, tid);
        get_target_name(new_target_type_name, new_target,
                        new_target_id_name, new_tid);
        get_attribute_name(attr_name, attr);

#ifdef CONFIG_RSBAC_LOG_PSEUDO
        if(pseudo)
          rsbac_printk(KERN_INFO
                       "rsbac_adf_set_attr(): request %s, pid %u, pseudo %u, target_type %s, tid %s, new_target_type %s, new_tid %s, attr %s, value %u, error %i\n",
                       request_name, pid_nr(caller_pid), pseudo, target_type_name, target_id_name,
                       new_target_type_name, new_target_id_name, attr_name, attr_val.dummy, error);
        else
#endif
        {
          char * owner_name = rsbac_kmalloc(32);

#ifdef CONFIG_RSBAC_UM_VIRTUAL
          if (RSBAC_UID_SET(owner))
            sprintf(owner_name, "%u/%u",
                    RSBAC_UID_SET(owner),
                    RSBAC_UID_NUM(owner));
          else
#endif
            sprintf(owner_name, "%u", RSBAC_UID_NUM(owner));

          rsbac_printk(KERN_INFO
                       "rsbac_adf_set_attr(): request %s, pid %u, uid %s, %starget_type %s, tid %s, new_target_type %s, new_tid %s, attr %s, value %u, error %i\n",
                       request_name, pid_nr(caller_pid), owner_name, audit_uid_name, target_type_name, target_id_name,
                       new_target_type_name, new_target_id_name, attr_name, attr_val.dummy, error);
          rsbac_kfree(owner_name);
          rsbac_kfree(audit_uid_name);
        }
        /* rsbac_kfree all helper mem */
        rsbac_kfree(request_name);
        rsbac_kfree(target_type_name);
        rsbac_kfree(new_target_type_name);
        rsbac_kfree(target_id_name);
        rsbac_kfree(new_target_id_name);
        rsbac_kfree(attr_name);
      }

/* count */
    rsbac_adf_set_attr_count[target]++;
#ifdef CONFIG_RSBAC_XSTATS
    rsbac_adf_set_attr_xcount[target][request]++;
#endif

    return(error);
  } /* end of rsbac_adf_set_attr() */


/****************
 *
 * Secure Delete
 *
 ****************/

#ifdef CONFIG_RSBAC_SECDEL

/* open_by_dentry */
/* This is done by hand (copy from rsbac_read_open), because system calls */
/* are currently blocked by rsbac */

static int open_by_dentry(struct dentry * file_dentry_p, struct file * file_p)
  {
    int tmperr;

    if ( !(S_ISREG(file_dentry_p->d_inode->i_mode)) )
      { /* this is not a file! -> error! */
        rsbac_printk(KERN_WARNING
               "open_by_dentry(): expected file is not a file!\n");
        return -RSBAC_EWRITEFAILED;
      }
    /* Now we fill the file structure, and */
    /* if there is an open func, use it, otherwise ignore */
    if ((tmperr = init_private_file(file_p, file_dentry_p, O_WRONLY | O_SYNC)))
      {
        rsbac_printk(KERN_WARNING
               "open_by_dentry(): could not open file!\n");
        return -RSBAC_EWRITEFAILED;
      }
    /* Without a write function we get into troubles -> error */
    if ((!file_p->f_op) || (!file_p->f_op->write))
      {
        rsbac_printk(KERN_WARNING
               "open_by_dentry(): file write function missing!\n");
        return -RSBAC_EWRITEFAILED;
      }
    return 0;
  }

/*
 **********************
 * Secure File Truncation
 */
static int do_rsbac_sec_trunc(struct dentry * dentry_p,
                              loff_t new_len,
                              loff_t old_len,
                              u_int may_sync)
  {
#if defined(CONFIG_RSBAC_MAINT)
    return 0;
#else
    int                           err = 0;
    rsbac_boolean_t               need_overwrite = FALSE;

    if (!rsbac_is_initialized())
      return 0;
    /* security checks */
    if(   !dentry_p
       || !dentry_p->d_inode)
      return -RSBAC_EINVALIDPOINTER;
    if(!S_ISREG(dentry_p->d_inode->i_mode))
      return -RSBAC_EINVALIDTARGET;
    if(dentry_p->d_sb->s_magic == PIPEFS_MAGIC)
      return 0;
    if(new_len >= old_len)
      return 0;

    if (in_interrupt())
      {
        printk(KERN_WARNING "do_rsbac_sec_trunc(): called from interrupt: pid %u(%s)!\n",
                     current->pid, current->comm);
        dump_stack();
        return -RSBAC_EFROMINTERRUPT;
      }

    if(dentry_p->d_inode && !rsbac_writable(dentry_p->d_inode->i_sb))
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_write)
          {
            rsbac_printk(KERN_DEBUG
                   "do_rsbac_sec_trunc(): ignoring file %lu on network device %02u:%02u!\n",
                   dentry_p->d_inode->i_ino,
                   MAJOR(dentry_p->d_inode->i_sb->s_dev),
                   MINOR(dentry_p->d_inode->i_sb->s_dev));
          }
#endif
        return 0;
      }

    /******* PM ********/
    #ifdef CONFIG_RSBAC_PM
    #ifdef CONFIG_RSBAC_SWITCH_PM
    if (rsbac_switch_pm)
    #endif
      /* no need to call module, if already need_overwrite */
      if(!need_overwrite)
        need_overwrite = rsbac_need_overwrite_pm(dentry_p);
    #endif  /* PM */

    /******* FF ********/
    #ifdef CONFIG_RSBAC_FF
    #ifdef CONFIG_RSBAC_SWITCH_FF
    if (rsbac_switch_ff)
    #endif
      /* no need to call module, if already need_overwrite */
      if(!need_overwrite)
        need_overwrite = rsbac_need_overwrite_ff(dentry_p);
    #endif  /* FF */

    /******* RC ********/
    #ifdef CONFIG_RSBAC_RC
    #ifdef CONFIG_RSBAC_SWITCH_RC
    if (rsbac_switch_rc)
    #endif
      /* no need to call module, if already need_overwrite */
      if(!need_overwrite)
        need_overwrite = rsbac_need_overwrite_rc(dentry_p);
    #endif  /* RC */

    /****** RES *******/
    #ifdef CONFIG_RSBAC_RES
    #ifdef CONFIG_RSBAC_SWITCH_RES
    if (rsbac_switch_res)
    #endif
      /* no need to call module, if already need_overwrite */
      if(!need_overwrite)
        need_overwrite = rsbac_need_overwrite_res(dentry_p);
    #endif  /* RES */

    /****** REG *******/
    #ifdef CONFIG_RSBAC_REG
    if(!need_overwrite)
      need_overwrite = rsbac_need_overwrite_reg(dentry_p);
    #endif  /* REG */

    if(need_overwrite)
      {
        char            * buffer;
        struct file       file;
        int               tmperr = 0;
        mm_segment_t      oldfs;

        buffer = rsbac_kmalloc(RSBAC_SEC_DEL_CHUNK_SIZE);
        if(!buffer)
          return -RSBAC_ENOMEM;

#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_write)
          {
            rsbac_printk(KERN_DEBUG
                   "rsbac_sec_trunc(): zeroing of file %lu on device %02u:%02u from byte %lu to %lu!\n",
                   dentry_p->d_inode->i_ino,
                   MAJOR(dentry_p->d_inode->i_sb->s_dev),
                   MINOR(dentry_p->d_inode->i_sb->s_dev),
                   (u_long) new_len,
                   (u_long) old_len-1);
          }
#endif
        /* open */
        err = open_by_dentry(dentry_p, &file);
        if(err)
          {
            rsbac_kfree(buffer);
            return err;
          }

#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_write)
          {
            rsbac_printk(KERN_DEBUG
                   "rsbac_sec_trunc(): file %lu on device %02u:%02u is open, seeking to %lu!\n",
                   dentry_p->d_inode->i_ino,
                   MAJOR(dentry_p->d_inode->i_sb->s_dev),
                   MINOR(dentry_p->d_inode->i_sb->s_dev),
                   (u_long) new_len);
          }
#endif

        /* OK, now we can start writing */

        /* Set current user space to kernel space, because write() reads
         * from user space
         */
        oldfs = get_fs();
        set_fs(KERNEL_DS);

          { /* taken from fs/read_write.c */
            file.f_pos = new_len;
            file.f_version = 0;
          }
        memset(buffer,0,RSBAC_SEC_DEL_CHUNK_SIZE);

#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_write)
          {
            rsbac_printk(KERN_DEBUG
                   "rsbac_sec_trunc(): file %lu on device %02u:%02u is positioned, starting to write!\n",
                   dentry_p->d_inode->i_ino,
                   MAJOR(dentry_p->d_inode->i_sb->s_dev),
                   MINOR(dentry_p->d_inode->i_sb->s_dev));
          }
#endif
	while (new_len < old_len)
	{
		struct iovec iov = { .iov_base = buffer,
				.iov_len = rsbac_min(RSBAC_SEC_DEL_CHUNK_SIZE, old_len-new_len) };
		struct kiocb kiocb;

		init_sync_kiocb(&kiocb, &file);
		kiocb.ki_pos = file.f_pos;
		kiocb.ki_left = iov.iov_len;

		for (;;) {
			tmperr = blkdev_aio_write(&kiocb, &iov, 1, kiocb.ki_pos);
			if (tmperr != -EIOCBRETRY)
				break;
			wait_on_retry_sync_kiocb(&kiocb);
		}

		if (-EIOCBQUEUED == tmperr)
			tmperr = wait_on_sync_kiocb(&kiocb);
		file.f_pos = kiocb.ki_pos;

		if (tmperr < 0) {
			err = tmperr;
			break;
		}
		new_len += tmperr;
	}
        set_fs(oldfs);

#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_write)
          {
            rsbac_printk(KERN_DEBUG
                   "rsbac_sec_trunc(): syncing file %lu on device %02u:%02u!\n",
                   dentry_p->d_inode->i_ino,
                   MAJOR(dentry_p->d_inode->i_sb->s_dev),
                   MINOR(dentry_p->d_inode->i_sb->s_dev));
          }
#endif

	if(may_sync && (dentry_p->d_inode->i_size > 0))
          err = generic_file_fsync(&file, 0, dentry_p->d_inode->i_size - 1, 1);
          
        rsbac_kfree(buffer);
      }
    /* Ready. */
    return err;

#endif /* else of MAINT */
  }

EXPORT_SYMBOL(rsbac_sec_trunc);
int rsbac_sec_trunc(struct dentry * dentry_p,
                    loff_t new_len, loff_t old_len)
  {
    return do_rsbac_sec_trunc(dentry_p, new_len, old_len, TRUE);
  }

EXPORT_SYMBOL(rsbac_sec_del);
int rsbac_sec_del(struct dentry * dentry_p, u_int may_sync)
  {
    return do_rsbac_sec_trunc(dentry_p,
                              0,
                              dentry_p->d_inode->i_size,
                              may_sync);
  }

#else /* no SECDEL */
EXPORT_SYMBOL(rsbac_sec_trunc);
int rsbac_sec_trunc(struct dentry * dentry_p,
                    loff_t new_len, loff_t old_len)
  {
    return 0;
  }
EXPORT_SYMBOL(rsbac_sec_del);
int rsbac_sec_del(struct dentry * dentry_p, u_int may_sync)
  {
    return 0;
  }
#endif /* SECDEL */

#ifdef CONFIG_RSBAC_SYM_REDIR
EXPORT_SYMBOL(rsbac_symlink_redirect);

/* This function changes the symlink content by adding a suffix, if
 * requested. It returns NULL, if unchanged, or a pointer to a
 * kmalloc'd new char * otherwise, which has to be kfree'd after use.
 */
char * rsbac_symlink_redirect(
  struct inode * inode_p,
  const char * name,
  u_int maxlen)
  {
#if defined(CONFIG_RSBAC_SYM_REDIR_REMOTE_IP) || defined(CONFIG_RSBAC_SYM_REDIR_MAC) || defined(CONFIG_RSBAC_SYM_REDIR_RC) || defined(CONFIG_RSBAC_SYM_REDIR_UID)
    union rsbac_target_id_t * i_tid_p;
    int err;
    union rsbac_attribute_value_t i_attr_val;
#endif

    if(!name)
      return NULL;
    if(!inode_p)
      return NULL;
    if (!rsbac_is_initialized())
      return NULL;

    if(!S_ISLNK(inode_p->i_mode))
      {
        rsbac_printk(KERN_DEBUG
               "rsbac_symlink_redirect(): called for non-symlink inode %u on dev %02u:%02u!\n",
               inode_p->i_ino,
               RSBAC_MAJOR(inode_p->i_sb->s_dev), RSBAC_MINOR(inode_p->i_sb->s_dev) );
        return NULL;
      }

    if (in_interrupt())
      {
        printk(KERN_WARNING "rsbac_symlink_redirect(): called from interrupt: pid %u(%s)!\n",
                     current->pid, current->comm);
        dump_stack();
        return NULL;
      }

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG
               "rsbac_symlink_redirect(): called for symlink inode %u on dev %02u:%02u!\n",
               inode_p->i_ino,
               RSBAC_MAJOR(inode_p->i_sb->s_dev), RSBAC_MINOR(inode_p->i_sb->s_dev) );
      }
#endif

#if defined(CONFIG_RSBAC_SYM_REDIR_REMOTE_IP) || defined(CONFIG_RSBAC_SYM_REDIR_MAC) || defined(CONFIG_RSBAC_SYM_REDIR_RC) || defined(CONFIG_RSBAC_SYM_REDIR_UID)
    i_tid_p = kmalloc(sizeof(*i_tid_p), GFP_KERNEL);
    if(!i_tid_p)
      {
        rsbac_printk(KERN_DEBUG
           "rsbac_symlink_redirect(): not enough memory for symlink redir remote ip inode %u on dev %02u:%02u!\n",
           inode_p->i_ino,
           RSBAC_MAJOR(inode_p->i_sb->s_dev), RSBAC_MINOR(inode_p->i_sb->s_dev) );
        return NULL;
      }
    i_tid_p->symlink.device = inode_p->i_sb->s_dev;
    i_tid_p->symlink.inode = inode_p->i_ino;
    i_tid_p->symlink.dentry_p = NULL;
#endif

#ifdef CONFIG_RSBAC_SYM_REDIR_REMOTE_IP
    if ((err = rsbac_get_attr(SW_GEN,
                              T_SYMLINK,
                              *i_tid_p,
                              A_symlink_add_remote_ip,
                              &i_attr_val,
                              FALSE) ))
      {
        rsbac_ds_get_error_num("rsbac_symlink_redirect()", A_symlink_add_remote_ip, err);
        kfree(i_tid_p);
        return NULL;  /* something weird happened */
      }
    if(i_attr_val.symlink_add_remote_ip)
      {
        u_int len;
        rsbac_enum_t add_remote_ip;
        __u32 addr;
        char * new_name;

        add_remote_ip = i_attr_val.symlink_add_remote_ip;
        i_tid_p->process = task_pid(current);
        err = rsbac_get_attr(SW_GEN,
                             T_PROCESS,
                             *i_tid_p,
                             A_remote_ip,
                             &i_attr_val,
                             FALSE);
        kfree(i_tid_p);
        if (err)
          {
            rsbac_ds_get_error_num("rsbac_symlink_redirect()", A_remote_ip, err);
            return NULL;  /* something weird happened */
          }
        addr = i_attr_val.remote_ip;
        len = strlen(name);
#if 0
        while(   len
              && (name[len-1] >= '0')
              && (name[len-1] <= '9')
             )
          len--;

#endif
        if(len > (maxlen - 20))
          {
            rsbac_printk(KERN_DEBUG
               "rsbac_symlink_redirect(): not enough space for symlink inode %u on dev %02u:%02u!\n",
               inode_p->i_ino,
               RSBAC_MAJOR(inode_p->i_sb->s_dev), RSBAC_MINOR(inode_p->i_sb->s_dev) );
            return NULL;
          }
        new_name = kmalloc(len + 20, GFP_KERNEL);
        if(!new_name)
          {
            rsbac_printk(KERN_DEBUG
               "rsbac_symlink_redirect(): not enough memory for symlink redir remote ip inode %u on dev %02u:%02u!\n",
               inode_p->i_ino,
               RSBAC_MAJOR(inode_p->i_sb->s_dev), RSBAC_MINOR(inode_p->i_sb->s_dev) );
            return NULL;
          }
        strcpy(new_name, name);
        switch(add_remote_ip)
          {
            case 1:
              sprintf(new_name+len, "%u",
                      ((unsigned char *)&addr)[0]);
              break;
            case 2:
              sprintf(new_name+len, "%u.%u",
                      ((unsigned char *)&addr)[0],
                      ((unsigned char *)&addr)[1]);
              break;
            case 3:
              sprintf(new_name+len, "%u.%u.%u",
                      ((unsigned char *)&addr)[0],
                      ((unsigned char *)&addr)[1],
                      ((unsigned char *)&addr)[2]);
              break;
            default:
              sprintf(new_name+len, "%u.%u.%u.%u",
                      ((unsigned char *)&addr)[0],
                      ((unsigned char *)&addr)[1],
                      ((unsigned char *)&addr)[2],
                      ((unsigned char *)&addr)[3]);
          }
        return new_name;
      }
#endif

#ifdef CONFIG_RSBAC_SYM_REDIR_UID
    if ((err = rsbac_get_attr(SW_GEN,
                              T_SYMLINK,
                              *i_tid_p,
                              A_symlink_add_uid,
                              &i_attr_val,
                              FALSE) ))
      {
        rsbac_ds_get_error_num("rsbac_symlink_redirect()", A_symlink_add_uid, err);
        kfree(i_tid_p);
        return NULL;  /* something weird happened */
      }
    if(i_attr_val.symlink_add_uid)
      {
        rsbac_uid_t user;

        kfree(i_tid_p);
        if(!rsbac_get_owner(&user))
          {
            u_int len;
            u_int room = 20;
            char * new_name;

#ifdef CONFIG_RSBAC_UM_VIRTUAL
            if (RSBAC_UID_SET(user))
              room = 40;
#endif
            len = strlen(name);
            while(   len
                  && (   (   (name[len-1] >= '0')
                          && (name[len-1] <= '9')
                         )
#ifdef CONFIG_RSBAC_UM_VIRTUAL
                      || (name[len-1] == '-')
#endif
                     )
                 )
              len--;
            if(len > (maxlen - room))
              {
                rsbac_printk(KERN_DEBUG
                   "rsbac_symlink_redirect(): not enough space for symlink inode %u on dev %02u:%02u!\n",
                   inode_p->i_ino,
                   RSBAC_MAJOR(inode_p->i_sb->s_dev), RSBAC_MINOR(inode_p->i_sb->s_dev) );
                return NULL;
              }
            new_name = kmalloc(len + room, GFP_KERNEL);
            if(!new_name)
              {
                rsbac_printk(KERN_DEBUG
                   "rsbac_symlink_redirect(): not enough memory for symlink redir uid inode %u on dev %02u:%02u!\n",
                   inode_p->i_ino,
                   RSBAC_MAJOR(inode_p->i_sb->s_dev), RSBAC_MINOR(inode_p->i_sb->s_dev) );
                return NULL;
              }
            strcpy(new_name, name);
#ifdef CONFIG_RSBAC_UM_VIRTUAL
            if (RSBAC_UID_SET(user))
              sprintf(new_name+len, "%u-%u",
                      RSBAC_UID_SET(user), RSBAC_UID_NUM(user));
            else
#endif
            ulongtostr(new_name+len, RSBAC_UID_NUM(user));
            return new_name;
          }
        else
          return NULL;
      }
#endif

#ifdef CONFIG_RSBAC_SYM_REDIR_MAC
    if ((err = rsbac_get_attr(SW_GEN,
                              T_SYMLINK,
                              *i_tid_p,
                              A_symlink_add_mac_level,
                              &i_attr_val,
                              FALSE) ))
      {
        rsbac_ds_get_error_num("rsbac_symlink_redirect()", A_symlink_add_mac_level, err);
        kfree(i_tid_p);
        return NULL;  /* something weird happened */
      }
    if(i_attr_val.symlink_add_mac_level)
      {
        u_int len;
        char * new_name;

        i_tid_p->process = task_pid(current);
        if ((err = rsbac_get_attr(SW_MAC,
                                  T_PROCESS,
                                  *i_tid_p,
                                  A_current_sec_level,
                                  &i_attr_val,
                                  FALSE) ))
          {
            rsbac_ds_get_error_num("rsbac_symlink_redirect()", A_current_sec_level, err);
            kfree(i_tid_p);
            return NULL;  /* something weird happened */
          }

        len = strlen(name);
        while(   len
              && (   (   (name[len-1] >= '0')
                      && (name[len-1] <= '9')
                     )
#ifdef CONFIG_RSBAC_SYM_REDIR_MAC_CAT
                  || (name[len-1] == ':')
#endif
                 )
             )
          len--;
#ifdef CONFIG_RSBAC_SYM_REDIR_MAC_CAT
        if(len > (maxlen - 85))
#else
        if(len > (maxlen - 20))
#endif
          {
            rsbac_printk(KERN_DEBUG
               "rsbac_symlink_redirect(): not enough space for symlink inode %u on dev %02u:%02u!\n",
               inode_p->i_ino,
               RSBAC_MAJOR(inode_p->i_sb->s_dev), RSBAC_MINOR(inode_p->i_sb->s_dev) );
            kfree(i_tid_p);
            return NULL;
          }

#ifdef CONFIG_RSBAC_SYM_REDIR_MAC_CAT
        new_name = kmalloc(len + 85, GFP_KERNEL);
#else
        new_name = kmalloc(len + 20, GFP_KERNEL);
#endif
        if(!new_name)
          {
            rsbac_printk(KERN_DEBUG
               "rsbac_symlink_redirect(): not enough memory for symlink redir MAC level inode %u on dev %02u:%02u!\n",
               inode_p->i_ino,
               RSBAC_MAJOR(inode_p->i_sb->s_dev), RSBAC_MINOR(inode_p->i_sb->s_dev) );
            kfree(i_tid_p);
            return NULL;
          }
        strcpy(new_name, name);
#ifdef CONFIG_RSBAC_SYM_REDIR_MAC_CAT
        len+=sprintf(new_name+len, "%u:", i_attr_val.current_sec_level);
        if ((err = rsbac_get_attr(SW_MAC,
                                  T_PROCESS,
                                  *i_tid_p,
                                  A_mac_curr_categories,
                                  &i_attr_val,
                                  FALSE) ))
          {
            rsbac_ds_get_error_num("rsbac_symlink_redirect()", A_mac_curr_categories, err);
            kfree(i_tid_p);
            kfree(new_name);
            return NULL;  /* something weird happened */
          }
        kfree(i_tid_p);
        u64tostrmac(new_name+len, i_attr_val.mac_categories);
#else
        len+=sprintf(new_name+len, "%u", i_attr_val.current_sec_level);
#endif
        return new_name;
      }
#endif

#ifdef CONFIG_RSBAC_SYM_REDIR_RC
    if ((err = rsbac_get_attr(SW_GEN,
                              T_SYMLINK,
                              *i_tid_p,
                              A_symlink_add_rc_role,
                              &i_attr_val,
                              FALSE) ))
      {
        rsbac_ds_get_error_num("rsbac_symlink_redirect()", A_symlink_add_rc_role, err);
        kfree(i_tid_p);
        return NULL;  /* something weird happened */
      }
    if(i_attr_val.symlink_add_rc_role)
      {
        u_int len;
        char * new_name;

        i_tid_p->process = task_pid(current);
        err = rsbac_get_attr(SW_RC,
                             T_PROCESS,
                             *i_tid_p,
                             A_rc_role,
                             &i_attr_val,
                             FALSE);
        kfree(i_tid_p);
        if (err)
          {
            rsbac_ds_get_error_num("rsbac_symlink_redirect()", A_rc_role, err);
            return NULL;  /* something weird happened */
          }

        len = strlen(name);
        while(   len
              && (name[len-1] >= '0')
              && (name[len-1] <= '9')
             )
          len--;
        if(len > (maxlen - 20))
          {
            rsbac_printk(KERN_DEBUG
               "rsbac_symlink_redirect(): not enough space for symlink inode %u on dev %02u:%02u!\n",
               inode_p->i_ino,
               RSBAC_MAJOR(inode_p->i_sb->s_dev), RSBAC_MINOR(inode_p->i_sb->s_dev) );
            return NULL;
          }

        new_name = kmalloc(len + 20, GFP_KERNEL);
        if(!new_name)
          {
            rsbac_printk(KERN_DEBUG
               "rsbac_symlink_redirect(): not enough memory for symlink redir RC role inode %u on dev %02u:%02u!\n",
               inode_p->i_ino,
               RSBAC_MAJOR(inode_p->i_sb->s_dev), RSBAC_MINOR(inode_p->i_sb->s_dev) );
            return NULL;
          }
        strcpy(new_name, name);
        ulongtostr(new_name+len, i_attr_val.rc_role);
        return new_name;
      }
#endif

    kfree(i_tid_p);
    return NULL;
  }
#endif

#ifdef CONFIG_RSBAC_ALLOW_DAC_DISABLE_PART
int rsbac_dac_part_disabled(struct dentry * dentry_p)
  {
    int                            err;
    enum  rsbac_target_t           i_target;
    union rsbac_target_id_t        i_tid;
    union rsbac_attribute_value_t  i_attr_val;

    if(   !dentry_p
       || !dentry_p->d_inode
       || !dentry_p->d_inode->i_sb->s_dev
       || !rsbac_is_initialized()
       || !current->pid
       || (current->pid == 1))
      return FALSE;

    if(S_ISREG(dentry_p->d_inode->i_mode))
      i_target = T_FILE;
    else
    if(S_ISDIR(dentry_p->d_inode->i_mode))
      i_target = T_DIR;
    else
    if(S_ISFIFO(dentry_p->d_inode->i_mode))
      i_target = T_FIFO;
    else
    if(S_ISLNK(dentry_p->d_inode->i_mode))
      i_target = T_SYMLINK;
    else
      return FALSE;

    if (in_interrupt())
      {
        printk(KERN_WARNING "rsbac_dac_part_disabled(): called from interrupt: pid %u(%s)!\n",
                     current->pid, current->comm);
        dump_stack();
        return FALSE;
      }

    i_tid.file.device = dentry_p->d_sb->s_dev;
    i_tid.file.inode = dentry_p->d_inode->i_ino;
    i_tid.file.dentry_p = dentry_p;

#ifdef CONFIG_RSBAC_DEBUG
    if (rsbac_debug_aef)
      {
        rsbac_printk(KERN_DEBUG
               "rsbac_dac_part_disable(): called for dentry_p->d_inode %u on dev %02u:%02u, dentry_p %p!\n",
               i_tid.file.inode,
               RSBAC_MAJOR(i_tid.file.device), RSBAC_MINOR(i_tid.file.device),
               i_tid.file.dentry_p );
      }
#endif

    if ((err = rsbac_get_attr(SW_GEN,
                              i_target,
                              i_tid,
                              A_linux_dac_disable,
                              &i_attr_val,
                              TRUE) ))
      {
        rsbac_printk(KERN_WARNING
               "rsbac_dac_part_disable(): rsbac_get_attr() for linux_dac_disable returned error %i!\n",
               err);
        return FALSE;  /* something weird happened */
      }
    if(i_attr_val.linux_dac_disable == LDD_true)
      return TRUE;
    else
      return FALSE;
  }
#endif

#ifdef CONFIG_RSBAC_FAKE_ROOT_UID
rsbac_uid_t rsbac_fake_uid(void)
  {
    int                            err;
    union rsbac_target_id_t        i_tid;
    union rsbac_attribute_value_t  i_attr_val;

    if(!current_uid())
      return 0;
    if (!rsbac_is_initialized())
      return current_uid();
    if (in_interrupt())
      {
        printk(KERN_WARNING "rsbac_fake_uid(): called from interrupt: pid %u(%s)!\n",
                     current->pid, current->comm);
        dump_stack();
        return current_uid();
      }

    i_tid.process = task_pid(current);
    if ((err = rsbac_get_attr(SW_GEN,
                              T_PROCESS,
                              i_tid,
                              A_fake_root_uid,
                              &i_attr_val,
                              FALSE) ))
      {
        rsbac_ds_get_error("rsbac_fake_uid()", A_fake_root_uid);
        return current_uid();
      }
    switch(i_attr_val.fake_root_uid)
      {
        case FR_both:
        case FR_uid_only:
          return 0;
        default:
          return current_uid();
      }
  }

rsbac_uid_t rsbac_fake_euid(void)
  {
    int                            err;
    union rsbac_target_id_t        i_tid;
    union rsbac_attribute_value_t  i_attr_val;

    if(!current_euid())
      return 0;
    if (!rsbac_is_initialized())
      return current_euid();

    if (in_interrupt())
      {
        printk(KERN_WARNING "rsbac_fake_euid(): called from interrupt: pid %u(%s)!\n",
                     current->pid, current->comm);
        dump_stack();
        return current_euid();
      }

    i_tid.process = task_pid(current);
    if ((err = rsbac_get_attr(SW_GEN,
                              T_PROCESS,
                              i_tid,
                              A_fake_root_uid,
                              &i_attr_val,
                              FALSE) ))
      {
        rsbac_ds_get_error("rsbac_fake_euid()", A_fake_root_uid);
        return current_euid();
      }
    switch(i_attr_val.fake_root_uid)
      {
        case FR_both:
        case FR_euid_only:
          return 0;
        default:
          return current_euid();
      }
  }

int rsbac_uid_faked(void)
  {
    int                            err;
    union rsbac_target_id_t        i_tid;
    union rsbac_attribute_value_t  i_attr_val;

    if (!rsbac_is_initialized())
      return 0;

    if (in_interrupt())
      {
        printk(KERN_WARNING "rsbac_uid_faked(): called from interrupt: pid %u(%s)!\n",
                     current->pid, current->comm);
        dump_stack();
        return 0;
      }

    i_tid.process = task_pid(current);
    if ((err = rsbac_get_attr(SW_GEN,
                              T_PROCESS,
                              i_tid,
                              A_fake_root_uid,
                              &i_attr_val,
                              FALSE) ))
      {
        rsbac_ds_get_error("rsbac_uid_faked()", A_fake_root_uid);
        return 0;  /* something weird happened */
      }
    switch(i_attr_val.fake_root_uid)
      {
        case FR_both:
        case FR_uid_only:
          return 1;
        default:
          return 0;
      }
  }

#endif

int rsbac_set_audit_uid(rsbac_uid_t uid)
  {
    union rsbac_target_id_t       tid;
    union rsbac_attribute_value_t attr_val;

    if(!uid || (uid == current_uid()))
      return 0;

    if (in_interrupt())
      {
        printk(KERN_WARNING "rsbac_set_audit_uid(): called from interrupt: pid %u(%s)!\n",
                     current->pid, current->comm);
        dump_stack();
        return -RSBAC_EFROMINTERRUPT;
      }

    tid.process = task_pid(current);
    if (rsbac_get_attr(SW_GEN,
                       T_PROCESS,
                       tid,
                       A_audit_uid,
                       &attr_val,
                       FALSE))
      {
        rsbac_ds_get_error("rsbac_set_audit_uid()", A_audit_uid);
        return -RSBAC_EREADFAILED;
      }
    if(attr_val.audit_uid != RSBAC_NO_USER)
      return 0;

    if (rsbac_get_attr(SW_GEN,
                       T_PROCESS,
                       tid,
                       A_auid_exempt,
                       &attr_val,
                       FALSE))
      {
        rsbac_ds_get_error("rsbac_set_audit_uid()", A_auid_exempt);
        return -RSBAC_EREADFAILED;
      }
    if(attr_val.auid_exempt == uid)
      return 0;

    attr_val.audit_uid = uid;
    if (rsbac_set_attr(SW_GEN,
                       T_PROCESS,
                       tid,
                       A_audit_uid,
                       attr_val))
      {
        rsbac_ds_set_error("rsbac_set_audit_uid()", A_audit_uid);
        return -RSBAC_EWRITEFAILED;
      }
    return 0;
  }

#if defined(CONFIG_RSBAC_CAP_LOG_MISSING) || defined(CONFIG_RSBAC_JAIL_LOG_MISSING)
EXPORT_SYMBOL(rsbac_log_missing_cap);

void rsbac_log_missing_cap(int cap)
  {
    #if defined(CONFIG_RSBAC_CAP_LOG_MISSING) || defined(CONFIG_RSBAC_CAP_LEARN)
    #if defined(CONFIG_RSBAC_CAP_LOG_MISSING) && defined(CONFIG_RSBAC_CAP_LEARN)
    if(rsbac_cap_log_missing || rsbac_cap_learn)
    #elif defined(CONFIG_RSBAC_CAP_LEARN)
    if(rsbac_cap_learn)
    #else
    if(rsbac_cap_log_missing)
    #endif
      rsbac_cap_log_missing_cap(cap);
    #endif
    #if defined(CONFIG_RSBAC_JAIL_LOG_MISSING)
    if(rsbac_jail_log_missing)
      rsbac_jail_log_missing_cap(cap);
    #endif
  }
#endif

/* end of rsbac/adf/main.c */
