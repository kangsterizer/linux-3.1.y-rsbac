/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - ACL module                       */
/* File: rsbac/adf/acl/syscalls.c                    */
/*                                                   */
/* Author and (c) 1999-2009: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 15/Oct/2009                        */
/*************************************************** */

#include <linux/string.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/error.h>
#include <rsbac/acl.h>
#include <rsbac/getname.h>
#include <rsbac/acl_getname.h>
#include <rsbac/helpers.h>
#include <rsbac/debug.h>
#include <rsbac/rkmem.h>
#include <rsbac/adf_main.h>
#ifdef CONFIG_RSBAC_NET_OBJ
#include <net/sock.h>
#endif

/************************************************* */
/*           Global Variables                      */
/************************************************* */

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

rsbac_boolean_t rsbac_acl_check_super(enum  rsbac_target_t target,
                              union rsbac_target_id_t tid,
                                    rsbac_uid_t user)
  {
    rsbac_boolean_t                   i_result = FALSE;
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
        case T_DEV:
        case T_IPC:
        case T_SCD:
        case T_USER:
        case T_PROCESS:
#ifdef CONFIG_RSBAC_ACL_UM_PROT
        case T_GROUP:
#endif
        case T_NETDEV:
        case T_NETTEMP_NT:
        case T_NETTEMP:
        case T_NETOBJ:
          break;
        default:
          return TRUE;
      }
    /* own right */
    err = rsbac_acl_get_single_right(target,
                                     tid,
                                     ACLS_USER,
                                     (rsbac_acl_subject_id_t) user,
                                     ACLR_SUPERVISOR,
                                     &i_result);
    if(err)
      {
        char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_check_super(): rsbac_acl_get_single_right() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
        return FALSE;
      }
    if(i_result)
      return(TRUE);

    /* try SUPERVISOR for group and role */
    /* group everyone */
    err = rsbac_acl_get_single_right(target,
                                     tid,
                                     ACLS_GROUP,
                                     RSBAC_ACL_GROUP_EVERYONE,
                                     ACLR_SUPERVISOR,
                                     &i_result);
    if(err)
      {
        char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_check_super(): rsbac_acl_get_single_right() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
        return FALSE;
      }
    if(i_result)
      return(TRUE);

    #if defined(CONFIG_RSBAC_RC)
    /* use process role */
    /* first get role */
    i_tid.process = task_pid(current);
    if (rsbac_get_attr(SW_RC,
                       T_PROCESS,
                       i_tid,
                       A_rc_role,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_printk(KERN_WARNING
               "rsbac_acl_check_super(): rsbac_get_attr() for process rc_role returned error!\n");
      }
    else
      {
        err = rsbac_acl_get_single_right(target,
                                         tid,
                                         ACLS_ROLE,
                                         i_attr_val1.rc_role,
                                         ACLR_SUPERVISOR,
                                         &i_result);
        if(err)
          {
            char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

            if(tmp)
              {
                get_error_name(tmp,err);
                rsbac_printk(KERN_WARNING
                       "rsbac_acl_check_super(): rsbac_acl_get_single_right() returned error %s!\n",
                       tmp);
                rsbac_kfree(tmp);
              }
            return FALSE;
          }
        if(i_result)
          return(TRUE);
      }
    #endif

    /* other groups */
    /* first get user groups */
    group_p = NULL;
    err = rsbac_acl_get_user_groups(0, user, &group_p, NULL);
    if(err<0)
      {
        char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_check_super(): rsbac_acl_get_user_groups() returned error %s!\n",
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
                                            ACLR_SUPERVISOR,
                                            &i_result);
        if(tmperr)
          {
            char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

            if(tmp)
              {
                rsbac_printk(KERN_WARNING
                       "rsbac_acl_check_super(): rsbac_acl_get_single_right() returned error %s!\n",
                       get_error_name(tmp,tmperr));
                rsbac_kfree(tmp);
              }
            if(group_p)
              rsbac_kfree(group_p);
            return FALSE;
          }
        if(i_result)
          {
            if(group_p)
              rsbac_kfree(group_p);
            return(TRUE);
          }
      }
    if(group_p)
      rsbac_kfree(group_p);

    /* give up */
    return FALSE;
  };


#if !defined(CONFIG_RSBAC_MAINT)
rsbac_boolean_t rsbac_acl_check_forward(enum  rsbac_target_t target,
                                union rsbac_target_id_t tid,
                                      rsbac_uid_t user,
                                      rsbac_acl_rights_vector_t rights);

rsbac_boolean_t rsbac_acl_check_super(enum  rsbac_target_t target,
                              union rsbac_target_id_t tid,
                                    rsbac_uid_t user);

rsbac_boolean_t rsbac_acl_check_right(enum  rsbac_target_t target,
                              union rsbac_target_id_t tid,
                                    rsbac_uid_t user,
                                    rsbac_pid_t caller_pid,
                              enum  rsbac_adf_request_t request);
#endif

/************************************************* */
/*          Externally visible functions           */
/************************************************* */

int rsbac_acl_sys_set_acl_entry(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
  enum   rsbac_acl_subject_type_t    subj_type,
         rsbac_acl_subject_id_t      subj_id,
         rsbac_acl_rights_vector_t   rights,
         rsbac_time_t                ttl)
  {
    int err=0;

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
      /* sanity check before using pointer */
      if(   (target == T_NETOBJ)
         && tid.netobj.sock_p
         && (   tid.netobj.remote_addr
             || !tid.netobj.sock_p->file
             || !tid.netobj.sock_p->file->f_dentry
             || !tid.netobj.sock_p->file->f_dentry->d_inode
             || (SOCKET_I(tid.netobj.sock_p->file->f_dentry->d_inode) != tid.netobj.sock_p)
            )
        )
        return -RSBAC_EINVALIDTARGET;
#endif

/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_ACL
    if(rsbac_switch_acl)
#endif
      {
        rsbac_uid_t user;

        if(rsbac_get_owner(&user))
          return -RSBAC_EREADFAILED;
        /* first try access control right (SUPERVISOR try is included) */
        if(!rsbac_acl_check_right(target, tid, user, task_pid(current), ACLR_ACCESS_CONTROL))
          {
            /* no access control -> try forward for these rights */
            /* but only, if no ttl requested */
            if(   (ttl != RSBAC_LIST_TTL_KEEP)
               || !rsbac_acl_check_forward(target, tid, user, rights)
              )
              {
                char * rights_string = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                char * subject_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                char * target_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                #ifdef CONFIG_RSBAC_LOG_FULL_PATH
                char * target_id_name
                  = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
                /* max. path name len + some extra */
                #else
                char * target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
                /* max. file name len + some extra */
                #endif

                u64tostracl(rights_string, rights);
                get_acl_subject_type_name(subject_type_name, subj_type);
                get_target_name(target_type_name, target, target_id_name, tid);
                rsbac_printk(KERN_INFO
                       "rsbac_acl_sys_set_acl_entry(): setting rights %s for %s %u to %s %s denied for user %u!\n",
                       rights_string,
                       subject_type_name,
                       subj_id,
                       target_type_name,
                       target_id_name,
                       user);
                rsbac_kfree(rights_string);
                rsbac_kfree(subject_type_name);
                rsbac_kfree(target_type_name);
                rsbac_kfree(target_id_name);

                #ifdef CONFIG_RSBAC_SOFTMODE
                if(   !rsbac_softmode
                #ifdef CONFIG_RSBAC_SOFTMODE_IND
                   && !rsbac_ind_softmode[SW_ACL]
                #endif
                  )
                #endif
                  return(-EPERM);
              }
          }
        if(rights & RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR)
          {
            /* you must have SUPERVISOR to set SUPERVISOR */
            if(!rsbac_acl_check_super(target, tid, user))
              {
                char * subject_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                char * target_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                #ifdef CONFIG_RSBAC_LOG_FULL_PATH
                char * target_id_name
                  = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
                /* max. path name len + some extra */
                #else
                char * target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
                /* max. file name len + some extra */
                #endif

                get_acl_subject_type_name(subject_type_name, subj_type);
                get_target_name(target_type_name, target, target_id_name, tid);
                rsbac_printk(KERN_INFO
                       "rsbac_acl_sys_set_acl_entry(): setting SUPERVISOR for %s %u to %s %s denied for user %u!\n",
                       subject_type_name,
                       subj_id,
                       target_type_name,
                       target_id_name,
                       user);
                rsbac_kfree(subject_type_name);
                rsbac_kfree(target_type_name);
                rsbac_kfree(target_id_name);
                #ifdef CONFIG_RSBAC_SOFTMODE
                if(   !rsbac_softmode
                #ifdef CONFIG_RSBAC_SOFTMODE_IND
                   && !rsbac_ind_softmode[SW_ACL]
                #endif
                  )
                #endif
                  return(-EPERM);
              }
          }
      }
#endif /* !MAINT */

    /* OK, check passed. Set ACL. */
    err = rsbac_acl_set_acl_entry(ta_number, target, tid, subj_type, subj_id, rights, ttl);
    if(err)
      {
        char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_sys_set_acl_entry(): rsbac_acl_set_acl_entry() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
      }
    return err;
  }

int rsbac_acl_sys_remove_acl_entry(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
  enum   rsbac_acl_subject_type_t    subj_type,
         rsbac_acl_subject_id_t      subj_id)
  {
    int err=0;

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
      /* sanity check before using pointer */
      if(   (target == T_NETOBJ)
         && tid.netobj.sock_p
         && (   tid.netobj.remote_addr
             || !tid.netobj.sock_p->file
             || !tid.netobj.sock_p->file->f_dentry
             || !tid.netobj.sock_p->file->f_dentry->d_inode
             || (SOCKET_I(tid.netobj.sock_p->file->f_dentry->d_inode) != tid.netobj.sock_p)
            )
        )
        return -RSBAC_EINVALIDTARGET;
#endif

/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_ACL
    if(rsbac_switch_acl)
#endif
      {
        rsbac_uid_t user;
        rsbac_acl_rights_vector_t res_rights = 0;

        if(rsbac_get_owner(&user))
          return -RSBAC_EREADFAILED;
        /* first try access control right (SUPERVISOR is included) */
        if(!rsbac_acl_check_right(target, tid, user, task_pid(current), ACLR_ACCESS_CONTROL))
          {
            char * subject_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
            char * target_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
            #ifdef CONFIG_RSBAC_LOG_FULL_PATH
            char * target_id_name
              = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
            /* max. path name len + some extra */
            #else
            char * target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
            /* max. file name len + some extra */
            #endif

            get_acl_subject_type_name(subject_type_name, subj_type);
            get_target_name(target_type_name, target, target_id_name, tid);
            rsbac_printk(KERN_INFO
                   "rsbac_acl_sys_remove_acl_entry(): removing ACL entry for %s %u at %s %s denied for user %u!\n",
                   subject_type_name,
                   subj_id,
                   target_type_name,
                   target_id_name,
                   user);
            rsbac_kfree(subject_type_name);
            rsbac_kfree(target_type_name);
            rsbac_kfree(target_id_name);
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_ACL]
            #endif
              )
            #endif
              return(-EPERM);
          }

        err = rsbac_acl_get_rights(0, target, tid, subj_type, subj_id, &res_rights, FALSE);
        if(err)
          {
            char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

            if(tmp)
              {
                rsbac_printk(KERN_WARNING
                       "rsbac_acl_sys_remove_acl_entry(): rsbac_acl_get_rights() returned error %s!\n",
                       get_error_name(tmp,err));
                rsbac_kfree(tmp);
              }
            return err;
          }
        if(res_rights & RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR)
          {
            /* you must have SUPERVISOR to remove an entry with SUPERVISOR */
            if(!rsbac_acl_check_super(target, tid, user))
              {
                char * subject_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                char * target_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                #ifdef CONFIG_RSBAC_LOG_FULL_PATH
                char * target_id_name
                  = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
                /* max. path name len + some extra */
                #else
                char * target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
                /* max. file name len + some extra */
                #endif

                get_acl_subject_type_name(subject_type_name, subj_type);
                get_target_name(target_type_name, target, target_id_name, tid);
                rsbac_printk(KERN_INFO
                       "rsbac_acl_sys_remove_acl_entry(): removing ACL entry with SUPERVISOR for %s %u at %s %s denied for user %u!\n",
                       subject_type_name,
                       subj_id,
                       target_type_name,
                       target_id_name,
                       user);
                rsbac_kfree(subject_type_name);
                rsbac_kfree(target_type_name);
                rsbac_kfree(target_id_name);
                #ifdef CONFIG_RSBAC_SOFTMODE
                if(   !rsbac_softmode
                #ifdef CONFIG_RSBAC_SOFTMODE_IND
                   && !rsbac_ind_softmode[SW_ACL]
                #endif
                  )
                #endif
                  return(-EPERM);
               }
           }
      }
#endif /* !MAINT */

    /* OK, check passed. Set ACL. */
    err = rsbac_acl_remove_acl_entry(ta_number, target, tid, subj_type, subj_id);
    if(err)
      {
        char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_sys_remove_acl_entry(): rsbac_acl_remove_acl_entry() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
      }
    return err;
  }

int rsbac_acl_sys_remove_acl(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid)
  {
    int err=0;

/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_ACL
    if(rsbac_switch_acl)
#endif
      {
        rsbac_uid_t user;

        if(rsbac_get_owner(&user))
          return -RSBAC_EREADFAILED;
        /* check SUPERVISOR */
        if(!rsbac_acl_check_super(target, tid, user))
          {
            char * target_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
            #ifdef CONFIG_RSBAC_LOG_FULL_PATH
            char * target_id_name
              = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
            /* max. path name len + some extra */
            #else
            char * target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
            /* max. file name len + some extra */
            #endif

            get_target_name(target_type_name, target, target_id_name, tid);
            rsbac_printk(KERN_INFO
                   "rsbac_acl_sys_remove_acl(): removing ACL from %s %s denied for user %u!\n",
                   target_type_name,
                   target_id_name,
                   user);
            rsbac_kfree(target_type_name);
            rsbac_kfree(target_id_name);
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_ACL]
            #endif
              )
            #endif
              return(-EPERM);
          }
      }
#endif /* !MAINT */

    /* OK, check passed. Set ACL. */
    err = rsbac_acl_remove_acl(ta_number, target, tid);
    if(err)
      {
        char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_sys_remove_acl(): rsbac_acl_remove_acl() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
      }
    return err;
  }

int rsbac_acl_sys_add_to_acl_entry(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
  enum   rsbac_acl_subject_type_t    subj_type,
         rsbac_acl_subject_id_t      subj_id,
         rsbac_acl_rights_vector_t   rights,
         rsbac_time_t                ttl)
  {
    int err=0;

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
      /* sanity check before using pointer */
      if(   (target == T_NETOBJ)
         && tid.netobj.sock_p
         && (   tid.netobj.remote_addr
             || !tid.netobj.sock_p->file
             || !tid.netobj.sock_p->file->f_dentry
             || !tid.netobj.sock_p->file->f_dentry->d_inode
             || (SOCKET_I(tid.netobj.sock_p->file->f_dentry->d_inode) != tid.netobj.sock_p)
            )
        )
        return -RSBAC_EINVALIDTARGET;
#endif

/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_ACL
    if(rsbac_switch_acl)
#endif
      {
        rsbac_uid_t user;

        if(rsbac_get_owner(&user))
          return -RSBAC_EREADFAILED;
        /* first try access control right (SUPERVISOR is included) */
        if(!rsbac_acl_check_right(target, tid, user, task_pid(current), ACLR_ACCESS_CONTROL))
          {
            /* no access control -> try forward for these rights */
            /* but only, if no ttl requested */
            if(   (ttl != RSBAC_LIST_TTL_KEEP)
               || !rsbac_acl_check_forward(target, tid, user, rights)
              )
              {
                char * rights_string = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                char * subject_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                char * target_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                #ifdef CONFIG_RSBAC_LOG_FULL_PATH
                char * target_id_name
                  = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
                /* max. path name len + some extra */
                #else
                char * target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
                /* max. file name len + some extra */
                #endif

                u64tostracl(rights_string, rights);
                get_acl_subject_type_name(subject_type_name, subj_type);
                get_target_name(target_type_name, target, target_id_name, tid);
                rsbac_printk(KERN_INFO
                       "rsbac_acl_sys_add_to_acl_entry(): adding rights %s for %s %u to %s %s denied for user %u!\n",
                       rights_string,
                       subject_type_name,
                       subj_id,
                       target_type_name,
                       target_id_name,
                       user);
                rsbac_kfree(rights_string);
                rsbac_kfree(subject_type_name);
                rsbac_kfree(target_type_name);
                rsbac_kfree(target_id_name);
                #ifdef CONFIG_RSBAC_SOFTMODE
                if(   !rsbac_softmode
                #ifdef CONFIG_RSBAC_SOFTMODE_IND
                   && !rsbac_ind_softmode[SW_ACL]
                #endif
                  )
                #endif
                  return(-EPERM);
              }
          }
        if(rights & RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR)
          {
            /* you must have SUPERVISOR to add SUPERVISOR */
            if(!rsbac_acl_check_super(target, tid, user))
              {
                char * subject_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                char * target_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                #ifdef CONFIG_RSBAC_LOG_FULL_PATH
                char * target_id_name
                  = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
                /* max. path name len + some extra */
                #else
                char * target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
                /* max. file name len + some extra */
                #endif

                get_acl_subject_type_name(subject_type_name, subj_type);
                get_target_name(target_type_name, target, target_id_name, tid);
                rsbac_printk(KERN_INFO
                       "rsbac_acl_sys_add_to_acl_entry(): adding SUPERVISOR for %s %u to %s %s denied for user %u!\n",
                       subject_type_name,
                       subj_id,
                       target_type_name,
                       target_id_name,
                       user);
                rsbac_kfree(subject_type_name);
                rsbac_kfree(target_type_name);
                rsbac_kfree(target_id_name);
                #ifdef CONFIG_RSBAC_SOFTMODE
                if(   !rsbac_softmode
                #ifdef CONFIG_RSBAC_SOFTMODE_IND
                   && !rsbac_ind_softmode[SW_ACL]
                #endif
                  )
                #endif
                  return(-EPERM);
              }
          }
      }
#endif /* !MAINT */

    /* OK, check passed. Set ACL. */
    err = rsbac_acl_add_to_acl_entry(ta_number, target, tid, subj_type, subj_id, rights, ttl);
    if(err)
      {
        char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_sys_add_to_acl_entry(): rsbac_acl_add_to_acl_entry() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
      }
    return err;
  }

int rsbac_acl_sys_remove_from_acl_entry(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
  enum   rsbac_acl_subject_type_t    subj_type,
         rsbac_acl_subject_id_t      subj_id,
         rsbac_acl_rights_vector_t   rights)
  {
    int err=0;

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
      /* sanity check before using pointer */
      if(   (target == T_NETOBJ)
         && tid.netobj.sock_p
         && (   tid.netobj.remote_addr
             || !tid.netobj.sock_p->file
             || !tid.netobj.sock_p->file->f_dentry
             || !tid.netobj.sock_p->file->f_dentry->d_inode
             || (SOCKET_I(tid.netobj.sock_p->file->f_dentry->d_inode) != tid.netobj.sock_p)
            )
        )
        return -RSBAC_EINVALIDTARGET;
#endif

/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_ACL
    if(rsbac_switch_acl)
#endif
      {
        rsbac_uid_t user;

        if(rsbac_get_owner(&user))
          return -RSBAC_EREADFAILED;
        /* first try access control right (SUPERVISOR is included) */
        if(!rsbac_acl_check_right(target, tid, user, task_pid(current), ACLR_ACCESS_CONTROL))
          {
            char * rights_string = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
            char * subject_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
            char * target_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
            #ifdef CONFIG_RSBAC_LOG_FULL_PATH
            char * target_id_name
              = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
            /* max. path name len + some extra */
            #else
            char * target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
            /* max. file name len + some extra */
            #endif

            u64tostracl(rights_string, rights);
            get_acl_subject_type_name(subject_type_name, subj_type);
            get_target_name(target_type_name, target, target_id_name, tid);
            rsbac_printk(KERN_INFO
                   "rsbac_acl_sys_remove_from_acl_entry(): removing rights %s for %s %u to %s %s denied for user %u!\n",
                   rights_string,
                   subject_type_name,
                   subj_id,
                   target_type_name,
                   target_id_name,
                   user);
            rsbac_kfree(rights_string);
            rsbac_kfree(subject_type_name);
            rsbac_kfree(target_type_name);
            rsbac_kfree(target_id_name);
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_ACL]
            #endif
              )
            #endif
              return(-EPERM);
          }
        if(rights & RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR)
          {
            /* you must have SUPERVISOR to revoke SUPERVISOR */
            if(!rsbac_acl_check_super(target, tid, user))
              {
                char * subject_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                char * target_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
                #ifdef CONFIG_RSBAC_LOG_FULL_PATH
                char * target_id_name
                  = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
                /* max. path name len + some extra */
                #else
                char * target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
                /* max. file name len + some extra */
                #endif

                get_acl_subject_type_name(subject_type_name, subj_type);
                get_target_name(target_type_name, target, target_id_name, tid);
                rsbac_printk(KERN_INFO
                       "rsbac_acl_sys_remove_from_acl_entry(): removing SUPERVISOR for %s %u to %s %s denied for user %u!\n",
                       subject_type_name,
                       subj_id,
                       target_type_name,
                       target_id_name,
                       user);
                rsbac_kfree(subject_type_name);
                rsbac_kfree(target_type_name);
                rsbac_kfree(target_id_name);
                #ifdef CONFIG_RSBAC_SOFTMODE
                if(   !rsbac_softmode
                #ifdef CONFIG_RSBAC_SOFTMODE_IND
                   && !rsbac_ind_softmode[SW_ACL]
                #endif
                  )
                #endif
                  return(-EPERM);
              }
          }
      }
#endif /* !MAINT */

    /* OK, check passed. Remove ACL. */
    err = rsbac_acl_remove_from_acl_entry(ta_number, target, tid, subj_type, subj_id, rights);
    if(err)
      {
        char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_sys_remove_from_acl_entry(): rsbac_acl_remove_from_acl_entry() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
      }
    return err;
  }

int rsbac_acl_sys_set_mask(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
         rsbac_acl_rights_vector_t   mask)
  {
    int err=0;

/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT) || defined (CONFIG_RSBAC_ACL_SUPER_FILTER)
    rsbac_uid_t user;

    if(rsbac_get_owner(&user))
      return -RSBAC_EREADFAILED;
#endif

#ifdef CONFIG_RSBAC_ACL_NET_OBJ_PROT
      /* sanity check before using pointer */
      if(   (target == T_NETOBJ)
         && tid.netobj.sock_p
         && (   tid.netobj.remote_addr
             || !tid.netobj.sock_p->file
             || !tid.netobj.sock_p->file->f_dentry
             || !tid.netobj.sock_p->file->f_dentry->d_inode
             || (SOCKET_I(tid.netobj.sock_p->file->f_dentry->d_inode) != tid.netobj.sock_p)
            )
        )
        return -RSBAC_EINVALIDTARGET;
#endif

#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_ACL
    if(rsbac_switch_acl)
#endif
      {
        /* first try access control right (SUPERVISOR is included) */
        if(!rsbac_acl_check_right(target, tid, user, task_pid(current), ACLR_ACCESS_CONTROL))
          {
            char * rights_string = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
            char * target_type_name = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
            #ifdef CONFIG_RSBAC_LOG_FULL_PATH
            char * target_id_name
              = rsbac_kmalloc_unlocked(CONFIG_RSBAC_MAX_PATH_LEN + RSBAC_MAXNAMELEN);
            /* max. path name len + some extra */
            #else
            char * target_id_name = rsbac_kmalloc_unlocked(2 * RSBAC_MAXNAMELEN);
            /* max. file name len + some extra */
            #endif

            u64tostracl(rights_string, mask);
            get_target_name(target_type_name, target, target_id_name, tid);
            rsbac_printk(KERN_INFO
                         "rsbac_acl_sys_set_mask(): setting mask %s for %s %s denied for user %u!\n",
                         rights_string,
                         target_type_name,
                         target_id_name,
                         user);
            rsbac_kfree(rights_string);
            rsbac_kfree(target_type_name);
            rsbac_kfree(target_id_name);
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_ACL]
            #endif
              )
            #endif
              return(-EPERM);
          }
      }
#endif /* !MAINT */

#ifdef CONFIG_RSBAC_ACL_SUPER_FILTER
    if(!(mask & RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR))
      { /* trial to mask out SUPERVISOR */
        rsbac_acl_rights_vector_t res_rights = 0;

        /* you must have direct SUPERVISOR as a USER to set a mask without SUPERVISOR */
        /* get direct own rights (still uses default_fd_rights) */
        err = rsbac_acl_get_rights(0, target, tid, ACLS_USER, user, &res_rights, FALSE);
        if(err)
          return -RSBAC_EREADFAILED;
        if(!(res_rights & RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR))
          mask |= RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR;
      }
#else
    /* SUPERVISOR must never be masked out */
    mask |= RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR;
#endif

    /* OK, checks passed. Set mask. */
    err = rsbac_acl_set_mask(ta_number, target, tid, mask);
    if(err)
      {
        char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_sys_set_mask(): rsbac_acl_set_mask() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
      }
    return err;
  }

int rsbac_acl_sys_remove_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t uid)
  {
    int err=0;

/* check only in non-maint mode */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_ACL
    if(rsbac_switch_acl)
#endif
      {
        rsbac_uid_t user;
        union rsbac_target_id_t tid;

        if(rsbac_get_owner(&user))
          return -RSBAC_EREADFAILED;
        tid.user = uid;
        /* first try access control right (SUPERVISOR is included) */
        if(!rsbac_acl_check_right(T_USER, tid, user, task_pid(current), R_DELETE))
          {
            rsbac_printk(KERN_INFO
                         "rsbac_acl_sys_remove_user(): removing all data for user %u denied for user %u!\n",
                         uid,
                         user);
            #ifdef CONFIG_RSBAC_SOFTMODE
            if(   !rsbac_softmode
            #ifdef CONFIG_RSBAC_SOFTMODE_IND
               && !rsbac_ind_softmode[SW_ACL]
            #endif
              )
            #endif
              return(-EPERM);
          }
      }
#endif /* !MAINT */

    rsbac_printk(KERN_INFO
                 "rsbac_acl_sys_remove_user(): removing all data for user %u!\n",
                 uid);
    /* OK, checks passed. Set mask. */
    err = rsbac_acl_remove_user(ta_number, uid);
    if(err)
      {
        char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_sys_remove_user(): rsbac_acl_remove_user() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
      }
    return err;
  }

/*********/

int rsbac_acl_sys_get_mask(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
         rsbac_acl_rights_vector_t * mask_p)
  {
    int err=0;

/* no check */

    /* OK, check passed. Get mask. */
    err = rsbac_acl_get_mask(ta_number, target, tid, mask_p);
    if(err)
      {
        char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_WARNING
                   "rsbac_acl_sys_get_mask(): rsbac_acl_get_mask() returned error %s!\n",
                   get_error_name(tmp,err));
            rsbac_kfree(tmp);
          }
      }
    return err;
  }

int rsbac_acl_sys_get_rights(
         rsbac_list_ta_number_t      ta_number,
  enum   rsbac_target_t              target,
  union  rsbac_target_id_t           tid,
  enum   rsbac_acl_subject_type_t    subj_type,
         rsbac_acl_subject_id_t      subj_id,
         rsbac_acl_rights_vector_t * rights_p,
         rsbac_boolean_t                     effective)
  {
    int err=0;
    rsbac_acl_rights_vector_t res_rights;
    #if defined(CONFIG_RSBAC_RC)
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    #endif

    /* no check (Attention: rsbac_acl_check_forward depends on this to be allowed!) */

    if(   (subj_type == ACLS_USER)
       && (subj_id == RSBAC_NO_USER)
      )
      rsbac_get_owner((rsbac_uid_t *) &subj_id);
    /* OK, check passed. Call ACL. */
    if(effective)
      {
        /* inherited own rights */
        res_rights = 0;
        err = rsbac_acl_get_rights(ta_number, target, tid, subj_type, subj_id, &res_rights, TRUE);
        if(err)
          {
            char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

            if(tmp)
              {
                rsbac_printk(KERN_WARNING
                       "rsbac_acl_sys_get_rights(): rsbac_acl_get_rights() returned error %s!\n",
                       get_error_name(tmp,err));
                rsbac_kfree(tmp);
              }
            return err;
          }
        *rights_p = res_rights;
        /* add group and role rights, if normal user */
        if(subj_type == ACLS_USER)
          {
            rsbac_acl_group_id_t * group_p;
            int                    i;
            int                    tmperr;

            /* group everyone */
            res_rights = 0;
            err = rsbac_acl_get_rights(ta_number, target, tid,
                                       ACLS_GROUP, RSBAC_ACL_GROUP_EVERYONE,
                                       &res_rights, TRUE);
            if(err)
              {
                char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

                if(tmp)
                  {
                    rsbac_printk(KERN_WARNING
                           "rsbac_acl_sys_get_rights(): rsbac_acl_get_rights() returned error %s!\n",
                           get_error_name(tmp,err));
                    rsbac_kfree(tmp);
                  }
                return err;
              }
            *rights_p |= res_rights;

            /* other groups */
            /* first get user groups */
            group_p = NULL;
            err = rsbac_acl_get_user_groups(ta_number, subj_id, &group_p, NULL);
            if(err<0)
              {
                char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

                if(tmp)
                  {
                    rsbac_printk(KERN_WARNING
                           "rsbac_acl_sys_get_rights(): rsbac_acl_get_user_groups() returned error %s!\n",
                           get_error_name(tmp,err));
                    rsbac_kfree(tmp);
                  }
                return err;
              }
            for(i=0; i<err; i++)
              {
                res_rights = 0;
                tmperr = rsbac_acl_get_rights(ta_number, target, tid, ACLS_GROUP, group_p[i],
                                              &res_rights, TRUE);
                if(tmperr)
                  {
                    char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

                    if(tmp)
                      {
                        rsbac_printk(KERN_WARNING
                               "rsbac_acl_sys_get_rights(): rsbac_acl_get_rights() returned error %s!\n",
                               get_error_name(tmp,err));
                        rsbac_kfree(tmp);
                      }
                    if(group_p)
                      rsbac_kfree(group_p);
                    return tmperr;
                  }
                *rights_p |= res_rights;
              }
            err = 0;
            if(group_p)
              rsbac_kfree(group_p);

            #if defined(CONFIG_RSBAC_RC)
            /* use user role */
            /* first get role */
            i_tid.user = subj_id;
            if (rsbac_get_attr(SW_RC,
                               T_USER,
                               i_tid,
                               A_rc_def_role,
                               &i_attr_val1,
                               TRUE))
              {
                rsbac_printk(KERN_WARNING
                       "rsbac_acl_sys_get_rights(): rsbac_get_attr() for process rc_role returned error!\n");
              }
            else
              {
                res_rights = 0;
                err = rsbac_acl_get_rights(ta_number, target, tid,
                                           ACLS_ROLE, i_attr_val1.rc_role,
                                           &res_rights, TRUE);
                if(err)
                  {
                    char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

                    if(tmp)
                      {
                        get_error_name(tmp,err);
                        rsbac_printk(KERN_WARNING
                               "rsbac_acl_sys_get_rights(): rsbac_acl_get_rights() returned error %s!\n",
                               tmp);
                        rsbac_kfree(tmp);
                      }
                    return err;
                  }
                *rights_p |= res_rights;
              }
            #endif

            /* check for SUPERVISOR right, if not yet there */
            if(   !(*rights_p & RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR)
               && rsbac_acl_check_super(target, tid, subj_id)
              )
              *rights_p |= RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR;
          }
        else /* not ACLS_USER */
          {
            if(!(*rights_p & RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR))
              {
                rsbac_boolean_t i_result = FALSE;

                /* check for SUPERVISOR right */
                /* own right */
                err = rsbac_acl_get_single_right(target,
                                                 tid,
                                                 subj_type,
                                                 subj_id,
                                                 ACLR_SUPERVISOR,
                                                 &i_result);
                if(err)
                  {
                    char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

                    if(tmp)
                      {
                        rsbac_printk(KERN_WARNING
                               "rsbac_acl_sys_get_rights(): rsbac_acl_get_right() returned error %s!\n",
                               get_error_name(tmp,err));
                        rsbac_kfree(tmp);
                      }
                  }
                else
                  if(i_result)
                    *rights_p |= RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR;
              }
          }
      }
    else /* not effective = direct */
      {
        /* direct own rights (still uses default_fd_rights) */
        res_rights = 0;
        err = rsbac_acl_get_rights(ta_number, target, tid, subj_type, subj_id, &res_rights, FALSE);
        if(!err)
          *rights_p = res_rights;
      }
    return err;
  }

int rsbac_acl_sys_get_tlist(
         rsbac_list_ta_number_t    ta_number,
  enum   rsbac_target_t            target,
  union  rsbac_target_id_t         tid,
  struct rsbac_acl_entry_t      ** entry_pp,
         rsbac_time_t           ** ttl_pp)
  {
    int err=0;

    /* no check */

    /* OK, check passed. Call ACL. */
    err = rsbac_acl_get_tlist(ta_number, target, tid, entry_pp, ttl_pp);
    if(err == -RSBAC_ENOTFOUND)
      err = 0;
    else
      if(err<0)
        {
          char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

          if(tmp)
            {
              rsbac_printk(KERN_WARNING
                     "rsbac_acl_sys_get_tlist(): rsbac_acl_get_tlist() returned error %s!\n",
                     get_error_name(tmp,err));
              rsbac_kfree(tmp);
            }
        }
    return err;
  }

/*********** Groups ***********/

int rsbac_acl_sys_group(
        rsbac_list_ta_number_t         ta_number,
  enum  rsbac_acl_group_syscall_type_t call,
  union rsbac_acl_group_syscall_arg_t  arg)
  {
    int err = -RSBAC_EINVALIDREQUEST;
    char * k_name;
    rsbac_acl_group_id_t k_group;
    struct rsbac_acl_group_entry_t entry;
    rsbac_uid_t caller;

    if(call >= ACLGS_none)
      return -RSBAC_EINVALIDREQUEST;
    if(rsbac_get_owner(&caller))
      return -RSBAC_EREADFAILED;

#ifdef CONFIG_RSBAC_DEBUG
    if(rsbac_debug_aef_acl)
      {
        char * tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);

        if(tmp)
          {
            rsbac_printk(KERN_DEBUG
                   "rsbac_acl_sys_group(): %s called\n",
                   get_acl_group_syscall_name(tmp,call));
            rsbac_kfree(tmp);
          }
      }
#endif
    
    switch(call)
      {
        case ACLGS_add_group:
          if(arg.add_group.type >= ACLG_NONE)
            {
              err = -RSBAC_EINVALIDVALUE;
              break;
            }
          k_name = rsbac_getname(arg.add_group.name);
          if(!k_name)
            {
              err = -RSBAC_EINVALIDVALUE;
              break;
            }
          err = rsbac_get_user((char *)&k_group, (char *)arg.add_group.group_id_p, sizeof(k_group));
          if(err)
            break;
          err = rsbac_acl_add_group(ta_number,
                                    caller,
                                    arg.add_group.type,
                                    k_name,
                                    &k_group);
          rsbac_putname(k_name);
          if(!err)
            err = rsbac_put_user((char *)&k_group, (char *) arg.add_group.group_id_p, sizeof(k_group));
          break;

        case ACLGS_change_group:
          if(arg.change_group.type >= ACLG_NONE)
            {
              err = -RSBAC_EINVALIDVALUE;
              break;
            }
          err = rsbac_acl_get_group_entry(ta_number, arg.change_group.id, &entry);
          if(err)
            break;
          /* check owner only, if non-maint */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_ACL
          if(rsbac_switch_acl)
#endif
            {
              if(entry.owner != caller)
                {
                  rsbac_printk(KERN_INFO
                               "rsbac_acl_group(): changing group %u denied for user %u - not owner!\n",
                               entry.id,
                               caller);
                  err = -EPERM;
                  break;
                }
            }
#endif /* !MAINT */
          {
            char * k_name;

            k_name = rsbac_getname(arg.change_group.name);
            if(k_name)
              {
                err = rsbac_acl_change_group(ta_number,
                                             arg.change_group.id,
                                             arg.change_group.owner,
                                             arg.change_group.type,
                                             k_name);
                putname(k_name);
              }
            else
              err = -RSBAC_EINVALIDVALUE;
          }
          break;

        case ACLGS_remove_group:
          err = rsbac_acl_get_group_entry(ta_number, arg.remove_group.id, &entry);
          if(err)
            break;
          /* check owner only, if non-maint */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_ACL
          if(rsbac_switch_acl)
#endif
            {
              if(entry.owner != caller)
                {
                  rsbac_printk(KERN_INFO
                               "rsbac_acl_group(): removing group %u denied for user %u - not owner!\n",
                               entry.id,
                               caller);
                  err = -EPERM;
                  break;
                }
            }
#endif /* !MAINT */
          err = rsbac_acl_remove_group(ta_number, arg.remove_group.id);
          break;

        case ACLGS_get_group_entry:
          if(!arg.get_group_entry.entry_p)
            {
              err = -RSBAC_EINVALIDPOINTER;
              break;
            }
          if(!arg.get_group_entry.id)
            { /* Everyone -> fill by hand */
              entry.id=0;
              entry.owner=RSBAC_NO_USER;
              entry.type=ACLG_GLOBAL;
              strcpy(entry.name, "Everyone");
              err=0;
            }
          else
            {
              err = rsbac_acl_get_group_entry(ta_number,
                                              arg.get_group_entry.id,
                                              &entry);
            }
          if(!err)
            {
              if(  (entry.owner != caller)
                 &&(entry.type != ACLG_GLOBAL)
                )
                {
                  rsbac_printk(KERN_INFO
                               "rsbac_acl_group(): getting group entry %u denied for user %u - neither owner nor global!\n",
                               entry.id,
                               caller);
                  err = -EPERM;
                }
              else
                err = rsbac_put_user((char *)&entry, (char *)arg.get_group_entry.entry_p, sizeof(entry));
            }
          break;

        case ACLGS_list_groups:
          if(arg.list_groups.maxnum <= 0)
            {
              err = -RSBAC_EINVALIDVALUE;
              break;
            }
          if(!arg.list_groups.group_entry_array)
            {
              err = -RSBAC_EINVALIDPOINTER;
              break;
            }
          {
            struct rsbac_acl_group_entry_t * entry_p;
            int tmperr=0;

            if(arg.list_groups.include_global)
              {
                struct rsbac_acl_group_entry_t   entry_0;

                entry_0.id=0;
                entry_0.owner=RSBAC_NO_USER;
                entry_0.type=ACLG_GLOBAL;
                strcpy(entry_0.name, "Everyone");
                tmperr = rsbac_put_user((char *) &entry_0,
                                        (char *) arg.list_groups.group_entry_array,
                                        sizeof(entry_0));
                if(tmperr)
                  {
                    err = tmperr;
                    break;
                  }
                else
                  err = 1;
                arg.list_groups.maxnum--;
                arg.list_groups.group_entry_array++;
              }
            else
              err = 0;

            if(arg.list_groups.maxnum)
              {
                long count;

                count = rsbac_acl_list_groups(ta_number,
                                              caller,
                                              arg.list_groups.include_global,
                                              &entry_p);
                if(count>0)
                  {
                    if(count > arg.list_groups.maxnum)
                      count = arg.list_groups.maxnum;
                    err+=count;
                    tmperr = rsbac_put_user((char *)entry_p,
                                            ((char *)arg.list_groups.group_entry_array),
                                            count * sizeof(*entry_p));
                    if(tmperr)
                      err=tmperr;
                    rsbac_kfree(entry_p);
                  }
                else
                  if(count < 0)
                    err=count;
              }
          }
          break;

        case ACLGS_add_member:
          /* check owner only, if non-maint */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_ACL
          if(rsbac_switch_acl)
#endif
            {
              err = rsbac_acl_get_group_entry(ta_number, arg.add_member.group, &entry);
              if(err)
                break;
              if(entry.owner != caller)
                {
                  rsbac_printk(KERN_INFO
                               "rsbac_acl_group(): adding group member to group %u denied for user %u - not owner!\n",
                               entry.id,
                               caller);
                  err = -EPERM;
                  break;
                }
            }
#endif /* !MAINT */
#ifdef CONFIG_RSBAC_UM_VIRTUAL
          if (RSBAC_UID_SET(arg.add_member.user) == RSBAC_UM_VIRTUAL_KEEP)
            arg.add_member.user = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(arg.add_member.user));
          else
            if (RSBAC_UID_SET(arg.add_member.user) > RSBAC_UM_VIRTUAL_MAX)
              return -RSBAC_EINVALIDVALUE;
#else
          arg.add_member.user = RSBAC_UID_NUM(arg.add_member.user);
#endif
          err = rsbac_acl_add_group_member(ta_number,
                                           arg.add_member.group,
                                           arg.add_member.user,
                                           arg.add_member.ttl);
          break;

        case ACLGS_remove_member:
          /* check owner only, if non-maint */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SWITCH_ACL
          if(rsbac_switch_acl)
#endif
            {
              err = rsbac_acl_get_group_entry(ta_number, arg.remove_member.group, &entry);
              if(err)
                break;
              if(entry.owner != caller)
                {
                  rsbac_printk(KERN_INFO
                               "rsbac_acl_group(): removing group member from group %u denied for user %u - not owner!\n",
                               entry.id,
                               caller);
                  err = -EPERM;
                  break;
                }
            }
#endif /* !MAINT */
#ifdef CONFIG_RSBAC_UM_VIRTUAL
          if (RSBAC_UID_SET(arg.remove_member.user) == RSBAC_UM_VIRTUAL_KEEP)
            arg.remove_member.user = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(arg.remove_member.user));
          else
            if (RSBAC_UID_SET(arg.remove_member.user) > RSBAC_UM_VIRTUAL_MAX)
              return -RSBAC_EINVALIDVALUE;
#else
          arg.remove_member.user = RSBAC_UID_NUM(arg.remove_member.user);
#endif
          err = rsbac_acl_remove_group_member(ta_number, arg.remove_member.group, arg.remove_member.user);
          break;

        case ACLGS_get_user_groups:
          {
            rsbac_acl_group_id_t * group_p = NULL;
            rsbac_time_t * ttl_p = NULL;

            if(arg.get_user_groups.maxnum <= 0)
              {
                err = -RSBAC_EINVALIDVALUE;
                break;
              }
            if(!arg.get_user_groups.group_array)
              {
                err = -RSBAC_EINVALIDPOINTER;
                break;
              }
            if(arg.get_user_groups.user == RSBAC_NO_USER)
              arg.get_user_groups.user = caller;
#if !defined(CONFIG_RSBAC_MAINT)
            else
#ifdef CONFIG_RSBAC_SWITCH_ACL
              if(rsbac_switch_acl)
#endif
                {
                  if(arg.get_user_groups.user != caller)
                    {
                      rsbac_printk(KERN_INFO
                                   "rsbac_acl_group(): getting user groups for user %u denied for user %u!\n",
                                   arg.get_user_groups.user,
                                   caller);
                      err = -EPERM;
                      break;
                    }
                }
#endif /* !MAINT */
#ifdef CONFIG_RSBAC_UM_VIRTUAL
            if (RSBAC_UID_SET(arg.get_user_groups.user) == RSBAC_UM_VIRTUAL_KEEP)
              arg.get_user_groups.user = RSBAC_GEN_UID (rsbac_get_vset(), RSBAC_UID_NUM(arg.get_user_groups.user));
            else
              if (RSBAC_UID_SET(arg.get_user_groups.user) > RSBAC_UM_VIRTUAL_MAX)
                return -RSBAC_EINVALIDVALUE;
#else
            arg.get_user_groups.user = RSBAC_UID_NUM(arg.get_user_groups.user);
#endif
            err = rsbac_acl_get_user_groups(ta_number, arg.get_user_groups.user, &group_p, &ttl_p);
            if(err>0)
              {
                int tmperr;

                err = rsbac_min(err, arg.get_user_groups.maxnum);
                tmperr = rsbac_put_user((char *)group_p,
                                        (char *)arg.get_user_groups.group_array,
                                        err * sizeof(*group_p));
                if(tmperr)
                  err=tmperr;
                if(arg.get_user_groups.ttl_array)
                  {
                    tmperr = rsbac_put_user((char *)ttl_p,
                                            (char *)arg.get_user_groups.ttl_array,
                                            err * sizeof(*ttl_p));
                    if(tmperr)
                      err=tmperr;
                  }
              }
            if(group_p)
              rsbac_kfree(group_p);
            if(ttl_p)
              rsbac_kfree(ttl_p);
            break;
          }

        case ACLGS_get_group_members:
          if(   (arg.get_group_members.maxnum <= 0)
             || !arg.get_group_members.group
            )
            {
              err = -RSBAC_EINVALIDVALUE;
              break;
            }
          if(arg.get_group_members.maxnum > RSBAC_ACL_MAX_MAXNUM)
            arg.get_group_members.maxnum = RSBAC_ACL_MAX_MAXNUM;
          if(!arg.get_group_members.user_array)
            {
              err = -RSBAC_EINVALIDPOINTER;
              break;
            }
          err = rsbac_acl_get_group_entry(ta_number,
                                          arg.get_group_members.group,
                                          &entry);
          if(err)
            break;
          if(  (entry.owner != caller)
             &&(entry.type != ACLG_GLOBAL)
            )
            {
              rsbac_printk(KERN_INFO
                           "rsbac_acl_group(): getting group members of group %u denied for user %u - neither owner nor global!\n",
                           entry.id,
                           caller);
              err = -EPERM;
              break;
            }
          {
            rsbac_uid_t * user_array;
            rsbac_time_t * ttl_array;
            
            user_array = rsbac_kmalloc_unlocked(sizeof(*user_array) * arg.get_group_members.maxnum);
            if(!user_array)
              return -RSBAC_ENOMEM;
            ttl_array = rsbac_kmalloc_unlocked(sizeof(*ttl_array) * arg.get_group_members.maxnum);
            if(!ttl_array)
              {
                rsbac_kfree(user_array);
                return -RSBAC_ENOMEM;
              }

            err = rsbac_acl_get_group_members(ta_number,
                                              arg.get_group_members.group,
                                              user_array,
                                              ttl_array,
                                              arg.get_group_members.maxnum);
            if(err>0)
              {
                int tmperr;

                tmperr = rsbac_put_user((char *)user_array,
                                        (char *)arg.get_group_members.user_array,
                                        err * sizeof(*user_array));
                if(tmperr)
                  err=tmperr;
                if(arg.get_group_members.ttl_array)
                  {
                    tmperr = rsbac_put_user((char *)ttl_array,
                                            (char *)arg.get_group_members.ttl_array,
                                            err * sizeof(*ttl_array));
                    if(tmperr)
                      err=tmperr;
                  }
              }
            rsbac_kfree(user_array);
            rsbac_kfree(ttl_array);
          }
          break;

        default:
          break;
      }
    #ifdef CONFIG_RSBAC_SOFTMODE
    if(   (   rsbac_softmode
    #ifdef CONFIG_RSBAC_SOFTMODE_IND
           || rsbac_ind_softmode[SW_ACL]
    #endif
          )
       && (err == -EPERM)
      )
      return 0;
    else
    #endif
      return err;
  }
/* end of rsbac/adf/acl/syscalls.c */
