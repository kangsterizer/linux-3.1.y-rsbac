/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - Privacy Model                    */
/* File: rsbac/adf/pm/main.c                         */
/*                                                   */
/* Author and (c) 1999-2009: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 06/Oct/2009                        */
/*************************************************** */

#include <linux/string.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/adf_main.h>
#include <rsbac/error.h>
#include <rsbac/debug.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/pm.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

static rsbac_pm_purpose_id_t
  get_ipc_purpose(struct rsbac_ipc_t ipc_id)
  {
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;

    /* get pm_ipc_purpose of given ipc */
    i_tid.ipc = ipc_id;
    if (rsbac_get_attr(SW_PM,
                       T_IPC,
                       i_tid,
                       A_pm_ipc_purpose,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_printk(KERN_WARNING
               "get_ipc_purpose(): rsbac_get_attr() returned error!\n");
        return(0);
      }
    return(i_attr_val1.pm_ipc_purpose);
  }

static enum rsbac_adf_req_ret_t
  tp_check(rsbac_pid_t caller_pid)
  {
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;

    /* get pm_process_type of caller-process */
    i_tid.process = caller_pid;
    if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                       i_tid,
                       A_pm_process_type,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_printk(KERN_WARNING
               "tp_check(): rsbac_get_attr() returned error!\n");
        return(NOT_GRANTED);
      }
    if(i_attr_val1.pm_process_type == PP_TP)
      return(NOT_GRANTED);
    else
      return(DO_NOT_CARE);
  };

/* This function does the actual checking for */
/* necessary(access) and (purpose-binding or consent). */
/* Additionally, information flow checking is done via input and output */
/* purpose sets. */
static enum rsbac_adf_req_ret_t
  na_and_pp_or_cs(       rsbac_pid_t          caller_pid,
                  struct rsbac_fs_file_t      file,
                         rsbac_pm_accesses_t  acc)
  {
    rsbac_pm_task_id_t            task;
    rsbac_pm_object_class_id_t    object_class;
    rsbac_pm_tp_id_t              tp;
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    union rsbac_pm_target_id_t    i_pm_tid;
    union rsbac_pm_data_value_t   i_data_val1;
    union rsbac_pm_data_value_t   i_data_val2;
    union rsbac_pm_set_id_t       i_pm_set_id;
    union rsbac_pm_set_member_t   i_pm_set_member;
          int                     error;
    
    /* get object_class of file */
    i_tid.file = file;
    if (rsbac_get_attr(SW_PM,
                       T_FILE,
                       i_tid,
                       A_pm_object_class,
                       &i_attr_val1,
                       TRUE))
      {
        rsbac_printk(KERN_WARNING
               "na_and_pp_or_cs(): rsbac_get_attr() returned error!\n");
               return(NOT_GRANTED);
      }
    object_class = i_attr_val1.pm_object_class;
    /* if there is no class for this file, this is an error!   */
    /* (all personal data must have a class assigned, and this */
    /* function must never be called for anything else)        */
    if(!object_class)
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_WARNING
                 "na_and_pp_or_cs(): personal_data with NIL class!\n");
#endif
        return(NOT_GRANTED);
      }

    /* get current_task of caller-process */
    i_tid.process = caller_pid;
    if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                       i_tid,
                       A_pm_current_task,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_printk(KERN_WARNING
               "na_and_pp_or_cs(): rsbac_get_attr() returned error!\n");
               return(NOT_GRANTED);
      }
    task = i_attr_val1.pm_current_task;
    if(!task)
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "na_and_pp_or_cs(): no current_task for calling process trying to access personal_data\n");
#endif
        return(NOT_GRANTED);
      }

    /* get pm_tp of caller-process */
    if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                       i_tid,
                       A_pm_tp,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_printk(KERN_WARNING
               "na_and_pp_or_cs(): rsbac_get_attr() returned error!\n");
        return(NOT_GRANTED);
      }
    tp = i_attr_val1.pm_tp;
    if(!tp)
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "na_and_pp_or_cs(): calling process trying to access personal_data has no TP-id\n");
#endif
        return(NOT_GRANTED);
      }

    /* get necessary accesses */
    i_pm_tid.na.task = task;
    i_pm_tid.na.object_class = object_class;
    i_pm_tid.na.tp = tp;
    if ((error = rsbac_pm_get_data(0,
                                   PMT_NA,
                                   i_pm_tid,
                                   PD_accesses,
                                   &i_data_val1)))
      {
        if(error != -RSBAC_EINVALIDTARGET)
          rsbac_printk(KERN_WARNING
                 "na_and_pp_or_cs(): rsbac_pm_get_data() returned error %i!\n",
                 error);
          return(NOT_GRANTED);
      }
    /* is requested access mode included in access mask? */
    if((acc & i_data_val1.accesses) != acc)
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "na_and_pp_or_cs(): requested access mode is not necessary\n");
#endif
        return(NOT_GRANTED);
      }

    /* OK, access is necessary -> check (purpose-bind or consent) */
    /* first try purpose-binding */
    
    /* get purpose-id of current_task */
    i_pm_tid.task = task;
    if ((error = rsbac_pm_get_data(0,
                                   PMT_TASK,
                                   i_pm_tid,
                                   PD_purpose,
                                   &i_data_val1)))
      {
        rsbac_printk(KERN_WARNING
                 "na_and_pp_or_cs(): rsbac_get_data() for current_TASK/purpose returned error %i!\n",
                 error);
        return(NOT_GRANTED);
      }
    if(!i_data_val1.purpose)
      {
        rsbac_printk(KERN_WARNING
               "na_and_pp_or_cs(): task %i has NIL purpose!\n",task);
        return(NOT_GRANTED);
      }
    /* get purpose-set-id of class */
    i_pm_tid.object_class = object_class;
    if ((error = rsbac_pm_get_data(0,
                                   PMT_CLASS,
                                   i_pm_tid,
                                   PD_pp_set,
                                   &i_data_val2)))
      {
        if(error != -RSBAC_EINVALIDTARGET)
          rsbac_printk(KERN_WARNING
                 "na_and_pp_or_cs(): rsbac_pm_get_data() returned error %i!\n",
                 error);
        return(NOT_GRANTED);
      }
    /* OK, if task's purpose is in class's purpose_set */
    i_pm_set_id.pp_set = i_data_val2.pp_set;
    i_pm_set_member.pp = i_data_val1.purpose;
    if (!rsbac_pm_set_member(0,PS_PP,i_pm_set_id,i_pm_set_member))
      { /* purpose binding failed -> try consent */
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "na_and_pp_or_cs(): purpose of current_task of calling process is NOT in purpose set of class of file -> trying consent\n");
#endif
        i_pm_tid.cs.purpose = i_data_val1.purpose;
        i_pm_tid.cs.file = file;
        if(!rsbac_pm_exists(0,PMT_CS,i_pm_tid))
          { /* neither pp-binding, nor consent -> do not grant */
#ifdef CONFIG_RSBAC_DEBUG
            if(rsbac_debug_adf_pm)
              rsbac_printk(KERN_DEBUG
                     "na_and_pp_or_cs(): there is no consent for this purpose for file\n");
#endif
            return(NOT_GRANTED);
          }
      }

    /* information flow check */

    /* read access: is purpose set of class of file superset of process */
    /* output purpose set? If not -> do not grant access */
    /* (Output purpose set id is process id) */
    if(   (acc & RSBAC_PM_A_READ)
       && !rsbac_pm_pp_superset(i_pm_set_id.pp_set, caller_pid) )
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "na_and_pp_or_cs(): failed information flow check for read access\n");
#endif
        return(NOT_GRANTED);
      }

    /* write access: is purpose set of class of file subset of process */
    /* input purpose set? If not -> do not grant access */
    /* (Input purpose set id is also process id) */
    if(   (acc & RSBAC_PM_A_WRITE_TO_FILE)
       && !rsbac_pm_pp_subset(i_pm_set_id.pp_set, caller_pid) )
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "na_and_pp_or_cs(): failed information flow check for write access\n");
#endif
        return(NOT_GRANTED);
      }

    /* OK, all checks done. GRANT! */
    return(GRANTED);
  }
  
/* reduced version for IPC objects */
static enum rsbac_adf_req_ret_t
  na_and_pp_ipc(       rsbac_pm_task_id_t   task,
                       rsbac_pid_t          caller_pid,
                       rsbac_pm_accesses_t  acc,
                struct rsbac_ipc_t          ipc_id)
  {
    rsbac_pm_tp_id_t              tp;
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    union rsbac_pm_target_id_t    i_pm_tid;
    union rsbac_pm_data_value_t   i_data_val1;
    union rsbac_pm_set_id_t       i_pm_set_id;
    union rsbac_pm_set_member_t   i_pm_set_member;
          int                     error;
    
    if(!task)
      return(NOT_GRANTED);

    /* get pm_tp of caller-process */
    i_tid.process = caller_pid;
    if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                       i_tid,
                       A_pm_tp,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_printk(KERN_WARNING
               "na_and_pp_ipc(): rsbac_get_attr() returned error!\n");
        return(NOT_GRANTED);
      }
    tp = i_attr_val1.pm_tp;
    if(!tp)
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "na_and_pp_ipc(): calling process trying to access ipc has task, but no TP-id\n");
#endif
        return(NOT_GRANTED);
      }
      return(NOT_GRANTED);

    /* get necessary accesses */
    i_pm_tid.na.task = task;
    i_pm_tid.na.object_class = RSBAC_PM_IPC_OBJECT_CLASS_ID;
    i_pm_tid.na.tp = tp;
    if ((error = rsbac_pm_get_data(0,
                                   PMT_NA,
                                   i_pm_tid,
                                   PD_accesses,
                                   &i_data_val1)))
      {
        if(error != -RSBAC_EINVALIDTARGET)
          rsbac_printk(KERN_WARNING
                 "na_and_pp_ipc(): rsbac_pm_get_data() returned error %i!\n",
                 error);
          return(NOT_GRANTED);
      }
    /* is requested access mode included in access mask? */
    if((acc & i_data_val1.accesses) != acc)
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "na_and_pp_ipc(): requested access mode is not necessary\n");
#endif
        return(NOT_GRANTED);
      }

    /* OK, access is necessary -> check purpose-bind */
    /* get purpose-id of current_task */
    i_pm_tid.task = task;
    if ((error = rsbac_pm_get_data(0,
                                   PMT_TASK,
                                   i_pm_tid,
                                   PD_purpose,
                                   &i_data_val1)))
      {
        rsbac_printk(KERN_WARNING
                 "na_and_pp_ipc(): rsbac_get_data() for current_TASK/purpose returned error %i!\n",
                 error);
        return(NOT_GRANTED);
      }
    if(!i_data_val1.purpose)
      {
        rsbac_printk(KERN_WARNING
               "na_and_pp_ipc(): task %i has NIL purpose!\n",task);
        return(NOT_GRANTED);
      }
    /* get ipc_purpose of IPC-object */
    i_tid.ipc = ipc_id;
    if (rsbac_get_attr(SW_PM,
                       T_IPC,
                       i_tid,
                       A_pm_ipc_purpose,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_printk(KERN_WARNING
               "na_and_pp_ipc(): rsbac_get_attr() returned error!\n");
        return(NOT_GRANTED);
      }

    /* grant, if task's purpose is ipc's ipc_purpose or if */
    /* IPC-pp is NIL and access is read-only */
    if (!(   (i_data_val1.purpose == i_attr_val1.pm_ipc_purpose)
          || (!i_data_val1.purpose && !(acc & RSBAC_PM_A_WRITING) ) ) )
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "na_and_pp_ipc(): purpose of current_task of calling process is NOT ipc_purpose\n");
#endif
        return(NOT_GRANTED);
      }
    /* information flow check */

    /* read access: is purpose of ipc object NIL or no other purpose in */
    /* output purpose set? If not -> do not grant access */
    /* (Output purpose set id is process id) */
    if(   (acc & RSBAC_PM_A_READ)
       && i_attr_val1.pm_ipc_purpose
       && !rsbac_pm_pp_only(i_attr_val1.pm_ipc_purpose, caller_pid) )
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_DEBUG
                 "na_and_pp_ipc(): failed information flow check for read access\n");
#endif
        return(NOT_GRANTED);
      }

    /* write access: is purpose of ipc in */
    /* input purpose set? If not -> do not grant access */
    /* (Input purpose set id is also process id) */
    if(acc & RSBAC_PM_A_WRITE_TO_FILE)
      {
        i_pm_set_id.in_pp_set = caller_pid;
        i_pm_set_member.pp = i_attr_val1.pm_ipc_purpose;
        if (!rsbac_pm_set_member(0, PS_IN_PP, i_pm_set_id, i_pm_set_member) )
          {
#ifdef CONFIG_RSBAC_DEBUG
            if(rsbac_debug_adf_pm)
              rsbac_printk(KERN_DEBUG
                     "na_and_pp_or_cs(): failed information flow check for write access\n");
#endif
            return(NOT_GRANTED);
          }
      }
    /* OK, all checks done. GRANT! */
    return(GRANTED);
  }


static enum rsbac_adf_req_ret_t
  na_ipc(rsbac_pm_task_id_t   task,
         rsbac_pid_t          caller_pid,
         rsbac_pm_accesses_t  acc)
  {
    rsbac_pm_tp_id_t              tp;
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    union rsbac_pm_target_id_t    i_pm_tid;
    union rsbac_pm_data_value_t   i_data_val1;
          int                     error;
    
    if(!task)
      return(NOT_GRANTED);

    /* get pm_tp of caller-process */
    i_tid.process = caller_pid;
    if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                       i_tid,
                       A_pm_tp,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_printk(KERN_WARNING
               "na_ipc(): rsbac_get_attr() returned error!\n");
        return(NOT_GRANTED);
      }
    tp = i_attr_val1.pm_tp;
    if(!tp)
      return(NOT_GRANTED);

    /* get necessary accesses */
    i_pm_tid.na.task = task;
    i_pm_tid.na.object_class = RSBAC_PM_IPC_OBJECT_CLASS_ID;
    i_pm_tid.na.tp = tp;
    if ((error = rsbac_pm_get_data(0,
                                   PMT_NA,
                                   i_pm_tid,
                                   PD_accesses,
                                   &i_data_val1)))
      {
        if(error != -RSBAC_EINVALIDTARGET)
          rsbac_printk(KERN_WARNING
                 "na_ipc(): rsbac_pm_get_data() returned error %i!\n",
                 error);
          return(NOT_GRANTED);
      }
    /* is requested access mode included in access mask? */
    if((acc & i_data_val1.accesses) == acc)
      return(GRANTED);
    else
      return(NOT_GRANTED);
  }

static enum rsbac_adf_req_ret_t
  na_dev(rsbac_pid_t          caller_pid,
         rsbac_pm_accesses_t  acc,
         struct rsbac_dev_desc_t dev)
  {
    rsbac_pm_tp_id_t              tp;
    rsbac_pm_task_id_t            task;
    rsbac_pm_object_class_id_t    object_class;
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    union rsbac_pm_target_id_t    i_pm_tid;
    union rsbac_pm_data_value_t   i_data_val1;
          int                     error;
    
    i_tid.process = caller_pid;
    if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                       i_tid,
                       A_pm_current_task,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_printk(KERN_WARNING
               "na_dev(): rsbac_get_attr() returned error!\n");
               return(NOT_GRANTED);
      }
    task = i_attr_val1.pm_current_task;
    /* if current_task = NIL -> do not grant */
    if(!task)
      {
        return(NOT_GRANTED);
      }

    /* get pm_tp of caller-process */
    i_tid.process = caller_pid;
    if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                       i_tid,
                       A_pm_tp,
                       &i_attr_val1,
                       FALSE))
      {
        rsbac_printk(KERN_WARNING
               "na_dev(): rsbac_get_attr() returned error!\n");
        return(NOT_GRANTED);
      }
    tp = i_attr_val1.pm_tp;
    if(!tp)
      return(NOT_GRANTED);

    /* get pm_object_class of dev target */
    i_tid.dev = dev;
    if (rsbac_get_attr(SW_PM,
                       T_DEV,
                       i_tid,
                       A_pm_object_class,
                       &i_attr_val1,
                       TRUE))
      {
        rsbac_printk(KERN_WARNING
               "na_dev(): rsbac_get_attr() returned error!\n");
        return(NOT_GRANTED);
      }
    object_class = i_attr_val1.pm_object_class;

    /* get necessary accesses */
    i_pm_tid.na.task = task;
    i_pm_tid.na.object_class = object_class;
    i_pm_tid.na.tp = tp;
    if ((error = rsbac_pm_get_data(0,
                                   PMT_NA,
                                   i_pm_tid,
                                   PD_accesses,
                                   &i_data_val1)))
      {
        if(error != -RSBAC_EINVALIDTARGET)
          rsbac_printk(KERN_WARNING
                 "na_dev(): rsbac_pm_get_data() returned error %i!\n",
                 error);
          return(NOT_GRANTED);
      }
    /* is requested access mode included in access mask? */
    if((acc & i_data_val1.accesses) == acc)
      return(GRANTED);
    else
      return(NOT_GRANTED);
  }

/* This function does the adjustment of input- and output-purpose-set of */
/* the calling process according to type of access and purpose set of class */
/* of file. */
static int
  adjust_in_out_pp(       rsbac_pid_t          caller_pid,
                   enum   rsbac_target_t       target,
                   struct rsbac_fs_file_t      file,
                          rsbac_pm_accesses_t  acc)
  {
    rsbac_pm_object_class_id_t    object_class;
    union rsbac_target_id_t       i_tid;
    union rsbac_attribute_value_t i_attr_val1;
    union rsbac_pm_target_id_t    i_pm_tid;
    union rsbac_pm_data_value_t   i_data_val1;
          int                     error;
    
    /* get pm_object_type of file */
    i_tid.file = file;
    if (rsbac_get_attr(SW_PM,
                       target,
                       i_tid,
                       A_pm_object_type,
                       &i_attr_val1,
                       TRUE))
      {
        rsbac_printk(KERN_WARNING
               "adjust_in_out_pp(): rsbac_get_attr() returned error!\n");
        return(-RSBAC_EREADFAILED);
      }
    /* we only adjust for personal_data */
    if(i_attr_val1.pm_object_type != PO_personal_data)
      return(0);
                  
    /* only personal_data left -> */
    /* get object_class of file */
    i_tid.file = file;
    if (rsbac_get_attr(SW_PM,
                       target,
                       i_tid,
                       A_pm_object_class,
                       &i_attr_val1,
                       TRUE))
      {
        rsbac_printk(KERN_WARNING
               "adjust_in_out_pp(): rsbac_get_attr() returned error!\n");
        return(-RSBAC_EREADFAILED);
      }
    object_class = i_attr_val1.pm_object_class;
    /* if there is no class for this file, this is an error!   */
    /* (all personal data must have a class assigned, and here */
    /* must never be anything else)        */
    if(!object_class)
      {
#ifdef CONFIG_RSBAC_DEBUG
        if(rsbac_debug_adf_pm)
          rsbac_printk(KERN_WARNING
                 "adjust_in_out_pp(): personal_data with NIL class!\n");
#endif
        return(-RSBAC_EINVALIDVALUE);
      }

    /* get pp_set-id of class */
    i_pm_tid.object_class = object_class;
    if ((error = rsbac_pm_get_data(0,
                                   PMT_CLASS,
                                   i_pm_tid,
                                   PD_pp_set,
                                   &i_data_val1)))
      {
        if(error != -RSBAC_EINVALIDTARGET)
          rsbac_printk(KERN_WARNING
                 "adjust_in_out_pp(): rsbac_pm_get_data() returned error %i!\n",
                 error);
        else
          rsbac_printk(KERN_WARNING
                 "adjust_in_out_pp(): class %i of file does not exist!\n",
                 object_class);
        return(-RSBAC_EREADFAILED);
      }

    /* adjust information flow check boundaries */

    /* read access: create intersection of input-purpose-set of process and  */
    /* purpose-set of class of file in input-purpose-set of process */
    /* (Input purpose set id is process id) */
    if(   (acc & RSBAC_PM_A_READ)
       && rsbac_pm_pp_intersec(i_data_val1.pp_set, caller_pid) )
      {
        rsbac_printk(KERN_WARNING
                 "adjust_in_out_pp(): call to rsbac_pm_pp_intersec failed\n");
        error = -RSBAC_EWRITEFAILED;
      }

    /* write access: create union of output-purpose-set of process and  */
    /* purpose-set of class of file in output-purpose-set of process */
    /* (Output purpose set id is process id) */
    if(   (acc & RSBAC_PM_A_WRITE_TO_FILE)
       && rsbac_pm_pp_union(i_data_val1.pp_set, caller_pid) )
      {
        rsbac_printk(KERN_WARNING
                 "adjust_in_out_pp(): call to rsbac_pm_pp_union failed\n");
        error = -RSBAC_EWRITEFAILED;
      }

    /* OK, everything is done. */
    return(error);
  }

/* This function does the adjustment of input- and output-purpose-set of */
/* the calling process according to type of access and ipc-purpose of ipc */
/* object. */
static int
  adjust_in_out_pp_ipc(   rsbac_pid_t          caller_pid,
                   struct rsbac_ipc_t          ipc,
                          rsbac_pm_accesses_t  acc)
  {
    union rsbac_pm_set_id_t       i_pm_set_id;
    union rsbac_pm_set_member_t   i_pm_set_member;
          rsbac_pm_purpose_id_t   i_pm_pp;
          int                     error = 0;
    
    /* get IPC-purpose */
    i_pm_pp = get_ipc_purpose(ipc);
    /* if ipc_purpose is 0, this cannot be a TP -> no access to personal data */
    /* -> no flow control */
    if(!i_pm_pp)
      return(0);
    
    /* adjust information flow check boundaries */

    /* read access: create intersection of input-purpose-set of process and */
    /* purpose-set of ipc in input-purpose-set of process -> clear set and */
    /* add ipc-purpose, because ipc-purpose must have been in it at decision */
    /* (Input purpose set id is process id) */
    if(acc & RSBAC_PM_A_READ)
      {
        i_pm_set_id.in_pp_set = caller_pid;
        /* if set does not exist, create it */
        if(   !rsbac_pm_set_exist(0,PS_IN_PP, i_pm_set_id) 
           && rsbac_pm_create_set(0,PS_IN_PP, i_pm_set_id) )
            {
              rsbac_printk(KERN_WARNING
                     "adjust_in_out_pp_ipc(): call to rsbac_pm_create_set returned error\n");
              error = -RSBAC_EWRITEFAILED;
            }
        if(rsbac_pm_clear_set(0,PS_IN_PP, i_pm_set_id) )
          {
            rsbac_printk(KERN_WARNING
                   "adjust_in_out_pp_ipc(): call to rsbac_pm_clear_set returned error\n");
            error = -RSBAC_EWRITEFAILED;
          }
        i_pm_set_member.pp = i_pm_pp;
        if(rsbac_pm_add_to_set(0,PS_IN_PP, i_pm_set_id, i_pm_set_member) )
          {
            rsbac_printk(KERN_WARNING
                   "adjust_in_out_pp_ipc(): call to rsbac_pm_add_to_set returned error\n");
            error = -RSBAC_EWRITEFAILED;
          }
      }

    /* write access: create union of output-purpose-set of process and */
    /* purpose-set of ipc in output-purpose-set of process -> */
    /* add ipc-purpose to output-purpose-set */
    /* (Input purpose set id is process id) */
    if(acc & RSBAC_PM_A_WRITE_TO_FILE)
      {
        i_pm_set_id.out_pp_set = caller_pid;
        /* if set does not exist, create it */
        if(   !rsbac_pm_set_exist(0,PS_OUT_PP, i_pm_set_id) 
           && rsbac_pm_create_set(0,PS_OUT_PP, i_pm_set_id) )
            {
              rsbac_printk(KERN_WARNING
                     "adjust_in_out_pp_ipc(): call to rsbac_pm_create_set returned error\n");
              error = -RSBAC_EWRITEFAILED;
            }
        /* add ipc_purpose to set */
        i_pm_set_member.pp = i_pm_pp;
        if(rsbac_pm_add_to_set(0,PS_OUT_PP, i_pm_set_id, i_pm_set_member) )
          {
            rsbac_printk(KERN_WARNING
                   "adjust_in_out_pp_ipc(): call to rsbac_pm_add_to_set returned error\n");
            error = -RSBAC_EWRITEFAILED;
          }
      }

    /* OK, everything is done. */
    return(error);
  }


/************************************************* */
/*          Externally visible functions           */
/************************************************* */

inline enum rsbac_adf_req_ret_t
   rsbac_adf_request_pm  (enum  rsbac_adf_request_t     request,
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
    union rsbac_attribute_value_t i_attr_val2;
    union rsbac_pm_target_id_t    i_pm_tid;
    union rsbac_pm_data_value_t   i_data_val1;
    union rsbac_pm_set_id_t       i_pm_set_id;
    union rsbac_pm_set_member_t   i_pm_set_member;
          rsbac_pm_purpose_id_t   i_pm_pp;
          int                     error;

    switch (request)
      {
        case R_ADD_TO_KERNEL:
            switch(target)
              {
                case T_FILE:
                case T_DEV:
                case T_NONE:
                  /* test owner's pm_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                       T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* only administrators are allowed to do this */
                  if (i_attr_val1.pm_role != PR_system_admin)
                    return(NOT_GRANTED);
                  else
                    return(GRANTED);

                /* all other cases */
                default:
                  return(DO_NOT_CARE);
              }

        case R_APPEND_OPEN:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       target,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* no append_open on TPs */
                  if(i_attr_val1.pm_object_type == PO_TP)
                    return(NOT_GRANTED);
                  /* TPs must not write on other than personal_data */
                  if(i_attr_val1.pm_object_type != PO_personal_data)
                    return(tp_check(caller_pid));
                  
                  /* only personal_data left -> */
                  /* check necessary && (purpose_bind || consent) */
                  return(na_and_pp_or_cs(caller_pid,
                                         tid.file,
                                         RSBAC_PM_A_APPEND));
                  break;

                /* Appending to devices is no problem here */
                case T_DEV:
                  return(DO_NOT_CARE);

                case T_IPC:
                  /* get IPC-purpose */
                  i_pm_pp = get_ipc_purpose(tid.ipc);
                  /* if IPC-pp is NIL -> process type must be NIL */
                  if(!i_pm_pp)
                    {
                      /* get process-type of caller-process */
                      i_tid.process = caller_pid;
                      if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                         i_tid,
                                         A_pm_process_type,
                                         &i_attr_val1,
                                         FALSE))
                        { 
                          rsbac_printk(KERN_WARNING
                                 "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                          return(NOT_GRANTED);
                        }
                      if(i_attr_val1.pm_process_type == PP_TP)
                        return(NOT_GRANTED);
                      else
                        return(GRANTED);
                    }
                  /* OK, we do have an IPC-purpose */                  
                  /* get current_task of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_current_task,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if current_task = NIL -> do not grant */
                  if(!i_attr_val1.pm_current_task)
                    {
                        return(NOT_GRANTED);
                    }
                  /* check necessary && purpose_bind */
                  return(na_and_pp_ipc(i_attr_val1.pm_current_task,
                                       caller_pid,
                                       RSBAC_PM_A_APPEND,
                                       tid.ipc));
                  break;

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_CHANGE_GROUP:
            switch(target)
              {
                /* We do not care about process or user groups */
                /* all other cases */
                default: return(DO_NOT_CARE);
              }

        case R_CHANGE_OWNER:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                case T_SYMLINK:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                                     target,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* no access on TPs and personal_data*/
                  if(   (i_attr_val1.pm_object_type == PO_TP)
                     || (i_attr_val1.pm_object_type == PO_personal_data))
                    return(NOT_GRANTED);
                  else
                    return(GRANTED);
                  break;

                /*  processes may only be given to other user, if    */
                /*  current_task is authorized for him.              */
                /*  If CONFIG_RSBAC_PM_ROLE_PROT is set, only changing  */
                /*  to or from pm_role general_user is allowed.      */
                case T_PROCESS:
                  /* get current_task of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_current_task,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if task = NIL: no problem, grant */
                  if(!i_attr_val1.pm_current_task)
                    return(GRANTED);

                  /* get task_set_id of process-owner */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                       T_USER,
                                     i_tid,
                                     A_pm_task_set,
                                     &i_attr_val2,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if user has no set of authorized tasks -> do not grant */
                  if(!i_attr_val2.pm_task_set)
                    return(NOT_GRANTED);

                  /* grant, if task is in owner's authorized task_set */
                  i_pm_set_id.task_set = i_attr_val2.pm_task_set;
                  i_pm_set_member.task = i_attr_val1.pm_current_task;
                  if (rsbac_pm_set_member(0,PS_TASK,i_pm_set_id,i_pm_set_member))
                    return(GRANTED);
                  /* else: don't... */
                  else
                    return(NOT_GRANTED);

                /* Change-owner without or for other target: do not care */
                case T_DIR:
                case T_IPC:
                case T_NONE:
                  return(DO_NOT_CARE);
                /* all other cases are undefined */
                default:
                  return(DO_NOT_CARE);
              }

        case R_CLONE:
            if (target == T_PROCESS)
              {
                /* get process_type of caller-process */
                i_tid.process = caller_pid;
                if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                   i_tid,
                                   A_pm_process_type,
                                   &i_attr_val1,
                                   FALSE))
                  {
                    rsbac_printk(KERN_WARNING
                           "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                    return(NOT_GRANTED);
                  }
                /* cloning is only allowed for normal processes */
                if(i_attr_val1.pm_process_type == PP_none)
                  return(GRANTED);
                else
                  return(NOT_GRANTED);
              }
            else
              return(DO_NOT_CARE);

        case R_CREATE:
            switch(target)
              {
                /* Creating dir or (pseudo) file IN target dir! */
                case T_DIR: 
                  /* get process_type of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_process_type,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* we only care for TPs here */
                  if(i_attr_val1.pm_process_type != PP_TP)
                    return(DO_NOT_CARE);

                  /* get current_task of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_current_task,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                             return(NOT_GRANTED);
                    }
                  if(!i_attr_val1.pm_current_task)
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if(rsbac_debug_adf_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_adf_request_pm(): no current_task for calling process trying to access personal_data\n");
#endif
                      return(NOT_GRANTED);
                    }

                  /* get pm_tp of caller-process */
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_tp,
                                     &i_attr_val2,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  if(!i_attr_val2.pm_tp)
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if(rsbac_debug_adf_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_adf_request_pm(): calling process trying to access personal_data has no TP-id\n");
#endif
                      return(NOT_GRANTED);
                    }

                  /* get necessary accesses for NIL class */
                  i_pm_tid.na.task = i_attr_val1.pm_current_task;
                  i_pm_tid.na.object_class = 0;
                  i_pm_tid.na.tp = i_attr_val2.pm_tp;
                  if ((error = rsbac_pm_get_data(0,
                                                 PMT_NA,
                                                 i_pm_tid,
                                                 PD_accesses,
                                                 &i_data_val1)))
                    {
                      if(error != -RSBAC_EINVALIDTARGET)
                        rsbac_printk(KERN_WARNING
                               "rsbac_adf_request_pm(): rsbac_pm_get_data() returned error %i!\n",
                               error);
                      return(NOT_GRANTED);
                    }
                  /* is requested access mode included in access mask? */
                  if(!(RSBAC_PM_A_CREATE & i_data_val1.accesses))
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if(rsbac_debug_adf_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_adf_request_pm(): requested access mode CREATE for class NIL is not necessary\n");
#endif
                      return(NOT_GRANTED);
                    }

                  /* OK, create is necessary -> grant */
                  return(GRANTED);
                  break;
                  
                case T_IPC:
                  /* get current_task of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_current_task,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if current_task = NIL, do not care */
                  if(!i_attr_val1.pm_current_task)
                    return(DO_NOT_CARE);

                  /* check necessary */
                  return(na_ipc(i_attr_val1.pm_current_task,
                                caller_pid,
                                RSBAC_PM_A_CREATE));
                  break;

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_DELETE:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                case T_SYMLINK:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       target,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if TP: only TP_Manager */
                  if(i_attr_val1.pm_object_type == PO_TP)
                    {
                      /* test owner's pm_role */
                      i_tid.user = owner;
                      if (rsbac_get_attr(SW_PM,
                       T_USER,
                                         i_tid,
                                         A_pm_role,
                                         &i_attr_val1,
                                         TRUE))
                        {
                          rsbac_printk(KERN_WARNING "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                          return(NOT_GRANTED);
                        }
                      if(i_attr_val1.pm_role == PR_tp_manager)
                        return(GRANTED);
                      else
                        return(NOT_GRANTED);
                    }
                  /* do not care for other than personal_data */
                  if(i_attr_val1.pm_object_type != PO_personal_data)
                    return(DO_NOT_CARE);
                  
                  /* check necessary && (purpose_bind || consent) */
                  /* (in fact, necessary means allowed here) */
                  return(na_and_pp_or_cs(caller_pid,
                                         tid.file,
                                         RSBAC_PM_A_DELETE));
                  break;

                case T_IPC:
                  /* get current_task of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_current_task,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if current_task = NIL, ipc_purpose must be NIL */
                  if(!i_attr_val1.pm_current_task)
                    {
                      if(!get_ipc_purpose(tid.ipc))
                        return(GRANTED);
                      else
                        return(NOT_GRANTED);
                    }
                  /* check necessary && purpose_bind */
                  return(na_and_pp_ipc(i_attr_val1.pm_current_task,
                                       caller_pid,
                                       RSBAC_PM_A_DELETE,
                                       tid.ipc));
                  break;

                case T_DIR:
                      return(DO_NOT_CARE);
                  break;
                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_EXECUTE:
        case R_MAP_EXEC:
            switch(target)
              {
                case T_FILE:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       T_FILE,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if not TP: do not care */
                  if(i_attr_val1.pm_object_type != PO_TP)
                    return(DO_NOT_CARE);

                  /* get pm_tp of target */
                  if (rsbac_get_attr(SW_PM,
                       T_FILE,
                                     tid,
                                     A_pm_tp,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if no tp: error! */
                  if(!i_attr_val1.pm_tp)
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): file with object_type TP has no tp_id!\n");
                      return(NOT_GRANTED);
                    }
                  /* get current_task of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_current_task,
                                     &i_attr_val2,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if there is no current task, do not grant */
                  if(!i_attr_val2.pm_current_task)
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if(rsbac_debug_adf_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_adf_request_pm(): no current_task for process trying to execute TP\n");
#endif
                      return(NOT_GRANTED);
                    }
                  /* get tp_set_id of current_task */
                  i_pm_tid.task = i_attr_val2.pm_current_task;
                  if ((error = rsbac_pm_get_data(0,
                                                 PMT_TASK,
                                                 i_pm_tid,
                                                 PD_tp_set,
                                                 &i_data_val1)))
                    {
                      if(error != -RSBAC_EINVALIDTARGET)
                        rsbac_printk(KERN_WARNING
                               "rsbac_adf_request_pm(): rsbac_pm_get_data() returned error %i!\n",
                               error);
                      return(NOT_GRANTED);
                    }
                  /* if there is no tp set, do not grant */
                  if(!i_data_val1.tp_set)
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if(rsbac_debug_adf_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_adf_request_pm(): no tp_set for current_task of process trying to execute TP\n");
#endif
                      return(NOT_GRANTED);
                    }
                  
                  /* grant, if file's tp is in process-current-task's */
                  /* authorized tp_set */
                  i_pm_set_id.tp_set = i_data_val1.tp_set;
                  i_pm_set_member.tp = i_attr_val1.pm_tp;
                  if (rsbac_pm_set_member(0,PS_TP,i_pm_set_id,i_pm_set_member))
                    return(GRANTED);
                  /* else: don't... */
                  else
                    {
#ifdef CONFIG_RSBAC_DEBUG
                      if(rsbac_debug_adf_pm)
                        rsbac_printk(KERN_DEBUG
                               "rsbac_adf_request_pm(): tp %i of file is not in tp_set %i of current_task %i of process\n",
                               i_attr_val1.pm_tp, i_data_val1.tp_set, i_attr_val2.pm_current_task);
#endif
                      return(NOT_GRANTED);
                    }

                /* all other cases are undefined */
                default:
                  return(DO_NOT_CARE);
              }

        case R_GET_STATUS_DATA:
            switch(target)
              {
                case T_SCD:
                  /* target rsbac_log? only for secoff and dataprot */
                  if (tid.scd != ST_rsbac_log)
                    return(GRANTED);
                  /* Secoff or dataprot? */
                  i_tid.user = owner;
                  if ((error=rsbac_get_attr(SW_PM,
                       T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE)))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error %i!\n",
                             error);
                      return(NOT_GRANTED);
                    }
                  /* grant only for secoff and dataprot */
                  if (   (i_attr_val1.pm_role == PR_security_officer)
                      || (i_attr_val1.pm_role == PR_data_protection_officer)
                     )
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);
                default:
                  return(DO_NOT_CARE);
               };

        case R_LINK_HARD:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                case T_SYMLINK:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       target,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if OT = TP or OT = personal_data -> do not grant, else do */
                  if(   (i_attr_val1.pm_object_type == PO_TP)
                     || (i_attr_val1.pm_object_type == PO_personal_data))
                    return(NOT_GRANTED);
                  else
                    return(GRANTED);
                  break;
                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_MODIFY_ACCESS_DATA:
        case R_RENAME:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                case T_SYMLINK:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       target,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }

                  /* if personal_data -> do not grant */
                  if(i_attr_val1.pm_object_type == PO_personal_data)
                    return(NOT_GRANTED);
                  /* alternative: check necessary && (purpose_bind || consent) */
                  /* return(na_and_pp_or_cs(caller_pid,
                                         tid.file,
                                         RSBAC_PM_A_WRITE)); */

                  /* if TP: only TP_Manager, else: do not care */
                  if(i_attr_val1.pm_object_type != PO_TP)
                    return(DO_NOT_CARE);
                  /* test owner's pm_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                       T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  if(i_attr_val1.pm_role == PR_tp_manager)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);
                  break;

                case T_DIR:
                  return(DO_NOT_CARE);
                  break;
                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_MODIFY_ATTRIBUTE:
            switch(attr)
              {
                /* all pm relevant attributes are changed via sys_rsbac_pm */
                /* using tickets in most cases -> deny here */
                case A_pm_object_type:
                case A_pm_tp:
                case A_pm_role:
                case A_pm_process_type:
                case A_pm_current_task:
                case A_pm_object_class:
                case A_pm_ipc_purpose:
                case A_pm_program_type:
                case A_pm_task_set:
                #ifdef CONFIG_RSBAC_PM_GEN_PROT
                case A_owner:
                case A_pseudo:
                case A_vset:
                case A_program_file:
                #endif
                #ifdef CONFIG_RSBAC_PM_AUTH_PROT
                case A_auth_may_setuid:
                case A_auth_may_set_cap:
                case A_auth_start_uid:
                case A_auth_start_euid:
                case A_auth_start_gid:
                case A_auth_start_egid:
                case A_auth_last_auth:
                #endif
                  return(NOT_GRANTED);
                /* All attributes (remove target!) */
                case A_none:
                #ifdef CONFIG_RSBAC_PM_AUTH_PROT
                case A_auth_add_f_cap:
                case A_auth_remove_f_cap:
                case A_auth_learn:
                #endif
                  switch(target)
                    { /* special care for pm-relevant files and devs*/
                      case T_FILE:
                      case T_FIFO:
                      case T_DEV:
                        /* get object_type */
                        if (rsbac_get_attr(SW_PM,
                       target,
                                           tid,
                                           A_pm_object_type,
                                           &i_attr_val1,
                                           TRUE))
                          {
                            rsbac_printk(KERN_WARNING "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                            return(NOT_GRANTED);
                          }
                        /* if OT is PM-relevant -> do not grant */
                        if(   (i_attr_val1.pm_object_type != PO_none)
                           && (i_attr_val1.pm_object_type != PO_non_personal_data))
                          return(NOT_GRANTED);
                        else
                          return(GRANTED);

                      /* we do not care for dirs or symlinks */
                      case T_DIR:
                      case T_SYMLINK:
                        return(DO_NOT_CARE);
                      
                      /* we do care for users, and if PM is active, we use  */
                      /* tickets to delete user attributes, so do not grant.*/ 
                      /* take care: if other models are active, their       */
                      /* additional restrictions are not met!               */
                      case T_USER:
                        return(NOT_GRANTED);

                      /* no removing of process attributes */
                      case T_PROCESS:
                        return(NOT_GRANTED);

                      case T_IPC:
                        /* get ipc_purpose */
                        if (rsbac_get_attr(SW_PM,
                       T_IPC,
                                           tid,
                                           A_pm_ipc_purpose,
                                           &i_attr_val1,
                                           FALSE))
                          {
                            rsbac_printk(KERN_WARNING "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                            return(NOT_GRANTED);
                          }
                        /* if a purpose is set -> do not grant, else: who cares? */
                        if(i_attr_val1.pm_ipc_purpose)
                          return(NOT_GRANTED);
                        else
                          return(GRANTED);

                      default:
                        return(DO_NOT_CARE);
                    }

                #ifdef CONFIG_RSBAC_PM_GEN_PROT
                case A_log_array_low:
                case A_log_array_high:
                case A_log_program_based:
                case A_log_user_based:
                case A_symlink_add_uid:
                case A_symlink_add_remote_ip:
                case A_fake_root_uid:
                case A_audit_uid:
                case A_auid_exempt:
                  /* test owner's pm_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                                     T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* security officer? -> grant  */
                  if (i_attr_val1.pm_role == PR_security_officer)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);
                #endif

                default:
                  return(DO_NOT_CARE);
              }

        case R_MODIFY_PERMISSIONS_DATA:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       target,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if TP: only TP_Manager, else: do not care */
                  if(i_attr_val1.pm_object_type != PO_TP)
                    return(DO_NOT_CARE);
                  /* test owner's pm_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                       T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  if(i_attr_val1.pm_role == PR_tp_manager)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);
                  break;

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_MODIFY_SYSTEM_DATA:
            switch(target)
              {
                case T_SCD:
                  /* target rlimit? no problem, but needed -> grant */
                  if (tid.scd == ST_rlimit || tid.scd == ST_mlock)
                    return(GRANTED);
                  /* Administrator? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                       T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if rsbac_log: grant only for secoff and dataprot */
                  if(tid.scd == ST_rsbac_log)
                    {
                      if (   (i_attr_val1.pm_role == PR_security_officer)
                          || (i_attr_val1.pm_role == PR_data_protection_officer)
                         )
                        return(GRANTED);
                      else
                        return(NOT_GRANTED);
                    }
                  /* if rsbac_log_remote: grant only for secoff */
                  if(tid.scd == ST_rsbac_remote_log)
                    {
                      if (   (i_attr_val1.pm_role == PR_security_officer)
                          || (i_attr_val1.pm_role == PR_data_protection_officer)
                         )
                        return(GRANTED);
                      else
                        return(NOT_GRANTED);
                    }
                  /* other scds: if administrator, then grant */
                  if (i_attr_val1.pm_role == PR_system_admin)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);
                  
                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_MOUNT:
            switch(target)
              {
                case T_FILE:
                case T_DIR:
                case T_DEV:
                  /* Administrator? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                       T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if administrator, then grant */
                  if (i_attr_val1.pm_role == PR_system_admin)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_READ:
            switch(target)
              {
#ifdef CONFIG_RSBAC_RW
                case T_FILE:
                case T_FIFO:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       target,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* no read_open on TPs */
                  if(i_attr_val1.pm_object_type == PO_TP)
                    return(NOT_GRANTED);
                  /* do not care for other than personal_data */
                  if(i_attr_val1.pm_object_type != PO_personal_data)
                    return(DO_NOT_CARE);
                  
                  /* check necessary && (purpose_bind || consent) */
                  return(na_and_pp_or_cs(caller_pid,
                                         tid.file,
                                         RSBAC_PM_A_READ));
                  break;

                case T_DEV:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       T_DEV,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* check read_open only on devs containing personal_data */
                  if(i_attr_val1.pm_object_type != PO_personal_data)
                    return(DO_NOT_CARE);
                  /* check necessary && purpose_bind */
                  return(na_dev(caller_pid,
                                RSBAC_PM_A_READ,
                                tid.dev));

#ifdef CONFIG_RSBAC_RW_SOCK
                case T_IPC:
                  /* get current_task of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_current_task,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if current_task = NIL, ipc_purpose must be NIL */
                  if(!i_attr_val1.pm_current_task)
                    {
                      if(!get_ipc_purpose(tid.ipc))
                        return(GRANTED);
                      else
                        return(NOT_GRANTED);
                    }
                  /* check necessary && purpose_bind */
                  return(na_and_pp_ipc(i_attr_val1.pm_current_task,
                                       caller_pid,
                                       RSBAC_PM_A_READ,
                                       tid.ipc));
                  break;
#endif /* RW_SOCK */
#endif /* RW */

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_READ_ATTRIBUTE:
            switch(attr)
              {
                case A_pm_object_type:
                case A_pm_tp:
                case A_pm_role:
                case A_pm_process_type:
                case A_pm_current_task:
                case A_pm_object_class:
                case A_pm_ipc_purpose:
                case A_pm_program_type:
                case A_pm_task_set:
                #ifdef CONFIG_RSBAC_PM_GEN_PROT
                case A_owner:
                case A_pseudo:
                case A_log_array_low:
                case A_log_array_high:
                case A_log_program_based:
                case A_log_user_based:
                case A_symlink_add_remote_ip:
                case A_symlink_add_uid:
                case A_fake_root_uid:
                case A_audit_uid:
                case A_auid_exempt:
                case A_vset:
                case A_program_file:
                #endif
                #ifdef CONFIG_RSBAC_PM_AUTH_PROT
                case A_auth_may_setuid:
                case A_auth_may_set_cap:
                case A_auth_start_uid:
                case A_auth_start_euid:
                case A_auth_start_gid:
                case A_auth_start_egid:
                case A_auth_learn:
                case A_auth_last_auth:
                #endif
                  /* Security Officer or Data Protection Officer? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                                     T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if sec_officer or data_prot_off, then grant */
                  if(   (i_attr_val1.pm_role == PR_security_officer)
                     || (i_attr_val1.pm_role == PR_data_protection_officer))
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                default:
                  return(DO_NOT_CARE);
              }

        case R_READ_OPEN:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       target,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* no read_open on TPs */
                  if(i_attr_val1.pm_object_type == PO_TP)
                    return(NOT_GRANTED);
                  /* do not care for other than personal_data */
                  if(i_attr_val1.pm_object_type != PO_personal_data)
                    return(DO_NOT_CARE);
                  
                  /* check necessary && (purpose_bind || consent) */
                  return(na_and_pp_or_cs(caller_pid,
                                         tid.file,
                                         RSBAC_PM_A_READ));
                  break;

                case T_DEV:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       T_DEV,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* check read_open only on devs containing personal_data */
                  if(i_attr_val1.pm_object_type != PO_personal_data)
                    return(DO_NOT_CARE);
                  /* check necessary && purpose_bind */
                  return(na_dev(caller_pid,
                                RSBAC_PM_A_READ,
                                tid.dev));

                case T_IPC:
                  /* get current_task of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_current_task,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if current_task = NIL, ipc_purpose must be NIL */
                  if(!i_attr_val1.pm_current_task)
                    {
                      if(!get_ipc_purpose(tid.ipc))
                        return(GRANTED);
                      else
                        return(NOT_GRANTED);
                    }
                  /* check necessary && purpose_bind */
                  return(na_and_pp_ipc(i_attr_val1.pm_current_task,
                                       caller_pid,
                                       RSBAC_PM_A_READ,
                                       tid.ipc));
                  break;

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_READ_WRITE_OPEN:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       target,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* no read_write_open on TPs */
                  if(i_attr_val1.pm_object_type == PO_TP)
                    return(NOT_GRANTED);
                  /* TPs must not write on other than personal_data */
                  if(i_attr_val1.pm_object_type != PO_personal_data)
                    return(tp_check(caller_pid));
                  
                  /* check necessary && (purpose_bind || consent) */
                  return(na_and_pp_or_cs(caller_pid,
                                         tid.file,
                                         RSBAC_PM_A_READ | RSBAC_PM_A_WRITE));
                  break;

                case T_DEV:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       T_DEV,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* check read_write_open only on devs containing personal_data or TPs*/
                  if(   (i_attr_val1.pm_object_type != PO_personal_data)
                     && (i_attr_val1.pm_object_type != PO_TP) )
                    return(DO_NOT_CARE);
                  /* check necessary && purpose_bind */
                  return(na_dev(caller_pid,
                                RSBAC_PM_A_READ | RSBAC_PM_A_WRITE,
                                tid.dev));

                case T_IPC:
                  /* get IPC-purpose */
                  i_pm_pp = get_ipc_purpose(tid.ipc);
                  /* if IPC-pp is NIL -> process type must be NIL */
                  if(!i_pm_pp)
                    {
                      /* get process-type of caller-process */
                      i_tid.process = caller_pid;
                      if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                         i_tid,
                                         A_pm_process_type,
                                         &i_attr_val1,
                                         FALSE))
                        { 
                          rsbac_printk(KERN_WARNING
                                 "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                          return(NOT_GRANTED);
                        }
                      if(i_attr_val1.pm_process_type == PP_TP)
                        return(NOT_GRANTED);
                      else
                        return(GRANTED);
                    }
                  /* OK, we do have an IPC-purpose */                  
                  /* get current_task of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_current_task,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if current_task = NIL -> do not grant */
                  if(!i_attr_val1.pm_current_task)
                    {
                        return(NOT_GRANTED);
                    }
                  /* check necessary && purpose_bind */
                  return(na_and_pp_ipc(i_attr_val1.pm_current_task,
                                       caller_pid,
                                       RSBAC_PM_A_READ | RSBAC_PM_A_WRITE,
                                       tid.ipc));
                  break;

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_REMOVE_FROM_KERNEL:
            switch(target)
              {
                case T_FILE:
                case T_DEV:
                case T_NONE:
                  /* test owner's pm_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                       T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* only administrators are allowed to do this */
                  if (i_attr_val1.pm_role != PR_system_admin)
                    return(NOT_GRANTED);
                  /* That's it */
                  return(GRANTED);

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

/*      case R_RENAME: see R_MODIFY_ACCESS_DATA */

        case R_SEND_SIGNAL:
            switch(target)
              {
                case T_PROCESS:
                  /* TPs are not allowed to send signals */
                  /* get process_type of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_process_type,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* we do not allow TPs here */
                  if(i_attr_val1.pm_process_type == PP_TP)
                    return(NOT_GRANTED);

                  /* SIGKILL to TPs is restricted to tp_managers to prevent */
                  /* inconsistencies */
                  /* get process_type of target-process */
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     tid,
                                     A_pm_process_type,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* we only care for TPs here */
                  if(i_attr_val1.pm_process_type != PP_TP)
                    return(DO_NOT_CARE);
  
                  /* test owner's pm_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                       T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* only tp_managers are allowed to do this */
                  if (i_attr_val1.pm_role != PR_tp_manager)
                    return(NOT_GRANTED);
                  /* That's it */
                  return(GRANTED);

                /* all other cases are undefined */
                default:
                  return(DO_NOT_CARE);
              }

        case R_SHUTDOWN:
            switch(target)
              {
                case T_NONE:
                  /* test owner's pm_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                       T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* only administrators are allowed to do this */
                  if (i_attr_val1.pm_role != PR_system_admin)
                    return(NOT_GRANTED);
                  /* That's it */
                  return(GRANTED);

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_SWITCH_LOG:
            switch(target)
              {
                case T_NONE:
                  /* test owner's pm_role */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                       T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* security officer? -> grant  */
                  if (i_attr_val1.pm_role == PR_security_officer)
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
                  /* deny PM to be switched, do not care for others */
                  if(   (attr_val.switch_target == SW_PM)
                     #ifdef CONFIG_RSBAC_PM_AUTH_PROT
                     || (attr_val.switch_target == SW_AUTH)
                     #endif
                     #ifdef CONFIG_RSBAC_SOFTMODE
                     || (attr_val.switch_target == SW_SOFTMODE)
                     #endif
                     #ifdef CONFIG_RSBAC_FREEZE
                     || (attr_val.switch_target == SW_FREEZE)
                     #endif
                    )
                    return(NOT_GRANTED);
                  else
                    return(DO_NOT_CARE);

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }
              
        /* notify only, handled by adf-dispatcher */
        case R_TERMINATE:
            if (target == T_PROCESS)
              { /* Remove input and output purpose set of process */
                i_pm_set_id.in_pp_set = tid.process;
                rsbac_pm_remove_set(0, PS_IN_PP, i_pm_set_id);
                i_pm_set_id.out_pp_set = tid.process;
                rsbac_pm_remove_set(0, PS_OUT_PP, i_pm_set_id);
                return(GRANTED);
              }
            else
              return(DO_NOT_CARE);

        case R_TRACE:
            switch(target)
              {
                case T_PROCESS:
                  /* get process_type of calling process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_process_type,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* do not grant for TPs */
                  if(i_attr_val1.pm_process_type == PP_TP)
                    return(NOT_GRANTED);

                  /* get process_type of target-process */
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     tid,
                                     A_pm_process_type,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* do not grant for TPs */
                  if(i_attr_val1.pm_process_type == PP_TP)
                    return(NOT_GRANTED);

                  /* neither P1 nor P2 is TP -> grant */
                  return(GRANTED);

                /* all other cases are undefined */
                default:
                  return(DO_NOT_CARE);
              }

        case R_TRUNCATE:
            switch(target)
              {
                case T_FILE:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       T_FILE,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* no append_open on TPs */
                  if(i_attr_val1.pm_object_type == PO_TP)
                    return(NOT_GRANTED);
                  /* TPs must not write on other than personal_data */
                  if(i_attr_val1.pm_object_type != PO_personal_data)
                    return(tp_check(caller_pid));
                  
                  /* check necessary && (purpose_bind || consent) */
                  return(na_and_pp_or_cs(caller_pid,
                                         tid.file,
                                         RSBAC_PM_A_WRITE));
                  break;

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_UMOUNT:
            switch(target)
              {
                case T_FILE:
                case T_DIR:
                case T_DEV:
                  /* Administrator? */
                  i_tid.user = owner;
                  if (rsbac_get_attr(SW_PM,
                       T_USER,
                                     i_tid,
                                     A_pm_role,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if administrator, then grant */
                  if (i_attr_val1.pm_role == PR_system_admin)
                    return(GRANTED);
                  else
                    return(NOT_GRANTED);

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_WRITE:
            switch(target)
              {
#ifdef CONFIG_RSBAC_RW
                case T_FILE:
                case T_FIFO:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       target,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* no append_open on TPs */
                  if(i_attr_val1.pm_object_type == PO_TP)
                    return(NOT_GRANTED);
                  /* TPs must not write on other than personal_data */
                  if(i_attr_val1.pm_object_type != PO_personal_data)
                    return(tp_check(caller_pid));
                  
                  /* check necessary && (purpose_bind || consent) */
                  return(na_and_pp_or_cs(caller_pid,
                                         tid.file,
                                         RSBAC_PM_A_WRITE));
                  break;

                case T_DEV:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       T_DEV,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* check write_open only on devs containing personal_data or TPs*/
                  if(   (i_attr_val1.pm_object_type != PO_personal_data)
                     && (i_attr_val1.pm_object_type != PO_TP) )
                    return(DO_NOT_CARE);
                  /* check necessary && purpose_bind */
                  return(na_dev(caller_pid,
                                RSBAC_PM_A_WRITE,
                                tid.dev));

#ifdef CONFIG_RSBAC_RW_SOCK
                case T_IPC:
                  /* get IPC-purpose */
                  i_pm_pp = get_ipc_purpose(tid.ipc);
                  /* if IPC-pp is NIL -> process type must be NIL */
                  if(!i_pm_pp)
                    {
                      /* get process-type of caller-process */
                      i_tid.process = caller_pid;
                      if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                         i_tid,
                                         A_pm_process_type,
                                         &i_attr_val1,
                                         FALSE))
                        { 
                          rsbac_printk(KERN_WARNING
                                 "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                          return(NOT_GRANTED);
                        }
                      if(i_attr_val1.pm_process_type == PP_TP)
                        return(NOT_GRANTED);
                      else
                        return(GRANTED);
                    }
                  /* OK, we do have an IPC-purpose */                  
                  /* get current_task of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_current_task,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if current_task = NIL -> do not grant */
                  if(!i_attr_val1.pm_current_task)
                    {
                        return(NOT_GRANTED);
                    }
                  /* check necessary && purpose_bind */
                  return(na_and_pp_ipc(i_attr_val1.pm_current_task,
                                       caller_pid,
                                       RSBAC_PM_A_WRITE,
                                       tid.ipc));
                  break;
#endif
#endif

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }

        case R_WRITE_OPEN:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       target,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* no append_open on TPs */
                  if(i_attr_val1.pm_object_type == PO_TP)
                    return(NOT_GRANTED);
                  /* TPs must not write on other than personal_data */
                  if(i_attr_val1.pm_object_type != PO_personal_data)
                    return(tp_check(caller_pid));
                  
                  /* check necessary && (purpose_bind || consent) */
                  return(na_and_pp_or_cs(caller_pid,
                                         tid.file,
                                         RSBAC_PM_A_WRITE));
                  break;

                case T_DEV:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                       T_DEV,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* check write_open only on devs containing personal_data or TPs*/
                  if(   (i_attr_val1.pm_object_type != PO_personal_data)
                     && (i_attr_val1.pm_object_type != PO_TP) )
                    return(DO_NOT_CARE);
                  /* check necessary && purpose_bind */
                  return(na_dev(caller_pid,
                                RSBAC_PM_A_WRITE,
                                tid.dev));

                case T_IPC:
                  /* get IPC-purpose */
                  i_pm_pp = get_ipc_purpose(tid.ipc);
                  /* if IPC-pp is NIL -> process type must be NIL */
                  if(!i_pm_pp)
                    {
                      /* get process-type of caller-process */
                      i_tid.process = caller_pid;
                      if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                         i_tid,
                                         A_pm_process_type,
                                         &i_attr_val1,
                                         FALSE))
                        { 
                          rsbac_printk(KERN_WARNING
                                 "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                          return(NOT_GRANTED);
                        }
                      if(i_attr_val1.pm_process_type == PP_TP)
                        return(NOT_GRANTED);
                      else
                        return(GRANTED);
                    }
                  /* OK, we do have an IPC-purpose */                  
                  /* get current_task of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     i_tid,
                                     A_pm_current_task,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if current_task = NIL -> do not grant */
                  if(!i_attr_val1.pm_current_task)
                    {
                        return(NOT_GRANTED);
                    }
                  /* check necessary && purpose_bind */
                  return(na_and_pp_ipc(i_attr_val1.pm_current_task,
                                       caller_pid,
                                       RSBAC_PM_A_WRITE,
                                       tid.ipc));
                  break;

                /* all other cases are undefined */
                default: return(DO_NOT_CARE);
              }


/*********************/
        default: return DO_NOT_CARE;
      }

    return(result);
  } /* end of rsbac_adf_request_pm() */


/*****************************************************************************/
/* If the request returned granted and the operation is performed,           */
/* the following function can be called by the AEF to get all aci set        */
/* correctly. For write accesses that are performed fully within the kernel, */
/* this is usually not done to prevent extra calls, including R_CLOSE for    */
/* cleaning up.                                                              */
/* The second instance of target specification is the new target, if one has */
/* been created, otherwise its values are ignored.                           */
/* On success, 0 is returned, and an error from rsbac/error.h otherwise.     */

int  rsbac_adf_set_attr_pm(
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
    union rsbac_attribute_value_t i_attr_val2;
    union rsbac_attribute_value_t i_attr_val3;
    union rsbac_attribute_value_t i_attr_val4;
    union rsbac_pm_target_id_t    i_pm_tid;
    union rsbac_pm_data_value_t   i_data_val1;
          int                     error;

    switch (request)
      {
        case R_APPEND_OPEN:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                  return(adjust_in_out_pp(caller_pid,
                                          target,
                                          tid.file,
                                          RSBAC_PM_A_APPEND));
                case T_IPC:
                  return(adjust_in_out_pp_ipc(caller_pid,
                                              tid.ipc,
                                              RSBAC_PM_A_APPEND));
                case T_DEV:
                  return(0);
                default:
                  return(0);
              }
#ifdef CONFIG_RSBAC_RW
        case R_READ:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                  return(adjust_in_out_pp(caller_pid,
                                          target,
                                          tid.file,
                                          RSBAC_PM_A_READ));
#ifdef CONFIG_RSBAC_RW_SOCK
                case T_IPC:
                  return(adjust_in_out_pp_ipc(caller_pid,
                                              tid.ipc,
                                              RSBAC_PM_A_READ));
#endif
                default:
                  return(0);
              }
#endif
        case R_READ_OPEN:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                  return(adjust_in_out_pp(caller_pid,
                                          target,
                                          tid.file,
                                          RSBAC_PM_A_READ));
                case T_IPC:
                  return(adjust_in_out_pp_ipc(caller_pid,
                                              tid.ipc,
                                              RSBAC_PM_A_READ));
                case T_DIR:
                case T_DEV:
                  return(0);
                default:
                  return(0);
              }
        case R_READ_WRITE_OPEN:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                  return(adjust_in_out_pp(caller_pid,
                                          target,
                                          tid.file,
                                          RSBAC_PM_A_READ | RSBAC_PM_A_WRITE));
                case T_IPC:
                  return(adjust_in_out_pp_ipc(caller_pid,
                                              tid.ipc,
                                              RSBAC_PM_A_READ | RSBAC_PM_A_WRITE));
                case T_DEV:
                  return(0);
                default:
                  return(0);
              }

#ifdef CONFIG_RSBAC_RW
        case R_WRITE:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                  return(adjust_in_out_pp(caller_pid,
                                          target,
                                          tid.file,
                                          RSBAC_PM_A_WRITE));
#ifdef CONFIG_RSBAC_RW_SOCK
                case T_IPC:
                  return(adjust_in_out_pp_ipc(caller_pid,
                                              tid.ipc,
                                              RSBAC_PM_A_WRITE));
#endif
                default:
                  return(0);
              }
#endif

        case R_WRITE_OPEN:
            switch(target)
              {
                case T_FILE:
                case T_FIFO:
                  return(adjust_in_out_pp(caller_pid,
                                          target,
                                          tid.file,
                                          RSBAC_PM_A_WRITE));
                case T_DEV:
                  return(0);

                case T_IPC:
                  return(adjust_in_out_pp_ipc(caller_pid,
                                              tid.ipc,
                                              RSBAC_PM_A_WRITE));
                default:
                  return(0);
              }

        case R_CLONE:
            if (target == T_PROCESS)
              {
                  /* Get owner from first process (provided on call) */
                  i_attr_val1.owner = owner;
                  /* Get pm_tp from first process */
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     tid,
                                     A_pm_tp,
                                     &i_attr_val2,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_set_attr_pm(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  /* Get pm_current_task from first process... */
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     tid,
                                     A_pm_current_task,
                                     &i_attr_val3,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_set_attr_pm(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  /* Get pm_process_type from first process */
                  if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                     tid,
                                     A_pm_process_type,
                                     &i_attr_val4,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_set_attr_pm(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  /* Set pm_tp for new process */
                  if (rsbac_set_attr(SW_PM,
                       T_PROCESS,
                                     new_tid,
                                     A_pm_tp,
                                     i_attr_val2))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_pm(): rsbac_set_attr() returned error!\n");
                      return(-RSBAC_EWRITEFAILED);
                    }
                  /* Set pm_current_task for new process */
                  if (rsbac_set_attr(SW_PM,
                       T_PROCESS,
                                     new_tid,
                                     A_pm_current_task,
                                     i_attr_val3))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_pm(): rsbac_set_attr() returned error!\n");
                      return(-RSBAC_EWRITEFAILED);
                    }
                  /* Set pm_process_type for new process */
                  if (rsbac_set_attr(SW_PM,
                       T_PROCESS,
                                     new_tid,
                                     A_pm_process_type,
                                     i_attr_val4))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_pm(): rsbac_set_attr() returned error!\n");
                      return(-RSBAC_EWRITEFAILED);
                    }
                  return(0);
              }
            else
              return(0);

        case R_CREATE:
            switch(target)
              {
                /* Creating dir or (pseudo) file IN target dir! */
                case T_DIR:
                  /* Mode of created item is ignored! */

                  /* Is calling process a TP? */
                  /* get process_type of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                                     T_PROCESS,
                                     i_tid,
                                     A_pm_process_type,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(NOT_GRANTED);
                    }
                  /* if TP: Set pm_object_class to purpose default class for new item */
                  if(i_attr_val1.pm_process_type == PP_TP)
                    {
                      /* get current_task of caller-process */
                      i_tid.process = caller_pid;
                      if (rsbac_get_attr(SW_PM,
                       T_PROCESS,
                                         i_tid,
                                         A_pm_current_task,
                                         &i_attr_val1,
                                         FALSE))
                        {
                          rsbac_printk(KERN_WARNING
                                 "rsbac_adf_set_attr_pm(): rsbac_get_attr() returned error!\n");
                                 return(RSBAC_EREADFAILED);
                        }
                      if(!i_attr_val1.pm_current_task)
                        {
#ifdef CONFIG_RSBAC_DEBUG
                          if(rsbac_debug_adf_pm)
                            rsbac_printk(KERN_DEBUG
                                   "rsbac_adf_set_attr_pm(): no current_task for calling process trying to access personal_data\n");
#endif
                          return(RSBAC_EREADFAILED);
                        }
                      /* get purpose of current_task */
                      i_pm_tid.task = i_attr_val1.pm_current_task;
                      if ((error = rsbac_pm_get_data(0,
                                                     PMT_TASK,
                                                     i_pm_tid,
                                                     PD_purpose,
                                                     &i_data_val1)))
                        {
                          if(error != -RSBAC_EINVALIDTARGET)
                            rsbac_printk(KERN_WARNING
                                   "rsbac_adf_set_attr_pm(): rsbac_pm_get_data() returned error %i!\n",
                                   error);
                          return(error);
                        }
                      /* if there is no purpose, return error */
                      if(!i_data_val1.purpose)
                        {
#ifdef CONFIG_RSBAC_DEBUG
                          if(rsbac_debug_adf_pm)
                            rsbac_printk(KERN_DEBUG
                                   "rsbac_adf_set_attr_pm(): no purpose for current_task of process trying to execute TP\n");
#endif
                          return(RSBAC_EREADFAILED);
                        }
                      /* get def_class of purpose of current_task */
                      i_pm_tid.pp = i_data_val1.purpose;
                      if ((error = rsbac_pm_get_data(0,
                                                     PMT_PP,
                                                     i_pm_tid,
                                                     PD_def_class,
                                                     &i_data_val1)))
                        {
                          if(error != -RSBAC_EINVALIDTARGET)
                            rsbac_printk(KERN_WARNING
                                   "rsbac_adf_set_attr_pm(): rsbac_pm_get_data() returned error %i!\n",
                                   error);
                          return(error);
                        }
                      i_attr_val1.pm_object_class = i_data_val1.def_class;
                    }
                  else /* calling process is no TP */
                    /* set class to NIL */
                    i_attr_val1.pm_object_class = 0;
                  
                  if (rsbac_get_attr(SW_PM,
                                     new_target,
                                     new_tid,
                                     A_pm_object_class,
                                     &i_attr_val2,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  if(i_attr_val1.pm_object_class != i_attr_val2.pm_object_class)
                    {
                      if (rsbac_set_attr(SW_PM,
                                         new_target,
                                         new_tid,
                                         A_pm_object_class,
                                         i_attr_val1))
                        {
                          rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_pm(): rsbac_set_attr() returned error!\n");
                          return(-RSBAC_EWRITEFAILED);
                        }
                    }
                  /* Set pm_tp for new item */
                  i_attr_val1.pm_tp = 0;
                  if (rsbac_get_attr(SW_PM,
                                     new_target,
                                     new_tid,
                                     A_pm_tp,
                                     &i_attr_val2,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  if(i_attr_val1.pm_tp != i_attr_val2.pm_tp)
                    {
                      if (rsbac_set_attr(SW_PM,
                                         new_target,
                                         new_tid,
                                         A_pm_tp,
                                         i_attr_val1))
                        {
                          rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_pm(): rsbac_set_attr() returned error!\n");
                          return(-RSBAC_EWRITEFAILED);
                        }
                    }

                  /* get process_type of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                                     T_PROCESS,
                                     i_tid,
                                     A_pm_process_type,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  /* Set pm_object_type for new item */
                  if(new_target == T_DIR)
                    i_attr_val1.pm_object_type = PO_dir;
                  else
                    /* files: if process is TP, set to personal_data */
                    /* to prevent unrestricted access */
                    if(i_attr_val1.pm_process_type == PP_TP)
                      i_attr_val1.pm_object_type = PO_personal_data;
                    else
                      i_attr_val1.pm_object_type = PO_none;
                  if (rsbac_get_attr(SW_PM,
                                     new_target,
                                     new_tid,
                                     A_pm_object_type,
                                     &i_attr_val2,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  if(i_attr_val1.pm_object_type != i_attr_val2.pm_object_type)
                    {
                      if (rsbac_set_attr(SW_PM,
                                         new_target,
                                         new_tid,
                                         A_pm_object_type,
                                         i_attr_val1))
                        {
                          rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_pm(): rsbac_set_attr() returned error!\n");
                          return(-RSBAC_EWRITEFAILED);
                        }
                    }
                  return(0);
                  break;

                case T_IPC: 
                  /* Set pm_ipc_purpose for new item */
                  /* get current_task of caller-process */
                  i_tid.process = caller_pid;
                  if (rsbac_get_attr(SW_PM,
                                     T_PROCESS,
                                     i_tid,
                                     A_pm_current_task,
                                     &i_attr_val1,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  /* if current_task = NIL, ipc_purpose must be NIL */
                  if(!i_attr_val1.pm_current_task)
                    i_attr_val1.pm_ipc_purpose = 0;
                  else
                    {
                      /* get purpose of current_task */
                      i_pm_tid.task = i_attr_val1.pm_current_task;
                      if ((error = rsbac_pm_get_data(0,
                                                     PMT_TASK,
                                                     i_pm_tid,
                                                     PD_purpose,
                                                     &i_data_val1)))
                        {
                          if(error == -RSBAC_EINVALIDTARGET)
                            rsbac_printk(KERN_WARNING
                                   "rsbac_adf_request_pm(): pm_current_task of calling process is invalid!\n");
                          else
                            rsbac_printk(KERN_WARNING
                                   "rsbac_adf_request_pm(): rsbac_pm_get_data() returned error %i!\n",
                                   error);
                          return(-RSBAC_EREADFAILED);
                        }
                      i_attr_val1.pm_ipc_purpose = i_data_val1.purpose;
                    }
                  if (rsbac_get_attr(SW_PM,
                                     target,
                                     tid,
                                     A_pm_ipc_purpose,
                                     &i_attr_val2,
                                     FALSE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  if(i_attr_val1.pm_ipc_purpose != i_attr_val2.pm_ipc_purpose)
                    {
                      if (rsbac_set_attr(SW_PM,
                                         target,
                                         tid,
                                         A_pm_ipc_purpose,
                                         i_attr_val1))
                        {
                          rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_pm(): rsbac_set_attr() returned error!\n");
                          return(-RSBAC_EWRITEFAILED);
                        }
                    }
                  return(0);
                  break;

                /* all other cases are undefined */
                default:
                  return(0);
              }

        case R_EXECUTE:
            switch(target)
              {
                case T_FILE:
                  /* get pm_object_type of target */
                  if (rsbac_get_attr(SW_PM,
                                     T_FILE,
                                     tid,
                                     A_pm_object_type,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  /* if not TP: do nothing */
                  if(i_attr_val1.pm_object_type != PO_TP)
                    return(0);

                  /* get pm_tp of target */
                  if (rsbac_get_attr(SW_PM,
                       T_FILE,
                                     tid,
                                     A_pm_tp,
                                     &i_attr_val1,
                                     TRUE))
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): rsbac_get_attr() returned error!\n");
                      return(-RSBAC_EREADFAILED);
                    }
                  /* if no tp: error! */
                  if(!i_attr_val1.pm_tp)
                    {
                      rsbac_printk(KERN_WARNING
                             "rsbac_adf_request_pm(): file with object_type TP has no tp_id!\n");
                      return(-RSBAC_EINVALIDVALUE);
                    }
                  /* Set pm_tp for this process */
                  i_tid.process = caller_pid;
                  if (rsbac_set_attr(SW_PM,
                                     T_PROCESS,
                                     i_tid,
                                     A_pm_tp,
                                     i_attr_val1))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_pm(): rsbac_set_attr() returned error!\n");
                      return(-RSBAC_EWRITEFAILED);
                    }
                  /* Set pm_process_type for this process */
                  i_attr_val1.pm_process_type = PP_TP;
                  if (rsbac_set_attr(SW_PM,
                                     T_PROCESS,
                                     i_tid,
                                     A_pm_process_type,
                                     i_attr_val1))
                    {
                      rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_pm(): rsbac_set_attr() returned error!\n");
                      return(-RSBAC_EWRITEFAILED);
                    }
                  return(0);

                /* all other cases are undefined */
                default:
                  return(0);
              }

/*********************/

        default: return 0;
      }

    return 0;
  } /* end of rsbac_adf_set_attr_pm() */

/******************************************/
#ifdef CONFIG_RSBAC_SECDEL
rsbac_boolean_t rsbac_need_overwrite_pm(struct dentry * dentry_p)
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
    if (rsbac_get_attr(SW_PM,
                       T_FILE,
                       i_tid,
                       A_pm_object_type,
                       &i_attr_val1,
                       TRUE))
      {
        rsbac_printk(KERN_WARNING "rsbac_need_overwrite_pm(): rsbac_get_attr() returned error!\n");
        return FALSE;
      }

    /* overwrite, if personal data */
    if (i_attr_val1.pm_object_type == PO_personal_data)
      return TRUE;
    else
      return FALSE;
  }
#endif

/* end of rsbac/adf/pm/main.c */
