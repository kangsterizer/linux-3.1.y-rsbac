/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2001:          */
/*   Amon Ott <ao@rsbac.org>          */
/* API: Data types for privacy        */
/*      model calls                   */
/* Last modified: 06/Sep/2001         */
/************************************ */

#ifndef __RSBAC_PM_TYPES_H
#define __RSBAC_PM_TYPES_H

#include <linux/types.h>

/* Basic types */

typedef __u32 rsbac_pm_task_id_t;
typedef __u32 rsbac_pm_task_set_id_t;
typedef __u32 rsbac_pm_tp_id_t;       /* transformation procedure id */
typedef __u32 rsbac_pm_tp_set_id_t;   /* transformation procedure set id */
typedef __u32 rsbac_pm_ru_set_id_t;   /* responsible user set id */
typedef __u32 rsbac_pm_purpose_id_t;
typedef __s32 rsbac_pm_pp_set_id_t;   /* purpose set id */
typedef rsbac_pid_t rsbac_pm_in_pp_set_id_t; /* input purpose set id */
typedef rsbac_pm_in_pp_set_id_t rsbac_pm_out_pp_set_id_t;
                                            /* output purpose set id */
typedef __u32 rsbac_pm_object_class_id_t;
typedef __u32 rsbac_pm_tkt_id_t;      /* ticket id */
typedef rsbac_time_t rsbac_pm_time_stamp_t; /* for ticket time stamps, same as */
                                      /* parameter for sys_time */
typedef __u8 rsbac_pm_accesses_t;   /* for necessary accesses */
#define RSBAC_PM_A_READ   1
#define RSBAC_PM_A_WRITE  2
#define RSBAC_PM_A_DELETE 4
#define RSBAC_PM_A_CREATE 8
#define RSBAC_PM_A_APPEND 16
#define RSBAC_PM_A_ALL    31
#define RSBAC_PM_A_WRITING (RSBAC_PM_A_WRITE | RSBAC_PM_A_DELETE \
                            | RSBAC_PM_A_CREATE | RSBAC_PM_A_APPEND)
#define RSBAC_PM_A_WRITE_TO_FILE (RSBAC_PM_A_WRITE | RSBAC_PM_A_APPEND)

#define RSBAC_PM_ROOT_TASK_SET_ID     (rsbac_pm_task_set_id_t) -1
#define RSBAC_PM_IPC_OBJECT_CLASS_ID  (rsbac_pm_object_class_id_t) 60000
#define RSBAC_PM_DEV_OBJECT_CLASS_ID  (rsbac_pm_object_class_id_t) 60001

/* enum attributes */

enum    rsbac_pm_list_t {PL_task,PL_class,PL_na,PL_cs,PL_tp,PL_pp,PL_tkt,PL_none};

enum    rsbac_pm_all_list_t {PA_task,PA_class,PA_na,PA_cs,PA_tp,PA_pp,PA_tkt,
                             PA_task_set,PA_tp_set,PA_ru_set,PA_pp_set,
                             PA_in_pp_set,PA_out_pp_set,PA_none};

enum    rsbac_pm_role_t {PR_user, PR_security_officer,
                         PR_data_protection_officer,
                         PR_tp_manager, PR_system_admin,
                         PR_none};
typedef rsbac_enum_t rsbac_pm_role_int_t;

enum    rsbac_pm_process_type_t {PP_none, PP_TP};
typedef rsbac_enum_t rsbac_pm_process_type_int_t;

enum    rsbac_pm_object_type_t {PO_none, PO_TP, PO_personal_data,
                                PO_non_personal_data, PO_ipc, PO_dir};
typedef rsbac_enum_t rsbac_pm_object_type_int_t;

typedef rsbac_pm_process_type_int_t rsbac_pm_program_type_int_t;

#ifdef __KERNEL__
enum    rsbac_pm_set_t  {PS_TASK,PS_TP,PS_RU,PS_PP,PS_IN_PP,PS_OUT_PP,PS_NONE};

/* unions */

union rsbac_pm_set_id_t
  {
    rsbac_pm_task_set_id_t   task_set;
    rsbac_pm_tp_set_id_t     tp_set;
    rsbac_pm_ru_set_id_t     ru_set;
    rsbac_pm_pp_set_id_t     pp_set;
    rsbac_pm_in_pp_set_id_t  in_pp_set;
    rsbac_pm_out_pp_set_id_t out_pp_set;
  };

union rsbac_pm_set_member_t
  {
    rsbac_pm_task_id_t      task;
    rsbac_pm_tp_id_t        tp;
    rsbac_uid_t             ru;
    rsbac_pm_purpose_id_t   pp;
  };

struct  rsbac_pm_na_id_t
  {
      rsbac_pm_task_id_t                 task;
      rsbac_pm_object_class_id_t         object_class;
      rsbac_pm_tp_id_t                   tp;
  };

struct  rsbac_pm_cs_id_t
  {
      rsbac_pm_purpose_id_t              purpose;
      struct rsbac_fs_file_t             file;
  };

/*****************/
/* api types     */
/*****************/

struct rsbac_pm_task_data_t
    {
      rsbac_pm_task_id_t                 id;
      rsbac_pm_purpose_id_t              purpose;
      rsbac_pm_tp_set_id_t               tp_set;
      rsbac_pm_ru_set_id_t               ru_set;
    };

struct rsbac_pm_class_data_t
    {
      rsbac_pm_object_class_id_t            id;
      rsbac_pm_pp_set_id_t                  pp_set;
    };

struct rsbac_pm_na_data_t
    {
      rsbac_pm_task_id_t                 task;
      rsbac_pm_object_class_id_t         object_class;
      rsbac_pm_tp_id_t                   tp;
      rsbac_pm_accesses_t                accesses;
    };

struct rsbac_pm_cs_data_t
    {
      rsbac_pm_purpose_id_t              purpose;
      struct rsbac_fs_file_t             file;
    };

struct rsbac_pm_tp_data_t
    {
      rsbac_pm_tp_id_t                   id;
    };

struct rsbac_pm_pp_data_t
    {
      rsbac_pm_purpose_id_t              id;
      rsbac_pm_object_class_id_t         def_class;
    };
#endif /* __KERNEL__ */

struct rsbac_pm_purpose_list_item_t
    {
      rsbac_pm_purpose_id_t                 id;
      struct rsbac_pm_purpose_list_item_t * next;
    };

/******* ticket ********/

#include <rsbac/pm_ticket.h>

#ifdef __KERNEL__
/****************************************************************************/
/* For all pm lists all manipulation is encapsulated by the function calls  */
/* rsbac_pm_set_data, rsbac_pm_get_data and rsbac_pm_remove_target.   */

/* For those, we declare some extra types to specify target and attribute.  */

enum   rsbac_pm_target_t {PMT_TASK,
                          PMT_CLASS,
                          PMT_NA,
                          PMT_CS,
                          PMT_TP,
                          PMT_PP,
                          PMT_TKT,
                          PMT_NONE};
typedef rsbac_enum_t rsbac_pm_target_int_t;

union  rsbac_pm_target_id_t
       {
          rsbac_pm_task_id_t          task;
          rsbac_pm_object_class_id_t  object_class;
          struct rsbac_pm_na_id_t     na;
          struct rsbac_pm_cs_id_t     cs;
          rsbac_pm_tp_id_t            tp;
          rsbac_pm_purpose_id_t       pp;
          rsbac_pm_tkt_id_t           tkt;
          int                         dummy;
       };

enum   rsbac_pm_data_t
       {                  PD_purpose,
                          PD_tp_set,
                          PD_ru_set,
                          PD_pp_set,
                          PD_task,
                          PD_class,
                          PD_tp,
                          PD_accesses,
                          PD_file,
                          PD_issuer,
                          PD_function_type,
                          PD_function_param,
                          PD_valid_until,
                          PD_def_class,
                          PD_none
       };
typedef rsbac_enum_t rsbac_pm_data_int_t;

union  rsbac_pm_data_value_t
       {
          rsbac_pm_purpose_id_t         purpose;
          rsbac_pm_tp_set_id_t          tp_set;
          rsbac_pm_ru_set_id_t          ru_set;
          rsbac_pm_pp_set_id_t          pp_set;
          rsbac_pm_task_id_t            task;
          rsbac_pm_object_class_id_t    object_class;
          rsbac_pm_tp_id_t              tp;
          rsbac_pm_accesses_t           accesses;
          struct rsbac_fs_file_t        file;
          rsbac_uid_t                   issuer;
          enum   rsbac_pm_tkt_function_type_t   function_type;
          union  rsbac_pm_tkt_internal_function_param_t  function_param;
          rsbac_pm_time_stamp_t         valid_until;
          rsbac_pm_object_class_id_t    def_class;
          int                           dummy;
       };


union  rsbac_pm_all_data_value_t
       {
          struct rsbac_pm_task_data_t   task;
          struct rsbac_pm_class_data_t  object_class;
          struct rsbac_pm_na_data_t     na;
          struct rsbac_pm_cs_data_t     cs;
          struct rsbac_pm_tp_data_t     tp;
          struct rsbac_pm_pp_data_t     pp;
          struct rsbac_pm_tkt_data_t    tkt;
          int                           dummy;
       };
#endif

#endif
