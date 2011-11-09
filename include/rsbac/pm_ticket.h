/******************************* */
/* Rule Set Based Access Control */
/* Author and (c) 1999-2005:     */
/*   Amon Ott <ao@rsbac.org>     */
/* API: Data types for privacy   */
/*      model calls / tickets    */
/* Last modified: 09/Feb/2005    */
/******************************* */

#ifndef __RSBAC_PM_TICKET_H
#define __RSBAC_PM_TICKET_H

#include <linux/types.h>

enum    rsbac_pm_tkt_function_type_t {/* issued by data_prot_officer */
                                      PTF_add_na, PTF_delete_na, PTF_add_task,
                                      PTF_delete_task, PTF_add_object_class,
                                      PTF_delete_object_class,
                                      PTF_add_authorized_tp,
                                      PTF_delete_authorized_tp,
                                      PTF_add_consent, PTF_delete_consent,
                                      PTF_add_purpose, PTF_delete_purpose,
                                      PTF_add_responsible_user,
                                      PTF_delete_responsible_user,
                                      PTF_delete_user_aci,
                                      PTF_set_role,
                                      PTF_set_object_class,
                                      PTF_switch_pm,
                                      PTF_switch_auth,
                                      PTF_set_device_object_type,
                                      PTF_set_auth_may_setuid,
                                      PTF_set_auth_may_set_cap,
                                      /* issued by user also */
                                      PTF_add_authorized_task,
                                      PTF_delete_authorized_task,
                                      /* never issued, internal */
                                      PTF_none};

struct rsbac_pm_add_na_t
  {
    rsbac_pm_task_id_t            task;
    rsbac_pm_object_class_id_t    object_class;
    rsbac_pm_tp_id_t              tp;
    rsbac_pm_accesses_t           accesses;
  };

struct rsbac_pm_delete_na_t
  {
    rsbac_pm_task_id_t            task;
    rsbac_pm_object_class_id_t    object_class;
    rsbac_pm_tp_id_t              tp;
    rsbac_pm_accesses_t           accesses;
  };

struct rsbac_pm_add_task_t
  {
    rsbac_pm_task_id_t            id;
    rsbac_pm_purpose_id_t         purpose;
  };

struct rsbac_pm_delete_task_t
  {
    rsbac_pm_task_id_t            id;
  };

#ifdef __KERNEL__
struct rsbac_pm_tkt_add_object_class_t
  {
    rsbac_pm_object_class_id_t            id;
    rsbac_pm_pp_set_id_t                  pp_set;
  };
#endif

struct rsbac_pm_add_object_class_t
  {
    rsbac_pm_object_class_id_t            id;
    struct rsbac_pm_purpose_list_item_t * pp_list_p;
  };

struct rsbac_pm_delete_object_class_t
  {
    rsbac_pm_object_class_id_t    id;
  };

struct rsbac_pm_add_authorized_tp_t
  {
    rsbac_pm_task_id_t            task;
    rsbac_pm_tp_id_t              tp;
  };

struct rsbac_pm_delete_authorized_tp_t
  {
    rsbac_pm_task_id_t            task;
    rsbac_pm_tp_id_t              tp;
  };

#ifdef __KERNEL__
struct rsbac_pm_tkt_add_consent_t
  {
    struct rsbac_fs_file_t        file;
    rsbac_pm_purpose_id_t         purpose;
  };
#endif

struct rsbac_pm_add_consent_t
  {
    char                        * filename;
           rsbac_pm_purpose_id_t  purpose;
  };

#ifdef __KERNEL__
struct rsbac_pm_tkt_delete_consent_t
  {
    struct rsbac_fs_file_t        file;
    rsbac_pm_purpose_id_t         purpose;
  };
#endif

struct rsbac_pm_delete_consent_t
  {
    char                        * filename;
    rsbac_pm_purpose_id_t         purpose;
  };

struct rsbac_pm_add_purpose_t
  {
    rsbac_pm_purpose_id_t         id;
    rsbac_pm_object_class_id_t    def_class;
  };

struct rsbac_pm_delete_purpose_t
  {
    rsbac_pm_purpose_id_t         id;
  };

struct rsbac_pm_add_responsible_user_t
  {
    rsbac_uid_t                   user;
    rsbac_pm_task_id_t            task;
  };

struct rsbac_pm_delete_responsible_user_t
  {
    rsbac_uid_t                   user;
    rsbac_pm_task_id_t            task;
  };

struct rsbac_pm_delete_user_aci_t
  {
    rsbac_uid_t                   id;
  };

struct rsbac_pm_set_role_t
  {
    rsbac_uid_t                   user;
    enum rsbac_pm_role_t          role;
  };

#ifdef __KERNEL__
struct rsbac_pm_tkt_set_object_class_t
  {
    struct rsbac_fs_file_t        file;
    rsbac_pm_object_class_id_t    object_class;
  };
#endif

struct rsbac_pm_set_object_class_t
  {
    char                        * filename;
    rsbac_pm_object_class_id_t    object_class;
  };

struct rsbac_pm_switch_pm_t
  {
    rsbac_boolean_t               value;
  };

struct rsbac_pm_switch_auth_t
  {
    rsbac_boolean_t               value;
  };

#ifdef __KERNEL__
struct rsbac_pm_tkt_set_device_object_type_t
  {
    struct rsbac_dev_desc_t       dev;
    enum rsbac_pm_object_type_t   object_type;
    rsbac_pm_object_class_id_t    object_class;
  };
#endif

struct rsbac_pm_set_device_object_type_t
  {
    char                        * filename;
    enum rsbac_pm_object_type_t   object_type;
    rsbac_pm_object_class_id_t    object_class;
  };

#ifdef __KERNEL__
struct rsbac_pm_tkt_set_auth_may_setuid_t
  {
    struct rsbac_fs_file_t        file;
    rsbac_boolean_t               value;
  };
#endif

struct rsbac_pm_set_auth_may_setuid_t
  {
    char                        * filename;
    rsbac_boolean_t               value;
  };

#ifdef __KERNEL__
struct rsbac_pm_tkt_set_auth_may_set_cap_t
  {
    struct rsbac_fs_file_t        file;
    rsbac_boolean_t               value;
  };
#endif

struct rsbac_pm_set_auth_may_set_cap_t
  {
    char                        * filename;
    rsbac_boolean_t               value;
  };

/***************/

struct rsbac_pm_add_authorized_task_t
  {
    rsbac_uid_t                   user;
    rsbac_pm_task_id_t            task;
  };

struct rsbac_pm_delete_authorized_task_t
  {
    rsbac_uid_t                   user;
    rsbac_pm_task_id_t            task;
  };

/***************/

struct rsbac_pm_create_tp_t
  {
    rsbac_pm_tp_id_t              id;
  };

struct rsbac_pm_delete_tp_t
  {
    rsbac_pm_tp_id_t              id;
  };

struct rsbac_pm_set_tp_t
  {
    char                        * filename;
    rsbac_pm_tp_id_t              tp;
  };

/***************/

#ifdef __KERNEL__
union   rsbac_pm_tkt_internal_function_param_t
         {
           struct rsbac_pm_add_na_t                   add_na;
           struct rsbac_pm_delete_na_t                delete_na;
           struct rsbac_pm_add_task_t                 add_task;
           struct rsbac_pm_delete_task_t              delete_task;
           struct rsbac_pm_tkt_add_object_class_t     tkt_add_object_class;
           struct rsbac_pm_delete_object_class_t      delete_object_class;
           struct rsbac_pm_add_authorized_tp_t        add_authorized_tp;
           struct rsbac_pm_delete_authorized_tp_t     delete_authorized_tp;
           struct rsbac_pm_tkt_add_consent_t          tkt_add_consent;
           struct rsbac_pm_tkt_delete_consent_t       tkt_delete_consent;
           struct rsbac_pm_add_purpose_t              add_purpose;
           struct rsbac_pm_delete_purpose_t           delete_purpose;
           struct rsbac_pm_add_responsible_user_t     add_responsible_user;
           struct rsbac_pm_delete_responsible_user_t  delete_responsible_user;
           struct rsbac_pm_delete_user_aci_t          delete_user_aci;
           struct rsbac_pm_set_role_t                 set_role;
           struct rsbac_pm_tkt_set_object_class_t     tkt_set_object_class;
           struct rsbac_pm_switch_pm_t                switch_pm;
           struct rsbac_pm_switch_pm_t                switch_auth;
           struct rsbac_pm_tkt_set_device_object_type_t tkt_set_device_object_type;
           struct rsbac_pm_tkt_set_auth_may_setuid_t  tkt_set_auth_may_setuid;
           struct rsbac_pm_tkt_set_auth_may_set_cap_t tkt_set_auth_may_set_cap;
           struct rsbac_pm_add_authorized_task_t      add_authorized_task;
           struct rsbac_pm_delete_authorized_task_t   delete_authorized_task;
           int                                        dummy;
         };
#endif

union   rsbac_pm_tkt_function_param_t
         {
           struct rsbac_pm_add_na_t                   add_na;
           struct rsbac_pm_delete_na_t                delete_na;
           struct rsbac_pm_add_task_t                 add_task;
           struct rsbac_pm_delete_task_t              delete_task;
           struct rsbac_pm_add_object_class_t         add_object_class;
           struct rsbac_pm_delete_object_class_t      delete_object_class;
           struct rsbac_pm_add_authorized_tp_t        add_authorized_tp;
           struct rsbac_pm_delete_authorized_tp_t     delete_authorized_tp;
           struct rsbac_pm_add_consent_t              add_consent;
           struct rsbac_pm_delete_consent_t           delete_consent;
           struct rsbac_pm_add_purpose_t              add_purpose;
           struct rsbac_pm_delete_purpose_t           delete_purpose;
           struct rsbac_pm_add_responsible_user_t     add_responsible_user;
           struct rsbac_pm_delete_responsible_user_t  delete_responsible_user;
           struct rsbac_pm_delete_user_aci_t          delete_user_aci;
           struct rsbac_pm_set_role_t                 set_role;
           struct rsbac_pm_set_object_class_t         set_object_class;
           struct rsbac_pm_switch_pm_t                switch_pm;
           struct rsbac_pm_switch_pm_t                switch_auth;
           struct rsbac_pm_set_device_object_type_t   set_device_object_type;
           struct rsbac_pm_set_auth_may_setuid_t      set_auth_may_setuid;
           struct rsbac_pm_set_auth_may_set_cap_t     set_auth_may_set_cap;
           struct rsbac_pm_add_authorized_task_t      add_authorized_task;
           struct rsbac_pm_delete_authorized_task_t   delete_authorized_task;
           int                                        dummy;
         };

/***********************/

enum    rsbac_pm_function_type_t     {/* tkt issued by data_prot_officer, */
                                      /* called by security_officer */
                                      PF_add_na, PF_delete_na, PF_add_task,
                                      PF_delete_task, PF_add_object_class,
                                      PF_delete_object_class,
                                      PF_add_authorized_tp,
                                      PF_delete_authorized_tp,
                                      PF_add_consent, PF_delete_consent,
                                      PF_add_purpose, PF_delete_purpose,
                                      PF_add_responsible_user,
                                      PF_delete_responsible_user,
                                      PF_delete_user_aci,
                                      PF_set_role,
                                      PF_set_object_class,
                                      PF_switch_pm,
                                      PF_switch_auth,
                                      PF_set_device_object_type,
                                      PF_set_auth_may_setuid,
                                      PF_set_auth_may_set_cap,
                                      /* tkt issued by data_prot_officer and */
                                      /* resp. user, called by security_officer */
                                      PF_add_authorized_task,
                                      PF_delete_authorized_task,
                                      /* called by tp_manager, no ticket */
                                      PF_create_tp, PF_delete_tp, PF_set_tp,
                                      /* called by data_prot_officer and */
                                      /* responsible user */
                                      PF_create_ticket,
                                      /* never to be called, internal */
                                      PF_none};

struct rsbac_pm_create_ticket_t
  {
           rsbac_pm_tkt_id_t              id;
           rsbac_pm_time_stamp_t          valid_for;  /* validity in secs */
    enum   rsbac_pm_tkt_function_type_t   function_type;
    union  rsbac_pm_tkt_function_param_t  function_param;
  };

union   rsbac_pm_function_param_t
         {
           struct rsbac_pm_add_na_t                   add_na;
           struct rsbac_pm_delete_na_t                delete_na;
           struct rsbac_pm_add_task_t                 add_task;
           struct rsbac_pm_delete_task_t              delete_task;
           struct rsbac_pm_add_object_class_t         add_object_class;
           struct rsbac_pm_delete_object_class_t      delete_object_class;
           struct rsbac_pm_add_authorized_tp_t        add_authorized_tp;
           struct rsbac_pm_delete_authorized_tp_t     delete_authorized_tp;
           struct rsbac_pm_add_consent_t              add_consent;
           struct rsbac_pm_delete_consent_t           delete_consent;
           struct rsbac_pm_add_purpose_t              add_purpose;
           struct rsbac_pm_delete_purpose_t           delete_purpose;
           struct rsbac_pm_add_responsible_user_t     add_responsible_user;
           struct rsbac_pm_delete_responsible_user_t  delete_responsible_user;
           struct rsbac_pm_delete_user_aci_t          delete_user_aci;
           struct rsbac_pm_set_role_t                 set_role;
           struct rsbac_pm_set_object_class_t         set_object_class;
           struct rsbac_pm_switch_pm_t                switch_pm;
           struct rsbac_pm_switch_pm_t                switch_auth;
           struct rsbac_pm_set_device_object_type_t   set_device_object_type;
           struct rsbac_pm_set_auth_may_setuid_t      set_auth_may_setuid;
           struct rsbac_pm_set_auth_may_set_cap_t     set_auth_may_set_cap;
           struct rsbac_pm_add_authorized_task_t      add_authorized_task;
           struct rsbac_pm_delete_authorized_task_t   delete_authorized_task;
           struct rsbac_pm_create_tp_t                create_tp;
           struct rsbac_pm_delete_tp_t                delete_tp;
           struct rsbac_pm_set_tp_t                   set_tp;
           struct rsbac_pm_create_ticket_t            create_ticket;
           int                                        dummy;
         };


/*******************/

#ifdef __KERNEL__
struct rsbac_pm_tkt_data_t
    {
             rsbac_pm_tkt_id_t                       id;
             rsbac_uid_t                             issuer;
      enum   rsbac_pm_tkt_function_type_t            function_type;
      union  rsbac_pm_tkt_internal_function_param_t  function_param;
             rsbac_pm_time_stamp_t                   valid_until;
    };
#endif

#endif
