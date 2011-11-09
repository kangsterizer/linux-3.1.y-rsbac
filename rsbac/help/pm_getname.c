/******************************** */
/* Rule Set Based Access Control  */
/* Author and (c) 1999-2004:      */
/*   Amon Ott <ao@rsbac.org>      */
/* PM getname functions           */
/* Last modified: 19/Nov/2004     */
/******************************** */

#include <rsbac/pm_getname.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

static char  pm_list[PL_none][6] = {
                        "task",
                        "class",
                        "na",
                        "cs",
                        "tp",
                        "pp",
                        "tkt" };

static char  pm_all_list[PA_none][11] = {
                        "task",
                        "class",
                        "na",
                        "cs",
                        "tp",
                        "pp",
                        "tkt",
                        "task_set",
                        "tp_set",
                        "ru_set",
                        "pp_set",
                        "in_pp_set",
                        "out_pp_set" };

static char  pm_role[PR_none+1][24] = {
                         "user",
                         "security_officer",
                         "data_protection_officer",
                         "tp_manager",
                         "system_admin",
                         "none" };

static char  pm_process_type[PP_TP+1][5] = {
                          "none",
                          "tp" };

static char  pm_object_type[PO_dir+1][18] = {
                          "none",
                          "tp",
                          "personal_data",
                          "non_personal_data",
                          "ipc",
                          "dir" };

#ifdef __KERNEL__
static char  pm_set[PS_NONE+1][5] = {
                          "TASK",
                          "TP",
                          "RU",
                          "PP",
                          "NONE" };

static char  pm_target[PMT_NONE+1][6] = {
                          "TASK",
                          "CLASS",
                          "NA",
                          "CS",
                          "TP",
                          "PP",
                          "TKT",
                          "NONE" };

static char  pm_data[PD_none+1][15] = {
                          "purpose",
                          "tp_set",
                          "ru_set",
                          "pp_set",
                          "task",
                          "class",
                          "tp",
                          "accesses",
                          "file",
                          "issuer",
                          "function_type",
                          "function_param",
                          "valid_until",
                          "def_class",
                          "none" };
#endif

static char  pm_function_type[PF_none+1][24] = {
                          "add_na",
                          "delete_na",
                          "add_task",
                          "delete_task",
                          "add_object_class",
                          "delete_object_class",
                          "add_authorized_tp",
                          "delete_authorized_tp",
                          "add_consent",
                          "delete_consent",
                          "add_purpose",
                          "delete_purpose",
                          "add_responsible_user",
                          "delete_responsible_user",
                          "delete_user_aci",
                          "set_role",
                          "set_object_class",
                          "switch_pm",
                          "switch_auth",
                          "set_device_object_type",
                          "set_auth_may_setuid",
                          "set_auth_may_set_cap",
                          /* issued by user also */
                          "add_authorized_task",
                          "delete_authorized_task",
                          /* called by tp_manager */
                          "create_tp",
                          "delete_tp",
                          "set_tp",
                          "create_ticket",
                          "none"};

#ifndef __KERNEL__
static char  pm_function_param[PF_none+1][123] = {
                          "\t\tticket task class tp accesses  (class can be IPC, DEV or NIL)",
                          "\tticket task class tp accesses  (class can be IPC, DEV or NIL)",
                          "\tticket id purpose",
                          "\tticket id",
                          "ticket id purpose1 purpose2 ...",
                          "ticket id",
                          "ticket task tp",
                          "ticket task tp",
                          "\tticket filename purpose",
                          "\tticket filename purpose",
                          "\tticket id default-class\n (class created, if necessary, and purpose added to pp-list of class)",
                          "\tticket id",
                          "ticket user task",
                          "ticket user task",
                          "ticket id",
                          "\tticket user role\n (roles: user|security_officer|data_protection_officer|tp_manager|system_admin)",
                          "ticket filename object_class\n (also sets object_type personal_data (cl!=0) or non_personal_data (cl=0)",
                          "\tticket value (0 or 1)",
                          "\tticket value (0 or 1)",
                          "ticket devicename object_type [object_class]\n (types: none, tp, personal_data, non_personal_data)\n (default class is DEV)",
                          "ticket filename value(0 or 1)",
                          "ticket filename value(0 or 1)",
                          /* issued by user also */
                          "ticket user task",
                          "ticket user task",
                          /* called by tp_manager */
                          "\tid",
                          "\tid",
                          "\t\tfilename id",
                          /* create_ticket */
                          "(call with create_ticket for params)",
                          "INVALID"};
#endif

static char  pm_tkt_function_type[PTF_none+1][25] = {
                          "add_na",
                          "delete_na",
                          "add_task",
                          "delete_task",
                          "add_object_class",
                          "delete_object_class",
                          "add_authorized_tp",
                          "delete_authorized_tp",
                          "add_consent",
                          "delete_consent",
                          "add_purpose",
                          "delete_purpose",
                          "add_responsible_user",
                          "delete_responsible_user",
                          "delete_user_aci",
                          "set_role",
                          "set_object_class",
                          "switch_pm",
                          "switch_auth",
                          "set_device_object_type",
                          "set_auth_may_setuid",
                          "set_auth_may_set_cap",
                          /* issued by user also */
                          "add_authorized_task",
                          "delete_authorized_task",
                          "none"};

#ifndef __KERNEL__
static char  pm_tkt_function_param[PTF_none+1][116] = {
                          "\t\ttask class tp accesses  (class can be IPC, DEV or NIL)",
                          "\ttask class tp accesses  (class can be IPC, DEV or NIL)",
                          "\tid purpose",
                          "\tid",
                          "id purpose1 purpose2 ...",
                          "id",
                          "task tp",
                          "task tp",
                          "\tfilename purpose",
                          "\tfilename purpose",
                          "\tid default-class (class must not be NIL, IPC or DEV)",
                          "\tid",
                          "user task",
                          "user task",
                          "user",
                          "\tuser role\n (roles: user|security_officer|data_protection_officer|tp_manager|system_admin)",
                          "filename object_class\n (sets object_type personal_data (cl!=0) or non_personal_data (cl=0)",
                          "\tvalue (0 or 1)",
                          "\tvalue (0 or 1)",
                          "devicename object_type [object_class]\n (types: none, tp, personal_data, non_personal_data)\n (default class is DEV)",
                          "filename value(0 or 1)",
                          "filename value(0 or 1)",
                          /* issued by user also */
                          "user task",
                          "user task",
                          "INVALID"};
#endif

/*****************************************/

char * get_pm_list_name(char * name,
                        enum  rsbac_pm_list_t value)
  {
    if(!name)
      return(NULL);
    if(value > PL_none)
      strcpy(name, "ERROR!");
    else
      strcpy(name, pm_list[value]);
    return(name);
  };

enum   rsbac_pm_list_t get_pm_list_nr(const char * name)
  {
     enum  rsbac_pm_list_t i;
    
    if(!name)
      return(PL_none);
    for (i = 0; i < PL_none; i++)
      {
        if (!strcmp(name,pm_list[i]))
          {
            return(i);
          }
      }
    return(PL_none);
  };

char * get_pm_all_list_name(char * name,
                            enum  rsbac_pm_all_list_t value)
  {
    if(!name)
      return(NULL);
    if(value > PA_none)
      strcpy(name, "ERROR!");
    else
      strcpy(name, pm_all_list[value]);
    return(name);
  };

enum   rsbac_pm_all_list_t get_pm_all_list_nr(const char * name)
  {
     enum  rsbac_pm_all_list_t i;
    
    if(!name)
      return(PA_none);
    for (i = 0; i < PA_none; i++)
      {
        if (!strcmp(name,pm_all_list[i]))
          {
            return(i);
          }
      }
    return(PA_none);
  };

/****/

char * get_pm_role_name(char * name,
                        enum  rsbac_pm_role_t value)
  {
    if(!name)
      return(NULL);
    if(value > PR_none)
      strcpy(name, "ERROR!");
    else
      strcpy(name, pm_role[value]);
    return(name);
  };

enum   rsbac_pm_role_t get_pm_role_nr(const char * name)
  {
     enum  rsbac_pm_role_t i;
    
    if(!name)
      return(PR_none);
    for (i = 0; i < PR_none; i++)
      {
        if (!strcmp(name,pm_role[i]))
          {
            return(i);
          }
      }
    return(PR_none);
  };

/****/

char * get_pm_process_type_name(char * name,
                        enum  rsbac_pm_process_type_t value)
  {
    if(!name)
      return(NULL);
    if(value > PP_TP)
      strcpy(name, "ERROR!");
    else
      strcpy(name, pm_process_type[value]);
    return(name);
  };

enum   rsbac_pm_process_type_t get_pm_process_type_nr(const char * name)
  {
     enum  rsbac_pm_process_type_t i;
    
    if(!name)
      return(PP_none);
    for (i = 0; i < PP_TP; i++)
      {
        if (!strcmp(name,pm_process_type[i]))
          {
            return(i);
          }
      }
    return(PP_none);
  };


/****/

char * get_pm_object_type_name(char * name,
                        enum  rsbac_pm_object_type_t value)
  {
    if(!name)
      return(NULL);
    if(value > PO_dir)
      strcpy(name, "ERROR!");
    else
      strcpy(name, pm_object_type[value]);
    return(name);
  };

enum   rsbac_pm_object_type_t get_pm_object_type_nr(const char * name)
  {
     enum  rsbac_pm_object_type_t i;
    
    if(!name)
      return(PO_none);
    for (i = 0; i < PO_dir; i++)
      {
        if (!strcmp(name,pm_object_type[i]))
          {
            return(i);
          }
      }
    return(PO_none);
  };

/****/

#ifdef __KERNEL__
char * get_pm_set_name(char * name,
                        enum  rsbac_pm_set_t value)
  {
    if(!name)
      return(NULL);
    if(value > PS_NONE)
      strcpy(name, "ERROR!");
    else
      strcpy(name, pm_set[value]);
    return(name);
  };

enum   rsbac_pm_set_t get_pm_set_nr(const char * name)
  {
     enum  rsbac_pm_set_t i;
    
    if(!name)
      return(PS_NONE);
    for (i = 0; i < PS_NONE; i++)
      {
        if (!strcmp(name,pm_set[i]))
          {
            return(i);
          }
      }
    return(PS_NONE);
  };

/****/

char * get_pm_target_name(char * name,
                        enum  rsbac_pm_target_t value)
  {
    if(!name)
      return(NULL);
    if(value > PMT_NONE)
      strcpy(name, "ERROR!");
    else
      strcpy(name, pm_target[value]);
    return(name);
  };

enum   rsbac_pm_target_t get_pm_target_nr(const char * name)
  {
     enum  rsbac_pm_target_t i;
    
    if(!name)
      return(PMT_NONE);
    for (i = 0; i < PMT_NONE; i++)
      {
        if (!strcmp(name,pm_target[i]))
          {
            return(i);
          }
      }
    return(PMT_NONE);
  };

/****/

char * get_pm_data_name(char * name,
                        enum  rsbac_pm_data_t value)
  {
    if(!name)
      return(NULL);
    if(value > PD_none)
      strcpy(name, "ERROR!");
    else
      strcpy(name, pm_data[value]);
    return(name);
  };

enum   rsbac_pm_data_t get_pm_data_nr(const char * name)
  {
     enum  rsbac_pm_data_t i;
    
    if(!name)
      return(PD_none);
    for (i = 0; i < PD_none; i++)
      {
        if (!strcmp(name,pm_data[i]))
          {
            return(i);
          }
      }
    return(PD_none);
  };
#endif /* def __KERNEL__ */

/****/

char * get_pm_function_type_name(char * name,
                        enum  rsbac_pm_function_type_t value)
  {
    if(!name)
      return(NULL);
    if(value > PF_none)
      strcpy(name, "ERROR!");
    else
      strcpy(name, pm_function_type[value]);
    return(name);
  };

enum   rsbac_pm_function_type_t get_pm_function_type_nr(const char * name)
  {
     enum  rsbac_pm_function_type_t i;
    
    if(!name)
      return(PF_none);
    for (i = 0; i < PF_none; i++)
      {
        if (!strcmp(name,pm_function_type[i]))
          {
            return(i);
          }
      }
    return(PF_none);
  };

#ifndef __KERNEL__
char * get_pm_function_param(char * name,
                        enum  rsbac_pm_function_type_t value)
  {
    if(!name)
      return(NULL);
    if(value > PF_none)
      strcpy(name, "ERROR!");
    else
      strcpy(name, pm_function_param[value]);
    return(name);
  };
#endif

/****/

char * get_pm_tkt_function_type_name(char * name,
                        enum  rsbac_pm_tkt_function_type_t value)
  {
    if(!name)
      return(NULL);
    if(value > PTF_none)
      strcpy(name, "ERROR!");
    else
      strcpy(name, pm_tkt_function_type[value]);
    return(name);
  };

enum   rsbac_pm_tkt_function_type_t
    get_pm_tkt_function_type_nr(const char * name)
  {
     enum  rsbac_pm_tkt_function_type_t i;
    
    if(!name)
      return(PTF_none);
    for (i = 0; i < PTF_none; i++)
      {
        if (!strcmp(name,pm_tkt_function_type[i]))
          {
            return(i);
          }
      }
    return(PTF_none);
  };

#ifndef __KERNEL__
char * get_pm_tkt_function_param(char * name,
                        enum  rsbac_pm_tkt_function_type_t value)
  {
    if(!name)
      return(NULL);
    if(value > PTF_none)
      strcpy(name, "ERROR!");
    else
    strcpy(name, pm_tkt_function_param[value]);
    return(name);
  };
#endif
