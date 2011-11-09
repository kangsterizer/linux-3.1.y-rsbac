/************************************ */
/* Rule Set Based Access Control      */
/*                                    */
/* Author and (c) 1999,2000: Amon Ott */
/*                                    */
/* Getname functions for ACL module   */
/* Last modified: 19/Sep/2000         */
/************************************ */

#include <rsbac/types.h>
#include <rsbac/getname.h>
#include <rsbac/acl_getname.h>
#include <rsbac/helpers.h>
#include <rsbac/error.h>

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

static char  acl_subject_type_list[ACLS_NONE+1][6] = {
                          "USER",
                          "ROLE",
                          "GROUP",
                          "NONE" };

static char  acl_group_syscall_list[ACLGS_none+1][18] = {
                          "add_group",
                          "change_group",
                          "remove_group",
                          "get_group_entry",
                          "list_groups",
                          "add_member",
                          "remove_member",
                          "get_user_groups",
                          "get_group_members",
                          "none" };

static char  acl_scd_type_list[AST_none-32+1][20] = {
                          "auth_administration",
                          "none" };

static char  acl_special_right_list[ACLR_NONE-32+1][20] = {
                          "FORWARD",
                          "ACCESS_CONTROL",
                          "SUPERVISOR",
                          "NONE" };

/*****************************************/

char * get_acl_subject_type_name(char * name,
                                 enum rsbac_acl_subject_type_t value)
  {
    if(!name)
      return(NULL);
    if(value > ACLS_NONE)
      strcpy(name, "ERROR!");
    else
      strcpy(name, acl_subject_type_list[value]);
    return(name);
  };

#ifndef __KERNEL__
enum rsbac_acl_subject_type_t get_acl_subject_type_nr(const char * name)
  {
     enum  rsbac_acl_subject_type_t i;

    if(!name)
      return(ACLS_NONE);
    for (i = 0; i < ACLS_NONE; i++)
      {
        if (!strcmp(name, acl_subject_type_list[i]))
          {
            return(i);
          }
      }
    return(ACLS_NONE);
  };
#endif

char * get_acl_group_syscall_name(char * name,
                                  enum rsbac_acl_group_syscall_type_t value)
  {
    if(!name)
      return(NULL);
    if(value > ACLGS_none)
      strcpy(name, "ERROR!");
    else
      strcpy(name, acl_group_syscall_list[value]);
    return(name);
  };

#ifndef __KERNEL__
enum rsbac_acl_group_syscall_type_t get_acl_group_syscall_nr(const char * name)
  {
    enum  rsbac_acl_group_syscall_type_t i;

    if(!name)
      return(ACLGS_none);
    for (i = 0; i < ACLGS_none; i++)
      {
        if (!strcmp(name, acl_group_syscall_list[i]))
          {
            return(i);
          }
      }
    return(ACLGS_none);
  };
#endif

char * get_acl_scd_type_name(char * name,
                            enum rsbac_acl_scd_type_t value)
  {
    if(!name)
      return(NULL);
    if(value < AST_min)
      {
        return(get_scd_type_name(name, value));
      }
    value -= AST_min;
    if(value > AST_none)
      {
        strcpy(name, "ERROR!");
        return(name);
      }
    strcpy(name, acl_scd_type_list[value]);
    return(name);
  };

#ifndef __KERNEL__
enum rsbac_acl_scd_type_t get_acl_scd_type_nr(const char * name)
  {
     enum  rsbac_acl_scd_type_t i;
    
    if(!name)
      return(AST_none);
    for (i = 0; i < AST_none-32; i++)
      {
        if (!strcmp(name, acl_scd_type_list[i]))
          {
            return(i+32);
          }
      }
    return(get_scd_type_nr(name));
  };
#endif

char * get_acl_special_right_name(char * name,
                            enum rsbac_acl_special_rights_t value)
  {
    if(!name)
      return(NULL);
    if(value < RSBAC_ACL_SPECIAL_RIGHT_BASE)
      {
        return(get_request_name(name, value));
      }
    value -= RSBAC_ACL_SPECIAL_RIGHT_BASE;
    if(value > ACLR_NONE)
      {
        strcpy(name, "ERROR!");
        return(name);
      }
    strcpy(name, acl_special_right_list[value]);
    return(name);
  };

#ifndef __KERNEL__
enum rsbac_acl_special_rights_t get_acl_special_right_nr(const char * name)
  {
     enum  rsbac_acl_special_rights_t i;
    
    if(!name)
      return(ACLR_NONE);
    for (i = 0; i < (ACLR_NONE - RSBAC_ACL_SPECIAL_RIGHT_BASE); i++)
      {
        if (!strcmp(name, acl_special_right_list[i]))
          {
            return(i + RSBAC_ACL_SPECIAL_RIGHT_BASE);
          }
      }
    return(get_request_nr(name));
  };
#endif
