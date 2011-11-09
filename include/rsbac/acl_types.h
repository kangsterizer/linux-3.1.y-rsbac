/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2007:          */
/*   Amon Ott <ao@rsbac.org>          */
/* API: Data types for attributes     */
/*      and standard module calls     */
/* Last modified: 25/Sep/2007         */
/************************************ */

#ifndef __RSBAC_ACL_TYPES_H
#define __RSBAC_ACL_TYPES_H

#include <linux/types.h>

#define RSBAC_ACL_TTL_KEEP RSBAC_LIST_TTL_KEEP

#define RSBAC_ACL_MAX_MAXNUM 1000000

enum rsbac_acl_subject_type_t {ACLS_USER, ACLS_ROLE, ACLS_GROUP, ACLS_NONE};

typedef __u8 rsbac_acl_int_subject_type_t;
typedef __u64 rsbac_acl_subject_id_t;
typedef __u32 rsbac_acl_old_subject_id_t;

#define RSBAC_ACL_GROUP_EVERYONE 0

#define RSBAC_ACL_ROLE_EVERYROLE 64

#define RSBAC_ACL_OLD_SPECIAL_RIGHT_BASE 48
#define RSBAC_ACL_SPECIAL_RIGHT_BASE 56

enum rsbac_acl_special_rights_t
  { ACLR_FORWARD = RSBAC_ACL_SPECIAL_RIGHT_BASE,
    ACLR_ACCESS_CONTROL,
    ACLR_SUPERVISOR,
    ACLR_NONE};

typedef __u64 rsbac_acl_rights_vector_t;

#define RSBAC_ACL_RIGHTS_VECTOR(x) ((rsbac_acl_rights_vector_t) 1 << (x))

#define RSBAC_ACL_SPECIAL_RIGHTS_VECTOR (\
  ((rsbac_acl_rights_vector_t) 1 << ACLR_FORWARD) | \
  ((rsbac_acl_rights_vector_t) 1 << ACLR_ACCESS_CONTROL) | \
  ((rsbac_acl_rights_vector_t) 1 << ACLR_SUPERVISOR) \
  )

#define RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR (\
  ((rsbac_acl_rights_vector_t) 1 << ACLR_SUPERVISOR) \
  )
#define RSBAC_NWS_REQUEST_VECTOR RSBAC_ACL_SUPERVISOR_RIGHT_VECTOR

#define RSBAC_ACL_ACCESS_CONTROL_RIGHT_VECTOR (\
  ((rsbac_acl_rights_vector_t) 1 << ACLR_ACCESS_CONTROL) \
  )
#define RSBAC_NWA_REQUEST_VECTOR RSBAC_ACL_ACCESS_CONTROL_RIGHT_VECTOR

#define RSBAC_ACL_ALL_RIGHTS_VECTOR (RSBAC_ALL_REQUEST_VECTOR | RSBAC_ACL_SPECIAL_RIGHTS_VECTOR)

#define RSBAC_ACL_DEFAULT_FD_MASK (RSBAC_FD_REQUEST_VECTOR | RSBAC_ACL_SPECIAL_RIGHTS_VECTOR)
#define RSBAC_ACL_DEFAULT_DEV_MASK (RSBAC_DEV_REQUEST_VECTOR | RSBAC_ACL_SPECIAL_RIGHTS_VECTOR)
#define RSBAC_ACL_DEFAULT_SCD_MASK (RSBAC_SCD_REQUEST_VECTOR | RSBAC_ACL_SPECIAL_RIGHTS_VECTOR)
#define RSBAC_ACL_DEFAULT_U_MASK (RSBAC_USER_REQUEST_VECTOR | RSBAC_ACL_SPECIAL_RIGHTS_VECTOR)
#define RSBAC_ACL_DEFAULT_G_MASK (RSBAC_GROUP_REQUEST_VECTOR | RSBAC_ACL_SPECIAL_RIGHTS_VECTOR)
#define RSBAC_ACL_DEFAULT_NETDEV_MASK (RSBAC_NETDEV_REQUEST_VECTOR | RSBAC_ACL_SPECIAL_RIGHTS_VECTOR)
#define RSBAC_ACL_DEFAULT_NETTEMP_MASK (RSBAC_NETTEMP_REQUEST_VECTOR | RSBAC_ACL_SPECIAL_RIGHTS_VECTOR)
#define RSBAC_ACL_DEFAULT_NETOBJ_MASK (RSBAC_NETOBJ_REQUEST_VECTOR | RSBAC_ACL_SPECIAL_RIGHTS_VECTOR)

#define RSBAC_ACL_USER_RIGHTS_VECTOR (RSBAC_USER_REQUEST_VECTOR \
                                      | RSBAC_ACL_RIGHTS_VECTOR(R_DELETE))

#define RSBAC_ACL_GROUP_RIGHTS_VECTOR RSBAC_GROUP_REQUEST_VECTOR

#define RSBAC_ACL_GEN_RIGHTS_VECTOR 0

#define RSBAC_ACL_ACMAN_RIGHTS_VECTOR (\
  ((rsbac_acl_rights_vector_t) 1 << ACLR_FORWARD) | \
  ((rsbac_acl_rights_vector_t) 1 << ACLR_ACCESS_CONTROL) | \
  ((rsbac_acl_rights_vector_t) 1 << ACLR_SUPERVISOR) \
  )

#define RSBAC_ACL_SYSADM_RIGHTS_VECTOR 0

/*
 * System Control Types, including general SCD types
 * (start at 32 to allow future SCD types, max is 63)
 * (should always be same as in RC model)
 */
#define AST_min 32
enum rsbac_acl_scd_type_t{AST_auth_administration = AST_min,
                          AST_none};

/* note: the desc struct must be the same as the beginning of the entry struct! */
struct rsbac_acl_entry_t
  {
    rsbac_acl_int_subject_type_t subj_type;  /* enum rsbac_acl_subject_type_t */
    rsbac_acl_subject_id_t       subj_id;
    rsbac_acl_rights_vector_t    rights;
  };

struct rsbac_acl_entry_desc_t
  {
    rsbac_acl_int_subject_type_t subj_type;  /* enum rsbac_acl_subject_type_t */
    rsbac_acl_subject_id_t       subj_id;
  };

struct rsbac_acl_old_entry_desc_t
  {
    rsbac_acl_int_subject_type_t subj_type;  /* enum rsbac_acl_subject_type_t */
    rsbac_acl_old_subject_id_t   subj_id;
  };

enum rsbac_acl_group_type_t {ACLG_GLOBAL, ACLG_PRIVATE, ACLG_NONE};

typedef __u32 rsbac_acl_group_id_t;

#define RSBAC_ACL_GROUP_NAMELEN 16

#define RSBAC_ACL_GROUP_VERSION 2

struct rsbac_acl_group_entry_t
  {
         rsbac_acl_group_id_t   id;
         rsbac_uid_t            owner;
    enum rsbac_acl_group_type_t type;
         char                   name[RSBAC_ACL_GROUP_NAMELEN];
  };

/**** syscalls ****/

enum rsbac_acl_syscall_type_t
  {
    ACLC_set_acl_entry,
    ACLC_remove_acl_entry,
    ACLC_remove_acl,
    ACLC_add_to_acl_entry,
    ACLC_remove_from_acl_entry,
    ACLC_set_mask,
    ACLC_remove_user,
    ACLC_none
  };

struct rsbac_acl_syscall_arg_t
  {
    enum   rsbac_target_t              target;
    union  rsbac_target_id_t           tid;
    enum   rsbac_acl_subject_type_t    subj_type;
           rsbac_acl_subject_id_t      subj_id;
           rsbac_acl_rights_vector_t   rights;
           rsbac_time_t                ttl;
  };

struct rsbac_acl_syscall_n_arg_t
  {
    enum   rsbac_target_t              target;
           char                      * name;
    enum   rsbac_acl_subject_type_t    subj_type;
           rsbac_acl_subject_id_t      subj_id;
           rsbac_acl_rights_vector_t   rights;
           rsbac_time_t                ttl;
  };


enum rsbac_acl_group_syscall_type_t
  {
    ACLGS_add_group,
    ACLGS_change_group,
    ACLGS_remove_group,
    ACLGS_get_group_entry,
    ACLGS_list_groups,
    ACLGS_add_member,
    ACLGS_remove_member,
    ACLGS_get_user_groups,
    ACLGS_get_group_members,
    ACLGS_none
  };

struct rsbac_acl_add_group_arg_t
  {
    enum rsbac_acl_group_type_t type;
    char * name;
    rsbac_acl_group_id_t * group_id_p;
  };

struct rsbac_acl_change_group_arg_t
  {
         rsbac_acl_group_id_t     id;
         rsbac_uid_t              owner;
    enum rsbac_acl_group_type_t   type;
         char                   * name;
  };

struct rsbac_acl_remove_group_arg_t
  {
    rsbac_acl_group_id_t id;
  };

struct rsbac_acl_get_group_entry_arg_t
  {
    rsbac_acl_group_id_t id;
    struct rsbac_acl_group_entry_t * entry_p;
  };

struct rsbac_acl_list_groups_arg_t
  {
    rsbac_boolean_t        include_global;
    struct rsbac_acl_group_entry_t * group_entry_array;
    u_int                  maxnum;
  };

struct rsbac_acl_add_member_arg_t
  {
    rsbac_acl_group_id_t group;
    rsbac_uid_t          user;
    rsbac_time_t ttl;
  };

struct rsbac_acl_remove_member_arg_t
  {
    rsbac_acl_group_id_t group;
    rsbac_uid_t          user;
  };

struct rsbac_acl_get_user_groups_arg_t
  {
    rsbac_uid_t            user;
    rsbac_acl_group_id_t * group_array;
    rsbac_time_t         * ttl_array;
    u_int                  maxnum;
  };

struct rsbac_acl_get_group_members_arg_t
  {
    rsbac_acl_group_id_t   group;
    rsbac_uid_t          * user_array;
    rsbac_time_t         * ttl_array;
    u_int                  maxnum;
  };

union rsbac_acl_group_syscall_arg_t
  {
    struct rsbac_acl_add_group_arg_t         add_group;
    struct rsbac_acl_change_group_arg_t      change_group;
    struct rsbac_acl_remove_group_arg_t      remove_group;
    struct rsbac_acl_get_group_entry_arg_t   get_group_entry;
    struct rsbac_acl_list_groups_arg_t       list_groups;
    struct rsbac_acl_add_member_arg_t        add_member;
    struct rsbac_acl_remove_member_arg_t     remove_member;
    struct rsbac_acl_get_user_groups_arg_t   get_user_groups;
    struct rsbac_acl_get_group_members_arg_t get_group_members;
  };

#endif
