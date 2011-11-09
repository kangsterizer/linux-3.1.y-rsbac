/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2009: Amon Ott */
/* API: Data structures               */
/* and functions for Access           */
/* Control Information / ACL          */
/* Last modified: 15/Oct/2009         */
/************************************ */

#ifndef __RSBAC_ACL_H
#define __RSBAC_ACL_H

#include <linux/init.h>
#include <rsbac/types.h>

/***************************************************/
/*               General Prototypes                */
/***************************************************/

/* All functions return 0, if no error occurred, and a negative error code  */
/* otherwise. The error codes are defined in rsbac_error.h.                 */

/****************************************************************************/
/* Initialization, including ACI restoration for all mounted devices from   */
/* disk. After this call, all ACI is kept in memory for performance reasons,*/
/* but user and file/dir object ACI are written to disk on every change.    */

#ifdef CONFIG_RSBAC_INIT_DELAY
extern int rsbac_init_acl(void);
#else
extern int rsbac_init_acl(void) __init;
#endif

/* mounting and umounting */
int rsbac_mount_acl(kdev_t kdev);
int rsbac_umount_acl(kdev_t kdev);

/* Some information about the current status is also available */
extern int rsbac_stats_acl(void);

/* Status checking */
extern int rsbac_check_acl(int correct);

/************************************************* */
/*               Access functions                  */
/************************************************* */

/* All these procedures handle the spinlocks to protect the targets during */
/* access.                                                                 */

/* rsbac_acl_set_acl_entry
 * Set ACL entry for given target and subject to given rights. If entry does
 * not exist, it is created, thus cutting the inheritance from default/parent.
 */

int rsbac_acl_set_acl_entry(rsbac_list_ta_number_t ta_number,
			    enum rsbac_target_t target,
			    union rsbac_target_id_t tid,
			    enum rsbac_acl_subject_type_t subj_type,
			    rsbac_acl_subject_id_t subj_id,
			    rsbac_acl_rights_vector_t rights,
			    rsbac_time_t ttl);

/* rsbac_acl_remove_acl_entry
 * Remove ACL entry for given target and subject. This reactivates the
 * inheritance from default/parent.
 */

int rsbac_acl_remove_acl_entry(rsbac_list_ta_number_t ta_number,
			       enum rsbac_target_t target,
			       union rsbac_target_id_t tid,
			       enum rsbac_acl_subject_type_t subj_type,
			       rsbac_acl_subject_id_t subj_id);

/* rsbac_acl_remove_acl
 * Remove ACL for given target. For cleanup on delete.
 */

int rsbac_acl_remove_acl(rsbac_list_ta_number_t ta_number,
			 enum rsbac_target_t target,
			 union rsbac_target_id_t tid);

/* rsbac_acl_add_to_acl_entry
 * Add given rights to ACL entry for given target and subject. If entry does
 * not exist, behaviour is exactly like rsbac_acl_set_acl_entry.
 */

int rsbac_acl_add_to_acl_entry(rsbac_list_ta_number_t ta_number,
			       enum rsbac_target_t target,
			       union rsbac_target_id_t tid,
			       enum rsbac_acl_subject_type_t subj_type,
			       rsbac_acl_subject_id_t subj_id,
			       rsbac_acl_rights_vector_t rights,
			       rsbac_time_t ttl);

/* rsbac_acl_remove_from_acl_entry
 * Remove given rights from ACL entry for given target and subject. If entry does
 * not exist, nothing happens.
 * This function does NOT remove the ACL entry, so removing all rights results in
 * NO rights for this subject/target combination!
 */

int rsbac_acl_remove_from_acl_entry(rsbac_list_ta_number_t ta_number,
				    enum rsbac_target_t target,
				    union rsbac_target_id_t tid,
				    enum rsbac_acl_subject_type_t
				    subj_type,
				    rsbac_acl_subject_id_t subj_id,
				    rsbac_acl_rights_vector_t rights);

/* rsbac_acl_set_mask
 * Set inheritance mask for given target to given rights. If item does
 * not exist, it is created.
 */

int rsbac_acl_set_mask(rsbac_list_ta_number_t ta_number,
		       enum rsbac_target_t target,
		       union rsbac_target_id_t tid,
		       rsbac_acl_rights_vector_t mask);

/* rsbac_acl_get_mask
 * Get inheritance mask for given target to given rights. If item does
 * not exist, default mask is returned.
 */

int rsbac_acl_get_mask(rsbac_list_ta_number_t ta_number,
		       enum rsbac_target_t target,
		       union rsbac_target_id_t tid,
		       rsbac_acl_rights_vector_t * mask_p);

/* rsbac_acl_get_rights
 * Get effective rights from ACL entry for given target and subject.
 * If entry does not exist, inherited rights are used. If there is no parent,
 * the default rights vector for this target type is returned.
 * This function does NOT add role or group rights to user rights!
 */

int rsbac_acl_get_rights(rsbac_list_ta_number_t ta_number,
			 enum rsbac_target_t target,
			 union rsbac_target_id_t tid,
			 enum rsbac_acl_subject_type_t subj_type,
			 rsbac_acl_subject_id_t subj_id,
			 rsbac_acl_rights_vector_t * rights_p,
			 rsbac_boolean_t inherit);

/* rsbac_acl_get_single_right
 * Show, whether a right is set for given target and subject.
 * If right is not set, it is checked at all parents, unless it has been
 * masked out *or* it is SUPERVISOR, CONFIG_RSBAC_ACL_SUPER_FILTER is set
 * and supervisor is masked out.
 */

int rsbac_acl_get_single_right(enum rsbac_target_t target,
			       union rsbac_target_id_t tid,
			       enum rsbac_acl_subject_type_t subj_type,
			       rsbac_acl_subject_id_t subj_id,
			       enum rsbac_adf_request_t right,
			       rsbac_boolean_t * result);


/************************************************************************** */
/* The rsbac_acl_copy_fd_acl() function copies a file/dir ACL to another    */
/* file/dir ACL. The old ACL of fd2 is erased before copying.               */

int rsbac_acl_copy_fd_acl(struct rsbac_fs_file_t file1,
			  struct rsbac_fs_file_t file2);

/************************************************************************** */
/* The rsbac_acl_copy_pp_acl() function copies a process acl to another     */

int rsbac_acl_copy_pp_acl(rsbac_pid_t old_pid, rsbac_pid_t new_pid);

/*************************************************
 * rsbac_acl_get_tlist
 * Get subjects from ACL entries for given target.
 */

int rsbac_acl_get_tlist(rsbac_list_ta_number_t ta_number,
			enum rsbac_target_t target,
			union rsbac_target_id_t tid,
			struct rsbac_acl_entry_t **entry_pp,
			rsbac_time_t ** ttl_pp);

/*************************************************
 * Group management
 */

/* add a group with new id and fill this id into *group_id_p */
int rsbac_acl_add_group(rsbac_list_ta_number_t ta_number,
			rsbac_uid_t owner,
			enum rsbac_acl_group_type_t type,
			char *name, rsbac_acl_group_id_t * group_id_p);

int rsbac_acl_change_group(rsbac_list_ta_number_t ta_number,
			   rsbac_acl_group_id_t id,
			   rsbac_uid_t owner,
			   enum rsbac_acl_group_type_t type, char *name);

int rsbac_acl_remove_group(rsbac_list_ta_number_t ta_number,
			   rsbac_acl_group_id_t id);

int rsbac_acl_get_group_entry(rsbac_list_ta_number_t ta_number,
			      rsbac_acl_group_id_t group,
			      struct rsbac_acl_group_entry_t *entry_p);

int rsbac_acl_list_groups(rsbac_list_ta_number_t ta_number,
			  rsbac_uid_t owner,
			  rsbac_boolean_t include_global,
			  struct rsbac_acl_group_entry_t **entry_pp);

/* check group existence */
rsbac_boolean_t rsbac_acl_group_exist(rsbac_acl_group_id_t group);

int rsbac_acl_add_group_member(rsbac_list_ta_number_t ta_number,
			       rsbac_acl_group_id_t group,
			       rsbac_uid_t user, rsbac_time_t ttl);

int rsbac_acl_remove_group_member(rsbac_list_ta_number_t ta_number,
				  rsbac_acl_group_id_t group,
				  rsbac_uid_t user);

/* check membership */
rsbac_boolean_t rsbac_acl_group_member(rsbac_acl_group_id_t group,
				       rsbac_uid_t user);

/* build rsbac_kmalloc'd array of all group memberships of the given user */
/* returns number of groups or negative error */
/* Attention: memory deallocation with rsbac_kfree must be done by caller! */
int rsbac_acl_get_user_groups(rsbac_list_ta_number_t ta_number,
			      rsbac_uid_t user,
			      rsbac_acl_group_id_t ** group_pp,
			      rsbac_time_t ** ttl_pp);

/* Returns number of members or negative error */
int rsbac_acl_get_group_members(rsbac_list_ta_number_t ta_number,
				rsbac_acl_group_id_t group,
				rsbac_uid_t user_array[],
				rsbac_time_t ttl_array[], int maxnum);

/* Remove subject from all ACLs */
int rsbac_acl_remove_subject(rsbac_list_ta_number_t ta_number,
			     struct rsbac_acl_entry_desc_t desc);

/*************************************************/
/* remove user from all groups and from all ACLs */
int rsbac_acl_remove_user(rsbac_list_ta_number_t ta_number,
			  rsbac_uid_t user);

/* Get list of all device entries */

int rsbac_acl_list_all_dev(rsbac_list_ta_number_t ta_number,
			   struct rsbac_dev_desc_t **id_pp);

int rsbac_acl_list_all_major_dev(rsbac_list_ta_number_t ta_number,
				 struct rsbac_dev_desc_t **id_pp);

int rsbac_acl_list_all_user(rsbac_list_ta_number_t ta_number,
			    rsbac_uid_t ** id_pp);

int rsbac_acl_list_all_group(rsbac_list_ta_number_t ta_number,
			     rsbac_gid_t ** id_pp);

int rsbac_acl_list_all_ipc(rsbac_list_ta_number_t ta_number,
			   struct rsbac_ipc_t ** id_pp);

#endif
