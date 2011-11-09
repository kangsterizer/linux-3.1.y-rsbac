/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2005:          */
/*   Amon Ott <ao@rsbac.org>          */
/* API: Data structures               */
/* and functions for Access           */
/* Control Information / AUTH         */
/* Last modified: 09/Feb/2005         */
/************************************ */

#ifndef __RSBAC_AUTH_H
#define __RSBAC_AUTH_H

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
extern int rsbac_init_auth(void);
#else
extern int rsbac_init_auth(void) __init;
#endif

/* mounting and umounting */
int rsbac_mount_auth(kdev_t kdev);
int rsbac_umount_auth(kdev_t kdev);

/* Some information about the current status is also available */
extern int rsbac_stats_auth(void);

/* Status checking */
extern int rsbac_check_auth(int correct, int check_inode);

/* RSBAC attribute saving to disk can be triggered from outside
 * param: call lock_kernel() before writing?
 */
#if defined(CONFIG_RSBAC_MAINT) || defined(CONFIG_RSBAC_AUTO_WRITE)
extern int rsbac_write_auth(rsbac_boolean_t);
#endif /* CONFIG_RSBAC_AUTO_WRITE */

/************************************************* */
/*               Access functions                  */
/************************************************* */

/* All these procedures handle the semaphores to protect the targets during */
/* access.                                                                  */
/* Trying to access a never created or removed set returns an error!        */

/* rsbac_auth_add_to_p_capset */
/* Add a set member to a set sublist. Set behaviour: also returns success, */
/* if member was already in set! */

int rsbac_auth_add_to_p_capset(
         rsbac_list_ta_number_t ta_number,
         rsbac_pid_t pid,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range,
         rsbac_time_t ttl);

int rsbac_auth_add_to_f_capset(
         rsbac_list_ta_number_t ta_number,
         rsbac_auth_file_t file,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range,
         rsbac_time_t ttl);

/* rsbac_auth_remove_from_p_capset */
/* Remove a set member from a sublist. Set behaviour: Returns no error, if */
/* member is not in list.                                                  */

int rsbac_auth_remove_from_p_capset(
         rsbac_list_ta_number_t ta_number,
         rsbac_pid_t pid,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range);

int rsbac_auth_remove_from_f_capset(
        rsbac_list_ta_number_t ta_number,
        rsbac_auth_file_t file,
  enum  rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t cap_range);

/* rsbac_auth_clear_p_capset */
/* Remove all set members from a sublist. Set behaviour: Returns no error, */
/* if list is empty.                                                       */

int rsbac_auth_clear_p_capset(
       rsbac_list_ta_number_t ta_number,
       rsbac_pid_t pid,
  enum rsbac_auth_cap_type_t cap_type);

int rsbac_auth_clear_f_capset(
       rsbac_list_ta_number_t ta_number,
       rsbac_auth_file_t file,
  enum rsbac_auth_cap_type_t cap_type);

/* rsbac_auth_p_capset_member */
/* Return truth value, whether member is in set */

rsbac_boolean_t  rsbac_auth_p_capset_member(rsbac_pid_t pid,
                                    enum rsbac_auth_cap_type_t cap_type,
                                    rsbac_uid_t member);

/* rsbac_auth_remove_p_capset */
/* Remove a full set. After this call the given id can only be used for */
/* creating a new set, anything else returns an error.                  */
/* To empty an existing set use rsbac_auth_clear_p_capset.                */

int rsbac_auth_remove_p_capsets(rsbac_pid_t pid);

int rsbac_auth_remove_f_capsets(rsbac_auth_file_t file);

/* rsbac_auth_copy_fp_capset */
/* copy a file capset to a process capset */
int rsbac_auth_copy_fp_capset(rsbac_auth_file_t    file,
                              rsbac_pid_t p_cap_set_id);

/* rsbac_auth_copy_pp_capset */
/* copy a process capset to another process capset */
int rsbac_auth_copy_pp_capset(rsbac_pid_t old_p_set_id,
                              rsbac_pid_t new_p_set_id);

/* rsbac_auth_get_f_caplist */
/* copy a file/dir capset to an array of length 2 * maxnum (first+last), */
/* returns number of caps copied */
int rsbac_auth_get_f_caplist(
         rsbac_list_ta_number_t ta_number,
         rsbac_auth_file_t file,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t **caplist_p,
         rsbac_time_t **ttllist_p);

/* rsbac_auth_get_p_caplist */
/* copy a process capset to an array of length 2 * maxnum (first+last), */
/* returns number of caps copied */
int rsbac_auth_get_p_caplist(
         rsbac_list_ta_number_t ta_number,
         rsbac_pid_t pid,
  enum   rsbac_auth_cap_type_t cap_type,
  struct rsbac_auth_cap_range_t **caplist_p,
         rsbac_time_t **ttllist_p);

#endif
