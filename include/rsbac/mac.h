/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2005:          */
/*   Amon Ott <ao@rsbac.org>          */
/* API: Data structures               */
/* and functions for Access           */
/* Control Information / MAC          */
/* Last modified: 09/Feb/2005         */
/************************************ */

#ifndef __RSBAC_MAC_H
#define __RSBAC_MAC_H

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
extern int rsbac_init_mac(void);
#else
extern int rsbac_init_mac(void) __init;
#endif

/* mounting and umounting */
int rsbac_mount_mac(kdev_t kdev);
int rsbac_umount_mac(kdev_t kdev);

/* Some information about the current status is also available */
extern int rsbac_stats_mac(void);

/* Status checking */
extern int rsbac_check_mac(int correct, int check_inode);

/* RSBAC attribute saving to disk can be triggered from outside
 * param: call lock_kernel() before writing?
 */
#if defined(CONFIG_RSBAC_MAINT) || defined(CONFIG_RSBAC_AUTO_WRITE)
extern int rsbac_write_mac(rsbac_boolean_t);
#endif /* CONFIG_RSBAC_AUTO_WRITE */

/************************************************* */
/*               Access functions                  */
/************************************************* */

/* All these procedures handle the semaphores to protect the targets during */
/* access.                                                                  */
/* Trying to access a never created or removed set returns an error!        */

/* rsbac_mac_add_to_truset */
/* Add a set member to a set sublist. Set behaviour: also returns success, */
/* if member was already in set! */

int rsbac_mac_add_to_p_truset(
  rsbac_list_ta_number_t ta_number,
  rsbac_pid_t pid,
  rsbac_uid_t member,
  rsbac_time_t ttl);

int rsbac_mac_add_to_f_truset(
  rsbac_list_ta_number_t ta_number,
  rsbac_mac_file_t file,
  rsbac_uid_t member,
  rsbac_time_t ttl);

/* rsbac_mac_remove_from_truset */
/* Remove a set member from a sublist. Set behaviour: Returns no error, if */
/* member is not in list.                                                  */

int rsbac_mac_remove_from_p_truset(
  rsbac_list_ta_number_t ta_number,
  rsbac_pid_t pid,
  rsbac_uid_t member);

int rsbac_mac_remove_from_f_truset(
  rsbac_list_ta_number_t ta_number,
  rsbac_mac_file_t file,
  rsbac_uid_t member);

/* rsbac_mac_clear_truset */
/* Remove all set members from a sublist. Set behaviour: Returns no error, */
/* if list is empty.                                                       */

int rsbac_mac_clear_p_truset(
  rsbac_list_ta_number_t ta_number,
  rsbac_pid_t pid);

int rsbac_mac_clear_f_truset(
  rsbac_list_ta_number_t ta_number,
  rsbac_mac_file_t file);

/* rsbac_mac_truset_member */
/* Return truth value, whether member is in set */

rsbac_boolean_t  rsbac_mac_p_truset_member(rsbac_pid_t pid,
                                   rsbac_uid_t member);

/* rsbac_mac_remove_truset */
/* Remove a full set. For cleanup, if object is deleted. */
/* To empty an existing set use rsbac_mac_clear_truset. */

int rsbac_mac_remove_p_trusets(rsbac_pid_t pid);

int rsbac_mac_remove_f_trusets(rsbac_mac_file_t file);

int rsbac_mac_copy_fp_truset(rsbac_mac_file_t    file,
                              rsbac_pid_t p_tru_set_id);

int rsbac_mac_copy_pp_truset(rsbac_pid_t old_p_set_id,
                              rsbac_pid_t new_p_set_id);

int rsbac_mac_get_f_trulist(
  rsbac_list_ta_number_t ta_number,
  rsbac_mac_file_t file,
  rsbac_uid_t **trulist_p,
  rsbac_time_t **ttllist_p);

int rsbac_mac_get_p_trulist(
  rsbac_list_ta_number_t ta_number,
  rsbac_pid_t pid,
  rsbac_uid_t **trulist_p,
  rsbac_time_t **ttllist_p);

#endif
