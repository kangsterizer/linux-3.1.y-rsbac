/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2011:          */
/*   Amon Ott <ao@rsbac.org>          */
/* API: Data structures               */
/* and functions for User Management  */
/* Last modified: 19/Apt/2011         */
/************************************ */

#ifndef __RSBAC_UM_H
#define __RSBAC_UM_H

#include <linux/init.h>
#include <rsbac/types.h>
#include <rsbac/um_types.h>

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
extern int rsbac_init_um(void);
#else
extern int rsbac_init_um(void) __init;
#endif

/* Some information about the current status is also available */
extern int rsbac_stats_um(void);

/************************************************* */
/*               Access functions                  */
/************************************************* */

/* Trying to access a never created or removed user entry returns an error! */

/* rsbac_um_add_user (fills *user_p with new uid) */

int rsbac_um_add_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t * user_p,
  struct rsbac_um_user_entry_t * entry_p,
  char * pass,
  rsbac_time_t ttl);

int rsbac_um_add_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t * group_p,
  struct rsbac_um_group_entry_t * entry_p,
  char * pass,
  rsbac_time_t ttl);

int rsbac_um_add_gm(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t user,
  rsbac_gid_num_t group,
  rsbac_time_t ttl);

int rsbac_um_mod_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t user,
  enum rsbac_um_mod_t mod,
  union rsbac_um_mod_data_t * data_p);

int rsbac_um_mod_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t group,
  enum rsbac_um_mod_t mod,
  union rsbac_um_mod_data_t * data_p);

int rsbac_um_get_user_item(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t user,
  enum rsbac_um_mod_t mod,
  union rsbac_um_mod_data_t * data_p);

int rsbac_um_get_group_item(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t group,
  enum rsbac_um_mod_t mod,
  union rsbac_um_mod_data_t * data_p);

int rsbac_um_user_exists(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t user);

int rsbac_um_group_exists(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t group);

int rsbac_um_remove_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t user);

int rsbac_um_remove_group(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t group);

int rsbac_um_remove_gm(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t user,
  rsbac_gid_num_t group);

int rsbac_um_get_next_user(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t old_user,
  rsbac_uid_t * next_user_p);

int rsbac_um_get_user_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_um_set_t vset,
  rsbac_uid_t ** list_pp);

int rsbac_um_get_gm_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t user,
  rsbac_gid_num_t ** list_pp);

int rsbac_um_get_gm_user_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_gid_t group,
  rsbac_uid_num_t ** list_pp);

int rsbac_um_get_group_list(
  rsbac_list_ta_number_t ta_number,
  rsbac_um_set_t vset,
  rsbac_gid_t ** list_pp);

int rsbac_um_get_user_entry(
  rsbac_list_ta_number_t ta_number,
  rsbac_uid_t user,
  struct rsbac_um_user_entry_t * entry_p,
  rsbac_time_t * ttl_p);

int rsbac_um_get_uid(
  rsbac_list_ta_number_t ta_number,
  char * name,
  rsbac_uid_t * uid_p);

int rsbac_um_get_gid(
  rsbac_list_ta_number_t ta_number,
  char * name,
  rsbac_gid_t * gid_p);

int rsbac_um_check_pass(rsbac_uid_t uid,
                        char * pass);

/* Check for good password (min length etc.) */
int rsbac_um_good_pass(rsbac_uid_t uid, char * pass);

#ifdef CONFIG_RSBAC_UM_ONETIME
int rsbac_um_add_onetime(rsbac_uid_t uid, char * pass, rsbac_time_t ttl);

int rsbac_um_remove_all_onetime(rsbac_uid_t uid);

int rsbac_um_count_onetime(rsbac_uid_t uid);
#endif

int rsbac_um_set_pass(rsbac_uid_t uid,
                      char * pass);

int rsbac_um_set_group_pass(rsbac_gid_t gid,
                            char * pass);

int rsbac_um_check_account(rsbac_uid_t user);

int rsbac_um_get_max_history(rsbac_list_ta_number_t ta_number, rsbac_uid_t uid);

int rsbac_um_set_max_history(rsbac_list_ta_number_t ta_number, rsbac_uid_t uid, __u8 max_history);

#endif
