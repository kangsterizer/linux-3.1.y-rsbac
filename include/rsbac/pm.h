/******************************* */
/* Rule Set Based Access Control */
/* Author and (c) 1999-2005:     */
/*   Amon Ott <ao@rsbac.org>     */
/* API: Data structures          */
/* and functions for Access      */
/* Control Information / PM      */
/* Last modified: 09/Feb/2005    */
/******************************* */

#ifndef __RSBAC_PM_H
#define __RSBAC_PM_H

#include <linux/init.h>
#include <rsbac/pm_types.h>

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
extern int rsbac_init_pm(void);
#else
extern int rsbac_init_pm(void) __init;
#endif

/* Some information about the current status is also available              */

extern int rsbac_stats_pm(void);

/* RSBAC attribute saving to disk can be triggered from outside
 * param: call lock_kernel() before writing?
 */

#ifdef CONFIG_RSBAC_AUTO_WRITE
extern int rsbac_write_pm(rsbac_boolean_t);
#endif /* CONFIG_RSBAC_AUTO_WRITE */

/************************************************* */
/*               Access functions                  */
/************************************************* */

/***********************/
/* Helper lists / sets */
/***********************/

/* All these procedures handle the semaphores to protect the targets during */
/* access.                                                                  */
/* Trying to access a never created or removed set returns an error!        */

/* rsbac_pm_add_to_set */
/* Add a set member to a set sublist. Set behaviour: also returns success,  */
/* if member was already in set! */

int rsbac_pm_add_to_set(
        rsbac_list_ta_number_t,
  enum  rsbac_pm_set_t,          /* set type          */
  union rsbac_pm_set_id_t,       /* set id            */
  union rsbac_pm_set_member_t);  /* set member to add */


/* rsbac_pm_remove_from_set */
/* Remove a set member from a sublist. Set behaviour: Returns no error, if */
/* member is not in list.                                                  */

int rsbac_pm_remove_from_set(
        rsbac_list_ta_number_t,
  enum  rsbac_pm_set_t,          /* see above */
  union rsbac_pm_set_id_t,
  union rsbac_pm_set_member_t);


/* rsbac_pm_clear_set */
/* Remove all members from a set. Set behaviour: Returns no error, */
/* if list is empty.                                               */

int rsbac_pm_clear_set(
        rsbac_list_ta_number_t,
  enum  rsbac_pm_set_t,          /* set type     */
  union rsbac_pm_set_id_t);      /* set id       */


/* rsbac_pm_set_member */
/* Return truth value, whether member is in set */

rsbac_boolean_t rsbac_pm_set_member(
        rsbac_list_ta_number_t,
  enum  rsbac_pm_set_t,          /* set type */
  union rsbac_pm_set_id_t,       /* set id   */
  union rsbac_pm_set_member_t);  /* member   */


/* rsbac_pm_pp_subset */
/* Return truth value, whether pp_set is subset of in_pp_set */

rsbac_boolean_t rsbac_pm_pp_subset(
  rsbac_pm_pp_set_id_t,
  rsbac_pm_in_pp_set_id_t);


/* rsbac_pm_pp_superset */
/* Return truth value, whether pp_set is superset of out_pp_set */

rsbac_boolean_t rsbac_pm_pp_superset(
  rsbac_pm_pp_set_id_t,
  rsbac_pm_out_pp_set_id_t);


/* rsbac_pm_pp_only */
/* Return truth value, if there is not other item in out_pp_set than purpose */

rsbac_boolean_t rsbac_pm_pp_only(
  rsbac_pm_purpose_id_t,
  rsbac_pm_out_pp_set_id_t);


/* rsbac_pm_pp_intersec */
/* Create intersection of pp_set and in_pp_set in in_pp_set */
/* If in_pp_set does not exist, it is created with all members of pp_set */
/* If pp_set does not exist or one of them is invalid, an error is returned */

int rsbac_pm_pp_intersec (rsbac_pm_pp_set_id_t,
                          rsbac_pm_in_pp_set_id_t);


/* rsbac_pm_pp_union */
/* Create union of pp_set and out_pp_set in out_pp_set */
/* If out_pp_set does not exist, it is created with all members of pp_set */
/* If pp_set does not exist or one of them is invalid, an error is returned */

int rsbac_pm_pp_union (rsbac_pm_pp_set_id_t,
                       rsbac_pm_out_pp_set_id_t);


/* rsbac_pm_create_set */
/* Create a new set of given type, using id id. Using any other set     */
/* function for a set id without creating this set returns an error.    */
/* To empty an existing set use rsbac_pm_clear_set.                     */

int rsbac_pm_create_set(
  rsbac_list_ta_number_t,
  enum  rsbac_pm_set_t,          /* set type */
  union rsbac_pm_set_id_t);      /* set id   */


/* rsbac_pm_set_exist */
/* Return truth value whether set exists, returns FALSE for invalid */
/* values. */

rsbac_boolean_t rsbac_pm_set_exist(
        rsbac_list_ta_number_t,
  enum  rsbac_pm_set_t,          /* set type */
  union rsbac_pm_set_id_t);      /* set id   */


/* rsbac_pm_remove_set */
/* Remove a full set. After this call the given id can only be used for */
/* creating a new set, anything else returns an error.                  */
/* To empty an existing set use rsbac_pm_clear_set.                     */

int rsbac_pm_remove_set(
        rsbac_list_ta_number_t,
  enum  rsbac_pm_set_t,          /* set type */
  union rsbac_pm_set_id_t);      /* set id   */


/**************/
/* Main lists */
/**************/

/* rsbac_pm_get_data() and rsbac_pm_set_data() change single data values.   */
/* rsbac_pm_add_target() adds a new list item and sets all data values as   */
/* given. rsbac_pm_remove_target() removes an item.                         */

/* A rsbac_pm_[sg]et_data() call for a non-existing target will return an   */
/* error.*/
/* Invalid parameter combinations return an error.                          */

/* All these procedures handle the semaphores to protect the targets during */
/* access.                                                                  */

int rsbac_pm_get_data(
        rsbac_list_ta_number_t,
  enum  rsbac_pm_target_t,          /* list type */
  union rsbac_pm_target_id_t,      /* item id in list */
  enum  rsbac_pm_data_t,            /* data item */
  union rsbac_pm_data_value_t *);  /* for return value */


int rsbac_pm_get_all_data(
        rsbac_list_ta_number_t,
  enum  rsbac_pm_target_t,          /* list type */
  union rsbac_pm_target_id_t,      /* item id in list */
  union rsbac_pm_all_data_value_t *);  /* for return value */


rsbac_boolean_t rsbac_pm_exists(
        rsbac_list_ta_number_t,
  enum  rsbac_pm_target_t,          /* list type */
  union rsbac_pm_target_id_t);     /* item id in list */


int rsbac_pm_set_data(
        rsbac_list_ta_number_t,
  enum  rsbac_pm_target_t,          /* list type */
  union rsbac_pm_target_id_t,      /* item id in list */
  enum  rsbac_pm_data_t,            /* data item */
  union rsbac_pm_data_value_t);    /* data value */


int rsbac_pm_add_target(
        rsbac_list_ta_number_t,
  enum  rsbac_pm_target_t,            /* list type */
  union rsbac_pm_all_data_value_t);  /* values for all */
                                     /* data items,    */
                                     /* incl. item id  */


int rsbac_pm_remove_target(
        rsbac_list_ta_number_t,
  enum  rsbac_pm_target_t,        /* list type */
  union rsbac_pm_target_id_t);   /* item id in list */

#endif
