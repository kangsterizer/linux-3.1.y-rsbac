/******************************* */
/* Rule Set Based Access Control */
/* Author and (c) 1999-2008:     */
/*   Amon Ott <ao@rsbac.org>     */
/* API: Data structures          */
/* and functions for Access      */
/* Control Information           */
/* Last modified: 23/Sep/2008    */
/******************************* */

#ifndef __RSBAC_ACI_H
#define __RSBAC_ACI_H

#include <rsbac/types.h>
#include <linux/init.h>

/***************************************************/
/*                   Prototypes                    */
/***************************************************/

/* All functions return 0, if no error occurred, and a negative error code  */
/* otherwise. The error codes are defined in rsbac_error.h.                 */

/****************************************************************************/
/* Initialization, including ACI restoration for all mounted devices from   */
/* disk. After this call, all ACI is kept in memory for performance reasons,*/
/* but user and file/dir object ACI are written to disk on every change.    */

#ifdef CONFIG_RSBAC_INIT_DELAY
extern int rsbac_init(kdev_t root_dev);
#else
extern int rsbac_init(kdev_t root_dev) __init;
#endif

/* Notify RSBAC of new kernel thread */
int rsbac_kthread_notify(rsbac_pid_t pid);

/* To turn RSBAC off on umount of root device */
extern void rsbac_off(void);

/* For other kernel parts to check, whether RSBAC was initialized correctly */
extern rsbac_boolean_t rsbac_initialized;

static inline rsbac_boolean_t rsbac_is_initialized(void)
{
  return rsbac_initialized;
}

/* Check if the device exists */
int rsbac_check_device(kdev_t kdev);

/* Is device writable? */
rsbac_boolean_t rsbac_writable(struct super_block * sb_p);

/* When mounting a device, its ACI must be read and added to the ACI lists. */
extern int rsbac_mount(struct vfsmount * mnt_p);

/* When umounting a device, its ACI must be removed from the ACI lists. */
extern int rsbac_umount(struct vfsmount * mnt_p);

/* On pivot_root, we must unblock the dentry tree of the old root */
/* by putting all cached rsbac.dat dentries */
int rsbac_free_dat_dentries(void);

/* Some information about the current status is also available */
extern int rsbac_stats(void);

/* Trigger internal consistency check (int: if != 0: correct errors) */
extern int rsbac_check(int correct, int check_inode);

/* RSBAC attribute saving to disk can be triggered from outside
 * param: call lock_kernel() before disk access?
 */
#if defined(CONFIG_RSBAC_MAINT) || defined(CONFIG_RSBAC_AUTO_WRITE)
extern int rsbac_write(void);
#endif

/* get the parent of a target
 * returns -RSBAC_EINVALIDTARGET for non-fs targets
 * and -RSBAC_ENOTFOUND, if no parent available
 * In kernels >= 2.4.0, device_p->d_covers is used and the item is properly
 * locked for reading, so never call with a write lock held on device_p!
 */
int rsbac_get_parent(enum rsbac_target_t target,
                     union rsbac_target_id_t tid,
                     enum rsbac_target_t * parent_target_p,
                     union rsbac_target_id_t * parent_tid_p);

/* Invalidate cached attribute values for one or all filesystem objects */

#ifdef CONFIG_RSBAC_FD_CACHE
int rsbac_fd_cache_invalidate(struct rsbac_fs_file_t * file_p);

int rsbac_fd_cache_invalidate_all(void);
#endif

/****************************************************************************/
/* For objects, users and processes all manipulation is encapsulated by the */
/* function calls rsbac_set_attr, rsbac_get_attr and rsbac_remove_target.   */
                          
int rsbac_ta_get_attr(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_switch_target_t module,
  enum rsbac_target_t target,
  union rsbac_target_id_t tid,
  enum rsbac_attribute_t attr,
  union rsbac_attribute_value_t * value,
  rsbac_boolean_t inherit);

#define rsbac_get_attr(module, target, tid, attr, value, inherit) \
  rsbac_ta_get_attr(0, module, target, tid, attr, value, inherit)

int rsbac_ta_set_attr(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_switch_target_t module,
  enum rsbac_target_t target,
  union rsbac_target_id_t tid,
  enum rsbac_attribute_t attr,
  union rsbac_attribute_value_t value);

#define rsbac_set_attr(module, target, tid, attr, value) \
  rsbac_ta_set_attr(0, module, target, tid, attr, value)

/* All RSBAC targets should be removed, if no longer needed, to prevent     */
/* memory wasting.                                                          */

int rsbac_ta_remove_target(
  rsbac_list_ta_number_t ta_number,
  enum rsbac_target_t target,
  union rsbac_target_id_t tid);

#define rsbac_remove_target(target, tid) \
  rsbac_ta_remove_target(0, target, tid)

int rsbac_ta_list_all_dev(rsbac_list_ta_number_t ta_number,
                          struct rsbac_dev_desc_t ** id_pp);

int rsbac_ta_list_all_user(rsbac_list_ta_number_t ta_number,
                           rsbac_uid_t ** id_pp);

int rsbac_ta_list_all_ipc(rsbac_list_ta_number_t ta_number,
			  struct rsbac_ipc_t ** id_pp);
	
int rsbac_ta_list_all_group(rsbac_list_ta_number_t ta_number,
                            rsbac_gid_t ** id_pp);

int rsbac_mark_kthread(rsbac_pid_t pid);
int rsbac_kthreads_init(void);
#endif
