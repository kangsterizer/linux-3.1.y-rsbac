/************************************ */
/* Rule Set Based Access Control      */
/* Author and (c) 1999-2005: Amon Ott */
/* API: for REG                       */
/*      Module Registration           */
/* Last modified: 09/Feb/2005         */
/************************************ */

#ifndef __RSBAC_REG_H
#define __RSBAC_REG_H

#include <rsbac/types.h>
#include <rsbac/debug.h>

#define RSBAC_REG_VERSION 1

/***************************************************/
/*                   Types                         */
/***************************************************/

#define RSBAC_REG_NAME_LEN 30

/* Decision function */
typedef \
  int rsbac_reg_request_func_t     ( enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

/* Attribute setting / notification function */
typedef \
  int rsbac_reg_set_attr_func_t    ( enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t,
                                           rsbac_uid_t); /* process owner */

/* Whether module wants this file to be overwritten on delete / truncate */
typedef rsbac_boolean_t rsbac_reg_need_overwrite_func_t(struct dentry * dentry_p);

/*
 * rsbac_reg_write_func_t
 *
 * Called by rsbac_write function to save all dirty lists, must return number
 * of files written or negative error. If auto_write is active, this function
 * will be called regularly and allows for asynchronous data writing to disk.
 *
 * If need_lock is TRUE, a lock_kernel() / unlock_kernel() pair must be used
 * around the write function.
 */
typedef int rsbac_reg_write_func_t(rsbac_boolean_t need_lock);

/* Called on every mount, allows updating of fs based data */
typedef int rsbac_reg_mount_func_t(kdev_t kdev);

/* Called on every umount, allows updating of fs based data */
typedef int rsbac_reg_umount_func_t(kdev_t kdev);

/* Called on rsbac_reg syscalls for handle syscall_handle */
/* Generic Syscall interface - note: data is a user space pointer! */
typedef int rsbac_reg_syscall_func_t(void * data);

/* Status and data structures integrity checking, called from sys_rsbac_check */
/* correct: if TRUE, errors are corrected, else just report */
/* check_inode: for inode number based data, check, if inode still exists */
typedef int rsbac_reg_check_func_t(int correct, int check_inode);

/*********/

struct rsbac_reg_entry_t
  {
    rsbac_reg_handle_t                handle;
    char                              name[RSBAC_REG_NAME_LEN+1];
    rsbac_reg_request_func_t        * request_func;
    rsbac_reg_set_attr_func_t       * set_attr_func;
    rsbac_reg_need_overwrite_func_t * need_overwrite_func;
    rsbac_reg_write_func_t          * write_func;
    rsbac_reg_mount_func_t          * mount_func;
    rsbac_reg_umount_func_t         * umount_func;
    rsbac_reg_check_func_t          * check_func;
    rsbac_boolean_t                           switch_on; /* turned on initially? */
  };

struct rsbac_reg_syscall_entry_t
  {
    rsbac_reg_handle_t                registration_handle;
    rsbac_reg_handle_t                dispatcher_handle;
    char                              name[RSBAC_REG_NAME_LEN+1];
    rsbac_reg_syscall_func_t        * syscall_func;
  };

/***************************************************/
/*                   Prototypes                    */
/***************************************************/

/* See rsbac/types.h for types */

/*
 * Register an ADF decision module
 * Returns given positive handle or negative error code from rsbac/error.h
 * Errors: -RSBAC_EINVALIDVALUE    (all functions are empty or handle is not positive)
 *         -RSBAC_EEXISTS          (handle exists - choose another one)
 *         -RSBAC_ECOULDNOTADDITEM (no entry available)
 *         -RSBAC_EINVALIDVERSION  (wrong REG version)
 */

rsbac_reg_handle_t rsbac_reg_register(        rsbac_version_t    version,
                                       struct rsbac_reg_entry_t  entry);

/*
 * Switch module on or off - for 'normal' modules this is done by general
 * function. This is a dummy, if module switching is disabled.
 * Returns 0 on success or -EINVALIDTARGET, if handle is invalid.
 */

int rsbac_reg_switch (rsbac_reg_handle_t handle, rsbac_boolean_t value);

/*
 * Unregister an ADF decision module
 * Returns 0 on success or -EINVALIDTARGET, if handle is invalid.
 */

int rsbac_reg_unregister(rsbac_reg_handle_t handle);


/*
 * Register a system call
 * Returns given positive handle or negative error code from rsbac/error.h
 * Errors: -RSBAC_EINVALIDVALUE    (function is empty or handle is not positive)
 *         -RSBAC_EEXISTS          (handle exists - choose another one)
 *         -RSBAC_ECOULDNOTADDITEM (no entry available)
 *         -RSBAC_EINVALIDVERSION  (wrong REG version)
 */

rsbac_reg_handle_t rsbac_reg_register_syscall(       rsbac_version_t            version,
                                              struct rsbac_reg_syscall_entry_t  entry);

/*
 * Unregister a system call
 * Returns 0 on success or -EINVALIDTARGET, if handle is invalid.
 */

int rsbac_reg_unregister_syscall(rsbac_reg_handle_t handle);

#endif
