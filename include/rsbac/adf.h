/******************************* */
/* Rule Set Based Access Control */
/* Author and (c) 1999-2009:     */
/*   Amon Ott <ao@rsbac.org>     */
/* API: for Access Control       */
/* Decision Facility             */
/* Last modified: 16/Jan/2009    */
/******************************* */

#ifndef __RSBAC_ADF_H
#define __RSBAC_ADF_H

#include <linux/init.h>
#include <linux/binfmts.h>
#include <asm/page.h>
#include <rsbac/types.h>
#include <rsbac/debug.h>
#include <rsbac/fs.h>

/***************************************************/
/*                   Prototypes                    */
/***************************************************/

/* Init function */
#ifdef CONFIG_RSBAC_INIT_DELAY
extern  void rsbac_init_adf(void);
#else
extern  void rsbac_init_adf(void) __init;
#endif

/* This function is the internal decision function, called from the next. */
/* It allows to ignore a certain module (last parameter), e.g. for asking */
/* all _other_ modules, but not the calling module, to avoid a circle.    */

extern enum rsbac_adf_req_ret_t
   rsbac_adf_request_int(enum  rsbac_adf_request_t     request,
                               rsbac_pid_t             caller_pid,
                         enum  rsbac_target_t          target,
                         union rsbac_target_id_t     * tid_p,
                         enum  rsbac_attribute_t       attr,
                         union rsbac_attribute_value_t * attr_val_p,
                         enum  rsbac_switch_target_t   ignore_module);

/*********************************************************************/
/* rsbac_adf_request()                                               */
/* This function is the main decision function, called from the AEF. */
/* It is a simple wrapper to the internal function, setting          */
/* ignore_module to SW_NONE.                                         */

static inline enum rsbac_adf_req_ret_t
   rsbac_adf_request( enum  rsbac_adf_request_t     request,
                            rsbac_pid_t             caller_pid,
                      enum  rsbac_target_t          target,
                      union rsbac_target_id_t       tid,
                      enum  rsbac_attribute_t       attr,
                      union rsbac_attribute_value_t attr_val)
  {
    return rsbac_adf_request_int(request,
                                 caller_pid,
                                 target,
                                 &tid,
                                 attr,
                                 &attr_val,
                                 SW_NONE);
  }


/* If the request returned granted and the operation is performed,           */
/* the following function is called by the AEF to get all aci set correctly. */
/* The second instance of target specification is the new target, if one has */
/* been created, otherwise its values are ignored.                           */
/* It returns 0 on success and an error from error.h otherwise.              */

extern  int  rsbac_adf_set_attr(     enum  rsbac_adf_request_t,
                                           rsbac_pid_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_target_t,
                                     union rsbac_target_id_t,
                                     enum  rsbac_attribute_t,
                                     union rsbac_attribute_value_t);

#include <linux/types.h>
#include <linux/dcache.h>

int rsbac_sec_del(struct dentry * dentry_p, u_int may_sync);

int rsbac_sec_trunc(struct dentry * dentry_p,
                    loff_t new_len, loff_t old_len);

/* This function changes the symlink content by adding a suffix, if
 * requested. It returns NULL, if unchanged, or a pointer to a
 * kmalloc'd new char * otherwise, which has to be kfree'd after use.
 */
char * rsbac_symlink_redirect(
  struct inode * inode_p,
  const char * name,
  u_int maxlen);

#ifdef CONFIG_RSBAC_ALLOW_DAC_DISABLE_PART
extern int rsbac_dac_part_disabled(struct dentry * dentry_p);
#endif

#ifdef CONFIG_RSBAC_FAKE_ROOT_UID
extern rsbac_uid_t rsbac_fake_uid(void);
extern rsbac_uid_t rsbac_fake_euid(void);
extern int rsbac_uid_faked(void);
#endif

int rsbac_cap_check_envp(struct linux_binprm *bprm);

extern int rsbac_handle_filldir(const struct file *file, const char *name, const unsigned int namlen, const ino_t ino);

int rsbac_set_audit_uid(rsbac_uid_t uid);

/* Mostly copied from drivers/char/mem.c */
static inline rsbac_boolean_t rsbac_is_videomem(unsigned long pfn, unsigned long size)
{
/* Intel architecture is a security disaster */
#if defined X86_64 || defined X86

	u64 from = ((u64)pfn) << PAGE_SHIFT;
	u64 to = from + size;
	u64 cursor = from;

	while (cursor < to) {
		if (!devmem_is_allowed(pfn)) {
			return FALSE;
		}
		cursor += PAGE_SIZE;
		pfn++;
	}
	return TRUE;
#endif
	return TRUE;
};

#endif
