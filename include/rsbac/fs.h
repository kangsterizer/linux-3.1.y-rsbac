/************************************* */
/* Rule Set Based Access Control       */
/* Author and (c) 1999-2009: Amon Ott  */
/* File system                         */
/* helper functions for all parts      */
/* Last modified: 15/Oct/2009          */
/************************************* */

#ifndef __RSBAC_FS_H
#define __RSBAC_FS_H

#include <linux/fs.h>
#include <linux/major.h>
#include <linux/root_dev.h>
#include <linux/sched.h>

/* original lookup_dentry function without rsbac patch for adf call */

struct dentry * rsbac_lookup_hash(struct qstr *name, struct dentry * base);
struct dentry * rsbac_lookup_one_len(const char * name, struct dentry * base, int len);

#ifndef SOCKFS_MAGIC
#define SOCKFS_MAGIC 0x534F434B
#endif

#ifndef SYSFS_MAGIC
#define SYSFS_MAGIC 0x62656572
#endif

#ifndef OCFS2_SUPER_MAGIC
#define OCFS2_SUPER_MAGIC 0x7461636f
#endif

struct vfsmount * rsbac_get_vfsmount(kdev_t kdev);

extern void __fput(struct file *);

#ifndef SHM_FS_MAGIC
#define SHM_FS_MAGIC 0x02011994
#endif

static inline int init_private_file(struct file *filp, struct dentry *dentry, int mode)
{
	memset(filp, 0, sizeof(*filp));
	filp->f_mode   = mode;
	atomic_long_set(&filp->f_count, 1);
	filp->f_dentry = dentry;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
	filp->f_cred = current_cred();
#else
	filp->f_uid    = current->fsuid;
	filp->f_gid    = current->fsgid;
#endif
	filp->f_op     = dentry->d_inode->i_fop;
	filp->f_mapping     = dentry->d_inode->i_mapping;
	file_ra_state_init(&filp->f_ra, filp->f_mapping);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
/* TODO	file->f_path.mnt = 
 * fil me when switch to full 2.6 (need vfsmount passed over)
 */
#endif
	if (filp->f_op->open)
		return filp->f_op->open(dentry->d_inode, filp);
	else
		return 0;
}

#endif
