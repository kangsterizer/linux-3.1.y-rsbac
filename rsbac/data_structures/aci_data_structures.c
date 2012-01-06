/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of ACI data structures             */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org> */
/* (some smaller parts copied from fs/namei.c        */
/*  and others)                                      */
/*                                                   */
/* Last modified: 17/Oct/2011                        */
/*************************************************** */

#include <linux/types.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/quotaops.h>
#include <linux/proc_fs.h>
#include <linux/msdos_fs.h>
#include <linux/iso_fs.h>
#include <linux/nfs_fs.h>
#include <linux/ext2_fs.h>
#include <linux/kthread.h>
#include <linux/coda.h>
#include <linux/initrd.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/srcu.h>
#include <linux/seq_file.h>
#include <linux/magic.h>
#include <linux/dnotify.h>
#include <linux/fsnotify.h>
#include <linux/mm.h>
#include <linux/blkdev.h>
#include <linux/freezer.h>
#include <net/net_namespace.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/file.h>
#include <linux/spinlock.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/aci_data_structures.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/fs.h>
#include <rsbac/getname.h>
#include <rsbac/net_getname.h>
#include <rsbac/adf.h>
#include <rsbac/adf_main.h>
#include <rsbac/reg.h>
#include <rsbac/rkmem.h>
#include <rsbac/gen_lists.h>
#include <rsbac/jail.h>
#include <linux/string.h>
#include <linux/kdev_t.h>

#define FUSE_SUPER_MAGIC 0x65735546
#define CEPH_SUPER_MAGIC 0x00c36400

#ifdef CONFIG_RSBAC_MAC
#include <rsbac/mac.h>
#endif

#ifdef CONFIG_RSBAC_PM
#include <rsbac/pm.h>
#endif

#ifdef CONFIG_RSBAC_DAZ
#include <rsbac/daz.h>
#endif

#if defined(CONFIG_RSBAC_RC)
#include <rsbac/rc.h>
#endif

#if defined(CONFIG_RSBAC_AUTH)
#include <rsbac/auth.h>
#endif

#if defined(CONFIG_RSBAC_ACL)
#include <rsbac/acl.h>
#endif

#if defined(CONFIG_RSBAC_JAIL)
rsbac_jail_id_t rsbac_jail_syslog_jail_id = 0;
#endif

#if defined(CONFIG_RSBAC_PAX) && (defined(CONFIG_PAX_NOEXEC) || defined(CONFIG_PAX_ASLR))
#include <rsbac/pax.h>
#endif

#ifdef CONFIG_RSBAC_UM
#include <rsbac/um.h>
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
#include <linux/unistd.h>
#include <linux/timer.h>
static u_int auto_interval = CONFIG_RSBAC_AUTO_WRITE * HZ;
#endif				/* CONFIG_RSBAC_AUTO_WRITE */

#if  (defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)) \
   || defined(CONFIG_RSBAC_INIT_THREAD)
static DECLARE_WAIT_QUEUE_HEAD(rsbacd_wait);
static struct timer_list rsbac_timer;
#endif

#if defined(CONFIG_RSBAC_NET_OBJ)
#include <rsbac/network.h>
#endif

/************************************************************************** */
/*                          Global Variables                                */
/************************************************************************** */

/* The following global variables are needed for access to ACI data.        */

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_initialized);
#endif
rsbac_boolean_t rsbac_initialized = FALSE;

static rsbac_boolean_t rsbac_allow_mounts = FALSE;

static char compiled_modules[80];

kdev_t rsbac_root_dev;
#ifdef CONFIG_RSBAC_INIT_DELAY
struct vfsmount * rsbac_root_mnt_p = NULL;
#endif
#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_root_dev);
#endif
DEFINE_SEMAPHORE(rsbac_write_sem);

static struct rsbac_device_list_head_t * device_head_p[RSBAC_NR_DEVICE_LISTS];
static spinlock_t device_list_locks[RSBAC_NR_DEVICE_LISTS];
static struct srcu_struct device_list_srcu[RSBAC_NR_DEVICE_LISTS];
static struct lock_class_key device_list_lock_class;

#ifdef CONFIG_RSBAC_FD_CACHE
static rsbac_list_handle_t fd_cache_handle[SW_NONE];
#ifdef CONFIG_RSBAC_XSTATS
static __u64 fd_cache_hits[SW_NONE];
static __u64 fd_cache_misses[SW_NONE];
static u_int fd_cache_invalidates;
static u_int fd_cache_invalidate_alls;
__u64 syscall_count[RSYS_none];
#endif
#endif

#ifdef CONFIG_RSBAC_XSTATS
__u64 syscall_count[RSYS_none];
#endif

static struct rsbac_dev_handles_t dev_handles;
static struct rsbac_dev_handles_t dev_major_handles;
static struct rsbac_ipc_handles_t ipc_handles;
static struct rsbac_user_handles_t user_handles;
#ifdef CONFIG_RSBAC_RC_UM_PROT
static struct rsbac_group_handles_t group_handles;
#endif
static struct rsbac_process_handles_t process_handles;

#ifdef CONFIG_RSBAC_NET_DEV
static struct rsbac_netdev_handles_t netdev_handles;
#endif
#ifdef CONFIG_RSBAC_NET_OBJ
static rsbac_list_handle_t net_temp_handle;
static struct rsbac_nettemp_handles_t nettemp_handles;
#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_PM) || defined(CONFIG_RSBAC_RC)
static struct rsbac_lnetobj_handles_t lnetobj_handles;
static struct rsbac_rnetobj_handles_t rnetobj_handles;
#endif
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
static struct rsbac_gen_netobj_aci_t def_gen_netobj_aci =
    DEFAULT_GEN_NETOBJ_ACI;
#endif
#endif

/* Default ACIs: implemented as variables, might be changeable some time */

/* rsbac root dir items, end of recursive inherit */
static struct rsbac_gen_fd_aci_t def_gen_root_dir_aci =
    DEFAULT_GEN_ROOT_DIR_ACI;
static struct rsbac_gen_fd_aci_t def_gen_fd_aci = DEFAULT_GEN_FD_ACI;

#if defined(CONFIG_RSBAC_MAC)
static struct rsbac_mac_fd_aci_t def_mac_root_dir_aci =
    DEFAULT_MAC_ROOT_DIR_ACI;
static struct rsbac_mac_fd_aci_t def_mac_fd_aci = DEFAULT_MAC_FD_ACI;
#endif
#if defined(CONFIG_RSBAC_DAZ)
static struct rsbac_daz_fd_aci_t  def_daz_root_dir_aci  = DEFAULT_DAZ_ROOT_DIR_ACI;
#if defined(CONFIG_RSBAC_DAZ_CACHE)
static rsbac_time_t rsbac_daz_ttl = CONFIG_RSBAC_DAZ_TTL;
#endif
#endif
#if defined(CONFIG_RSBAC_PM)
static struct rsbac_pm_fd_aci_t def_pm_fd_aci = DEFAULT_PM_FD_ACI;
#endif
#if defined(CONFIG_RSBAC_RC)
static struct rsbac_rc_fd_aci_t def_rc_root_dir_aci =
    DEFAULT_RC_ROOT_DIR_ACI;
static struct rsbac_rc_fd_aci_t def_rc_fd_aci = DEFAULT_RC_FD_ACI;
#endif
#if defined(CONFIG_RSBAC_RES)
static struct rsbac_res_fd_aci_t def_res_fd_aci = DEFAULT_RES_FD_ACI;
#endif

#if defined(CONFIG_RSBAC_PROC)
#include <rsbac/proc_fs.h>

#ifdef CONFIG_RSBAC_XSTATS
static __u64 get_attr_count[T_NONE] = { 0, 0, 0, 0, 0, 0, 0 };
static __u64 set_attr_count[T_NONE] = { 0, 0, 0, 0, 0, 0, 0 };
static __u64 remove_count[T_NONE] = { 0, 0, 0, 0, 0, 0, 0 };
static __u64 get_parent_count = 0;
#endif

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(proc_rsbac_root_p);
#endif
struct proc_dir_entry *proc_rsbac_root_p = NULL;

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(proc_rsbac_backup_p);
#endif
struct proc_dir_entry *proc_rsbac_backup_p = NULL;

#endif				/* PROC */

#ifdef CONFIG_DEVFS_MOUNT
#include <linux/devfs_fs_kernel.h>
#endif

static struct rsbac_mount_list_t * rsbac_mount_list = NULL;

#ifdef CONFIG_RSBAC_MAC
static struct rsbac_mac_process_aci_t mac_init_p_aci =
    DEFAULT_MAC_P_INIT_ACI;
#endif
#ifdef CONFIG_RSBAC_RC
static struct rsbac_rc_process_aci_t rc_kernel_p_aci =
    DEFAULT_RC_P_KERNEL_ACI;
#endif

static kdev_t umount_device_in_progress = RSBAC_AUTO_DEV;

static struct kmem_cache * device_item_slab = NULL;

/**************************************************/
/*       Declarations of internal functions       */
/**************************************************/

static struct rsbac_device_list_item_t *lookup_device(kdev_t kdev, u_int hash);

/************************************************* */
/*               Internal Help functions           */
/************************************************* */

static u_int gen_nr_fd_hashes = RSBAC_LIST_MIN_MAX_HASHES;
static u_int gen_nr_p_hashes = 1;

#if defined(CONFIG_RSBAC_MAC)
static u_int mac_nr_fd_hashes = RSBAC_LIST_MIN_MAX_HASHES;
static u_int mac_nr_p_hashes = 1;
#endif
#if defined(CONFIG_RSBAC_PM)
static u_int pm_nr_fd_hashes = RSBAC_LIST_MIN_MAX_HASHES;
#endif
#if defined(CONFIG_RSBAC_DAZ)
static u_int daz_nr_fd_hashes = RSBAC_LIST_MIN_MAX_HASHES;

#if defined(CONFIG_RSBAC_DAZ_CACHE)
static u_int daz_scanned_nr_fd_hashes = RSBAC_LIST_MIN_MAX_HASHES;
#endif
#endif
#if defined(CONFIG_RSBAC_FF)
static u_int ff_nr_fd_hashes = RSBAC_LIST_MIN_MAX_HASHES;
#endif
#if defined(CONFIG_RSBAC_RC)
static u_int rc_nr_fd_hashes = RSBAC_LIST_MIN_MAX_HASHES;
static u_int rc_nr_p_hashes = 1;
#endif
#if defined(CONFIG_RSBAC_AUTH)
static u_int auth_nr_fd_hashes = RSBAC_LIST_MIN_MAX_HASHES;
#endif
#if defined(CONFIG_RSBAC_CAP)
static u_int cap_nr_fd_hashes = RSBAC_LIST_MIN_MAX_HASHES;
#endif
#if defined(CONFIG_RSBAC_JAIL)
static u_int jail_nr_p_hashes = 1;
#endif
#if defined(CONFIG_RSBAC_PAX)
static u_int pax_nr_fd_hashes = RSBAC_LIST_MIN_MAX_HASHES;
#endif
#if defined(CONFIG_RSBAC_RES)
static u_int res_nr_fd_hashes = RSBAC_LIST_MIN_MAX_HASHES;
#endif

static inline u_int device_hash(kdev_t id)
{
  return id & (RSBAC_NR_DEVICE_LISTS - 1);
}

/* These help functions do NOT handle data consistency protection by */
/* rw-spinlocks! This is done exclusively by non-internal functions! */

/************************************************************************** */
/* Read/Write functions                                                     */

/* This help function protects some filesystems from being written to */
/* and disables writing under some conditions, e.g. in an interrupt */

rsbac_boolean_t rsbac_writable(struct super_block * sb_p)
{
#ifdef CONFIG_RSBAC_NO_WRITE
	return FALSE;
#else
	if (!sb_p || !sb_p->s_dev)
		return FALSE;
	if (rsbac_debug_no_write || (sb_p->s_flags & MS_RDONLY)
	    || in_interrupt())
		return FALSE;
	if (!MAJOR(sb_p->s_dev)
#ifndef CONFIG_RSBAC_MSDOS_WRITE
	    || (sb_p->s_magic == MSDOS_SUPER_MAGIC)
#endif
	    || (sb_p->s_magic == SOCKFS_MAGIC)
	    || (sb_p->s_magic == PIPEFS_MAGIC)
	    || (sb_p->s_magic == SYSFS_MAGIC)
	    || (sb_p->s_magic == NFS_SUPER_MAGIC)
	    || (sb_p->s_magic == CODA_SUPER_MAGIC)
	    || (sb_p->s_magic == NCP_SUPER_MAGIC)
	    || (sb_p->s_magic == SMB_SUPER_MAGIC)
	    || (sb_p->s_magic == ISOFS_SUPER_MAGIC)
	    || (sb_p->s_magic == OCFS2_SUPER_MAGIC)
	    || (sb_p->s_magic == FUSE_SUPER_MAGIC)
	    || (sb_p->s_magic == CEPH_SUPER_MAGIC))
		return FALSE;
	else
		return TRUE;
#endif
}

/* This lookup function ensures correct access to the file system.          */
/* It returns a pointer to the dentry of the rsbac directory on the mounted */
/* device specified by kdev. If the directory    */
/* does not exist, it is created, if create_dir == TRUE and writable. */

static int lookup_aci_path_dentry(struct vfsmount *mnt_p,
				  struct dentry **dir_dentry_pp,
				  rsbac_boolean_t create_dir, kdev_t kdev)
{
	struct dentry *dir_dentry_p = NULL;
	struct dentry *root_dentry_p = NULL;
	int err = 0;
	struct rsbac_device_list_item_t *device_p;
	u_int hash;
	int srcu_idx;

	if (!dir_dentry_pp)
		return -RSBAC_EINVALIDPOINTER;

	if (!mnt_p) {
		mnt_p = rsbac_get_vfsmount(kdev);
		if (!mnt_p) {
			rsbac_printk(KERN_WARNING "lookup_aci_path_dentry(): invalid device %02u:%02u\n",
				     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
			return -RSBAC_EINVALIDDEV;
		}
	}

	/* pipefs and sockfs must not be read from */
	if ((mnt_p->mnt_sb->s_magic == PIPEFS_MAGIC)
	    || (mnt_p->mnt_sb->s_magic == SOCKFS_MAGIC)
	    ) {
		return -RSBAC_ENOTFOUND;
	}
	hash = device_hash(kdev);

	srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
	device_p = lookup_device(kdev, hash);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "lookup_aci_path_dentry(): No entry for device %02u:%02u\n",
			     MAJOR(kdev), MINOR(kdev));
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}
	/* already looked up earlier? */
	if (device_p->rsbac_dir_dentry_p) {
		*dir_dentry_pp = device_p->rsbac_dir_dentry_p;
		spin_lock(&device_p->rsbac_dir_dentry_p->d_lock);
		rsbac_pr_debug(ds, "device_p->rsbac_dir_dentry_p->d_count "
			       "for device %02u:%02u is %i!\n",
			       MAJOR(mnt_p->mnt_sb->s_dev), MINOR(mnt_p->mnt_sb->s_dev),
			       device_p->rsbac_dir_dentry_p->d_count);
		spin_unlock(&device_p->rsbac_dir_dentry_p->d_lock);
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
		return 0;
	}
	/* Must unlock here for the lookup */
	srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
	rsbac_pr_debug(ds, "first time lookup for or non-existing %s on device "
		       "%02u:%02u!\n", RSBAC_ACI_PATH,
		       MAJOR(mnt_p->mnt_sb->s_dev), MINOR(mnt_p->mnt_sb->s_dev));
	if (!mnt_p->mnt_sb->s_root) {
		rsbac_printk(KERN_WARNING "lookup_aci_path_dentry(): Super_block for device %02u:%02u has no root dentry!\n",
			     MAJOR(mnt_p->mnt_sb->s_dev), MINOR(mnt_p->mnt_sb->s_dev));
		err = -RSBAC_EINVALIDDEV;
		goto out;
	}

	if (!mnt_p->mnt_sb->s_root->d_inode) {
		rsbac_printk(KERN_WARNING "lookup_aci_path_dentry(): Super_block for device %02u:%02u has no root dentry->d_inode!\n",
			     MAJOR(mnt_p->mnt_sb->s_dev), MINOR(mnt_p->mnt_sb->s_dev));
		err = -RSBAC_EINVALIDDEV;
		goto out;
	}

	/* lookup dentry of ACI_PATH on this device */
	spin_lock(&mnt_p->mnt_sb->s_root->d_lock);
	rsbac_pr_debug(ds, "lookup rsbac path %s for device %02u:%02u, "
		       "sb_p->s_root->d_count is %i!\n",
		       RSBAC_ACI_PATH, MAJOR(mnt_p->mnt_sb->s_dev),
		       MINOR(mnt_p->mnt_sb->s_dev),
		       mnt_p->mnt_sb->s_root->d_count);
	spin_unlock(&mnt_p->mnt_sb->s_root->d_lock);

	dir_dentry_p =
	    rsbac_lookup_one_len(RSBAC_ACI_PATH, mnt_p->mnt_sb->s_root,
				 strlen(RSBAC_ACI_PATH));
	if (IS_ERR(dir_dentry_p))
		switch (PTR_ERR(dir_dentry_p)) {
		case -ENOENT:
		case -ENOTDIR:
			err = -RSBAC_ENOTFOUND;
			goto out;
		case -ENOMEM:
			rsbac_printk(KERN_WARNING "lookup_aci_path_dentry(): memory allocation error!\n");
			err = -RSBAC_ENOROOTDIR;
			goto out;
		case -ENAMETOOLONG:
			rsbac_printk(KERN_WARNING "lookup_aci_path_dentry(): ACI_PATH too long on fs!\n");
			err = -RSBAC_EPATHTOOLONG;
			goto out;
		case -EACCES:
			rsbac_printk(KERN_WARNING "lookup_aci_path_dentry(): No access to ACI_PATH!\n");
			err = -RSBAC_EACCESS;
			goto out;
		default:
			rsbac_printk(KERN_WARNING "lookup_aci_path_dentry(): Error on root dir: %li!\n",
				     PTR_ERR(dir_dentry_p));
			err = -RSBAC_ENOROOTDIR;
			goto out;
		}

	if (!dir_dentry_p) {
		rsbac_printk(KERN_WARNING "lookup_aci_path_dentry(): rsbac_lookup_(dentry|one) returned null pointer!\n");
		err = -RSBAC_EINVALIDPOINTER;
		goto out;
	}
	if (!dir_dentry_p->d_inode) {	/* dir could not be found -> try to create it */
		/* but only, if allowed... */
		if (!create_dir) {
			err = -RSBAC_ENOTFOUND;
			goto out_dir_dput;
		}
		rsbac_pr_debug(ds, "try to create dir, first test writable!\n");
		/* ... and writable. */
		if (!rsbac_writable(mnt_p->mnt_sb)) {	/* mounted read only or special case */
			err = -RSBAC_ENOTWRITABLE;
			goto out_dir_dput;
		}
		root_dentry_p = lock_parent(dir_dentry_p);
		err = PTR_ERR(root_dentry_p);
		if (IS_ERR(root_dentry_p)) {
			err = -RSBAC_ECOULDNOTCREATEPATH;
			goto out_dir_dput;
		}
		if (!root_dentry_p->d_inode
		    || !root_dentry_p->d_inode->i_op
		    || !root_dentry_p->d_inode->i_op->mkdir) {
			unlock_dir(root_dentry_p);
			err = -RSBAC_ECOULDNOTCREATEPATH;
			goto out_dir_dput;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,34)
		dquot_initialize(root_dentry_p->d_inode);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
		vfs_dq_init(root_dentry_p->d_inode);
#else
		DQUOT_INIT(root_dentry_p->d_inode);
#endif
		err =
		    root_dentry_p->d_inode->i_op->mkdir(root_dentry_p->
							d_inode,
							dir_dentry_p,
							RSBAC_ACI_DIR_MODE);
		unlock_dir(root_dentry_p);
		if (err) {
			err = -RSBAC_ECOULDNOTCREATEPATH;
			goto out_dir_dput;
		}
	} else {		/* was found */
		/* check, whether this is a dir */
		if (!S_ISDIR(dir_dentry_p->d_inode->i_mode)) {	/* no dir! We have a real prob here! */
			rsbac_printk(KERN_WARNING "lookup_aci_path_dentry(): supposed /%s dir on dev %02u:%02u is no dir!\n",
				     RSBAC_ACI_PATH,
				     MAJOR(mnt_p->mnt_sb->s_dev),
				     MINOR(mnt_p->mnt_sb->s_dev));
			err = -RSBAC_EACCESS;
			goto out_dir_dput;
		}
	}
	spin_lock(&dir_dentry_p->d_lock);
	rsbac_pr_debug(ds, "dir_dentry_p->d_count is %i!\n",
		       dir_dentry_p->d_count);
	spin_unlock(&dir_dentry_p->d_lock);
	spin_lock(&mnt_p->mnt_sb->s_root->d_lock);
	rsbac_pr_debug(ds, "mnt_p->mnt_sb->s_root->d_count is now %i!\n",
		       mnt_p->mnt_sb->s_root->d_count);
	spin_unlock(&mnt_p->mnt_sb->s_root->d_lock);
	/* we want to keep dir_dentry_p in device_item */
	/* dput must be done in remove_device_item! */
	*dir_dentry_pp = dir_dentry_p;

	/* Must lock and relookup device_p to cache result */
	srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
	device_p = lookup_device(kdev, hash);
	if (device_p && !device_p->rsbac_dir_dentry_p) {
		device_p->rsbac_dir_dentry_p = dir_dentry_p;
		device_p->rsbac_dir_inode = dir_dentry_p->d_inode->i_ino;
	}
	srcu_read_unlock(&device_list_srcu[hash], srcu_idx);

      out:
	return err;

      out_dir_dput:
	dput(dir_dentry_p);
	goto out;
}

/************************************************************************** */
/* The lookup functions return NULL, if the item is not found, and a        */
/* pointer to the item otherwise.                                           */

/* First, a lookup for the device list item                                 */

static struct rsbac_device_list_item_t *lookup_device(kdev_t kdev, u_int hash)
{
	struct rsbac_device_list_item_t *curr = rcu_dereference(device_head_p[hash])->curr;

	/* if there is no current item or it is not the right one, search... */
	if (!(curr && (MAJOR(curr->id) == MAJOR(kdev))
	     && (MINOR(curr->id) == MINOR(kdev))))
	{
		curr = rcu_dereference(device_head_p[hash])->head;
		while (curr
		       && ((RSBAC_MAJOR(curr->id) != RSBAC_MAJOR(kdev))
			   || (RSBAC_MINOR(curr->id) != RSBAC_MINOR(kdev))
		       )
		    ) {
			curr = curr->next;
		}
		if (curr)
			rcu_dereference(device_head_p[hash])->curr = curr;
	}
	/* it is the current item -> return it */
	return curr;
}

#ifdef CONFIG_RSBAC_FD_CACHE
u_int hash_fd_cache(void * desc, __u32 nr_hashes)
{
	return ( ((struct rsbac_fd_cache_desc_t *) desc)->inode & (nr_hashes - 1) );
}
#endif

static int dev_compare(void *desc1, void *desc2)
{
	int result;
	struct rsbac_dev_desc_t *i_desc1 = desc1;
	struct rsbac_dev_desc_t *i_desc2 = desc2;

	result = memcmp(&i_desc1->type,
			&i_desc2->type, sizeof(i_desc1->type));
	if (result)
		return result;
	result = memcmp(&i_desc1->major,
			&i_desc2->major, sizeof(i_desc1->major));
	if (result)
		return result;
	return memcmp(&i_desc1->minor,
		      &i_desc2->minor, sizeof(i_desc1->minor));
}

#ifdef CONFIG_RSBAC_RC
static int dev_major_compare(void *desc1, void *desc2)
{
	int result;
	struct rsbac_dev_desc_t *i_desc1 = desc1;
	struct rsbac_dev_desc_t *i_desc2 = desc2;

	result = memcmp(&i_desc1->type,
			&i_desc2->type, sizeof(i_desc1->type));
	if (result)
		return result;
	return memcmp(&i_desc1->major,
		      &i_desc2->major, sizeof(i_desc1->major));
}
#endif

static int ipc_compare(void *desc1, void *desc2)
{
	int result;
	struct rsbac_ipc_t *i_desc1 = desc1;
	struct rsbac_ipc_t *i_desc2 = desc2;

	result = memcmp(&i_desc1->type,
			&i_desc2->type, sizeof(i_desc1->type));
	if (result)
		return result;
	else
		return memcmp(&i_desc1->id.id_nr,
			      &i_desc2->id.id_nr,
			      sizeof(i_desc1->id.id_nr));
}

#ifdef CONFIG_RSBAC_NET_DEV
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG) || defined(CONFIG_RSBAC_RC)
static int netdev_compare(void *desc1, void *desc2)
{
	return strncmp(desc1, desc2, RSBAC_IFNAMSIZ);
}
#endif
#endif

/************************************************************************** */
/* Convert functions                                                        */

static int gen_fd_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_gen_fd_aci_t *new_aci = new_data;
	struct rsbac_gen_fd_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
	new_aci->log_array_low = old_aci->log_array_low;
	new_aci->log_array_high = old_aci->log_array_high;
	new_aci->log_program_based = old_aci->log_program_based;
	new_aci->symlink_add_remote_ip = old_aci->symlink_add_remote_ip;
	new_aci->symlink_add_uid = old_aci->symlink_add_uid;
	new_aci->symlink_add_mac_level = old_aci->symlink_add_mac_level;
	new_aci->symlink_add_rc_role = old_aci->symlink_add_rc_role;
	new_aci->linux_dac_disable = old_aci->linux_dac_disable;
	new_aci->fake_root_uid = old_aci->fake_root_uid;
	new_aci->auid_exempt = old_aci->auid_exempt;
	new_aci->vset = RSBAC_UM_VIRTUAL_KEEP;
	return 0;
}

static int gen_fd_old_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_gen_fd_aci_t *new_aci = new_data;
	struct rsbac_gen_fd_old_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
	new_aci->log_array_low = old_aci->log_array_low;
	new_aci->log_array_high = old_aci->log_array_high;
	new_aci->log_program_based = old_aci->log_program_based;
	new_aci->symlink_add_remote_ip = 0;
	new_aci->symlink_add_uid = old_aci->symlink_add_uid;
	new_aci->symlink_add_mac_level = old_aci->symlink_add_mac_level;
	new_aci->symlink_add_rc_role = old_aci->symlink_add_rc_role;
	new_aci->linux_dac_disable = old_aci->linux_dac_disable;
	new_aci->fake_root_uid = old_aci->fake_root_uid;
	new_aci->auid_exempt = old_aci->auid_exempt;
	new_aci->vset = RSBAC_UM_VIRTUAL_KEEP;
	return 0;
}

static rsbac_list_conv_function_t *gen_fd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_GEN_FD_OLD_ACI_VERSION:
		return gen_fd_conv;
	case RSBAC_GEN_FD_OLD_OLD_ACI_VERSION:
		return gen_fd_old_conv;
	default:
		return NULL;
	}
}

static int gen_dev_conv(void *old_desc,
			void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_dev_desc_t *new = new_desc;
	struct rsbac_dev_t *old = old_desc;

	memcpy(new_data, old_data, sizeof(struct rsbac_gen_dev_aci_t));
	new->type = old->type;
	new->major = RSBAC_MAJOR(old->id);
	new->minor = RSBAC_MINOR(old->id);
	return 0;
}

static rsbac_list_conv_function_t *gen_dev_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_GEN_DEV_OLD_ACI_VERSION:
		return gen_dev_conv;
	default:
		return NULL;
	}
}

static int gen_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(struct rsbac_gen_user_aci_t));
	return 0;
}

static rsbac_list_conv_function_t *gen_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_GEN_USER_OLD_ACI_VERSION:
		return gen_user_conv;
	default:
		return NULL;
	}
}

#ifdef CONFIG_RSBAC_MAC
static int mac_old_fd_conv(void *old_desc,
			   void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_mac_fd_aci_t *new_aci = new_data;
	struct rsbac_mac_fd_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
	new_aci->sec_level = old_aci->sec_level;
	new_aci->mac_categories = old_aci->mac_categories;
	new_aci->mac_auto = old_aci->mac_auto;
	new_aci->mac_prop_trusted = old_aci->mac_prop_trusted;
	new_aci->mac_file_flags = old_aci->mac_file_flags;
	return 0;
}

static int mac_old_old_fd_conv(void *old_desc,
			       void *old_data,
			       void *new_desc, void *new_data)
{
	struct rsbac_mac_fd_aci_t *new_aci = new_data;
	struct rsbac_mac_fd_old_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
	new_aci->sec_level = old_aci->sec_level;
	new_aci->mac_categories = old_aci->mac_categories;
	new_aci->mac_auto = old_aci->mac_auto;
	new_aci->mac_prop_trusted = FALSE;
	if (old_aci->mac_shared)
		new_aci->mac_file_flags = MAC_write_up;
	else
		new_aci->mac_file_flags = 0;
	return 0;
}

static int mac_old_old_old_fd_conv(void *old_desc,
				   void *old_data,
				   void *new_desc, void *new_data)
{
	struct rsbac_mac_fd_aci_t *new_aci = new_data;
	struct rsbac_mac_fd_old_old_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
	new_aci->sec_level = old_aci->sec_level;
	new_aci->mac_categories = old_aci->mac_categories;
	new_aci->mac_auto = old_aci->mac_auto;
	new_aci->mac_prop_trusted = FALSE;
	new_aci->mac_file_flags = 0;
	return 0;
}

static rsbac_list_conv_function_t *mac_fd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_MAC_FD_OLD_ACI_VERSION:
		return mac_old_fd_conv;
	case RSBAC_MAC_FD_OLD_OLD_ACI_VERSION:
		return mac_old_old_fd_conv;
	case RSBAC_MAC_FD_OLD_OLD_OLD_ACI_VERSION:
		return mac_old_old_old_fd_conv;
	default:
		return NULL;
	}
}

static int mac_dev_conv(void *old_desc,
			void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_dev_desc_t *new = new_desc;
	struct rsbac_dev_t *old = old_desc;

	memcpy(new_data, old_data, sizeof(struct rsbac_mac_dev_aci_t));
	new->type = old->type;
	new->major = RSBAC_MAJOR(old->id);
	new->minor = RSBAC_MINOR(old->id);
	return 0;
}

static rsbac_list_conv_function_t *mac_dev_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_MAC_DEV_OLD_ACI_VERSION:
		return mac_dev_conv;
	default:
		return NULL;
	}
}

static int mac_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(struct rsbac_mac_user_aci_t));
	return 0;
}

static int mac_old_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	struct rsbac_mac_user_aci_t *new_aci = new_data;
	struct rsbac_mac_user_old_aci_t *old_aci = old_data;

	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	new_aci->security_level = old_aci->access_appr;
	new_aci->initial_security_level = old_aci->access_appr;
	new_aci->min_security_level = old_aci->min_access_appr;
	new_aci->mac_categories = old_aci->mac_categories;
	new_aci->mac_initial_categories = old_aci->mac_categories;
	new_aci->mac_min_categories = old_aci->mac_min_categories;
	new_aci->system_role = old_aci->system_role;
	new_aci->mac_user_flags = RSBAC_MAC_DEF_U_FLAGS;
	if (old_aci->mac_allow_auto)
		new_aci->mac_user_flags |= MAC_allow_auto;
	return 0;
}

static int mac_old_old_user_conv(void *old_desc,
				 void *old_data,
				 void *new_desc, void *new_data)
{
	struct rsbac_mac_user_aci_t *new_aci = new_data;
	struct rsbac_mac_user_old_old_aci_t *old_aci = old_data;

	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	new_aci->security_level = old_aci->access_appr;
	new_aci->initial_security_level = old_aci->access_appr;
	new_aci->min_security_level = old_aci->min_access_appr;
	new_aci->mac_categories = old_aci->mac_categories;
	new_aci->mac_initial_categories = old_aci->mac_categories;
	new_aci->mac_min_categories = old_aci->mac_min_categories;
	new_aci->system_role = old_aci->system_role;
	new_aci->mac_user_flags = RSBAC_MAC_DEF_U_FLAGS;
	return 0;
}

static int mac_old_old_old_user_conv(void *old_desc,
				     void *old_data,
				     void *new_desc, void *new_data)
{
	struct rsbac_mac_user_aci_t *new_aci = new_data;
	struct rsbac_mac_user_old_old_old_aci_t *old_aci = old_data;

	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	new_aci->security_level = old_aci->access_appr;
	new_aci->initial_security_level = old_aci->access_appr;
	new_aci->min_security_level = SL_unclassified;
	new_aci->mac_categories = old_aci->mac_categories;
	new_aci->mac_initial_categories = old_aci->mac_categories;
	new_aci->mac_min_categories = RSBAC_MAC_MIN_CAT_VECTOR;
	new_aci->system_role = old_aci->system_role;
	new_aci->mac_user_flags = RSBAC_MAC_DEF_U_FLAGS;
	return 0;
}

static rsbac_list_conv_function_t *mac_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_MAC_USER_OLD_ACI_VERSION:
		return mac_user_conv;
	case RSBAC_MAC_USER_OLD_OLD_ACI_VERSION:
		return mac_old_user_conv;
	case RSBAC_MAC_USER_OLD_OLD_OLD_ACI_VERSION:
		return mac_old_old_user_conv;
	case RSBAC_MAC_USER_OLD_OLD_OLD_OLD_ACI_VERSION:
		return mac_old_old_old_user_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_PM
static int pm_dev_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_dev_desc_t *new = new_desc;
	struct rsbac_dev_t *old = old_desc;

	memcpy(new_data, old_data, sizeof(struct rsbac_pm_dev_aci_t));
	new->type = old->type;
	new->major = RSBAC_MAJOR(old->id);
	new->minor = RSBAC_MINOR(old->id);
	return 0;
}

static rsbac_list_conv_function_t *pm_dev_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_PM_DEV_OLD_ACI_VERSION:
		return pm_dev_conv;
	default:
		return NULL;
	}
}
static int pm_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(struct rsbac_pm_user_aci_t));
	return 0;
}

static rsbac_list_conv_function_t *pm_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_PM_USER_OLD_ACI_VERSION:
		return pm_user_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_DAZ
static int daz_old_fd_conv(
	void * old_desc,
	void * old_data,
	void * new_desc,
	void * new_data)
  {
    struct rsbac_daz_fd_aci_t     * new_aci = new_data;
    struct rsbac_daz_fd_old_aci_t * old_aci = old_data;

    memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
    new_aci->daz_scanner = old_aci->daz_scanner;
    new_aci->daz_do_scan = DEFAULT_DAZ_FD_DO_SCAN;
    return 0;
  }

static rsbac_list_conv_function_t * daz_fd_get_conv(rsbac_version_t old_version)
  {
    switch(old_version)
      {
        case RSBAC_DAZ_FD_OLD_ACI_VERSION:
          return daz_old_fd_conv;
        default:
          return NULL;
      }
  }

static int daz_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(rsbac_system_role_int_t));
	return 0;
}

static rsbac_list_conv_function_t *daz_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_DAZ_USER_OLD_ACI_VERSION:
		return daz_user_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_FF
static int ff_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(rsbac_system_role_int_t));
	return 0;
}

static rsbac_list_conv_function_t *ff_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_FF_USER_OLD_ACI_VERSION:
		return ff_user_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_RC
static int rc_dev_conv(void *old_desc,
		       void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_dev_desc_t *new = new_desc;
	struct rsbac_dev_t *old = old_desc;

	memcpy(new_data, old_data, sizeof(rsbac_rc_type_id_t));
	new->type = old->type;
	new->major = RSBAC_MAJOR(old->id);
	new->minor = RSBAC_MINOR(old->id);
	return 0;
}

static rsbac_list_conv_function_t *rc_dev_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_RC_DEV_OLD_ACI_VERSION:
		return rc_dev_conv;
	default:
		return NULL;
	}
}

static int rc_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(struct rsbac_rc_user_aci_t));
	return 0;
}

static int rc_user_old_conv(void *old_desc,
			void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_rc_user_aci_t *new_aci = new_data;
	rsbac_rc_role_id_t *old_aci = old_data;

	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	new_aci->rc_role = *old_aci;
	new_aci->rc_type = RSBAC_RC_GENERAL_TYPE;
	return 0;
}

static rsbac_list_conv_function_t *rc_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_RC_USER_OLD_ACI_VERSION:
		return rc_user_conv;
	case RSBAC_RC_USER_OLD_OLD_ACI_VERSION:
		return rc_user_old_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_AUTH
static int auth_old_fd_conv(void *old_desc,
			    void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_auth_fd_aci_t *new_aci = new_data;
	struct rsbac_auth_fd_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
	new_aci->auth_may_setuid = old_aci->auth_may_setuid;
	new_aci->auth_may_set_cap = old_aci->auth_may_set_cap;
	new_aci->auth_learn = FALSE;
	return 0;
}

static rsbac_list_conv_function_t *auth_fd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_AUTH_FD_OLD_ACI_VERSION:
		return auth_old_fd_conv;
	default:
		return NULL;
	}
}

static int auth_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(rsbac_system_role_int_t));
	return 0;
}

static rsbac_list_conv_function_t *auth_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_AUTH_USER_OLD_ACI_VERSION:
		return auth_user_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_CAP
static int cap_old_fd_conv(void *old_desc, void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_cap_fd_aci_t *new_aci = new_data;
	struct rsbac_cap_fd_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
	new_aci->min_caps.cap[0] = old_aci->min_caps;
	new_aci->max_caps.cap[0] = old_aci->max_caps;
	new_aci->min_caps.cap[1] = (__u32) 0;
	new_aci->max_caps.cap[1] = (__u32) -1;
	new_aci->cap_ld_env = old_aci->cap_ld_env;
	return 0;
}

static int cap_old_old_fd_conv(void *old_desc, void *old_data, void *new_desc, void *new_data)
{
        struct rsbac_cap_fd_aci_t *new_aci = new_data;
        struct rsbac_cap_fd_old_old_aci_t *old_aci = old_data;

        memcpy(new_desc, old_desc, sizeof(rsbac_inode_nr_t));
	new_aci->min_caps.cap[0] = old_aci->min_caps;
	new_aci->max_caps.cap[0] = old_aci->max_caps;
	new_aci->min_caps.cap[1] = (__u32) 0;
	new_aci->max_caps.cap[1] = (__u32) -1;
        new_aci->cap_ld_env = LD_inherit;
        return 0;
}

static rsbac_list_conv_function_t *cap_fd_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
		case RSBAC_CAP_FD_OLD_OLD_ACI_VERSION:
			return cap_old_old_fd_conv;
		case RSBAC_CAP_FD_OLD_ACI_VERSION:
			return cap_old_fd_conv;
		default:
			return NULL;
	}
}

static int cap_old_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	struct rsbac_cap_user_aci_t *new_aci = new_data;
	struct rsbac_cap_user_old_aci_t *old_aci = old_data;

	memcpy(new_desc, old_desc, sizeof(rsbac_uid_t));
	new_aci->cap_role = old_aci->cap_role;
	new_aci->min_caps.cap[0] = old_aci->min_caps;
	new_aci->max_caps.cap[0] = old_aci->max_caps;
	new_aci->min_caps.cap[1] = (__u32) 0;
	new_aci->max_caps.cap[1] = (__u32) -1;
	new_aci->cap_ld_env = old_aci->cap_ld_env;
	return 0;
}

static int cap_old_old_user_conv(void *old_desc, void *old_data, void *new_desc, void *new_data)
{
        rsbac_uid_t *new_user = new_desc;
        rsbac_old_uid_t *old_user = old_desc;
        struct rsbac_cap_user_aci_t *new_aci = new_data;
        struct rsbac_cap_user_old_old_aci_t *old_aci = old_data;

        *new_user = RSBAC_GEN_UID(0,*old_user);
	new_aci->cap_role = old_aci->cap_role;
	new_aci->min_caps.cap[0] = old_aci->min_caps;
	new_aci->max_caps.cap[0] = old_aci->max_caps;
	new_aci->min_caps.cap[1] = (__u32) 0;
	new_aci->max_caps.cap[1] = (__u32) -1;
	new_aci->cap_ld_env = old_aci->cap_ld_env;
        return 0;
}

static int cap_old_old_old_user_conv(void *old_desc, void *old_data, void *new_desc, void *new_data)
{
        rsbac_uid_t *new_user = new_desc;
        rsbac_old_uid_t *old_user = old_desc;
        struct rsbac_cap_user_aci_t *new_aci = new_data;
        struct rsbac_cap_user_old_old_aci_t *old_aci = old_data;

        *new_user = RSBAC_GEN_UID(0,*old_user);
	new_aci->cap_role = old_aci->cap_role;
	new_aci->min_caps.cap[0] = old_aci->min_caps;
	new_aci->max_caps.cap[0] = old_aci->max_caps;
	new_aci->min_caps.cap[1] = (__u32) 0;
	new_aci->max_caps.cap[1] = (__u32) -1;
	new_aci->cap_ld_env = LD_allow;
        return 0;
}

static rsbac_list_conv_function_t *cap_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
		case RSBAC_CAP_USER_OLD_ACI_VERSION:
			return cap_old_user_conv;
		case RSBAC_CAP_USER_OLD_OLD_ACI_VERSION:
			return cap_old_old_user_conv;
		case RSBAC_CAP_USER_OLD_OLD_OLD_ACI_VERSION:
			return cap_old_old_old_user_conv;
		default:
			return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_JAIL
static int jail_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(rsbac_system_role_int_t));
	return 0;
}

static rsbac_list_conv_function_t *jail_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_JAIL_USER_OLD_ACI_VERSION:
		return jail_user_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_PAX
static int pax_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(rsbac_system_role_int_t));
	return 0;
}

static rsbac_list_conv_function_t *pax_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_PAX_USER_OLD_ACI_VERSION:
		return pax_user_conv;
	default:
		return NULL;
	}
}
#endif

#ifdef CONFIG_RSBAC_RES
static int res_user_conv(void *old_desc,
			     void *old_data,
			     void *new_desc, void *new_data)
{
	*((rsbac_uid_t *)new_desc) = *((rsbac_old_uid_t *)old_desc);
	memcpy(new_data, old_data, sizeof(struct rsbac_res_user_aci_t));
	return 0;
}

static rsbac_list_conv_function_t *res_user_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
	case RSBAC_RES_USER_OLD_ACI_VERSION:
		return res_user_conv;
	default:
		return NULL;
	}
}
#endif


#ifdef CONFIG_RSBAC_NET_OBJ
static int net_temp_old_conv(void *old_desc, void *old_data, void *new_desc, void *new_data)
{
	struct rsbac_net_temp_data_t *new_aci = new_data;
	struct rsbac_net_temp_old_data_t *old_aci = old_data;

        memcpy(new_desc, old_desc, sizeof(rsbac_net_temp_id_t));
	new_aci->address_family = old_aci->address_family;
	new_aci->type = old_aci->type;
	new_aci->protocol = old_aci->protocol;
	memcpy(new_aci->netdev, old_aci->netdev, sizeof(rsbac_netdev_id_t));
	memcpy(new_aci->name, old_aci->name, sizeof(new_aci->name));
	switch(new_aci->address_family) {
		case AF_INET:
			new_aci->address.inet.nr_addr = 1;
			new_aci->address.inet.addr[0] = *((__u32 *) old_aci->address);
			new_aci->address.inet.valid_bits[0] = old_aci->valid_len;
			if((old_aci->min_port == 0) && (old_aci->max_port == RSBAC_NET_MAX_PORT))
				new_aci->ports.nr_ports = 0;
			else {
				new_aci->ports.nr_ports = 1;
				new_aci->ports.ports[0].min = old_aci->min_port;
				new_aci->ports.ports[0].max = old_aci->max_port;
			}
			break;
		default:
			memcpy(new_aci->address.other.addr, old_aci->address, sizeof(old_aci->address));
			new_aci->address.other.valid_len = old_aci->valid_len;
			new_aci->ports.nr_ports = 0;
			break;
	}
	return 0;
}


static rsbac_list_conv_function_t *net_temp_get_conv(rsbac_version_t old_version)
{
	switch (old_version) {
		case RSBAC_NET_TEMP_OLD_VERSION:
			return net_temp_old_conv;
		default:
			return NULL;
	}
}
#endif

/************************************************************************** */
/* The add_item() functions add an item to the list, set head.curr to it,   */
/* and return a pointer to the item.                                        */
/* These functions will NOT check, if there is already an item under the    */
/* same ID! If this happens, the lookup functions will return the old item! */
/* All list manipulation must be protected by rw-spinlocks to prevent       */
/* inconsistency and undefined behaviour in other concurrent functions.     */

/* register_fd_lists() */
/* register fd lists for device */

static int register_fd_lists(struct rsbac_device_list_item_t *device_p,
			     kdev_t kdev)
{
	char *name;
	int err = 0;
	int tmperr;
	struct rsbac_list_info_t *info_p;
	if (!device_p)
		return -RSBAC_EINVALIDPOINTER;
	name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
	if (!name)
		return -RSBAC_ENOMEM;
	info_p = rsbac_kmalloc(sizeof(*info_p));
	if (!info_p) {
		rsbac_kfree(name);
		return -RSBAC_ENOMEM;
	}

	/* register general lists */
	{
		info_p->version = RSBAC_GEN_FD_ACI_VERSION;
		info_p->key = RSBAC_GEN_FD_ACI_KEY;
		info_p->desc_size = sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_gen_fd_aci_t);
		info_p->max_age = 0;
		gen_nr_fd_hashes = RSBAC_GEN_NR_FD_LISTS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.gen,
					     info_p,
					     RSBAC_LIST_PERSIST |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     gen_fd_get_conv,
					     &def_gen_fd_aci,
					     RSBAC_GEN_FD_NAME,
					     kdev,
					     gen_nr_fd_hashes,
					     rsbac_list_hash_fd,
					     RSBAC_GEN_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering general list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_GEN_FD_NAME,
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev),
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}

#if defined(CONFIG_RSBAC_MAC)
	{
		/* register MAC lists */
		info_p->version = RSBAC_MAC_FD_ACI_VERSION;
		info_p->key = RSBAC_MAC_FD_ACI_KEY;
		info_p->desc_size = sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_mac_fd_aci_t);
		info_p->max_age = 0;
		mac_nr_fd_hashes = RSBAC_MAC_NR_FD_LISTS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.mac,
					     info_p,
					     RSBAC_LIST_PERSIST | (RSBAC_MAJOR(kdev) ? RSBAC_LIST_OWN_SLAB : 0) |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     mac_fd_get_conv,
					     &def_mac_fd_aci,
					     RSBAC_MAC_FD_NAME,
					     kdev,
					     mac_nr_fd_hashes,
					     rsbac_list_hash_fd,
					     RSBAC_MAC_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering MAC list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_MAC_FD_NAME,
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev),
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

#if defined(CONFIG_RSBAC_PM)
	{
		/* register PM lists */
		info_p->version = RSBAC_PM_FD_ACI_VERSION;
		info_p->key = RSBAC_PM_FD_ACI_KEY;
		info_p->desc_size = sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_pm_fd_aci_t);
		info_p->max_age = 0;
		pm_nr_fd_hashes = RSBAC_PM_NR_FD_LISTS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.pm,
					     info_p,
					     RSBAC_LIST_PERSIST | (RSBAC_MAJOR(kdev) ? RSBAC_LIST_OWN_SLAB : 0) |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     NULL, &def_pm_fd_aci,
					     RSBAC_PM_FD_NAME, kdev,
					     pm_nr_fd_hashes,
					     rsbac_list_hash_fd,
					     RSBAC_PM_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering PM list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_PM_FD_NAME,
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev),
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

#if defined(CONFIG_RSBAC_DAZ)
	{
		struct rsbac_daz_fd_aci_t def_daz_fd_aci =
		    DEFAULT_DAZ_FD_ACI;
		/* register DAZ lists */
		info_p->version = RSBAC_DAZ_FD_ACI_VERSION;
		info_p->key = RSBAC_DAZ_FD_ACI_KEY;
		info_p->desc_size = sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_daz_fd_aci_t);
		info_p->max_age = 0;
		daz_nr_fd_hashes = RSBAC_DAZ_NR_FD_LISTS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.daz,
					     info_p,
					     RSBAC_LIST_PERSIST |
					     RSBAC_LIST_DEF_DATA |
					     RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     daz_fd_get_conv,
					     &def_daz_fd_aci,
					     RSBAC_DAZ_FD_NAME, kdev,
					     daz_nr_fd_hashes,
					     rsbac_list_hash_fd,
					     RSBAC_DAZ_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering DAZ list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_DAZ_FD_NAME,
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev),
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#if defined(CONFIG_RSBAC_DAZ_CACHE)
	{
		rsbac_daz_scanned_t def_daz_scanned_fd_aci =
		    DEFAULT_DAZ_FD_SCANNED;

		info_p->version = RSBAC_DAZ_SCANNED_FD_ACI_VERSION;
		info_p->key = RSBAC_DAZ_FD_ACI_KEY;
		info_p->desc_size = sizeof(rsbac_inode_nr_t);
		info_p->data_size = sizeof(rsbac_daz_scanned_t);
		info_p->max_age = 0;
		daz_scanned_nr_fd_hashes = RSBAC_DAZ_SCANNED_NR_FD_LISTS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.dazs,
					     info_p,
#ifdef CONFIG_RSBAC_DAZ_PERSIST
					     RSBAC_LIST_PERSIST |
#endif
					     RSBAC_LIST_DEF_DATA | (RSBAC_MAJOR(kdev) ? RSBAC_LIST_OWN_SLAB : 0) |
					     RSBAC_LIST_AUTO_HASH_RESIZE |
					     RSBAC_LIST_NO_MAX,
					     NULL,
					     NULL,
					     &def_daz_scanned_fd_aci,
					     RSBAC_DAZ_SCANNED_FD_NAME, kdev,
					     daz_scanned_nr_fd_hashes,
					     rsbac_list_hash_fd,
					     RSBAC_DAZ_SCANNED_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering DAZ scanned list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_DAZ_SCANNED_FD_NAME,
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev),
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif
#endif

#if defined(CONFIG_RSBAC_FF)
	{
		rsbac_ff_flags_t def_ff_fd_aci = RSBAC_FF_DEF;

		info_p->version = RSBAC_FF_FD_ACI_VERSION;
		info_p->key = RSBAC_FF_FD_ACI_KEY;
		info_p->desc_size = sizeof(rsbac_inode_nr_t);
		info_p->data_size = sizeof(rsbac_ff_flags_t);
		info_p->max_age = 0;
		ff_nr_fd_hashes = RSBAC_FF_NR_FD_LISTS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.ff,
					     info_p,
					     RSBAC_LIST_PERSIST | (RSBAC_MAJOR(kdev) ? RSBAC_LIST_OWN_SLAB : 0) |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     NULL, &def_ff_fd_aci,
					     RSBAC_FF_FD_NAME, kdev,
					     ff_nr_fd_hashes,
					     rsbac_list_hash_fd,
					     RSBAC_FF_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering FF list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_FF_FD_NAME,
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev),
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

#if defined(CONFIG_RSBAC_RC)
	{
		info_p->version = RSBAC_RC_FD_ACI_VERSION;
		info_p->key = RSBAC_RC_FD_ACI_KEY;
		info_p->desc_size = sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_rc_fd_aci_t);
		info_p->max_age = 0;
		rc_nr_fd_hashes = RSBAC_RC_NR_FD_LISTS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.rc,
					     info_p,
					     RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     NULL, &def_rc_fd_aci,
					     RSBAC_RC_FD_NAME, kdev,
					     rc_nr_fd_hashes,
					     rsbac_list_hash_fd,
					     RSBAC_RC_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering RC list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_RC_FD_NAME,
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev),
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

#if defined(CONFIG_RSBAC_AUTH)
	{
		struct rsbac_auth_fd_aci_t def_auth_fd_aci =
		    DEFAULT_AUTH_FD_ACI;

		info_p->version = RSBAC_AUTH_FD_ACI_VERSION;
		info_p->key = RSBAC_AUTH_FD_ACI_KEY;
		info_p->desc_size = sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_auth_fd_aci_t);
		info_p->max_age = 0;
		auth_nr_fd_hashes = RSBAC_AUTH_NR_FD_LISTS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.auth,
					     info_p,
					     RSBAC_LIST_PERSIST |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     auth_fd_get_conv,
					     &def_auth_fd_aci,
					     RSBAC_AUTH_FD_NAME, kdev,
					     auth_nr_fd_hashes,
					     rsbac_list_hash_fd,
					     RSBAC_AUTH_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering AUTH list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_AUTH_FD_NAME,
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev),
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

#if defined(CONFIG_RSBAC_CAP)
	{
		struct rsbac_cap_fd_aci_t def_cap_fd_aci = DEFAULT_CAP_FD_ACI;

		info_p->version = RSBAC_CAP_FD_ACI_VERSION;
		info_p->key = RSBAC_CAP_FD_ACI_KEY;
		info_p->desc_size = sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_cap_fd_aci_t);
		info_p->max_age = 0;
		cap_nr_fd_hashes = RSBAC_CAP_NR_FD_LISTS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.cap,
					     info_p,
					     RSBAC_LIST_PERSIST |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     cap_fd_get_conv, 
					     &def_cap_fd_aci,
					     RSBAC_CAP_FD_NAME, kdev,
					     cap_nr_fd_hashes,
					     rsbac_list_hash_fd,
					     RSBAC_CAP_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering CAP list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_CAP_FD_NAME,
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev),
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

#if defined(CONFIG_RSBAC_PAX)
	{
		rsbac_pax_flags_t def_pax_fd_aci;

#ifdef CONFIG_RSBAC_PAX_DEFAULT
		def_pax_fd_aci = 0;
#ifdef CONFIG_RSBAC_PAX_PAGEEXEC
		def_pax_fd_aci |= PF_PAX_PAGEEXEC;
#endif
#ifdef CONFIG_RSBAC_PAX_EMUTRAMP
		def_pax_fd_aci |= PF_PAX_EMUTRAMP;
#endif
#ifdef CONFIG_RSBAC_PAX_MPROTECT
		def_pax_fd_aci |= PF_PAX_MPROTECT;
#endif
#ifdef CONFIG_RSBAC_PAX_RANDMMAP
		def_pax_fd_aci |= PF_PAX_RANDMMAP;
#endif
#ifdef CONFIG_RSBAC_PAX_RANDEXEC
		def_pax_fd_aci |= PF_PAX_RANDEXEC;
#endif
#ifdef CONFIG_RSBAC_PAX_SEGMEXEC
		def_pax_fd_aci |= PF_PAX_SEGMEXEC;
#endif

#else
		def_pax_fd_aci = RSBAC_PAX_DEF_FLAGS;
#endif

		info_p->version = RSBAC_PAX_FD_ACI_VERSION;
		info_p->key = RSBAC_PAX_FD_ACI_KEY;
		info_p->desc_size = sizeof(rsbac_inode_nr_t);
		info_p->data_size = sizeof(rsbac_pax_flags_t);
		info_p->max_age = 0;
		pax_nr_fd_hashes = RSBAC_PAX_NR_FD_LISTS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.pax,
					     info_p,
					     RSBAC_LIST_PERSIST |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     NULL, &def_pax_fd_aci,
					     RSBAC_PAX_FD_NAME, kdev,
					     pax_nr_fd_hashes,
					     rsbac_list_hash_fd,
					     RSBAC_PAX_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering PAX list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_PAX_FD_NAME,
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev),
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

#if defined(CONFIG_RSBAC_RES)
	{
		info_p->version = RSBAC_RES_FD_ACI_VERSION;
		info_p->key = RSBAC_RES_FD_ACI_KEY;
		info_p->desc_size = sizeof(rsbac_inode_nr_t);
		info_p->data_size =
		    sizeof(struct rsbac_res_fd_aci_t);
		info_p->max_age = 0;
		res_nr_fd_hashes = RSBAC_RES_NR_FD_LISTS;
		tmperr = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					     &device_p->handles.res,
					     info_p,
					     RSBAC_LIST_PERSIST |
					     RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					     NULL,
					     NULL, &def_res_fd_aci,
					     RSBAC_RES_FD_NAME, kdev,
					     res_nr_fd_hashes,
					     rsbac_list_hash_fd,
					     RSBAC_RES_OLD_FD_NAME);
		if (tmperr) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "register_fd_lists(): registering RES list %s for device %02u:%02u failed with error %s!\n",
					     RSBAC_RES_FD_NAME,
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev),
					     get_error_name(tmp,
							    tmperr));
				rsbac_kfree(tmp);
			}
			err = tmperr;
		}
	}
#endif

	rsbac_kfree(name);
	rsbac_kfree(info_p);
	return err;
}

/* aci_detach_fd_lists() */
/* detach from fd lists for device */

static int aci_detach_fd_lists(struct rsbac_device_list_item_t *device_p)
{
	int err = 0;
	int tmperr;

	if (!device_p)
		return -RSBAC_EINVALIDPOINTER;

	/* detach all general lists */
	tmperr = rsbac_list_detach(&device_p->handles.gen,
					   RSBAC_GEN_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from general list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_GEN_FD_NAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}

#if defined(CONFIG_RSBAC_MAC)
	/* detach all MAC lists */
	tmperr = rsbac_list_detach(&device_p->handles.mac,
				   RSBAC_MAC_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from MAC list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_MAC_FD_NAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_PM)
	/* detach all PM lists */
	tmperr = rsbac_list_detach(&device_p->handles.pm,
				   RSBAC_PM_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from PM list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_PM_FD_NAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_DAZ)
	/* detach all DAZ lists */
	tmperr = rsbac_list_detach(&device_p->handles.daz,
				   RSBAC_DAZ_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from DAZ list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_DAZ_FD_NAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#if defined(CONFIG_RSBAC_DAZ_CACHE)
	/* detach all DAZ scanned lists */
	tmperr = rsbac_list_detach(&device_p->handles.dazs,
				      RSBAC_DAZ_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from DAZ scanned list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_DAZ_SCANNED_FD_NAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif
#endif

#if defined(CONFIG_RSBAC_FF)
	/* detach all FF lists */
	tmperr = rsbac_list_detach(&device_p->handles.ff,
				   RSBAC_FF_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from FF list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_FF_FD_NAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_RC)
	/* detach all RC lists */
	tmperr = rsbac_list_detach(&device_p->handles.rc,
				   RSBAC_RC_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from RC list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_RC_FD_NAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_AUTH)
	/* detach all AUTH lists */
	tmperr = rsbac_list_detach(&device_p->handles.auth,
			      RSBAC_AUTH_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from AUTH list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_AUTH_FD_NAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_CAP)
	/* detach all CAP lists */
	tmperr = rsbac_list_detach(&device_p->handles.cap,
				   RSBAC_CAP_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from CAP list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_CAP_FD_NAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_PAX)
	/* detach all PAX lists */
	tmperr = rsbac_list_detach(&device_p->handles.pax,
				   RSBAC_PAX_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from PAX list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_PAX_FD_NAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

#if defined(CONFIG_RSBAC_RES)
	/* detach all RES lists */
	tmperr = rsbac_list_detach(&device_p->handles.res,
				   RSBAC_RES_FD_ACI_KEY);
	if (tmperr) {
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			rsbac_printk(KERN_WARNING "detach_fd_lists(): detaching from RES list %s for device %02u:%02u failed with error %s!\n",
				     RSBAC_RES_FD_NAME,
				     RSBAC_MAJOR(device_p->id),
				     RSBAC_MINOR(device_p->id),
				     get_error_name(tmp, tmperr));
			rsbac_kfree(tmp);
		}
		err = tmperr;
	}
#endif

	return err;
}


/* Create a device item without adding to list. No locking needed. */
static struct rsbac_device_list_item_t
*create_device_item(struct vfsmount *mnt_p)
{
	struct rsbac_device_list_item_t *new_item_p;

	if (!mnt_p)
		return NULL;
	/* allocate memory for new device, return NULL, if failed */
	if (!(new_item_p = rsbac_smalloc_clear_unlocked(device_item_slab)))
		return NULL;

	new_item_p->id = mnt_p->mnt_sb->s_dev;
	new_item_p->mnt_p = mnt_p;
	new_item_p->mount_count = 1;
	return new_item_p;
}

/* Add an existing device item to list. Locking needed. */
static struct rsbac_device_list_item_t
*add_device_item(struct rsbac_device_list_item_t *device_p)
{
	struct rsbac_device_list_head_t * new_p;
	struct rsbac_device_list_head_t * old_p;
	u_int hash;

	if (!device_p)
		return NULL;

	hash = device_hash(device_p->id);
	spin_lock(&device_list_locks[hash]);
	old_p = device_head_p[hash];
	new_p = rsbac_kmalloc(sizeof(*new_p));
	*new_p = *old_p;
	/* add new device to device list */
	if (!new_p->head) {	/* first device */
		new_p->head = device_p;
		new_p->tail = device_p;
		new_p->curr = device_p;
		new_p->count = 1;
		device_p->prev = NULL;
		device_p->next = NULL;
	} else {		/* there is another device -> hang to tail */
		device_p->prev = new_p->tail;
		device_p->next = NULL;
		new_p->tail->next = device_p;
		new_p->tail = device_p;
		new_p->curr = device_p;
		new_p->count++;
	}
	rcu_assign_pointer(device_head_p[hash], new_p);
	spin_unlock(&device_list_locks[hash]);
	synchronize_srcu(&device_list_srcu[hash]);
	rsbac_kfree(old_p);
	return device_p;
}

/************************************************************************** */
/* The remove_item() functions remove an item from the list. If this item   */
/* is head, tail or curr, these pointers are set accordingly.               */
/* To speed up removing several subsequent items, curr is set to the next   */
/* item, if possible.                                                       */
/* If the item is not found, nothing is done.                               */

static void clear_device_item(struct rsbac_device_list_item_t *item_p)
{
	if (!item_p)
		return;

	/* dput() rsbac_dir_dentry_p, if set */
	if (item_p->rsbac_dir_dentry_p) {
		dput(item_p->rsbac_dir_dentry_p);
	}
	/* OK, lets remove the device item itself */
	rsbac_sfree(device_item_slab, item_p);
}

/* remove_device_item unlocks device_list_locks[hash]! */
static void remove_device_item(kdev_t kdev)
{
	struct rsbac_device_list_item_t *item_p;
	u_int hash;
               
	hash = device_hash(kdev);
	/* first we must locate the item. */
	if ((item_p = lookup_device(kdev, hash))) {	/* ok, item was found */
		struct rsbac_device_list_head_t * new_p;
		struct rsbac_device_list_head_t * old_p;

		old_p = device_head_p[hash];
		new_p = rsbac_kmalloc(sizeof(*new_p));
		if (!new_p) {
			/* Ouch! */
			spin_unlock(&device_list_locks[hash]);
			return;
		}
		*new_p = *old_p;
		if (new_p->head == item_p) {	/* item is head */
			if (new_p->tail == item_p) {	/* item is head and tail = only item -> list will be empty */
				new_p->head = NULL;
				new_p->tail = NULL;
			} else {	/* item is head, but not tail -> next item becomes head */
				item_p->next->prev = NULL;
				new_p->head = item_p->next;
			}
		} else {	/* item is not head */
			if (new_p->tail == item_p) {	/*item is not head, but tail -> previous item becomes tail */
				item_p->prev->next = NULL;
				new_p->tail = item_p->prev;
			} else {	/* item is neither head nor tail -> item is cut out */
				item_p->prev->next = item_p->next;
				item_p->next->prev = item_p->prev;
			}
		}

		/* curr is no longer valid -> reset.                              */
		new_p->curr = NULL;
		/* adjust counter */
		new_p->count--;
		rcu_assign_pointer(device_head_p[hash], new_p);
		spin_unlock(&device_list_locks[hash]);
		synchronize_srcu(&device_list_srcu[hash]);
		rsbac_kfree(old_p);
	} else {
		spin_unlock(&device_list_locks[hash]);
	}
}

/**************************************************/
/*       Externally visible help functions        */
/**************************************************/

/* helper, copied from open.d/do_truncate() */
static int rsbac_clear_file(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int error;
	struct iattr newattrs;

	mutex_lock(&inode->i_mutex);
	newattrs.ia_size = 0;
	newattrs.ia_valid = ATTR_SIZE | ATTR_CTIME;
	error = notify_change(dentry, &newattrs);
	mutex_unlock(&inode->i_mutex);
	return error;
}

static void wakeup_auto(u_long dummy)
{
	wake_up((void *) dummy);
}

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_check_device);
#endif

int rsbac_check_device(kdev_t kdev)
{
	struct rsbac_device_list_item_t *device_p;
	u_int hash;
	int srcu_idx;

	hash = device_hash(kdev);
	srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
	device_p = lookup_device(kdev, hash);
	srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
	if (device_p)
		return 0;
	else
		return -RSBAC_ENOTFOUND;
}

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_get_vfsmount);
#endif
struct vfsmount *rsbac_get_vfsmount(kdev_t kdev)
{
	struct rsbac_device_list_item_t *device_p;
	struct vfsmount *mnt_p;
	u_int hash;
	int srcu_idx;

	if (RSBAC_IS_AUTO_DEV(kdev))
		return NULL;

	hash = device_hash(kdev);
	/* get super_block-pointer */
	srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
	device_p = lookup_device(kdev, hash);
	if (!device_p) {
#if 0
		DECLARE_WAIT_QUEUE_HEAD(auto_wait);
		struct timer_list auto_timer;

		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);

		rsbac_printk(KERN_INFO "rsbac_get_vfsmount(): device %02u:%02u not yet available, sleeping\n",
			     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
		init_timer(&auto_timer);
		auto_timer.function = wakeup_auto;
		auto_timer.data = (u_long) & auto_wait;
		auto_timer.expires = jiffies + HZ;
		add_timer(&auto_timer);
		interruptible_sleep_on(&auto_wait);

		srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
		device_p = lookup_device(kdev, hash);
		if (!device_p) {
#endif
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			rsbac_printk(KERN_WARNING "rsbac_get_vfsmount(): unknown device %02u:%02u\n",
				     RSBAC_MAJOR(kdev),
				     RSBAC_MINOR(kdev));
			return NULL;
#if 0
		}
#endif
	}
	mnt_p = device_p->mnt_p;
	srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
	return mnt_p;
}

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_read_open);
#endif
int rsbac_read_open(char *name, struct file **file_pi, kdev_t kdev)
{
	struct dentry *dir_dentry_p;
	struct dentry *file_dentry_p;
	struct file *file_p;
	struct path path;
	int err;
	struct vfsmount *mnt_p;

	if (!name || !file_pi) {
		rsbac_pr_debug(ds, "called with NULL pointer!");
		return -RSBAC_EINVALIDPOINTER;
	}

	mnt_p = rsbac_get_vfsmount(kdev);
	if (!mnt_p) {
		rsbac_printk(KERN_WARNING "rsbac_read_open(): invalid device %02u:%02u\n",
			     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
		return -RSBAC_EINVALIDDEV;
	}
	/* lookup dentry of ACI_PATH on root device, lock is released there */
	if ((err =
	     lookup_aci_path_dentry(mnt_p, &dir_dentry_p, FALSE, kdev))) {
		return err;
	}

	/* open file for reading - this must be done 'by hand', because     */
	/* standard system calls are now extended by rsbac decision calls.  */
	file_dentry_p =
	    rsbac_lookup_one_len(name, dir_dentry_p, strlen(name));

	if (!file_dentry_p || IS_ERR(file_dentry_p)) {	/* error in lookup */
		return -RSBAC_EREADFAILED;
	}
	if (!file_dentry_p->d_inode || !file_dentry_p->d_inode->i_size) {
		/* file not found or empty: trying backup */
		char *bname;
		int name_len = strlen(name);

		dput(file_dentry_p);
		bname = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (!bname) {
			return -RSBAC_ENOMEM;
		}

		strcpy(bname, name);
		bname[name_len] = 'b';
		name_len++;
		bname[name_len] = (char) 0;
		rsbac_pr_debug(ds, "could not lookup file %s, trying backup %s\n",
			     name, bname);
		file_dentry_p =
		    rsbac_lookup_one_len(bname, dir_dentry_p,
					 strlen(bname));
		rsbac_kfree(bname);
		if (!file_dentry_p || IS_ERR(file_dentry_p)) {	/* error in lookup */
			return -RSBAC_EREADFAILED;
		}
		if (!file_dentry_p->d_inode || !file_dentry_p->d_inode->i_size) {
			/* backup file also not found: return error */
			rsbac_pr_debug(ds, "backup file %sb not found or empty\n",
				       name);
			dput(file_dentry_p);
			return -RSBAC_ENOTFOUND;
		}
	}
	if (!(S_ISREG(file_dentry_p->d_inode->i_mode))) {	/* this is not a file! -> error! */
		rsbac_printk(KERN_WARNING "rsbac_read_open(): expected file is not a file!\n");
		dput(file_dentry_p);
		return -RSBAC_EREADFAILED;
	}

	/* Now we fill the file structure and */
	/* if there is an open func for this file, use it, otherwise ignore */
	path.dentry = file_dentry_p;
	path.mnt = mntget(mnt_p);
	file_p = alloc_file(&path, FMODE_READ, path.dentry->d_inode->i_fop);

	if (!file_p) {
		path_put(&path);
		rsbac_printk(KERN_WARNING "rsbac_read_open(): could not open file '%s'!\n",
			     name);
		return -RSBAC_EREADFAILED;
	}

	/* if there is no read func, we get a problem -> error */
	if ((!file_p->f_op) || (!file_p->f_op->read)) {
		if (!file_p->f_op) {
			rsbac_printk(KERN_WARNING "rsbac_read_open(): no f_op for file '%s'!\n",
				     name);
		} else {
			rsbac_printk(KERN_WARNING "rsbac_read_open(): no file read func for file '%s'!\n",
				     name);
			if (file_p->f_op->release)
				file_p->f_op->release(path.dentry->
						      d_inode, file_p);
		}
		path_put(&path);
		return -RSBAC_EREADFAILED;
	}

	*file_pi = file_p;

	if (file_p->f_op->open)
		return file_p->f_path.dentry->d_inode->i_fop->open(path.dentry->d_inode, file_p);
	else
		return 0;
}

#ifndef check_parent
#define check_parent(dir, dentry) \
	((dir) == (dentry)->d_parent && !list_empty(&dentry->d_bucket))
#endif

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_write_open);
#endif
int rsbac_write_open(char *name, struct file **file_pi, kdev_t kdev)
{
	struct dentry *dir_dentry_p = NULL;
	struct dentry *ldir_dentry_p = NULL;
	struct dentry *file_dentry_p = NULL;
	struct file * file_p;
	struct path path;
	int err = 0;
	int tmperr = 0;
	struct vfsmount *mnt_p;

	if (!file_pi || !name) {
		rsbac_pr_debug(write, "called with NULL pointer!\n");
		return -RSBAC_EINVALIDPOINTER;
	}

	/* get super_block-pointer */
	mnt_p = rsbac_get_vfsmount(kdev);
	if (!mnt_p) {
		rsbac_printk(KERN_WARNING "rsbac_write_open(): invalid device %02u:%02u\n",
			     RSBAC_MAJOR(kdev), RSBAC_MINOR(kdev));
		return -RSBAC_EINVALIDDEV;
	}
	if (!rsbac_writable(mnt_p->mnt_sb)) {
		rsbac_pr_debug(write, "called for non-writable device\n");
		return -RSBAC_ENOTWRITABLE;
	}

	err = mnt_want_write(mnt_p);
	if (err)
		return err;

	/* lookup dentry of ACI_PATH on this device (create, if needed and possible),
	 * returns errorcode, if failed */
	if ((tmperr = lookup_aci_path_dentry(mnt_p, &dir_dentry_p, TRUE,
					     kdev))) {
		err = tmperr;
		goto out;
	}

	/* open file for reading - this must be done 'by hand', because     */
	/* standard system calls are now extended by rsbac decision calls.  */
	file_dentry_p =
	    rsbac_lookup_one_len(name, dir_dentry_p, strlen(name));
	if (!file_dentry_p || IS_ERR(file_dentry_p)) {
		rsbac_pr_debug(write, "lookup of %s returned error %li\n",
			     name, PTR_ERR(file_dentry_p));
		err = -RSBAC_EWRITEFAILED;
		goto out;
	}
#if 1
	if (file_dentry_p->d_inode) {	/* file was found: try to rename it as backup file */
		if (!dir_dentry_p->d_inode->i_op
		    || !dir_dentry_p->d_inode->i_op->rename) {
			rsbac_printk(KERN_WARNING "rsbac_write_open(): File system supports no rename - no backup of %s made!",
				     name);
		} else {
			char *bname;
			int name_len = strlen(name);
			struct dentry *new_file_dentry_p = NULL;
			struct dentry *old_dir_p, *new_dir_p;

			bname = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (!bname) {
				err = -RSBAC_ENOMEM;
				goto out_dput;
			}
			strcpy(bname, name);
			bname[name_len] = 'b';
			bname[name_len + 1] = (char) 0;
			mutex_lock(&dir_dentry_p->d_inode->i_mutex);
			new_file_dentry_p =
			    rsbac_lookup_one_len(bname, dir_dentry_p,
						 strlen(bname));
			mutex_unlock(&dir_dentry_p->d_inode->i_mutex);
			if (new_file_dentry_p
			    && !IS_ERR(new_file_dentry_p)) {
				/* lock parent == rsbac-dir for rest of rename */
				old_dir_p = dget(file_dentry_p->d_parent);
				new_dir_p =
				    dget(new_file_dentry_p->d_parent);
				double_lock(new_dir_p, old_dir_p);
				dquot_initialize(old_dir_p->d_inode);
				dquot_initialize(new_dir_p->d_inode);
				/* try to rename file in rsbac dir */
				/* rsbac_pr_debug(write, "calling rename function\n"); */
				err =
				    dir_dentry_p->d_inode->i_op->
				    rename(old_dir_p->d_inode,
					   file_dentry_p,
					   new_dir_p->d_inode,
					   new_file_dentry_p);
				/* unlock dir (dputs both dentries) */
				double_unlock(new_dir_p, old_dir_p);
				if (err) {
					rsbac_printk(KERN_WARNING "rsbac_write_open(): could not rename %s to %s on dev %02u:%02u, error %i - no backup!\n",
						     name, bname,
						     RSBAC_MAJOR(kdev),
						     RSBAC_MINOR(kdev),
						     err);
				} else {
					/* The following d_move() should become unconditional */
					if (!
					    (mnt_p->mnt_sb->s_type->
					     fs_flags
					      & FS_RENAME_DOES_D_MOVE
					    ))
						d_move(file_dentry_p,
						       new_file_dentry_p);
					fsnotify_create(old_dir_p->d_inode,
							new_file_dentry_p);
				}
				dput(new_file_dentry_p);
				dput(file_dentry_p);
				/* re-init dentry structure */
				mutex_lock(&dir_dentry_p->d_inode->i_mutex);
				file_dentry_p =
				    rsbac_lookup_one_len(name,
							 dir_dentry_p,
							 strlen(name));
				mutex_unlock(&dir_dentry_p->d_inode->i_mutex);
				if (!file_dentry_p
				    || IS_ERR(file_dentry_p)) {
					rsbac_pr_debug(write, "relookup of %s "
						       "returned error %li\n",
						       name,
						       PTR_ERR(file_dentry_p));
					err = -RSBAC_EWRITEFAILED;
					goto out;
				}
				if (file_dentry_p->d_inode) {
					rsbac_printk(KERN_WARNING "rsbac_write_open(): relookup of %s returned dentry with existing inode %li, trying unlink\n",
						     name,
						     file_dentry_p->
						     d_inode->i_ino);
					/* file was found: try to delete it */
					if (!dir_dentry_p->d_inode->i_op
					    || !dir_dentry_p->d_inode->
					    i_op->unlink) {
						rsbac_printk(KERN_WARNING "rsbac_write_open(): File system supports no unlink - %s not deleted!",
							     name);
						rsbac_kfree(bname);
						err = -RSBAC_EWRITEFAILED;
						goto out_dput;
					} else {
						old_dir_p =
						    lock_parent
						    (file_dentry_p);
						dquot_initialize(old_dir_p->d_inode);
						err = -ENOENT;
							err =
							    dir_dentry_p->
							    d_inode->i_op->
							    unlink
							    (old_dir_p->
							     d_inode,
							     file_dentry_p);
						/* unlock parent dir */
						unlock_dir(old_dir_p);
						/* free file dentry */
						dput(file_dentry_p);
						if (err) {
							rsbac_printk
							    (KERN_WARNING
							     "rsbac_write_open(): could not unlink %s on dev %02u:%02u, error %i!\n",
							     name,
							     RSBAC_MAJOR
							     (kdev),
							     RSBAC_MINOR
							     (kdev), err);
						}
						/* re-init dentry structure */
						file_dentry_p =
						    rsbac_lookup_one_len
						    (name, dir_dentry_p,
						     strlen(name));
						if (!file_dentry_p
						    ||
						    IS_ERR(file_dentry_p)) {
							rsbac_pr_debug(write, "relookup of %s returned error %li\n",
								       name,
								       PTR_ERR(file_dentry_p));
							rsbac_kfree(bname);
							err =
							    -RSBAC_EWRITEFAILED;
							goto out;
						}
						if (file_dentry_p->d_inode) {
							rsbac_printk
							    (KERN_WARNING
							     "rsbac_write_open(): relookup of %s returned dentry with existing inode %li\n",
							     name,
							     file_dentry_p->
							     d_inode->
							     i_ino);
							rsbac_kfree(bname);
							err =
							    -RSBAC_EWRITEFAILED;
							goto out_dput;
						}
					}
				}
			} else {
				rsbac_printk(KERN_WARNING "rsbac_write_open(): rsbac_lookup_(dentry|one) for backup file %s on dev %02u:%02u failed with error %li - no backup!\n",
					     bname, RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev),
					     PTR_ERR(new_file_dentry_p));
			}
			rsbac_kfree(bname);
		}
	}
#endif				/* backup part */

	if (!file_dentry_p->d_inode) {
		/* file not found or renamed away: try to create a new one */
		if (!dir_dentry_p->d_inode->i_op
		    || !dir_dentry_p->d_inode->i_op->create) {
			rsbac_printk(KERN_WARNING "%s\n",
				     "rsbac_write_open(): File system supports no create!");
			err = -RSBAC_EWRITEFAILED;
			goto out_dput;
		}

		/* lock parent == rsbac-dir for create */
		ldir_dentry_p = lock_parent(file_dentry_p);
		if (IS_ERR(ldir_dentry_p)) {
			rsbac_pr_debug(write, "lock_parent of %s returned "
				       "error %li\n", name,
				       PTR_ERR(ldir_dentry_p));
			err = -RSBAC_EWRITEFAILED;
			goto out_dput;
		}
		/* try to create file in rsbac dir */
		/* rsbac_pr_debug(write, "calling create function\n"); */
		dquot_initialize(ldir_dentry_p->d_inode);
		err =
		    dir_dentry_p->d_inode->i_op->create(ldir_dentry_p->
							d_inode,
							file_dentry_p,
							RSBAC_ACI_FILE_MODE,
							NULL);
		unlock_dir(ldir_dentry_p);

		if (err) {
			goto out_dput;
		}
		/* create was successful */
	}

	if (!(S_ISREG(file_dentry_p->d_inode->i_mode))) {	/* this is not a file! -> error! */
		rsbac_printk(KERN_WARNING "rsbac_write_open(): expected file is not a file, mode is %o!\n",
			     file_dentry_p->d_inode->i_mode);
		err = -RSBAC_EWRITEFAILED;
		goto out_dput;
	}
	/* Without a write function we get into troubles -> error */
	if ((!file_dentry_p->d_inode->i_fop) || (!file_dentry_p->d_inode->i_fop->write)) {
		rsbac_printk(KERN_WARNING "rsbac_write_open(): file write function missing!\n");
		err = -RSBAC_EWRITEFAILED;
		goto out_dput;
	}

	/* file alloc will call mnt_want_write */
	mnt_drop_write(mnt_p);

	if ((tmperr = get_write_access(file_dentry_p->d_inode))) {
		rsbac_printk(KERN_WARNING "rsbac_write_open(): could not get write access on file!\n");
		dput(file_dentry_p);
		return -RSBAC_EWRITEFAILED;
	}

	/* Now we fill the file structure, file_take_write, mnt_want_write */
	path.dentry = file_dentry_p;
	path.mnt = mntget(mnt_p);
	file_p = alloc_file(&path, FMODE_WRITE, path.dentry->d_inode->i_fop);
	if (!file_p) {
		rsbac_printk(KERN_WARNING "rsbac_write_open(): could not init file!\n");
		put_write_access(file_p->f_dentry->d_inode);
		file_release_write(file_p);
		path_put(&path);
		return -RSBAC_EWRITEFAILED;
	}

	/* truncating */
	if (rsbac_clear_file(file_dentry_p)) {
		if (file_p->f_op->release)
			file_p->f_op->release(file_dentry_p->d_inode,
					      file_p);
		rsbac_printk(KERN_WARNING "rsbac_write_open(): could not truncate!\n");
		err = -RSBAC_EWRITEFAILED;
		put_write_access(file_p->f_dentry->d_inode);
		file_release_write(file_p);
		goto out_dput;
	}
	/* set synchronous mode for this file */
	file_p->f_flags |= O_SYNC;
	*file_pi = file_p;

out:
	if (err)
		mnt_drop_write(mnt_p);
	return err;

out_dput:
	dput(file_dentry_p);
	goto out;
}


#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_read_close);
#endif
void rsbac_read_close(struct file *file_p)
{
	/* cleanup copied from __fput */
	if (file_p->f_op && file_p->f_op->release)
		file_p->f_op->release(file_p->f_dentry->d_inode, file_p);
	path_put(&file_p->f_path);
	put_filp(file_p);
}

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_write_close);
#endif
void rsbac_write_close(struct file *file_p)
{
	put_write_access(file_p->f_dentry->d_inode);
	mnt_drop_write(file_p->f_path.mnt);
	file_release_write(file_p);
	rsbac_read_close(file_p);
}

#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_lookup_full_path);
#endif
int rsbac_lookup_full_path(struct dentry *dentry_p, char path[], int maxlen, int pseudonymize)
{
	int len = 0;
	char *i_path;
	int tmplen = 0;
#ifdef CONFIG_RSBAC_LOG_PSEUDO_FS
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val;
#endif
	int srcu_idx;

	if (!dentry_p || !path)
		return -RSBAC_EINVALIDPOINTER;
	if (maxlen <= 0)
		return -RSBAC_EINVALIDVALUE;
	i_path = rsbac_kmalloc(maxlen + RSBAC_MAXNAMELEN);
	if (!i_path)
		return -RSBAC_ENOMEM;

	path[0] = 0;

	while (dentry_p && (len < maxlen) && dentry_p->d_name.len
	       && dentry_p->d_name.name) {
#ifdef CONFIG_RSBAC_LOG_PSEUDO_FS
		if (   pseudonymize
		    && dentry_p->d_inode
		    && dentry_p->d_parent
		    && dentry_p->d_parent->d_inode
		    && (i_tid.user = dentry_p->d_inode->i_uid)
		    && (dentry_p->d_inode->i_uid !=
			dentry_p->d_parent->d_inode->i_uid)
		    && !rsbac_get_attr(SW_GEN, T_USER, i_tid, A_pseudo,
				       &i_attr_val, FALSE)
		    && i_attr_val.pseudo) {	/* Max len of 32 Bit value in decimal print is 11 */
			if ((maxlen - len) < 12) {
				rsbac_kfree(i_path);
				return len;
			}
			tmplen =
			    snprintf(i_path, 11, "%u", i_attr_val.pseudo);
		} else
#endif
		{
			tmplen = dentry_p->d_name.len;
			if ((tmplen + 1) > (maxlen - len)) {
				rsbac_kfree(i_path);
				return len;
			}
			strncpy(i_path, dentry_p->d_name.name, tmplen);
		}
		/* Skip double / on multi mounts.
		 * Last / is appended at the end of the function */
		if((i_path[tmplen-1] != '/') && (tmplen != 1)) {
			if(len && (i_path[tmplen-1] != '/')) {
				i_path[tmplen] = '/';
				tmplen++;
			}
			i_path[tmplen]=0;
			strcat(i_path, path);
			strcpy(path, i_path);
			len += tmplen;
		}
		if (dentry_p->d_parent && (dentry_p->d_parent != dentry_p)
		    && (dentry_p->d_sb->s_root != dentry_p)
		    )
			dentry_p = dentry_p->d_parent;
		else {
			struct rsbac_device_list_item_t *device_p;
			u_int hash;

			if (dentry_p->d_sb->s_dev == rsbac_root_dev) {
				break;
			}
			hash = device_hash(dentry_p->d_sb->s_dev);
			srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
			device_p = lookup_device(dentry_p->d_sb->s_dev, hash);
			if (   device_p
			    && device_p->mnt_p
		            && (device_p->mnt_p->mnt_mountpoint->d_sb->s_dev != dentry_p->d_sb->s_dev)
			   ) {
				dentry_p = device_p->mnt_p->mnt_mountpoint;
				srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			} else {
				srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
				break;
			}
		}
	}
	
	i_path[tmplen]=0;
	strcat(i_path, path);
	strcpy(path, i_path);
	
	rsbac_kfree(i_path);
	return len;
}

/************************************************* */
/*               proc fs functions                 */
/************************************************* */

#if defined(CONFIG_RSBAC_PROC)
static int
devices_proc_show(struct seq_file *m, void *v)
{
	struct rsbac_device_list_item_t *device_p;
	u_int count = 0;
	u_int i;
	char tmp[RSBAC_MAXNAMELEN];
	int srcu_idx;

	if (!rsbac_initialized)
		return -ENOSYS;

	for (i = 0; i < RSBAC_NR_DEVICE_LISTS; i++)
		count += rcu_dereference(device_head_p[i])->count;
	seq_printf(m, "%u RSBAC Devices\n---------------\nHash size is %u\n",
		       count, RSBAC_NR_DEVICE_LISTS);

	for (i = 0; i < RSBAC_NR_DEVICE_LISTS; i++) {
		srcu_idx = srcu_read_lock(&device_list_srcu[i]);
		for (device_p = rcu_dereference(device_head_p[i])->head; device_p;
		     device_p = device_p->next) {
			if (device_p->mnt_p && device_p->mnt_p->mnt_sb
			    && device_p->mnt_p->mnt_sb->s_type
			    && device_p->mnt_p->mnt_sb->s_type->name) {
				if (device_p->mnt_p->mnt_mountpoint) {
				        if (device_p->mnt_p->mnt_mountpoint->d_sb->s_dev == device_p->mnt_p->mnt_sb->s_dev)
				        	sprintf(tmp, "none");
					else
						strncpy(tmp, device_p->mnt_p->mnt_mountpoint->d_name.name, RSBAC_MAXNAMELEN - 1);
				} else
					sprintf(tmp, "unknown");
				seq_printf(m,
					    "%02u:%02u with mount_count %u, fs_type %s (%lx), mountpoint %s, parent %02u:%02u\n",
					    RSBAC_MAJOR(device_p->id),
					    RSBAC_MINOR(device_p->id),
					    device_p->mount_count,
					    device_p->mnt_p->mnt_sb->s_type->name,
					    device_p->mnt_p->mnt_sb->s_magic,
					    tmp,
					    RSBAC_MAJOR(device_p->mnt_p->mnt_mountpoint->d_sb->s_dev),
					    RSBAC_MINOR(device_p->mnt_p->mnt_mountpoint->d_sb->s_dev));
			} else
				    seq_printf(m,
					    "%02u:%02u with mount_count %u, no mnt_p\n",
					    RSBAC_MAJOR(device_p->id),
					    RSBAC_MINOR(device_p->id),
					    device_p->mount_count);
		}
		srcu_read_unlock(&device_list_srcu[i], srcu_idx);
	}
	return 0;
}

static int devices_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, devices_proc_show, NULL);
}

static const struct file_operations devices_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = devices_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *devices;

static int
stats_proc_show(struct seq_file *m, void *v)
{
	struct rsbac_device_list_item_t *device_p;
	long fd_count, fd_dev_count;
	u_long fd_sum = 0;
	u_long sum = 0;
	u_long total_sum = 0;
	long tmp_count;
	int i;
	int srcu_idx;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}
#ifdef CONFIG_RSBAC_MAINT
	seq_printf(m,
		    "RSBAC Status\n------------\nRSBAC Version: %s (Maintenance Mode)\nSupported Modules:%s\n",
		    RSBAC_VERSION, compiled_modules);
#else
	seq_printf(m,
		    "RSBAC Status\n------------\nRSBAC Version: %s\nCompiled Modules:%s\n",
		    RSBAC_VERSION, compiled_modules);
#endif
#ifdef CONFIG_RSBAC_SWITCH
	{
		char *active_modules;

		active_modules = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (active_modules) {
			active_modules[0] = (char) 0;
#ifdef CONFIG_RSBAC_REG
			strcat(active_modules, " REG");
#endif
#ifdef CONFIG_RSBAC_MAC
#ifdef CONFIG_RSBAC_SWITCH_MAC
			if (rsbac_switch_mac)
#endif
#ifdef CONFIG_RSBAC_MAC_LIGHT
				strcat(active_modules, " MAC-L");
#else
				strcat(active_modules, " MAC");
#endif
#endif
#ifdef CONFIG_RSBAC_PM
#ifdef CONFIG_RSBAC_SWITCH_PM
			if (rsbac_switch_pm)
#endif
				strcat(active_modules, " PM");
#endif
#ifdef CONFIG_RSBAC_DAZ
#ifdef CONFIG_RSBAC_SWITCH_DAZ
			if (rsbac_switch_daz)
#endif
				strcat(active_modules, " DAZ");
#endif
#ifdef CONFIG_RSBAC_FF
#ifdef CONFIG_RSBAC_SWITCH_FF
			if (rsbac_switch_ff)
#endif
				strcat(active_modules, " FF");
#endif
#ifdef CONFIG_RSBAC_RC
#ifdef CONFIG_RSBAC_SWITCH_RC
			if (rsbac_switch_rc)
#endif
				strcat(active_modules, " RC");
#endif
#ifdef CONFIG_RSBAC_AUTH
#ifdef CONFIG_RSBAC_SWITCH_AUTH
			if (rsbac_switch_auth)
#endif
				strcat(active_modules, " AUTH");
#endif
#ifdef CONFIG_RSBAC_ACL
#ifdef CONFIG_RSBAC_SWITCH_ACL
			if (rsbac_switch_acl)
#endif
				strcat(active_modules, " ACL");
#endif
#ifdef CONFIG_RSBAC_CAP
#ifdef CONFIG_RSBAC_SWITCH_CAP
			if (rsbac_switch_cap)
#endif
				strcat(active_modules, " CAP");
#endif
#ifdef CONFIG_RSBAC_JAIL
#ifdef CONFIG_RSBAC_SWITCH_JAIL
			if (rsbac_switch_jail)
#endif
				strcat(active_modules, " JAIL");
#endif
#ifdef CONFIG_RSBAC_RES
#ifdef CONFIG_RSBAC_SWITCH_RES
			if (rsbac_switch_res)
#endif
				strcat(active_modules, " RES");
#endif
#ifdef CONFIG_RSBAC_PAX
#ifdef CONFIG_RSBAC_SWITCH_PAX
			if (rsbac_switch_pax)
#endif
				strcat(active_modules, " PAX");
#endif
			seq_printf(m, "Active Modules:  %s\n",
				    active_modules);
			rsbac_kfree(active_modules);
		}
	}
#else
	seq_printf(m, "All modules active (no switching)\n");
#endif

#ifdef CONFIG_RSBAC_SOFTMODE
	if (rsbac_softmode) {
#ifdef CONFIG_RSBAC_SOFTMODE_IND
		seq_printf(m, "Global softmode is enabled\n");
#else
		seq_printf(m, "Softmode is enabled\n");
#endif
	} else {
#ifdef CONFIG_RSBAC_SOFTMODE_IND
		seq_printf(m, "Global softmode is disabled\n");
#else
		seq_printf(m, "Softmode is disabled\n");
#endif
	}
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	{
		char *tmp;

		tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
		if (tmp) {
			  seq_printf(m,
				    "Individual softmode enabled for:");
			for (i = 0; i <= RSBAC_MAX_MOD; i++)
				if (rsbac_ind_softmode[i])
					 seq_printf(m, " %s",
						    get_switch_target_name
						    (tmp, i));
			rsbac_kfree(tmp);
			seq_printf(m, "\n");
		}
	}
#endif
#endif

	seq_printf(m, "\n");

	tmp_count = 0;
	for (i = 0; i < RSBAC_NR_DEVICE_LISTS; i++) {
		srcu_idx = srcu_read_lock(&device_list_srcu[i]);
		device_p = rcu_dereference(device_head_p[i])->head;
		if (device_p)
			seq_printf(m, "FD items:\n");
		while (device_p) {
			fd_dev_count = 0;
			fd_count = rsbac_list_count(device_p->handles.gen);
			if (fd_count >= 0) {
				seq_printf(m, "Dev %02u:%02u: %lu GEN",
						RSBAC_MAJOR(device_p->id),
						RSBAC_MINOR(device_p->id),
						fd_count);
				fd_dev_count += fd_count;
			}

#if defined(CONFIG_RSBAC_MAC)
			fd_count = rsbac_list_count(device_p->handles.mac);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu MAC", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_PM)
			fd_count = rsbac_list_count(device_p->handles.pm);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu PM", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_DAZ)
			fd_count = rsbac_list_count(device_p->handles.daz);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu DAZ", fd_count);
				fd_dev_count += fd_count;
			}
#if defined(CONFIG_RSBAC_DAZ_CACHE)
			fd_count = rsbac_list_count(device_p->handles.dazs);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu DAZ SCANNED", fd_count);
				fd_dev_count += fd_count;
			}
#endif
#endif

#if defined(CONFIG_RSBAC_FF)
			fd_count = rsbac_list_count(device_p->handles.ff);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu FF", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_RC)
			fd_count = rsbac_list_count(device_p->handles.rc);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu RC", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_AUTH)
			fd_count = rsbac_list_count(device_p->handles.auth);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu AUTH", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_CAP)
			fd_count = rsbac_list_count(device_p->handles.cap);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu CAP", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_RES)
			fd_count = rsbac_list_count(device_p->handles.res);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu RES", fd_count);
				fd_dev_count += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_PAX)
			fd_count = rsbac_list_count(device_p->handles.pax);
			if (fd_count >= 0) {
				seq_printf(m, ", %lu PAX", fd_count);
				fd_dev_count += fd_count;
			}
#endif

			seq_printf(m, ", %lu total\n",
				       fd_dev_count);
			fd_sum += fd_dev_count;
			device_p = device_p->next;
		}
		tmp_count += rcu_dereference(device_head_p[i])->count;
		srcu_read_unlock(&device_list_srcu[i], srcu_idx);
	}
	seq_printf(m,
		    "Sum of %lu Devices with %lu fd-items\n\n",
		    tmp_count, fd_sum);
	total_sum += fd_sum;
	/* dev lists */
	sum = 0;
	tmp_count = rsbac_list_count(dev_handles.gen);
	seq_printf(m, "DEV: %lu GEN", tmp_count);
	sum += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(dev_handles.mac);
	seq_printf(m, ", %lu MAC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(dev_handles.pm);
	seq_printf(m, ", %lu PM", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(dev_major_handles.rc);
	seq_printf(m, ", %lu major RC", tmp_count);
	sum += tmp_count;
	tmp_count = rsbac_list_count(dev_handles.rc);
	seq_printf(m, ", %lu RC", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, ", %lu total\n", sum);
	total_sum += sum;
	/* ipc lists */
	sum = 0;
	seq_printf(m, "IPC: 0 GEN");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(ipc_handles.mac);
	seq_printf(m, ", %lu MAC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(ipc_handles.pm);
	seq_printf(m, ", %lu PM", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(ipc_handles.rc);
	seq_printf(m, ", %lu RC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_list_count(ipc_handles.jail);
	seq_printf(m, ", %lu JAIL", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, ", %lu total\n", sum);
	total_sum += sum;
	/* user lists */
	sum = 0;
	tmp_count = rsbac_list_count(user_handles.gen);
	seq_printf(m, "USER: %lu GEN", tmp_count);
	sum += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(user_handles.mac);
	seq_printf(m, ", %lu MAC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(user_handles.pm);
	seq_printf(m, ", %lu PM", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_DAZ)
	tmp_count = rsbac_list_count(user_handles.daz);
	seq_printf(m, ", %lu DAZ", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_FF)
	tmp_count = rsbac_list_count(user_handles.ff);
	seq_printf(m, ", %lu FF", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(user_handles.rc);
	seq_printf(m, ", %lu RC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	tmp_count = rsbac_list_count(user_handles.auth);
	seq_printf(m, ", %lu AUTH", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_CAP)
	tmp_count = rsbac_list_count(user_handles.cap);
	seq_printf(m, ", %lu CAP", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_list_count(user_handles.jail);
	seq_printf(m, ", %lu JAIL", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RES)
	tmp_count = rsbac_list_count(user_handles.res);
	seq_printf(m, ", %lu RES", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PAX)
	tmp_count = rsbac_list_count(user_handles.pax);
	seq_printf(m, ", %lu PAX", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, ", %lu total\n", sum);
	total_sum += sum;
	/* process lists */
	sum = 0;
	tmp_count = rsbac_list_count(process_handles.gen);
	seq_printf(m, "PROCESS: %lu GEN", tmp_count);
	sum += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(process_handles.mac);
	seq_printf(m, ", %lu MAC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(process_handles.pm);
	seq_printf(m, ", %lu PM", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_DAZ)
	tmp_count = rsbac_list_count(process_handles.daz);
	seq_printf(m, ", %lu DAZ", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(process_handles.rc);
	seq_printf(m, ", %lu RC", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	tmp_count = rsbac_list_count(process_handles.auth);
	seq_printf(m, ", %lu AUTH", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_CAP)
	tmp_count = rsbac_list_count(process_handles.cap);
	seq_printf(m, ", %lu CAP", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_list_count(process_handles.jail);
	seq_printf(m, ", %lu JAIL", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, ", %lu total\n", sum);
	total_sum += sum;
#if defined(CONFIG_RSBAC_UM)
	/* group lists */
	sum = 0;
	seq_printf(m, "GROUP:");
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	tmp_count = rsbac_list_count(group_handles.rc);
	seq_printf(m, " %lu RC,", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, " %lu total\n", sum);
	total_sum += sum;
#endif

#if defined(CONFIG_RSBAC_NET_DEV)
	/* netdev lists */
	sum = 0;
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	tmp_count = rsbac_list_count(netdev_handles.gen);
	seq_printf(m, "NETDEV: %lu GEN, ", tmp_count);
	sum += tmp_count;
#else
	seq_printf(m, "NETDEV: ");
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(netdev_handles.rc);
	seq_printf(m, "%lu RC, ", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, "%lu total\n", sum);
	total_sum += sum;
#endif

#if defined(CONFIG_RSBAC_NET_OBJ)
	/* net template list */
	tmp_count = rsbac_list_count(net_temp_handle);
	seq_printf(m, "%lu Network Templates\n", tmp_count);
	/* nettemp lists */
	sum = 0;
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
	tmp_count = rsbac_list_count(nettemp_handles.gen);
	seq_printf(m, "NETTEMP: %lu GEN, ", tmp_count);
	sum += tmp_count;
#else
	seq_printf(m, "NETTEMP: ");
#endif
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(nettemp_handles.mac);
	seq_printf(m, "%lu MAC, ", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(nettemp_handles.pm);
	seq_printf(m, "%lu PM, ", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(nettemp_handles.rc);
	seq_printf(m, "%lu RC, ", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, "%lu total\n", sum);
	total_sum += sum;
	/* local netobj lists */
	sum = 0;
	seq_printf(m, "LNETOBJ: ");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(lnetobj_handles.mac);
	seq_printf(m, "%lu MAC, ", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(lnetobj_handles.pm);
	seq_printf(m, "%lu PM, ", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(lnetobj_handles.rc);
	seq_printf(m, "%lu RC, ", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, "%lu total\n", sum);
	total_sum += sum;
	/* remote netobj lists */
	sum = 0;
	seq_printf(m, "RNETOBJ: ");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(rnetobj_handles.mac);
	seq_printf(m, "%lu MAC, ", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(rnetobj_handles.pm);
	seq_printf(m, "%lu PM, ", tmp_count);
	sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(rnetobj_handles.rc);
	seq_printf(m, "%lu RC, ", tmp_count);
	sum += tmp_count;
#endif
	seq_printf(m, "%lu total\n", sum);
	total_sum += sum;
#endif				/* NET_OBJ */

	seq_printf(m,
		       "Total sum of %lu registered rsbac-items\n",
		       total_sum);
	seq_printf(m,
		       "\nadf_request calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu\n",
		       rsbac_adf_request_count[T_FILE],
		       rsbac_adf_request_count[T_DIR],
		       rsbac_adf_request_count[T_FIFO],
		       rsbac_adf_request_count[T_SYMLINK],
		       rsbac_adf_request_count[T_DEV],
		       rsbac_adf_request_count[T_IPC],
		       rsbac_adf_request_count[T_SCD],
		       rsbac_adf_request_count[T_USER],
		       rsbac_adf_request_count[T_PROCESS],
		       rsbac_adf_request_count[T_NETDEV],
		       rsbac_adf_request_count[T_NETTEMP],
		       rsbac_adf_request_count[T_NETOBJ],
		       rsbac_adf_request_count[T_GROUP],
		       rsbac_adf_request_count[T_UNIXSOCK]);
	seq_printf(m,
		       "adf_set_attr calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu\n",
		       rsbac_adf_set_attr_count[T_FILE],
		       rsbac_adf_set_attr_count[T_DIR],
		       rsbac_adf_set_attr_count[T_FIFO],
		       rsbac_adf_set_attr_count[T_SYMLINK],
		       rsbac_adf_set_attr_count[T_DEV],
		       rsbac_adf_set_attr_count[T_IPC],
		       rsbac_adf_set_attr_count[T_SCD],
		       rsbac_adf_set_attr_count[T_USER],
		       rsbac_adf_set_attr_count[T_PROCESS],
		       rsbac_adf_set_attr_count[T_NETDEV],
		       rsbac_adf_set_attr_count[T_NETTEMP],
		       rsbac_adf_set_attr_count[T_NETOBJ],
		       rsbac_adf_set_attr_count[T_GROUP],
		       rsbac_adf_set_attr_count[T_UNIXSOCK]);
	return 0;
}

static int stats_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stats_proc_show, NULL);
}

static const struct file_operations stats_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = stats_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *stats;

static int
active_proc_show(struct seq_file *m, void *v)
{
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m, "Version: %s\n", RSBAC_VERSION);
#ifdef CONFIG_RSBAC_MAINT
	seq_printf(m, "Mode: Maintenance\n");
	seq_printf(m, "Softmode: unavailable\n");
#else
#ifdef CONFIG_RSBAC_SOFTMODE
	if (rsbac_softmode)
		seq_printf(m, "Mode: SOFTMODE\n");
	else
#endif
		seq_printf(m, "Mode: Secure\n");
#ifdef CONFIG_RSBAC_SOFTMODE
	seq_printf(m, "Softmode: available\n");
#else
	seq_printf(m, "Softmode: unavailable\n");
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	seq_printf(m, "Ind-Soft: available\n");
#else
	seq_printf(m, "Ind-Soft: unavailable\n");
#endif
#ifdef CONFIG_RSBAC_SWITCH
	seq_printf(m, "Switching off: available for");
#ifdef CONFIG_RSBAC_SWITCH_MAC
#ifndef CONFIG_RSBAC_SWITCH_ON
	if (rsbac_switch_mac)
#endif
		seq_printf(m, " MAC");
#endif
#ifdef CONFIG_RSBAC_SWITCH_PM
#ifndef CONFIG_RSBAC_SWITCH_ON
	if (rsbac_switch_pm)
#endif
		seq_printf(m, " PM");
#endif
#ifdef CONFIG_RSBAC_SWITCH_DAZ
	seq_printf(m, " DAZ");
#endif
#ifdef CONFIG_RSBAC_SWITCH_FF
	seq_printf(m, " FF");
#endif
#ifdef CONFIG_RSBAC_SWITCH_RC
#ifndef CONFIG_RSBAC_SWITCH_ON
	if (rsbac_switch_rc)
#endif
		seq_printf(m, " RC");
#endif
#ifdef CONFIG_RSBAC_SWITCH_AUTH
	seq_printf(m, " AUTH");
#endif
#ifdef CONFIG_RSBAC_SWITCH_ACL
	seq_printf(m, " ACL");
#endif
#ifdef CONFIG_RSBAC_SWITCH_CAP
	seq_printf(m, " CAP");
#endif
#ifdef CONFIG_RSBAC_SWITCH_JAIL
	seq_printf(m, " JAIL");
#endif
#ifdef CONFIG_RSBAC_SWITCH_RES
	seq_printf(m, " RES");
#endif
#ifdef CONFIG_RSBAC_SWITCH_PAX
	seq_printf(m, " PAX");
#endif
	seq_printf(m, "\n");
	seq_printf(m, "Switching on: available for");
#ifdef CONFIG_RSBAC_SWITCH_ON
#ifdef CONFIG_RSBAC_SWITCH_MAC
	seq_printf(m, " MAC");
#endif
#ifdef CONFIG_RSBAC_SWITCH_PM
	seq_printf(m, " PM");
#endif
#ifdef CONFIG_RSBAC_SWITCH_RC
	seq_printf(m, " RC");
#endif
#endif
#ifdef CONFIG_RSBAC_SWITCH_DAZ
	seq_printf(m, " DAZ");
#endif
#ifdef CONFIG_RSBAC_SWITCH_FF
	seq_printf(m, " FF");
#endif
#ifdef CONFIG_RSBAC_SWITCH_AUTH
	seq_printf(m, " AUTH");
#endif
#ifdef CONFIG_RSBAC_SWITCH_ACL
	seq_printf(m, " ACL");
#endif
#ifdef CONFIG_RSBAC_SWITCH_CAP
	seq_printf(m, " CAP");
#endif
#ifdef CONFIG_RSBAC_SWITCH_JAIL
	seq_printf(m, " JAIL");
#endif
#ifdef CONFIG_RSBAC_SWITCH_RES
	seq_printf(m, " RES");
#endif
#ifdef CONFIG_RSBAC_SWITCH_PAX
	seq_printf(m, " PAX");
#endif
	seq_printf(m, "\n");
#else
	seq_printf(m, "Switching off: unavailable\n");
	seq_printf(m, "Switching on: unavailable\n");
#endif
#endif
#ifdef CONFIG_RSBAC_REG
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_REG])
		seq_printf(m, "Module: REG  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: REG  on\n");
#endif

#ifdef CONFIG_RSBAC_MAC
#ifdef CONFIG_RSBAC_SWITCH_MAC
	if (!rsbac_switch_mac)
		seq_printf(m, "Module: MAC  OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_MAC])
		seq_printf(m, "Module: MAC  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: MAC  on\n");
#endif

#ifdef CONFIG_RSBAC_PM
#ifdef CONFIG_RSBAC_SWITCH_PM
	if (!rsbac_switch_pm)
		seq_printf(m, "Module: PM   OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_PM])
		seq_printf(m, "Module: PM   SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: PM   on\n");
#endif

#ifdef CONFIG_RSBAC_DAZ
#ifdef CONFIG_RSBAC_SWITCH_DAZ
	if (!rsbac_switch_daz)
		seq_printf(m, "Module: DAZ  OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_DAZ])
		seq_printf(m, "Module: DAZ  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: DAZ  on\n");
#endif

#ifdef CONFIG_RSBAC_FF
#ifdef CONFIG_RSBAC_SWITCH_FF
	if (!rsbac_switch_ff)
		seq_printf(m, "Module: FF   OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_FF])
		seq_printf(m, "Module: FF   SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: FF   on\n");
#endif

#ifdef CONFIG_RSBAC_RC
#ifdef CONFIG_RSBAC_SWITCH_RC
	if (!rsbac_switch_rc)
		seq_printf(m, "Module: RC   OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_RC])
		seq_printf(m, "Module: RC   SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: RC   on\n");
#endif

#ifdef CONFIG_RSBAC_AUTH
#ifdef CONFIG_RSBAC_SWITCH_AUTH
	if (!rsbac_switch_auth)
		seq_printf(m, "Module: AUTH OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_AUTH])
		seq_printf(m, "Module: AUTH SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: AUTH on\n");
#endif

#ifdef CONFIG_RSBAC_ACL
#ifdef CONFIG_RSBAC_SWITCH_ACL
	if (!rsbac_switch_acl)
		seq_printf(m, "Module: ACL  OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_ACL])
		seq_printf(m, "Module: ACL  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: ACL  on\n");
#endif

#ifdef CONFIG_RSBAC_CAP
#ifdef CONFIG_RSBAC_SWITCH_CAP
	if (!rsbac_switch_cap)
		seq_printf(m, "Module: CAP  OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_CAP])
		seq_printf(m, "Module: CAP  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: CAP  on\n");
#endif

#ifdef CONFIG_RSBAC_JAIL
#ifdef CONFIG_RSBAC_SWITCH_JAIL
	if (!rsbac_switch_jail)
		seq_printf(m, "Module: JAIL OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_JAIL])
		seq_printf(m, "Module: JAIL SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: JAIL on\n");
#endif

#ifdef CONFIG_RSBAC_RES
#ifdef CONFIG_RSBAC_SWITCH_RES
	if (!rsbac_switch_res)
		seq_printf(m, "Module: RES  OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_RES])
		seq_printf(m, "Module: RES  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: RES  on\n");
#endif

#ifdef CONFIG_RSBAC_PAX
#ifdef CONFIG_RSBAC_SWITCH_PAX
	if (!rsbac_switch_pax)
		seq_printf(m, "Module: PAX  OFF\n");
	else
#endif
#ifdef CONFIG_RSBAC_SOFTMODE_IND
	if (rsbac_ind_softmode[SW_PAX])
		seq_printf(m, "Module: PAX  SOFTMODE\n");
	else
#endif
		seq_printf(m, "Module: PAX  on\n");
#endif
	return 0;
}

static int active_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, active_proc_show, NULL);
}

static const struct file_operations active_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = active_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *active;

#ifdef CONFIG_RSBAC_XSTATS
static int
xstats_proc_show(struct seq_file *m, void *v)
{
	int i, j;
	char name[80];
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m,
		       "RSBAC ADF call Statistics\n-------------------------\nadf_request table:\n");
	seq_printf(m,
		    "Request /\tFILE\tDIR\tFIFO\tSYMLINK\tDEV\tIPC\tSCD\tUSER\tPROCESS\tNETDEV\tNETTEMP\tNETOBJ\tGROUP\tUNIXSOCK NONE");

	for (i = 0; i < R_NONE; i++) {
		get_request_name(name, i);
		name[15] = 0;
		seq_printf(m, "\n%-14s\t", name);
		for (j = 0; j <= T_NONE; j++) {
			if ((j == T_NETTEMP_NT)
			    || (j == T_FD)
			    )
				continue;
			seq_printf(m, "%llu\t",
				       rsbac_adf_request_xcount[j][i]);
		}
	}

	seq_printf(m,
		       "\n\nadf_request calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu, none: %llu\n",
		       rsbac_adf_request_count[T_FILE],
		       rsbac_adf_request_count[T_DIR],
		       rsbac_adf_request_count[T_FIFO],
		       rsbac_adf_request_count[T_SYMLINK],
		       rsbac_adf_request_count[T_DEV],
		       rsbac_adf_request_count[T_IPC],
		       rsbac_adf_request_count[T_SCD],
		       rsbac_adf_request_count[T_USER],
		       rsbac_adf_request_count[T_PROCESS],
		       rsbac_adf_request_count[T_NETDEV],
		       rsbac_adf_request_count[T_NETTEMP],
		       rsbac_adf_request_count[T_NETOBJ],
		       rsbac_adf_request_count[T_GROUP],
		       rsbac_adf_request_count[T_UNIXSOCK],
		       rsbac_adf_request_count[T_NONE]);
	seq_printf(m,
		       "\n\nadf_set_attr table:\nRequest /\tFILE\tDIR\tFIFO\tSYMLINK\tDEV\tIPC\tSCD\tUSER\tPROCESS\tNETDEV\tNETTEMP\tNETOBJ\tGROUP\tUNIXSOCK NONE");
	for (i = 0; i < R_NONE; i++) {
		get_request_name(name, i);
		name[15] = 0;
		seq_printf(m, "\n%-14s\t", name);
		for (j = 0; j <= T_NONE; j++) {
			if ((j == T_NETTEMP_NT)
			    || (j == T_FD)
			    )
				continue;
			seq_printf(m, "%llu\t",
				       rsbac_adf_set_attr_xcount[j][i]);
		}
	}

	seq_printf(m,
		       "\n\nadf_set_attr calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu, none: %llu\n",
		       rsbac_adf_set_attr_count[T_FILE],
		       rsbac_adf_set_attr_count[T_DIR],
		       rsbac_adf_set_attr_count[T_FIFO],
		       rsbac_adf_set_attr_count[T_SYMLINK],
		       rsbac_adf_set_attr_count[T_DEV],
		       rsbac_adf_set_attr_count[T_IPC],
		       rsbac_adf_set_attr_count[T_SCD],
		       rsbac_adf_set_attr_count[T_USER],
		       rsbac_adf_set_attr_count[T_PROCESS],
		       rsbac_adf_set_attr_count[T_NETDEV],
		       rsbac_adf_set_attr_count[T_NETTEMP],
		       rsbac_adf_set_attr_count[T_NETOBJ],
		       rsbac_adf_set_attr_count[T_GROUP],
		       rsbac_adf_set_attr_count[T_UNIXSOCK],
		       rsbac_adf_set_attr_count[T_NONE]);
	seq_printf(m,
		    "\nSyscall counts\n-------------\n");

	for (i = 0; i < RSYS_none; i++) {
		get_syscall_name(name, i);
		name[30] = 0;
		seq_printf(m, "%-26s %llu\n",
		               name, syscall_count[i]);
	}

	seq_printf(m,
		       "\n\nData Structures:\nrsbac_get_attr calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu\n",
		       get_attr_count[T_FILE],
		       get_attr_count[T_DIR],
		       get_attr_count[T_FIFO],
		       get_attr_count[T_SYMLINK],
		       get_attr_count[T_DEV],
		       get_attr_count[T_IPC],
		       get_attr_count[T_SCD],
		       get_attr_count[T_USER],
		       get_attr_count[T_PROCESS],
		       get_attr_count[T_NETDEV],
		       get_attr_count[T_NETTEMP],
		       get_attr_count[T_NETOBJ],
		       get_attr_count[T_GROUP],
		       get_attr_count[T_UNIXSOCK]);

	seq_printf(m,
		       "\nrsbac_set_attr calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu\n",
		       set_attr_count[T_FILE],
		       set_attr_count[T_DIR],
		       set_attr_count[T_FIFO],
		       set_attr_count[T_SYMLINK],
		       set_attr_count[T_DEV],
		       set_attr_count[T_IPC],
		       set_attr_count[T_SCD],
		       set_attr_count[T_USER],
		       set_attr_count[T_PROCESS],
		       set_attr_count[T_NETDEV],
		       set_attr_count[T_NETTEMP],
		       set_attr_count[T_NETOBJ],
		       set_attr_count[T_GROUP],
		       set_attr_count[T_UNIXSOCK]);

	seq_printf(m,
		       "\nrsbac_remove_target calls:\nfile: %llu, dir: %llu, fifo: %llu, symlink: %llu, dev: %llu, ipc: %llu, scd: %llu, user: %llu, process: %llu, netdev: %llu, nettemp: %llu, netobj: %llu, group: %llu, unixsock: %llu\n",
		       remove_count[T_FILE],
		       remove_count[T_DIR],
		       remove_count[T_FIFO],
		       remove_count[T_SYMLINK],
		       remove_count[T_DEV],
		       remove_count[T_IPC],
		       remove_count[T_SCD],
		       remove_count[T_USER],
		       remove_count[T_PROCESS],
		       remove_count[T_NETDEV],
		       remove_count[T_NETTEMP],
		       remove_count[T_NETOBJ],
		       remove_count[T_GROUP],
		       remove_count[T_UNIXSOCK]);

	seq_printf(m,
		       "\nrsbac_get_parent calls: %llu\n",
		       get_parent_count);

#ifdef CONFIG_RSBAC_FD_CACHE
	seq_printf(m,
			"\nFD Cache hits                 misses               items   subitem hm-ratio\n");
	for (i = 0; i < SW_NONE; i++) {
		if (fd_cache_handle[i]) {
			__u64 tmp_hits = fd_cache_hits[i];
			__u64 tmp_misses = fd_cache_misses[i];

			while ((tmp_hits > (__u32) -1) || (tmp_misses > (__u32) -1)) {
				tmp_hits >>= 1;
				tmp_misses >>= 1;
			}
			if (!tmp_misses)
				tmp_misses = 1;
			seq_printf(m,
					"%-8s %-20llu %-20llu %-7lu %-7lu %u\n",
			       get_switch_target_name(name, i),
			       fd_cache_hits[i], fd_cache_misses[i],
			       rsbac_list_lol_count(fd_cache_handle[i]),
			       rsbac_list_lol_all_subcount(fd_cache_handle[i]),
			       ((__u32) tmp_hits)/((__u32) tmp_misses));
		}
	}
	seq_printf(m, "\n%u fd_cache_invalidates, %u fd_cache_invalidate_alls\n",
			fd_cache_invalidates, fd_cache_invalidate_alls);
#endif
	return 0;
}

static int xstats_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, xstats_proc_show, NULL);
}

static const struct file_operations xstats_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = xstats_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *xstats;
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
static int
auto_write_proc_show(struct seq_file *m, void *v)
{
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m,
		    "RSBAC auto write settings\n-------------------------\n");
	seq_printf(m,
		    "auto interval %u jiffies (%i jiffies = 1 second)\n",
		    auto_interval, HZ);

#ifdef CONFIG_RSBAC_DEBUG
	seq_printf(m, "debug level is %i\n",
		       rsbac_debug_auto);
#endif

	return 0;
}

static int auto_write_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, auto_write_proc_show, NULL);
}

static ssize_t auto_write_proc_write(struct file *file,
				 const char __user * buf, size_t count,
				 loff_t *data)
{
	ssize_t err;
	char *k_buf;
	char *p;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (count > PROC_BLOCK_SIZE) {
		return -EOVERFLOW;
	}

	if (!(k_buf = (char *) __get_free_page(GFP_KERNEL)))
		return -ENOMEM;
	err = copy_from_user(k_buf, buf, count);
	if (err < 0)
		return err;

	err = count;
	if (count < 13 || strncmp("auto", k_buf, 4)) {
		goto out;
	}
	if (!rsbac_initialized) {
		err = -ENOSYS;
		goto out;
	}
	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_MODIFY_SYSTEM_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		err = -EPERM;
		goto out;
	}

	/*
	 * Usage: echo "auto interval #N" > /proc/rsbac_info/auto_write
	 *   to set auto_interval to given value
	 */
	if (!strncmp("interval", k_buf + 5, 8)) {
		unsigned int interval;

		p = k_buf + 5 + 9;

		if (*p == '\0')
			goto out;

		interval = simple_strtoul(p, NULL, 0);
		/* only accept minimum of 1 second */
		if (interval >= HZ) {
			rsbac_printk(KERN_INFO "auto_write_proc_write(): setting auto write interval to %u\n",
				     interval);
			auto_interval = interval;
			err = count;
			goto out;
		} else {
			rsbac_printk(KERN_INFO "auto_write_proc_write(): rejecting too short auto write interval %u (min. %i)\n",
				     interval, HZ);
			goto out;
		}
	}
#ifdef CONFIG_RSBAC_DEBUG
	/*
	 * Usage: echo "auto debug #N" > /proc/rsbac_info/auto_write
	 *   to set rsbac_debug_auto to given value
	 */
	if (!strncmp("debug", k_buf + 5, 5)) {
		unsigned int debug_level;

		p = k_buf + 5 + 6;

		if (*p == '\0')
			goto out;

		debug_level = simple_strtoul(p, NULL, 0);
		/* only accept 0 or 1 */
		if (!debug_level || (debug_level == 1)) {
			rsbac_printk(KERN_INFO "auto_write_proc_write(): setting rsbac_debug_auto to %u\n",
				     debug_level);
			rsbac_debug_auto = debug_level;
			err = count;
		} else {
			rsbac_printk(KERN_INFO "auto_write_proc_write(): rejecting invalid debug level (should be 0 or 1)\n");
		}
	}
#endif

      out:
	free_page((ulong) k_buf);
	return err;
}

static const struct file_operations auto_write_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = auto_write_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
       .write          = auto_write_proc_write,
};

static struct proc_dir_entry *auto_write;
#endif				/* CONFIG_RSBAC_AUTO_WRITE > 0 */

static int
versions_proc_show(struct seq_file *m, void *v)
{
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m,
		      "RSBAC version settings (%s)\n----------------------\n",
		      RSBAC_VERSION);
	seq_printf(m,
		    "Device list head size is %u, hash size is %u\n",
		    (int) sizeof(struct rsbac_device_list_item_t),
		    RSBAC_NR_DEVICE_LISTS);
	seq_printf(m,
		    "FD lists:\nGEN  aci version is %u, aci entry size is %Zd, %u lists per device\n",
		    RSBAC_GEN_FD_ACI_VERSION,
		    sizeof(struct rsbac_gen_fd_aci_t),
		    gen_nr_fd_hashes);
#if defined(CONFIG_RSBAC_MAC)
	seq_printf(m,
		    "MAC  aci version is %u, aci entry size is %Zd, %u lists per device\n",
		    RSBAC_MAC_FD_ACI_VERSION,
		    sizeof(struct rsbac_mac_fd_aci_t),
		    mac_nr_fd_hashes);
#endif
#if defined(CONFIG_RSBAC_PM)
	seq_printf(m,
		    "PM   aci version is %u, aci entry size is %Zd, %u lists per device\n",
		    RSBAC_PM_FD_ACI_VERSION,
		    sizeof(struct rsbac_pm_fd_aci_t),
		    pm_nr_fd_hashes);
#endif
#if defined(CONFIG_RSBAC_DAZ)
	seq_printf(m,
		    "DAZ  aci version is %u, aci entry size is %Zd, %u lists per device\n",
		    RSBAC_DAZ_FD_ACI_VERSION,
		    sizeof(struct rsbac_daz_fd_aci_t),
		    daz_nr_fd_hashes);
#if defined(CONFIG_RSBAC_DAZ_CACHE)
	seq_printf(m,
		    "DAZS aci version is %u, aci entry size is %Zd, %u lists per device\n",
		    RSBAC_DAZ_SCANNED_FD_ACI_VERSION,
		    sizeof(rsbac_daz_scanned_t),
		    daz_scanned_nr_fd_hashes);
#endif
#endif
#if defined(CONFIG_RSBAC_FF)
	seq_printf(m,
		    "FF   aci version is %u, aci entry size is %Zd, %u lists per device\n",
		    RSBAC_FF_FD_ACI_VERSION, sizeof(rsbac_ff_flags_t),
		    ff_nr_fd_hashes);
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %Zd, %u lists per device\n",
		    RSBAC_RC_FD_ACI_VERSION,
		    sizeof(struct rsbac_rc_fd_aci_t),
		    rc_nr_fd_hashes);
#endif
#if defined(CONFIG_RSBAC_AUTH)
	seq_printf(m,
		    "AUTH aci version is %u, aci entry size is %Zd, %u lists per device\n",
		    RSBAC_AUTH_FD_ACI_VERSION,
		    sizeof(struct rsbac_auth_fd_aci_t),
		    auth_nr_fd_hashes);
#endif
#if defined(CONFIG_RSBAC_CAP)
	seq_printf(m,
		    "CAP  aci version is %u, aci entry size is %Zd, %u lists per device\n",
		    RSBAC_CAP_FD_ACI_VERSION,
		    sizeof(struct rsbac_cap_fd_aci_t),
		    cap_nr_fd_hashes);
#endif
#if defined(CONFIG_RSBAC_PAX)
	seq_printf(m,
		    "PAX  aci version is %u, aci entry size is %Zd, %u lists per device\n",
		    RSBAC_PAX_FD_ACI_VERSION, sizeof(rsbac_pax_flags_t),
		    pax_nr_fd_hashes);
#endif
#if defined(CONFIG_RSBAC_RES)
	seq_printf(m,
		    "RES  aci version is %u, aci entry size is %Zd, %u lists per device\n",
		    RSBAC_RES_FD_ACI_VERSION,
		    sizeof(struct rsbac_res_fd_aci_t),
		    res_nr_fd_hashes);
#endif
	seq_printf(m,
		    "\nDEV lists:\nGEN  aci version is %u, aci entry size is %Zd\n",
		    RSBAC_GEN_DEV_ACI_VERSION,
		    sizeof(struct rsbac_gen_dev_aci_t));
#if defined(CONFIG_RSBAC_MAC)
	seq_printf(m,
		    "MAC  aci version is %u, aci entry size is %Zd\n",
		    RSBAC_MAC_DEV_ACI_VERSION,
		    sizeof(struct rsbac_mac_dev_aci_t));
#endif
#if defined(CONFIG_RSBAC_PM)
	seq_printf(m,
		    "PM   aci version is %u, aci entry size is %Zd\n",
		    RSBAC_PM_DEV_ACI_VERSION,
		    sizeof(struct rsbac_pm_dev_aci_t));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %Zd\n",
		    RSBAC_RC_DEV_ACI_VERSION, sizeof(rsbac_rc_type_id_t));
#endif
	seq_printf(m, "\nIPC lists:\n");
#if defined(CONFIG_RSBAC_MAC)
	seq_printf(m,
		    "MAC  aci version is %u, aci entry size is %Zd\n",
		    RSBAC_MAC_IPC_ACI_VERSION,
		    sizeof(struct rsbac_mac_ipc_aci_t));
#endif
#if defined(CONFIG_RSBAC_PM)
	seq_printf(m,
		    "PM   aci version is %u, aci entry size is %Zd\n",
		    RSBAC_PM_IPC_ACI_VERSION,
		    sizeof(struct rsbac_pm_ipc_aci_t));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %Zd\n",
		    RSBAC_RC_IPC_ACI_VERSION, sizeof(rsbac_rc_type_id_t));
#endif
#if defined(CONFIG_RSBAC_JAIL)
	seq_printf(m,
		    "JAIL aci version is %u, aci entry size is %Zd\n",
		    RSBAC_JAIL_IPC_ACI_VERSION, sizeof(rsbac_jail_id_t));
#endif
	seq_printf(m,
		    "\nUSER lists:\nGEN  aci version is %u, aci entry size is %Zd\n",
		    RSBAC_GEN_USER_ACI_VERSION,
		    sizeof(struct rsbac_gen_user_aci_t));
#if defined(CONFIG_RSBAC_MAC)
	seq_printf(m,
		    "MAC  aci version is %u, aci entry size is %Zd\n",
		    RSBAC_MAC_USER_ACI_VERSION,
		    sizeof(struct rsbac_mac_user_aci_t));
#endif
#if defined(CONFIG_RSBAC_PM)
	seq_printf(m,
		    "PM   aci version is %u, aci entry size is %Zd\n",
		    RSBAC_PM_USER_ACI_VERSION,
		    sizeof(struct rsbac_pm_user_aci_t));
#endif
#if defined(CONFIG_RSBAC_DAZ)
	seq_printf(m,
		    "DAZ  aci version is %u, aci entry size is %Zd\n",
		    RSBAC_DAZ_USER_ACI_VERSION,
		    sizeof(rsbac_system_role_int_t));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %Zd\n",
		    RSBAC_RC_USER_ACI_VERSION, sizeof(rsbac_rc_role_id_t));
#endif
#if defined(CONFIG_RSBAC_AUTH)
	seq_printf(m,
		    "AUTH aci version is %u, aci entry size is %Zd\n",
		    RSBAC_AUTH_USER_ACI_VERSION,
		    sizeof(rsbac_system_role_int_t));
#endif
#if defined(CONFIG_RSBAC_CAP)
	seq_printf(m,
		    "CAP  aci version is %u, aci entry size is %Zd\n",
		    RSBAC_CAP_USER_ACI_VERSION,
		    sizeof(struct rsbac_cap_user_aci_t));
#endif
#if defined(CONFIG_RSBAC_JAIL)
	seq_printf(m,
		    "JAIL aci version is %u, aci entry size is %Zd\n",
		    RSBAC_JAIL_USER_ACI_VERSION,
		    sizeof(rsbac_system_role_int_t));
#endif
#if defined(CONFIG_RSBAC_PAX)
	seq_printf(m,
		    "PAX  aci version is %u, aci entry size is %Zd\n",
		    RSBAC_PAX_USER_ACI_VERSION,
		    sizeof(rsbac_system_role_int_t));
#endif
#if defined(CONFIG_RSBAC_RES)
	seq_printf(m,
		    "RES aci version is %u, aci entry size is %Zd\n",
		    RSBAC_RES_USER_ACI_VERSION,
		    sizeof(struct rsbac_res_user_aci_t));
#endif
	seq_printf(m,
		    "\nPROCESS lists:\nGEN  aci version is %i, aci entry size is %Zd, number of lists is %u\n",
		    RSBAC_GEN_PROCESS_ACI_VERSION,
		    sizeof(rsbac_request_vector_t),
		    CONFIG_RSBAC_GEN_NR_P_LISTS);
#if defined(CONFIG_RSBAC_MAC)
	seq_printf(m,
		    "MAC  aci version is %u, aci entry size is %Zd, number of lists is %u\n",
		    RSBAC_MAC_PROCESS_ACI_VERSION,
		    sizeof(struct rsbac_mac_process_aci_t),
		    CONFIG_RSBAC_MAC_NR_P_LISTS);
#endif
#if defined(CONFIG_RSBAC_PM)
	seq_printf(m,
		    "PM   aci version is %u, aci entry size is %Zd\n",
		    RSBAC_PM_PROCESS_ACI_VERSION,
		    sizeof(struct rsbac_pm_process_aci_t));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %Zd, number of lists is %u\n",
		    RSBAC_RC_PROCESS_ACI_VERSION,
		    sizeof(struct rsbac_rc_process_aci_t),
		    CONFIG_RSBAC_RC_NR_P_LISTS);
#endif
#if defined(CONFIG_RSBAC_AUTH)
	seq_printf(m,
		    "AUTH aci version is %u, aci entry size is %Zd\n",
		    RSBAC_AUTH_PROCESS_ACI_VERSION,
		    sizeof(struct rsbac_auth_process_aci_t));
#endif
#if defined(CONFIG_RSBAC_CAP)
	seq_printf(m,
		    "CAP aci version is %u, aci entry size is %Zd\n",
		    RSBAC_CAP_PROCESS_ACI_VERSION,
		    sizeof(struct rsbac_cap_process_aci_t));
#endif
#if defined(CONFIG_RSBAC_JAIL)
	seq_printf(m,
		    "JAIL aci version is %u, aci entry size is %Zd, number of lists is %u\n",
		    RSBAC_JAIL_PROCESS_ACI_VERSION,
		    sizeof(struct rsbac_jail_process_aci_t),
		    CONFIG_RSBAC_JAIL_NR_P_LISTS);
#endif

#if defined(CONFIG_RSBAC_NET_DEV)
	seq_printf(m, "\nNETDEV lists:\n");
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	seq_printf(m,
		    "GEN  aci version is %u, aci entry size is %Zd\n",
		    RSBAC_GEN_NETDEV_ACI_VERSION,
		    sizeof(struct rsbac_gen_netdev_aci_t));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %Zd\n",
		    RSBAC_RC_NETDEV_ACI_VERSION,
		    sizeof(rsbac_rc_type_id_t));
#endif
#endif

#if defined(CONFIG_RSBAC_NET_OBJ)
	seq_printf(m,
		    "\nNetwork Template list: version is %u, data size is %Zd\n",
		    RSBAC_NET_TEMP_VERSION,
		    sizeof(struct rsbac_net_temp_data_t));
	seq_printf(m,
		    "\nNETOBJ lists:\nGEN  aci version is %u, aci entry size is %Zd\n",
		    RSBAC_GEN_NETOBJ_ACI_VERSION,
		    sizeof(struct rsbac_gen_netobj_aci_t));
#if defined(CONFIG_RSBAC_MAC)
	seq_printf(m,
		    "MAC  aci version is %u, aci entry size is %Zd\n",
		    RSBAC_MAC_NETOBJ_ACI_VERSION,
		    sizeof(struct rsbac_mac_netobj_aci_t));
#endif
#if defined(CONFIG_RSBAC_PM)
	seq_printf(m,
		    "PM   aci version is %u, aci entry size is %Zd\n",
		    RSBAC_PM_NETOBJ_ACI_VERSION,
		    sizeof(struct rsbac_pm_netobj_aci_t));
#endif
#if defined(CONFIG_RSBAC_RC)
	seq_printf(m,
		    "RC   aci version is %u, aci entry size is %Zd\n",
		    RSBAC_RC_NETOBJ_ACI_VERSION,
		    sizeof(rsbac_rc_type_id_t));
#endif
#endif
	seq_printf(m,
		    "\nlog_levels array: version is %u, array size is %Zd\n",
		    RSBAC_LOG_LEVEL_VERSION,
		    R_NONE * (T_NONE + 1) * sizeof(rsbac_enum_t));
	seq_printf(m,
		    "\nattribute value union size is %u\n",
		    (int) sizeof(union rsbac_attribute_value_t));
#ifdef CONFIG_RSBAC_FD_CACHE
	seq_printf(m,
		    "fd cache attribute value union size is %u\n",
		    (int) sizeof(union rsbac_attribute_value_cache_t));
#endif
	return 0;
}

static int versions_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, versions_proc_show, NULL);
}

static const struct file_operations versions_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = versions_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *versions;

#ifdef CONFIG_RSBAC_NET_OBJ
static int
net_temp_proc_show(struct seq_file *m, void *v)
{
	rsbac_net_temp_id_t *temp_array;
	long count;

	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m, "Network Templates\n-----------------\n");
	count =
	    rsbac_list_get_all_desc(net_temp_handle,
				    (void **) &temp_array);
	if (count > 0) {
		__u32 i;
		struct rsbac_net_temp_data_t data;

		for (i = 0; i < count; i++) {
			if (!rsbac_list_get_data
			    (net_temp_handle, &temp_array[i], &data)) {
				seq_printf(m, "%10u  %s\n",
					    temp_array[i], data.name);
				}
			}
		rsbac_kfree(temp_array);
	}
	seq_printf(m, "%lu templates\n", count);
	return 0;
}

static int net_temp_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, net_temp_proc_show, NULL);
}

static const struct file_operations net_temp_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = net_temp_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *net_temp;
#endif				/* NET_OBJ */

#ifdef CONFIG_RSBAC_JAIL
static int
jails_proc_show(struct seq_file *m, void *v)
{
	rsbac_pid_t *pid_array;
	struct rsbac_ipc_t *ipc_array;
	u_long count = 0;
	u_int i;
	struct rsbac_jail_process_aci_t data;
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}

	seq_printf(m,
		    "Syslog-Jail is %u\n\nJAILed Processes\n----------------\nPID    Jail-ID    Flags   Max Caps   SCD get    SCD modify IP\n",
		    rsbac_jail_syslog_jail_id);

	count = rsbac_list_get_all_desc(process_handles.jail,
					(void **) &pid_array);
	if (count > 0) {
		for (i = 0; i < count; i++) {
			if (!rsbac_list_get_data
			    (process_handles.jail,
			     &pid_array[i], &data)) {
				seq_printf(m,
					    "%-5u  %-10u %-7u %-10i%-10u %-10u %-10u %u.%u.%u.%u\n",
					    pid_nr(pid_array[i]), data.id,
					    data.flags,
					    data.max_caps.cap[1],
					    data.max_caps.cap[0],
					    data.scd_get,
					    data.scd_modify,
					    NIPQUAD(data.ip));
			}
		}
		rsbac_kfree(pid_array);
	}
	seq_printf(m, "%lu jailed processes\n", count);
	seq_printf(m,
		    "\nJAIL IPCs\n---------\nType        IPC-ID     Jail-ID\n");

	count =
	    rsbac_list_get_all_desc(ipc_handles.jail,
				    (void **) &ipc_array);
	if (count > 0) {
		__u32 i;
		rsbac_jail_id_t data;
		char tmp[RSBAC_MAXNAMELEN];

		for (i = 0; i < count; i++) {
			if (!rsbac_list_get_data
			    (ipc_handles.jail, &ipc_array[i], &data)) {
				seq_printf(m,
					    "%-10s  %-10lu %-10u\n",
					    get_ipc_target_name(tmp,
								ipc_array
								[i].type),
					    ipc_array[i].id.id_nr, data);
			}
		}
		rsbac_kfree(ipc_array);
	}
	seq_printf(m, "%lu JAIL IPCs\n", count);
	return 0;
}

static int jails_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, jails_proc_show, NULL);
}

static const struct file_operations jails_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = jails_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *jails;

#endif				/* JAIL */

#ifdef CONFIG_RSBAC_PAX
static int
pax_proc_show(struct seq_file *m, void *v)
{
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;

	if (!rsbac_initialized)
		return -ENOSYS;

	rsbac_target_id.scd = ST_rsbac;
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
			       task_pid(current),
			       T_SCD,
			       rsbac_target_id,
			       A_none, rsbac_attribute_value)) {
		return -EPERM;
	}
	seq_puts(m, "RSBAC PaX module\n----------------\n");
	seq_printf(m, "%li user list items.\n", rsbac_list_count(user_handles.pax));
	return 0;
}

static ssize_t pax_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, pax_proc_show, NULL);
}

static const struct file_operations pax_proc_fops = {
       .owner          = THIS_MODULE,
       .open           = pax_proc_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};

static struct proc_dir_entry *pax;
#endif

static int register_all_rsbac_proc(void)
{
	proc_rsbac_root_p = create_proc_entry("rsbac-info",
					      S_IFDIR | S_IRUGO | S_IXUGO,
					      NULL);
	if (!proc_rsbac_root_p)
		return -RSBAC_ECOULDNOTADDITEM;

	proc_rsbac_backup_p = create_proc_entry("backup",
						S_IFDIR | S_IRUGO |
						S_IXUGO,
						proc_rsbac_root_p);
	if (!proc_rsbac_backup_p)
		return -RSBAC_ECOULDNOTADDITEM;

	devices = proc_create("devices",  S_IFREG | S_IRUGO, proc_rsbac_root_p, &devices_proc_fops);
	stats = proc_create("stats", S_IFREG | S_IRUGO, proc_rsbac_root_p, &stats_proc_fops);
	active = proc_create("active", S_IFREG | S_IRUGO, proc_rsbac_root_p, &active_proc_fops);
#ifdef CONFIG_RSBAC_XSTATS
	xstats = proc_create("xstats", S_IFREG | S_IRUGO, proc_rsbac_root_p, &xstats_proc_fops);
#endif
#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
	auto_write = proc_create("auto_write", S_IFREG | S_IRUGO | S_IWUGO, proc_rsbac_root_p, &auto_write_proc_fops);
#endif
	versions = proc_create("versions", S_IFREG | S_IRUGO, proc_rsbac_root_p, &versions_proc_fops);
#ifdef CONFIG_RSBAC_NET_OBJ
	net_temp = proc_create("net_temp", S_IFREG | S_IRUGO, proc_rsbac_root_p, &net_temp_proc_fops);
#endif
#ifdef CONFIG_RSBAC_JAIL
	jails = proc_create("jails", S_IFREG | S_IRUGO, proc_rsbac_root_p, &jails_proc_fops);
#endif
#ifdef CONFIG_RSBAC_PAX
	pax = proc_create("pax", S_IFREG | S_IRUGO, proc_rsbac_root_p, &pax_proc_fops);
#endif

	return 0;
}

/*
static int unregister_all_rsbac_proc(void)
  {
#ifdef CONFIG_RSBAC_PAX
    remove_proc_entry("pax", proc_rsbac_root_p);
#endif
#ifdef CONFIG_RSBAC_JAIL
    remove_proc_entry("jails", proc_rsbac_root_p);
#endif
#ifdef CONFIG_RSBAC_NET_OBJ
    remove_proc_entry("net_temp", proc_rsbac_root_p);
#endif
    remove_proc_entry("versions", proc_rsbac_root_p);
    remove_proc_entry("devices", proc_rsbac_root_p);
    remove_proc_entry("stats", proc_rsbac_root_p);
    remove_proc_entry("active", proc_rsbac_root_p);
    remove_proc_entry("auto-write", proc_rsbac_root_p);
    remove_proc_entry("backup", proc_rsbac_root_p);
    remove_proc_entry("rsbac-info", &proc_root);
    return0;
  }
*/
#endif


/************************************************* */
/*               RSBAC daemon                      */
/************************************************* */

/************************************************************************** */
/* Initialization, including ACI restoration for root device from disk.     */
/* After this call, all ACI is kept in memory for performance reasons,      */
/* but user and file/dir object ACI are written to disk on every change.    */

/* Since there can be no access to aci data structures before init,         */
/* rsbac_do_init() will initialize all rw-spinlocks to unlocked.               */

/* DAZ init prototype */
#if defined(CONFIG_RSBAC_DAZ) && !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init_daz(void);
#else
int __init rsbac_init_daz(void);
#endif
#endif

#ifdef CONFIG_RSBAC_INIT_DELAY
static void registration_error(int err, char *listname)
#else
static void __init registration_error(int err, char *listname)
#endif
{
	if (err < 0) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_do_init(): Registering %s list failed with error %s\n",
				     listname, get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
}

#ifdef CONFIG_RSBAC_FD_CACHE
#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_fd_cache_lists(void)
#else
static int __init register_fd_cache_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_lol_info_t *list_info_p;
	char * tmp;
	u_int i;

	for (i = 0; i < SW_NONE; i++) {
		fd_cache_handle[i] = NULL;
#ifdef CONFIG_RSBAC_XSTATS
		fd_cache_hits[i] = 0;
		fd_cache_misses[i] = 0;
#endif
	}
	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	tmp = rsbac_kmalloc_unlocked(RSBAC_MAXNAMELEN);
	if (!tmp) {
		rsbac_kfree(list_info_p);
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering FD Cache lists\n");
	list_info_p->version = RSBAC_FD_CACHE_VERSION;
	list_info_p->key = RSBAC_FD_CACHE_KEY;
	list_info_p->desc_size = sizeof(struct rsbac_fd_cache_desc_t);
	list_info_p->data_size = 0;
	list_info_p->subdesc_size = sizeof(rsbac_enum_t);
	list_info_p->subdata_size =
	    sizeof(union rsbac_attribute_value_cache_t);
	list_info_p->max_age = 0;
	sprintf(tmp, "%sGEN", RSBAC_FD_CACHE_NAME);
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				  &fd_cache_handle[SW_GEN], list_info_p,
				  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | \
				    RSBAC_LIST_AUTO_HASH_RESIZE | \
				    RSBAC_LIST_NO_MAX_WARN,
				  NULL,
				  NULL, /* subcompare */
				  NULL, NULL, /* get_conv */
				  NULL, NULL, /* def data */
				  tmp,
				  RSBAC_AUTO_DEV,
				  RSBAC_LIST_MIN_MAX_HASHES,
				  hash_fd_cache,
				  NULL);
	if (err)
		registration_error(err, "FD Cache GEN");
	else
		rsbac_list_lol_max_items(fd_cache_handle[SW_GEN],
			RSBAC_FD_CACHE_KEY,
			CONFIG_RSBAC_FD_CACHE_MAX_ITEMS, A_none);

#if defined(CONFIG_RSBAC_MAC) && defined(CONFIG_RSBAC_MAC_DEF_INHERIT)
	sprintf(tmp, "%sMAC", RSBAC_FD_CACHE_NAME);
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				  &fd_cache_handle[SW_MAC], list_info_p,
				  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | \
				    RSBAC_LIST_AUTO_HASH_RESIZE | \
				    RSBAC_LIST_NO_MAX_WARN,
				  NULL,
				  NULL, /* subcompare */
				  NULL, NULL, /* get_conv */
				  NULL, NULL, /* def data */
				  tmp,
				  RSBAC_AUTO_DEV,
				  RSBAC_LIST_MIN_MAX_HASHES,
				  hash_fd_cache,
				  NULL);
	if (err)
		registration_error(err, "FD Cache MAC");
	else
		rsbac_list_lol_max_items(fd_cache_handle[SW_MAC],
			RSBAC_FD_CACHE_KEY,
			CONFIG_RSBAC_FD_CACHE_MAX_ITEMS, A_none);
#endif
#if defined(CONFIG_RSBAC_FF)
	sprintf(tmp, "%sFF", RSBAC_FD_CACHE_NAME);
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				  &fd_cache_handle[SW_FF], list_info_p,
				  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | \
				    RSBAC_LIST_AUTO_HASH_RESIZE | \
				    RSBAC_LIST_NO_MAX_WARN,
				  NULL,
				  NULL, /* subcompare */
				  NULL, NULL, /* get_conv */
				  NULL, NULL, /* def data */
				  tmp,
				  RSBAC_AUTO_DEV,
				  RSBAC_LIST_MIN_MAX_HASHES,
				  hash_fd_cache,
				  NULL);
	if (err)
		registration_error(err, "FD Cache FF");
	else
		rsbac_list_lol_max_items(fd_cache_handle[SW_FF],
			RSBAC_FD_CACHE_KEY,
			CONFIG_RSBAC_FD_CACHE_MAX_ITEMS, A_none);
#endif
#if defined(CONFIG_RSBAC_RC)
	sprintf(tmp, "%sRC", RSBAC_FD_CACHE_NAME);
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				  &fd_cache_handle[SW_RC], list_info_p,
				  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | \
				    RSBAC_LIST_AUTO_HASH_RESIZE | \
				    RSBAC_LIST_NO_MAX_WARN,
				  NULL,
				  NULL, /* subcompare */
				  NULL, NULL, /* get_conv */
				  NULL, NULL, /* def data */
				  tmp,
				  RSBAC_AUTO_DEV,
				  RSBAC_LIST_MIN_MAX_HASHES,
				  hash_fd_cache,
				  NULL);
	if (err)
		registration_error(err, "FD Cache RC");
	else
		rsbac_list_lol_max_items(fd_cache_handle[SW_RC],
			RSBAC_FD_CACHE_KEY,
			CONFIG_RSBAC_FD_CACHE_MAX_ITEMS, A_none);
#endif
#if defined(CONFIG_RSBAC_DAZ) && !defined(CONFIG_RSBAC_DAZ_CACHE)
	sprintf(tmp, "%sDAZ", RSBAC_FD_CACHE_NAME);
	err = rsbac_list_lol_register_hashed(RSBAC_LIST_VERSION,
				  &fd_cache_handle[SW_DAZ], list_info_p,
				  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | \
				    RSBAC_LIST_AUTO_HASH_RESIZE | \
				    RSBAC_LIST_NO_MAX_WARN,
				  NULL,
				  NULL, /* subcompare */
				  NULL, NULL, /* get_conv */
				  NULL, NULL, /* def data */
				  tmp,
				  RSBAC_AUTO_DEV,
				  RSBAC_LIST_MIN_MAX_HASHES,
				  hash_fd_cache,
				  NULL);
	if (err)
		registration_error(err, "FD Cache DAZ");
	else
		rsbac_list_lol_max_items(fd_cache_handle[SW_DAZ],
			RSBAC_FD_CACHE_KEY,
			CONFIG_RSBAC_FD_CACHE_MAX_ITEMS,
			A_none);
#endif

	rsbac_kfree(list_info_p);
	rsbac_kfree(tmp);
	return err;
}
#endif

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_dev_lists(void)
#else
static int __init register_dev_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering DEV lists\n");
	{
		struct rsbac_gen_dev_aci_t def_aci = DEFAULT_GEN_DEV_ACI;

		list_info_p->version = RSBAC_GEN_DEV_ACI_VERSION;
		list_info_p->key = RSBAC_GEN_DEV_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_dev_desc_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_gen_dev_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &dev_handles.gen, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  dev_compare,
					  gen_dev_get_conv, &def_aci,
					  RSBAC_GEN_ACI_DEV_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_dev,
					  NULL);
		if (err) {
			registration_error(err, "DEV General");
		}
	}
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_dev_aci_t def_aci = DEFAULT_MAC_DEV_ACI;

		list_info_p->version = RSBAC_MAC_DEV_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_DEV_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_dev_desc_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_dev_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &dev_handles.mac, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  dev_compare,
					  mac_dev_get_conv, &def_aci,
					  RSBAC_MAC_ACI_DEV_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_dev,
					  NULL);
		if (err) {
			registration_error(err, "DEV MAC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_PM)
	{
		struct rsbac_pm_dev_aci_t def_aci = DEFAULT_PM_DEV_ACI;

		list_info_p->version = RSBAC_PM_DEV_ACI_VERSION;
		list_info_p->key = RSBAC_PM_DEV_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_dev_desc_t);
		list_info_p->data_size = sizeof(struct rsbac_pm_dev_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &dev_handles.pm, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  dev_compare,
					  pm_dev_get_conv, &def_aci,
					  RSBAC_PM_ACI_DEV_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_dev,
					  NULL);
		if (err) {
			registration_error(err, "DEV PM");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC)
	{
		rsbac_rc_type_id_t def_major_aci = RSBAC_RC_GENERAL_TYPE;
		rsbac_rc_type_id_t def_aci = RC_type_inherit_parent;

		list_info_p->version = RSBAC_RC_DEV_ACI_VERSION;
		list_info_p->key = RSBAC_RC_DEV_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_dev_desc_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &dev_major_handles.rc,
					  list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  dev_major_compare,
					  rc_dev_get_conv, &def_major_aci,
					  RSBAC_RC_ACI_DEV_MAJOR_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_dev,
					  NULL);
		if (err) {
			registration_error(err, "DEV major RC");
		}
		list_info_p->version = RSBAC_RC_DEV_ACI_VERSION;
		list_info_p->key = RSBAC_RC_DEV_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_dev_desc_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &dev_handles.rc, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  dev_compare,
					  rc_dev_get_conv, &def_aci,
					  RSBAC_RC_ACI_DEV_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_dev,
					  NULL);
		if (err) {
			registration_error(err, "DEV RC");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_ipc_lists(void)
#else
static int __init register_ipc_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering IPC lists\n");
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_ipc_aci_t def_aci = DEFAULT_MAC_IPC_ACI;

		list_info_p->version = RSBAC_MAC_IPC_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_IPC_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_ipc_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_ipc_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &ipc_handles.mac,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | RSBAC_LIST_AUTO_HASH_RESIZE,
					  ipc_compare,
					  NULL,
					  &def_aci,
					  RSBAC_MAC_ACI_IPC_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_ipc,
					  NULL);
		if (err) {
			registration_error(err, "IPC MAC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_PM)
	{
		struct rsbac_pm_ipc_aci_t def_aci = DEFAULT_PM_IPC_ACI;

		list_info_p->version = RSBAC_PM_IPC_ACI_VERSION;
		list_info_p->key = RSBAC_PM_IPC_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_ipc_t);
		list_info_p->data_size = sizeof(struct rsbac_pm_ipc_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &ipc_handles.pm,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | RSBAC_LIST_AUTO_HASH_RESIZE,
					  ipc_compare,
					  NULL,
					  &def_aci,
					  RSBAC_PM_ACI_IPC_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_ipc,
					  NULL);
		if (err) {
			registration_error(err, "IPC PM");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC)
	{
		rsbac_rc_type_id_t def_aci = RSBAC_RC_GENERAL_TYPE;

		list_info_p->version = RSBAC_RC_IPC_ACI_VERSION;
		list_info_p->key = RSBAC_RC_IPC_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_ipc_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &ipc_handles.rc,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | RSBAC_LIST_AUTO_HASH_RESIZE,
					  ipc_compare,
					  NULL,
					  &def_aci,
					  RSBAC_RC_ACI_IPC_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_ipc,
					  NULL);
		if (err) {
			registration_error(err, "IPC RC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_JAIL)
	{
		rsbac_jail_id_t def_aci = RSBAC_JAIL_DEF_ID;

		list_info_p->version = RSBAC_JAIL_IPC_ACI_VERSION;
		list_info_p->key = RSBAC_JAIL_IPC_ACI_KEY;
		list_info_p->desc_size = sizeof(struct rsbac_ipc_t);
		list_info_p->data_size = sizeof(rsbac_jail_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &ipc_handles.jail,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_OWN_SLAB | RSBAC_LIST_AUTO_HASH_RESIZE,
					  ipc_compare,
					  NULL,
					  &def_aci,
					  RSBAC_JAIL_ACI_IPC_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_ipc,
					  NULL);
		if (err) {
			registration_error(err, "IPC JAIL");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_user_lists1(void)
#else
static int __init register_user_lists1(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering USER lists\n");
	{
		struct rsbac_gen_user_aci_t def_aci = DEFAULT_GEN_U_ACI;

		list_info_p->version = RSBAC_GEN_USER_ACI_VERSION;
		list_info_p->key = RSBAC_GEN_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_gen_user_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.gen, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  gen_user_get_conv,
					  &def_aci,
					  RSBAC_GEN_ACI_USER_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER General");
		}
	}
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_user_aci_t def_aci = DEFAULT_MAC_U_ACI;

		list_info_p->version = RSBAC_MAC_USER_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_user_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.mac, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  mac_user_get_conv, &def_aci,
					  RSBAC_MAC_ACI_USER_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER MAC");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.mac)) {
			struct rsbac_mac_user_aci_t sysadm_aci =
			    DEFAULT_MAC_U_SYSADM_ACI;
			struct rsbac_mac_user_aci_t secoff_aci =
			    DEFAULT_MAC_U_SECOFF_ACI;
			struct rsbac_mac_user_aci_t auditor_aci =
			    DEFAULT_MAC_U_AUDITOR_ACI;
			rsbac_uid_t user;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER MAC ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			if (rsbac_list_add
			    (user_handles.mac, &user, &sysadm_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER MAC entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			if (rsbac_list_add
			    (user_handles.mac, &user, &secoff_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER MAC entry could not be added!\n");
			user = RSBAC_AUDITOR_UID;
			if (rsbac_list_add
			    (user_handles.mac, &user, &auditor_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): AUDITOR USER MAC entry could not be added!\n");
		}
	}
#endif
#if defined(CONFIG_RSBAC_PM)
	{
		struct rsbac_pm_user_aci_t def_aci = DEFAULT_PM_U_ACI;

		list_info_p->version = RSBAC_PM_USER_ACI_VERSION;
		list_info_p->key = RSBAC_PM_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_pm_user_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.pm, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  pm_user_get_conv,
					  &def_aci, RSBAC_PM_ACI_USER_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER PM");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.pm)) {
			struct rsbac_pm_user_aci_t sysadm_aci =
			    DEFAULT_PM_U_SYSADM_ACI;
			struct rsbac_pm_user_aci_t secoff_aci =
			    DEFAULT_PM_U_SECOFF_ACI;
			struct rsbac_pm_user_aci_t dataprot_aci =
			    DEFAULT_PM_U_DATAPROT_ACI;
			struct rsbac_pm_user_aci_t tpman_aci =
			    DEFAULT_PM_U_TPMAN_ACI;
			rsbac_uid_t user;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER PM ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			if (rsbac_list_add
			    (user_handles.pm, &user, &sysadm_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER PM entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			if (rsbac_list_add
			    (user_handles.pm, &user, &secoff_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER PM entry could not be added!\n");
			user = RSBAC_DATAPROT_UID;
			if (rsbac_list_add
			    (user_handles.pm, &user, &dataprot_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): DATAPROT USER PM entry could not be added!\n");
			user = RSBAC_TPMAN_UID;
			if (rsbac_list_add
			    (user_handles.pm, &user, &tpman_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): TPMAN USER PM entry could not be added!\n");
		}
	}
#endif
#if defined(CONFIG_RSBAC_DAZ)
	{
		rsbac_system_role_int_t def_aci = SR_user;

		list_info_p->version = RSBAC_DAZ_USER_ACI_VERSION;
		list_info_p->key = RSBAC_DAZ_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size = sizeof(rsbac_system_role_int_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register(RSBAC_LIST_VERSION,
					  &user_handles.daz, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_PERSIST | RSBAC_LIST_DEF_DATA,
					  NULL,
					  daz_user_get_conv,
					  &def_aci,
					  RSBAC_DAZ_ACI_USER_NAME,
					  RSBAC_AUTO_DEV);
		if (err) {
			registration_error(err, "USER DAZ");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.daz)) {
			rsbac_uid_t user;
			rsbac_system_role_int_t role;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER DAZ ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			role = SR_administrator;
			if (rsbac_list_add(user_handles.daz, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER DAZ entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			role = SR_security_officer;
			if (rsbac_list_add(user_handles.daz, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER DAZ entry could not be added!\n");
		}
	}
#endif
#if defined(CONFIG_RSBAC_FF)
	{
		rsbac_system_role_int_t def_aci = SR_user;

		list_info_p->version = RSBAC_FF_USER_ACI_VERSION;
		list_info_p->key = RSBAC_FF_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size = sizeof(rsbac_system_role_int_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register(RSBAC_LIST_VERSION,
					  &user_handles.ff, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_PERSIST | RSBAC_LIST_DEF_DATA,
					  NULL,
					  ff_user_get_conv,
					  &def_aci, RSBAC_FF_ACI_USER_NAME,
					  RSBAC_AUTO_DEV);
		if (err) {
			registration_error(err, "USER FF");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.ff)) {
			rsbac_uid_t user;
			rsbac_system_role_int_t role;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER FF ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			role = SR_administrator;
			if (rsbac_list_add(user_handles.ff, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER FF entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			role = SR_security_officer;
			if (rsbac_list_add(user_handles.ff, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER FF entry could not be added!\n");
			user = RSBAC_AUDITOR_UID;
			role = SR_auditor;
			if (rsbac_list_add(user_handles.ff, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): AUDITOR USER FF entry could not be added!\n");
		}
	}
#endif
#if defined(CONFIG_RSBAC_CAP)
	{
		struct rsbac_cap_user_aci_t def_aci = DEFAULT_CAP_U_ACI;

		list_info_p->version = RSBAC_CAP_USER_ACI_VERSION;
		list_info_p->key = RSBAC_CAP_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_cap_user_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.cap, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST |
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL, 
					  cap_user_get_conv,
					  &def_aci,
					  RSBAC_CAP_ACI_USER_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER CAP");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.cap)) {
			struct rsbac_cap_user_aci_t sysadm_aci =
			    DEFAULT_CAP_U_SYSADM_ACI;
			struct rsbac_cap_user_aci_t secoff_aci =
			    DEFAULT_CAP_U_SECOFF_ACI;
			struct rsbac_cap_user_aci_t auditor_aci =
			    DEFAULT_CAP_U_AUDITOR_ACI;
			rsbac_uid_t user;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER CAP ACI could not be read - generating standard entries!\n");
			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER CAP ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			if (rsbac_list_add
			    (user_handles.cap, &user, &sysadm_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER CAP entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			if (rsbac_list_add
			    (user_handles.cap, &user, &secoff_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER CAP entry could not be added!\n");
			user = RSBAC_AUDITOR_UID;
			if (rsbac_list_add
			    (user_handles.cap, &user, &auditor_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): AUDITOR USER CAP entry could not be added!\n");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_user_lists2(void)
#else
static int __init register_user_lists2(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}

#if defined(CONFIG_RSBAC_RC)
	{
		struct rsbac_rc_user_aci_t def_aci = DEFAULT_RC_U_ACI;

		list_info_p->version = RSBAC_RC_USER_ACI_VERSION;
		list_info_p->key = RSBAC_RC_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_rc_user_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &user_handles.rc, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  rc_user_get_conv, &def_aci,
					  RSBAC_RC_ACI_USER_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_uid,
					  NULL);
		if (err) {
			registration_error(err, "USER RC");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.rc)) {
			rsbac_uid_t user;
			struct rsbac_rc_user_aci_t sysadm_aci =
			    DEFAULT_RC_U_SYSADM_ACI;
			struct rsbac_rc_user_aci_t secoff_aci =
			    DEFAULT_RC_U_SECOFF_ACI;
			struct rsbac_rc_user_aci_t auditor_aci =
			    DEFAULT_RC_U_AUDITOR_ACI;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER RC ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			if (rsbac_list_add
			    (user_handles.rc, &user, &sysadm_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER RC entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			if (rsbac_list_add
			    (user_handles.rc, &user, &secoff_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER RC entry could not be added!\n");
			user = RSBAC_AUDITOR_UID;
			if (rsbac_list_add
			    (user_handles.rc, &user, &auditor_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): AUDITOR USER RC entry could not be added!\n");
		}
	}
#endif
#if defined(CONFIG_RSBAC_AUTH)
	{
		rsbac_system_role_int_t def_aci = SR_user;

		list_info_p->version = RSBAC_AUTH_USER_ACI_VERSION;
		list_info_p->key = RSBAC_AUTH_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size = sizeof(rsbac_system_role_int_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register(RSBAC_LIST_VERSION,
					  &user_handles.auth, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_PERSIST,
					  NULL,
					  auth_user_get_conv,
					  &def_aci,
					  RSBAC_AUTH_ACI_USER_NAME,
					  RSBAC_AUTO_DEV);
		if (err) {
			registration_error(err, "USER AUTH");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.auth)) {
			rsbac_uid_t user;
			rsbac_system_role_int_t role;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER AUTH ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			role = SR_administrator;
			if (rsbac_list_add
			    (user_handles.auth, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER AUTH entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			role = SR_security_officer;
			if (rsbac_list_add
			    (user_handles.auth, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER AUTH entry could not be added!\n");
			user = RSBAC_AUDITOR_UID;
			role = SR_auditor;
			if (rsbac_list_add
			    (user_handles.auth, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): AUDITOR USER AUTH entry could not be added!\n");
		}
	}
#endif				/* AUTH */
#if defined(CONFIG_RSBAC_JAIL)
	{
		rsbac_system_role_int_t def_aci = SR_user;

		list_info_p->version = RSBAC_JAIL_USER_ACI_VERSION;
		list_info_p->key = RSBAC_JAIL_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size = sizeof(rsbac_system_role_int_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register(RSBAC_LIST_VERSION,
					  &user_handles.jail, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_PERSIST,
					  NULL,
					  jail_user_get_conv,
					  &def_aci,
					  RSBAC_JAIL_ACI_USER_NAME,
					  RSBAC_AUTO_DEV);
		if (err) {
			registration_error(err, "USER JAIL");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.jail)) {
			rsbac_uid_t user;
			rsbac_system_role_int_t role;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER JAIL ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			role = SR_administrator;
			if (rsbac_list_add
			    (user_handles.jail, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER JAIL entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			role = SR_security_officer;
			if (rsbac_list_add
			    (user_handles.jail, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER JAIL entry could not be added!\n");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RES)
	{
		list_info_p->version = RSBAC_RES_USER_ACI_VERSION;
		list_info_p->key = RSBAC_RES_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_res_user_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register(RSBAC_LIST_VERSION,
					  &user_handles.res, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST,
					  NULL,
					  res_user_get_conv,
					  NULL,
					  RSBAC_RES_ACI_USER_NAME,
					  RSBAC_AUTO_DEV);
		if (err) {
			registration_error(err, "USER RES");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.res)) {
			struct rsbac_res_user_aci_t sysadm_aci =
			    DEFAULT_RES_U_SYSADM_ACI;
			struct rsbac_res_user_aci_t secoff_aci =
			    DEFAULT_RES_U_SECOFF_ACI;
			rsbac_uid_t user;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER RES ACI could not be read - generating standard entries!\n");
			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER RES ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			if (rsbac_list_add
			    (user_handles.res, &user, &sysadm_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER RES entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			if (rsbac_list_add
			    (user_handles.res, &user, &secoff_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER RES entry could not be added!\n");
		}
	}
#endif
#if defined(CONFIG_RSBAC_PAX)
	{
		rsbac_system_role_int_t def_aci = SR_user;

		list_info_p->version = RSBAC_PAX_USER_ACI_VERSION;
		list_info_p->key = RSBAC_PAX_USER_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_uid_t);
		list_info_p->data_size = sizeof(rsbac_system_role_int_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register(RSBAC_LIST_VERSION,
					  &user_handles.pax, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_PERSIST,
					  NULL,
					  pax_user_get_conv,
					  &def_aci,
					  RSBAC_PAX_ACI_USER_NAME,
					  RSBAC_AUTO_DEV);
		if (err) {
			registration_error(err, "USER PAX");
		} else
		    if (!rsbac_no_defaults
			&& !rsbac_list_count(user_handles.pax)) {
			rsbac_uid_t user;
			rsbac_system_role_int_t role;

			rsbac_printk(KERN_WARNING "rsbac_do_init(): USER PAX ACI could not be read - generating standard entries!\n");
			user = RSBAC_SYSADM_UID;
			role = SR_administrator;
			if (rsbac_list_add(user_handles.pax, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SYSADM USER PAX entry could not be added!\n");
			user = RSBAC_SECOFF_UID;
			role = SR_security_officer;
			if (rsbac_list_add(user_handles.pax, &user, &role))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): SECOFF USER PAX entry could not be added!\n");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_process_lists(void)
#else
static int __init register_process_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering PROCESS lists\n");
	{
		struct rsbac_gen_process_aci_t def_aci = DEFAULT_GEN_P_ACI;

		list_info_p->version = RSBAC_GEN_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_GEN_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_gen_process_aci_t);
		list_info_p->max_age = 0;
		gen_nr_p_hashes = CONFIG_RSBAC_GEN_NR_P_LISTS;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
						&process_handles.gen,
						list_info_p,
						RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
						NULL,
						NULL, &def_aci,
						RSBAC_GEN_ACI_PROCESS_NAME,
						RSBAC_AUTO_DEV,
						gen_nr_p_hashes,
						(gen_nr_p_hashes > 1) ? rsbac_list_hash_pid : NULL,
						NULL);
		if (err) {
			registration_error(err, "PROCESS GEN");
		}
	}
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_process_aci_t def_aci = DEFAULT_MAC_P_ACI;

		list_info_p->version = RSBAC_MAC_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_process_aci_t);
		list_info_p->max_age = 0;
		mac_nr_p_hashes = CONFIG_RSBAC_MAC_NR_P_LISTS;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
						&process_handles.mac,
						list_info_p,
						RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
						NULL,
						NULL, &def_aci,
						RSBAC_MAC_ACI_PROCESS_NAME,
						RSBAC_AUTO_DEV,
						mac_nr_p_hashes,
						(mac_nr_p_hashes > 1) ? rsbac_list_hash_pid : NULL,
						NULL);
		if (err) {
			registration_error(err, "PROCESS MAC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_PM)
	{
		struct rsbac_pm_process_aci_t def_aci = DEFAULT_PM_P_ACI;

		list_info_p->version = RSBAC_PM_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_PM_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_pm_process_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &process_handles.pm,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_PM_ACI_PROCESS_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_pid,
					  NULL);
		if (err) {
			registration_error(err, "PROCESS PM");
		}
	}
#endif
#if defined(CONFIG_RSBAC_DAZ)
	{
		struct rsbac_daz_process_aci_t def_aci = DEFAULT_DAZ_P_ACI;

		list_info_p->version = RSBAC_DAZ_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_DAZ_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_daz_process_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &process_handles.daz,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_DAZ_ACI_PROCESS_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_pid,
					  NULL);
		if (err) {
			registration_error(err, "PROCESS DAZ");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC)
	{
		struct rsbac_rc_process_aci_t def_aci = DEFAULT_RC_P_ACI;

		list_info_p->version = RSBAC_RC_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_RC_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_rc_process_aci_t);
		list_info_p->max_age = 0;
		rc_nr_p_hashes = CONFIG_RSBAC_RC_NR_P_LISTS;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
						&process_handles.rc,
						list_info_p,
						RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
						NULL,
						NULL, &def_aci,
						RSBAC_RC_ACI_PROCESS_NAME,
						RSBAC_AUTO_DEV,
						rc_nr_p_hashes,
						(rc_nr_p_hashes > 1) ? rsbac_list_hash_pid : NULL,
						NULL);
		if (err) {
			registration_error(err, "PROCESS RC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_AUTH)
	{
		struct rsbac_auth_process_aci_t def_aci = DEFAULT_AUTH_P_ACI;

		list_info_p->version = RSBAC_AUTH_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_AUTH_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_auth_process_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &process_handles.auth,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_AUTH_ACI_PROCESS_NAME,
					  RSBAC_AUTO_DEV,
#if defined(CONFIG_RSBAC_AUTH_LEARN)
					  RSBAC_LIST_MIN_MAX_HASHES,
					  rsbac_list_hash_pid,
#else
					  1,
					  NULL,
#endif
					  NULL);
		if (err) {
			registration_error(err, "PROCESS AUTH");
		}
	}
#endif
#if defined(CONFIG_RSBAC_CAP)
	{
		struct rsbac_cap_process_aci_t def_aci = DEFAULT_CAP_P_ACI;

#if defined(CONFIG_RSBAC_CAP_PROC_HIDE)
		if (rsbac_cap_process_hiding)
			def_aci.cap_process_hiding = PH_from_other_users;
#endif
		list_info_p->version = RSBAC_CAP_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_CAP_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_cap_process_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &process_handles.cap,
					  list_info_p,
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_CAP_ACI_PROCESS_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_pid,
					  NULL);
		if (err) {
			registration_error(err, "PROCESS CAP");
		}
	}
#endif
#if defined(CONFIG_RSBAC_JAIL)
	{
		struct rsbac_jail_process_aci_t def_aci =
		    DEFAULT_JAIL_P_ACI;

		list_info_p->version = RSBAC_JAIL_PROCESS_ACI_VERSION;
		list_info_p->key = RSBAC_JAIL_PROCESS_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_pid_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_jail_process_aci_t);
		list_info_p->max_age = 0;
		jail_nr_p_hashes = CONFIG_RSBAC_JAIL_NR_P_LISTS;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
						&process_handles.jail,
						list_info_p,
						RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
						NULL,
						NULL, &def_aci,
						RSBAC_JAIL_ACI_PROCESS_NAME,
						RSBAC_AUTO_DEV,
						jail_nr_p_hashes,
						(jail_nr_p_hashes > 1) ? rsbac_list_hash_pid : NULL,
						NULL);
		if (err) {
			registration_error(err, "PROCESS JAIL");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_UM
#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_group_lists(void)
#else
static int __init register_group_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering GROUP lists\n");
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	{
		rsbac_rc_type_id_t def_aci = RSBAC_RC_GENERAL_TYPE;

		list_info_p->version = RSBAC_RC_GROUP_ACI_VERSION;
		list_info_p->key = RSBAC_RC_GROUP_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_gid_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &group_handles.rc, list_info_p,
#ifdef CONFIG_RSBAC_DEV_USER_BACKUP
					  RSBAC_LIST_BACKUP |
#endif
					  RSBAC_LIST_PERSIST | RSBAC_LIST_OWN_SLAB |
#ifndef CONFIG_RSBAC_UM_VIRTUAL
					  RSBAC_LIST_DEF_DATA |
#endif
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL, NULL,
					  &def_aci,
					  RSBAC_RC_ACI_GROUP_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_gid,
					  NULL);
		if (err) {
			registration_error(err, "GROUP RC");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}
#endif				/* UM */

#ifdef CONFIG_RSBAC_NET_DEV
#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_netdev_lists(void)
#else
static int __init register_netdev_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering NETDEV lists\n");
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	{
		struct rsbac_gen_netdev_aci_t def_aci =
		    DEFAULT_GEN_NETDEV_ACI;

		list_info_p->version = RSBAC_GEN_NETDEV_ACI_VERSION;
		list_info_p->key = RSBAC_GEN_NETDEV_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_netdev_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_gen_netdev_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register(RSBAC_LIST_VERSION,
					  &netdev_handles.gen,
					  list_info_p,
					  RSBAC_LIST_BACKUP |
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA,
					  netdev_compare, NULL, &def_aci,
					  RSBAC_GEN_ACI_NETDEV_NAME,
					  RSBAC_AUTO_DEV);
		if (err) {
			registration_error(err, "NETDEV General");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC)
	{
		rsbac_rc_type_id_t def_aci = RSBAC_RC_GENERAL_TYPE;

		list_info_p->version = RSBAC_RC_NETDEV_ACI_VERSION;
		list_info_p->key = RSBAC_RC_NETDEV_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_netdev_id_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register(RSBAC_LIST_VERSION,
					  &netdev_handles.rc,
					  list_info_p,
					  RSBAC_LIST_BACKUP |
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA,
					  netdev_compare, NULL, &def_aci,
					  RSBAC_RC_ACI_NETDEV_NAME,
					  RSBAC_AUTO_DEV);
		if (err) {
			registration_error(err, "NETDEV RC");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}
#endif				/* NET_DEV */

#ifdef CONFIG_RSBAC_NET_OBJ
#ifdef CONFIG_RSBAC_INIT_DELAY
static void fill_default_nettemp(void)
#else
static void __init fill_default_nettemp(void)
#endif
{
	rsbac_net_temp_id_t id;
	struct rsbac_net_temp_data_t data;

	id = RSBAC_NET_TEMP_LNET_ID;
	memset(&data, 0, sizeof(data));
	data.address_family = AF_INET;
	data.type = RSBAC_NET_ANY;
	data.protocol = RSBAC_NET_ANY;
	strcpy(data.name, "Localnet");
	data.address.inet.nr_addr = 1;
	data.address.inet.valid_bits[0] = 8;
	rsbac_net_str_to_inet(RSBAC_NET_TEMP_LNET_ADDRESS,
			      &data.address.inet.addr[0]);
	data.ports.nr_ports = 0;
	rsbac_list_add(net_temp_handle, &id, &data);

	id = RSBAC_NET_TEMP_LAN_ID;
	memset(&data, 0, sizeof(data));
	data.address_family = AF_INET;
	data.type = RSBAC_NET_ANY;
	data.protocol = RSBAC_NET_ANY;
	strcpy(data.name, "Internal LAN");
	data.address.inet.nr_addr = 1;
	data.address.inet.valid_bits[0] = 16;
	rsbac_net_str_to_inet(RSBAC_NET_TEMP_LAN_ADDRESS,
			      &data.address.inet.addr[0]);
	data.ports.nr_ports = 0;
	rsbac_list_add(net_temp_handle, &id, &data);

	id = RSBAC_NET_TEMP_AUTO_ID;
	memset(&data, 0, sizeof(data));
	data.address_family = AF_INET;
	data.type = RSBAC_NET_ANY;
	data.protocol = RSBAC_NET_ANY;
	strcpy(data.name, "Auto-IPv4");
	data.address.inet.nr_addr = 1;
	data.address.inet.valid_bits[0] = 32;
	data.ports.nr_ports = 0;
	rsbac_list_add(net_temp_handle, &id, &data);

	id = RSBAC_NET_TEMP_INET_ID;
	memset(&data, 0, sizeof(data));
	data.address_family = AF_INET;
	data.type = RSBAC_NET_ANY;
	data.protocol = RSBAC_NET_ANY;
	strcpy(data.name, "AF_INET");
	data.address.inet.nr_addr = 1;
	data.address.inet.valid_bits[0] = 0;
	data.ports.nr_ports = 0;
	rsbac_list_add(net_temp_handle, &id, &data);

	id = RSBAC_NET_TEMP_INET_ID;
	memset(&data, 0, sizeof(data));
	data.address_family = RSBAC_NET_ANY;
	data.type = RSBAC_NET_ANY;
	data.protocol = RSBAC_NET_ANY;
	strcpy(data.name, "ALL");
	data.ports.nr_ports = 0;
	rsbac_list_add(net_temp_handle, &id, &data);
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_nettemp_list(void)
#else
static int __init register_nettemp_list(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering network template list\n");
	list_info_p->version = RSBAC_NET_TEMP_VERSION;
	list_info_p->key = RSBAC_NET_TEMP_KEY;
	list_info_p->desc_size = sizeof(rsbac_net_temp_id_t);
	list_info_p->data_size = sizeof(struct rsbac_net_temp_data_t);
	list_info_p->max_age = 0;
	err = rsbac_list_register(RSBAC_LIST_VERSION,
				  &net_temp_handle,
				  list_info_p,
				  RSBAC_LIST_BACKUP |
				  RSBAC_LIST_PERSIST,
				  rsbac_list_compare_u32,
				  net_temp_get_conv,
				  NULL,
				  RSBAC_NET_TEMP_NAME,
				  RSBAC_AUTO_DEV);
	if (err) {
		registration_error(err, "Network Template");
	} else
	    if (!rsbac_no_defaults && !rsbac_list_count(net_temp_handle)) {
		rsbac_printk(KERN_WARNING "rsbac_do_init(): Network Templates could not be read - generating standard entries!\n");
		fill_default_nettemp();
	}
	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_nettemp_aci_lists(void)
#else
static int __init register_nettemp_aci_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering NETTEMP lists\n");
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
	{
		list_info_p->version = RSBAC_GEN_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_GEN_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_temp_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_gen_netobj_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &nettemp_handles.gen,
					  list_info_p,
					  RSBAC_LIST_BACKUP |
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL, NULL,
					  &def_gen_netobj_aci,
					  RSBAC_GEN_ACI_NETTEMP_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_nettemp,
					  NULL);
		if (err) {
			registration_error(err, "NETTEMP GEN");
		}
	}
#endif
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_netobj_aci_t def_aci =
		    DEFAULT_MAC_NETOBJ_ACI;

		list_info_p->version = RSBAC_MAC_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_temp_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_netobj_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &nettemp_handles.mac,
					  list_info_p,
					  RSBAC_LIST_BACKUP |
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL, NULL,
					  &def_aci,
					  RSBAC_MAC_ACI_NETTEMP_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_nettemp,
					  NULL);
		if (err) {
			registration_error(err, "NETTEMP MAC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_PM)
	{
		struct rsbac_pm_netobj_aci_t def_aci =
		    DEFAULT_PM_NETOBJ_ACI;

		list_info_p->version = RSBAC_PM_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_PM_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_temp_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_pm_netobj_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &nettemp_handles.pm,
					  list_info_p,
					  RSBAC_LIST_BACKUP |
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL, NULL,
					  &def_aci,
					  RSBAC_PM_ACI_NETTEMP_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_nettemp,
					  NULL);
		if (err) {
			registration_error(err, "NETTEMP PM");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC)
	{
		struct rsbac_rc_nettemp_aci_t def_aci =
		    DEFAULT_RC_NETTEMP_ACI;

		list_info_p->version = RSBAC_RC_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_RC_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_temp_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_rc_nettemp_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &nettemp_handles.rc,
					  list_info_p,
					  RSBAC_LIST_BACKUP |
					  RSBAC_LIST_PERSIST |
					  RSBAC_LIST_DEF_DATA | RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL, NULL,
					  &def_aci,
					  RSBAC_RC_ACI_NETTEMP_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_nettemp,
					  NULL);
		if (err) {
			registration_error(err, "NETTEMP RC");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
static int register_netobj_lists(void)
#else
static int __init register_netobj_lists(void)
#endif
{
	int err = 0;
	struct rsbac_list_info_t *list_info_p;

	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
	rsbac_pr_debug(ds, "registering local NETOBJ lists\n");
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_netobj_aci_t def_aci =
		    DEFAULT_MAC_NETOBJ_ACI;

		list_info_p->version = RSBAC_MAC_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_obj_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_netobj_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &lnetobj_handles.mac,
					  list_info_p,
					  RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_MAC_ACI_LNETOBJ_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_netobj,
					  NULL);
		if (err) {
			registration_error(err, "LNETOBJ MAC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_PM)
	{
		struct rsbac_pm_netobj_aci_t def_aci =
		    DEFAULT_PM_NETOBJ_ACI;

		list_info_p->version = RSBAC_PM_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_PM_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_obj_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_pm_netobj_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &lnetobj_handles.pm,
					  list_info_p,
					  RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_PM_ACI_LNETOBJ_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_netobj,
					  NULL);
		if (err) {
			registration_error(err, "LNETOBJ PM");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC)
	{
		rsbac_rc_type_id_t def_aci = RSBAC_RC_GENERAL_TYPE;

		list_info_p->version = RSBAC_RC_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_RC_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_obj_id_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &lnetobj_handles.rc,
					  list_info_p,
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_RC_ACI_LNETOBJ_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_netobj,
					  NULL);
		if (err) {
			registration_error(err, "LNETOBJ RC");
		}
	}
#endif
	rsbac_pr_debug(ds, "registering remote NETOBJ lists\n");
#if defined(CONFIG_RSBAC_MAC)
	{
		struct rsbac_mac_netobj_aci_t def_aci =
		    DEFAULT_MAC_NETOBJ_ACI;

		list_info_p->version = RSBAC_MAC_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_MAC_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_obj_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_mac_netobj_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &rnetobj_handles.mac,
					  list_info_p,
					  RSBAC_LIST_AUTO_HASH_RESIZE | RSBAC_LIST_OWN_SLAB,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_MAC_ACI_RNETOBJ_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_netobj,
					  NULL);
		if (err) {
			registration_error(err, "RNETOBJ MAC");
		}
	}
#endif
#if defined(CONFIG_RSBAC_PM)
	{
		struct rsbac_pm_netobj_aci_t def_aci =
		    DEFAULT_PM_NETOBJ_ACI;

		list_info_p->version = RSBAC_PM_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_PM_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_obj_id_t);
		list_info_p->data_size =
		    sizeof(struct rsbac_pm_netobj_aci_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &rnetobj_handles.pm,
					  list_info_p,
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_PM_ACI_RNETOBJ_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_netobj,
					  NULL);
		if (err) {
			registration_error(err, "RNETOBJ PM");
		}
	}
#endif
#if defined(CONFIG_RSBAC_RC)
	{
		rsbac_rc_type_id_t def_aci = RSBAC_RC_GENERAL_TYPE;

		list_info_p->version = RSBAC_RC_NETOBJ_ACI_VERSION;
		list_info_p->key = RSBAC_RC_NETOBJ_ACI_KEY;
		list_info_p->desc_size = sizeof(rsbac_net_obj_id_t);
		list_info_p->data_size = sizeof(rsbac_rc_type_id_t);
		list_info_p->max_age = 0;
		err = rsbac_list_register_hashed(RSBAC_LIST_VERSION,
					  &rnetobj_handles.rc,
					  list_info_p,
					  RSBAC_LIST_AUTO_HASH_RESIZE,
					  NULL,
					  NULL,
					  &def_aci,
					  RSBAC_RC_ACI_RNETOBJ_NAME,
					  RSBAC_AUTO_DEV,
					  1,
					  rsbac_list_hash_netobj,
					  NULL);
		if (err) {
			registration_error(err, "RNETOBJ RC");
		}
	}
#endif

	rsbac_kfree(list_info_p);
	return err;
}
#endif				/* NET_OBJ */

#ifdef CONFIG_RSBAC_INIT_DELAY
static int rsbac_do_init(void)
#else
static int __init rsbac_do_init(void)
#endif
{
	int err = 0;
	struct rsbac_device_list_item_t *device_p;
	struct rsbac_device_list_item_t *new_device_p;
	struct rsbac_list_info_t *list_info_p;
	struct vfsmount *mnt_p;
	u_int i;

	rsbac_pr_debug(stack, "free stack: %lu\n", rsbac_stack_free_space());
	list_info_p = rsbac_kmalloc_unlocked(sizeof(*list_info_p));
	if (!list_info_p) {
		return -ENOMEM;
	}
#ifdef CONFIG_RSBAC_INIT_DELAY
	if (rsbac_root_mnt_p)
		mnt_p = rsbac_root_mnt_p;
	else
#endif
	{
		spin_lock(&current->fs->lock);
		mnt_p = mntget(current->fs->root.mnt);
		spin_unlock(&current->fs->lock);
	}
	compiled_modules[0] = (char) 0;
#ifdef CONFIG_RSBAC_REG
	strcat(compiled_modules, " REG");
#endif
#ifdef CONFIG_RSBAC_MAC
#ifdef CONFIG_RSBAC_MAC_LIGHT
	strcat(compiled_modules, " MAC-L");
#else
	strcat(compiled_modules, " MAC");
#endif
#endif
#ifdef CONFIG_RSBAC_PM
	strcat(compiled_modules, " PM");
#endif
#ifdef CONFIG_RSBAC_DAZ
	strcat(compiled_modules, " DAZ");
#endif
#ifdef CONFIG_RSBAC_FF
	strcat(compiled_modules, " FF");
#endif
#ifdef CONFIG_RSBAC_RC
	strcat(compiled_modules, " RC");
#endif
#ifdef CONFIG_RSBAC_AUTH
	strcat(compiled_modules, " AUTH");
#endif
#ifdef CONFIG_RSBAC_ACL
	strcat(compiled_modules, " ACL");
#endif
#ifdef CONFIG_RSBAC_CAP
	strcat(compiled_modules, " CAP");
#endif
#ifdef CONFIG_RSBAC_JAIL
	strcat(compiled_modules, " JAIL");
#endif
#ifdef CONFIG_RSBAC_RES
	strcat(compiled_modules, " RES");
#endif
#ifdef CONFIG_RSBAC_PAX
	strcat(compiled_modules, " PAX");
#endif
#ifdef CONFIG_RSBAC_MAINT
	rsbac_printk(KERN_INFO "rsbac_do_init(): Initializing RSBAC %s (Maintenance Mode)\n",
		     RSBAC_VERSION);
	/* Print banner we are initializing */
	printk(KERN_INFO
		"rsbac_do_init(): Initializing RSBAC %s on device %02u:%02u (Maintenance Mode)\n",
		RSBAC_VERSION,
		RSBAC_MAJOR(mnt_p->mnt_sb->s_dev),
		RSBAC_MINOR(mnt_p->mnt_sb->s_dev));

	rsbac_printk(KERN_INFO "rsbac_do_init(): Supported module data structures:%s\n",
		     compiled_modules);
#else
	rsbac_printk(KERN_INFO "rsbac_do_init(): Initializing RSBAC %s on device %02u:%02u\n",
		     RSBAC_VERSION,
		     RSBAC_MAJOR(mnt_p->mnt_sb->s_dev),
		     RSBAC_MINOR(mnt_p->mnt_sb->s_dev));
	/* Print banner we are initializing */
#ifdef CONFIG_RSBAC_RMSG_NOSYSLOG
	if (rsbac_nosyslog)
#endif
		printk(KERN_INFO
		       "rsbac_do_init(): Initializing RSBAC %s\n",
		       RSBAC_VERSION);

	rsbac_printk(KERN_INFO "rsbac_do_init(): compiled modules:%s\n",
		     compiled_modules);
#endif

	device_item_slab = rsbac_slab_create("rsbac_device_item",
			sizeof(struct rsbac_device_list_item_t));

	for (i = 0; i < RSBAC_NR_DEVICE_LISTS; i++) {
		device_head_p[i] = rsbac_kmalloc_clear_unlocked(sizeof(*device_head_p[i]));
		if (!device_head_p[i]) {
			rsbac_printk(KERN_WARNING
				"rsbac_do_init(): Failed to allocate device_list_heads[%s]\n", i);
			return -ENOMEM;
		}
		spin_lock_init(&device_list_locks[i]);
		init_srcu_struct(&device_list_srcu[i]);
		lockdep_set_class(&device_list_locks[i], &device_list_lock_class);
	}

#if defined(CONFIG_RSBAC_PROC)
	rsbac_pr_debug(stack, "free stack before registering proc dir: %lu\n",
		       rsbac_stack_free_space());
	rsbac_printk(KERN_INFO "rsbac_do_init(): Registering RSBAC proc dir\n");
	register_all_rsbac_proc();
#endif
	rsbac_pr_debug(stack, "free stack before get_super: %lu\n",
		       rsbac_stack_free_space());
	/* read fd aci from root device */
	rsbac_pr_debug(ds, "reading aci from device "
		       "number %02u:%02u\n",
		       RSBAC_MAJOR(rsbac_root_dev),
		       RSBAC_MINOR(rsbac_root_dev));
	/* create a private device item */
	new_device_p = create_device_item(mnt_p);
	if (!new_device_p) {
		rsbac_printk(KERN_CRIT
			     "rsbac_do_init(): Could not alloc device item!\n");
		err = -RSBAC_ECOULDNOTADDDEVICE;
		goto out;
	}
	/* Add new_device_p to device list */
	/* OK, go on */
	device_p = add_device_item(new_device_p);
	if (!device_p) {
		rsbac_printk(KERN_CRIT
			     "rsbac_do_init(): Could not add device!\n");
		clear_device_item(new_device_p);
		err = -RSBAC_ECOULDNOTADDDEVICE;
		goto out;
	}

	/* init lists - we need the root device_p to be initialized, but no generic list registered */
	rsbac_printk(KERN_INFO "rsbac_do_init(): Initializing generic lists\n");
	rsbac_list_init();

	rsbac_pr_debug(stack, "free stack before init_debug: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_debug();

	rsbac_printk(KERN_INFO "rsbac_do_init(): reading FD attributes from root dev\n");
	rsbac_pr_debug(stack, "free stack before reading FD lists: %lu\n",
		       rsbac_stack_free_space());
	/* no locking needed, device_p is known and there can be no parallel init! */
	if ((err = register_fd_lists(device_p, rsbac_root_dev))) {
		char *tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);

		if (tmp) {
			rsbac_printk(KERN_WARNING "rsbac_do_init(): File/Dir lists registration failed for dev %02u:%02u, err %s!\n",
				     RSBAC_MAJOR(rsbac_root_dev),
				     RSBAC_MINOR(rsbac_root_dev),
				     get_error_name(tmp, err));
			rsbac_kfree(tmp);
		}
	}
	rsbac_pr_debug(stack, "free stack before DEV lists registration: %lu\n",
		       rsbac_stack_free_space());
	register_dev_lists();
	rsbac_pr_debug(stack, "free stack before registering IPC lists: %lu\n",
		       rsbac_stack_free_space());
	register_ipc_lists();
	rsbac_pr_debug(stack, "free stack before registering USER lists 1: %lu\n",
		       rsbac_stack_free_space());
	register_user_lists1();
	rsbac_pr_debug(stack, "free stack before registering USER lists 2: %lu\n",
		       rsbac_stack_free_space());
	register_user_lists2();
	rsbac_pr_debug(stack, "free stack before registering PROCESS aci: %lu\n",
		       rsbac_stack_free_space());
	register_process_lists();


#ifdef CONFIG_RSBAC_UM
	rsbac_pr_debug(stack, "free stack before GROUP lists registration: %lu\n",
		       rsbac_stack_free_space());
	register_group_lists();
#endif				/* CONFIG_RSBAC_UM */

#ifdef CONFIG_RSBAC_NET_DEV
	register_netdev_lists();
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
	register_nettemp_list();
	register_nettemp_aci_lists();
	register_netobj_lists();
#endif				/* NET_OBJ */

#ifdef CONFIG_RSBAC_FD_CACHE
	if (!rsbac_fd_cache_disable)
		register_fd_cache_lists();
#endif

/* Call other init functions */
#if defined(CONFIG_RSBAC_MAC)
	rsbac_pr_debug(stack, "free stack before init_mac: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_mac();
#endif

#ifdef CONFIG_RSBAC_PM
	rsbac_pr_debug(stack, "free stack before init_pm: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_pm();
#endif

#if defined(CONFIG_RSBAC_DAZ) && !defined(CONFIG_RSBAC_MAINT)
	rsbac_pr_debug(stack, "free stack before init_daz: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_daz();
#endif

#if defined(CONFIG_RSBAC_RC)
	rsbac_pr_debug(stack, "free stack before init_rc: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_rc();
#endif

#if defined(CONFIG_RSBAC_AUTH)
	rsbac_pr_debug(stack, "free stack before init_auth: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_auth();
	if (rsbac_auth_enable_login) {
		struct dentry *t_dentry;
		struct dentry *dir_dentry = NULL;
		struct rsbac_auth_fd_aci_t auth_fd_aci =
		    DEFAULT_AUTH_FD_ACI;

		rsbac_printk(KERN_WARNING "rsbac_do_init(): auth_enable_login is set: setting auth_may_setuid for %s\n",
			     RSBAC_AUTH_LOGIN_PATH);

		/* lookup filename */
		if (mnt_p) {
			dir_dentry =
			    rsbac_lookup_one_len(RSBAC_AUTH_LOGIN_PATH_DIR,
						 mnt_p->mnt_sb->s_root,
						 strlen
						 (RSBAC_AUTH_LOGIN_PATH_DIR));
		}
		if (!dir_dentry) {
			err = -RSBAC_ENOTFOUND;
			rsbac_printk(KERN_WARNING "rsbac_do_init(): call to rsbac_lookup_one_len for /%s failed\n",
				     RSBAC_AUTH_LOGIN_PATH_DIR);
			goto auth_out;
		}
		if (IS_ERR(dir_dentry)) {
			err = PTR_ERR(dir_dentry);
			rsbac_printk(KERN_WARNING "rsbac_do_init(): call to rsbac_lookup_one_len for /%s returned %i\n",
				     RSBAC_AUTH_LOGIN_PATH_DIR, err);
			goto auth_out;
		}
		if (!dir_dentry->d_inode) {
			err = -RSBAC_ENOTFOUND;
			rsbac_printk(KERN_WARNING "rsbac_do_init(): call to rsbac_lookup_one_len for /%s failed\n",
				     RSBAC_AUTH_LOGIN_PATH_DIR);
			dput(dir_dentry);
			goto auth_out;
		}
		t_dentry = rsbac_lookup_one_len(RSBAC_AUTH_LOGIN_PATH_FILE,
						dir_dentry,
						strlen
						(RSBAC_AUTH_LOGIN_PATH_FILE));
		if (!t_dentry) {
			err = -RSBAC_ENOTFOUND;
			rsbac_printk(KERN_WARNING "rsbac_do_init(): call to rsbac_lookup_one_len for /%s/%s failed\n",
				     RSBAC_AUTH_LOGIN_PATH_DIR,
				     RSBAC_AUTH_LOGIN_PATH_FILE);
			goto auth_out;
		}
		if (IS_ERR(t_dentry)) {
			err = PTR_ERR(t_dentry);
			rsbac_printk(KERN_WARNING "rsbac_do_init(): call to rsbac_lookup_one_len for /%s/%s returned %i\n",
				     RSBAC_AUTH_LOGIN_PATH_DIR,
				     RSBAC_AUTH_LOGIN_PATH_FILE, err);
			goto auth_out;
		}
		if (!t_dentry->d_inode) {
			err = -RSBAC_ENOTFOUND;
			rsbac_printk(KERN_WARNING "rsbac_do_init(): call to rsbac_lookup_one_len for /%s/%s failed\n",
				     RSBAC_AUTH_LOGIN_PATH_DIR,
				     RSBAC_AUTH_LOGIN_PATH_FILE);
			dput(t_dentry);
			goto auth_out;
		}

		if (!t_dentry->d_inode) {
			rsbac_printk(KERN_WARNING "rsbac_do_init(): file %s not found\n",
				     RSBAC_AUTH_LOGIN_PATH);
			err = -RSBAC_EINVALIDTARGET;
			goto auth_out_dput;
		}
		/* is inode of type file? */
		if (!S_ISREG(t_dentry->d_inode->i_mode)) {
			rsbac_printk(KERN_WARNING "rsbac_do_init(): %s is no file\n",
				     RSBAC_AUTH_LOGIN_PATH);
			err = -RSBAC_EINVALIDTARGET;
			goto auth_out_dput;
		}
		rsbac_list_get_data(device_p->handles.auth,
				    &t_dentry->d_inode->i_ino,
				    &auth_fd_aci);
		auth_fd_aci.auth_may_setuid = TRUE;
		if (rsbac_list_add(device_p->handles.auth, &t_dentry->d_inode->i_ino, &auth_fd_aci)) {	/* Adding failed! */
			rsbac_printk(KERN_WARNING "rsbac_do_init(): Could not add AUTH file/dir item!\n");
			err = -RSBAC_ECOULDNOTADDITEM;
		}

	      auth_out_dput:
	      auth_out:
		{
		}
	}
#endif

#if defined(CONFIG_RSBAC_ACL)
	rsbac_pr_debug(stack, "free stack before init_acl: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_acl();
#endif

#if defined(CONFIG_RSBAC_UM)
	rsbac_pr_debug(stack, "free stack before init_um: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_um();
#endif
	rsbac_pr_debug(stack, "free stack before init_adf: %lu\n",
		       rsbac_stack_free_space());
	rsbac_init_adf();

#if defined(CONFIG_RSBAC_PAX) && defined(CONFIG_PAX_HOOK_ACL_FLAGS)
	pax_set_initial_flags_func = rsbac_pax_set_flags_func;
#endif

/* Tell that rsbac is initialized                                       */
	rsbac_allow_mounts = TRUE;

/* Add initrd mount */
#if 0 && defined(CONFIG_BLK_DEV_INITRD)
	if (initrd_start) {
		sb_p = user_get_super(MKDEV(RAMDISK_MAJOR, 0));
		if (sb_p) {
			rsbac_mount(sb_p, NULL);
			drop_super(sb_p);
		}
		sb_p = user_get_super(MKDEV(RAMDISK_MAJOR, INITRD_MINOR));
		if (sb_p) {
			rsbac_mount(sb_p, NULL);
			drop_super(sb_p);
		}
	}
#endif

/* Add delayed mounts */
	if (rsbac_mount_list) {
		struct rsbac_mount_list_t * mount_p = rsbac_mount_list;

		while (mount_p) {
			/* skip root dev */
			if(!lookup_device(mount_p->mnt_p->mnt_sb->s_dev, device_hash(mount_p->mnt_p->mnt_sb->s_dev))) {
				rsbac_printk(KERN_INFO "rsbac_do_init(): mounting delayed device %02u:%02u, fs-type %s\n",
					MAJOR(mount_p->mnt_p->mnt_sb->s_dev),
					MINOR(mount_p->mnt_p->mnt_sb->s_dev),
					mount_p->mnt_p->mnt_sb->s_type->name);
				rsbac_mount(mount_p->mnt_p);
			} else {
				mntput(mount_p->mnt_p);
			}
			rsbac_mount_list = mount_p;
			mount_p = mount_p->next;
			kfree(rsbac_mount_list);
		}
		rsbac_mount_list = NULL;
	}

/* Tell that rsbac is initialized                                       */
	rsbac_initialized = TRUE;

/* Force a check, if configured */
#ifdef CONFIG_RSBAC_INIT_CHECK
	rsbac_pr_debug(stack, "free stack before rsbac_check: %lu\n",
		       rsbac_stack_free_space());
	rsbac_printk(KERN_INFO "rsbac_do_init(): Forcing consistency check.\n");
	rsbac_check_lists(1);
#if defined(CONFIG_RSBAC_ACL)
	rsbac_check_acl(1);
#endif
#endif

	if (!current->fs) {
		rsbac_printk(KERN_WARNING "rsbac_do_init(): current->fs is invalid!\n");
		err = -RSBAC_EINVALIDPOINTER;
	}
      out:
	/* We are up and running */
	rsbac_printk(KERN_INFO "rsbac_do_init(): Ready.\n");

	kfree(list_info_p);
	return err;
}


#if  (defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)) \
   || defined(CONFIG_RSBAC_INIT_THREAD)
/* rsbac kernel timer for auto-write */
void wakeup_rsbacd(u_long dummy)
{
	wake_up(&rsbacd_wait);
}
#endif

#ifdef CONFIG_RSBAC_INIT_THREAD
/* rsbac kernel daemon for init */
static int rsbac_initd(void *dummy)
{
	rsbac_printk(KERN_INFO "rsbac_initd(): Initializing.\n");

/* Dead loop for timeout testing */
/*    while(1) { } */

	rsbac_pr_debug(stack, "free stack before rsbac_do_init(): %lu\n",
		       rsbac_stack_free_space());
	/* init RSBAC */
	rsbac_do_init();

	rsbac_pr_debug(stack, "free stack after rsbac_do_init(): %lu\n",
		       rsbac_stack_free_space());
	/* wake up init process */
	wake_up(&rsbacd_wait);
	/* ready */
	rsbac_printk(KERN_INFO "rsbac_initd(): Exiting.\n");
	do_exit(0);
	return 0;
}
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
/* rsbac kernel daemon for auto-write */
static int rsbacd(void *dummy)
{
	struct task_struct *tsk = current;
	char *name = rsbac_kmalloc(RSBAC_MAXNAMELEN);
	unsigned long list_check_time = jiffies + HZ * rsbac_list_check_interval;

	rsbac_printk(KERN_INFO "rsbacd(): Initializing.\n");

	sys_close(0);
	sys_close(1);
	sys_close(2);

	rsbac_pr_debug(auto, "Setting auto timer.\n");
/* This might already have been done for rsbac_initd thread */
#ifndef CONFIG_RSBAC_INIT_THREAD
	init_timer(&rsbac_timer);
	rsbac_timer.function = wakeup_rsbacd;
	rsbac_timer.data = 0;
	rsbac_timer.expires = jiffies + auto_interval;
	add_timer(&rsbac_timer);
#endif
	rsbac_pr_debug(stack, "free stack: %lu\n", rsbac_stack_free_space());
	for (;;) {
		/* wait */
		/* Unblock all signals. */
		flush_signals(tsk);
		spin_lock_irq(&tsk->sighand->siglock);
		flush_signal_handlers(tsk, 1);
		sigemptyset(&tsk->blocked);
		recalc_sigpending();
		spin_unlock_irq(&tsk->sighand->siglock);
		/* set new timer */
		mod_timer(&rsbac_timer, jiffies + auto_interval);
		interruptible_sleep_on(&rsbacd_wait);
#ifdef CONFIG_PM
		if (try_to_freeze())
		    continue;
		/* sleep */
#endif

		/* Cleanup lists regularly */
		if (time_after_eq(jiffies, list_check_time)) {
		list_check_time =
			    jiffies +
			    HZ * rsbac_list_check_interval;
			rsbac_pr_debug(auto, "cleaning up lists\n");
			rsbac_check_lists(1);
		}
		/* Write lists */
		if (rsbac_initialized && !rsbac_debug_no_write) {
			int err = 0;
			/* rsbac_pr_debug(auto, "calling rsbac_write()\n"); */
			down(&rsbac_write_sem);
			if (!rsbac_debug_no_write) {
				up(&rsbac_write_sem);
				err = rsbac_write();
			} else
				up(&rsbac_write_sem);
			if (err < 0) {
				if (name)
					rsbac_printk(KERN_WARNING "rsbacd(): rsbac_write returned error %s!\n",
						     get_error_name(name,
								    err));
				else
					rsbac_printk(KERN_WARNING "rsbacd(): rsbac_write returned error %i!\n",
						     err);
			} else if (err > 0)
				rsbac_pr_debug(auto, "rsbac_write() wrote %i "
					       "lists\n", err);
		}
	}
	return 0;
}
#endif

/************************************************* */
/*               Init function                     */
/************************************************* */

/* All functions return 0, if no error occurred, and a negative error code  */
/* otherwise. The error codes are defined in rsbac_error.h.                 */

struct rsbac_kthread_t {
	struct list_head list;
	rsbac_pid_t pid;
};
struct rsbac_kthread_t * rsbac_kthread;
int rsbac_kthread_size_t;

int rsbac_kthreads_init(void)
{
	rsbac_kthread_size_t = sizeof(struct rsbac_kthread_t);
	rsbac_kthread = kmalloc(rsbac_kthread_size_t, GFP_ATOMIC);
	INIT_LIST_HEAD(&rsbac_kthread->list);
	return 0;
}

int rsbac_mark_kthread(rsbac_pid_t pid)
{
	struct rsbac_kthread_t * rsbac_kthread_new;

	if (rsbac_initialized)
		return 0;
	rsbac_kthread_new = kmalloc(rsbac_kthread_size_t, GFP_ATOMIC);
	rsbac_kthread_new->pid = pid;
	list_add(&rsbac_kthread_new->list, &rsbac_kthread->list);
	return 0;
}

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init(kdev_t root_dev)
#else
int __init rsbac_init(kdev_t root_dev)
#endif
{
#ifdef CONFIG_RSBAC_RC
	struct rsbac_rc_process_aci_t rc_init_p_aci = DEFAULT_RC_P_INIT_ACI;
#endif
#ifdef CONFIG_RSBAC_INIT_THREAD
	struct task_struct * rsbac_init_thread;
#endif
	struct task_struct * rsbacd_thread;
#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_RC)
	rsbac_pid_t init_pid;
	struct rsbac_kthread_t * rsbac_kthread_entry;
	struct list_head * p;
#endif

	int err = 0;
#if  defined(CONFIG_RSBAC_AUTO_WRITE) \
   || defined(CONFIG_RSBAC_INIT_THREAD) || defined(CONFIG_RSBAC_NO_WRITE)
	rsbac_pid_t rsbacd_pid;
#endif

	if (rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_init(): RSBAC already initialized\n");
		return -RSBAC_EREINIT;
	}
	if (!current->fs) {
		rsbac_printk(KERN_WARNING "rsbac_init(): current->fs is invalid!\n");
		return -RSBAC_EINVALIDPOINTER;
	}

	rsbac_root_dev = root_dev;

#if  (defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)) \
   || defined(CONFIG_RSBAC_INIT_THREAD)
	/* init the rsbacd wait queue head */
	init_waitqueue_head(&rsbacd_wait);
#endif

#ifdef CONFIG_RSBAC_INIT_THREAD
/* trigger dependency */
#ifdef CONFIG_RSBAC_MAX_INIT_TIME
#endif
	rsbac_printk(KERN_INFO "rsbac_init(): Setting init timeout to %u seconds (%u jiffies).\n",
		     RSBAC_MAX_INIT_TIME, RSBAC_MAX_INIT_TIME * HZ);
	init_timer(&rsbac_timer);
	rsbac_timer.function = wakeup_rsbacd;
	rsbac_timer.data = 0;
	rsbac_timer.expires = jiffies + (RSBAC_MAX_INIT_TIME * HZ);
	add_timer(&rsbac_timer);

/* Start rsbac thread for init */
	rsbac_init_thread = kthread_create(rsbac_initd, NULL, "rsbac_initd");
	if (IS_ERR(rsbac_init_thread))
		goto panic;
	rsbacd_pid = task_pid(rsbac_init_thread);
	wake_up_process(rsbac_init_thread);
	rsbac_printk(KERN_INFO "rsbac_init(): Started rsbac_initd thread with pid %u\n",
		     pid_nr(rsbacd_pid));

	if (!rsbac_initialized)
		interruptible_sleep_on(&rsbacd_wait);
	if (!rsbac_initialized) {
		rsbac_printk(KERN_ERR
			     "rsbac_init(): *** RSBAC init timed out - RSBAC not correctly initialized! ***\n");
		rsbac_printk(KERN_ERR
			     "rsbac_init(): *** Killing rsbac_initd! ***\n");
		sys_kill(pid_nr(rsbacd_pid), SIGKILL);
		rsbac_initialized = FALSE;
	}
#else
	rsbac_do_init();
#endif

#if defined(CONFIG_RSBAC_AUTO_WRITE) && (CONFIG_RSBAC_AUTO_WRITE > 0)
	if (rsbac_initialized) {
		/* Start rsbacd thread for auto write */
		rsbacd_thread = kthread_create(rsbacd, NULL, "rsbacd");
		if (IS_ERR(rsbacd_thread)) {
			rsbac_printk(KERN_ERR
				     "rsbac_init(): *** Starting rsbacd thread failed with error %i! ***\n",
				     PTR_ERR(rsbacd_thread));
		} else {
			rsbacd_pid = task_pid(rsbacd_thread);
			wake_up_process(rsbacd_thread);
			rsbac_printk(KERN_INFO "rsbac_init(): Started rsbacd thread with pid %u\n",
				     pid_nr(rsbacd_pid));
		}
	}
#endif

/* Ready. */
/*    schedule(); */
#ifdef CONFIG_RSBAC_INIT_THREAD
	sys_wait4(-1, NULL, WNOHANG, NULL);
#endif

/* Add all processes to list of processes as init processes */
#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_RC)
	{
#ifdef CONFIG_RSBAC_MAC
		struct rsbac_mac_user_aci_t * mac_u_aci_p;
#endif
#ifdef CONFIG_RSBAC_RC
		struct rsbac_rc_user_aci_t * rc_u_aci_p;
#endif
		rsbac_uid_t user = RSBAC_SYSADM_UID;
		rsbac_pid_t pid = find_pid_ns(1, &init_pid_ns);
		struct task_struct *p;

#ifdef CONFIG_RSBAC_RC
		union rsbac_target_id_t k_tid;
		union rsbac_attribute_value_t k_attr_val;
#endif

		rsbac_printk(KERN_INFO "rsbac_init(): Adjusting attributes of existing processes\n");
/* Prepare entries: change standard values to root's values */
#ifdef CONFIG_RSBAC_MAC
		mac_u_aci_p = rsbac_kmalloc_unlocked(sizeof(*mac_u_aci_p));
		if (mac_u_aci_p) {
			if(!rsbac_list_get_data
				(user_handles.mac, &user, mac_u_aci_p)) {
				mac_init_p_aci.owner_sec_level =
				    mac_u_aci_p->security_level;
				mac_init_p_aci.owner_initial_sec_level =
				    mac_u_aci_p->initial_security_level;
				mac_init_p_aci.current_sec_level =
				    mac_u_aci_p->initial_security_level;
				mac_init_p_aci.owner_min_sec_level =
				    mac_u_aci_p->min_security_level;
				mac_init_p_aci.mac_owner_categories =
				    mac_u_aci_p->mac_categories;
				mac_init_p_aci.mac_owner_initial_categories =
				    mac_u_aci_p->mac_initial_categories;
				mac_init_p_aci.mac_curr_categories =
				    mac_u_aci_p->mac_initial_categories;
				mac_init_p_aci.mac_owner_min_categories =
				    mac_u_aci_p->mac_min_categories;
				mac_init_p_aci.min_write_open =
				    mac_u_aci_p->security_level;
				mac_init_p_aci.max_read_open =
				    mac_u_aci_p->min_security_level;
				mac_init_p_aci.min_write_categories =
				    mac_u_aci_p->mac_categories;
				mac_init_p_aci.max_read_categories =
				    mac_u_aci_p->mac_min_categories;
				mac_init_p_aci.mac_process_flags =
				    (mac_u_aci_p->
				     mac_user_flags & RSBAC_MAC_P_FLAGS) |
				    RSBAC_MAC_DEF_INIT_P_FLAGS;
			}
			rsbac_kfree(mac_u_aci_p);
		}
#endif

/* Set process aci - first init */
#ifdef CONFIG_RSBAC_MAC
		if (rsbac_list_add
		    (process_handles.mac, &pid,
		     &mac_init_p_aci))
			rsbac_printk(KERN_WARNING "rsbac_do_init(): MAC ACI for Init process 1 could not be added!");
#endif
#ifdef CONFIG_RSBAC_RC
		/* Get boot role */
		if (rsbac_rc_get_boot_role(&rc_init_p_aci.rc_role)) {	/* none: use root's role */
			rc_u_aci_p = rsbac_kmalloc_unlocked(sizeof(*rc_u_aci_p));
			if (rc_u_aci_p) {
				if (!rsbac_list_get_data
				    (user_handles.rc, &user, rc_u_aci_p)) {
					rc_init_p_aci.rc_role = rc_u_aci_p->rc_role;
				} else {	/* last resort: general role */
					rsbac_ds_get_error("rsbac_do_init",
							   A_rc_def_role);
					rc_init_p_aci.rc_role =
					    RSBAC_RC_GENERAL_ROLE;
				}
				rsbac_kfree(rc_u_aci_p);
			}
		}
		rc_kernel_p_aci.rc_role = rc_init_p_aci.rc_role;
		if (rsbac_list_add
		    (process_handles.rc, &pid,
		     &rc_init_p_aci))
			rsbac_printk(KERN_WARNING "rsbac_do_init(): RC ACI for Init process 1 could not be added!");
#endif
		read_lock(&tasklist_lock);
		for_each_process(p)
		{
			/* not for kernel and init though... */
			if ((!p->pid) || (p->pid == 1))
				continue;
			pid = task_pid(p);
			rsbac_pr_debug(ds, "setting aci for process %u (%s)\n", pid, p->comm);
#ifdef CONFIG_RSBAC_MAC
			if (rsbac_list_add
			    (process_handles.mac, &pid,
			     &mac_init_p_aci))
				rsbac_printk(KERN_WARNING "rsbac_do_init(): MAC ACI for Init process %u could not be added!\n",
					     pid);
#endif
#ifdef CONFIG_RSBAC_RC
			k_tid.process = pid;
			if (rsbac_get_attr(SW_GEN, T_PROCESS,
					k_tid,
					A_kernel_thread,
					&k_attr_val,
					FALSE)) {
				rsbac_printk(KERN_WARNING "rsbac_do_init(): RC ACI for Kernel thread %u could not be added!\n", pid);
			}
			if (k_attr_val.kernel_thread) {
				if (rsbac_list_add
				    (process_handles.rc,
				     &pid, &rc_kernel_p_aci))
					rsbac_printk(KERN_WARNING "rsbac_do_init(): RC ACI for Kernel thread %u could not be added!\n",
					     pid);
		}
#endif
		}
		read_unlock(&tasklist_lock);
	}
	list_for_each(p, &rsbac_kthread->list) {
		rsbac_kthread_entry = list_entry(p, 
				struct rsbac_kthread_t, list);
		if (pid_nr(rsbac_kthread_entry->pid) != 1 
				&& rsbac_kthread_entry->pid != rsbacd_pid)
		{
			read_lock(&tasklist_lock);
			if(pid_task(rsbac_kthread_entry->pid, PIDTYPE_PID)) {
				read_unlock(&tasklist_lock);
				rsbac_kthread_notify(rsbac_kthread_entry->pid);
			}
			else {
				read_unlock(&tasklist_lock);
				rsbac_pr_debug(ds, "rsbac_do_init(): skipping gone away pid %u\n",
					pid_nr(rsbac_kthread_entry->pid));
			}
			/* kernel list implementation is for exclusive 
			 * wizards use, let's not free it now till 
			 * i know why it oops. consume about no 
			 * memory anyway. michal.
			 */
			
			/* list_del(&rsbac_kthread_entry->list);
			 * kfree(rsbac_kthread_entry);*/
		}
	} /* explicitly mark init and rsbacd */
	init_pid = find_pid_ns(1, &init_pid_ns);
#ifdef CONFIG_RSBAC_MAC
	if (rsbac_list_add(process_handles.mac, &init_pid, &mac_init_p_aci))
		rsbac_printk(KERN_WARNING "rsbac_do_init(): MAC ACI for \"init\" process could not be added!");
        if (rsbac_list_add(process_handles.mac, &rsbacd_pid, &mac_init_p_aci))
		rsbac_printk(KERN_WARNING "rsbac_do_init(): MAC ACI for \"rsbacd\" process could not be added!");
#endif
#ifdef CONFIG_RSBAC_RC
	if (rsbac_list_add(process_handles.rc, &init_pid, &rc_init_p_aci))
		rsbac_printk(KERN_WARNING "rsbac_do_init(): RC ACI for \"init\" process could not be added");
        if (rsbac_list_add(process_handles.rc, &rsbacd_pid, &rc_kernel_p_aci))
		rsbac_printk(KERN_WARNING "rsbac_do_init(): RC ACI for \"rsbacd\" process could not be added");
#endif
	
	/*kfree(rsbac_kthread);*/
#endif	/* MAC or RC */

	rsbac_printk(KERN_INFO "rsbac_init(): Ready.\n");
	return err;

#ifdef CONFIG_RSBAC_INIT_THREAD
panic:
	rsbac_printk(KERN_ERR "rsbac_init(): *** RSBAC init failed to start - RSBAC not correctly initialized! ***\n");
	/* let's panic - but only when in secure mode, warn otherwise */
#if !defined(CONFIG_RSBAC_MAINT)
#ifdef CONFIG_RSBAC_SOFTMODE
	if (!rsbac_softmode)
		panic("RSBAC: rsbac_init(): *** Unable to initialize - PANIC ***\n");
#endif
	panic("RSBAC: rsbac_init(): *** Unable to initialize - PANIC ***\n");
#endif
#endif
}

int rsbac_kthread_notify(rsbac_pid_t pid)
{
	if (!rsbac_initialized)
		return 0;
//	rsbac_printk(KERN_DEBUG "rsbac_kthread_notify: marking pid %u!\n",
//		     pid);
/* Set process aci */
#ifdef CONFIG_RSBAC_MAC
	if (rsbac_list_add
	    (process_handles.mac, &pid, &mac_init_p_aci))
		rsbac_printk(KERN_WARNING "rsbac_kthread_notify(): MAC ACI for kernel process %u could not be added!",
			     pid_nr(pid));
#endif
#ifdef CONFIG_RSBAC_RC
	if (rsbac_list_add
	    (process_handles.rc, &pid, &rc_kernel_p_aci))
		rsbac_printk(KERN_WARNING "rsbac_kthread_notify(): RC ACI for kernel process %u could not be added!",
			     pid_nr(pid));
#endif
	return 0;
}

/* When mounting a device, its ACI must be read and added to the ACI lists. */

EXPORT_SYMBOL(rsbac_mount);
int rsbac_mount(struct vfsmount * mnt_p)
{
	int err = 0;
	struct rsbac_device_list_item_t *device_p;
	struct rsbac_device_list_item_t *new_device_p;
	rsbac_boolean_t old_no_write;
	u_int hash;
	int srcu_idx;

	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_mount(): called from interrupt, process %u(%s)!\n",
				current->pid, current->comm);
		return -RSBAC_EFROMINTERRUPT;
	}
	if (!mnt_p || !mnt_p->mnt_sb) {
		rsbac_printk(KERN_WARNING "rsbac_mount(): called with NULL pointer\n");
		return -RSBAC_EINVALIDPOINTER;
	}
	if (!rsbac_allow_mounts) {
		struct rsbac_mount_list_t * mount_p;

#ifdef CONFIG_RSBAC_INIT_DELAY
		if (!RSBAC_MAJOR(rsbac_delayed_root)
		    && !RSBAC_MINOR(rsbac_delayed_root)
		    && rsbac_delayed_root_str[0]
		    ) {		/* translate string to kdev_t */
			char *p = rsbac_delayed_root_str;
			u_int major = 0;
			u_int minor = 0;

			major = simple_strtoul(p, NULL, 0);
			while ((*p != ':') && (*p != '\0'))
				p++;
			if (*p) {
				p++;
				minor = simple_strtoul(p, NULL, 0);
			}
			rsbac_delayed_root = RSBAC_MKDEV(major, minor);
		}
		if (!rsbac_no_delay_init
		    && ((!RSBAC_MAJOR(rsbac_delayed_root)
			 && !RSBAC_MINOR(rsbac_delayed_root)
			 && (MAJOR(mnt_p->mnt_sb->s_dev) > 1)
			)
			|| ((RSBAC_MAJOR(rsbac_delayed_root)
			     || RSBAC_MINOR(rsbac_delayed_root)
			    )
			    &&
			    ((MAJOR(mnt_p->mnt_sb->s_dev) ==
			      RSBAC_MAJOR(rsbac_delayed_root))
			     && (!RSBAC_MINOR(rsbac_delayed_root)
				 || (MINOR(mnt_p->mnt_sb->s_dev) ==
				     RSBAC_MINOR(rsbac_delayed_root))
			     )
			    )
			)
		    )
		    ) {
			if (RSBAC_MAJOR(rsbac_delayed_root)
			    || RSBAC_MINOR(rsbac_delayed_root)) {
				rsbac_printk(KERN_INFO "rsbac_mount(): forcing delayed RSBAC init on DEV %02u:%02u, matching %02u:%02u!\n",
					     MAJOR(mnt_p->mnt_sb->s_dev),
					     MINOR(mnt_p->mnt_sb->s_dev),
					     RSBAC_MAJOR
					     (rsbac_delayed_root),
					     RSBAC_MINOR
					     (rsbac_delayed_root));
			} else {
				rsbac_printk(KERN_INFO "rsbac_mount(): forcing delayed RSBAC init on DEV %02u:%02u!\n",
					     MAJOR(mnt_p->mnt_sb->s_dev),
					     MINOR(mnt_p->mnt_sb->s_dev));
			}
			rsbac_root_mnt_p = mnt_p;
			rsbac_init(mnt_p->mnt_sb->s_dev);
			return 0;
		}
#endif

		rsbac_printk(KERN_WARNING "rsbac_mount(): RSBAC not initialized while mounting DEV %02u:%02u, fs-type %s, delaying\n",
				MAJOR(mnt_p->mnt_sb->s_dev), MINOR(mnt_p->mnt_sb->s_dev),
				mnt_p->mnt_sb->s_type->name);
		mount_p = kmalloc(sizeof(*mount_p), GFP_KERNEL);
		if (mount_p) {
			mount_p->mnt_p = mntget(mnt_p);
			mount_p->next = rsbac_mount_list;
			rsbac_mount_list = mount_p;
		}

		return -RSBAC_ENOTINITIALIZED;
	}
	rsbac_pr_debug(ds, "mounting device %02u:%02u\n",
		       MAJOR(mnt_p->mnt_sb->s_dev), MINOR(mnt_p->mnt_sb->s_dev));
	rsbac_pr_debug(stack, "free stack: %lu\n", rsbac_stack_free_space());
	down(&rsbac_write_sem);
	old_no_write = rsbac_debug_no_write;
	rsbac_debug_no_write = TRUE;
	up(&rsbac_write_sem);
	hash = device_hash(mnt_p->mnt_sb->s_dev);
	srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
	device_p = lookup_device(mnt_p->mnt_sb->s_dev, hash);
	/* repeated mount? */
	if (device_p) {
		rsbac_printk(KERN_INFO "rsbac_mount: repeated mount %u of device %02u:%02u\n",
			     device_p->mount_count, MAJOR(mnt_p->mnt_sb->s_dev),
			     MINOR(mnt_p->mnt_sb->s_dev));
		device_p->mount_count++;
		if (!device_p->mnt_p)
			device_p->mnt_p = mntget(mnt_p);
		else
		        if (   device_p->mnt_p->mnt_mountpoint
		            && (device_p->mnt_p->mnt_mountpoint->d_sb->s_dev == device_p->mnt_p->mnt_sb->s_dev)
		    	   ) {
				mntput(device_p->mnt_p);
				device_p->mnt_p = mntget(mnt_p);
		        }
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
	} else {
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
		/* OK, go on */
		new_device_p = create_device_item(mnt_p);
		rsbac_pr_debug(stack, "after creating device item: free stack: %lu\n",
			       rsbac_stack_free_space());
		if (!new_device_p) {
			rsbac_debug_no_write = old_no_write;
			return -RSBAC_ECOULDNOTADDDEVICE;
		}

		srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
		/* make sure to only add, if this device item has not been added in the meantime */
		device_p = lookup_device(mnt_p->mnt_sb->s_dev, hash);
		if (device_p) {
			rsbac_printk(KERN_WARNING "rsbac_mount(): mount race for device %02u:%02u detected!\n",
				     MAJOR(mnt_p->mnt_sb->s_dev),
				     MINOR(mnt_p->mnt_sb->s_dev));
			device_p->mount_count++;
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			clear_device_item(new_device_p);
		} else {
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			device_p = add_device_item(new_device_p);
			if (!device_p) {
				rsbac_printk(KERN_WARNING "rsbac_mount: adding device %02u:%02u failed!\n",
					     MAJOR(mnt_p->mnt_sb->s_dev),
					     MINOR(mnt_p->mnt_sb->s_dev));
				clear_device_item(new_device_p);
				rsbac_debug_no_write = old_no_write;
				return -RSBAC_ECOULDNOTADDDEVICE;
			}
			mntget(device_p->mnt_p);
		}

		/* we do not lock device head - we know the device_p and hope for the best... */
		/* also, we are within kernel mount sem */
		if ((err = register_fd_lists(new_device_p, mnt_p->mnt_sb->s_dev))) {
			char *tmp;

			tmp = rsbac_kmalloc(RSBAC_MAXNAMELEN);
			if (tmp) {
				rsbac_printk(KERN_WARNING "rsbac_mount(): File/Dir ACI registration failed for dev %02u:%02u, err %s!\n",
					     MAJOR(mnt_p->mnt_sb->s_dev),
					     MINOR(mnt_p->mnt_sb->s_dev),
					     get_error_name(tmp, err));
				rsbac_kfree(tmp);
			}
		}
		rsbac_pr_debug(stack, "after registering fd lists: free stack: %lu\n",
			       rsbac_stack_free_space());
	}

/* call other mount functions */
#if defined(CONFIG_RSBAC_MAC)
	rsbac_mount_mac(mnt_p->mnt_sb->s_dev);
	rsbac_pr_debug(stack, "after mount_mac: free stack: %lu\n",
		       rsbac_stack_free_space());
#endif
#if defined(CONFIG_RSBAC_AUTH)
	rsbac_mount_auth(mnt_p->mnt_sb->s_dev);
	rsbac_pr_debug(stack, "after mount_auth: free stack: %lu\n",
		       rsbac_stack_free_space());
#endif
#if defined(CONFIG_RSBAC_ACL)
	rsbac_mount_acl(mnt_p->mnt_sb->s_dev);
	rsbac_pr_debug(stack, "after mount_acl: free stack: %lu\n",
		       rsbac_stack_free_space());
#endif
#if defined(CONFIG_RSBAC_REG)
	rsbac_mount_reg(mnt_p->mnt_sb->s_dev);
	rsbac_pr_debug(stack, "after mount_reg: free stack: %lu\n",
		       rsbac_stack_free_space());
#endif				/* REG */

	rsbac_debug_no_write = old_no_write;
	return err;
}

/* When umounting a device, its ACI must be removed from the ACI lists.     */
/* Removing the device ACI should be no problem.                            */

EXPORT_SYMBOL(rsbac_umount);
int rsbac_umount(struct vfsmount *mnt_p)
{
	struct rsbac_device_list_item_t *device_p;
	kdev_t kdev;
	u_int hash;

	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_umount(): called from interrupt, process %u(%s)!\n",
				current->pid, current->comm);
		return -RSBAC_EFROMINTERRUPT;
	}
	if (!mnt_p) {
		rsbac_printk(KERN_WARNING "rsbac_umount(): called with NULL pointer\n");
		return -RSBAC_EINVALIDPOINTER;
	}
	if (!rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_umount(): RSBAC not initialized\n");
		if (rsbac_mount_list) {
			struct rsbac_mount_list_t * mount_p;
			struct rsbac_mount_list_t * prev_mount_p;

			mount_p = rsbac_mount_list;
			prev_mount_p = NULL;
			while (mount_p) {
				if (mount_p->mnt_p == mnt_p) {
					mntput(mnt_p);
					rsbac_printk(KERN_WARNING "rsbac_umount(): found delayed mount for device %02u:%02u, removing\n",
							RSBAC_MAJOR(mnt_p->mnt_sb->s_dev), RSBAC_MINOR(mnt_p->mnt_sb->s_dev));
					if (prev_mount_p) {
						prev_mount_p->next = mount_p->next;
						kfree (mount_p);
						mount_p = prev_mount_p->next;
					} else {
						rsbac_mount_list = mount_p->next;
						kfree (mount_p);
						mount_p = rsbac_mount_list;
					}
				} else {
					prev_mount_p = mount_p;
					mount_p = mount_p->next;
				}
			}
		}

		return -RSBAC_ENOTINITIALIZED;
	}
	kdev = mnt_p->mnt_sb->s_dev;
	rsbac_pr_debug(ds, "umounting device %02u:%02u\n",
		       MAJOR(kdev), MINOR(kdev));

	/* sync attribute lists */
#if defined(CONFIG_RSBAC_AUTO_WRITE)
	if (!rsbac_debug_no_write) {
		down(&rsbac_write_sem);
		/* recheck no_write with lock - might have been set in between */
		if (!rsbac_debug_no_write) {
			up(&rsbac_write_sem);
			rsbac_write();
		} else
			up(&rsbac_write_sem);
	}
#endif
/* call other umount functions */
#if defined(CONFIG_RSBAC_MAC)
	rsbac_umount_mac(kdev);
#endif
#if defined(CONFIG_RSBAC_AUTH)
	rsbac_umount_auth(kdev);
#endif
#if defined(CONFIG_RSBAC_ACL)
	rsbac_umount_acl(kdev);
#endif
#if defined(CONFIG_RSBAC_REG)
	rsbac_umount_reg(kdev);
#endif

	hash = device_hash(kdev);
	/* wait for write access to device_list_head */
	spin_lock(&device_list_locks[hash]);
	while (!RSBAC_IS_AUTO_DEV(umount_device_in_progress)) {
		DECLARE_WAIT_QUEUE_HEAD(auto_wait);
		struct timer_list auto_timer;

		spin_unlock(&device_list_locks[hash]);
		
		init_timer(&auto_timer);
		auto_timer.function = wakeup_auto;
		auto_timer.data = (u_long) & auto_wait;
		auto_timer.expires = jiffies + HZ;
		add_timer(&auto_timer);
		interruptible_sleep_on(&auto_wait);

		spin_lock(&device_list_locks[hash]);
	}
	/* OK, nobody else is working on it... */
	umount_device_in_progress = kdev;
	device_p = lookup_device(kdev, hash);
	if (device_p) {
		if (device_p->mount_count == 1) {
			/* remove_device_item unlocks device_list_locks[hash]! */
			remove_device_item(kdev);
			aci_detach_fd_lists(device_p);
			if (device_p->mnt_p)
				mntput(device_p->mnt_p);
			clear_device_item(device_p);
			spin_lock(&device_list_locks[hash]);
		} else {
			if (device_p->mount_count > 1) {
				device_p->mount_count--;
				if (device_p->mnt_p == mnt_p) {
					device_p->mnt_p = NULL;
					spin_unlock(&device_list_locks[hash]);
					mntput(mnt_p);
					rsbac_printk(KERN_WARNING "rsbac_umount: removed primary mount for device %02u:%02u, inheritance broken!\n",
						     RSBAC_MAJOR(kdev),
						     RSBAC_MINOR(kdev));
					spin_lock(&device_list_locks[hash]);
				}
			} else {
				rsbac_printk(KERN_WARNING "rsbac_umount: device %02u:%02u has mount_count < 1!\n",
					     RSBAC_MAJOR(kdev),
					     RSBAC_MINOR(kdev));
			}
		}
	}
	umount_device_in_progress = RSBAC_AUTO_DEV;
	spin_unlock(&device_list_locks[hash]);

#ifdef CONFIG_RSBAC_FD_CACHE
	rsbac_fd_cache_invalidate_all();
#endif

	return 0;
}

/* On pivot_root, we must unblock the dentry tree of the old root */
/* by putting all cached rsbac.dat dentries */

int rsbac_free_dat_dentries(void)
{
	struct rsbac_device_list_item_t *device_p;
	u_int i;

	if (!rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_free_dat_dentry(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}

	rsbac_printk(KERN_INFO "rsbac_free_dat_dentry(): freeing dat dir dentries\n");

	for (i = 0; i < RSBAC_NR_DEVICE_LISTS; i++) {
		spin_lock(&device_list_locks[i]);
		device_p = device_head_p[i]->head;
		while (device_p) {
			if (device_p->rsbac_dir_dentry_p) {
				dput(device_p->rsbac_dir_dentry_p);
				device_p->rsbac_dir_dentry_p = NULL;
			}
			device_p = device_p->next;
		}
		spin_unlock(&device_list_locks[i]);
	}
	return 0;
}

/***************************************************/
/* We also need some status information...         */

int rsbac_stats(void)
{
	struct rsbac_device_list_item_t *device_p;
	long fd_count;
	u_long fd_sum = 0;
	u_long dev_sum = 0;
	u_long ipc_sum = 0;
	u_long user_sum = 0;
	u_long process_sum = 0;
#if defined(CONFIG_RSBAC_UM)
	u_long group_sum = 0;
#endif
#if defined(CONFIG_RSBAC_NET_OBJ)
	u_long nettemp_sum = 0;
	u_long lnetobj_sum = 0;
	u_long rnetobj_sum = 0;
#endif
	u_long total_sum = 0;
	long tmp_count = 0;
	u_int i;
	int srcu_idx;

	if (!rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_stats(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	for (i = 0; i < RSBAC_NR_DEVICE_LISTS; i++) {
		srcu_idx = srcu_read_lock(&device_list_srcu[i]);
/*    rsbac_printk(KERN_INFO "rsbac_stats(): currently %u processes working on file/dir aci\n",
                     device_list_lock.lock); */
		device_p = rcu_dereference(device_head_p[i])->head;
		while (device_p) {	/* for all sublists */
			fd_count = rsbac_list_count(device_p->handles.gen);
			if (fd_count > 0) {
				rsbac_printk(", %lu GEN", fd_count);
				fd_sum += fd_count;
			}

#if defined(CONFIG_RSBAC_MAC)
			fd_count = rsbac_list_count(device_p->handles.mac);
			if (fd_count > 0) {
				rsbac_printk(", %lu MAC", fd_count);
				fd_sum += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_PM)
			fd_count = rsbac_list_count(device_p->handles.pm);
			if (fd_count > 0) {
				rsbac_printk(", %lu PM", fd_count);
				fd_sum += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_DAZ)
			fd_count = rsbac_list_count(device_p->handles.daz);
			if (fd_count > 0) {
				rsbac_printk(", %lu DAZ", fd_count);
				fd_sum += fd_count;
			}
#if defined(CONFIG_RSBAC_DAZ_CACHE)
			fd_count = rsbac_list_count(device_p->handles.dazs);
			if (fd_count > 0) {
				rsbac_printk(", %lu DAZ SCANNED", fd_count);
				fd_sum += fd_count;
			}
#endif
#endif

#if defined(CONFIG_RSBAC_FF)
			fd_count = rsbac_list_count(device_p->handles.ff);
			if (fd_count > 0) {
				rsbac_printk(", %lu FF", fd_count);
				fd_sum += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_RC)
			fd_count = rsbac_list_count(device_p->handles.rc);
			if (fd_count > 0) {
				rsbac_printk(", %lu RC", fd_count);
				fd_sum += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_AUTH)
			fd_count = rsbac_list_count(device_p->handles.auth);
			if (fd_count > 0) {
				rsbac_printk(", %lu AUTH", fd_count);
				fd_sum += fd_count;
			}
#endif

#if defined(CONFIG_RSBAC_CAP)
			fd_count = rsbac_list_count(device_p->handles.cap);
			if (fd_count > 0) {
				rsbac_printk(", %lu CAP", fd_count);
				fd_sum += fd_count;
			}
#endif
#if defined(CONFIG_RSBAC_RES)
			fd_count = rsbac_list_count(device_p->handles.res);
			if (fd_count > 0) {
				rsbac_printk(", %lu RES", fd_count);
				fd_sum += fd_count;
			}
#endif
#if defined(CONFIG_RSBAC_PAX)
			fd_count = rsbac_list_count(device_p->handles.pax);
			if (fd_count > 0) {
				rsbac_printk(", %lu PAX", fd_count);
				fd_sum += fd_count;
			}
#endif

			rsbac_printk("\n");
			device_p = device_p->next;
		}
		tmp_count += rcu_dereference(device_head_p[i])->count;
		srcu_read_unlock(&device_list_srcu[i], srcu_idx);
	}
	rsbac_printk(KERN_INFO "rsbac_stats(): Sum of %u Devices with %lu fd-items\n",
		     tmp_count, fd_sum);
	/* free access to device_list_head */
	total_sum += fd_sum;

	/* dev lists */
	tmp_count = rsbac_list_count(dev_handles.gen);
	rsbac_printk(KERN_INFO "DEV items: %lu GEN", tmp_count);
	dev_sum += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(dev_handles.mac);
	rsbac_printk(", %lu MAC", tmp_count);
	dev_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(dev_handles.pm);
	rsbac_printk(", %lu PM", tmp_count);
	dev_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(dev_major_handles.rc);
	rsbac_printk(", %lu major RC", tmp_count);
	dev_sum += tmp_count;
	tmp_count = rsbac_list_count(dev_handles.rc);
	rsbac_printk(", %lu RC", tmp_count);
	dev_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu DEV items\n", dev_sum);
	total_sum += dev_sum;

	/* ipc lists */
	rsbac_printk(KERN_INFO "IPC items: no GEN");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(ipc_handles.mac);
	rsbac_printk(", %lu MAC", tmp_count);
	ipc_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(ipc_handles.pm);
	rsbac_printk(", %lu PM", tmp_count);
	ipc_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(ipc_handles.rc);
	rsbac_printk(", %lu RC", tmp_count);
	ipc_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_list_count(ipc_handles.jail);
	rsbac_printk(", %lu JAIL", tmp_count);
	ipc_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu IPC items\n", ipc_sum);
	total_sum += ipc_sum;

	/* user lists */
	tmp_count = rsbac_list_count(user_handles.gen);
	rsbac_printk(KERN_INFO "USER items: %lu GEN", tmp_count);
	user_sum += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(user_handles.mac);
	rsbac_printk(", %lu MAC", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(user_handles.pm);
	rsbac_printk(", %lu PM", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_DAZ)
	tmp_count = rsbac_list_count(user_handles.daz);
	rsbac_printk(", %lu DAZ", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(user_handles.rc);
	rsbac_printk(", %lu RC", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	tmp_count = rsbac_list_count(user_handles.auth);
	rsbac_printk(", %lu AUTH", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_CAP)
	tmp_count = rsbac_list_count(user_handles.cap);
	rsbac_printk(", %lu CAP", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_list_count(user_handles.jail);
	rsbac_printk(", %lu JAIL", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RES)
	tmp_count = rsbac_list_count(user_handles.res);
	rsbac_printk(", %lu RES", tmp_count);
	user_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PAX)
	tmp_count = rsbac_list_count(user_handles.pax);
	rsbac_printk(", %lu PAX", tmp_count);
	user_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu USER items\n", user_sum);
	total_sum += user_sum;

	/* process lists */
	tmp_count = rsbac_list_count(process_handles.gen);
	rsbac_printk(KERN_INFO "PROCESS items: %lu GEN", tmp_count);
	process_sum += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(process_handles.mac);
	rsbac_printk(", %lu MAC", tmp_count);
	process_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(process_handles.pm);
	rsbac_printk(", %lu PM", tmp_count);
	process_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_DAZ)
	tmp_count = rsbac_list_count(process_handles.daz);
	rsbac_printk(", %lu DAZ", tmp_count);
	process_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(process_handles.rc);
	rsbac_printk(", %lu RC", tmp_count);
	process_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	tmp_count = rsbac_list_count(process_handles.auth);
	rsbac_printk(", %lu AUTH", tmp_count);
	process_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_CAP)
	tmp_count = rsbac_list_count(process_handles.cap);
	rsbac_printk(", %lu CAP", tmp_count);
	process_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_list_count(process_handles.jail);
	rsbac_printk(", %lu JAIL", tmp_count);
	process_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu PROCESS items\n", process_sum);
	total_sum += process_sum;

#if defined(CONFIG_RSBAC_UM)
	/* group lists */
	rsbac_printk(KERN_INFO "GROUP items: ");
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	tmp_count = rsbac_list_count(group_handles.rc);
	rsbac_printk("%lu RC", tmp_count);
	user_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu GROUP items\n", group_sum);
	total_sum += group_sum;
#endif

#if defined(CONFIG_RSBAC_NET_OBJ)
	/* nettemp lists */
	rsbac_printk(KERN_INFO "NETTEMP items: ");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(nettemp_handles.mac);
	rsbac_printk("%lu MAC, ", tmp_count);
	nettemp_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(nettemp_handles.pm);
	rsbac_printk("%lu PM, ", tmp_count);
	nettemp_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(nettemp_handles.rc);
	rsbac_printk("%lu RC, ", tmp_count);
	nettemp_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu NETTEMP items\n", nettemp_sum);
	total_sum += nettemp_sum;

	/* local netobj lists */
	rsbac_printk(KERN_INFO "Local NETOBJ items:");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(lnetobj_handles.mac);
	rsbac_printk(" %lu MAC,", tmp_count);
	lnetobj_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(lnetobj_handles.pm);
	rsbac_printk(" %lu PM,", tmp_count);
	lnetobj_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(lnetobj_handles.rc);
	rsbac_printk(" %lu RC", tmp_count);
	lnetobj_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu Local NETOBJ items\n",
		     lnetobj_sum);
	total_sum += lnetobj_sum;

	/* remote netobj lists */
	rsbac_printk(KERN_INFO "Remote NETOBJ items:");
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_list_count(rnetobj_handles.mac);
	rsbac_printk(" %lu MAC,", tmp_count);
	rnetobj_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_list_count(rnetobj_handles.pm);
	rsbac_printk(" %lu PM,", tmp_count);
	rnetobj_sum += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_list_count(rnetobj_handles.rc);
	rsbac_printk(" %lu RC", tmp_count);
	rnetobj_sum += tmp_count;
#endif
	rsbac_printk("\n");
	rsbac_printk(KERN_INFO "Sum of %lu Remote NETOBJ items\n",
		     rnetobj_sum);
	total_sum += rnetobj_sum;
#endif				/* NET_OBJ */

	rsbac_printk(KERN_INFO "Total of %lu registered rsbac-items\n", total_sum);

	rsbac_printk(KERN_INFO "adf_request calls: file: %lu, dir: %lu, fifo: %lu, symlink: %lu, dev: %lu, ipc: %lu, scd: %lu, user: %lu, process: %lu, netdev: %lu, nettemp: %lu, netobj: %lu, unixsock: %lu\n",
		     rsbac_adf_request_count[T_FILE],
		     rsbac_adf_request_count[T_DIR],
		     rsbac_adf_request_count[T_FIFO],
		     rsbac_adf_request_count[T_SYMLINK],
		     rsbac_adf_request_count[T_DEV],
		     rsbac_adf_request_count[T_IPC],
		     rsbac_adf_request_count[T_SCD],
		     rsbac_adf_request_count[T_USER],
		     rsbac_adf_request_count[T_PROCESS],
		     rsbac_adf_request_count[T_NETDEV],
		     rsbac_adf_request_count[T_NETTEMP],
		     rsbac_adf_request_count[T_NETOBJ],
		     rsbac_adf_request_count[T_UNIXSOCK]);
	rsbac_printk(KERN_INFO "adf_set_attr calls: file: %lu, dir: %lu, fifo: %lu, symlink: %lu, dev: %lu, ipc: %lu, scd: %lu, user: %lu, process: %lu, netdev: %lu, nettemp: %lu, netobj: %lu, unixsock: %lu\n",
		     rsbac_adf_set_attr_count[T_FILE],
		     rsbac_adf_set_attr_count[T_DIR],
		     rsbac_adf_set_attr_count[T_FIFO],
		     rsbac_adf_set_attr_count[T_SYMLINK],
		     rsbac_adf_set_attr_count[T_DEV],
		     rsbac_adf_set_attr_count[T_IPC],
		     rsbac_adf_set_attr_count[T_SCD],
		     rsbac_adf_set_attr_count[T_USER],
		     rsbac_adf_set_attr_count[T_PROCESS],
		     rsbac_adf_set_attr_count[T_NETDEV],
		     rsbac_adf_set_attr_count[T_NETTEMP],
		     rsbac_adf_set_attr_count[T_NETOBJ],
		     rsbac_adf_set_attr_count[T_UNIXSOCK]);

#if defined(CONFIG_RSBAC_PM)
	rsbac_stats_pm();
#endif
#if defined(CONFIG_RSBAC_RC)
	rsbac_stats_rc();
#endif
#if defined(CONFIG_RSBAC_AUTH)
	rsbac_stats_auth();
#endif
#if defined(CONFIG_RSBAC_ACL)
	rsbac_stats_acl();
#endif
	return 0;
}

/***************************************************/
/* rsbac_write() to write all dirty lists to disk  */
/*               returns no. of lists written      */

#if defined(CONFIG_RSBAC_AUTO_WRITE)
int rsbac_write()
{
	int err = 0;
	u_int count = 0;
	int subcount;

	if (!rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_write(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (rsbac_debug_no_write)
		return 0;

	subcount = rsbac_write_lists();
	if (subcount > 0) {
		count += subcount;
	} else if (subcount < 0) {
		err = subcount;
		if (err != -RSBAC_ENOTWRITABLE) {
			rsbac_printk(KERN_WARNING "rsbac_write(): rsbac_write_lists() returned error %i\n",
				     err);
		}
	}

#if defined(CONFIG_RSBAC_REG)
	subcount = rsbac_write_reg();
	if (subcount > 0) {
		count += subcount;
	} else if (subcount < 0) {
		err = subcount;
		if (err != -RSBAC_ENOTWRITABLE) {
			rsbac_printk(KERN_WARNING "rsbac_write(): rsbac_write_reg() returned error %i\n",
				     err);
		}
	}
#endif

	if (count > 0)
		rsbac_pr_debug(write, "total of %u lists written\n", count);
	return count;
}
#endif

/************************************************* */
/*               Attribute functions               */
/************************************************* */

/* A rsbac_set_attr() call for a non-existing object, user                  */
/* or process entry will first add the target and then set the attribute.   */
/* Invalid combinations and trying to set security_level to or from         */
/* SL_rsbac_internal return an error.                                       */
/* A rsbac_get_attr() call for a non-existing target will return the        */
/* default value stored in def_aci, which should be the first enum item.*/

/* All these procedures handle the rw-spinlocks to protect the targets during */
/* access.                                                                  */

/* get the parent of a target
 * returns -RSBAC_EINVALIDTARGET for non-fs targets
 * and -RSBAC_ENOTFOUND, if no parent available
 * In kernels >= 2.4.0, device_p->d_covers is used and the device_p item is
 * properly locked for reading, so never call with a write lock held on
 * device_p!
 */
#if defined(CONFIG_RSBAC_REG)
EXPORT_SYMBOL(rsbac_get_parent);
#endif
int rsbac_get_parent(enum rsbac_target_t target,
		     union rsbac_target_id_t tid,
		     enum rsbac_target_t *parent_target_p,
		     union rsbac_target_id_t *parent_tid_p)
{
	int srcu_idx;

	if (!parent_target_p || !parent_tid_p)
		return -RSBAC_EINVALIDPOINTER;
/*
	rsbac_pr_debug(ds, "Getting file/dir/fifo/symlink "
		       "parent for device %02u:%02u, inode %lu, dentry_p %p\n",
		       RSBAC_MAJOR(tid.file.device),
		       RSBAC_MINOR(tid.file.device),
		       (u_long)tid.file.inode, tid.file.dentry_p);
*/
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		break;
	default:
		return -RSBAC_EINVALIDTARGET;
	}

	if (!tid.file.dentry_p)
		return -RSBAC_ENOTFOUND;

#ifdef CONFIG_RSBAC_XSTATS
	get_parent_count++;
#endif
	*parent_target_p = T_DIR;
	/* Is this dentry root of a mounted device? */
	if (tid.file.dentry_p->d_sb
	    && (tid.file.dentry_p->d_sb->s_root == tid.file.dentry_p)
	    ) {
		struct rsbac_device_list_item_t *device_p;
		u_int hash;

		if (tid.file.device == rsbac_root_dev)
			return -RSBAC_ENOTFOUND;
		hash = device_hash(tid.file.device);
		/* wait for read access to device_list_head */
		srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
		device_p = lookup_device(tid.file.device, hash);
		if (!device_p
		    || !device_p->mnt_p
		    || !device_p->mnt_p->mnt_mountpoint
		    || !device_p->mnt_p->mnt_mountpoint->d_parent
		    || (device_p->mnt_p->mnt_mountpoint->d_parent == device_p->mnt_p->mnt_mountpoint)
		    || !device_p->mnt_p->mnt_mountpoint->d_parent->d_inode
		    || !device_p->mnt_p->mnt_mountpoint->d_parent->d_inode->i_ino
		    || !device_p->mnt_p->mnt_mountpoint->d_sb
		    || !device_p->mnt_p->mnt_mountpoint->d_sb->s_dev
		    || (device_p->mnt_p->mnt_mountpoint->d_sb->s_dev == tid.file.device)) {
			/* free access to device_list_head */
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			return -RSBAC_ENOTFOUND;
		}
		parent_tid_p->dir.device =
		    device_p->mnt_p->mnt_mountpoint->d_parent->d_sb->s_dev;
		parent_tid_p->dir.inode =
		    device_p->mnt_p->mnt_mountpoint->d_parent->d_inode->i_ino;
		parent_tid_p->dir.dentry_p = device_p->mnt_p->mnt_mountpoint->d_parent;
		/* free access to device_list_head */
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
	} else {		/* no root of filesystem -> use d_parent, dev keeps unchanged */
		if (!tid.file.dentry_p->d_parent) {
			rsbac_printk(KERN_DEBUG "rsbac_get_parent(): oops - d_parent is NULL!\n");
			return -RSBAC_ENOTFOUND;
		}
		if (tid.file.dentry_p == tid.file.dentry_p->d_parent) {
			// rsbac_printk(KERN_DEBUG "rsbac_get_parent(): oops - d_parent == dentry_p!\n");
			return -RSBAC_ENOTFOUND;
		}
		if (!tid.file.dentry_p->d_parent->d_inode) {
			rsbac_printk(KERN_DEBUG "rsbac_get_parent(): oops - d_parent has no d_inode!\n");
			return -RSBAC_ENOTFOUND;
		}
		if (!tid.file.dentry_p->d_parent->d_inode->i_ino)
		{
			rsbac_printk(KERN_DEBUG "rsbac_get_parent(): oops - d_parent d_inode->i_ino is 0!\n");
			return -RSBAC_ENOTFOUND;
		}
		parent_tid_p->dir.device = tid.file.device;
		parent_tid_p->dir.inode =
		    tid.file.dentry_p->d_parent->d_inode->i_ino;
		parent_tid_p->dir.dentry_p = tid.file.dentry_p->d_parent;
	}
	return 0;
}

static int get_attr_fd(rsbac_list_ta_number_t ta_number,
			enum rsbac_switch_target_t module,
			enum rsbac_target_t target,
			union rsbac_target_id_t *tid_p,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *value,
			rsbac_boolean_t inherit)
{
	int err = 0;
	struct rsbac_device_list_item_t *device_p;
#if defined(CONFIG_RSBAC_FF)
	rsbac_ff_flags_t ff_flags = 0;
	rsbac_ff_flags_t ff_tmp_flags;
	rsbac_ff_flags_t ff_mask = -1;
#endif
	u_int hash;
	int srcu_idx;

	/* use loop for inheritance - used to be recursive calls */
	for (;;) {
/*		rsbac_pr_debug(ds, "Getting file/dir/fifo/"
			       "symlink attribute %u for device %02u:%02u, "
			       "inode %lu, dentry_p %p\n", attr,
			       RSBAC_MAJOR(tid_p->file.device),
			       RSBAC_MINOR(tid_p->file.device),
			       (u_long)tid_p->file.inode,
			       tid_p->file.dentry_p); */
		hash = device_hash(tid_p->file.device);
		/* wait for read access to device_list_head */
		srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
		/* OK, go on */
		/* rsbac_pr_debug(ds, "passed device read lock\n"); */
		/* lookup device */
		device_p = lookup_device(tid_p->file.device, hash);
		if (!device_p) {
			rsbac_printk(KERN_WARNING "rsbac_get_attr(): unknown device %02u:%02u\n",
				     RSBAC_MAJOR(tid_p->file.device),
				     RSBAC_MINOR(tid_p->file.device));
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			return -RSBAC_EINVALIDDEV;
		}
		switch (module) {
		case SW_GEN:
			{
				struct rsbac_gen_fd_aci_t aci =
				    DEFAULT_GEN_FD_ACI;

				if (attr == A_internal) {
					if (!device_p->rsbac_dir_inode
					    || !tid_p->file.inode)
						value->internal = FALSE;
					else if (device_p->
						 rsbac_dir_inode ==
						 tid_p->file.inode)
						value->internal = TRUE;
					else if (inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* inheritance possible? */
						if (!rsbac_get_parent(target, *tid_p, &parent_target, &parent_tid)) {	/* yes: inherit this single level */
							if (device_p->
							    rsbac_dir_inode
							    ==
							    parent_tid.
							    file.inode)
								value->
								    internal
								    = TRUE;
							else
								value->
								    internal
								    =
								    FALSE;
						} else {
							value->internal =
							    FALSE;
						}
					} else {
						value->internal = FALSE;
					}

					/* free access to device_list_head */
					srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
					return 0;
				}
				rsbac_ta_list_get_data_ttl(ta_number,
							   device_p->
							   handles.gen,
							   NULL,
							   &tid_p->file.
							   inode, &aci);
				switch (attr) {
				case A_log_array_low:
					value->log_array_low =
					    aci.log_array_low;
					break;
				case A_log_array_high:
					value->log_array_high =
					    aci.log_array_high;
					break;
				case A_log_program_based:
					value->log_program_based =
					    aci.log_program_based;
					break;
				case A_symlink_add_remote_ip:
					value->symlink_add_remote_ip =
					    aci.symlink_add_remote_ip;
					break;
				case A_symlink_add_uid:
					value->symlink_add_uid =
					    aci.symlink_add_uid;
					break;
				case A_symlink_add_mac_level:
					value->symlink_add_mac_level =
					    aci.symlink_add_mac_level;
					break;
				case A_symlink_add_rc_role:
					value->symlink_add_rc_role =
					    aci.symlink_add_rc_role;
					break;
				case A_linux_dac_disable:
					value->linux_dac_disable =
					    aci.linux_dac_disable;
					if ((value->linux_dac_disable ==
					     LDD_inherit) && inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* free access to device_list_head - see above */
						srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
						/* inheritance possible? */
						if (!rsbac_get_parent
						    (target, *tid_p,
						     &parent_target,
						     &parent_tid)) {
							target =
							    parent_target;
							*tid_p =
							    parent_tid;
							continue;
						} else {
							value->
							    linux_dac_disable
							    =
							    def_gen_root_dir_aci.
							    linux_dac_disable;
							return 0;
						}
					}
					break;
				case A_fake_root_uid:
					value->fake_root_uid =
					    aci.fake_root_uid;
					break;
				case A_auid_exempt:
					value->auid_exempt =
					    aci.auid_exempt;
					break;
				case A_vset:
					value->vset =
					    aci.vset;
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;

#if defined(CONFIG_RSBAC_MAC)
		case SW_MAC:
			{
				struct rsbac_mac_fd_aci_t aci =
				    DEFAULT_MAC_FD_ACI;

				rsbac_ta_list_get_data_ttl(ta_number,
							   device_p->
							   handles.mac,
							   NULL,
							   &tid_p->file.
							   inode, &aci);
				switch (attr) {
				case A_security_level:
					value->security_level =
					    aci.sec_level;
					if ((value->security_level ==
					     SL_inherit) && inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* free access to device_list_head - see above */
						srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
						/* inheritance possible? */
						if (!rsbac_get_parent
						    (target, *tid_p,
						     &parent_target,
						     &parent_tid)) {
							target =
							    parent_target;
							*tid_p =
							    parent_tid;
							continue;
						} else {
							value->
							    security_level
							    =
							    def_mac_root_dir_aci.
							    sec_level;
							return 0;
						}
					}
					break;
				case A_mac_categories:
					value->mac_categories =
					    aci.mac_categories;
					if ((value->mac_categories ==
					     RSBAC_MAC_INHERIT_CAT_VECTOR)
					    && inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* free access to device_list_head - see above */
						srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
						/* inheritance possible? */
						if (!rsbac_get_parent
						    (target, *tid_p,
						     &parent_target,
						     &parent_tid)) {
							target =
							    parent_target;
							*tid_p =
							    parent_tid;
							continue;
						} else {
							value->
							    mac_categories
							    =
							    def_mac_root_dir_aci.
							    mac_categories;
							return 0;
						}
					}
					break;
				case A_mac_auto:
					value->mac_auto = aci.mac_auto;
					if ((value->mac_auto == MA_inherit)
					    && inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* free access to device_list_head - see above */
						srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
						/* inheritance possible? */
						if (!rsbac_get_parent
						    (target, *tid_p,
						     &parent_target,
						     &parent_tid)) {
							target =
							    parent_target;
							*tid_p =
							    parent_tid;
							continue;
						} else {
							value->mac_auto
							    =
							    def_mac_root_dir_aci.
							    mac_auto;
							return 0;
						}
					}
					break;
				case A_mac_prop_trusted:
					value->mac_prop_trusted =
					    aci.mac_prop_trusted;
					break;
				case A_mac_file_flags:
					value->mac_file_flags =
					    aci.mac_file_flags;
					break;

				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_PM)
		case SW_PM:
			{
				struct rsbac_pm_fd_aci_t aci =
				    DEFAULT_PM_FD_ACI;

				rsbac_ta_list_get_data_ttl(ta_number,
							   device_p->
							   handles.pm,
							   NULL,
							   &tid_p->file.
							   inode, &aci);
				switch (attr) {
				case A_pm_object_class:
					value->pm_object_class =
					    aci.pm_object_class;
					break;
				case A_pm_tp:
					value->pm_tp = aci.pm_tp;
					break;
				case A_pm_object_type:
					value->pm_object_type =
					    aci.pm_object_type;
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* PM */

#if defined(CONFIG_RSBAC_DAZ)
		case SW_DAZ:
			{
#if defined(CONFIG_RSBAC_DAZ_CACHE)
				if (attr == A_daz_scanned) {
					err = rsbac_ta_list_get_data_ttl
					    (ta_number,
					     device_p->handles.dazs,
					     NULL, &tid_p->file.inode,
					     &value->daz_scanned);
				} else
#endif
				{
					struct rsbac_daz_fd_aci_t aci =
					    DEFAULT_DAZ_FD_ACI;

					rsbac_ta_list_get_data_ttl
					    (ta_number,
					     device_p->handles.daz,
					     NULL, &tid_p->file.inode,
					     &aci);
					switch (attr) {
					case A_daz_scanner:
						value->daz_scanner =
						    aci.daz_scanner;
						break;
					case A_daz_do_scan:
						value->daz_do_scan = aci.daz_do_scan;
						if(   (value->daz_do_scan == DAZ_inherit)
							&& inherit) {
							enum rsbac_target_t       parent_target;
							union rsbac_target_id_t   parent_tid;

							srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
							if(!rsbac_get_parent(target, *tid_p, &parent_target, &parent_tid)) {
								target = parent_target;
								*tid_p = parent_tid;
								continue;
							} else {
								value->daz_do_scan
									= def_daz_root_dir_aci.daz_do_scan;
								return 0;
							}
						}
						break;
					default:
						err = -RSBAC_EINVALIDATTR;
					}
				}
			}
			break;
#endif				/* DAZ */

#if defined(CONFIG_RSBAC_FF)
		case SW_FF:
			{
				switch (attr) {
				case A_ff_flags:
					ff_tmp_flags = RSBAC_FF_DEF;
					rsbac_ta_list_get_data_ttl
					    (ta_number,
					     device_p->handles.ff,
					     NULL,
					     &tid_p->file.inode,
					     &ff_tmp_flags);
					ff_flags |= ff_tmp_flags & ff_mask;
					value->ff_flags = ff_flags;
					if ((ff_tmp_flags &
					     FF_add_inherited)
					    && inherit) {
						/* inheritance possible? */
						if (!rsbac_get_parent
						    (target, *tid_p,
						     &target, tid_p)) {
							/* free access to device_list_head - see above */
							srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
							ff_mask &=
							    ~
							    (FF_no_delete_or_rename
							     |
							     FF_add_inherited);
							ff_flags &=
							    ~
							    (FF_add_inherited);
							continue;
						} else
							value->ff_flags &=
							    ~
							    (FF_add_inherited);
					}
					break;

				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* FF */

#if defined(CONFIG_RSBAC_RC)
		case SW_RC:
			{
				struct rsbac_rc_fd_aci_t aci =
				    DEFAULT_RC_FD_ACI;

				rsbac_ta_list_get_data_ttl(ta_number,
							   device_p->
							   handles.rc,
							   NULL,
							   &tid_p->file.
							   inode, &aci);
				switch (attr) {
				case A_rc_type_fd:
					value->rc_type_fd = aci.rc_type_fd;
					if (value->rc_type_fd ==
					    RC_type_inherit_parent
					    && inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* free access to device_list_head - see above */
						srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
						/* inheritance possible? */
						if (!rsbac_get_parent
						    (target, *tid_p,
						     &parent_target,
						     &parent_tid)) {
							target =
							    parent_target;
							*tid_p =
							    parent_tid;
							continue;
						} else {
							value->rc_type_fd
							    =
							    def_rc_root_dir_aci.
							    rc_type_fd;
							return 0;
						}
					}
					break;
				case A_rc_force_role:
					value->rc_force_role =
					    aci.rc_force_role;
					if (value->rc_force_role ==
					    RC_role_inherit_parent
					    && inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* free access to device_list_head - see above */
						srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
						/* inheritance possible? */
						if (!rsbac_get_parent
						    (target, *tid_p,
						     &parent_target,
						     &parent_tid)) {
							target =
							    parent_target;
							*tid_p =
							    parent_tid;
							continue;
						} else {
							value->
							    rc_force_role =
							    def_rc_root_dir_aci.
							    rc_force_role;
							return 0;
						}
					}
					break;
				case A_rc_initial_role:
					value->rc_initial_role =
					    aci.rc_initial_role;
					if (value->rc_initial_role ==
					    RC_role_inherit_parent
					    && inherit) {
						enum rsbac_target_t
						    parent_target;
						union rsbac_target_id_t
						    parent_tid;

						/* free access to device_list_head - see above */
						srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
						/* inheritance possible? */
						if (!rsbac_get_parent
						    (target, *tid_p,
						     &parent_target,
						     &parent_tid)) {
							target =
							    parent_target;
							*tid_p =
							    parent_tid;
							continue;
						} else {
							value->
							    rc_initial_role
							    =
							    def_rc_root_dir_aci.
							    rc_initial_role;
							return 0;
						}
					}
					break;

				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* RC */

#if defined(CONFIG_RSBAC_AUTH)
		case SW_AUTH:
			{
				struct rsbac_auth_fd_aci_t aci =
				    DEFAULT_AUTH_FD_ACI;

				rsbac_ta_list_get_data_ttl(ta_number,
							   device_p->
							   handles.auth,
							   NULL,
							   &tid_p->file.
							   inode, &aci);
				switch (attr) {
				case A_auth_may_setuid:
					value->auth_may_setuid =
					    aci.auth_may_setuid;
					break;
				case A_auth_may_set_cap:
					value->auth_may_set_cap =
					    aci.auth_may_set_cap;
					break;
				case A_auth_learn:
					value->auth_learn = aci.auth_learn;
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* AUTH */

#if defined(CONFIG_RSBAC_CAP)
		case SW_CAP:
			{
				struct rsbac_cap_fd_aci_t aci =
				    DEFAULT_CAP_FD_ACI;

				rsbac_ta_list_get_data_ttl(ta_number,
							   device_p->
							   handles.cap,
							   NULL,
							   &tid_p->file.
							   inode, &aci);
				switch (attr) {
				case A_min_caps:
					value->min_caps.cap[0] = aci.min_caps.cap[0];
                                        value->min_caps.cap[1] = aci.min_caps.cap[1];
					break;
				case A_max_caps:
					value->max_caps.cap[0] = aci.max_caps.cap[0];
					value->max_caps.cap[1] = aci.max_caps.cap[1];
					break;
				case A_cap_ld_env:
					value->cap_ld_env = aci.cap_ld_env;
					if ((value->cap_ld_env == LD_inherit) && inherit) {
						enum rsbac_target_t parent_target;
						union rsbac_target_id_t parent_tid;
						srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
						if (!rsbac_get_parent(target,
									*tid_p,
									&parent_target,
									&parent_tid)) {
							target = parent_target;
							*tid_p = parent_tid;
							continue;
						} else {
							value->cap_ld_env = LD_deny;
							return 0;
						}
					}
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* CAP */

#if defined(CONFIG_RSBAC_RES)
		case SW_RES:
			{
				struct rsbac_res_fd_aci_t aci =
				    DEFAULT_RES_FD_ACI;

				rsbac_ta_list_get_data_ttl(ta_number,
							   device_p->
							   handles.res,
							   NULL,
							   &tid_p->file.
							   inode, &aci);
				switch (attr) {
				case A_res_min:
					memcpy(&value->res_array,
					       &aci.res_min,
					       sizeof(aci.res_min));
					break;
				case A_res_max:
					memcpy(&value->res_array,
					       &aci.res_max,
					       sizeof(aci.res_max));
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* RES */

#if defined(CONFIG_RSBAC_PAX)
		case SW_PAX:
			{
				switch (attr) {
				case A_pax_flags:
					value->pax_flags =
					    RSBAC_PAX_DEF_FLAGS;
					rsbac_ta_list_get_data_ttl
					    (ta_number,
					     device_p->handles.pax,
					     NULL, &tid_p->file.inode,
					     &value->pax_flags);
					break;

				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
			break;
#endif				/* PAX */

		default:
			err = -RSBAC_EINVALIDMODULE;
		}
		/* free access to device_list_head */
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
		/* and return */
		return err;
	}			/* end of for(;;) loop for inheritance */
}

static int get_attr_dev(rsbac_list_ta_number_t ta_number,
			enum rsbac_switch_target_t module,
			enum rsbac_target_t target,
			struct rsbac_dev_desc_t dev,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *value,
			rsbac_boolean_t inherit)
{
	int err = 0;
/*	rsbac_pr_debug(ds, "Getting dev attribute\n"); */
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_dev_aci_t aci =
			    DEFAULT_GEN_DEV_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   dev_handles.gen,
						   NULL, &dev, &aci);
			switch (attr) {
			case A_log_array_low:
				value->log_array_low = aci.log_array_low;
				break;
			case A_log_array_high:
				value->log_array_high = aci.log_array_high;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_dev_aci_t aci =
			    DEFAULT_MAC_DEV_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   dev_handles.mac,
						   NULL, &dev, &aci);
			switch (attr) {
			case A_security_level:
				value->security_level = aci.sec_level;
				break;
			case A_mac_categories:
				value->mac_categories = aci.mac_categories;
				break;
			case A_mac_check:
				value->mac_check = aci.mac_check;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_dev_aci_t aci = DEFAULT_PM_DEV_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   dev_handles.pm,
						   NULL, &dev, &aci);
			switch (attr) {
			case A_pm_object_class:
				value->pm_object_class =
				    aci.pm_object_class;
				break;
			case A_pm_object_type:
				value->pm_object_type = aci.pm_object_type;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* PM */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = RSBAC_RC_GENERAL_TYPE;

			switch (dev.type) {
			case D_char:
			case D_block:
				if (rsbac_ta_list_get_data_ttl(ta_number,
							       dev_handles.
							       rc, NULL,
							       &dev, &type)
				    || ((type == RC_type_inherit_parent)
					&& inherit)
				    ) {
				    	dev.minor = 0;
					rsbac_ta_list_get_data_ttl
					    (ta_number,
					     dev_major_handles.rc, NULL,
					     &dev, &type);
				}
				break;
			case D_char_major:
			case D_block_major:
				dev.type -= (D_block_major - D_block);
			    	dev.minor = 0;
				rsbac_ta_list_get_data_ttl(ta_number,
							   dev_major_handles.
							   rc, NULL, &dev,
							   &type);
				break;
			default:
				return -RSBAC_EINVALIDTARGET;
			}
			switch (attr) {
			case A_rc_type:
				value->rc_type = type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	/* and return */
	return err;
}

static int get_attr_ipc(rsbac_list_ta_number_t ta_number,
			enum rsbac_switch_target_t module,
			enum rsbac_target_t target,
			union rsbac_target_id_t *tid_p,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *value,
			rsbac_boolean_t inherit)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Getting ipc attribute\n"); */
	/* lookup only, if not sock or (sock-id != NULL), OK with NULL fifo */
	switch (module) {
#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_ipc_aci_t aci =
			    DEFAULT_MAC_IPC_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   ipc_handles.mac,
						   NULL,
						   &tid_p->ipc, &aci);
			switch (attr) {
			case A_security_level:
				value->security_level = aci.sec_level;
				break;
			case A_mac_categories:
				value->mac_categories = aci.mac_categories;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_ipc_aci_t aci = DEFAULT_PM_IPC_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   ipc_handles.pm,
						   NULL,
						   &tid_p->ipc, &aci);
			switch (attr) {
			case A_pm_object_class:
				value->pm_object_class =
				    aci.pm_object_class;
				break;
			case A_pm_ipc_purpose:
				value->pm_ipc_purpose = aci.pm_ipc_purpose;
				break;
			case A_pm_object_type:
				value->pm_object_type = aci.pm_object_type;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* PM */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = RSBAC_RC_GENERAL_TYPE;

			rsbac_ta_list_get_data_ttl(ta_number,
						   ipc_handles.rc,
						   NULL,
						   &tid_p->ipc, &type);
			switch (attr) {
			case A_rc_type:
				value->rc_type = type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

#if defined(CONFIG_RSBAC_JAIL)
	case SW_JAIL:
		{
			rsbac_jail_id_t id = RSBAC_JAIL_DEF_ID;

			rsbac_ta_list_get_data_ttl(ta_number,
						   ipc_handles.jail,
						   NULL, &tid_p->ipc, &id);
			switch (attr) {
			case A_jail_id:
				value->jail_id = id;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* JAIL */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	/* and return */
	return err;
}

static int get_attr_user(rsbac_list_ta_number_t ta_number,
			enum rsbac_switch_target_t module,
			enum rsbac_target_t target,
			union rsbac_target_id_t *tid_p,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *value,
			rsbac_boolean_t inherit)
{
	int err = 0;
#if defined(CONFIG_RSBAC_UM_VIRTUAL) || defined(CONFIG_RSBAC_RES)
	rsbac_uid_t all_user;
#endif

	/* rsbac_pr_debug(ds, "Getting user attribute\n"); */
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_user_aci_t aci =
			    DEFAULT_GEN_U_ACI;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.gen,
						   NULL,
						   &tid_p->user, &aci);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.gen,
								NULL,
								&all_user,
								&aci);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.gen,
						   NULL,
						   &tid_p->user, &aci);
#endif
			switch (attr) {
			case A_pseudo:
				value->pseudo = aci.pseudo;
				break;
			case A_log_user_based:
				value->log_user_based = aci.log_user_based;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_user_aci_t aci =
			    DEFAULT_MAC_U_ACI;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.mac,
						   NULL,
						   &tid_p->user, &aci);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.mac,
								NULL,
								&all_user,
								&aci);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.mac,
						   NULL,
						   &tid_p->user, &aci);
#endif
			switch (attr) {
			case A_security_level:
				value->security_level = aci.security_level;
				break;
			case A_initial_security_level:
				value->security_level =
				    aci.initial_security_level;
				break;
			case A_min_security_level:
				value->security_level =
				    aci.min_security_level;
				break;
			case A_mac_categories:
				value->mac_categories = aci.mac_categories;
				break;
			case A_mac_initial_categories:
				value->mac_categories =
				    aci.mac_initial_categories;
				break;
			case A_mac_min_categories:
				value->mac_categories =
				    aci.mac_min_categories;
				break;
			case A_system_role:
			case A_mac_role:
				value->system_role = aci.system_role;
				break;
			case A_mac_user_flags:
				value->mac_user_flags = aci.mac_user_flags;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_user_aci_t aci = DEFAULT_PM_U_ACI;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.pm,
						   NULL,
						   &tid_p->user, &aci);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.pm,
								NULL,
								&all_user,
								&aci);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.pm,
						   NULL,
						   &tid_p->user, &aci);
#endif
			switch (attr) {
			case A_pm_task_set:
				value->pm_task_set = aci.pm_task_set;
				break;
			case A_pm_role:
				value->pm_role = aci.pm_role;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* PM */

#if defined(CONFIG_RSBAC_DAZ)
	case SW_DAZ:
		{
			rsbac_system_role_int_t role = SR_user;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.daz,
						   NULL,
						   &tid_p->user, &role);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.daz,
								NULL,
								&all_user,
								&role);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.daz,
						   NULL,
						   &tid_p->user, &role);
#endif
			switch (attr) {
			case A_system_role:
			case A_daz_role:
				value->system_role = role;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* DAZ */

#if defined(CONFIG_RSBAC_FF)
	case SW_FF:
		{
			rsbac_system_role_int_t role = SR_user;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.ff,
						   NULL,
						   &tid_p->user, &role);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.ff,
								NULL,
								&all_user,
								&role);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.ff,
						   NULL,
						   &tid_p->user, &role);
#endif
			switch (attr) {
			case A_system_role:
			case A_ff_role:
				value->system_role = role;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* FF */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_user_aci_t aci = DEFAULT_RC_U_ACI;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.rc,
						   NULL,
						   &tid_p->user, &aci);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.rc,
								NULL,
								&all_user,
								&aci);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.rc,
						   NULL,
						   &tid_p->user, &aci);
#endif
			switch (attr) {
			case A_rc_def_role:
				value->rc_def_role = aci.rc_role;
				break;
			case A_rc_type:
				value->rc_type = aci.rc_type;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

#if defined(CONFIG_RSBAC_AUTH)
	case SW_AUTH:
		{
			rsbac_system_role_int_t role = SR_user;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.auth,
						   NULL,
						   &tid_p->user, &role);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.auth,
								NULL,
								&all_user,
								&role);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.auth,
						   NULL,
						   &tid_p->user, &role);
#endif
			switch (attr) {
			case A_system_role:
			case A_auth_role:
				value->system_role = role;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* AUTH */

#if defined(CONFIG_RSBAC_CAP)
	case SW_CAP:
		{
			struct rsbac_cap_user_aci_t aci =
			    DEFAULT_CAP_U_ACI;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.cap,
						   NULL,
						   &tid_p->user, &aci);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.cap,
								NULL,
								&all_user,
								&aci);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.cap,
						   NULL,
						   &tid_p->user, &aci);
#endif
			switch (attr) {
			case A_system_role:
			case A_cap_role:
				value->system_role = aci.cap_role;
				break;
			case A_min_caps:
				value->min_caps.cap[0] = aci.min_caps.cap[0];
				value->min_caps.cap[1] = aci.min_caps.cap[1];
				break;
			case A_max_caps:
				value->max_caps.cap[0] = aci.max_caps.cap[0];
				value->max_caps.cap[1] = aci.max_caps.cap[1];
				break;
			case A_cap_ld_env:
				value->cap_ld_env = aci.cap_ld_env;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* CAP */

#if defined(CONFIG_RSBAC_JAIL)
	case SW_JAIL:
		{
			rsbac_system_role_int_t role = SR_user;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.jail,
						   NULL,
						   &tid_p->user, &role);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.jail,
								NULL,
								&all_user,
								&role);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.jail,
						   NULL,
						   &tid_p->user, &role);
#endif
			switch (attr) {
			case A_system_role:
			case A_jail_role:
				value->system_role = role;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* JAIL */

#if defined(CONFIG_RSBAC_RES)
	case SW_RES:
		{
			struct rsbac_res_user_aci_t aci =
			    DEFAULT_RES_U_ACI;

			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.res,
						   NULL,
						   &tid_p->user, &aci);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					err = rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.res,
								NULL,
								&all_user,
								&aci);
					if (err == -RSBAC_ENOTFOUND) {
						err = 0;
						if (RSBAC_UID_SET(tid_p->user)) {
							all_user = RSBAC_ALL_USERS;
							rsbac_ta_list_get_data_ttl(ta_number,
										user_handles.res,
										NULL,
										&all_user,
										&aci);
						}
					}
				}
			}
			switch (attr) {
			case A_system_role:
			case A_res_role:
				value->system_role = aci.res_role;
				break;
			case A_res_min:
				memcpy(&value->res_array, &aci.res_min,
				       sizeof(aci.res_min));
				break;
			case A_res_max:
				memcpy(&value->res_array, &aci.res_max,
				       sizeof(aci.res_max));
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RES */

#if defined(CONFIG_RSBAC_PAX)
	case SW_PAX:
		{
			rsbac_system_role_int_t role = SR_user;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.pax,
						   NULL,
						   &tid_p->user, &role);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					all_user = RSBAC_GEN_UID(RSBAC_UID_SET(tid_p->user), RSBAC_ALL_USERS);
					rsbac_ta_list_get_data_ttl(ta_number,
								user_handles.pax,
								NULL,
								&all_user,
								&role);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.pax,
						   NULL,
						   &tid_p->user, &role);
#endif
			switch (attr) {
			case A_system_role:
			case A_pax_role:
				value->system_role = role;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* PAX */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	/* and return */
	return err;
}

static int get_attr_process(rsbac_list_ta_number_t ta_number,
			    enum rsbac_switch_target_t module,
			    enum rsbac_target_t target,
			    union rsbac_target_id_t *tid_p,
			    enum rsbac_attribute_t attr,
			    union rsbac_attribute_value_t *value,
			    rsbac_boolean_t inherit)
{
	int err = 0;
/*	rsbac_pr_debug(ds, "Getting process attribute"); */
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_process_aci_t aci =
			    DEFAULT_GEN_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.gen,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_vset:
				value->vset = aci.vset;
				break;
			case A_log_program_based:
				value->log_program_based =
				    aci.log_program_based;
				break;
			case A_fake_root_uid:
				value->fake_root_uid = aci.fake_root_uid;
				break;
			case A_audit_uid:
				value->audit_uid = aci.audit_uid;
				break;
			case A_auid_exempt:
				value->auid_exempt = aci.auid_exempt;
				break;
			case A_remote_ip:
				value->remote_ip = aci.remote_ip;
				break;
			case A_kernel_thread:
				value->kernel_thread = aci.kernel_thread;
				break;
#if defined(CONFIG_RSBAC_AUTH_LEARN) || defined(CONFIG_RSBAC_CAP_LEARN)
			case A_program_file:
				value->program_file = aci.program_file;
				break;
#endif
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_process_aci_t aci =
			    DEFAULT_MAC_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.mac,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_security_level:
				value->security_level =
				    aci.owner_sec_level;
				break;
			case A_initial_security_level:
				value->security_level =
				    aci.owner_initial_sec_level;
				break;
			case A_min_security_level:
				value->security_level =
				    aci.owner_min_sec_level;
				break;
			case A_mac_categories:
				value->mac_categories =
				    aci.mac_owner_categories;
				break;
			case A_mac_initial_categories:
				value->mac_categories =
				    aci.mac_owner_initial_categories;
				break;
			case A_mac_min_categories:
				value->mac_categories =
				    aci.mac_owner_min_categories;
				break;
			case A_current_sec_level:
				value->current_sec_level =
				    aci.current_sec_level;
				break;
			case A_mac_curr_categories:
				value->mac_categories =
				    aci.mac_curr_categories;
				break;
			case A_min_write_open:
				value->min_write_open = aci.min_write_open;
				break;
			case A_min_write_categories:
				value->mac_categories =
				    aci.min_write_categories;
				break;
			case A_max_read_open:
				value->max_read_open = aci.max_read_open;
				break;
			case A_max_read_categories:
				value->mac_categories =
				    aci.max_read_categories;
				break;
			case A_mac_process_flags:
				value->mac_process_flags =
				    aci.mac_process_flags;
				break;
			case A_mac_auto:
				if (aci.mac_process_flags & MAC_auto)
					value->mac_auto = TRUE;
				else
					value->mac_auto = FALSE;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_process_aci_t aci =
			    DEFAULT_PM_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.pm,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
			case A_pm_tp:
				value->pm_tp = aci.pm_tp;
				break;
			case A_pm_current_task:
				value->pm_current_task =
				    aci.pm_current_task;
				break;
			case A_pm_process_type:
				value->pm_process_type =
				    aci.pm_process_type;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* PM */

#if defined(CONFIG_RSBAC_DAZ)
	case SW_DAZ:
		{
			struct rsbac_daz_process_aci_t aci =
			    DEFAULT_DAZ_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.daz,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
			case A_daz_scanner:
				value->daz_scanner = aci.daz_scanner;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* DAZ */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_process_aci_t aci =
			    DEFAULT_RC_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.rc,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_rc_role:
				value->rc_role = aci.rc_role;
				break;
			case A_rc_type:
				value->rc_type = aci.rc_type;
				break;
			case A_rc_select_type:
			        value->rc_select_type = aci.rc_select_type;
			        break;
			case A_rc_force_role:
				value->rc_force_role = aci.rc_force_role;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

#if defined(CONFIG_RSBAC_AUTH)
	case SW_AUTH:
		{
			struct rsbac_auth_process_aci_t aci =
			    DEFAULT_AUTH_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.auth,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
			case A_auth_may_setuid:
				value->auth_may_setuid =
				    aci.auth_may_setuid;
				break;
			case A_auth_may_set_cap:
				value->auth_may_set_cap =
				    aci.auth_may_set_cap;
				break;
#if defined(CONFIG_RSBAC_AUTH_LEARN)
			case A_auth_start_uid:
				value->auth_start_uid = aci.auth_start_uid;
				break;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
			case A_auth_start_euid:
				value->auth_start_euid =
				    aci.auth_start_euid;
				break;
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
			case A_auth_start_gid:
				value->auth_start_gid = aci.auth_start_gid;
				break;
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
			case A_auth_start_egid:
				value->auth_start_egid =
				    aci.auth_start_egid;
				break;
#endif
#endif
			case A_auth_learn:
				value->auth_learn = aci.auth_learn;
				break;
#else
			case A_auth_learn:
				value->auth_learn = FALSE;
				break;
#endif
			case A_auth_last_auth:
				value->auth_last_auth = aci.auth_last_auth;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* AUTH */

#if defined(CONFIG_RSBAC_CAP)
	case SW_CAP:
		{
			struct rsbac_cap_process_aci_t aci =
			    DEFAULT_CAP_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.cap,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
			case A_cap_process_hiding:
				value->cap_process_hiding =
				    aci.cap_process_hiding;
				break;
#if defined(CONFIG_RSBAC_CAP_LOG_MISSING) || defined(CONFIG_RSBAC_CAP_LEARN)
			case A_max_caps_user:
				value->max_caps_user.cap[0] = aci.max_caps_user.cap[0];
				value->max_caps_user.cap[1] = aci.max_caps_user.cap[1];
				break;
			case A_max_caps_program:
				value->max_caps_program.cap[0] = aci.max_caps_program.cap[0];
				value->max_caps_program.cap[1] = aci.max_caps_program.cap[1];
				break;
#endif
			case A_cap_ld_env:
				value->cap_ld_env = aci.cap_ld_env;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* CAP */

#if defined(CONFIG_RSBAC_JAIL)
	case SW_JAIL:
		{
			struct rsbac_jail_process_aci_t aci =
			    DEFAULT_JAIL_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.jail,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_jail_id:
				value->jail_id = aci.id;
				break;
			case A_jail_parent:
				value->jail_parent = aci.parent;
				break;
			case A_jail_ip:
				value->jail_ip = aci.ip;
				break;
			case A_jail_flags:
				value->jail_flags = aci.flags;
				break;
			case A_jail_max_caps:
				value->jail_max_caps.cap[0] = aci.max_caps.cap[0];
				value->jail_max_caps.cap[1] = aci.max_caps.cap[1];
				break;
			case A_jail_scd_get:
				value->jail_scd_get = aci.scd_get;
				break;
			case A_jail_scd_modify:
				value->jail_scd_modify = aci.scd_modify;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* JAIL */

#if defined(CONFIG_RSBAC_PAX)
	case SW_PAX:
		{
			struct task_struct *task_p;

			switch (attr) {
			case A_pax_flags:
				read_lock(&tasklist_lock);
				task_p = pid_task(tid_p->process, PIDTYPE_PID);
				if (task_p) {
#if defined(CONFIG_PAX_NOEXEC) || defined(CONFIG_PAX_ASLR)
					if (task_p->mm)
						value->pax_flags =
						    task_p->mm->
						    pax_flags &
						    RSBAC_PAX_ALL_FLAGS;
					else
#endif
						value->pax_flags = 0;
				} else
					err = -RSBAC_EINVALIDTARGET;
				read_unlock(&tasklist_lock);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* PAX */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	return err;
}

#ifdef CONFIG_RSBAC_UM
static int get_attr_group(rsbac_list_ta_number_t ta_number,
			  enum rsbac_switch_target_t module,
			  enum rsbac_target_t target,
			  union rsbac_target_id_t *tid_p,
			  enum rsbac_attribute_t attr,
			  union rsbac_attribute_value_t *value,
			  rsbac_boolean_t inherit)
{
	int err = 0;

	/* rsbac_pr_debug(ds, "Getting group attribute\n"); */
	switch (module) {
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = RSBAC_RC_GENERAL_TYPE;

#if defined(CONFIG_RSBAC_UM_VIRTUAL)
			err = rsbac_ta_list_get_data_ttl(ta_number,
						   group_handles.rc,
						   NULL,
						   &tid_p->group, &type);
			if (err == -RSBAC_ENOTFOUND) {
				err = 0;
				if(inherit) {
					rsbac_gid_t all_group;

					all_group = RSBAC_GEN_GID(RSBAC_GID_SET(tid_p->group), RSBAC_ALL_GROUPS);
					rsbac_ta_list_get_data_ttl(ta_number,
								group_handles.rc,
								NULL,
								&all_group,
								&type);
				}
			}
#else
			rsbac_ta_list_get_data_ttl(ta_number,
						   group_handles.rc,
						   NULL,
						   &tid_p->group, &type);
#endif
			switch (attr) {
			case A_rc_type:
				value->rc_type = type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	/* and return */
	return err;
}
#endif

#ifdef CONFIG_RSBAC_NET_DEV
static int get_attr_netdev(rsbac_list_ta_number_t ta_number,
			   enum rsbac_switch_target_t module,
			   enum rsbac_target_t target,
			   union rsbac_target_id_t *tid_p,
			   enum rsbac_attribute_t attr,
			   union rsbac_attribute_value_t *value,
			   rsbac_boolean_t inherit)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Getting netdev attribute\n"); */
	switch (module) {
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	case SW_GEN:
		{
			struct rsbac_gen_netdev_aci_t aci =
			    DEFAULT_GEN_NETDEV_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   netdev_handles.gen,
						   NULL,
						   &tid_p->netdev, &aci);
			switch (attr) {
			case A_log_array_low:
				value->log_array_low = aci.log_array_low;
				break;
			case A_log_array_high:
				value->log_array_high = aci.log_array_high;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif
#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = RSBAC_RC_GENERAL_TYPE;

			rsbac_ta_list_get_data_ttl(ta_number,
						   netdev_handles.rc,
						   NULL,
						   &tid_p->netdev, &type);
			switch (attr) {
			case A_rc_type:
				value->rc_type = type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	/* and return */
	return err;
}
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
static int get_attr_nettemp(rsbac_list_ta_number_t ta_number,
			    enum rsbac_switch_target_t module,
			    enum rsbac_target_t target,
			    union rsbac_target_id_t *tid_p,
			    enum rsbac_attribute_t attr,
			    union rsbac_attribute_value_t *value,
			    rsbac_boolean_t inherit)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Getting nettemp attribute"); */
	if (tid_p->nettemp
	    && !rsbac_ta_list_exist(ta_number, net_temp_handle, &tid_p->nettemp)
	    )
		return -RSBAC_EINVALIDTARGET;
	switch (module) {
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
	case SW_GEN:
		{
			struct rsbac_gen_fd_aci_t aci =
			    DEFAULT_GEN_NETOBJ_ACI;

			if (tid_p->nettemp)
				rsbac_ta_list_get_data_ttl(ta_number,
							   nettemp_handles.
							   gen, NULL,
							   &tid_p->nettemp,
							   &aci);
			switch (attr) {
			case A_log_array_low:
				value->log_array_low = aci.log_array_low;
				break;
			case A_log_array_high:
				value->log_array_high = aci.log_array_high;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif
#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_netobj_aci_t aci =
			    DEFAULT_MAC_NETOBJ_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   nettemp_handles.mac,
						   NULL,
						   &tid_p->nettemp, &aci);
			switch (attr) {
			case A_security_level:
				value->security_level = aci.sec_level;
				break;
			case A_mac_categories:
				value->mac_categories = aci.mac_categories;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_netobj_aci_t aci =
			    DEFAULT_PM_NETOBJ_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   nettemp_handles.pm,
						   NULL,
						   &tid_p->nettemp, &aci);
			switch (attr) {
			case A_pm_object_class:
				value->pm_object_class =
				    aci.pm_object_class;
				break;
			case A_pm_ipc_purpose:
				value->pm_ipc_purpose = aci.pm_ipc_purpose;
				break;
			case A_pm_object_type:
				value->pm_object_type = aci.pm_object_type;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* PM */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_nettemp_aci_t aci =
			    DEFAULT_RC_NETTEMP_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   nettemp_handles.rc,
						   NULL,
						   &tid_p->nettemp, &aci);
			switch (attr) {
			case A_rc_type:
				value->rc_type = aci.netobj_type;
				break;

			case A_rc_type_nt:
				value->rc_type = aci.nettemp_type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	return err;
}

static int get_attr_netobj(rsbac_list_ta_number_t ta_number,
			   enum rsbac_switch_target_t module,
			   enum rsbac_target_t target,
			   union rsbac_target_id_t *tid_p,
			   enum rsbac_attribute_t attr,
			   union rsbac_attribute_value_t *value,
			   rsbac_boolean_t inherit)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Getting netobj attribute"); */
	switch (module) {
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
	case SW_GEN:
		{
			struct rsbac_gen_netobj_aci_t aci =
			    DEFAULT_GEN_NETOBJ_ACI;
			rsbac_net_temp_id_t temp;

			switch (attr) {
			case A_local_log_array_low:
			case A_local_log_array_high:
				if(!ta_number && tid_p->netobj.local_temp)
					temp = tid_p->netobj.local_temp;
				else
					rsbac_ta_net_lookup_templates(ta_number,
								      &tid_p->
								      netobj,
								      &temp, NULL);
				break;
			case A_remote_log_array_low:
			case A_remote_log_array_high:
				if(!ta_number && tid_p->netobj.remote_temp)
					temp = tid_p->netobj.remote_temp;
				else
					rsbac_ta_net_lookup_templates(ta_number,
								      &tid_p->
								      netobj, NULL,
								      &temp);
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (temp)
				rsbac_ta_list_get_data_ttl(ta_number,
							   nettemp_handles.
							   gen, NULL,
							   &temp, &aci);
			switch (attr) {
			case A_local_log_array_low:
			case A_remote_log_array_low:
				value->log_array_low = aci.log_array_low;
				break;
			case A_local_log_array_high:
			case A_remote_log_array_high:
				value->log_array_high = aci.log_array_high;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif
#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_netobj_aci_t aci =
			    DEFAULT_MAC_NETOBJ_ACI;

			switch (attr) {
			case A_local_sec_level:
			case A_local_mac_categories:
				if (rsbac_ta_list_get_data_ttl(ta_number, lnetobj_handles.mac, NULL, &tid_p->netobj.sock_p, &aci)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;

					if(!ta_number && tid_p->netobj.local_temp)
						temp = tid_p->netobj.local_temp;
					else
						rsbac_ta_net_lookup_templates
						    (ta_number, &tid_p->netobj,
						     &temp, NULL);
					if (temp)
						rsbac_ta_list_get_data_ttl
						    (ta_number,
						     nettemp_handles.mac,
						     NULL, &temp, &aci);
				}
				break;

			case A_remote_sec_level:
			case A_remote_mac_categories:
				if (rsbac_ta_list_get_data_ttl(ta_number, rnetobj_handles.mac, NULL, &tid_p->netobj.sock_p, &aci)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;

					if(!ta_number && tid_p->netobj.remote_temp)
						temp = tid_p->netobj.remote_temp;
					else
						rsbac_ta_net_lookup_templates
						    (ta_number, &tid_p->netobj,
						     NULL, &temp);
					if (temp)
						rsbac_ta_list_get_data_ttl
						    (ta_number,
						     nettemp_handles.mac,
						     NULL, &temp, &aci);
				}
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (err)
				break;
			switch (attr) {
			case A_local_sec_level:
			case A_remote_sec_level:
				value->security_level = aci.sec_level;
				break;
			case A_local_mac_categories:
			case A_remote_mac_categories:
				value->mac_categories = aci.mac_categories;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_netobj_aci_t aci =
			    DEFAULT_PM_NETOBJ_ACI;

			switch (attr) {
			case A_local_pm_object_class:
			case A_local_pm_ipc_purpose:
			case A_local_pm_object_type:
				if (rsbac_ta_list_get_data_ttl(ta_number, lnetobj_handles.pm, NULL, &tid_p->netobj.sock_p, &aci)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;

					if(!ta_number && tid_p->netobj.local_temp)
						temp = tid_p->netobj.local_temp;
					else
						rsbac_ta_net_lookup_templates
					    (ta_number, &tid_p->netobj,
					     &temp, NULL);
					if (temp)
						rsbac_ta_list_get_data_ttl
						    (ta_number,
						     nettemp_handles.pm,
						     NULL, &temp, &aci);
				}
				break;

			case A_remote_pm_object_class:
			case A_remote_pm_ipc_purpose:
			case A_remote_pm_object_type:
				if (rsbac_ta_list_get_data_ttl(ta_number, rnetobj_handles.pm, NULL, &tid_p->netobj.sock_p, &aci)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;

					if(!ta_number && tid_p->netobj.remote_temp)
						temp = tid_p->netobj.remote_temp;
					else
						rsbac_ta_net_lookup_templates
						    (ta_number, &tid_p->netobj,
						     NULL, &temp);
					if (temp)
						rsbac_ta_list_get_data_ttl
						    (ta_number,
						     nettemp_handles.pm,
						     NULL, &temp, &aci);
				}
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (err)
				break;
			switch (attr) {
			case A_local_pm_object_class:
			case A_remote_pm_object_class:
				value->pm_object_class =
				    aci.pm_object_class;
				break;
			case A_local_pm_ipc_purpose:
			case A_remote_pm_ipc_purpose:
				value->pm_ipc_purpose = aci.pm_ipc_purpose;
				break;
			case A_local_pm_object_type:
			case A_remote_pm_object_type:
				value->pm_object_type = aci.pm_object_type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* PM */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = RSBAC_RC_GENERAL_TYPE;

			switch (attr) {
			case A_local_rc_type:
				if (rsbac_ta_list_get_data_ttl(ta_number, lnetobj_handles.rc, NULL, &tid_p->netobj.sock_p, &type)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;
					struct rsbac_rc_nettemp_aci_t aci;

					if(!ta_number && tid_p->netobj.local_temp)
						temp = tid_p->netobj.local_temp;
					else
						rsbac_ta_net_lookup_templates
						    (ta_number, &tid_p->netobj,
						     &temp, NULL);
					if (temp) {
						if (!rsbac_ta_list_get_data_ttl(ta_number, nettemp_handles.rc, NULL, &temp, &aci))
							type = aci.netobj_type;
					}
				}
				break;

			case A_remote_rc_type:
				if (rsbac_ta_list_get_data_ttl(ta_number, rnetobj_handles.rc, NULL, &tid_p->netobj.sock_p, &type)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;
					struct rsbac_rc_nettemp_aci_t aci;

					if(!ta_number && tid_p->netobj.remote_temp)
						temp = tid_p->netobj.remote_temp;
					else
						rsbac_ta_net_lookup_templates
						    (ta_number, &tid_p->netobj,
						     NULL, &temp);
					if (temp) {
						if (!rsbac_ta_list_get_data_ttl(ta_number, nettemp_handles.rc, NULL, &temp, &aci))
							type =
							    aci.
							    netobj_type;
					}
				}
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err)
				value->rc_type = type;
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	return err;
}
#endif				/* NET_OBJ */

#ifdef CONFIG_RSBAC_FD_CACHE
int rsbac_fd_cache_invalidate(struct rsbac_fs_file_t * file_p)
{
	struct rsbac_fd_cache_desc_t fd_desc;
	int i;

	fd_desc.device = file_p->device;
	fd_desc.inode = file_p->inode;
			
	for (i = 0; i < SW_NONE; i++) {
		if (fd_cache_handle[i])
			rsbac_list_lol_remove(fd_cache_handle[i], &fd_desc);
	}
#ifdef CONFIG_RSBAC_XSTATS
	fd_cache_invalidates++;
#endif
	return 0;
}

int rsbac_fd_cache_invalidate_all(void)
{
	int i;

	for (i = 0; i < SW_NONE; i++) {
		if (fd_cache_handle[i])
			rsbac_list_lol_remove_all(fd_cache_handle[i]);
	}
#ifdef CONFIG_RSBAC_XSTATS
	fd_cache_invalidate_alls++;
#endif
	return 0;
}
#endif

/* The value parameter to rsbac_get_attr(s) and rsbac_set_attr() is a pointer */
/* to the appropiate data structure holding the attribute value.            */

int rsbac_ta_get_attr(rsbac_list_ta_number_t ta_number,
		      enum rsbac_switch_target_t module,
		      enum rsbac_target_t target,
		      union rsbac_target_id_t tid,
		      enum rsbac_attribute_t attr,
		      union rsbac_attribute_value_t *value_p,
		      rsbac_boolean_t inherit)
{
	int err = 0;

	if (!rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_get_attr(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (!value_p)
		return -RSBAC_EINVALIDPOINTER;
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_get_attr(): called from interrupt, process %u(%s)!\n",
				current->pid, current->comm);
		return -RSBAC_EFROMINTERRUPT;
	}
#ifdef CONFIG_RSBAC_XSTATS
	get_attr_count[target]++;
#endif
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
#ifdef CONFIG_RSBAC_FD_CACHE
		if (inherit && !ta_number && fd_cache_handle[module] && (RSBAC_MAJOR(tid.file.device) > 1)) {
			struct rsbac_fd_cache_desc_t fd_desc;
			rsbac_enum_t cache_attr = attr;

			fd_desc.device = tid.file.device;
			fd_desc.inode = tid.file.inode;
			if (!rsbac_list_lol_get_subdata(fd_cache_handle[module],
						&fd_desc, &cache_attr,
						value_p)) {
#ifdef CONFIG_RSBAC_XSTATS
				fd_cache_hits[module]++;
#endif
				return 0;
			}
			err = get_attr_fd(0, module, target, &tid,
				   attr, value_p, TRUE);
			if (!err && !ta_number) {
#if 0
				rsbac_pr_debug(auto, "Adding fd cache item device %02u:%02u inode %u attr %u\n",
					RSBAC_MAJOR(fd_desc.device), RSBAC_MINOR(fd_desc.device),
					fd_desc.inode, attr);
#endif
				rsbac_list_lol_subadd_ttl(fd_cache_handle[module],
						rsbac_fd_cache_ttl,
                                                &fd_desc, &cache_attr,
                                                value_p);
#ifdef CONFIG_RSBAC_XSTATS
				fd_cache_misses[module]++;
#endif
			}
			return err;
		}
#endif

		return get_attr_fd(ta_number, module, target, &tid,
				   attr, value_p, inherit);

	case T_DEV:
		return get_attr_dev(ta_number, module, target, tid.dev,
				    attr, value_p, inherit);

	case T_IPC:
		return get_attr_ipc(ta_number, module, target, &tid,
				    attr, value_p, inherit);

	case T_USER:
		return get_attr_user(ta_number, module, target, &tid,
				     attr, value_p, inherit);

	case T_PROCESS:
		return get_attr_process(ta_number, module, target, &tid,
					attr, value_p, inherit);

#ifdef CONFIG_RSBAC_UM
	case T_GROUP:
		return get_attr_group(ta_number, module, target, &tid,
				      attr, value_p, inherit);
#endif				/* CONFIG_RSBAC_UM */

#ifdef CONFIG_RSBAC_NET_DEV
	case T_NETDEV:
		return get_attr_netdev(ta_number, module, target, &tid,
				       attr, value_p, inherit);
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
	case T_NETTEMP:
		return get_attr_nettemp(ta_number, module, target, &tid,
					attr, value_p, inherit);

	case T_NETOBJ:
		return get_attr_netobj(ta_number, module, target, &tid,
				       attr, value_p, inherit);
#endif

		/* switch target: no valid target */
	default:
		return -RSBAC_EINVALIDTARGET;
	}

	return err;
}

/************************************************************************** */

static int set_attr_fd(rsbac_list_ta_number_t ta_number,
		       enum rsbac_switch_target_t module,
		       enum rsbac_target_t target,
		       union rsbac_target_id_t *tid_p,
		       enum rsbac_attribute_t attr,
		       union rsbac_attribute_value_t *value_p)
{
	int err = 0;
	struct rsbac_device_list_item_t *device_p;
	u_int hash;
	int srcu_idx;

	/* rsbac_pr_debug(ds, "Setting file/dir/fifo/symlink "
		       "attribute %u for device %02u:%02u, inode %lu, "
		       "dentry_p %p\n", attr,
		       RSBAC_MAJOR(tid_p->file.device),
		       RSBAC_MINOR(tid_p->file.device),
		       (u_long)tid_p->file.inode, tid_p->file.dentry_p); */
	hash = device_hash(tid_p->file.device);
	srcu_idx = srcu_read_lock(&device_list_srcu[hash]);
	/* rsbac_pr_debug(ds, "passed device read lock\n"); */
	/* lookup device */
	device_p = lookup_device(tid_p->file.device, hash);
	if (!device_p) {
		rsbac_printk(KERN_WARNING "rsbac_set_attr(): unknown device %02u:%02u\n",
			     RSBAC_MAJOR(tid_p->file.
					 device),
			     RSBAC_MINOR(tid_p->file.
					 device));
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
		return -RSBAC_EINVALIDDEV;
	}
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_fd_aci_t aci = DEFAULT_GEN_FD_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   device_p->handles.gen,
						   NULL,
						   &tid_p->file.inode,
						   &aci);
			switch (attr) {
			case A_log_array_low:
				aci.log_array_low = value_p->log_array_low;
				break;
			case A_log_array_high:
				aci.log_array_high =
				    value_p->log_array_high;
				break;
			case A_log_program_based:
				aci.log_program_based =
				    value_p->log_program_based;
				break;
			case A_symlink_add_remote_ip:
				aci.symlink_add_remote_ip =
				    value_p->symlink_add_remote_ip;
				break;
			case A_symlink_add_uid:
				aci.symlink_add_uid =
				    value_p->symlink_add_uid;
				break;
			case A_symlink_add_mac_level:
				aci.symlink_add_mac_level =
				    value_p->symlink_add_mac_level;
				break;
			case A_symlink_add_rc_role:
				aci.symlink_add_rc_role =
				    value_p->symlink_add_rc_role;
				break;
			case A_linux_dac_disable:
				aci.linux_dac_disable =
				    value_p->linux_dac_disable;
				break;
			case A_fake_root_uid:
				aci.fake_root_uid = value_p->fake_root_uid;
				break;
			case A_auid_exempt:
				aci.auid_exempt = value_p->auid_exempt;
				break;
			case A_vset:
				aci.vset = value_p->vset;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    device_p->
							    handles.gen,
							    0,
							    &tid_p->file.
							    inode, &aci);
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_fd_aci_t aci = DEFAULT_MAC_FD_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						device_p->handles.mac,
						NULL,
						&tid_p->file.inode,
						&aci);
			switch (attr) {
			case A_security_level:
				aci.sec_level = value_p->security_level;
				break;
			case A_mac_categories:
				aci.mac_categories =
				    value_p->mac_categories;
				break;
			case A_mac_auto:
				aci.mac_auto = value_p->mac_auto;
				break;
			case A_mac_prop_trusted:
				aci.mac_prop_trusted =
				    value_p->mac_prop_trusted;
				break;
			case A_mac_file_flags:
				aci.mac_file_flags =
				    value_p->
				    mac_file_flags & RSBAC_MAC_F_FLAGS;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							device_p->
							handles.mac,
							0,
							&tid_p->file.
							inode, &aci);
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_fd_aci_t aci = DEFAULT_PM_FD_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   device_p->handles.pm,
						   NULL,
						   &tid_p->file.inode,
						   &aci);
			switch (attr) {
			case A_pm_object_class:
				aci.pm_object_class =
				    value_p->pm_object_class;
				break;
			case A_pm_tp:
				aci.pm_tp = value_p->pm_tp;
				break;
			case A_pm_object_type:
				aci.pm_object_type =
				    value_p->pm_object_type;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							device_p->
							handles.pm,
							0,
							&tid_p->file.
							inode, &aci);
			}
		}
		break;
#endif				/* PM */

#if defined(CONFIG_RSBAC_DAZ)
	case SW_DAZ:
		{
#if defined(CONFIG_RSBAC_DAZ_CACHE)
			if (attr == A_daz_scanned) {
				err =
				    rsbac_list_add_ttl(device_p->handles.dazs,
						       rsbac_daz_ttl,
						       &tid_p->file.inode,
						       &value_p->
						       daz_scanned);
			} else
#endif
			{
				struct rsbac_daz_fd_aci_t aci =
				    DEFAULT_DAZ_FD_ACI;

				rsbac_ta_list_get_data_ttl(ta_number,
							   device_p->
							   handles.daz,
							   NULL,
							   &tid_p->file.inode,
							   &aci);
				switch (attr) {
				case A_daz_scanner:
					aci.daz_scanner =
					    value_p->daz_scanner;
					break;
				case A_daz_do_scan:
					aci.daz_do_scan = value_p->daz_do_scan;
					break;
				default:
					err = -RSBAC_EINVALIDATTR;
				}
				if (!err) {
					err = rsbac_ta_list_add_ttl
						(ta_number,
						device_p->handles.daz,
						0,
						&tid_p->file.inode, &aci);
				}
			}
		}
		break;
#endif				/* DAZ */

#if defined(CONFIG_RSBAC_FF)
	case SW_FF:
		{
			switch (attr) {
			case A_ff_flags:
				err = rsbac_ta_list_add_ttl(ta_number,
							device_p->
							handles.ff,
							0,
							&tid_p->file.
							inode,
							&value_p->ff_flags);
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* FF */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_fd_aci_t aci = DEFAULT_RC_FD_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   device_p->handles.rc,
						   NULL,
						   &tid_p->file.inode,
						   &aci);
			switch (attr) {
			case A_rc_type_fd:
				aci.rc_type_fd = value_p->rc_type_fd;
				break;
			case A_rc_force_role:
				aci.rc_force_role = value_p->rc_force_role;
				break;
			case A_rc_initial_role:
				aci.rc_initial_role =
				    value_p->rc_initial_role;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							device_p->
							handles.rc,
							0,
							&tid_p->file.
							inode, &aci);
			}
		}
		break;
#endif				/* RC */

#if defined(CONFIG_RSBAC_AUTH)
	case SW_AUTH:
		{
			struct rsbac_auth_fd_aci_t aci =
			    DEFAULT_AUTH_FD_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						device_p->handles.auth,
						NULL,
						&tid_p->file.inode,
						&aci);
			switch (attr) {
			case A_auth_may_setuid:
				aci.auth_may_setuid =
				    value_p->auth_may_setuid;
				break;
			case A_auth_may_set_cap:
				aci.auth_may_set_cap =
				    value_p->auth_may_set_cap;
				break;
			case A_auth_learn:
				aci.auth_learn = value_p->auth_learn;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							device_p->
							handles.auth,
							0,
							&tid_p->file.
							inode, &aci);
			}
		}
		break;
#endif				/* AUTH */

#if defined(CONFIG_RSBAC_CAP)
	case SW_CAP:
		{
			struct rsbac_cap_fd_aci_t aci = DEFAULT_CAP_FD_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						device_p->handles.cap,
						NULL,
						&tid_p->file.inode,
						&aci);
			switch (attr) {
			case A_min_caps:
				aci.min_caps.cap[0] = value_p->min_caps.cap[0];
                                aci.min_caps.cap[1] = value_p->min_caps.cap[1];
				break;
			case A_max_caps:
				aci.max_caps.cap[0] = value_p->max_caps.cap[0];
                                aci.max_caps.cap[1] = value_p->max_caps.cap[1];
				break;
			case A_cap_ld_env:
				aci.cap_ld_env = value_p->cap_ld_env;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    device_p->
							    handles.cap,
							    0,
							    &tid_p->file.
							    inode, &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_RES)
	case SW_RES:
		{
			struct rsbac_res_fd_aci_t aci = DEFAULT_RES_FD_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						device_p->handles.res,
						NULL,
						&tid_p->file.inode,
						&aci);
			switch (attr) {
			case A_res_min:
				memcpy(&aci.res_min, &value_p->res_array,
				       sizeof(aci.res_min));
				break;
			case A_res_max:
				memcpy(&aci.res_max, &value_p->res_array,
				       sizeof(aci.res_max));
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				struct rsbac_res_fd_aci_t def_aci =
				    DEFAULT_RES_FD_ACI;

				if (memcmp(&aci, &def_aci, sizeof(aci)))
					err = rsbac_ta_list_add_ttl
						(ta_number,
						device_p->handles.res,
						0,
						&tid_p->file.inode, &aci);
				else
					err =
					    rsbac_ta_list_remove(ta_number,
								 device_p->
								 handles.res,
								 &tid_p->file.
								 inode);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_PAX)
	case SW_PAX:
		{
			switch (attr) {
			case A_pax_flags:
				value_p->pax_flags &= RSBAC_PAX_ALL_FLAGS;
				err = rsbac_ta_list_add_ttl(ta_number,
							    device_p->
							    handles.pax,
							    0,
							    &tid_p->file.
							    inode,
							    &value_p->pax_flags);
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* PAX */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}
	/* free access to device_list_head */
	srcu_read_unlock(&device_list_srcu[hash], srcu_idx);

#ifdef CONFIG_RSBAC_FD_CACHE
	if (fd_cache_handle[module]) {
		if (target == T_DIR)
			rsbac_list_lol_remove_all(fd_cache_handle[module]);
		else {
			struct rsbac_fd_cache_desc_t fd_desc;

			fd_desc.device = tid_p->file.device;
			fd_desc.inode = tid_p->file.inode;
			rsbac_list_lol_remove(fd_cache_handle[module], &fd_desc);
		}
	}
#endif

	return err;
}

static int set_attr_dev(rsbac_list_ta_number_t ta_number,
			enum rsbac_switch_target_t module,
			enum rsbac_target_t target,
			struct rsbac_dev_desc_t dev,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *value_p)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting dev attribute\n"); */
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_dev_aci_t aci =
			    DEFAULT_GEN_DEV_ACI;

			if (dev.type > D_char)
				return -RSBAC_EINVALIDTARGET;
			rsbac_ta_list_get_data_ttl(ta_number,
						   dev_handles.gen,
						   NULL, &dev, &aci);
			switch (attr) {
			case A_log_array_low:
				aci.log_array_low = value_p->log_array_low;
				break;
			case A_log_array_high:
				aci.log_array_high =
				    value_p->log_array_high;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    dev_handles.
							    gen, 0, &dev,
							    &aci);
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_dev_aci_t aci =
			    DEFAULT_MAC_DEV_ACI;

			if (dev.type > D_char)
				return -RSBAC_EINVALIDTARGET;
			rsbac_ta_list_get_data_ttl(ta_number,
						   dev_handles.mac,
						   NULL, &dev, &aci);
			switch (attr) {
			case A_security_level:
				aci.sec_level = value_p->security_level;
				break;
			case A_mac_categories:
				aci.mac_categories =
				    value_p->mac_categories;
				break;
			case A_mac_check:
				aci.mac_check = value_p->mac_check;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    dev_handles.
							    mac, 0, &dev,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_dev_aci_t aci = DEFAULT_PM_DEV_ACI;

			if (dev.type > D_char)
				return -RSBAC_EINVALIDTARGET;
			rsbac_ta_list_get_data_ttl(ta_number,
						   dev_handles.pm,
						   NULL, &dev, &aci);
			switch (attr) {
			case A_pm_object_type:
				aci.pm_object_type =
				    value_p->pm_object_type;
				break;
			case A_pm_object_class:
				aci.pm_object_class =
				    value_p->pm_object_class;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    dev_handles.pm,
							    0, &dev, &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = value_p->rc_type;
			struct rsbac_dev_desc_t dev_desc;
			rsbac_list_handle_t handle;

			dev_desc.major = dev.major;
			dev_desc.minor = dev.minor;
			switch (dev.type) {
			case D_char:
				dev_desc.type = D_char;
				handle = dev_handles.rc;
				break;
			case D_block:
				dev_desc.type = D_block;
				handle = dev_handles.rc;
				break;
			case D_char_major:
				if (type > RC_type_max_value)
					return -RSBAC_EINVALIDVALUE;
				dev_desc.type = D_char;
			    	dev_desc.minor = 0;
				handle = dev_major_handles.rc;
				break;
			case D_block_major:
				if (type > RC_type_max_value)
					return -RSBAC_EINVALIDVALUE;
				dev_desc.type = D_block;
			    	dev_desc.minor = 0;
				handle = dev_major_handles.rc;
				break;
			default:
				return -RSBAC_EINVALIDTARGET;
			}

			switch (attr) {
			case A_rc_type:
				err = rsbac_ta_list_add_ttl(ta_number,
							    handle,
							    0,
							    &dev_desc,
							    &type);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}

static int set_attr_ipc(rsbac_list_ta_number_t ta_number,
			enum rsbac_switch_target_t module,
			enum rsbac_target_t target,
			union rsbac_target_id_t *tid_p,
			enum rsbac_attribute_t attr,
			union rsbac_attribute_value_t *value_p)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting ipc attribute"); */
	switch (module) {
#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_ipc_aci_t aci =
			    DEFAULT_MAC_IPC_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   ipc_handles.mac,
						   NULL,
						   &tid_p->ipc, &aci);
			switch (attr) {
			case A_security_level:
				aci.sec_level = value_p->security_level;
				break;
			case A_mac_categories:
				aci.mac_categories =
				    value_p->mac_categories;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    ipc_handles.
							    mac, 0,
							    &tid_p->ipc,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_ipc_aci_t aci = DEFAULT_PM_IPC_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   ipc_handles.pm,
						   NULL,
						   &tid_p->ipc, &aci);
			switch (attr) {
			case A_pm_object_type:
				aci.pm_object_type =
				    value_p->pm_object_type;
				break;
			case A_pm_ipc_purpose:
				aci.pm_ipc_purpose =
				    value_p->pm_ipc_purpose;
				break;
			case A_pm_object_class:
				aci.pm_object_class =
				    value_p->pm_object_class;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    ipc_handles.pm,
							    0,
							    &tid_p->ipc,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = value_p->rc_type;

			switch (attr) {
			case A_rc_type:
				err = rsbac_ta_list_add_ttl(ta_number,
							    ipc_handles.rc,
							    0,
							    &tid_p->ipc,
							    &type);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_JAIL)
	case SW_JAIL:
		{
			rsbac_jail_id_t id = value_p->jail_id;

			switch (attr) {
			case A_jail_id:
/*				if (id)
					rsbac_pr_debug(aef,
						       "Setting jail_id for IPC "
						       "%s %lu to %u\n",
						       get_ipc_target_name(tmp,
						       			   tid_p->ipc.type),
						       tid_p->ipc.id.id_nr,
						       id); */
				err = rsbac_ta_list_add_ttl(ta_number,
							    ipc_handles.
							    jail, 0,
							    &tid_p->ipc,
							    &id);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}

static int set_attr_user(rsbac_list_ta_number_t ta_number,
			 enum rsbac_switch_target_t module,
			 enum rsbac_target_t target,
			 union rsbac_target_id_t *tid_p,
			 enum rsbac_attribute_t attr,
			 union rsbac_attribute_value_t *value_p)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting %s user attribute %i "
		       "for %u to %i\n",
		       get_switch_target_name(tmp, module), attr,
		       tid_p->user, value_p->dummy); */
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_user_aci_t aci =
			    DEFAULT_GEN_U_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.gen,
						   NULL,
						   &tid_p->user, &aci);
			switch (attr) {
			case A_pseudo:
				aci.pseudo = value_p->pseudo;
				break;
			case A_log_user_based:
				aci.log_user_based =
				    value_p->log_user_based;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.
							    gen, 0,
							    &tid_p->user,
							    &aci);
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_user_aci_t aci =
			    DEFAULT_MAC_U_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.mac,
						   NULL,
						   &tid_p->user, &aci);
			switch (attr) {
			case A_security_level:
				if (value_p->security_level <
				    aci.min_security_level)
					err = -RSBAC_EINVALIDVALUE;
				else
					aci.security_level =
					    value_p->security_level;
				break;
			case A_initial_security_level:
				if ((value_p->security_level <
				     aci.min_security_level)
				    || (value_p->security_level >
					aci.security_level)
				    )
					err = -RSBAC_EINVALIDVALUE;
				else
					aci.initial_security_level =
					    value_p->security_level;
				break;
			case A_min_security_level:
				if (value_p->security_level >
				    aci.security_level)
					err = -RSBAC_EINVALIDVALUE;
				else
					aci.min_security_level =
					    value_p->security_level;
				break;
			case A_mac_categories:
				if ((value_p->mac_categories & aci.
				     mac_min_categories) !=
				    aci.mac_min_categories)
					err = -RSBAC_EINVALIDVALUE;
				else
					aci.mac_categories =
					    value_p->mac_categories;
				break;
			case A_mac_initial_categories:
				if (((value_p->mac_categories & aci.
				      mac_min_categories) !=
				     aci.mac_min_categories)
				    ||
				    ((value_p->mac_categories & aci.
				      mac_categories) !=
				     value_p->mac_categories)
				    )
					err = -RSBAC_EINVALIDVALUE;
				else
					aci.mac_initial_categories =
					    value_p->mac_categories;
				break;
			case A_mac_min_categories:
				if ((value_p->mac_categories & aci.
				     mac_categories) !=
				    value_p->mac_categories)
					err = -RSBAC_EINVALIDVALUE;
				else
					aci.mac_min_categories =
					    value_p->mac_categories;
				break;
			case A_system_role:
			case A_mac_role:
				aci.system_role = value_p->system_role;
				break;
			case A_mac_user_flags:
				aci.mac_user_flags =
				    value_p->
				    mac_user_flags & RSBAC_MAC_U_FLAGS;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.
							    mac, 0,
							    &tid_p->user,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_user_aci_t aci = DEFAULT_PM_U_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.pm,
						   NULL,
						   &tid_p->user, &aci);
			switch (attr) {
			case A_pm_task_set:
				aci.pm_task_set = value_p->pm_task_set;
				break;
			case A_pm_role:
				aci.pm_role = value_p->pm_role;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.
							    pm, 0,
							    &tid_p->user,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_DAZ)
	case SW_DAZ:
		{
			rsbac_system_role_int_t role =
			    value_p->system_role;

			switch (attr) {
			case A_system_role:
			case A_daz_role:
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.
							    daz, 0,
							    &tid_p->user,
							    &role);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_FF)
	case SW_FF:
		{
			rsbac_system_role_int_t role =
			    value_p->system_role;

			switch (attr) {
			case A_system_role:
			case A_ff_role:
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.
							    ff, 0,
							    &tid_p->user,
							    &role);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_user_aci_t aci = DEFAULT_RC_U_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.rc,
						   NULL,
						   &tid_p->user, &aci);
			switch (attr) {
			case A_rc_def_role:
				aci.rc_role = value_p->rc_def_role;
				break;
			case A_rc_type:
				aci.rc_type = value_p->rc_type;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.
							    rc, 0,
							    &tid_p->user,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_AUTH)
	case SW_AUTH:
		{
			rsbac_system_role_int_t role =
			    value_p->system_role;

			switch (attr) {
			case A_system_role:
			case A_auth_role:
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.
							    auth, 0,
							    &tid_p->user,
							    &role);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_CAP)
	case SW_CAP:
		{
			struct rsbac_cap_user_aci_t aci =
			    DEFAULT_CAP_U_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.cap,
						   NULL,
						   &tid_p->user, &aci);
			switch (attr) {
			case A_system_role:
			case A_cap_role:
				aci.cap_role = value_p->system_role;
				break;
			case A_min_caps:
				aci.min_caps.cap[0] = value_p->min_caps.cap[0];
				aci.min_caps.cap[1] = value_p->min_caps.cap[1];
				break;
			case A_max_caps:
				aci.max_caps.cap[0] = value_p->max_caps.cap[0];
				aci.max_caps.cap[1] = value_p->max_caps.cap[1];
				break;
			case A_cap_ld_env:
				aci.cap_ld_env = value_p->cap_ld_env;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.
							    cap, 0,
							    &tid_p->user,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_JAIL)
	case SW_JAIL:
		{
			rsbac_system_role_int_t role =
			    value_p->system_role;

			switch (attr) {
			case A_system_role:
			case A_jail_role:
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.
							    jail, 0,
							    &tid_p->user,
							    &role);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_RES)
	case SW_RES:
		{
			struct rsbac_res_user_aci_t aci =
			    DEFAULT_RES_U_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   user_handles.res,
						   NULL,
						   &tid_p->user, &aci);
			switch (attr) {
			case A_system_role:
			case A_res_role:
				aci.res_role = value_p->system_role;
				break;
			case A_res_min:
				memcpy(&aci.res_min, &value_p->res_array,
				       sizeof(aci.res_min));
				break;
			case A_res_max:
				memcpy(&aci.res_max, &value_p->res_array,
				       sizeof(aci.res_max));
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				struct rsbac_res_user_aci_t def_aci =
				    DEFAULT_RES_U_ACI;

				if (tid_p->user != RSBAC_ALL_USERS) {
					rsbac_uid_t all_users =
					    RSBAC_ALL_USERS;

					rsbac_ta_list_get_data_ttl
					    (ta_number, user_handles.res,
					     NULL, &all_users, &def_aci);
				}
				if (memcmp(&aci, &def_aci, sizeof(aci)))
					err =
					    rsbac_ta_list_add_ttl
					    (ta_number, user_handles.res,
					     0, &tid_p->user, &aci);
				else
					err =
					    rsbac_ta_list_remove(ta_number,
								 user_handles.
								 res,
								 &tid_p->
								 user);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_PAX)
	case SW_PAX:
		{
			rsbac_system_role_int_t role =
			    value_p->system_role;

			switch (attr) {
			case A_system_role:
			case A_pax_role:
				err = rsbac_ta_list_add_ttl(ta_number,
							    user_handles.
							    pax, 0,
							    &tid_p->user,
							    &role);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}

static int set_attr_process(rsbac_list_ta_number_t ta_number,
			    enum rsbac_switch_target_t module,
			    enum rsbac_target_t target,
			    union rsbac_target_id_t *tid_p,
			    enum rsbac_attribute_t attr,
			    union rsbac_attribute_value_t *value_p)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting process attribute\n"); */
	if (!tid_p->process) {
		rsbac_printk(KERN_WARNING "rsbac_set_attr(): Trying to set attribute for process 0!\n");
		return -RSBAC_EINVALIDTARGET;
	}
	switch (module) {
	case SW_GEN:
		{
			struct rsbac_gen_process_aci_t aci =
			    DEFAULT_GEN_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.gen,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_vset:
				aci.vset = value_p->vset;
				break;
			case A_log_program_based:
				aci.log_program_based =
				    value_p->log_program_based;
				break;
			case A_fake_root_uid:
				aci.fake_root_uid = value_p->fake_root_uid;
				break;
			case A_audit_uid:
				aci.audit_uid = value_p->audit_uid;
				break;
			case A_auid_exempt:
				aci.auid_exempt = value_p->auid_exempt;
				break;
			case A_remote_ip:
				aci.remote_ip = value_p->remote_ip;
				break;
			case A_kernel_thread:
				aci.kernel_thread = value_p->kernel_thread;
				break;
#if defined(CONFIG_RSBAC_AUTH_LEARN) || defined(CONFIG_RSBAC_CAP_LEARN)
			case A_program_file:
				aci.program_file =
				    value_p->program_file;
				break;
#endif
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.gen,
							    0,
							    &tid_p->
							    process, &aci);
			}
		}
		break;

#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_process_aci_t aci =
			    DEFAULT_MAC_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.mac,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_security_level:
				aci.owner_sec_level =
				    value_p->security_level;
				break;
			case A_initial_security_level:
				aci.owner_initial_sec_level =
				    value_p->security_level;
				break;
			case A_min_security_level:
				aci.owner_min_sec_level =
				    value_p->security_level;
				break;
			case A_mac_categories:
				aci.mac_owner_categories =
				    value_p->mac_categories;
				break;
			case A_mac_initial_categories:
				aci.mac_owner_initial_categories =
				    value_p->mac_categories;
				break;
			case A_mac_min_categories:
				aci.mac_owner_min_categories =
				    value_p->mac_categories;
				break;
			case A_current_sec_level:
				aci.current_sec_level =
				    value_p->current_sec_level;
				break;
			case A_mac_curr_categories:
				aci.mac_curr_categories =
				    value_p->mac_categories;
				break;
			case A_min_write_open:
				aci.min_write_open =
				    value_p->min_write_open;
				break;
			case A_min_write_categories:
				aci.min_write_categories =
				    value_p->mac_categories;
				break;
			case A_max_read_open:
				aci.max_read_open = value_p->max_read_open;
				break;
			case A_max_read_categories:
				aci.max_read_categories =
				    value_p->mac_categories;
				break;
			case A_mac_process_flags:
				aci.mac_process_flags =
				    value_p->
				    mac_process_flags & RSBAC_MAC_P_FLAGS;
				break;
			case A_mac_auto:
				if (value_p->mac_auto)
					aci.mac_process_flags |= MAC_auto;
				else
					aci.mac_process_flags &= ~MAC_auto;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.mac,
							    0,
							    &tid_p->
							    process, &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_process_aci_t aci =
			    DEFAULT_PM_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.pm,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
			case A_pm_tp:
				aci.pm_tp = value_p->pm_tp;
				break;
			case A_pm_current_task:
				aci.pm_current_task =
				    value_p->pm_current_task;
				break;
			case A_pm_process_type:
				aci.pm_process_type =
				    value_p->pm_process_type;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.
							    pm, 0,
							    &tid_p->
							    process, &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_DAZ)
	case SW_DAZ:
		{
			struct rsbac_daz_process_aci_t aci =
			    DEFAULT_DAZ_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.daz,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
			case A_daz_scanner:
				aci.daz_scanner = value_p->daz_scanner;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.
							    daz, 0,
							    &tid_p->
							    process, &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_process_aci_t aci =
			    DEFAULT_RC_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.rc,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_rc_role:
				aci.rc_role = value_p->rc_role;
				break;
			case A_rc_type:
				aci.rc_type = value_p->rc_type;
				break;
			case A_rc_select_type:
			        aci.rc_select_type = value_p->rc_select_type;
			        break;
			case A_rc_force_role:
				aci.rc_force_role = value_p->rc_force_role;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.rc,
							    0,
							    &tid_p->
							    process, &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_AUTH)
	case SW_AUTH:
		{
			struct rsbac_auth_process_aci_t aci =
			    DEFAULT_AUTH_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.auth,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
			case A_auth_may_setuid:
				aci.auth_may_setuid =
				    value_p->auth_may_setuid;
				break;
			case A_auth_may_set_cap:
				aci.auth_may_set_cap =
				    value_p->auth_may_set_cap;
				break;
#if defined(CONFIG_RSBAC_AUTH_LEARN)
			case A_auth_start_uid:
				aci.auth_start_uid =
				    value_p->auth_start_uid;
				break;
#ifdef CONFIG_RSBAC_AUTH_DAC_OWNER
			case A_auth_start_euid:
				aci.auth_start_euid =
				    value_p->auth_start_euid;
				break;
#endif
#ifdef CONFIG_RSBAC_AUTH_GROUP
			case A_auth_start_gid:
				aci.auth_start_gid =
				    value_p->auth_start_gid;
				break;
#ifdef CONFIG_RSBAC_AUTH_DAC_GROUP
			case A_auth_start_egid:
				aci.auth_start_egid =
				    value_p->auth_start_egid;
				break;
#endif
#endif
			case A_auth_learn:
				aci.auth_learn = value_p->auth_learn;
				break;
#endif
			case A_auth_last_auth:
				aci.auth_last_auth =
				    value_p->auth_last_auth;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.auth,
							    0,
							    &tid_p->process,
							    &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_CAP)
	case SW_CAP:
		{
			struct rsbac_cap_process_aci_t aci =
			    DEFAULT_CAP_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.cap,
						   NULL,
						   &tid_p->process, &aci);
			switch (attr) {
			case A_cap_process_hiding:
				aci.cap_process_hiding =
				    value_p->cap_process_hiding;
				break;
#if defined(CONFIG_RSBAC_CAP_LOG_MISSING) || defined(CONFIG_RSBAC_CAP_LEARN)
			case A_max_caps_user:
				aci.max_caps_user.cap[0] = value_p->max_caps_user.cap[0];
				aci.max_caps_user.cap[1] = value_p->max_caps_user.cap[1];
				break;
			case A_max_caps_program:
				aci.max_caps_program.cap[0] = value_p->max_caps_program.cap[0];
				aci.max_caps_program.cap[1] = value_p->max_caps_program.cap[1];
#endif
				break;
			case A_cap_ld_env:
				aci.cap_ld_env = value_p->cap_ld_env;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.
							    cap, 0,
							    &tid_p->
							    process, &aci);
			}
		}
		break;
#endif

#if defined(CONFIG_RSBAC_JAIL)
	case SW_JAIL:
		{
			struct rsbac_jail_process_aci_t aci =
			    DEFAULT_JAIL_P_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   process_handles.jail,
						   NULL, &tid_p->process,
						   &aci);
			switch (attr) {
			case A_jail_id:
				aci.id = value_p->jail_id;
				break;
			case A_jail_parent:
				aci.parent = value_p->jail_parent;
				break;
			case A_jail_ip:
				aci.ip = value_p->jail_ip;
				break;
			case A_jail_flags:
				aci.flags = value_p->jail_flags;
				break;
			case A_jail_max_caps:
				aci.max_caps.cap[0] = value_p->jail_max_caps.cap[0];
				aci.max_caps.cap[1] = value_p->jail_max_caps.cap[1];
				break;
			case A_jail_scd_get:
				aci.scd_get = value_p->jail_scd_get;
				break;
			case A_jail_scd_modify:
				aci.scd_modify = value_p->jail_scd_modify;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    process_handles.jail,
							    0,
							    &tid_p->
							    process, &aci);
			}
		}
		break;
#endif

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}

#ifdef CONFIG_RSBAC_UM
static int set_attr_group(rsbac_list_ta_number_t ta_number,
			  enum rsbac_switch_target_t module,
			  enum rsbac_target_t target,
			  union rsbac_target_id_t *tid_p,
			  enum rsbac_attribute_t attr,
			  union rsbac_attribute_value_t *value_p)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting group attribute\n"); */
	switch (module) {
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = value_p->rc_type;
			rsbac_gid_t group_desc;

			group_desc = tid_p->group;

			switch (attr) {
			case A_rc_type:
				err = rsbac_ta_list_add_ttl(ta_number,
							    group_handles.
							    rc, 0,
							    &group_desc,
							    &type);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}
#endif				/* UM */

#ifdef CONFIG_RSBAC_NET_DEV
static int set_attr_netdev(rsbac_list_ta_number_t ta_number,
			   enum rsbac_switch_target_t module,
			   enum rsbac_target_t target,
			   union rsbac_target_id_t *tid_p,
			   enum rsbac_attribute_t attr,
			   union rsbac_attribute_value_t *value_p)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting netdev attribute\n"); */
	switch (module) {
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	case SW_GEN:
		{
			struct rsbac_gen_netdev_aci_t aci =
			    DEFAULT_GEN_NETDEV_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   netdev_handles.gen,
						   NULL,
						   &tid_p->netdev, &aci);
			switch (attr) {
			case A_log_array_low:
				aci.log_array_low = value_p->log_array_low;
				break;
			case A_log_array_high:
				aci.log_array_high =
				    value_p->log_array_high;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    netdev_handles.
							    gen, 0,
							    &tid_p->netdev,
							    &aci);
			}
		}
		break;
#endif
#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = value_p->rc_type;

			switch (attr) {
			case A_rc_type:
				err = rsbac_ta_list_add_ttl(ta_number,
							    netdev_handles.
							    rc, 0,
							    &tid_p->netdev,
							    &type);
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
static int set_attr_nettemp(rsbac_list_ta_number_t ta_number,
			    enum rsbac_switch_target_t module,
			    enum rsbac_target_t target,
			    union rsbac_target_id_t *tid_p,
			    enum rsbac_attribute_t attr,
			    union rsbac_attribute_value_t *value_p)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting nettemp attribute\n"); */
	if (!rsbac_ta_list_exist(ta_number, net_temp_handle, &tid_p->nettemp))
		return -RSBAC_EINVALIDTARGET;
	switch (module) {
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
	case SW_GEN:
		{
			struct rsbac_gen_netobj_aci_t aci =
			    DEFAULT_GEN_NETOBJ_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   nettemp_handles.gen,
						   NULL,
						   &tid_p->nettemp, &aci);
			switch (attr) {
			case A_log_array_low:
				aci.log_array_low = value_p->log_array_low;
				break;
			case A_log_array_high:
				aci.log_array_high =
				    value_p->log_array_high;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    nettemp_handles.
							    gen, 0,
							    &tid_p->
							    nettemp, &aci);
			}
		}
		break;
#endif				/* IND_NETOBJ_LOG */
#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_netobj_aci_t aci =
			    DEFAULT_MAC_NETOBJ_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   nettemp_handles.mac,
						   NULL,
						   &tid_p->nettemp, &aci);
			switch (attr) {
			case A_security_level:
				aci.sec_level = value_p->security_level;
				break;
			case A_mac_categories:
				aci.mac_categories =
				    value_p->mac_categories;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    nettemp_handles.
							    mac, 0,
							    &tid_p->
							    nettemp, &aci);
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_netobj_aci_t aci =
			    DEFAULT_PM_NETOBJ_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   nettemp_handles.pm,
						   NULL,
						   &tid_p->nettemp, &aci);
			switch (attr) {
			case A_pm_object_class:
				aci.pm_object_class =
				    value_p->pm_object_class;
				break;
			case A_pm_ipc_purpose:
				aci.pm_ipc_purpose =
				    value_p->pm_ipc_purpose;
				break;
			case A_pm_object_type:
				aci.pm_object_type =
				    value_p->pm_object_type;
				break;
			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    nettemp_handles.
							    pm, 0,
							    &tid_p->
							    nettemp, &aci);
			}
		}
		break;
#endif				/* PM */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			struct rsbac_rc_nettemp_aci_t aci =
			    DEFAULT_RC_NETTEMP_ACI;

			rsbac_ta_list_get_data_ttl(ta_number,
						   nettemp_handles.rc,
						   NULL,
						   &tid_p->nettemp, &aci);
			switch (attr) {
			case A_rc_type:
				aci.netobj_type = value_p->rc_type;
				break;
			case A_rc_type_nt:
				aci.nettemp_type = value_p->rc_type;
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (!err) {
				err = rsbac_ta_list_add_ttl(ta_number,
							    nettemp_handles.
							    rc, 0,
							    &tid_p->
							    nettemp, &aci);
			}
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}

static int set_attr_netobj(rsbac_list_ta_number_t ta_number,
			   enum rsbac_switch_target_t module,
			   enum rsbac_target_t target,
			   union rsbac_target_id_t *tid_p,
			   enum rsbac_attribute_t attr,
			   union rsbac_attribute_value_t *value_p)
{
	int err = 0;
	/* rsbac_pr_debug(ds, "Setting netobj attribute\n"); */
	switch (module) {
#if defined(CONFIG_RSBAC_MAC)
	case SW_MAC:
		{
			struct rsbac_mac_netobj_aci_t aci =
			    DEFAULT_MAC_NETOBJ_ACI;

			switch (attr) {
			case A_local_sec_level:
			case A_local_mac_categories:
				if (rsbac_ta_list_get_data_ttl(ta_number, lnetobj_handles.mac, NULL, &tid_p->netobj.sock_p, &aci)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;

					rsbac_ta_net_lookup_templates
					    (ta_number, &tid_p->netobj,
					     &temp, NULL);
					if (temp)
						rsbac_ta_list_get_data_ttl
						    (ta_number,
						     nettemp_handles.mac,
						     NULL, &temp, &aci);
				}
				break;

			case A_remote_sec_level:
			case A_remote_mac_categories:
				if (rsbac_ta_list_get_data_ttl(ta_number, rnetobj_handles.mac, NULL, &tid_p->netobj.sock_p, &aci)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;

					rsbac_ta_net_lookup_templates
					    (ta_number, &tid_p->netobj,
					     NULL, &temp);
					if (temp)
						rsbac_ta_list_get_data_ttl
						    (ta_number,
						     nettemp_handles.mac,
						     NULL, &temp, &aci);
				}
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (err)
				break;
			{
				switch (attr) {
				case A_local_sec_level:
					aci.sec_level =
					    value_p->security_level;
					err =
					    rsbac_ta_list_add_ttl
					    (ta_number,
					     lnetobj_handles.mac, 0,
					     &tid_p->netobj.sock_p, &aci);
					break;
				case A_remote_sec_level:
					aci.sec_level =
					    value_p->security_level;
					err =
					    rsbac_ta_list_add_ttl
					    (ta_number,
					     rnetobj_handles.mac, 0,
					     &tid_p->netobj.sock_p, &aci);
					break;
				case A_local_mac_categories:
					aci.mac_categories =
					    value_p->mac_categories;
					err =
					    rsbac_ta_list_add_ttl
					    (ta_number,
					     lnetobj_handles.mac, 0,
					     &tid_p->netobj.sock_p, &aci);
					break;
				case A_remote_mac_categories:
					aci.mac_categories =
					    value_p->mac_categories;
					err =
					    rsbac_ta_list_add_ttl
					    (ta_number,
					     rnetobj_handles.mac, 0,
					     &tid_p->netobj.sock_p, &aci);
					break;

				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
		}
		break;
#endif				/* MAC */

#if defined(CONFIG_RSBAC_PM)
	case SW_PM:
		{
			struct rsbac_pm_netobj_aci_t aci =
			    DEFAULT_PM_NETOBJ_ACI;

			switch (attr) {
			case A_local_pm_object_class:
			case A_local_pm_ipc_purpose:
			case A_local_pm_object_type:
				if (rsbac_ta_list_get_data_ttl(ta_number, lnetobj_handles.pm, NULL, &tid_p->netobj.sock_p, &aci)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;

					rsbac_ta_net_lookup_templates
					    (ta_number, &tid_p->netobj,
					     &temp, NULL);
					if (temp)
						rsbac_ta_list_get_data_ttl
						    (ta_number,
						     nettemp_handles.pm,
						     NULL, &temp, &aci);
				}
				break;

			case A_remote_pm_object_class:
			case A_remote_pm_ipc_purpose:
			case A_remote_pm_object_type:
				if (rsbac_ta_list_get_data_ttl(ta_number, rnetobj_handles.pm, NULL, &tid_p->netobj.sock_p, &aci)) {	/* not found -> fallback to template */
					rsbac_net_temp_id_t temp = 0;

					rsbac_ta_net_lookup_templates
					    (ta_number, &tid_p->netobj,
					     NULL, &temp);
					if (temp)
						rsbac_ta_list_get_data_ttl
						    (ta_number,
						     nettemp_handles.pm,
						     NULL, &temp, &aci);
				}
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
			if (err)
				break;
			{
				switch (attr) {
				case A_local_pm_object_class:
					aci.pm_object_class =
					    value_p->pm_object_class;
					err =
					    rsbac_ta_list_add_ttl
					    (ta_number, lnetobj_handles.pm,
					     0, &tid_p->netobj.sock_p,
					     &aci);
					break;
				case A_remote_pm_object_class:
					aci.pm_object_class =
					    value_p->pm_object_class;
					err =
					    rsbac_ta_list_add_ttl
					    (ta_number, rnetobj_handles.pm,
					     0, &tid_p->netobj.sock_p,
					     &aci);
					break;
				case A_local_pm_ipc_purpose:
					aci.pm_ipc_purpose =
					    value_p->pm_ipc_purpose;
					err =
					    rsbac_ta_list_add_ttl
					    (ta_number, lnetobj_handles.pm,
					     0, &tid_p->netobj.sock_p,
					     &aci);
					break;
				case A_remote_pm_ipc_purpose:
					aci.pm_ipc_purpose =
					    value_p->pm_ipc_purpose;
					err =
					    rsbac_ta_list_add_ttl
					    (ta_number, rnetobj_handles.pm,
					     0, &tid_p->netobj.sock_p,
					     &aci);
					break;
				case A_local_pm_object_type:
					aci.pm_object_type =
					    value_p->pm_object_type;
					err =
					    rsbac_ta_list_add_ttl
					    (ta_number, lnetobj_handles.pm,
					     0, &tid_p->netobj.sock_p,
					     &aci);
					break;
				case A_remote_pm_object_type:
					aci.pm_object_type =
					    value_p->pm_object_type;
					err =
					    rsbac_ta_list_add_ttl
					    (ta_number, rnetobj_handles.pm,
					     0, &tid_p->netobj.sock_p,
					     &aci);
					break;

				default:
					err = -RSBAC_EINVALIDATTR;
				}
			}
		}
		break;
#endif				/* PM */

#if defined(CONFIG_RSBAC_RC)
	case SW_RC:
		{
			rsbac_rc_type_id_t type = value_p->rc_type;

			switch (attr) {
			case A_local_rc_type:
				err = rsbac_ta_list_add_ttl(ta_number,
							    lnetobj_handles.
							    rc, 0,
							    &tid_p->netobj.
							    sock_p, &type);
				break;

			case A_remote_rc_type:
				err = rsbac_ta_list_add_ttl(ta_number,
							    rnetobj_handles.
							    rc, 0,
							    &tid_p->netobj.
							    sock_p, &type);
				break;

			default:
				err = -RSBAC_EINVALIDATTR;
			}
		}
		break;
#endif				/* RC */

	default:
		err = -RSBAC_EINVALIDMODULE;
	}

	return err;
}
#endif				/* UM */


int rsbac_ta_set_attr(rsbac_list_ta_number_t ta_number,
		      enum rsbac_switch_target_t module,
		      enum rsbac_target_t target,
		      union rsbac_target_id_t tid,
		      enum rsbac_attribute_t attr,
		      union rsbac_attribute_value_t value)
{
	int err = 0;
/*
#ifdef CONFIG_RSBAC_DEBUG
      char tmp[RSBAC_MAXNAMELEN];
#endif
*/
	if (!rsbac_initialized) {
		rsbac_printk(KERN_WARNING "rsbac_set_attr(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_set_attr(): called from interrupt, process %u(%s)!\n",
				current->pid, current->comm);
		return -RSBAC_EFROMINTERRUPT;
	}
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		err = set_attr_fd(ta_number, module, target, &tid, attr, &value);
		break;

	case T_DEV:
		err =
		    set_attr_dev(ta_number, module, target, tid.dev, attr,
				 &value);
		break;

	case T_IPC:
		err =
		    set_attr_ipc(ta_number, module, target, &tid, attr,
				 &value);
		break;

	case T_USER:
		err =
		    set_attr_user(ta_number, module, target, &tid, attr,
				  &value);
		break;

	case T_PROCESS:
		err =
		    set_attr_process(ta_number, module, target, &tid, attr,
				     &value);
		break;

#ifdef CONFIG_RSBAC_UM
	case T_GROUP:
		err =
		    set_attr_group(ta_number, module, target, &tid, attr,
				   &value);
		break;
#endif				/* CONFIG_RSBAC_UM */

#ifdef CONFIG_RSBAC_NET_DEV
	case T_NETDEV:
		err =
		    set_attr_netdev(ta_number, module, target, &tid, attr,
				    &value);
		break;
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
	case T_NETTEMP:
		err =
		    set_attr_nettemp(ta_number, module, target, &tid, attr,
				     &value);
		break;

	case T_NETOBJ:
		err =
		    set_attr_netobj(ta_number, module, target, &tid, attr,
				    &value);
		break;
#endif				/* NET_OBJ */

		/* switch(target): no valid target */
	default:
		return -RSBAC_EINVALIDTARGET;
	}
#ifdef CONFIG_RSBAC_XSTATS
	if (!err)
		set_attr_count[target]++;
#endif
	return err;
}

/************************************************************************** */

int rsbac_ta_remove_target(rsbac_list_ta_number_t ta_number,
			   enum rsbac_target_t target,
			   union rsbac_target_id_t tid)
{
	int error = 0;
	struct rsbac_device_list_item_t *device_p;
	u_int hash;
	int srcu_idx;

	if (!rsbac_initialized) {
		// rsbac_printk(KERN_WARNING "rsbac_remove_target(): RSBAC not initialized\n");
		return -RSBAC_ENOTINITIALIZED;
	}
	if (in_interrupt()) {
		rsbac_printk(KERN_WARNING "rsbac_remove_target(): called from interrupt!\n");
		return -RSBAC_EFROMINTERRUPT;
	}
	switch (target) {
	case T_FILE:
	case T_DIR:
	case T_FIFO:
	case T_SYMLINK:
	case T_UNIXSOCK:
		/* rsbac_pr_debug(ds, "Removing file/dir/fifo/symlink ACI\n"); */
#if defined(CONFIG_RSBAC_MAC)
		/* file and dir items can also have mac_f_trusets -> remove first */
		if ((target == T_FILE)
		    || (target == T_DIR)
		    )
			error = rsbac_mac_remove_f_trusets(tid.file);
#endif
#if defined(CONFIG_RSBAC_AUTH)
		/* file and dir items can also have auth_f_capsets -> remove first */
		if ((target == T_FILE)
		    || (target == T_DIR)
		    )
			error = rsbac_auth_remove_f_capsets(tid.file);
#endif
#if defined(CONFIG_RSBAC_ACL)
		/* items can also have an acl_fd_item -> remove first */
		error = rsbac_acl_remove_acl(ta_number, target, tid);
#endif
		hash = device_hash(tid.file.device);
		/* wait for read access to device_list_head */
		srcu_idx = srcu_read_lock(&device_list_srcu[hash]);

		/* lookup device */
		device_p = lookup_device(tid.file.device, hash);
		if (!device_p) {
			srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
			rsbac_printk(KERN_WARNING "rsbac_remove_target(): unknown device %02u:%02u\n",
				     RSBAC_MAJOR(tid.file.
						 device),
				     RSBAC_MINOR(tid.file.
						 device));
			return -RSBAC_EINVALIDDEV;
		}
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.gen,
				     &tid.file.inode);
#if defined(CONFIG_RSBAC_MAC)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.mac,
				     &tid.file.inode);
#endif
#if defined(CONFIG_RSBAC_PM)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.pm,
				     &tid.file.inode);
#endif
#if defined(CONFIG_RSBAC_DAZ)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.daz,
				     &tid.file.inode);
#if defined(CONFIG_RSBAC_DAZ_CACHE)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.dazs,
				     &tid.file.inode);
#endif
#endif
#if defined(CONFIG_RSBAC_FF)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.ff,
				     &tid.file.inode);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.rc,
				     &tid.file.inode);
#endif
#if defined(CONFIG_RSBAC_AUTH)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.auth,
				     &tid.file.inode);
#endif
#if defined(CONFIG_RSBAC_CAP)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.cap,
				     &tid.file.inode);
#endif
#if defined(CONFIG_RSBAC_PAX)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.pax,
				     &tid.file.inode);
#endif
#if defined(CONFIG_RSBAC_RES)
		rsbac_ta_list_remove(ta_number,
				     device_p->handles.res,
				     &tid.file.inode);
#endif

		/* free access to device_list_head */
		srcu_read_unlock(&device_list_srcu[hash], srcu_idx);
#ifdef CONFIG_RSBAC_FD_CACHE
		rsbac_fd_cache_invalidate(&tid.file);
#endif
		break;

	case T_DEV:
		{
                  switch (tid.dev.type)
                    {
                      case D_block:
                      case D_char:
                        rsbac_ta_list_remove(ta_number,
                                         dev_handles.gen,
                                         &tid.dev);
#if defined(CONFIG_RSBAC_MAC)
                        rsbac_ta_list_remove(ta_number,
                                         dev_handles.mac,
                                         &tid.dev);
#endif
#if defined(CONFIG_RSBAC_PM)
                        rsbac_ta_list_remove(ta_number,
                                         dev_handles.pm,
                                         &tid.dev);
#endif
#if defined(CONFIG_RSBAC_RC)
                        rsbac_ta_list_remove(ta_number,
                                         dev_handles.rc,
                                         &tid.dev);
#endif
                        break;
                      case D_block_major:
                      case D_char_major:
                        {
                          enum rsbac_dev_type_t orig_devtype=tid.dev.type;

                          if (tid.dev.type==D_block_major)    
                            tid.dev.type=D_block;
                          else
                            tid.dev.type=D_char;
                          rsbac_ta_list_remove(ta_number,
                                           dev_major_handles.gen,
                                           &tid.dev);
#if defined(CONFIG_RSBAC_MAC)
                          rsbac_ta_list_remove(ta_number,
                                           dev_major_handles.mac,
                                           &tid.dev);
#endif
#if defined(CONFIG_RSBAC_PM)
                          rsbac_ta_list_remove(ta_number,
                                           dev_major_handles.pm,
                                           &tid.dev);
#endif
#if defined(CONFIG_RSBAC_RC)
                          rsbac_ta_list_remove(ta_number,
                                           dev_major_handles.rc,
                                           &tid.dev);
#endif
                          tid.dev.type=orig_devtype;
                          break;
                        }
                      default:
                        return -RSBAC_EINVALIDTARGET;
                    }
		}
		break;

	case T_IPC:
		/* rsbac_pr_debug(ds, "Removing ipc ACI\n"); */
#if defined(CONFIG_RSBAC_MAC)
		rsbac_ta_list_remove(ta_number, ipc_handles.mac, &tid.ipc);
#endif
#if defined(CONFIG_RSBAC_PM)
		rsbac_ta_list_remove(ta_number, ipc_handles.pm, &tid.ipc);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number, ipc_handles.rc, &tid.ipc);
#endif
#if defined(CONFIG_RSBAC_JAIL)
		rsbac_ta_list_remove(ta_number,
				     ipc_handles.jail, &tid.ipc);
#endif
		break;

	case T_USER:
		/* rsbac_pr_debug(ds, "Removing user ACI"); */
		rsbac_ta_list_remove(ta_number,
				     user_handles.gen, &tid.user);
#if defined(CONFIG_RSBAC_MAC)
		rsbac_ta_list_remove(ta_number,
				     user_handles.mac, &tid.user);
#endif
#if defined(CONFIG_RSBAC_PM)
		rsbac_ta_list_remove(ta_number,
				     user_handles.pm, &tid.user);
#endif
#if defined(CONFIG_RSBAC_DAZ)
		rsbac_ta_list_remove(ta_number,
				     user_handles.daz, &tid.user);
#endif
#if defined(CONFIG_RSBAC_FF)
		rsbac_ta_list_remove(ta_number,
				     user_handles.ff, &tid.user);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number,
				     user_handles.rc, &tid.user);
#endif
#if defined(CONFIG_RSBAC_AUTH)
		rsbac_ta_list_remove(ta_number,
				     user_handles.auth, &tid.user);
#endif
#if defined(CONFIG_RSBAC_CAP)
		rsbac_ta_list_remove(ta_number,
				     user_handles.cap, &tid.user);
#endif
#if defined(CONFIG_RSBAC_JAIL)
		rsbac_ta_list_remove(ta_number,
				     user_handles.jail, &tid.user);
#endif
#if defined(CONFIG_RSBAC_PAX)
		rsbac_ta_list_remove(ta_number,
				     user_handles.pax, &tid.user);
#endif
#if defined(CONFIG_RSBAC_RES)
		rsbac_ta_list_remove(ta_number,
				     user_handles.res, &tid.user);
#endif
		break;

	case T_PROCESS:
/* too noisy... kicked out.
		rsbac_pr_debug(ds, "Removing process ACI\n");
*/
#if defined(CONFIG_RSBAC_ACL)
		/* process items can also have an acl_p_item -> remove first */
		error = rsbac_acl_remove_acl(ta_number, target, tid);
#endif
		rsbac_ta_list_remove(ta_number,
				     process_handles.gen,
				     &tid.process);
#if defined(CONFIG_RSBAC_MAC)
		/* process items can also have mac_p_trusets -> remove first */
		error = rsbac_mac_remove_p_trusets(tid.process);
		rsbac_ta_list_remove(ta_number,
				     process_handles.mac,
				     &tid.process);
#endif
#if defined(CONFIG_RSBAC_PM)
		rsbac_ta_list_remove(ta_number,
				     process_handles.pm, &tid.process);
#endif
#if defined(CONFIG_RSBAC_DAZ)
		rsbac_ta_list_remove(ta_number,
				     process_handles.daz, &tid.process);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number,
				     process_handles.rc,
				     &tid.process);
#endif
#if defined(CONFIG_RSBAC_AUTH)
		/* process items can also have auth_p_capsets -> remove first */
		error = rsbac_auth_remove_p_capsets(tid.process);
		rsbac_ta_list_remove(ta_number,
				     process_handles.auth, &tid.process);
#endif
#if defined(CONFIG_RSBAC_CAP)
		rsbac_ta_list_remove(ta_number,
				     process_handles.cap, &tid.process);
#endif
#if defined(CONFIG_RSBAC_JAIL)
		rsbac_ta_list_remove(ta_number,
				     process_handles.jail,
				     &tid.process);
#endif
		break;

#ifdef CONFIG_RSBAC_UM
	case T_GROUP:
		/* rsbac_pr_debug(ds, "Removing group ACI\n"); */
#if defined(CONFIG_RSBAC_RC_UM_PROT)
		rsbac_ta_list_remove(ta_number,
				     group_handles.rc, &tid.group);
#endif
		break;
#endif				/* CONFIG_RSBAC_UM */

#ifdef CONFIG_RSBAC_NET_DEV
	case T_NETDEV:
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
		rsbac_ta_list_remove(ta_number,
				     netdev_handles.gen, &tid.netdev);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number,
				     netdev_handles.rc, &tid.netdev);
#endif
		break;
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
	case T_NETTEMP:
/* too noisy... kicked out.
		rsbac_pr_debug(ds, "Removing nettemp ACI\n");
*/
#if defined(CONFIG_RSBAC_IND_NETOBJ_LOG)
		rsbac_ta_list_remove(ta_number,
				     nettemp_handles.gen, &tid.nettemp);
#endif
#if defined(CONFIG_RSBAC_MAC)
		rsbac_ta_list_remove(ta_number,
				     nettemp_handles.mac, &tid.nettemp);
#endif
#if defined(CONFIG_RSBAC_PM)
		rsbac_ta_list_remove(ta_number,
				     nettemp_handles.pm, &tid.nettemp);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number,
				     nettemp_handles.rc, &tid.nettemp);
#endif
#if defined(CONFIG_RSBAC_ACL_NET_OBJ_PROT)
		rsbac_acl_remove_acl(ta_number, T_NETTEMP_NT, tid);
		rsbac_acl_remove_acl(ta_number, T_NETTEMP, tid);
#endif
		break;

	case T_NETOBJ:
/* too noisy... kicked out.
		rsbac_pr_debug(ds, "Removing netobj ACI\n");
*/
#if defined(CONFIG_RSBAC_MAC)
		rsbac_ta_list_remove(ta_number,
				     lnetobj_handles.mac,
				     &tid.netobj.sock_p);
		rsbac_ta_list_remove(ta_number,
				     rnetobj_handles.mac,
				     &tid.netobj.sock_p);
#endif
#if defined(CONFIG_RSBAC_PM)
		rsbac_ta_list_remove(ta_number,
				     lnetobj_handles.pm,
				     &tid.netobj.sock_p);
		rsbac_ta_list_remove(ta_number,
				     rnetobj_handles.pm,
				     &tid.netobj.sock_p);
#endif
#if defined(CONFIG_RSBAC_RC)
		rsbac_ta_list_remove(ta_number,
				     lnetobj_handles.rc,
				     &tid.netobj.sock_p);
		rsbac_ta_list_remove(ta_number,
				     rnetobj_handles.rc,
				     &tid.netobj.sock_p);
#endif
		break;

#endif

	default:
		return -RSBAC_EINVALIDTARGET;
	}
#ifdef CONFIG_RSBAC_XSTATS
	remove_count[target]++;
#endif
	return error;
}
EXPORT_SYMBOL(rsbac_ta_remove_target);

int rsbac_ta_list_all_dev(rsbac_list_ta_number_t ta_number,
			  struct rsbac_dev_desc_t **id_pp)
{
	int count = 0;
	int tmp_count;

	tmp_count = rsbac_ta_list_count(ta_number, dev_handles.gen);
	if (tmp_count > 0)
		count += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_ta_list_count(ta_number, dev_handles.mac);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_ta_list_count(ta_number, dev_handles.pm);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_ta_list_count(ta_number, dev_major_handles.rc);
	if (tmp_count > 0)
		count += tmp_count;
	tmp_count = rsbac_ta_list_count(ta_number, dev_handles.rc);
	if (tmp_count > 0)
		count += tmp_count;
#endif
	if (id_pp) {
		struct rsbac_dev_desc_t *i_id_p = NULL;
		char *pos = NULL;
#if defined(CONFIG_RSBAC_MAC) || defined(CONFIG_RSBAC_PM) || defined(CONFIG_RSBAC_RC)
		u_int i;
#endif

		if (count > 0) {
			int i_count = 0;

			i_count = count + 20;	/* max value to expect */
			*id_pp = rsbac_kmalloc_unlocked(i_count * sizeof(**id_pp));
			if (!*id_pp)
				return -RSBAC_ENOMEM;
			pos = (char *) *id_pp;
			tmp_count = rsbac_ta_list_get_all_desc(ta_number,
							       dev_handles.
							       gen,
							       (void **)
							       &i_id_p);
			if (tmp_count > 0) {
				if (tmp_count > i_count)
					tmp_count = i_count;
				memcpy(pos, i_id_p,
				       tmp_count * sizeof(*i_id_p));
				rsbac_kfree(i_id_p);
				count = tmp_count;
				i_count -= tmp_count;
				pos += tmp_count * sizeof(*i_id_p);
			} else
				count = 0;
#if defined(CONFIG_RSBAC_MAC)
			if (i_count) {
				tmp_count =
				    rsbac_ta_list_get_all_desc(ta_number,
							       dev_handles.
							       mac,
							       (void **)
							       &i_id_p);
				if (tmp_count > 0) {
					if (tmp_count > i_count)
						tmp_count = i_count;
					for (i = 0; i < tmp_count; i++) {
						if (!rsbac_ta_list_exist
						    (ta_number,
						     dev_handles.gen,
						     &i_id_p[i])) {
							memcpy(pos,
							       &i_id_p[i],
							       sizeof
							       (*i_id_p));
							pos +=
							    sizeof
							    (*i_id_p);
							count++;
							i_count--;
						}
					}
					rsbac_kfree(i_id_p);
				}
			}
#endif
#if defined(CONFIG_RSBAC_PM)
			if (i_count) {
				tmp_count =
				    rsbac_ta_list_get_all_desc(ta_number,
							       dev_handles.
							       pm,
							       (void **)
							       &i_id_p);
				if (tmp_count > 0) {
					if (tmp_count > i_count)
						tmp_count = i_count;
					for (i = 0; i < tmp_count; i++) {
						if (!rsbac_ta_list_exist
						    (ta_number,
						     dev_handles.gen,
						     &i_id_p[i]))
#if defined(CONFIG_RSBAC_MAC)
							if (!rsbac_ta_list_exist(ta_number, dev_handles.mac, &i_id_p[i]))
#endif
							{
								memcpy(pos,
								       &i_id_p
								       [i],
								       sizeof
								       (*i_id_p));
								pos +=
								    sizeof
								    (*i_id_p);
								count++;
								i_count--;
							}
					}
					rsbac_kfree(i_id_p);
				}
			}
#endif
#if defined(CONFIG_RSBAC_RC)
			if (i_count) {
				tmp_count =
				    rsbac_ta_list_get_all_desc(ta_number,
							       dev_major_handles.
							       rc,
							       (void **)
							       &i_id_p);
				if (tmp_count > 0) {
					if (tmp_count > i_count)
						tmp_count = i_count;
					for (i = 0; i < tmp_count; i++) {
						i_id_p[i].type +=
						    (D_block_major -
						     D_block);
						memcpy(pos, &i_id_p[i],
						       sizeof(*i_id_p));
						pos += sizeof(*i_id_p);
						count++;
						i_count--;
					}
					rsbac_kfree(i_id_p);
				}
			}
			if (i_count) {
				tmp_count =
				    rsbac_ta_list_get_all_desc(ta_number,
							       dev_handles.
							       rc,
							       (void **)
							       &i_id_p);
				if (tmp_count > 0) {
					if (tmp_count > i_count)
						tmp_count = i_count;
					for (i = 0; i < tmp_count; i++) {
						if (!rsbac_ta_list_exist
						    (ta_number,
						     dev_handles.gen,
						     &i_id_p[i]))
#if defined(CONFIG_RSBAC_MAC)
							if (!rsbac_ta_list_exist(ta_number, dev_handles.mac, &i_id_p[i]))
#endif
#if defined(CONFIG_RSBAC_PM)
								if (!rsbac_ta_list_exist(ta_number, dev_handles.pm, &i_id_p[i]))
#endif
								{
									memcpy
									    (pos,
									     &i_id_p
									     [i],
									     sizeof
									     (*i_id_p));
									pos += sizeof(*i_id_p);
									count++;
									i_count--;
								}
					}
					rsbac_kfree(i_id_p);
				}
			}
#endif
			if (!count)
				rsbac_kfree(*id_pp);
		}
	}
	return count;
}

/* Copy new items, of they do not exist. Adjust list counters. */
static int copy_new_uids(rsbac_list_handle_t list,
			 rsbac_list_ta_number_t ta_number,
			 int *count_p,
			 int *i_count_p, rsbac_uid_t * res_id_p)
{
	rsbac_uid_t *i_id_p = NULL;
	rsbac_boolean_t found;
	int tmp_count;
	int i;
	int j;

	if (!list || !count_p || !i_count_p || !res_id_p)
		return -RSBAC_EINVALIDPOINTER;
	if (!*i_count_p)
		return 0;
/*	rsbac_pr_debug(ds, "list %p, ta_number %u, count %u, "
		       "i_count %u, res_id_p %p, res_id_p[0] %u\n",
		       list, ta_number, *count_p, *i_count_p, res_id_p,
		       res_id_p[0]); */
	tmp_count =
	    rsbac_ta_list_get_all_desc(ta_number, list, (void **) &i_id_p);
	if (tmp_count > 0) {
		if (tmp_count > *i_count_p)
			tmp_count = *i_count_p;
		for (i = 0; i < tmp_count; i++) {
			found = FALSE;
			for (j = 0; j < *count_p; j++) {
				if (res_id_p[j] == i_id_p[i]) {
					found = TRUE;
					break;
				}
			}
			if (found == FALSE) {
				res_id_p[*count_p] = i_id_p[i];
				(*count_p)++;
				(*i_count_p)--;
			}
		}
		rsbac_kfree(i_id_p);
	}
	return 0;
}

int rsbac_ta_list_all_user(rsbac_list_ta_number_t ta_number,
			   rsbac_uid_t ** id_pp)
{
	int count = 0;
	int tmp_count;

	tmp_count = rsbac_ta_list_count(ta_number, user_handles.gen);
	if (tmp_count > 0)
		count += tmp_count;
#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.mac);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.pm);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_DAZ)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.daz);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_FF)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.ff);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.rc);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_AUTH)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.auth);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_CAP)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.cap);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.jail);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PAX)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.pax);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RES)
	tmp_count = rsbac_ta_list_count(ta_number, user_handles.res);
	if (tmp_count > 0)
		count += tmp_count;
#endif
	if (id_pp) {
		if (count > 0) {
			int i_count;
			rsbac_uid_t *i_id_p = NULL;

			i_count = count + 20;	/* max value to expect */
			*id_pp = rsbac_kmalloc_unlocked(i_count * sizeof(**id_pp));
			if (!*id_pp)
				return -RSBAC_ENOMEM;
			tmp_count = rsbac_ta_list_get_all_desc(ta_number,
							       user_handles.
							       gen,
							       (void **)
							       &i_id_p);
			if (tmp_count > 0) {
				if (tmp_count > i_count)
					tmp_count = i_count;
				memcpy(*id_pp, i_id_p,
				       tmp_count * sizeof(*i_id_p));
				rsbac_kfree(i_id_p);
				count = tmp_count;
				i_count -= tmp_count;
			} else
				count = 0;
#if defined(CONFIG_RSBAC_MAC)
			copy_new_uids(user_handles.mac, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_PM)
			copy_new_uids(user_handles.pm, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_DAZ)
			copy_new_uids(user_handles.daz, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_FF)
			copy_new_uids(user_handles.ff, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_RC)
			copy_new_uids(user_handles.rc, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_AUTH)
			copy_new_uids(user_handles.auth, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_CAP)
			copy_new_uids(user_handles.cap, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_JAIL)
			copy_new_uids(user_handles.jail, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_PAX)
			copy_new_uids(user_handles.pax, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_RES)
			copy_new_uids(user_handles.res, ta_number, &count,
				      &i_count, *id_pp);
#endif
			if (!count)
				rsbac_kfree(*id_pp);
		}
	}
	return count;
}

/* Copy new items, of they do not exist. Adjust list counters. */
static int copy_new_ipcs(rsbac_list_handle_t list,
			 rsbac_list_ta_number_t ta_number,
			 int *count_p,
			 int *i_count_p, struct rsbac_ipc_t * res_id_p)
{
	struct rsbac_ipc_t *i_id_p = NULL;
	rsbac_boolean_t found;
	int tmp_count;
	int i;
	int j;

	if (!list || !count_p || !i_count_p || !res_id_p)
		return -RSBAC_EINVALIDPOINTER;
	if (!*i_count_p)
		return 0;
/*	rsbac_pr_debug(ds, "list %p, ta_number %u, count %u, "
		      "i_count %u, res_id_p %p, res_id_p[0] %u\n",
		       list, ta_number, *count_p, *i_count_p, res_id_p,
		       res_id_p[0]); */
	tmp_count =
	    rsbac_ta_list_get_all_desc(ta_number, list, (void **) &i_id_p);
	if (tmp_count > 0) {
		if (tmp_count > *i_count_p)
			tmp_count = *i_count_p;
		for (i = 0; i < tmp_count; i++) {
			found = FALSE;
			for (j = 0; j < *count_p; j++) {
				if (!ipc_compare(&res_id_p[j], &i_id_p[i])) {
					found = TRUE;
					break;
				}
			}
			if (found == FALSE) {
				res_id_p[*count_p] = i_id_p[i];
				(*count_p)++;
				(*i_count_p)--;
			}
		}
		rsbac_kfree(i_id_p);
	}
	return 0;
}

int rsbac_ta_list_all_ipc(rsbac_list_ta_number_t ta_number,
			   struct rsbac_ipc_t ** id_pp)
{
	int count = 0;
	int tmp_count;

#if defined(CONFIG_RSBAC_MAC)
	tmp_count = rsbac_ta_list_count(ta_number, ipc_handles.mac);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_PM)
	tmp_count = rsbac_ta_list_count(ta_number, ipc_handles.pm);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_ta_list_count(ta_number, ipc_handles.rc);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_JAIL)
	tmp_count = rsbac_ta_list_count(ta_number, ipc_handles.jail);
	if (tmp_count > 0)
		count += tmp_count;
#endif
	if (id_pp) {
		if (count > 0) {
			int i_count;

			i_count = count + 20;	/* max value to expect */
			*id_pp = rsbac_kmalloc_unlocked(i_count * sizeof(**id_pp));
			if (!*id_pp)
				return -RSBAC_ENOMEM;
			count = 0;
#if defined(CONFIG_RSBAC_MAC)
			copy_new_ipcs(ipc_handles.mac, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_PM)
			copy_new_ipcs(ipc_handles.pm, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_RC)
			copy_new_ipcs(ipc_handles.rc, ta_number, &count,
				      &i_count, *id_pp);
#endif
#if defined(CONFIG_RSBAC_JAIL)
			copy_new_ipcs(ipc_handles.jail, ta_number, &count,
				      &i_count, *id_pp);
#endif
			if (!count)
				rsbac_kfree(*id_pp);
		}
	}
	return count;
}

int rsbac_ta_list_all_group(rsbac_list_ta_number_t ta_number,
			    rsbac_gid_t ** id_pp)
{
#if defined(CONFIG_RSBAC_RC_UM_PROT)
	int count = 0;
	int tmp_count;

	tmp_count = rsbac_ta_list_count(ta_number, group_handles.rc);
	if (tmp_count > 0)
		count += tmp_count;
	if (id_pp) {
		if (count > 0) {
			int i_count;
			rsbac_gid_t *i_id_p = NULL;

			i_count = count + 20;	/* max value to expect */
			*id_pp = rsbac_kmalloc_unlocked(i_count * sizeof(**id_pp));
			if (!*id_pp)
				return -RSBAC_ENOMEM;
			tmp_count = rsbac_ta_list_get_all_desc(ta_number,
							       group_handles.
							       rc,
							       (void **)
							       &i_id_p);
			if (tmp_count > 0) {
				if (tmp_count > i_count)
					tmp_count = i_count;
				memcpy(*id_pp, i_id_p,
				       tmp_count * sizeof(*i_id_p));
				rsbac_kfree(i_id_p);
				count = tmp_count;
				i_count -= tmp_count;
			} else
				count = 0;
			if (!count)
				rsbac_kfree(*id_pp);
		}
	}
	return count;
#else
	return 0;
#endif
}


#ifdef CONFIG_RSBAC_NET_DEV
int rsbac_ta_net_list_all_netdev(rsbac_list_ta_number_t ta_number,
				 rsbac_netdev_id_t ** id_pp)
{
	int count = 0;
	int tmp_count;

#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
	tmp_count = rsbac_ta_list_count(ta_number, netdev_handles.gen);
	if (tmp_count > 0)
		count += tmp_count;
#endif
#if defined(CONFIG_RSBAC_RC)
	tmp_count = rsbac_ta_list_count(ta_number, netdev_handles.rc);
	if (tmp_count > 0)
		count += tmp_count;
#endif
	if (id_pp) {
		rsbac_netdev_id_t *i_id_p = NULL;
		char *pos = NULL;
#if defined(CONFIG_RSBAC_RC)
		u_int i;
#endif

		if (count > 0) {
			int i_count = 0;

			i_count = count + 20;	/* max value to expect */
			*id_pp = rsbac_kmalloc_unlocked(i_count * sizeof(**id_pp));
			if (!*id_pp)
				return -RSBAC_ENOMEM;
			pos = (char *) *id_pp;
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
			tmp_count = rsbac_ta_list_get_all_desc(ta_number,
							       netdev_handles.
							       gen,
							       (void **)
							       &i_id_p);
			if (tmp_count > 0) {
				if (tmp_count > i_count)
					tmp_count = i_count;
				memcpy(pos, i_id_p,
				       tmp_count * sizeof(*i_id_p));
				rsbac_kfree(i_id_p);
				count = tmp_count;
				i_count -= tmp_count;
				pos += tmp_count * sizeof(*i_id_p);
			} else
				count = 0;
#endif
#if defined(CONFIG_RSBAC_RC)
			if (i_count) {
				tmp_count =
				    rsbac_ta_list_get_all_desc(ta_number,
							       netdev_handles.
							       rc,
							       (void **)
							       &i_id_p);
				if (tmp_count > 0) {
					if (tmp_count > i_count)
						tmp_count = i_count;
					for (i = 0; i < tmp_count; i++) {
#if defined(CONFIG_RSBAC_IND_NETDEV_LOG)
						if (!rsbac_ta_list_exist
						    (ta_number,
						     netdev_handles.gen,
						     &i_id_p[i]))
#endif
						{
							memcpy(pos,
							       &i_id_p[i],
							       sizeof
							       (*i_id_p));
							pos +=
							    sizeof
							    (*i_id_p);
							count++;
							i_count--;
						}
					}
					rsbac_kfree(i_id_p);
				}
			}
#endif
			if (!count)
				rsbac_kfree(*id_pp);
		}
	}
	return count;
}
#endif

#ifdef CONFIG_RSBAC_NET_OBJ
/* Get a template id from a net description */
int rsbac_net_get_id(rsbac_list_ta_number_t ta_number,
		     struct rsbac_net_description_t *desc_p,
		     rsbac_net_temp_id_t * id_p)
{
	if (!rsbac_initialized)
		return -RSBAC_ENOTINITIALIZED;
	if (!id_p || !desc_p)
		return -RSBAC_EINVALIDPOINTER;
	if (rsbac_ta_list_get_desc(ta_number,
				   net_temp_handle,
				   id_p, desc_p, rsbac_net_compare_data)
	    )
		*id_p = RSBAC_NET_UNKNOWN;
	return 0;
}

/* get the template ids for a netobj */
/* set *_temp_p to NULL, if you do not need it */
int rsbac_ta_net_lookup_templates(rsbac_list_ta_number_t ta_number,
				  struct rsbac_net_obj_desc_t *netobj_p,
				  rsbac_net_temp_id_t * local_temp_p,
				  rsbac_net_temp_id_t * remote_temp_p)
{
	struct rsbac_net_description_t *rsbac_net_desc_p;
	int err = 0;
	struct net_device *dev;

	if (!netobj_p || !netobj_p->sock_p || !netobj_p->sock_p->sk
	    || !netobj_p->sock_p->ops)
		return -RSBAC_EINVALIDPOINTER;
	if (!local_temp_p && !remote_temp_p)
		return -RSBAC_EINVALIDVALUE;

	rsbac_net_desc_p = rsbac_kmalloc_unlocked(sizeof(*rsbac_net_desc_p));
	if (!rsbac_net_desc_p)
		return -RSBAC_ENOMEM;

	rsbac_net_desc_p->address_family = netobj_p->sock_p->ops->family;
	rsbac_net_desc_p->type = netobj_p->sock_p->type;
	rsbac_net_desc_p->protocol = netobj_p->sock_p->sk->sk_protocol;
	if (netobj_p->sock_p->sk->sk_bound_dev_if) {
		dev = dev_get_by_index(&init_net, netobj_p->sock_p->sk->
				     sk_bound_dev_if);
		if (dev) {
			strcpy(rsbac_net_desc_p->netdev, dev->name);
			dev_put(dev);
		} else
			rsbac_net_desc_p->netdev[0] = RSBAC_NET_UNKNOWN;
	} else
		rsbac_net_desc_p->netdev[0] = RSBAC_NET_UNKNOWN;
	if (local_temp_p) {
		switch (rsbac_net_desc_p->address_family) {
		case AF_INET:
			if (netobj_p->local_addr) {
				struct sockaddr_in *addr =
				    netobj_p->local_addr;

				rsbac_net_desc_p->address =
				    &addr->sin_addr.s_addr;
				rsbac_net_desc_p->address_len =
				    sizeof(__u32);
				rsbac_net_desc_p->port =
				    ntohs(addr->sin_port);
			} else {
				rsbac_net_desc_p->address =
				    &inet_sk(netobj_p->sock_p->sk)->
				    inet_rcv_saddr;
				rsbac_net_desc_p->address_len =
				    sizeof(__u32);
				rsbac_net_desc_p->port =
				    inet_sk(netobj_p->sock_p->sk)->inet_num;
			}
			dev = ip_dev_find(&init_net, *(__u32 *) rsbac_net_desc_p->address);

			if (dev) {
				strcpy(rsbac_net_desc_p->netdev,
				       dev->name);
				dev_put(dev);
			}
			break;
		case AF_UNIX:
			rsbac_printk(KERN_WARNING "rsbac_ta_net_lookup_templates(): unsupported family AF_UNIX, should be target UNIXSOCK or IPC-anonunix\n");
			BUG();
			return -RSBAC_EINVALIDTARGET;

		default:
			rsbac_net_desc_p->address = NULL;
			rsbac_net_desc_p->port = RSBAC_NET_UNKNOWN;
		}
		if ((err = rsbac_net_get_id(ta_number, rsbac_net_desc_p,
			local_temp_p))) {
			*local_temp_p = 0;
			rsbac_printk(KERN_WARNING "rsbac_net_lookup_templates(): rsbac_net_get_id for local returned error %u\n",
				     err);
		}
		if (rsbac_net_desc_p->address_family == AF_INET)
			rsbac_pr_debug(ds_net,
				       "user %u temp id for local is %u\n",
				       current_uid(), *local_temp_p);
	}
	if (remote_temp_p) {
		switch (rsbac_net_desc_p->address_family) {
		case AF_INET:
			if (netobj_p->remote_addr) {
				struct sockaddr_in *addr =
				    netobj_p->remote_addr;

				rsbac_net_desc_p->address =
				    &addr->sin_addr.s_addr;
				rsbac_net_desc_p->address_len =
				    sizeof(__u32);
				rsbac_net_desc_p->port =
				    ntohs(addr->sin_port);
			} else {
				rsbac_net_desc_p->address =
				    &inet_sk(netobj_p->sock_p->sk)->inet_daddr;
				rsbac_net_desc_p->address_len =
				    sizeof(__u32);
				rsbac_net_desc_p->port =
				    ntohs(inet_sk(netobj_p->sock_p->sk)->
					  inet_dport);
			}
			dev = ip_dev_find(&init_net, *(__u32 *) rsbac_net_desc_p->address);

			if (dev) {
				strcpy(rsbac_net_desc_p->netdev,
				       dev->name);
				dev_put(dev);
			}
			break;
		case AF_UNIX:
			rsbac_printk(KERN_WARNING "rsbac_ta_net_lookup_templates(): unsupported family AF_UNIX, should be target UNIXSOCK or IPC-anonunix\n");
			return -RSBAC_EINVALIDTARGET;

		default:
			rsbac_net_desc_p->address = NULL;
			rsbac_net_desc_p->address_len = 0;
			rsbac_net_desc_p->port = RSBAC_NET_UNKNOWN;
		}
		if ((err =
		     rsbac_net_get_id(ta_number, rsbac_net_desc_p,
				      remote_temp_p))) {
			*remote_temp_p = 0;
			rsbac_printk(KERN_WARNING "rsbac_net_lookup_templates(): rsbac_net_get_id for remote returned error %u\n",
				     err);
		}
		if (rsbac_net_desc_p->address_family == AF_INET)
			rsbac_pr_debug(ds_net,
				       "user %u temp id for remote is %u\n",
				       current_uid(), *remote_temp_p);
	}
	rsbac_kfree(rsbac_net_desc_p);
	return 0;
}

void rsbac_net_obj_cleanup(rsbac_net_obj_id_t netobj)
{
	union rsbac_target_id_t tid;

	tid.netobj.sock_p = netobj;
	rsbac_remove_target(T_NETOBJ, tid);
}

int rsbac_ta_net_template_exists(rsbac_list_ta_number_t ta_number,
	rsbac_net_temp_id_t id)
{
  return rsbac_ta_list_exist(ta_number, net_temp_handle, &id);
}

int rsbac_ta_net_template(rsbac_list_ta_number_t ta_number,
			  enum rsbac_net_temp_syscall_t call,
			  rsbac_net_temp_id_t id,
			  union rsbac_net_temp_syscall_data_t *data_p)
{
	struct rsbac_net_temp_data_t int_data;
	int err;

	memset(&int_data, 0, sizeof(int_data));
	int_data.address_family = AF_MAX;
	int_data.type = RSBAC_NET_ANY;
	int_data.protocol = RSBAC_NET_ANY;
	strcpy(int_data.name, "DEFAULT");

	switch (call) {
	case NTS_new_template:
	case NTS_check_id:
		break;
	case NTS_copy_template:
		err = rsbac_ta_list_get_data_ttl(ta_number,
						 net_temp_handle,
						 NULL,
						 &data_p->id, &int_data);
		if (err)
			return err;
		break;
	default:
		err = rsbac_ta_list_get_data_ttl(ta_number,
						 net_temp_handle,
						 NULL, &id, &int_data);
		if (err)
			return err;
	}
	/* get data values from user space */
	switch (call) {
	case NTS_set_address:
		if(int_data.address_family == AF_INET) {
			int i;

			memcpy(&int_data.address.inet, &data_p->address.inet,
				sizeof(int_data.address.inet));
			if(int_data.address.inet.nr_addr > RSBAC_NET_NR_INET_ADDR)
				return -RSBAC_EINVALIDVALUE;
			for(i=0; i<int_data.address.inet.nr_addr; i++)
				if(int_data.address.inet.valid_bits[i] > 32)
					return -RSBAC_EINVALIDVALUE;
		} else {
			memcpy(&int_data.address.other, &data_p->address.other,
				sizeof(int_data.address.other));
		}
		return rsbac_ta_list_add_ttl(ta_number, net_temp_handle, 0,
					     &id, &int_data);
	case NTS_set_address_family:
		if(int_data.address_family != data_p->address_family) {
			int_data.address_family = data_p->address_family;
			memset(&int_data.address, 0, sizeof(int_data.address));
		}
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_set_type:
		int_data.type = data_p->type;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_set_protocol:
		int_data.protocol = data_p->protocol;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_set_netdev:
		strncpy(int_data.netdev, data_p->netdev, RSBAC_IFNAMSIZ);
		int_data.netdev[RSBAC_IFNAMSIZ] = 0;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_set_ports:
		memcpy(&int_data.ports, &data_p->ports,
			sizeof(int_data.ports));
		if(int_data.ports.nr_ports > RSBAC_NET_NR_PORTS)
			return -RSBAC_EINVALIDVALUE;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_set_name:
		strncpy(int_data.name, data_p->name,
			RSBAC_NET_TEMP_NAMELEN - 1);
		int_data.name[RSBAC_NET_TEMP_NAMELEN - 1] = 0;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_new_template:
		if (rsbac_ta_list_exist(ta_number, net_temp_handle, &id))
			return -RSBAC_EEXISTS;
		strncpy(int_data.name, data_p->name,
			RSBAC_NET_TEMP_NAMELEN - 1);
		int_data.name[RSBAC_NET_TEMP_NAMELEN - 1] = 0;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_copy_template:
		if (rsbac_ta_list_exist(ta_number, net_temp_handle, &id))
			return -RSBAC_EEXISTS;
		return rsbac_ta_list_add_ttl(ta_number,
					     net_temp_handle,
					     0, &id, &int_data);
	case NTS_delete_template:
		return rsbac_ta_list_remove(ta_number, net_temp_handle,
					    &id);
	case NTS_check_id:
		if (rsbac_ta_list_exist(ta_number, net_temp_handle, &id)) {
			data_p->id = id;
			return 0;
		} else
			return -RSBAC_ENOTFOUND;
	case NTS_get_address:
		memcpy(&data_p->address, &int_data.address,
		       sizeof(int_data.address));
		return 0;
	case NTS_get_address_family:
		data_p->address_family = int_data.address_family;
		return 0;
	case NTS_get_type:
		data_p->type = int_data.type;
		return 0;
	case NTS_get_protocol:
		data_p->protocol = int_data.protocol;
		return 0;
	case NTS_get_netdev:
		strncpy(data_p->netdev, int_data.netdev, RSBAC_IFNAMSIZ);
		return 0;
	case NTS_get_ports:
		memcpy(&data_p->ports, &int_data.ports,
		       sizeof(int_data.ports));
		return 0;
	case NTS_get_name:
		strcpy(data_p->name, int_data.name);
		return 0;

	default:
		return -RSBAC_EINVALIDREQUEST;
	}
}

int rsbac_ta_net_list_all_template(rsbac_list_ta_number_t ta_number,
				   rsbac_net_temp_id_t ** id_pp)
{
	if (id_pp)
		return rsbac_ta_list_get_all_desc(ta_number,
						  net_temp_handle,
						  (void **) id_pp);
	else
		return rsbac_ta_list_count(ta_number, net_temp_handle);
}

int rsbac_ta_net_template_exist(rsbac_list_ta_number_t ta_number,
				rsbac_net_temp_id_t temp)
{
	return rsbac_ta_list_exist(ta_number, net_temp_handle, &temp);
}

int rsbac_net_remote_request(enum rsbac_adf_request_t request)
{
	switch (request) {
	case R_SEND:
	case R_RECEIVE:
	case R_READ:
	case R_WRITE:
	case R_ACCEPT:
	case R_CONNECT:
		return TRUE;

	default:
		return FALSE;
	}
}

#endif				/* NET_OBJ */

#if defined(CONFIG_RSBAC_DAZ)
EXPORT_SYMBOL(rsbac_daz_get_ttl);
/* Get ttl for new cache items in seconds */
rsbac_time_t rsbac_daz_get_ttl(void)
{
#if defined(CONFIG_RSBAC_DAZ_CACHE)
	return rsbac_daz_ttl;
#else
	return 0;
#endif
}

EXPORT_SYMBOL(rsbac_daz_set_ttl);
void rsbac_daz_set_ttl(rsbac_time_t ttl)
{
#if defined(CONFIG_RSBAC_DAZ_CACHE)
	if (ttl) {
		if (ttl > RSBAC_LIST_MAX_AGE_LIMIT)
			ttl = RSBAC_LIST_MAX_AGE_LIMIT;
		rsbac_daz_ttl = ttl;
	}
#endif
}

EXPORT_SYMBOL(rsbac_daz_flush_cache);
int rsbac_daz_flush_cache(void)
{
#if defined(CONFIG_RSBAC_DAZ_CACHE)
	struct rsbac_device_list_item_t *device_p;
	u_int i;
	int srcu_idx;

	for (i = 0; i < RSBAC_NR_DEVICE_LISTS; i++) {
		srcu_idx = srcu_read_lock(&device_list_srcu[i]);
		device_p = rcu_dereference(device_head_p[i])->head;
		while (device_p) {
			rsbac_list_remove_all(device_p->handles.dazs);
			device_p = device_p->next;
		}
		srcu_read_unlock(&device_list_srcu[i], srcu_idx);
	}
#endif
	return 0;
}
#endif

#if defined(CONFIG_RSBAC_JAIL)
static int rsbac_jail_exists_compare(void * data1, void * data2)
{
  struct rsbac_jail_process_aci_t * aci_p = data1;

  return memcmp(&aci_p->id, data2, sizeof(rsbac_jail_id_t));
}

rsbac_boolean_t rsbac_jail_exists(rsbac_jail_id_t jail_id)
{
	rsbac_pid_t pid;

	if(!rsbac_ta_list_get_desc(0,
				process_handles.jail,
				&pid,
				&jail_id,
				rsbac_jail_exists_compare))
		return TRUE;
	else
		return FALSE;
}
#endif

void rsbac_flags_set(unsigned long int rsbac_flags)
{
}
