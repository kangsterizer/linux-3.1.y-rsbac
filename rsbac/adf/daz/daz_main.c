/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - Dazuko Malware Scan              */
/* File: rsbac/adf/daz/daz_main.c                    */
/*                                                   */
/* Author and (c) 1999-2011: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Copyright (c) 2004 H+BEDV Datentechnik GmbH       */
/* Written by John Ogness <jogness@antivir.de>       */
/*                                                   */
/* Last modified: 12/Jul/2011                        */
/*************************************************** */

/* Dazuko RSBAC. 
   Allow RSBAC Linux file access control for 3rd-party applications.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
   */

#include "dazuko_rsbac.h"
#include "dazuko_xp.h"
#include "dazukoio.h"

#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/random.h>

#include <linux/vermagic.h>

#include <linux/string.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <asm/uaccess.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/adf.h>
#include <rsbac/adf_main.h>
#include <rsbac/debug.h>
#include <rsbac/error.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/net_getname.h>
#include <rsbac/rkmem.h>
#include <rsbac/proc_fs.h>

/************************************************* */
/*           Global Variables                      */
/************************************************* */

#include <linux/device.h>

#define DAZ_MAX_FILENAME PATH_MAX

ssize_t linux_dazuko_device_read(struct file *file, char *buffer, size_t length, loff_t *pos);
ssize_t linux_dazuko_device_write(struct file *file, const char *buffer, size_t length, loff_t *pos);
long linux_dazuko_device_ioctl(struct file *file, unsigned int cmd, unsigned long param);
int linux_dazuko_device_open(struct inode *inode, struct file *file);
int linux_dazuko_device_release(struct inode *inode, struct file *file);

extern struct xp_atomic active;

static int			dev_major = -1;

static struct file_operations	fops = {
	read: linux_dazuko_device_read,		/* read */
	write: linux_dazuko_device_write,	/* write */
	unlocked_ioctl: linux_dazuko_device_ioctl,	/* ioctl */
	open: linux_dazuko_device_open,		/* open */
	release: linux_dazuko_device_release,	/* release */
};

static struct class *dazuko_class = NULL;

static struct kmem_cache * dazuko_file_slab = NULL;
static struct kmem_cache * xp_file_slab = NULL;
static struct kmem_cache * xp_daemon_slab = NULL;
static struct kmem_cache * dazuko_filename_slab = NULL;

/************************************************* */
/*          Internal Help functions                */
/************************************************* */

#if defined(CONFIG_RSBAC_DAZ_CACHE)
static int daz_reset_scanned(struct rsbac_fs_file_t file)
{
	union rsbac_attribute_value_t i_attr_val1;
	union rsbac_target_id_t       i_tid;

	/* reset scanned status for file */
	rsbac_pr_debug(adf_daz, "pid %u (%.15s), resetting scanned status!\n",
				       current->pid, current->comm);
	i_tid.file=file;
	i_attr_val1.daz_scanned = DAZ_unscanned;
	if(rsbac_set_attr(SW_DAZ,
				T_FILE,
				i_tid,
				A_daz_scanned,
				i_attr_val1))
	{
		rsbac_printk(KERN_WARNING "daz_reset_scanned(): rsbac_set_attr() for daz_scanned on device %02u:%02u inode %u returned error!\n",
			MAJOR(file.device), MINOR(file.device), file.inode);
		return -RSBAC_EWRITEFAILED;
	}
	if (rsbac_get_attr(SW_DAZ,
		T_FILE,
		i_tid,
		A_daz_scanner,
		&i_attr_val1,
		TRUE)) {
		rsbac_printk(KERN_WARNING
			"daz_reset_scanned(): rsbac_get_attr() for daz_scanner returned error!\n");
		return -RSBAC_EREADFAILED;
	}
	if (i_attr_val1.daz_scanner) {
		/* reset scanner flag for file */
		i_attr_val1.daz_scanner = FALSE;
		if(rsbac_set_attr(SW_DAZ,
					T_FILE,
					i_tid,
					A_daz_scanner,
					i_attr_val1))
		{
			rsbac_printk(KERN_WARNING "daz_reset_scanned(): rsbac_set_attr() for daz_scanner on device %02u:%02u inode %u returned error!\n",
				MAJOR(file.device), MINOR(file.device), file.inode);
			return -RSBAC_EWRITEFAILED;
		}
	}
	return 0;
}
#else
static inline int daz_reset_scanned(struct rsbac_fs_file_t file)
{
	return 0;
}
#endif


/* mutex */

inline int xp_init_mutex(struct xp_mutex *mutex)
{
#ifdef init_MUTEX
	init_MUTEX(&(mutex->mutex));
#else
	sema_init(&(mutex->mutex), 1);
#endif

	return 0;
}

inline int xp_down(struct xp_mutex *mutex)
{
	down(&(mutex->mutex));
	return 0;
}

inline int xp_up(struct xp_mutex *mutex)
{
	up(&(mutex->mutex));
	return 0;
}

inline int xp_destroy_mutex(struct xp_mutex *mutex)
{
	return 0;
}


/* read-write lock */

inline int xp_init_rwlock(struct xp_rwlock *rwlock)
{
	rwlock_init(&(rwlock->rwlock));
	return 0;
}

inline int xp_write_lock(struct xp_rwlock *rwlock)
{
	write_lock(&(rwlock->rwlock));
	return 0;
}

inline int xp_write_unlock(struct xp_rwlock *rwlock)
{
	write_unlock(&(rwlock->rwlock));
	return 0;
}

inline int xp_read_lock(struct xp_rwlock *rlock)
{
	read_lock(&(rlock->rwlock));
	return 0;
}

inline int xp_read_unlock(struct xp_rwlock *rlock)
{
	read_unlock(&(rlock->rwlock));
	return 0;
}

inline int xp_destroy_rwlock(struct xp_rwlock *rwlock)
{
	return 0;
}


/* wait-notify queue */

inline int xp_init_queue(struct xp_queue *queue)
{
	init_waitqueue_head(&(queue->queue));
	return 0;
}

inline int xp_wait_until_condition(struct xp_queue *queue, int (*cfunction)(void *), void *cparam, int allow_interrupt)
{
	/* wait until cfunction(cparam) != 0 (condition is true) */

	if (allow_interrupt)
	{
		return wait_event_interruptible(queue->queue, cfunction(cparam) != 0);
	}
	else
	{
		wait_event(queue->queue, cfunction(cparam) != 0);
	}

	return 0;
}

inline int xp_notify(struct xp_queue *queue)
{
	wake_up(&(queue->queue));
	return 0;
}

inline int xp_destroy_queue(struct xp_queue *queue)
{
	return 0;
}


/* memory */

inline int xp_copyin(const void *user_src, void *kernel_dest, size_t size)
{
	return copy_from_user(kernel_dest, user_src, size);
}

inline int xp_copyout(const void *kernel_src, void *user_dest, size_t size)
{
	return copy_to_user(user_dest, kernel_src, size);
}

inline int xp_verify_user_writable(const void *user_ptr, size_t size)
{
	return 0;
}

inline int xp_verify_user_readable(const void *user_ptr, size_t size)
{
	return 0;
}


/* path attribute */

inline int xp_is_absolute_path(const char *path)
{
	return (path[0] == '/');
}


/* atomic */

inline int xp_atomic_set(struct xp_atomic *atomic, int value)
{
	atomic_set(&(atomic->atomic), value);
	return 0;
}

inline int xp_atomic_inc(struct xp_atomic *atomic)
{
	atomic_inc(&(atomic->atomic));
	return 0;
}

inline int xp_atomic_dec(struct xp_atomic *atomic)
{
	atomic_dec(&(atomic->atomic));
	return 0;
}

inline int xp_atomic_read(struct xp_atomic *atomic)
{
	return atomic_read(&(atomic->atomic));
}


/* file descriptor */

inline int xp_copy_file(struct xp_file *dest, struct xp_file *src)
{
	return 0;
}

inline int xp_compare_file(struct xp_file *file1, struct xp_file *file2)
{
	return 0;
}

inline int xp_fill_file_struct(struct dazuko_file_struct *dfs)
{
	/* make sure we have access to everything */
	if (dfs == NULL)
		return -1;

	if (dfs->extra_data == NULL)
		return -1;

	if (dfs->extra_data->dentry == NULL)
		return -1;

	if (dfs->extra_data->dentry->d_inode == NULL)
		return -1;

	/* ok, we have everything we need */

	dfs->extra_data->full_filename = rsbac_smalloc_unlocked(dazuko_filename_slab);
	if (dfs->extra_data->full_filename == NULL)
		return -1;
	rsbac_lookup_full_path(dfs->extra_data->dentry, dfs->extra_data->full_filename, DAZ_MAX_FILENAME, 0);

	rsbac_pr_debug(adf_daz, "pid %u (%.15s), file is %s!\n",
				       current->pid, current->comm,
				       dfs->extra_data->full_filename);

	/* find the actual value of the length */
	dfs->extra_data->full_filename_length = strlen(dfs->extra_data->full_filename);

	/* reference copy of full path */
	dfs->filename = dfs->extra_data->full_filename;
	dfs->filename_length = dfs->extra_data->full_filename_length;

	dfs->file_p.size = dfs->extra_data->dentry->d_inode->i_size;
	dfs->file_p.set_size = 1;
	dfs->file_p.uid = dfs->extra_data->dentry->d_inode->i_uid;
	dfs->file_p.set_uid = 1;
	dfs->file_p.gid = dfs->extra_data->dentry->d_inode->i_gid;
	dfs->file_p.set_gid = 1;
	dfs->file_p.mode = dfs->extra_data->dentry->d_inode->i_mode;
	dfs->file_p.set_mode = 1;
	dfs->file_p.device_type = dfs->extra_data->dentry->d_inode->i_rdev;
	dfs->file_p.set_device_type = 1;

	return 0;
}

static int dazuko_file_struct_cleanup(struct dazuko_file_struct **dfs)
{
	if (dfs == NULL)
		return 0;

	if (*dfs == NULL)
		return 0;

	if ((*dfs)->extra_data != NULL)
	{
		if ((*dfs)->extra_data->full_filename)
			rsbac_sfree(dazuko_filename_slab, (*dfs)->extra_data->full_filename);

		rsbac_sfree(xp_file_slab, (*dfs)->extra_data);
	}

	rsbac_sfree(dazuko_file_slab, *dfs);

	*dfs = NULL;

	return 0;
}


/* daemon id */

int xp_id_compare(struct xp_daemon_id *id1, struct xp_daemon_id *id2)
{
	if (id1 == NULL || id2 == NULL)
		return -1;

	/* if file's are available and they match,
	 * then we say that the id's match */
	if (id1->file != NULL && id1->file == id2->file)
		return 0;

	if (id1->pid == id2->pid)
		return 0;

	return 1;
}

int xp_id_free(struct xp_daemon_id *id)
{
	rsbac_sfree(xp_daemon_slab, id);
	return 0;
}

struct xp_daemon_id* xp_id_copy(struct xp_daemon_id *id)
{
	struct xp_daemon_id	*ptr;

	if (id == NULL)
		return NULL;

	ptr = rsbac_smalloc(xp_daemon_slab);

	if (ptr != NULL)
	{
		ptr->pid = id->pid;
		ptr->file = id->file;
	}
	return ptr;
}


/* system hook */

inline int xp_sys_hook()
{
	int wanted_major = CONFIG_RSBAC_DAZ_DEV_MAJOR;

	/* Called from insmod when inserting the module. */
	/* register the dazuko device */
	if((wanted_major > 0) && (wanted_major <= 254)) {
		dev_major = register_chrdev(wanted_major, DEVICE_NAME, &fops);
		if (dev_major < 0) {
			rsbac_printk(KERN_WARNING "dazuko: unable to register major chrdev %u, err=%d\n",
				wanted_major, dev_major);
			return dev_major;
		}
		dev_major = wanted_major;
		dazuko_class = class_create(THIS_MODULE, "dazuko");
		device_create(dazuko_class, NULL,
				MKDEV(wanted_major, 0),
				NULL, "dazuko");
	} else {
		dev_major = register_chrdev(0, DEVICE_NAME, &fops);
		if (dev_major < 0) {
			rsbac_printk(KERN_WARNING "dazuko: unable to register any major chrdev, err=%d\n",
				dev_major);
			return dev_major;
		}
		dazuko_class = class_create(THIS_MODULE, "dazuko");
		device_create(dazuko_class, NULL,
				MKDEV(dev_major, 0),
				NULL, "dazuko");
	}
	return 0;
}

inline int xp_sys_unhook()
{
	/* Called by rmmod when removing the module. */
	unregister_chrdev(dev_major, DEVICE_NAME);
	device_destroy(dazuko_class, MKDEV(dev_major, CONFIG_RSBAC_DAZ_DEV_MAJOR));
	class_destroy(dazuko_class);

	return 0;
}


/* ioctl's */

int linux_dazuko_device_open(struct inode *inode, struct file *file)
{
	DPRINT(("dazuko: linux_dazuko_device_open() [%d]\n", current->pid));

	return 0;
}

ssize_t linux_dazuko_device_read(struct file *file, char *buffer, size_t length, loff_t *pos)
{
	/* Reading from the dazuko device simply
	 * returns the device number. This is to
	 * help out the daemon. */

	char	tmp[20];
	size_t	dev_major_len;

	DPRINT(("dazuko: linux_dazuko_device_read() [%d]\n", current->pid));

	/* only one read is allowed */
	if (*pos != 0)
		return 0;

	if (dev_major < 0)
		return -ENODEV;

	/* print dev_major to a string
	 * and get length (with terminator) */
	dazuko_bzero(tmp, sizeof(tmp));

	dev_major_len = dazuko_snprintf(tmp, sizeof(tmp), "%d", dev_major) + 1;

	if (tmp[sizeof(tmp)-1] != 0)
	{
		rsbac_printk(KERN_WARNING "dazuko: failing device_read, device number overflow for dameon %d (dev_major=%d)\n", current->pid, dev_major);
		return -EFAULT;
	}

	if (length < dev_major_len)
		return -EINVAL;

	/* copy dev_major string to userspace */
	if (xp_copyout(tmp, buffer, dev_major_len) != 0)
		return -EFAULT;

	*pos = dev_major_len;

	return dev_major_len;
}

ssize_t linux_dazuko_device_write(struct file *file, const char *buffer, size_t length, loff_t *pos)
{
	struct dazuko_request	*u_request;
	struct xp_daemon_id	xp_id;
	char			tmpbuffer[32];
	char			*value;
	unsigned int		size;

	size = length;
	if (length >= sizeof(tmpbuffer))
		size = sizeof(tmpbuffer) -1;

	/* copy request pointer string to kernelspace */
	if (xp_copyin(buffer, tmpbuffer, size) != 0)
		return -EFAULT;

	tmpbuffer[size] = 0;

	if (dazuko_get_value("\nRA=", buffer, &value) != 0)
	{
		rsbac_printk(KERN_WARNING "dazuko: error: linux_dazuko_device_write.RA missing\n");
		return -EFAULT;
	}

	u_request = (struct dazuko_request *)simple_strtoul(value, NULL, 10);

	rsbac_kfree(value);

	xp_id.pid = current->pid;
	xp_id.file = file;

	if (dazuko_handle_user_request(u_request, &xp_id) == 0)
		return length;
	else
		return -EINTR;
}

long linux_dazuko_device_ioctl(struct file *file, unsigned int cmd, unsigned long param)
{
	/* A daemon uses this function to interact with
	 * the kernel. A daemon can set scanning parameters,
	 * give scanning response, and get filenames to scan. */

	struct xp_daemon_id	xp_id;
	int			error = 0;

	if (param == 0)
	{
		rsbac_printk(KERN_WARNING "dazuko: error: linux_dazuko_device_ioctl(..., 0)\n");
		return -EFAULT;
	}

	xp_id.pid = current->pid;
	xp_id.file = file;

	error = dazuko_handle_user_request_compat12((void *)param, _IOC_NR(cmd), &xp_id);

	if (error != 0)
	{
		/* general error occurred */

		return -EPERM;
	}

	return error;
}

int linux_dazuko_device_release(struct inode *inode, struct file *file)
{
	struct xp_daemon_id	xp_id;

	DPRINT(("dazuko: dazuko_device_release() [%d]\n", current->pid));

	xp_id.pid = current->pid;
	xp_id.file = file;

	return dazuko_unregister_daemon(&xp_id);
}


/************************************************* */
/*          Externally visible functions           */
/************************************************* */

#ifdef CONFIG_RSBAC_INIT_DELAY
int rsbac_init_daz(void)
#else
int __init rsbac_init_daz(void)
#endif
{
	if (rsbac_is_initialized())
	{
		rsbac_printk(KERN_WARNING "rsbac_init_daz(): RSBAC already initialized\n");
		return -RSBAC_EREINIT;
	}

	/* init data structures */
	rsbac_printk(KERN_INFO "rsbac_init_daz(): Initializing RSBAC: DAZuko subsystem\n");

	dazuko_file_slab = rsbac_slab_create("rsbac_daz_file",
					sizeof(struct dazuko_file_struct));
	xp_file_slab = rsbac_slab_create("rsbac_daz_xp_file",
					sizeof(struct xp_file_struct));
	xp_daemon_slab = rsbac_slab_create("rsbac_daz_xp_daemon",
					sizeof(struct xp_daemon_id));
	dazuko_filename_slab = rsbac_slab_create("rsbac_daz_filename",
					DAZ_MAX_FILENAME);

	return dazuko_init();
}

static int daz_ignored(union rsbac_target_id_t tid)
{
	union rsbac_attribute_value_t i_attr_val1;

	if (rsbac_get_attr(SW_DAZ,
		T_FILE,
		tid,
		A_daz_do_scan,
		&i_attr_val1,
		TRUE)) {
		rsbac_printk(KERN_WARNING
			"rsbac_adf_request_daz(): rsbac_get_attr() for daz_do_scan returned error!\n");
		return FALSE;
	}
	if(i_attr_val1.daz_do_scan == DAZ_never)
		return TRUE;
	return FALSE;
}

static enum rsbac_adf_req_ret_t daz_check_secoff(rsbac_uid_t owner, enum rsbac_attribute_t attr)
{
	union rsbac_target_id_t       i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	switch(attr) {
		case A_daz_scanned:
		case A_daz_scanner:
		case A_system_role:
		case A_daz_role:
		case A_daz_do_scan:
			/* All attributes (remove target!) */
		case A_none:
			/* Security Officer? */
			i_tid.user = owner;
			if (rsbac_get_attr(SW_DAZ,
				T_USER,
				i_tid,
				A_daz_role,
				&i_attr_val1,
				TRUE)) {
				rsbac_printk(KERN_WARNING
						"rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
				return NOT_GRANTED;
			}
			/* if sec_officer, then grant */
			if (i_attr_val1.system_role == SR_security_officer)
				return GRANTED;
			else
				return NOT_GRANTED;

		default:
			return DO_NOT_CARE;
	}
}

inline enum rsbac_adf_req_ret_t
rsbac_adf_request_daz (enum  rsbac_adf_request_t     request,
		rsbac_pid_t             caller_pid,
		enum  rsbac_target_t          target,
		union rsbac_target_id_t       tid,
		enum  rsbac_attribute_t       attr,
		union rsbac_attribute_value_t attr_val,
		rsbac_uid_t             owner)
{
	struct dazuko_file_struct *dfs = NULL;
	struct xp_daemon_id xp_id;
	int error = 0;
	int check_error = 0;
	struct event_properties event_p;
	int event;
	int daemon_allowed;

	union rsbac_target_id_t       i_tid;
	union rsbac_attribute_value_t i_attr_val1;

	/* get daz_do_scan for target */
	switch(target) {
		case T_FILE:
			switch(request) {
				case R_DELETE:
					if(daz_ignored(tid))
						return DO_NOT_CARE;
					event = DAZUKO_ON_UNLINK;
					daemon_allowed = 1;
					break;
				case R_CLOSE:
					if(daz_ignored(tid))
						return DO_NOT_CARE;
					event = DAZUKO_ON_CLOSE;
					daemon_allowed = 1;
					break;
				case R_EXECUTE:
					if(daz_ignored(tid))
						return DO_NOT_CARE;
					event = DAZUKO_ON_EXEC;
					daemon_allowed = 0;
					break;
				case R_READ_WRITE_OPEN:
				case R_READ_OPEN:
					if(daz_ignored(tid))
						return DO_NOT_CARE;
					event = DAZUKO_ON_OPEN;
					daemon_allowed = 1;
					break;
				case R_READ_ATTRIBUTE:
				case R_MODIFY_ATTRIBUTE:
					return daz_check_secoff(owner, attr);
				default:
					return DO_NOT_CARE;
			}
			break;
		case T_DIR:
			switch(request) {
				case R_DELETE:
					if(daz_ignored(tid))
						return DO_NOT_CARE;
					event = DAZUKO_ON_RMDIR;
					daemon_allowed = 1;
					break;
				case R_READ_ATTRIBUTE:
				case R_MODIFY_ATTRIBUTE:
					return daz_check_secoff(owner, attr);
				default:
					return DO_NOT_CARE;
			}
			break;
		case T_DEV:
			switch(request) {
				case R_READ_WRITE_OPEN:
				case R_READ_OPEN:
				case R_APPEND_OPEN:
				case R_WRITE_OPEN:
					if(   (tid.dev.type == D_char)
						&& (tid.dev.major == CONFIG_RSBAC_DAZ_DEV_MAJOR)
					  ) {
						i_tid.process = caller_pid;
						if (rsbac_get_attr(SW_DAZ,
									T_PROCESS,
									i_tid,
									A_daz_scanner,
									&i_attr_val1,
									FALSE)) {
							rsbac_printk(KERN_WARNING
									"rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
							return NOT_GRANTED;
						}
						/* if scanner, then grant */
						if (i_attr_val1.daz_scanner)
							return GRANTED;
						else
							return NOT_GRANTED;
					}
					else
						return DO_NOT_CARE;
				default:
					return DO_NOT_CARE;
			}
			break;
		case T_PROCESS:
			switch(request) {
				case R_READ_ATTRIBUTE:
				case R_MODIFY_ATTRIBUTE:
					return daz_check_secoff(owner, attr);
				default:
					return DO_NOT_CARE;
			}
			break;
		case T_USER:
			switch(request) {
				case R_READ_ATTRIBUTE:
				case R_MODIFY_ATTRIBUTE:
					return daz_check_secoff(owner, attr);
				default:
					return DO_NOT_CARE;
			}
			break;
		case T_NONE:
			switch(request) {
				case R_SWITCH_MODULE:
					/* we need the switch_target */
					if(attr != A_switch_target)
						return NOT_GRANTED;
					/* do not care for other modules */
					if(   (attr_val.switch_target != SW_DAZ)
#ifdef CONFIG_RSBAC_SOFTMODE
						&& (attr_val.switch_target != SW_SOFTMODE)
#endif
#ifdef CONFIG_RSBAC_FREEZE
						&& (attr_val.switch_target != SW_FREEZE)
#endif
					  )
						return DO_NOT_CARE;
					return daz_check_secoff(owner, attr);
				default:
					return DO_NOT_CARE;
			}
			break;
		default:
			return DO_NOT_CARE;
	}

/* From here we can only have FILE or DIR targets */

#if defined(CONFIG_RSBAC_DAZ_CACHE)
	if (rsbac_get_attr(SW_DAZ,
				target,
				tid,
				A_daz_scanned,
				&i_attr_val1,
				TRUE))
	{
		rsbac_printk(KERN_WARNING
				"rsbac_adf_request_daz(): rsbac_get_attr() returned error!\n");
		return -RSBAC_EREADFAILED;
	}
	if(i_attr_val1.daz_scanned == DAZ_clean)
		return GRANTED;
#endif

	rsbac_pr_debug(adf_daz, "pid %u (%.15s), scanning required!\n",
				       current->pid, current->comm);
	xp_id.pid = current->pid;
	xp_id.file = NULL;

	check_error = dazuko_sys_check(event, daemon_allowed, &xp_id);

	if (!check_error)
	{
		dazuko_bzero(&event_p, sizeof(event_p));
		/*
		   event_p.flags = flags;
		   event_p.set_flags = 1;
		   event_p.mode = mode;
		   event_p.set_mode = 1;
		   */
		event_p.pid = current->pid;
		event_p.set_pid = 1;
		event_p.uid = current_uid();
		event_p.set_uid = 1;

		dfs = rsbac_smalloc_clear_unlocked(dazuko_file_slab);
		if (dfs != NULL)
		{
			dfs->extra_data = rsbac_smalloc_clear_unlocked(xp_file_slab);
			if (dfs->extra_data != NULL)
			{
				dfs->extra_data->dentry = tid.file.dentry_p;

				error = dazuko_sys_pre(event, dfs, NULL, &event_p);

#if defined(CONFIG_RSBAC_DAZ_CACHE)
				if(error != 2) {
					if(error == 0)
						i_attr_val1.daz_scanned = DAZ_clean;
					else
						i_attr_val1.daz_scanned = DAZ_infected;

					if (rsbac_set_attr(SW_DAZ,
								target,
								tid,
								A_daz_scanned,
								i_attr_val1))
					{
						rsbac_printk(KERN_WARNING "rsbac_adf_request_daz(): rsbac_set_attr() returned error!\n");
						dazuko_file_struct_cleanup(&dfs);
						return NOT_GRANTED;
					}
				}
#endif
				rsbac_pr_debug(adf_daz, "pid %u (%.15s), dazuko_sys_pre() result is %i\n",
				       current->pid, current->comm, error);
			}
			else
			{
				rsbac_sfree(dazuko_file_slab, dfs);
				dfs = NULL;
			}

			dazuko_file_struct_cleanup(&dfs);
		}
		if(error == 2)
			return DO_NOT_CARE;
		if(error == 0) {
			rsbac_pr_debug(adf_daz, "pid %u (%.15s), file clean!\n",
				       current->pid, current->comm);
			return GRANTED;
		} else {
			rsbac_pr_debug(adf_daz, "pid %u (%.15s), file infected!\n",
				       current->pid, current->comm);
			return NOT_GRANTED;
		}
	}
	rsbac_pr_debug(adf_daz, "pid %u (%.15s), dazuko_sys_check() result is %i\n",
	       current->pid, current->comm, check_error);
	return DO_NOT_CARE;
} /* end of rsbac_adf_request_daz() */


/*****************************************************************************/
/* If the request returned granted and the operation is performed,           */
/* the following function can be called by the AEF to get all aci set        */
/* correctly. For write accesses that are performed fully within the kernel, */
/* this is usually not done to prevent extra calls, including R_CLOSE for    */
/* cleaning up. Because of this, the write boundary is not adjusted - there  */
/* is no user-level writing anyway...                                        */
/* The second instance of target specification is the new target, if one has */
/* been created, otherwise its values are ignored.                           */
/* On success, 0 is returned, and an error from rsbac/error.h otherwise.     */

inline int rsbac_adf_set_attr_daz(
		enum  rsbac_adf_request_t     request,
		rsbac_pid_t             caller_pid,
		enum  rsbac_target_t          target,
		union rsbac_target_id_t       tid,
		enum  rsbac_target_t          new_target,
		union rsbac_target_id_t       new_tid,
		enum  rsbac_attribute_t       attr,
		union rsbac_attribute_value_t attr_val,
		rsbac_uid_t             owner)
{
	struct dazuko_file_struct *dfs = NULL;
	struct xp_daemon_id xp_id;
	int check_error = 0;
	struct event_properties event_p;
	int event;
	int daemon_allowed;
	union rsbac_target_id_t       i_tid;
	union rsbac_attribute_value_t i_attr_val1;
	union rsbac_attribute_value_t i_attr_val2;

	switch(target) {
		case T_FILE:
			switch(request) {
				case R_EXECUTE:
					/* get daz_scanner for file */
					if (rsbac_get_attr(SW_DAZ,
								T_FILE,
								tid,
								A_daz_scanner,
								&i_attr_val1,
								TRUE))
					{
						rsbac_printk(KERN_WARNING
								"rsbac_adf_set_attr_daz(): rsbac_get_attr() returned error!\n");
						return -RSBAC_EREADFAILED;
					}
					/* get for process */
					i_tid.process = caller_pid;
					if (rsbac_get_attr(SW_DAZ,
								T_PROCESS,
								i_tid,
								A_daz_scanner,
								&i_attr_val2,
								FALSE))
					{
						rsbac_printk(KERN_WARNING
							"rsbac_adf_set_attr_daz(): rsbac_get_attr() returned error!\n");
						return -RSBAC_EREADFAILED;
					}
					/* and set for process, if different */
					if(i_attr_val1.daz_scanner != i_attr_val2.daz_scanner)
						if (rsbac_set_attr(SW_DAZ,
								T_PROCESS,
								i_tid,
								A_daz_scanner,
								i_attr_val1))
						{
							rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_daz(): rsbac_set_attr() returned error!\n");
							return -RSBAC_EWRITEFAILED;
						}
					if(daz_ignored(tid))
						return 0;
					event = DAZUKO_ON_EXEC;
					daemon_allowed = 0;
					break;
				case R_WRITE:
					if(daz_ignored(tid))
						return 0;
					daz_reset_scanned(tid.file);
					return 0;
				case R_CLOSE:
					if(daz_ignored(tid))
						return 0;
					event = DAZUKO_ON_CLOSE;
					daemon_allowed = 1;
					if(   (attr == A_f_mode)
							&& (attr_val.f_mode & FMODE_WRITE)
					)
						daz_reset_scanned(tid.file);
					break;
				case R_READ_OPEN:
					if(daz_ignored(tid))
						return 0;
					event = DAZUKO_ON_OPEN;
					daemon_allowed = 1;
					break;
				case R_APPEND_OPEN:
				case R_READ_WRITE_OPEN:
				case R_WRITE_OPEN:
					if(daz_ignored(tid))
						return 0;
					daz_reset_scanned(tid.file);
					event = DAZUKO_ON_OPEN;
					daemon_allowed = 1;
					break;
				case R_DELETE:
					if(daz_ignored(tid))
						return 0;
					daz_reset_scanned(tid.file);
					event = DAZUKO_ON_UNLINK;
					daemon_allowed = 1;
					break;
				default:
					return 0;
			}
			break;
		case T_DIR:
			switch(request) {
				case R_DELETE:
					if(daz_ignored(tid))
						return 0;
					event = DAZUKO_ON_RMDIR;
					daemon_allowed = 1;
					break;
				default:
					return 0;
			}
		case T_PROCESS:
			switch(request) {
				case R_CLONE:
					/* Get daz_scanner from first process */
					if (rsbac_get_attr(SW_DAZ,
							T_PROCESS,
							tid,
							A_daz_scanner,
							&i_attr_val1,
							FALSE))
					{
						rsbac_printk(KERN_WARNING
							"rsbac_adf_set_attr_daz(): rsbac_get_attr() returned error!\n");
						return -RSBAC_EREADFAILED;
					}
					/* Set daz_scanner for new process, if set for first */
					if (   i_attr_val1.daz_scanner
						&& (rsbac_set_attr(SW_DAZ,
								T_PROCESS,
								new_tid,
								A_daz_scanner,
								i_attr_val1)) )
					{
						rsbac_printk(KERN_WARNING "rsbac_adf_set_attr_daz(): rsbac_set_attr() returned error!\n");
						return -RSBAC_EWRITEFAILED;
					}
					return 0;
				default:
					return 0;
			}
		default:
			return 0;
	}

#if defined(CONFIG_RSBAC_DAZ_CACHE)
	/* get daz_scanned for file */
	if (rsbac_get_attr(SW_DAZ,
				target,
				tid,
				A_daz_scanned,
				&i_attr_val1,
				TRUE))
	{
		rsbac_printk(KERN_WARNING
				"rsbac_adf_set_attr_daz(): rsbac_get_attr() returned error!\n");
		return -RSBAC_EREADFAILED;
	}
	if(i_attr_val1.daz_scanned == DAZ_clean)
		return 0;
#endif

	xp_id.pid = current->pid;
	xp_id.file = NULL;

	check_error = dazuko_sys_check(event, daemon_allowed, &xp_id);

	if (!check_error)
	{
		dazuko_bzero(&event_p, sizeof(event_p));
		/*
		   event_p.flags = flags;
		   event_p.set_flags = 1;
		   event_p.mode = mode;
		   event_p.set_mode = 1;
		   */
		event_p.pid = current->pid;
		event_p.set_pid = 1;
		event_p.uid = current_uid();
		event_p.set_uid = 1;

		dfs = rsbac_smalloc_clear_unlocked(dazuko_file_slab);
		if (dfs != NULL)
		{
			dfs->extra_data = rsbac_smalloc_clear_unlocked(xp_file_slab);
			if (dfs->extra_data != NULL)
			{
				dfs->extra_data->dentry = tid.file.dentry_p;

				dazuko_sys_post(event, dfs, NULL, &event_p);
				dazuko_file_struct_cleanup(&dfs);
			}
			else
			{
				rsbac_sfree(dazuko_file_slab, dfs);
				dfs = NULL;
			}
		}
	}

	return 0;
} /* end of rsbac_adf_set_attr_daz() */
