/*************************************************** */
/* Rule Set Based Access Control                     */
/* Implementation of the Access Control Decision     */
/* Facility (ADF) - JAIL module                      */
/* File: rsbac/adf/jail/syscalls.c                   */
/*                                                   */
/* Author and (c) 1999-2010: Amon Ott <ao@rsbac.org> */
/*                                                   */
/* Last modified: 04/Nov/2010                        */
/*************************************************** */

#include <linux/string.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <rsbac/types.h>
#include <rsbac/aci.h>
#include <rsbac/error.h>
#include <rsbac/rkmem.h>
#include <rsbac/debug.h>
#include <rsbac/helpers.h>
#include <rsbac/getname.h>
#include <rsbac/network.h>
#include <rsbac/jail.h>
#include <asm/uaccess.h>

static rsbac_jail_id_t next_id = 1;

/* Create a jail for current process */
/* Note: It is allowed to create jails within jails, but with restrictions */
int rsbac_jail_sys_jail(rsbac_version_t version,
		char * path,
		rsbac_jail_ip_t ip,
		rsbac_jail_flags_t flags,
		rsbac_cap_vector_t max_caps,
		rsbac_jail_scd_vector_t scd_get,
		rsbac_jail_scd_vector_t scd_modify)
{
	union rsbac_target_id_t i_tid;
	union rsbac_attribute_value_t i_attr_val1;
	int err = 0;
	rsbac_jail_id_t parent = 0;
#ifdef CONFIG_RSBAC_NET
	int chk_addr_ret;
#endif

	if(version != RSBAC_JAIL_VERSION)
		return -RSBAC_EINVALIDVERSION;

#ifdef CONFIG_RSBAC_NET
	chk_addr_ret = inet_addr_type(&init_net, ip);
	if (ip != INADDR_ANY &&
			chk_addr_ret != RTN_LOCAL &&
			chk_addr_ret != RTN_MULTICAST &&
			chk_addr_ret != RTN_BROADCAST)
		return -EADDRNOTAVAIL;
#endif

	/* Get jail_id for this process */
	i_tid.process = task_pid(current);
	if (rsbac_get_attr(SW_JAIL,
				T_PROCESS,
				i_tid,
				A_jail_id,
				&i_attr_val1,
				TRUE))
	{
		rsbac_ds_get_error("rsbac_jail_sys_jail()", A_jail_id);
		return(-RSBAC_EREADFAILED);
	}

	if (i_attr_val1.jail_id)
	{ /* this process is already in a jail -> limit ip and flags */
		parent = i_attr_val1.jail_id;
		if (rsbac_get_attr(SW_JAIL,
					T_PROCESS,
					i_tid,
					A_jail_flags,
					&i_attr_val1,
					TRUE))
		{
			rsbac_ds_get_error("rsbac_jail_sys_jail()", A_jail_flags);
			return(-RSBAC_EREADFAILED);
		}

		flags &= i_attr_val1.jail_flags | JAIL_allow_parent_ipc;
		if (rsbac_get_attr(SW_JAIL,
					T_PROCESS,
					i_tid,
					A_jail_scd_get,
					&i_attr_val1,
					TRUE))
		{
			rsbac_ds_get_error("rsbac_jail_sys_jail()", A_jail_scd_get);
			return(-RSBAC_EREADFAILED);
		}

		scd_get &= i_attr_val1.jail_scd_get;
		if (rsbac_get_attr(SW_JAIL,
					T_PROCESS,
					i_tid,
					A_jail_scd_modify,
					&i_attr_val1,
					TRUE))
		{
			rsbac_ds_get_error("rsbac_jail_sys_jail()", A_jail_scd_modify);
			return(-RSBAC_EREADFAILED);
		}

		scd_modify &= i_attr_val1.jail_scd_modify;
		if (rsbac_get_attr(SW_JAIL,
					T_PROCESS,
					i_tid,
					A_jail_ip,
					&i_attr_val1,
					TRUE))
		{
			rsbac_ds_get_error("rsbac_jail_sys_jail()", A_jail_ip);
			return(-RSBAC_EREADFAILED);
		}

		if(i_attr_val1.jail_ip)
			ip = i_attr_val1.jail_ip;

		if (rsbac_get_attr(SW_JAIL,
					T_PROCESS,
					i_tid,
					A_jail_max_caps,
					&i_attr_val1,
					TRUE))
		{
			rsbac_ds_get_error("rsbac_jail_sys_jail()", A_jail_max_caps);
			return(-RSBAC_EREADFAILED);
		}

		max_caps.cap[0] &= i_attr_val1.jail_max_caps.cap[0];
		max_caps.cap[1] &= i_attr_val1.jail_max_caps.cap[1];
	}

	/* check syslog id */
	if(flags & JAIL_this_is_syslog) {
		if(   rsbac_jail_syslog_jail_id
				&& rsbac_jail_exists(rsbac_jail_syslog_jail_id)
		  )
			return -RSBAC_EEXISTS;
	}

	if(path)
	{
		mm_segment_t oldfs;
		struct file * file;
		struct files_struct *files = current->files;
		struct fdtable *fdt;
		int fd;

		err = sys_chroot(path);
		if(err)
			return err;
		/* Set current user space to kernel space, because sys_chdir() takes name */
		/* from user space */
		oldfs = get_fs();
		set_fs(KERNEL_DS);
		err = sys_chdir("/");
		/* Set current user space back to user space */
		set_fs(oldfs);

restart:
		rcu_read_lock();
		fdt = files_fdtable(files);
		fdt = rcu_dereference((files)->fdt);

		for(fd=0; fd < fdt->max_fds; fd++)
		{
			file = fcheck(fd);
			if(   file
					&& file->f_dentry
					&& file->f_dentry->d_inode
					&& S_ISDIR(file->f_dentry->d_inode->i_mode)
			  )
			{
				char * filename;

#ifdef CONFIG_RSBAC_LOG_FULL_PATH
				filename = rsbac_kmalloc(CONFIG_RSBAC_MAX_PATH_LEN + 4);
				if(filename)
					rsbac_get_full_path(file->f_dentry, filename, CONFIG_RSBAC_MAX_PATH_LEN);
#else
				filename = rsbac_kmalloc(RSBAC_MAXNAMELEN + 4);
				if(filename)
					rsbac_get_full_path(file->f_dentry, filename, RSBAC_MAXNAMELEN);
#endif

				rsbac_printk(KERN_INFO
						"rsbac_jail_sys_jail(): avoid possible chroot breakout by closing open dir fd %u, inode %u, device %02u:%02u, path %s\n",
						fd,
						file->f_dentry->d_inode->i_ino,
						MAJOR(file->f_dentry->d_sb->s_dev),
						MINOR(file->f_dentry->d_sb->s_dev),
						filename);
				if(filename)
					rsbac_kfree(filename);

				rcu_read_unlock();
				sys_close(fd);
				goto restart;
			}
		}
		rcu_read_unlock();
	}

	/* Set jail_id for this process - number might wrap, so better check */
	i_attr_val1.jail_id = next_id++;
	while (!i_attr_val1.jail_id || rsbac_jail_exists(i_attr_val1.jail_id))
		i_attr_val1.jail_id = next_id++;

	if (rsbac_set_attr(SW_JAIL,
				T_PROCESS,
				i_tid,
				A_jail_id,
				i_attr_val1))
	{
		rsbac_ds_set_error("rsbac_jail_sys_jail()", A_jail_id);
		return(-RSBAC_EWRITEFAILED);
	}

	if (flags & JAIL_this_is_syslog) {
		rsbac_jail_syslog_jail_id = i_attr_val1.jail_id;
	}

	/* Set jail_parent for this process */
	i_attr_val1.jail_parent = parent;
	if (rsbac_set_attr(SW_JAIL, T_PROCESS, i_tid, A_jail_parent, i_attr_val1)) {
		rsbac_ds_set_error("rsbac_jail_sys_jail()", A_jail_parent);
		return (-RSBAC_EWRITEFAILED);
	}

	/* Set jail_ip for this process */
	i_attr_val1.jail_ip = ip;
	if (rsbac_set_attr(SW_JAIL,
				T_PROCESS,
				i_tid,
				A_jail_ip,
				i_attr_val1))
	{
		rsbac_ds_set_error("rsbac_jail_sys_jail()", A_jail_ip);
		return(-RSBAC_EWRITEFAILED);
	}

	/* Set jail_flags for this process */
	i_attr_val1.jail_flags = flags;
	if (rsbac_set_attr(SW_JAIL,
				T_PROCESS,
				i_tid,
				A_jail_flags,
				i_attr_val1))
	{
		rsbac_ds_set_error("rsbac_jail_sys_jail()", A_jail_flags);
		return(-RSBAC_EWRITEFAILED);
	}

	/* Set jail_max_caps for this process */
	i_attr_val1.jail_max_caps.cap[0] = max_caps.cap[0];
	i_attr_val1.jail_max_caps.cap[1] = max_caps.cap[1];
	if (rsbac_set_attr(SW_JAIL,
				T_PROCESS,
				i_tid,
				A_jail_max_caps,
				i_attr_val1))
	{
		rsbac_ds_set_error("rsbac_jail_sys_jail()", A_jail_max_caps);
		return(-RSBAC_EWRITEFAILED);
	}

	/* Set jail_scd_get for this process */
	i_attr_val1.jail_scd_get = scd_get;
	if (rsbac_set_attr(SW_JAIL,
				T_PROCESS,
				i_tid,
				A_jail_scd_get,
				i_attr_val1))
	{
		rsbac_ds_set_error("rsbac_jail_sys_jail()", A_jail_scd_get);
		return(-RSBAC_EWRITEFAILED);
	}

	/* Set jail_scd_modify for this process */
	i_attr_val1.jail_scd_modify = scd_modify;
	if (rsbac_set_attr(SW_JAIL,
				T_PROCESS,
				i_tid,
				A_jail_scd_modify,
				i_attr_val1))
	{
		rsbac_ds_set_error("rsbac_jail_sys_jail()", A_jail_scd_modify);
		return(-RSBAC_EWRITEFAILED);
	}
	return err;
}
