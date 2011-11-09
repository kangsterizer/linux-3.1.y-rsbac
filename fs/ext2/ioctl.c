/*
 * linux/fs/ext2/ioctl.c
 *
 * Copyright (C) 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 */

#include "ext2.h"
#include <linux/capability.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <asm/current.h>
#include <asm/uaccess.h>

#ifdef CONFIG_RSBAC
#include <net/sock.h>
#include <rsbac/hooks.h>
#endif

long ext2_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = filp->f_dentry->d_inode;
	struct ext2_inode_info *ei = EXT2_I(inode);
	unsigned int flags;
	unsigned short rsv_window_size;
	int ret;

#ifdef CONFIG_RSBAC
	enum  rsbac_adf_request_t rsbac_request;
	enum  rsbac_target_t rsbac_target = T_NONE;
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
#endif

#ifdef CONFIG_RSBAC
	rsbac_pr_debug(aef, "calling ADF\n");
	switch (cmd) {
		case EXT2_IOC_GETFLAGS:
		case EXT2_IOC_GETVERSION:
			rsbac_request = R_GET_PERMISSIONS_DATA;
			break;
		case EXT2_IOC_SETFLAGS:
		case EXT2_IOC_SETVERSION:
			rsbac_request = R_MODIFY_PERMISSIONS_DATA;
			break;
		default:
			rsbac_request = R_NONE;
	}
	if(S_ISSOCK(inode->i_mode)) {
		if(SOCKET_I(inode)->ops
				&& (SOCKET_I(inode)->ops->family == AF_UNIX)) {
			rsbac_target = T_UNIXSOCK;
			rsbac_target_id.unixsock.device = filp->f_dentry->d_sb->s_dev;
			rsbac_target_id.unixsock.inode  = inode->i_ino;
			rsbac_target_id.unixsock.dentry_p = filp->f_dentry;
		}
#ifdef CONFIG_RSBAC_NET_OBJ
		else {
			rsbac_target = T_NETOBJ;
			rsbac_target_id.netobj.sock_p
				= SOCKET_I(inode);
			rsbac_target_id.netobj.local_addr = NULL;
			rsbac_target_id.netobj.local_len = 0;
			rsbac_target_id.netobj.remote_addr = NULL;
			rsbac_target_id.netobj.remote_len = 0;
		}
#endif
	}
	else {
		if (S_ISDIR(inode->i_mode))
			rsbac_target = T_DIR;
		else if (S_ISFIFO(inode->i_mode))
			rsbac_target = T_FIFO;
		else if (S_ISLNK(inode->i_mode))
			rsbac_target = T_SYMLINK;
		else
			rsbac_target = T_FILE;
		rsbac_target_id.file.device = filp->f_dentry->d_sb->s_dev;
		rsbac_target_id.file.inode  = inode->i_ino;
		rsbac_target_id.file.dentry_p = filp->f_dentry;
	}
	rsbac_attribute_value.ioctl_cmd = cmd;
	if(   (rsbac_request != R_NONE)
			&& !rsbac_adf_request(rsbac_request,
				task_pid(current),
				rsbac_target,
				rsbac_target_id,
				A_ioctl_cmd,
				rsbac_attribute_value))
	{
		return -EPERM;
	}
#endif

	ext2_debug ("cmd = %u, arg = %lu\n", cmd, arg);

	switch (cmd) {
	case EXT2_IOC_GETFLAGS:
		ext2_get_inode_flags(ei);
		flags = ei->i_flags & EXT2_FL_USER_VISIBLE;
		return put_user(flags, (int __user *) arg);
	case EXT2_IOC_SETFLAGS: {
		unsigned int oldflags;

		ret = mnt_want_write(filp->f_path.mnt);
		if (ret)
			return ret;

		if (!inode_owner_or_capable(inode)) {
			ret = -EACCES;
			goto setflags_out;
		}

		if (get_user(flags, (int __user *) arg)) {
			ret = -EFAULT;
			goto setflags_out;
		}

		flags = ext2_mask_flags(inode->i_mode, flags);

		mutex_lock(&inode->i_mutex);
		/* Is it quota file? Do not allow user to mess with it */
		if (IS_NOQUOTA(inode)) {
			mutex_unlock(&inode->i_mutex);
			ret = -EPERM;
			goto setflags_out;
		}
		oldflags = ei->i_flags;

		/*
		 * The IMMUTABLE and APPEND_ONLY flags can only be changed by
		 * the relevant capability.
		 *
		 * This test looks nicer. Thanks to Pauline Middelink
		 */
		if ((flags ^ oldflags) & (EXT2_APPEND_FL | EXT2_IMMUTABLE_FL)) {
			if (!capable(CAP_LINUX_IMMUTABLE)) {
				mutex_unlock(&inode->i_mutex);
				ret = -EPERM;
				goto setflags_out;
			}
		}

		flags = flags & EXT2_FL_USER_MODIFIABLE;
		flags |= oldflags & ~EXT2_FL_USER_MODIFIABLE;
		ei->i_flags = flags;
		mutex_unlock(&inode->i_mutex);

		ext2_set_inode_flags(inode);
		inode->i_ctime = CURRENT_TIME_SEC;
		mark_inode_dirty(inode);
setflags_out:
		mnt_drop_write(filp->f_path.mnt);
		return ret;
	}
	case EXT2_IOC_GETVERSION:
		return put_user(inode->i_generation, (int __user *) arg);
	case EXT2_IOC_SETVERSION:
		if (!inode_owner_or_capable(inode))
			return -EPERM;
		ret = mnt_want_write(filp->f_path.mnt);
		if (ret)
			return ret;
		if (get_user(inode->i_generation, (int __user *) arg)) {
			ret = -EFAULT;
		} else {
			inode->i_ctime = CURRENT_TIME_SEC;
			mark_inode_dirty(inode);
		}
		mnt_drop_write(filp->f_path.mnt);
		return ret;
	case EXT2_IOC_GETRSVSZ:
		if (test_opt(inode->i_sb, RESERVATION)
			&& S_ISREG(inode->i_mode)
			&& ei->i_block_alloc_info) {
			rsv_window_size = ei->i_block_alloc_info->rsv_window_node.rsv_goal_size;
			return put_user(rsv_window_size, (int __user *)arg);
		}
		return -ENOTTY;
	case EXT2_IOC_SETRSVSZ: {

		if (!test_opt(inode->i_sb, RESERVATION) ||!S_ISREG(inode->i_mode))
			return -ENOTTY;

		if (!inode_owner_or_capable(inode))
			return -EACCES;

		if (get_user(rsv_window_size, (int __user *)arg))
			return -EFAULT;

		ret = mnt_want_write(filp->f_path.mnt);
		if (ret)
			return ret;

		if (rsv_window_size > EXT2_MAX_RESERVE_BLOCKS)
			rsv_window_size = EXT2_MAX_RESERVE_BLOCKS;

		/*
		 * need to allocate reservation structure for this inode
		 * before set the window size
		 */
		/*
		 * XXX What lock should protect the rsv_goal_size?
		 * Accessed in ext2_get_block only.  ext3 uses i_truncate.
		 */
		mutex_lock(&ei->truncate_mutex);
		if (!ei->i_block_alloc_info)
			ext2_init_block_alloc_info(inode);

		if (ei->i_block_alloc_info){
			struct ext2_reserve_window_node *rsv = &ei->i_block_alloc_info->rsv_window_node;
			rsv->rsv_goal_size = rsv_window_size;
		}
		mutex_unlock(&ei->truncate_mutex);
		mnt_drop_write(filp->f_path.mnt);
		return 0;
	}
	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long ext2_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	/* These are just misnamed, they actually get/put from/to user an int */
	switch (cmd) {
	case EXT2_IOC32_GETFLAGS:
		cmd = EXT2_IOC_GETFLAGS;
		break;
	case EXT2_IOC32_SETFLAGS:
		cmd = EXT2_IOC_SETFLAGS;
		break;
	case EXT2_IOC32_GETVERSION:
		cmd = EXT2_IOC_GETVERSION;
		break;
	case EXT2_IOC32_SETVERSION:
		cmd = EXT2_IOC_SETVERSION;
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return ext2_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif
