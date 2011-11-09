/* Dazuko RSBAC. Allow RSBAC Linux file access control for 3rd-party applications.
   Copyright (c) 2004 H+BEDV Datentechnik GmbH
   Written by John Ogness <jogness@antivir.de>

   Copyright (c) 2004-2010 Amon Ott <ao@rsbac.org>

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

#ifndef DAZUKO_RSBAC_H
#define DAZUKO_RSBAC_H

#ifdef CONFIG_MODVERSIONS
#define MODVERSIONS
#include <config/modversions.h>
#endif

#include <linux/kernel.h>
#include <linux/version.h>

#ifdef MODULE
#include <linux/module.h>
#endif

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) ((a)*65536+(b)*256+(c))
#endif

#include <linux/slab.h>
#include <asm/atomic.h>

#ifdef CONFIG_SMP
#ifndef __SMP__
#define __SMP__
#endif
#endif

#include <linux/semaphore.h>


#define	DEVICE_NAME		"dazuko"

#define XP_ERROR_PERMISSION	-EPERM;
#define XP_ERROR_INTERRUPT	-EINTR;
#define XP_ERROR_BUSY		-EBUSY;
#define XP_ERROR_FAULT		-EFAULT;
#define XP_ERROR_INVALID	-EINVAL;


struct xp_daemon_id
{
	int		pid;
	struct file	*file;
};

struct xp_file
{
	char	c;
};

struct xp_mutex
{
	struct semaphore	mutex;
};

struct xp_atomic
{
	atomic_t	atomic;
};

struct xp_file_struct
{
	int			full_filename_length;	/* length of filename */
	char			*full_filename;		/* kernelspace filename with full path */
	struct dentry		*dentry;		/* used to get inode */
};

struct xp_queue
{
	wait_queue_head_t queue;
};

struct xp_rwlock
{
	rwlock_t	rwlock;
};

#endif
