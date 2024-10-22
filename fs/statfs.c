#include <linux/syscalls.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/security.h>
#include <linux/uaccess.h>

#include <rsbac/hooks.h>

static int flags_by_mnt(int mnt_flags)
{
	int flags = 0;

	if (mnt_flags & MNT_READONLY)
		flags |= ST_RDONLY;
	if (mnt_flags & MNT_NOSUID)
		flags |= ST_NOSUID;
	if (mnt_flags & MNT_NODEV)
		flags |= ST_NODEV;
	if (mnt_flags & MNT_NOEXEC)
		flags |= ST_NOEXEC;
	if (mnt_flags & MNT_NOATIME)
		flags |= ST_NOATIME;
	if (mnt_flags & MNT_NODIRATIME)
		flags |= ST_NODIRATIME;
	if (mnt_flags & MNT_RELATIME)
		flags |= ST_RELATIME;
	return flags;
}

static int flags_by_sb(int s_flags)
{
	int flags = 0;
	if (s_flags & MS_SYNCHRONOUS)
		flags |= ST_SYNCHRONOUS;
	if (s_flags & MS_MANDLOCK)
		flags |= ST_MANDLOCK;
	return flags;
}

static int calculate_f_flags(struct vfsmount *mnt)
{
	return ST_VALID | flags_by_mnt(mnt->mnt_flags) |
		flags_by_sb(mnt->mnt_sb->s_flags);
}

int statfs_by_dentry(struct dentry *dentry, struct kstatfs *buf)
{
	int retval;

#ifdef CONFIG_RSBAC
	union rsbac_target_id_t rsbac_target_id;
	union rsbac_attribute_value_t rsbac_attribute_value;
#endif

	if (!dentry->d_sb->s_op->statfs)
		return -ENOSYS;

#ifdef CONFIG_RSBAC
	rsbac_pr_debug(aef, "calling ADF\n");
	rsbac_target_id.dev.type = D_block;
	rsbac_target_id.dev.major = RSBAC_MAJOR(dentry->d_sb->s_dev);
	rsbac_target_id.dev.minor = RSBAC_MINOR(dentry->d_sb->s_dev);
	rsbac_attribute_value.dummy = 0;
	if (!rsbac_adf_request(R_GET_STATUS_DATA,
				task_pid(current),
				T_DEV,
				rsbac_target_id,
				A_none,
				rsbac_attribute_value)) {
		return -EPERM;
	}
#endif

	memset(buf, 0, sizeof(*buf));
	retval = security_sb_statfs(dentry);
	if (retval)
		return retval;
	retval = dentry->d_sb->s_op->statfs(dentry, buf);
	if (retval == 0 && buf->f_frsize == 0)
		buf->f_frsize = buf->f_bsize;
	return retval;
}

int vfs_statfs(struct path *path, struct kstatfs *buf)
{
	int error;

	error = statfs_by_dentry(path->dentry, buf);
	if (!error)
		buf->f_flags = calculate_f_flags(path->mnt);
	return error;
}
EXPORT_SYMBOL(vfs_statfs);

int user_statfs(const char __user *pathname, struct kstatfs *st)
{
	struct path path;
	int error = user_path_at(AT_FDCWD, pathname, LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT, &path);
	if (!error) {
		error = vfs_statfs(&path, st);
		path_put(&path);
	}
	return error;
}

int fd_statfs(int fd, struct kstatfs *st)
{
	struct file *file = fget(fd);
	int error = -EBADF;
	if (file) {
		error = vfs_statfs(&file->f_path, st);
		fput(file);
	}
	return error;
}

static int do_statfs_native(struct kstatfs *st, struct statfs __user *p)
{
	struct statfs buf;

	if (sizeof(buf) == sizeof(*st))
		memcpy(&buf, st, sizeof(*st));
	else {
		if (sizeof buf.f_blocks == 4) {
			if ((st->f_blocks | st->f_bfree | st->f_bavail |
			     st->f_bsize | st->f_frsize) &
			    0xffffffff00000000ULL)
				return -EOVERFLOW;
			/*
			 * f_files and f_ffree may be -1; it's okay to stuff
			 * that into 32 bits
			 */
			if (st->f_files != -1 &&
			    (st->f_files & 0xffffffff00000000ULL))
				return -EOVERFLOW;
			if (st->f_ffree != -1 &&
			    (st->f_ffree & 0xffffffff00000000ULL))
				return -EOVERFLOW;
		}

		buf.f_type = st->f_type;
		buf.f_bsize = st->f_bsize;
		buf.f_blocks = st->f_blocks;
		buf.f_bfree = st->f_bfree;
		buf.f_bavail = st->f_bavail;
		buf.f_files = st->f_files;
		buf.f_ffree = st->f_ffree;
		buf.f_fsid = st->f_fsid;
		buf.f_namelen = st->f_namelen;
		buf.f_frsize = st->f_frsize;
		buf.f_flags = st->f_flags;
		memset(buf.f_spare, 0, sizeof(buf.f_spare));
	}
	if (copy_to_user(p, &buf, sizeof(buf)))
		return -EFAULT;
	return 0;
}

static int do_statfs64(struct kstatfs *st, struct statfs64 __user *p)
{
	struct statfs64 buf;
	if (sizeof(buf) == sizeof(*st))
		memcpy(&buf, st, sizeof(*st));
	else {
		buf.f_type = st->f_type;
		buf.f_bsize = st->f_bsize;
		buf.f_blocks = st->f_blocks;
		buf.f_bfree = st->f_bfree;
		buf.f_bavail = st->f_bavail;
		buf.f_files = st->f_files;
		buf.f_ffree = st->f_ffree;
		buf.f_fsid = st->f_fsid;
		buf.f_namelen = st->f_namelen;
		buf.f_frsize = st->f_frsize;
		buf.f_flags = st->f_flags;
		memset(buf.f_spare, 0, sizeof(buf.f_spare));
	}
	if (copy_to_user(p, &buf, sizeof(buf)))
		return -EFAULT;
	return 0;
}

SYSCALL_DEFINE2(statfs, const char __user *, pathname, struct statfs __user *, buf)
{
	struct kstatfs st;
	int error = user_statfs(pathname, &st);
	if (!error)
		error = do_statfs_native(&st, buf);
	return error;
}

SYSCALL_DEFINE3(statfs64, const char __user *, pathname, size_t, sz, struct statfs64 __user *, buf)
{
	struct kstatfs st;
	int error;
	if (sz != sizeof(*buf))
		return -EINVAL;
	error = user_statfs(pathname, &st);
	if (!error)
		error = do_statfs64(&st, buf);
	return error;
}

SYSCALL_DEFINE2(fstatfs, unsigned int, fd, struct statfs __user *, buf)
{
	struct kstatfs st;
	int error = fd_statfs(fd, &st);
	if (!error)
		error = do_statfs_native(&st, buf);
	return error;
}

SYSCALL_DEFINE3(fstatfs64, unsigned int, fd, size_t, sz, struct statfs64 __user *, buf)
{
	struct kstatfs st;
	int error;

	if (sz != sizeof(*buf))
		return -EINVAL;

	error = fd_statfs(fd, &st);
	if (!error)
		error = do_statfs64(&st, buf);
	return error;
}

SYSCALL_DEFINE2(ustat, unsigned, dev, struct ustat __user *, ubuf)
{
	struct super_block *s;
	struct ustat tmp;
	struct kstatfs sbuf;
	int err;

	s = user_get_super(new_decode_dev(dev));
	if (!s)
		return -EINVAL;

	err = statfs_by_dentry(s->s_root, &sbuf);
	drop_super(s);
	if (err)
		return err;

	memset(&tmp,0,sizeof(struct ustat));
	tmp.f_tfree = sbuf.f_bfree;
	tmp.f_tinode = sbuf.f_ffree;

	return copy_to_user(ubuf, &tmp, sizeof(struct ustat)) ? -EFAULT : 0;
}
