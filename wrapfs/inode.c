/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Edited By    : Kunta Gautham Reddy (HW2)
 * Date         : 13-Apr-2014
 * Added        :
 *		__create_whiteout() - to create a whitoutfile.
 *		modified other functions to support u2fs
 */

#include "wrapfs.h"

static int wrapfs_create(struct inode *dir, struct dentry *dentry,
			 int mode, struct nameidata *nd)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path, saved_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	printk(KERN_INFO "dentry = %s\n", dentry->d_name.name);
	UDBG;
	if (!lower_path.dentry) {
		UDBG;
		wrapfs_get_lower_path_idx(dentry, &lower_path, 1);
		lower_dentry = create_parents(dir, dentry,
					dentry->d_name.name, 0);
		if (IS_ERR(lower_dentry)) {
			err = PTR_ERR(lower_dentry);
			return -EPERM;
		}
		UDBG;
		return -EPERM;
		wrapfs_get_lower_path_idx(lower_dentry, &lower_path, 0);
		goto begin_creation;
	}
	UDBG;
begin_creation:
	UDBG;
	lower_parent_dentry = lock_parent(lower_dentry);
	printk(KERN_INFO "parent dentry = %s\n",
			lower_parent_dentry->d_name.name);
	UDBG;

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;

	pathcpy(&saved_path, &nd->path);
	pathcpy(&nd->path, &lower_path);
	UDBG;
	err = vfs_create(lower_parent_dentry->d_inode, lower_dentry, mode, nd);
	UDBG;
	pathcpy(&nd->path, &saved_path);
	if (err)
		goto out;
	UDBG;
	err = wrapfs_interpose(dentry, dir->i_sb, &lower_path);
	UDBG;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
	UDBG;
out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int wrapfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(old_dentry->d_inode);
	wrapfs_get_lower_path(old_dentry, &lower_old_path);
	wrapfs_get_lower_path(new_dentry, &lower_new_path);

	if (!lower_new_path.dentry || !lower_old_path.dentry)
		return 0;

	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = mnt_want_write(lower_new_path.mnt);
	if (err)
		goto out_unlock;

	err = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
		       lower_new_dentry);
	if (err || !lower_new_dentry->d_inode)
		goto out;

	err = wrapfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_new_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_new_dentry->d_inode);
	set_nlink(old_dentry->d_inode,
		  wrapfs_lower_inode(old_dentry->d_inode)->i_nlink);
	i_size_write(new_dentry->d_inode, file_size_save);
out:
	mnt_drop_write(lower_new_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	wrapfs_put_lower_path(old_dentry, &lower_old_path);
	wrapfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

/*
 *	Function for deleting creating whiteout
 */
int __create_whiteout(struct dentry *dentry)
{
	struct dentry *lower_dir_dentry = NULL;
	struct dentry *lower_dentry, *lower_dentry1 = NULL;
	struct dentry *lower_wh_dentry = NULL;
	char *name = NULL;
	int err = -EINVAL;
	int len = dentry->d_name.len;

	UDBG;
	name = kmalloc(len + 5, GFP_KERNEL);
	if (unlikely(!name))
		return -ENOMEM;
	lower_dentry = wrapfs_lower_dentry_idx(dentry, 1);
	lower_dentry1 = wrapfs_lower_dentry_idx(dentry, 0);
	UDBG;

	len = lower_dentry->d_name.len;
	strcpy(name, ".wh.");
	strlcat(name, lower_dentry->d_name.name, len + 5);
	UDBG;
	printk(KERN_INFO "whitename = %s\n", name);
	UDBG;
	printk(KERN_INFO "name = %s\n", lower_dentry->d_name.name);
	printk(KERN_INFO "name = %s\n", lower_dentry->d_parent->d_name.name);
	lower_wh_dentry =
		lookup_lck_len(name, lower_dentry1->d_parent,
				dentry->d_name.len + 4);
	if (IS_ERR(lower_wh_dentry))
		goto out;
	UDBG;
	if (lower_wh_dentry->d_inode) {
		dput(lower_wh_dentry);
		err = 0;
		goto out;
	}
	UDBG;

	/* Normal Left side brach file or folder deletion */
	lower_dir_dentry = lock_parent_wh(lower_wh_dentry);
	UDBG;
	err = vfs_create(lower_dir_dentry->d_inode,
			lower_wh_dentry,
			current_umask() & S_IRUGO,
			0);
	UDBG;
	unlock_dir(lower_dir_dentry);
	dput(lower_wh_dentry);

out:
	kfree(name);
	return err;
}

static int wrapfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err = 0;
	struct dentry *lower_dentry = NULL;
	struct inode *lower_dir_inode = wrapfs_lower_inode(dir);
	struct dentry *lower_dir_dentry = NULL;
	struct path lower_path;

	UDBG;
	wrapfs_get_lower_path(dentry, &lower_path);
	if (!lower_path.dentry->d_inode) {
		printk(KERN_INFO "\n\nCall for unlink in readonly branch:\n\n");
		UDBG;

		wrapfs_get_lower_path_idx(dentry, &lower_path, 1);
		err = __create_whiteout(dentry);
		if (!err) {
			printk(KERN_INFO" File Created Successfully\n");
			/*fsstack_copy_attr_times(dir, lower_dir_inode);*/
			return err;
		} else {
			printk(KERN_INFO"Error\n");
			wrapfs_put_lower_path(dentry, &lower_path);
			return -EPERM;
		}
	}

	UDBG;
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_unlink(lower_dir_inode, lower_dentry);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(dentry->d_inode,
		  wrapfs_lower_inode(dentry->d_inode)->i_nlink);
	dentry->d_inode->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */

/*TODO : Check for the entries in the rdonly branch and create a mask file.
*/
out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int wrapfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_path.dentry->d_inode)
		return 0;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_symlink(lower_parent_dentry->d_inode, lower_dentry, symname);
	if (err)
		goto out;
	err = wrapfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int wrapfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;

	if (!lower_path.dentry) {
		wrapfs_get_lower_path_idx(dentry, &lower_path, 1);
		lower_dentry = create_parents(dir, dentry,
					dentry->d_name.name, 0);
		if (IS_ERR(lower_dentry)) {
			err = PTR_ERR(lower_dentry);
			return -EPERM;
		}
		return 0;
		wrapfs_get_lower_path_idx(lower_dentry, &lower_path, 0);
		goto begin_mkdir;
	}
	UDBG;
begin_mkdir:
	lower_parent_dentry = lock_parent(lower_dentry);
	if (IS_ERR(lower_parent_dentry)) {
		err = PTR_ERR(lower_parent_dentry);
		goto out_unlock;
	}

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out;

	err = vfs_mkdir(lower_parent_dentry->d_inode, lower_dentry, mode);

	if (err)
		goto out_unlock;

	unlock_dir(lower_parent_dentry);

	err = wrapfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out_unlock;

	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
	/* update number of links on parent directory */
	set_nlink(dir, wrapfs_lower_inode(dir)->i_nlink);

out_unlock:
	mnt_drop_write(lower_path.mnt);

out:
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int wrapfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	UDBG;

	if (!lower_path.dentry) {
		wrapfs_put_lower_path(dentry, &lower_path);
		/* create a mask for the directory*/
		return -EPERM;
	}

	lower_dir_dentry = lock_parent(lower_dentry);
	UDBG;
	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_rmdir(lower_dir_dentry->d_inode, lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */

	/* TODO: check in rd branch and create a mask*/

	if (dentry->d_inode)
		clear_nlink(dentry->d_inode);
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int wrapfs_mknod(struct inode *dir, struct dentry *dentry, int mode,
			dev_t dev)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_mknod(lower_parent_dentry->d_inode, lower_dentry, mode, dev);
	if (err)
		goto out;

	err = wrapfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, wrapfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_parent_dentry);
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in wrapfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int wrapfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	wrapfs_get_lower_path(old_dentry, &lower_old_path);
	wrapfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = mnt_want_write(lower_old_path.mnt);
	if (err)
		goto out;
	err = mnt_want_write(lower_new_path.mnt);
	if (err)
		goto out_drop_old_write;

	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			 lower_new_dir_dentry->d_inode, lower_new_dentry);
	if (err)
		goto out_err;

	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
	fsstack_copy_inode_size(new_dir, lower_new_dir_dentry->d_inode);
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      lower_old_dir_dentry->d_inode);
		fsstack_copy_inode_size(old_dir,
					lower_old_dir_dentry->d_inode);
	}

out_err:
	mnt_drop_write(lower_new_path.mnt);
out_drop_old_write:
	mnt_drop_write(lower_old_path.mnt);
out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	wrapfs_put_lower_path(old_dentry, &lower_old_path);
	wrapfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int wrapfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_inode->i_op ||
	    !lower_dentry->d_inode->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(dentry->d_inode, lower_dentry->d_inode);

out:
	wrapfs_put_lower_path(dentry, &lower_path);
	return err;
}

static void *wrapfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = wrapfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
out:
	nd_set_link(nd, buf);
	return NULL;
}

/* this @nd *IS* still used */
static void wrapfs_put_link(struct dentry *dentry, struct nameidata *nd,
			    void *cookie)
{
	char *buf = nd_get_link(nd);
	if (!IS_ERR(buf))	/* free the char* */
		kfree(buf);
}

static int wrapfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode = NULL;
	int err = 0;
	int is_file;
	int i = 0;
	const int write_mask = (mask & MAY_WRITE) && !(mask & MAY_READ);
	struct inode *inode_grabbed;

	printk(KERN_INFO "inode num = %lu\n", inode->i_ino);
	inode_grabbed = igrab(inode);
	is_file = !S_ISDIR(inode->i_mode);

	if (!WRAPFS_I(inode)->lower_inodes) {
		if (is_file)
			err = -ESTALE;
		goto out;
	}
	if (!inode)
		goto out;
	for (i = 0; i <= 1; i++) {
		if (!wrapfs_lower_inode_idx(inode, i))
			continue;

		lower_inode = wrapfs_lower_inode_idx(inode, i);
		printk(KERN_INFO "inodenum->ino = %lu\n", lower_inode->i_ino);
		if (!is_file)	/* && !S_ISDIR(lower_inode->i_mode)) */
			continue;
		err = inode_permission(lower_inode, mask);
		if (err && err == -EACCES && i == 1 &&
			lower_inode->i_sb->s_magic == NFS_SUPER_MAGIC)
			err = generic_permission(lower_inode, mask);
		if (err)
			goto out;
		if (is_file || write_mask) {
			if (is_file && write_mask) {
				err = get_write_access(lower_inode);
				if (!err)
					put_write_access(lower_inode);
			}
			break;
		}
	}
out:
	printk(KERN_INFO "Wrapfs_permission successful\n");
	iput(inode_grabbed);
	return err;
}

static int wrapfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = dentry->d_inode;

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	wrapfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = wrapfs_lower_inode(inode);


/*	TODO :FOR SETTING FILE PRESENT IN RDONLY BRANH */

	if (!lower_path.dentry) {
		wrapfs_put_lower_path(dentry, &lower_path);
		return -EPERM;
	}
/*
	err = (!(branchperms(dentry->d_sb, 1) & MAY_WRITE)) ? -EROFS : 0;
	if (err || IS_RDONLY(inode))

	lower_dentry = wrapfs_lower_dentry(dentry);
	if (lower_dentry) {
		err = -EINVAL;
		goto out;
	}
	lower_inode = lower_dentry->d_inode;
	err = inode_change_ok(lower_inode, ia);
	if (err)
		goto out;

*/

/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = wrapfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use lower_dentry->d_inode, because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	err = notify_change(lower_dentry, &lower_ia); /* note: lower_ia */
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	wrapfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

const struct inode_operations wrapfs_symlink_iops = {
	.readlink	= wrapfs_readlink,
	.permission	= wrapfs_permission,
	.follow_link	= wrapfs_follow_link,
	.setattr	= wrapfs_setattr,
	.put_link	= wrapfs_put_link,
};

const struct inode_operations wrapfs_dir_iops = {
	.create		= wrapfs_create,
	.lookup		= wrapfs_lookup,
	.link		= wrapfs_link,
	.unlink		= wrapfs_unlink,
	.symlink	= wrapfs_symlink,
	.mkdir		= wrapfs_mkdir,
	.rmdir		= wrapfs_rmdir,
	.mknod		= wrapfs_mknod,
	.rename		= wrapfs_rename,
	.permission	= wrapfs_permission,
	.setattr	= wrapfs_setattr,
};

const struct inode_operations wrapfs_main_iops = {
	.permission	= wrapfs_permission,
	.setattr	= wrapfs_setattr,
};
