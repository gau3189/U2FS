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
/* Edited By	: Kunta Gautham Reddy (HW2)
 * Date		: 13-Apr-2014
 * Added	: wrapfs_getdents_callback
 *		: get_whiteout
 *		: wrapfs_check_filename
 *		: wrapfs_filldir
 * added the above files to support duplicate elimation
 * and .wh.filename i.e to skip files deleted in rd-only branch
*/

#include "wrapfs.h"

static ssize_t wrapfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err = 0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	printk(KERN_INFO" In wrapfs_read\n");
	UDBG;
	printk(KERN_INFO"name = %s\n", dentry->d_name.name);
	lower_file = wrapfs_lower_file(file);
	if (!lower_file) {
		UDBG;
		lower_file = wrapfs_lower_file_idx(file, 1);
		UDBG;
		if (!lower_file)
			return err;
		UDBG;
	}
	err = vfs_read(lower_file, buf, count, ppos);
	UDBG;
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);

	printk(KERN_INFO" In wrapfs_read success\n ");
	return err;
}

static ssize_t wrapfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err = 0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	printk(KERN_INFO"\n\n In wrapfs_write\n\n");
	UDBG;
	lower_file = wrapfs_lower_file(file);
	printk(KERN_INFO "\n\n lower_file = %s\n", dentry->d_name.name);
	err = vfs_write(lower_file, buf, count, ppos);
	UDBG;
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
		UDBG;
		fsstack_copy_attr_times(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	}
	printk(KERN_INFO" In wrapfs_write successful\n ");
	return err;
}

struct wrapfs_getdents_callback {
	void *dirent;
	int entries_written;
	int filldir_size;
	filldir_t filldir;
	char **files;
	int index;
	int count;
	int leftcount;
};

char *get_whiteout(char *name, int len)
{
	char *buf;
	buf = kmalloc(len + 5, GFP_KERNEL);
	if (unlikely(!buf))
		return ERR_PTR(-ENOMEM);
	UDBG;
	strcpy(buf, ".wh.");
	UDBG;
	strlcat(buf, name, len + 6);
	UDBG;
	return buf;
}

static int wrapfs_check_filename(char **files, char *name, int len, int count)
{
	int i = 0;
	int namelen = len + 6;
	char *whname = get_whiteout(name, len);
	printk("whiteOutname = %s\n", whname);
	for (i = 0; i < count; i++) {
		printk(KERN_INFO "checkfilename i = %d\n", i);
		if (!strncmp(files[i], whname, namelen))
			return 1;
		if (!strncmp(files[i], name, len))
			return 1;
	}
	UDBG;
	return 0;
}
/* based on generic filldir in fs/readir.c */
static int wrapfs_filldir(void *dirent, const char *oname, int namelen,
			   loff_t offset, u64 ino, unsigned int d_type)
{
	struct wrapfs_getdents_callback *buf = dirent;
	int err = 0;
	int is_whiteout = false;
	char *name = (char *) oname;
	int count = buf->count;
	UDBG;

	printk(KERN_INFO "In wrapfs fill dir\n");
	printk(KERN_INFO "passed name = %s\n", name);
	if (buf->index == 0) {
		printk(KERN_INFO" buf.files allocation\n");
		buf->files[count] = kmalloc(namelen, GFP_KERNEL);
		buf->files[count] = name;
		buf->count++;
	}
	if (buf->index == 0) {
		if (!strncmp(name, ".wh.", 4))
			is_whiteout = true;
	}
	if (buf->index == 1 && buf->leftcount >= 1) {
		err = wrapfs_check_filename(buf->files, name, namelen,
						buf->leftcount);
		if (err) {
			printk(KERN_INFO "whiteout entry name = %s\n", name);
			is_whiteout = true;
		}
		err = 0;
	}
	/* if 'name' isn't a whiteout, filldir it. */
	if (!is_whiteout) {
		UDBG;
		err = buf->filldir(buf->dirent, name, namelen, offset,
				   ino, d_type);
		UDBG;
	}
	/*
	 * If we did fill it, stuff it in our hash, otherwise return an
	 * error.
	 */
	return err;
}

static int wrapfs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct wrapfs_getdents_callback buf;
	int i = 0;
	UDBG;
	printk(KERN_INFO" In wrapfs_readdir\n");
	printk(KERN_INFO"file name ==%s\n", file->f_path.dentry->d_name.name);
	for (i = 0; i <= 1; i++) {
		UDBG;
		lower_file = wrapfs_lower_file_idx(file, i);
		if (!lower_file) {
			buf.files = NULL;
			buf.leftcount = 0;
			continue;
		}
		UDBG;
		buf.dirent = dirent;
		buf.filldir = filldir;
		buf.index = i;
		buf.count = 0;
		if (i == 0)
			buf.files = kmalloc(100*sizeof(char *), GFP_KERNEL);

		printk(KERN_INFO "lower file = %s\n i = %d\n",
			lower_file->f_path.dentry->d_name.name, i);
		err = vfs_readdir(lower_file, wrapfs_filldir, &buf);
		if (i == 0)
			buf.leftcount = buf.count;
		else
			buf.leftcount = 0;
		file->f_pos = lower_file->f_pos;
		if (err >= 0 && !lower_file->f_path.dentry->d_inode)
			fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
		if (err)
			goto out;
	}
	printk(KERN_INFO" In wrapfs_readdir success\n ");
out:
	return err;
}

static long wrapfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

out:
	printk(KERN_INFO" In wrapfs_unlocked_ioctl success\n ");
	return err;
}

#ifdef CONFIG_COMPAT
static long wrapfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int wrapfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;
	 printk(KERN_INFO" In wrapfs_mmap\n");
	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = wrapfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "wrapfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!WRAPFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "wrapfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
		err = do_munmap(current->mm, vma->vm_start,
				vma->vm_end - vma->vm_start);
		if (err) {
			printk(KERN_ERR "wrapfs: do_munmap failed %d\n", err);
			goto out;
		}
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &wrapfs_vm_ops;
	vma->vm_flags |= VM_CAN_NONLINEAR;

	file->f_mapping->a_ops = &wrapfs_aops; /* set our aops */
	if (!WRAPFS_F(file)->lower_vm_ops) /* save for our ->fault */
		WRAPFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	printk(KERN_INFO" In wrapfs_mmap success\n ");
	return err;
}

static int __open_dir(struct inode *inode, struct file *file,
			struct dentry *parent)
{
	struct dentry *lower_dentry;
	struct file *lower_file;
	struct vfsmount *lower_mnt;
	struct dentry *dentry = file->f_path.dentry;
	int i = 0, idx = 0;
	UDBG;
	for (i = 0; i <= 1; i++) {
		UDBG;
		printk(KERN_INFO "i = %d\n", i);
		lower_dentry = wrapfs_lower_dentry_idx(dentry, i);
		if (!lower_dentry || !lower_dentry->d_inode)
			continue;
		UDBG;
		dget(lower_dentry);
		lower_mnt = mntget(wrapfs_lower_mnt_idx(dentry, i));
		if (!lower_mnt)
			lower_mnt = mntget(wrapfs_lower_mnt_idx(parent, i));

		lower_file = dentry_open(lower_dentry,
					lower_mnt, file->f_flags,
					current_cred());
		if (IS_ERR(lower_file))
			return PTR_ERR(lower_file);

		wrapfs_set_lower_file_idx(file, i, lower_file);
		if (!wrapfs_lower_mnt_idx(dentry, i))
			wrapfs_set_lower_mnt_idx(dentry, i, lower_mnt);

		branchget(inode->i_sb, i);
		idx = i;

		if (!wrapfs_lower_inode_idx(inode, idx))
			fsstack_copy_attr_all(inode,
					wrapfs_lower_inode_idx(inode, idx));

	}
	return 0;
}

static int __open_file(struct inode *inode, struct file *file,
			struct dentry *parent)
{
	struct dentry *lower_dentry;
	struct file *lower_file;
	struct vfsmount *lower_mnt;
	struct dentry *dentry  = file->f_path.dentry;
	int lower_flags;
	int i = 0, idx = 0;
	UDBG;
	for (i = 0; i <= 1; i++) {
		lower_dentry = wrapfs_lower_dentry_idx(dentry, i);
		if (!lower_dentry || !lower_dentry->d_inode)
			continue;
		UDBG;
		lower_flags = file->f_flags;

		if (lower_dentry->d_inode && (i == 1)) {
			if (lower_flags & O_TRUNC) {
				int size = 0;
				int err = 0;
				UDBG;
				err = copyup_file(parent->d_inode, file,
							i, 0, size);
				UDBG;
				printk(KERN_INFO "err = %d\n", err);
				return err;
			} else
				lower_flags &= ~(OPEN_WRITE_FLAGS);
		}
		dget(lower_dentry);
		lower_mnt = mntget(wrapfs_lower_mnt_idx(dentry, i));

		if (!lower_mnt)
			lower_mnt = mntget(wrapfs_lower_mnt_idx(parent, i));

		lower_file = dentry_open(lower_dentry, lower_mnt, lower_flags,
				current_cred());

		if (IS_ERR(lower_file)) {
			dput(lower_dentry);
			mntput(lower_mnt);
			return PTR_ERR(lower_file);
		}
		wrapfs_set_lower_file(file, lower_file);
		branchget(inode->i_sb, i);
		idx = i;
		goto out;
	}
	UDBG;
out:
	if (!wrapfs_lower_inode_idx(inode, idx))
		fsstack_copy_attr_all(inode,
				wrapfs_lower_inode_idx(inode, idx));
	UDBG;
/*	if (!lower_mnt)
		mntput(lower_mnt);
*/
	return 0;
}

static int wrapfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *parent = NULL;
	struct file *lower_file = NULL;
	int size, i = 0;
	printk(KERN_INFO"IN WRAPFS_OPEN\n");
	UDBG;
	/* don't open unhashed/deleted files */
	if (d_unhashed(dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct wrapfs_file_info), GFP_KERNEL);
	if (!WRAPFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	atomic_set(&WRAPFS_F(file)->generation,
				atomic_read(&WRAPFS_I(inode)->generation));

	size = sizeof(struct file *) * 2;
	WRAPFS_F(file)->lower_files = kzalloc(size, GFP_KERNEL);
	if (unlikely(!WRAPFS_F(file)->lower_files)) {
		err = -ENOMEM;
		goto out_err;
	}
	printk(KERN_INFO "Before for loop\n");
	parent = dget_parent(dentry);
/* Added by Gautham*/
	if (S_ISDIR(inode->i_mode))
		err = __open_dir(inode, file, parent);
	else
		err = __open_file(inode, file, parent);
	UDBG;
	if (err) {
		for (i = 0; i <= 1; i++) {
			lower_file = wrapfs_lower_file_idx(file, i);
			if (!lower_file)
				continue;
			branchput(dentry->d_sb, i);
			fput(lower_file);
		}
	}
/* Added by Gautham*/
out_err:
	dput(parent);
	printk(KERN_INFO "successfully completed\n");
	return err;
}

static int wrapfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;
	 printk(KERN_INFO" In wrapfs_flush\n");
	lower_file = wrapfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush)
		err = lower_file->f_op->flush(lower_file, id);

	printk(KERN_INFO" In wrapfs_reafflush success\n");
	return err;
}

/* release all lower object references & free the file info structure */
static int wrapfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;
	int i = 0;
	struct dentry *dentry = file->f_path.dentry;
	struct super_block *sb = inode->i_sb;
	struct wrapfs_file_info *fileinfo;
	struct wrapfs_inode_info *inodeinfo;
	printk(KERN_INFO" In wrapfs_file_release\n");
	fileinfo = WRAPFS_F(file);
	BUG_ON(file->f_path.dentry->d_inode != inode);
	inodeinfo = WRAPFS_I(inode);

	/* fput all lower files */
	for (i = 0; i <= 1; i++) {
		lower_file = wrapfs_lower_file_idx(file, i);
		if (lower_file) {
			wrapfs_set_lower_file_idx(file, i, NULL);
			fput(lower_file);
			branchput(sb, i);
		}
		if (d_unhashed(dentry) && (dentry != dentry->d_sb->s_root)) {
			dput(wrapfs_lower_dentry_idx(dentry, i));
			wrapfs_set_lower_dentry_idx(dentry, i, NULL);
		}
	}

	kfree(fileinfo->lower_files);
	kfree(fileinfo);

	printk(KERN_INFO" In wrapfs_file_release success\n ");
	return 0;
}

static int wrapfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err, i;
	struct file *lower_file;
	/*struct path lower_path;*/
	struct dentry *dentry = file->f_path.dentry;

	/*Added by Gautham*/
	struct dentry *lower_dentry;
	struct inode *lower_inode, *inode;
	 printk(KERN_INFO" In wrapfs_fsync\n");
	err = generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	inode = dentry->d_inode;
	if (unlikely(!inode)) {
		printk(KERN_ERR"u2fs: null lower_node\n");
		goto out;
	}
	for (i = 0; i <= 1; i++) {
		lower_inode = wrapfs_lower_inode_idx(inode, i);
		if (!lower_inode || !lower_inode->i_fop->fsync)
			continue;
	lower_file = wrapfs_lower_file_idx(file, i);
	lower_dentry = wrapfs_lower_dentry_idx(dentry, i);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	if (!err && i == 0)
		fsstack_copy_attr_times(inode, lower_inode);
	if (err)
		goto out;
	}
/*	lower_file = wrapfs_lower_file(file);
	wrapfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	wrapfs_put_lower_path(dentry, &lower_path);
*/
out:
	printk(KERN_INFO" In wrapfs_fsync success\n ");
	return err;
}

static int wrapfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0, i = 0;
	struct file *lower_file = NULL;

	struct dentry *dentry = file->f_path.dentry;
	struct inode *lower_inode, *inode;
	printk(KERN_INFO" In wrapfs_fasync\n");
	inode = dentry->d_inode;
	if (unlikely(!inode))
		printk(KERN_ERR"u2fs : null lower inode\n");

	for (i = 0; i <= 1; i++) {
		lower_inode = wrapfs_lower_inode_idx(inode, i);
		if (!lower_inode || !lower_inode->i_fop->fasync)
			continue;
		lower_file = wrapfs_lower_file_idx(file, i);
		if (lower_file->f_op && lower_file->f_op->fasync)
			err = lower_file->f_op->fasync(fd, lower_file, flag);
		if (!err || i == 0)
			fsstack_copy_attr_times(inode, lower_inode);
		if (err)
			goto out;
	}
out:
	printk(KERN_INFO" In wrapfs_fasync success\n ");
	return err;
}

const struct file_operations wrapfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= wrapfs_read,
	.write		= wrapfs_write,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.mmap		= wrapfs_mmap,
	.open		= wrapfs_open,
	.flush		= wrapfs_flush,
	.release	= wrapfs_file_release,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};

/* trimmed directory options */
const struct file_operations wrapfs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= wrapfs_readdir,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.open		= wrapfs_open,
	.release	= wrapfs_file_release,
	.flush		= wrapfs_flush,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};
