
/*
 * Copyright (c) 2003-2014 Erez Zadok
 * Copyright (c) 2003-2006 Charles P. Wright
 * Copyright (c) 2005-2007 Josef 'Jeff' Sipek
 * Copyright (c) 2005-2006 Junjiro Okajima
 * Copyright (c) 2005      Arun M. Krishnakumar
 * Copyright (c) 2004-2006 David P. Quigley
 * Copyright (c) 2003-2004 Mohammad Nayyer Zubair
 * Copyright (c) 2003      Puja Gupta
 * Copyright (c) 2003      Harikesavan Krishnan
 * Copyright (c) 2003-2014 Stony Brook University
 * Copyright (c) 2003-2014 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Name		:Kunta Gautham Reddy (HW2)
 * Date		: 13-Apr-2014
 * Added        : Modified and added different functions and
 *                structures to support u2fs.
 *
 */
#include "wrapfs.h"

/*
 * For detailed explanation of copyup see:
 * Documentation/filesystems/wrapfs/concepts.txt
 */


/*
 * Determine the mode based on the copyup flags, and the existing dentry.
 *
 * Handle file systems which may not support certain options.  For example
 * jffs2 doesn't allow one to chmod a symlink.  So we ignore such harmless
 * errors, rather than propagating them up, which results in copyup errors
 * and errors returned back to users.
 */
static int copyup_permissions(struct super_block *sb,
			      struct dentry *old_lower_dentry,
			      struct dentry *new_lower_dentry)
{
	struct inode *i = old_lower_dentry->d_inode;
	struct iattr newattrs;
	int err;
	UDBG;
	UDBG;
	newattrs.ia_atime = i->i_atime;
	newattrs.ia_mtime = i->i_mtime;
	newattrs.ia_ctime = i->i_ctime;
	newattrs.ia_gid = i->i_gid;
	newattrs.ia_uid = i->i_uid;
	newattrs.ia_valid = ATTR_CTIME | ATTR_ATIME | ATTR_MTIME |
		ATTR_ATIME_SET | ATTR_MTIME_SET | ATTR_FORCE |
		ATTR_GID | ATTR_UID;
/*	mutex_lock(&new_lower_dentry->d_inode->i_mutex);*/

	UDBG;
/*	err = notify_change(new_lower_dentry, &newattrs);
	if (err)
		goto out;
	UDBG;
*/	/* now try to change the mode and ignore EOPNOTSUPP on symlinks */
/*	newattrs.ia_mode = i->i_mode;
	newattrs.ia_valid = ATTR_MODE | ATTR_FORCE;
	err = notify_change(new_lower_dentry, &newattrs);
	if (err == -EOPNOTSUPP &&
	    S_ISLNK(new_lower_dentry->d_inode->i_mode)) {
		printk(KERN_WARNING
		       "wrapfs: changing \"%s\" symlink mode unsupported\n",
		       new_lower_dentry->d_name.name);
		err = 0;
	}

out:
*/	UDBG;
/*	mutex_unlock(&new_lower_dentry->d_inode->i_mutex);*/
	err = 0;
	return err;
}

int init_lower_nd(struct nameidata *nd, unsigned int flags)
{
	int err = 0;
#ifdef ALLOC_LOWER_ND_FILE
	/*
	 * XXX: one day we may need to have the lower return an open file
	 * for us.  It is not needed in 2.6.23-rc1 for nfs2/nfs3, but may
	 * very well be needed for nfs4.
	 */
	struct file *file;
#endif /* ALLOC_LOWER_ND_FILE */

	memset(nd, 0, sizeof(struct nameidata));
	if (!flags)
		return err;

	switch (flags) {
	case LOOKUP_CREATE:
		nd->intent.open.flags |= O_CREAT;
	/* fall through: shared code for create/open cases */
	case LOOKUP_OPEN:
		nd->flags = flags;
		nd->intent.open.flags |= (FMODE_READ | FMODE_WRITE);
	#ifdef ALLOC_LOWER_ND_FILE
		file = kzalloc(sizeof(struct file), GFP_KERNEL);
		if (unlikely(!file)) {
			err = -ENOMEM;
			break; /* exit switch statement and thus return */
		}
		nd->intent.open.file = file;
	#endif /* ALLOC_LOWER_ND_FILE */
	break;
	default:
		/*
		 * We should never get here, for now.
		 * We can add new cases here later on.
		 */
		pr_debug("unionfs: unknown nameidata flag 0x%x\n", flags);
		BUG();
		break;
	}
	return err;
}




/*
 * create the new device/file/directory - use copyup_permission to copyup
 * times, and mode
 *
 * if the object being copied up is a regular file, the file is only created,
 * the contents have to be copied up separately
 */
static int __copyup_ndentry(struct dentry *old_lower_dentry,
			    struct dentry *new_lower_dentry,
			    struct dentry *new_lower_parent_dentry,
			    char *symbuf)
{
	int err = 0;
	struct nameidata nd;
	umode_t old_mode = old_lower_dentry->d_inode->i_mode;
	UDBG;
	printk(KERN_INFO "old_lower_dentry = %s\n",
				old_lower_dentry->d_name.name);
	printk(KERN_INFO "new_lower_dentry = %s\n",
				new_lower_dentry->d_name.name);
	printk(KERN_INFO "new_lower_parent_dentry = %s\n",
				new_lower_parent_dentry->d_name.name);
	if (S_ISDIR(old_mode)) {
		UDBG;
		err = vfs_mkdir(new_lower_parent_dentry->d_inode,
				new_lower_dentry,
				old_mode);
	} else if (S_ISLNK(old_mode)) {
		UDBG;
		err = vfs_symlink(new_lower_parent_dentry->d_inode,
					new_lower_dentry,
					symbuf);
	} else if (S_ISBLK(old_mode) || S_ISCHR(old_mode) ||
		   S_ISFIFO(old_mode) || S_ISSOCK(old_mode)) {
		UDBG;
		err = vfs_mknod(new_lower_parent_dentry->d_inode,
				new_lower_dentry,
				old_mode,
				old_lower_dentry->d_inode->i_rdev);
	} else if (S_ISREG(old_mode)) {
		UDBG;
		memset(&nd, 0, sizeof(struct nameidata));
		nd.intent.open.flags |= O_CREAT;
		err = init_lower_nd(&nd, LOOKUP_CREATE);
		if (unlikely(err < 0))
			goto out;
		err = vfs_create(new_lower_parent_dentry->d_inode,
				new_lower_dentry,
				old_mode, &nd);
	} else {
		UDBG;
		printk(KERN_CRIT "wrapfs: unknown inode type %d\n",
		       old_mode);
		BUG();
	}
out:
	return err;
}

static int __copyup_reg_data(struct dentry *dentry,
			     struct dentry *new_lower_dentry, int new_bindex,
			     struct dentry *old_lower_dentry, int old_bindex,
			     struct file **copyup_file, loff_t len)
{
	struct super_block *sb = dentry->d_sb;
	struct file *input_file;
	struct file *output_file;
	struct vfsmount *output_mnt, *mnt;
	mm_segment_t old_fs;
	char *buf = NULL;
	ssize_t read_bytes, write_bytes;
	loff_t size;
	int err = 0;
	struct path input_path, output_path;
	/* open old file */
	UDBG;
	printk(KERN_INFO "new_index = %d\n", new_bindex);
	printk(KERN_INFO "old_index = %d\n", old_bindex);
	printk(KERN_INFO "new_lower_dentry = %s\n",
			new_lower_dentry->d_name.name);
	printk(KERN_INFO "old_lower_dentry = %s\n",
				old_lower_dentry->d_name.name);
	mnt = mntget(wrapfs_lower_mnt_idx(dentry, old_bindex));
	branchget(sb, old_bindex);
	/* dentry_open calls dput and mntput if it returns an error */
	UDBG;
	input_path.dentry = old_lower_dentry;
	input_path.mnt = wrapfs_lower_mnt_idx(dentry, old_bindex);
	input_file = dentry_open(input_path.dentry, input_path.mnt,
				O_RDONLY | O_LARGEFILE, current_cred());
	path_put(&input_path);

	UDBG;
	if (IS_ERR(input_file)) {
		dput(old_lower_dentry);
		err = PTR_ERR(input_file);
		goto out;
	}
	UDBG;
	if (unlikely(!input_file->f_op || !input_file->f_op->read)) {
		err = -EINVAL;
		goto out_close_in;
	}

	/* open new file */
	UDBG;
	dget(new_lower_dentry);
	output_mnt = mntget(wrapfs_lower_mnt_idx(dentry, old_bindex));
	branchget(sb, new_bindex);
	output_path.dentry = new_lower_dentry;
	output_path.mnt = output_mnt;
	UDBG;
	output_file = dentry_open(new_lower_dentry, output_mnt,
				  O_RDWR | O_LARGEFILE, current_cred());
	UDBG;
	path_put(&output_path);
	if (IS_ERR(output_file)) {
		err = PTR_ERR(output_file);
		goto out_close_in2;
	}
	if (unlikely(!output_file->f_op || !output_file->f_op->write)) {
		err = -EINVAL;
		goto out_close_out;
	}

	/* allocating a buffer */
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (unlikely(!buf)) {
		err = -ENOMEM;
		goto out_close_out;
	}
	UDBG;
	input_file->f_pos = 0;
	output_file->f_pos = 0;
	UDBG;
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	size = len;
	err = 0;
	do {
		UDBG;
		if (len >= PAGE_SIZE)
			size = PAGE_SIZE;
		else if ((len < PAGE_SIZE) && (len > 0))
			size = len;

		len -= PAGE_SIZE;
		/*printk(KERN_INFO "len = %d\n", len);
		printk(KERN_INFO "size = %d\n", size);
		*/
		read_bytes =
			input_file->f_op->read(input_file,
					       (char __user *)buf, size,
					       &input_file->f_pos);
		UDBG;
		if (read_bytes <= 0) {
			err = read_bytes;
			break;
		}

		lockdep_off();
		write_bytes =
			output_file->f_op->write(output_file,
						 (char __user *)buf,
						 read_bytes,
						 &output_file->f_pos);
		UDBG;
		lockdep_on();
		if ((write_bytes < 0) || (write_bytes < read_bytes)) {
			err = write_bytes;
			break;
		}
	} while ((read_bytes > 0) && (len > 0));
	UDBG;
	set_fs(old_fs);

	kfree(buf);

#if 0
	/* XXX: code no longer needed? */
	if (!err)
		err = output_file->f_op->fsync(output_file, 0);
#endif

	if (err)
		goto out_close_out;
	UDBG;
	if (copyup_file) {
		*copyup_file = output_file;
		goto out_close_in;
	}

out_close_out:
	fput(output_file);

out_close_in2:
	branchput(sb, new_bindex);

out_close_in:
	fput(input_file);

out:	UDBG;
	branchput(sb, old_bindex);

	return err;
}

/*
 * dput the lower references for old and new dentry & clear a lower dentry
 * pointer
 */
static void __clear(struct dentry *dentry, struct dentry *old_lower_dentry,
		    int old_bstart, int old_bend,
		    struct dentry *new_lower_dentry, int new_bindex)
{
	/* get rid of the lower dentry and all its traces */
	UDBG;
	wrapfs_set_lower_dentry_idx(dentry, new_bindex, NULL);

	dput(new_lower_dentry);
	dput(old_lower_dentry);
}

/*
 * Copy up a dentry to a file of specified name.
 *
 * @dir: used to pull the ->i_sb to access other branches
 * @dentry: the non-negative dentry whose lower_inode we should copy
 * @bstart: the branch of the lower_inode to copy from
 * @new_bindex: the branch to create the new file in
 * @name: the name of the file to create
 * @namelen: length of @name
 * @copyup_file: the "struct file" to return (optional)
 * @len: how many bytes to copy-up?
 */
int copyup_dentry(struct inode *dir, struct dentry *dentry, int bstart,
		  int new_bindex, const char *name, int namelen,
		  struct file **copyup_file, loff_t len)
{
	struct dentry *new_lower_dentry;
	struct dentry *old_lower_dentry = NULL;
	struct super_block *sb;
	struct inode *inode;
	int err = 0;
	int old_bstart = 0;
	int old_bend = 1;
	int old_bindex = 1;
	struct dentry *new_lower_parent_dentry = NULL;
	mm_segment_t oldfs;
	char *symbuf = NULL;

	/*verify_locked(dentry);*/

	UDBG;
	printk(KERN_INFO "new_index = %d\n", new_bindex);
	printk(KERN_INFO "bstart = %d\n", bstart);
	printk(KERN_INFO "dentry_name = %s\n", dentry->d_name.name);
	printk(KERN_INFO "name = %s\n", name);

	sb = dir->i_sb;

	UDBG;
	/* Create the directory structure above this dentry. */
	new_lower_dentry = create_parents(dir, dentry, name, new_bindex);
	UDBG;
	printk(KERN_INFO "Create Parent Succedded\n");
	printk(KERN_INFO "new_index = %d\n", new_bindex);
	printk(KERN_INFO "old_index = %d\n", old_bindex);
	if (IS_ERR(new_lower_dentry)) {
		err = PTR_ERR(new_lower_dentry);
		goto out;
	}
	UDBG;
	old_lower_dentry = wrapfs_lower_dentry_idx(dentry, old_bindex);
	/* we conditionally dput this old_lower_dentry at end of function */
	UDBG;
	dget(old_lower_dentry);
	UDBG;
	/* For symlinks, we must read the link before we lock the directory. */
	if (S_ISLNK(old_lower_dentry->d_inode->i_mode)) {

		symbuf = kmalloc(PATH_MAX, GFP_KERNEL);
		if (unlikely(!symbuf)) {
			__clear(dentry, old_lower_dentry,
				old_bstart, old_bend,
				new_lower_dentry, new_bindex);
			err = -ENOMEM;
			goto out_free;
		}

		oldfs = get_fs();
		set_fs(KERNEL_DS);
		err = old_lower_dentry->d_inode->i_op->readlink(
			old_lower_dentry,
			(char __user *)symbuf,
			PATH_MAX);
		set_fs(oldfs);
		if (err < 0) {
			__clear(dentry, old_lower_dentry,
				old_bstart, old_bend,
				new_lower_dentry, new_bindex);
			goto out_free;
		}
		symbuf[err] = '\0';
	}
	UDBG;
	/* Now we lock the parent, and create the object in the new branch. */
	new_lower_parent_dentry = lock_parent(new_lower_dentry);
	UDBG;
	/* create the new inode */
	err = __copyup_ndentry(old_lower_dentry, new_lower_dentry,
			       new_lower_parent_dentry, symbuf);

	UDBG;
	if (err) {
		__clear(dentry, old_lower_dentry,
			old_bstart, old_bend,
			new_lower_dentry, new_bindex);
		goto out_unlock;
	}
	UDBG;
	/* We actually copyup the file here. */
	if (S_ISREG(old_lower_dentry->d_inode->i_mode))
		err = __copyup_reg_data(dentry, new_lower_dentry, new_bindex,
					old_lower_dentry, old_bindex,
					copyup_file, len);
	UDBG;
	if (err)
		goto out_unlink;
	UDBG;
	/* Set permissions. */
	err = copyup_permissions(sb, old_lower_dentry, new_lower_dentry);
	UDBG;
	if (err)
		goto out_unlink;

	goto out_unlock;

out_unlink:
	/*
	 * copyup failed, because we possibly ran out of space or
	 * quota, or something else happened so let's unlink; we don't
	 * really care about the return value of vfs_unlink
	 */
	UDBG;
	printk(KERN_INFO "Out_Unlink\n");
	vfs_unlink(new_lower_parent_dentry->d_inode, new_lower_dentry);

	if (copyup_file) {
		/* need to close the file */

		fput(*copyup_file);
		branchput(sb, new_bindex);
	}

	/*
	 * TODO: should we reset the error to something like -EIO?
	 *
	 * If we don't reset, the user may get some nonsensical errors, but
	 * on the other hand, if we reset to EIO, we guarantee that the user
	 * will get a "confusing" error message.
	 */

out_unlock:
	UDBG;
	unlock_dir(new_lower_parent_dentry);

out_free:
	/*
	 * If old_lower_dentry was not a file, then we need to dput it.  If
	 * it was a file, then it was already dput indirectly by other
	 * functions we call above which operate on regular files.
	 */
	UDBG;
	if (old_lower_dentry && old_lower_dentry->d_inode &&
	    !S_ISREG(old_lower_dentry->d_inode->i_mode))
		dput(old_lower_dentry);
	kfree(symbuf);

	if (err) {
		/*
		 * if directory creation succeeded, but inode copyup failed,
		 * then purge new dentries.
		 */
		UDBG;
		__clear(dentry, NULL, old_bstart, old_bend,
				wrapfs_lower_dentry(dentry), 0);
		goto out;
	}
	if (!S_ISDIR(dentry->d_inode->i_mode)) {
		UDBG;
		wrapfs_postcopyup_release(dentry);
		if (!wrapfs_lower_inode(dentry->d_inode)) {
			/*
			 * If we got here, then we copied up to an
			 * unlinked-open file, whose name is .wrapfsXXXXX.
			 */
			UDBG;
			inode = new_lower_dentry->d_inode;
			/*atomic_inc(&inode->i_count);*/
			wrapfs_set_lower_inode_idx(dentry->d_inode,
						    0,
						    inode);
			UDBG;
		}
	}
	UDBG;
	wrapfs_postcopyup_setmnt(dentry);
	/* sync inode times from copied-up inode to our inode */
/*	wrapfs_copy_attr_times(dentry->d_inode);
	wrapfs_check_inode(dir);
	wrapfs_check_dentry(dentry);*/
out:
	UDBG;
	return err;
}

/*
 * This function creates a copy of a file represented by 'file' which
 * currently resides in branch 'bstart' to branch 'new_bindex.'  The copy
 * will be named "name".
 */
int copyup_named_file(struct inode *dir, struct file *file, char *name,
		      int bstart, int new_bindex, loff_t len)
{
	int err = 0;
	struct file *output_file = NULL;

	err = copyup_dentry(dir, file->f_path.dentry, bstart, new_bindex,
			    name, strlen(name), &output_file, len);
	if (!err)
		wrapfs_set_lower_file_idx(file, new_bindex, output_file);


	return err;
}

/*
 * This function creates a copy of a file represented by 'file' which
 * currently resides in branch 'bstart' to branch 'new_bindex'.
 */
int copyup_file(struct inode *dir, struct file *file, int bstart,
		int new_bindex, loff_t len)
{
	int err = 0;
	struct file *output_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	UDBG;
	printk(KERN_INFO "new_index = %d\n", new_bindex);
	printk(KERN_INFO "bstart = %d\n", bstart);
	printk(KERN_INFO "file = %s\n", dentry->d_name.name);
	err = copyup_dentry(dir, dentry, bstart, new_bindex,
			    dentry->d_name.name, dentry->d_name.len,
			    &output_file, len);
	UDBG;
	if (!err)
		wrapfs_set_lower_file_idx(file, new_bindex, output_file);
	printk(KERN_INFO "success\n");
	UDBG;
	return err;
}

/* purge a dentry's lower-branch states (dput/mntput, etc.) */
static void __cleanup_dentry(struct dentry *dentry, int bindex,
			     int old_bstart, int old_bend)
{
	int loop_start;
	int loop_end;
	int i;

	loop_start = min(old_bstart, bindex);
	loop_end = max(old_bend, bindex);
	UDBG;
	/*
	 * This loop sets the bstart and bend for the new dentry by
	 * traversing from left to right.  It also dputs all negative
	 * dentries except bindex
	 */
	for (i = loop_start; i <= loop_end; i++) {
		UDBG;
		if (!wrapfs_lower_dentry_idx(dentry, i))
			continue;

		if (i == bindex)
			continue;
		UDBG;
		if (!wrapfs_lower_dentry_idx(dentry, i)->d_inode) {
			dput(wrapfs_lower_dentry_idx(dentry, i));
			wrapfs_set_lower_dentry_idx(dentry, i, NULL);

			mntput(wrapfs_lower_mnt_idx(dentry, bindex));
			wrapfs_set_lower_mnt_idx(dentry, i, NULL);
		}
	}

}

/* set lower inode ptr and update bstart & bend if necessary */
static void __set_inode(struct dentry *upper, struct dentry *lower,
			int bindex)
{
	wrapfs_set_lower_inode_idx(upper->d_inode, bindex,
				    igrab(lower->d_inode));

}

/* set lower dentry ptr and update bstart & bend if necessary */
static void __set_dentry(struct dentry *upper, struct dentry *lower,
			 int bindex)
{
	wrapfs_set_lower_dentry_idx(upper, bindex, lower);
}

/*
 * This function replicates the directory structure up-to given dentry
 * in the bindex branch.
 */
struct dentry *create_parents(struct inode *dir, struct dentry *dentry,
			      const char *name, int bindex)
{
	int err;
	struct dentry *child_dentry;
	struct dentry *parent_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct dentry *lower_dentry = NULL;
	const char *childname;
	unsigned int childnamelen;
	int nr_dentry;
	int count = 0;
	struct dentry **path = NULL;
	struct super_block *sb;

	/*verify_locked(dentry);*/

	lower_dentry = ERR_PTR(-ENOMEM);
	printk(KERN_INFO "In Create Parents\n");
	/* There is no sense allocating any less than the minimum. */
	nr_dentry = 1;
	path = kmalloc(nr_dentry * sizeof(struct dentry *), GFP_KERNEL);
	if (unlikely(!path))
		goto out;

	/* assume the negative dentry of wrapfs as the parent dentry */
	parent_dentry = dentry;

	/*
	 * This loop finds the first parent that exists in the given branch.
	 * We start building the directory structure from there.  At the end
	 * of the loop, the following should hold:
	 *  - child_dentry is the first nonexistent child
	 *  - parent_dentry is the first existent parent
	 *  - path[0] is the = deepest child
	 *  - path[count] is the first child to create
	 */
	do {
		UDBG;
		child_dentry = parent_dentry;
		UDBG;
		/* find the parent directory dentry in wrapfs */
		parent_dentry = dget_parent(child_dentry);
		UDBG;
		/* find out the lower_parent_dentry in the given branch */
		lower_parent_dentry =
			wrapfs_lower_dentry_idx(parent_dentry, bindex);

		UDBG;
		printk(KERN_INFO"parent = %s\n",
					lower_parent_dentry->d_name.name);
		printk(KERN_INFO"child = %s\n",
					child_dentry->d_name.name);
		/* grow path table */
		if (count == nr_dentry) {
			void *p;

			nr_dentry *= 2;
			p = krealloc(path, nr_dentry * sizeof(struct dentry *),
				     GFP_KERNEL);
			if (unlikely(!p)) {
				lower_dentry = ERR_PTR(-ENOMEM);
				goto out;
			}
			path = p;
		}

		/* store the child dentry */
		path[count++] = child_dentry;
	} while (!lower_parent_dentry->d_inode);
	count--;
	UDBG;
	printk(KERN_INFO"count = %d\n", count);
	sb = dentry->d_sb;

	/*
	 * This code goes between the begin/end labels and basically
	 * emulates a while(child_dentry != dentry), only cleaner and
	 * shorter than what would be a much longer while loop.
	 */
begin:
	/* get lower parent dir in the current branch */
	UDBG;
	lower_parent_dentry = wrapfs_lower_dentry_idx(parent_dentry, bindex);
	dput(parent_dentry);
	UDBG;
	/* init the values to lookup */
	childname = child_dentry->d_name.name;
	childnamelen = child_dentry->d_name.len;
	printk(KERN_INFO "dentry = %s\n", dentry->d_name.name);
	printk(KERN_INFO "child_dentry = %s\n", child_dentry->d_name.name);

	UDBG;
	if (child_dentry != dentry) {
		/* lookup child in the underlying file system */
		UDBG;
		lower_dentry = lookup_lck_len(childname, lower_parent_dentry,
					      childnamelen);
		UDBG;
		if (IS_ERR(lower_dentry))
			goto out;
	} else {
		/*
		 * Is the name a whiteout of the child name ?  lookup the
		 * whiteout child in the underlying file system
		 */
		UDBG;
		lower_dentry = lookup_lck_len(name, lower_parent_dentry,
					      strlen(name));
		UDBG;
		if (IS_ERR(lower_dentry))
			goto out;

		/* Replace the current dentry (if any) with the new one */
		dput(wrapfs_lower_dentry_idx(dentry, bindex));
		UDBG;
		wrapfs_set_lower_dentry_idx(dentry, bindex,
					     lower_dentry);
		UDBG;
		__cleanup_dentry(dentry, bindex, 0, 1);
		goto out;
	}

	if (lower_dentry->d_inode) {
		/*
		 * since this already exists we dput to avoid
		 * multiple references on the same dentry
		 */
		dput(lower_dentry);
	} else {

		/* it's a negative dentry, create a new dir */
		UDBG;
		printk(KERN_INFO "Its a negative dentry\n");
		lower_parent_dentry = lock_parent(lower_dentry);
		UDBG;
		err = vfs_mkdir(lower_parent_dentry->d_inode,
				lower_dentry,
				child_dentry->d_inode->i_mode);
		UDBG;
		if (!err)
			err = copyup_permissions(dir->i_sb, child_dentry,
						 lower_dentry);
		UDBG;
		unlock_dir(lower_parent_dentry);
		if (err) {
			dput(lower_dentry);
			lower_dentry = ERR_PTR(err);
			goto out;
		}
		UDBG;

	}

	__set_inode(child_dentry, lower_dentry, bindex);
	__set_dentry(child_dentry, lower_dentry, bindex);
	/*
	 * update times of this dentry, but also the parent, because if
	 * we changed, the parent may have changed too.
	 */
	UDBG;
	fsstack_copy_attr_times(parent_dentry->d_inode,
				lower_parent_dentry->d_inode);
	UDBG;
/*	fsstack_copy_attr_times(child_dentry->d_inode,
				lower_dentry->d_inode);
*/	UDBG;
	parent_dentry = child_dentry;
	child_dentry = path[--count];
	goto begin;
out:
	/* cleanup any leftover locks from the do/while loop above */
	if (IS_ERR(lower_dentry))
		while (count)
			dput(path[count--]);
	kfree(path);
	return lower_dentry;
}

/*
 * Post-copyup helper to ensure we have valid mnts: set lower mnt of
 * dentry+parents to the first parent node that has an mnt.
 */
void wrapfs_postcopyup_setmnt(struct dentry *dentry)
{
	struct dentry *parent, *hasone;
	int bindex = 0;
	UDBG;
	if (wrapfs_lower_mnt_idx(dentry, bindex))
		return;
	hasone = dentry->d_parent;
	/* this loop should stop at root dentry */
	UDBG;
	while (!wrapfs_lower_mnt_idx(hasone, bindex))
		hasone = hasone->d_parent;
	parent = dentry;
	UDBG;
	while (!wrapfs_lower_mnt_idx(parent, bindex)) {
		wrapfs_set_lower_mnt_idx(parent, bindex,
			mntget(wrapfs_lower_mnt_idx(hasone, bindex)));
		parent = parent->d_parent;
	}
}

/*
 * Post-copyup helper to release all non-directory source objects of a
 * copied-up file.  Regular files should have only one lower object.
 */
void wrapfs_postcopyup_release(struct dentry *dentry)
{

	BUG_ON(S_ISDIR(dentry->d_inode->i_mode));

/*	path_put_lowers(dentry,  0, 1, false);
	iput_lowers(dentry->d_inode, 0, 1, false);
*/
}
