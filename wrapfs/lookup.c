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

/* Name		:Kunta Gautham Reddy (HW2)
 * Date		: 13-Apr-2014
 * Added        : Modified and added different functions and
 *                structures to support u2fs lookup.
 *
 */
#include "wrapfs.h"

/* The dentry cache is just so we have properly sized dentries */
static struct kmem_cache *wrapfs_dentry_cachep;


/* is the filename valid == !(whiteout for a file or opaque dir marker) */
bool is_validname(const char *name)
{
	printk(KERN_INFO"In is_validname name = %s\n", name);
	UDBG;
	if (!strncmp(name, ".wh.", 4))
		return false;
	UDBG;
	return true;
}

int __realloc_dentry_private_data(struct dentry *dentry)
{
	struct wrapfs_dentry_info *info = WRAPFS_D(dentry);
	void *p;
	int size;

	BUG_ON(!info);
	size = sizeof(struct path) * 2;
	p = krealloc(info->lower_paths, size, GFP_ATOMIC);
	if (unlikely(!p))
		return -ENOMEM;

	info->lower_paths = p;
	atomic_set(&info->generation,
		atomic_read(&WRAPFS_SB(dentry->d_sb)->generation));

	memset(info->lower_paths, 0, size);
	return 0;
}

int wrapfs_init_dentry_cache(void)
{
	wrapfs_dentry_cachep =
		kmem_cache_create("wrapfs_dentry",
				sizeof(struct wrapfs_dentry_info),
				0, SLAB_RECLAIM_ACCOUNT, NULL);

	return wrapfs_dentry_cachep ? 0 : -ENOMEM;
}

void wrapfs_destroy_dentry_cache(void)
{
	if (wrapfs_dentry_cachep)
		kmem_cache_destroy(wrapfs_dentry_cachep);
}

void free_dentry_private_data(struct dentry *dentry)
{
	if (!dentry || !dentry->d_fsdata)
		return;
	kmem_cache_free(wrapfs_dentry_cachep, dentry->d_fsdata);
	dentry->d_fsdata = NULL;
}

/* allocate new dentry private data */
int new_dentry_private_data(struct dentry *dentry)
{
	struct wrapfs_dentry_info *info = WRAPFS_D(dentry);

	/* use zalloc to init dentry_info.lower_path */
	info = kmem_cache_alloc(wrapfs_dentry_cachep, GFP_ATOMIC);
	if (!info)
		return -ENOMEM;
	/*spin_lock_init(&info->lock);*/

	info->lower_paths = NULL;
	dentry->d_fsdata = info;

	/* Realloc_dentry_private_data*/
	if (!__realloc_dentry_private_data(dentry))
		return 0;

	free_dentry_private_data(dentry);
	return -ENOMEM;
}


/*static int wrapfs_inode_test(struct inode *inode, void *candidate_lower_inode)
{
	struct inode *current_lower_inode = wrapfs_lower_inode(inode);
	if (current_lower_inode == (struct inode *)candidate_lower_inode)
		return 1;found a match
	else
		return 0;  no match
}

static int wrapfs_inode_set(struct inode *inode, void *lower_inode)
{
	we do actual inode initialization in wrapfs_iget
	return 0;
}
*/
struct inode *wrapfs_iget(struct super_block *sb, unsigned long ino)
{
	int size;
	struct wrapfs_inode_info *info;
	struct inode *inode;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	info = WRAPFS_I(inode);
	memset(info, 0, offsetof(struct wrapfs_inode_info, vfs_inode));
	atomic_set(&info->generation,
			atomic_read(&WRAPFS_SB(inode->i_sb)->generation));
	spin_lock_init(&info->rdlock);
	info->rdcount = 1;
	info->hashsize = -1;
	INIT_LIST_HEAD(&info->readdircache);

	size = 2 * sizeof(struct inode *);
	info->lower_inodes = kmalloc(size, GFP_KERNEL);
	if (unlikely(!info->lower_inodes)) {
		printk(KERN_CRIT "wrapfs: no kernel memory when allocating "
				"lower-pointer array!\n");
		iget_failed(inode);
		return ERR_PTR(-ENOMEM);
	}

	inode->i_version++;
	inode->i_op = &wrapfs_main_iops;
	inode->i_fop = &wrapfs_main_fops;

	inode->i_mapping->a_ops = &wrapfs_aops;

	inode->i_atime.tv_sec = inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_sec = inode->i_mtime.tv_nsec = 0;
	inode->i_ctime.tv_sec = inode->i_ctime.tv_nsec = 0;
	unlock_new_inode(inode);

	return inode;
}
/* Added by Gautham */

/*
 * Main driver function for wrapfs's lookup.
 *
 * Returns: NULL (ok), ERR_PTR if an error occurred.
 * Fills in lower_parent_path with <dentry,mnt> on success.
 */
static struct dentry *__wrapfs_lookup(struct dentry *dentry, int flags,
				      struct path *lower_parent_path, int idx)
{
	int err = 0;
	struct vfsmount *lower_dir_mnt = NULL;
	struct dentry *lower_dir_dentry = NULL;
	struct dentry *lower_dentry = NULL;
	const char *name;
	struct path lower_path;
	struct qstr this;

	printk(KERN_INFO" Wrapfs_lookup\n");

	/* must initialize dentry operations */
	d_set_d_op(dentry, &wrapfs_dops);

	UDBG;
	printk(KERN_INFO "parameters passed dentry = %s \t flags = %d \t"
			"path = %s idx = %d\n", dentry->d_name.name, flags,
				lower_parent_path->dentry->d_name.name, idx);
	if (IS_ROOT(dentry))
		goto out;

	name = dentry->d_name.name;
	/* now start the actual lookup procedure */
	lower_dir_dentry = lower_parent_path->dentry;
	lower_dir_mnt = lower_parent_path->mnt;

	/* Use vfs_path_lookup to check if the dentry exists or not */
	err = vfs_path_lookup(lower_dir_dentry, lower_dir_mnt, name, 0,
			      &lower_path);

	/* no error: handle positive dentries */
	if (!err) {
		UDBG;
		printk(KERN_INFO "Positive dentry idx=%d \t dentry = %s\n", idx,
						lower_path.dentry->d_name.name);
		UDBG;
		wrapfs_set_lower_path_idx(dentry, &lower_path, idx);
		err = wrapfs_interpose(dentry, dentry->d_sb,
						&lower_path);
		UDBG;
		if (err) /* path_put underlying path on error */
			wrapfs_put_reset_lower_path_idx(dentry, idx);
		goto out;
	}

	/*
	 * We don't consider ENOENT an error, and we want to return a
	 * negative dentry.
	 */
	if (err && err != -ENOENT) {
		printk(KERN_INFO "ENOENT Value for idx=%d\t dentry =%s\n",
					idx, lower_path.dentry->d_name.name);
		goto out;
	}
	/* instatiate a new negative dentry */
	UDBG;
	printk(KERN_INFO "Negative dentry idx=%d\t dentry = %s\n", idx,
					lower_path.dentry->d_name.name);
	this.name = name;
	this.len = strlen(name);
	this.hash = full_name_hash(this.name, this.len);
	lower_dentry = d_lookup(lower_dir_dentry, &this);
	printk(KERN_INFO "name = %s \t dentry = %s\n", this.name,
						dentry->d_name.name);
	UDBG;

	if (lower_dentry)
		goto setup_lower;
	UDBG;
	lower_dentry = d_alloc(lower_dir_dentry, &this);
	if (!lower_dentry) {
		err = -ENOMEM;
		goto out;
	}
	d_add(lower_dentry, NULL); /* instantiate and hash */
	UDBG;
setup_lower:
	UDBG;
	lower_path.dentry = lower_dentry;
	lower_path.mnt = mntget(lower_dir_mnt);
	wrapfs_set_lower_path_idx(dentry, &lower_path, idx);
	UDBG;
	mntput(lower_dir_mnt);
	UDBG;
	/*
	 * If the intent is to create a file, then don't return an error, so
	 * the VFS will continue the process of making this negative dentry
	 * into a positive one.
	 */
	if (flags & (LOOKUP_CREATE|LOOKUP_RENAME_TARGET))
		err = 0;

	printk(KERN_INFO"In __wrpafs_lookup completed successfully\n");
out:
	UDBG;
	return ERR_PTR(err);
}


struct dentry *wrapfs_lookup(struct inode *dir, struct dentry *dentry,
				struct nameidata *nd)
{
	struct dentry *ret = NULL, *parent = NULL;
	struct path lower_parent_path;
	int err = 0, i = 0;
	const char *name;

	printk(KERN_INFO "In wrpafs_lookup\n");
	BUG_ON(!nd);

	name = dentry->d_name.name;
	UDBG;
	if (!is_validname(name)) {
		UDBG;
		err = -EPERM;
		goto out;
	}

	printk(KERN_INFO "dentry = %s\n", dentry->d_name.name);
	err = new_dentry_private_data(dentry);
	if (err) {
		ret = ERR_PTR(err);
		goto out;
	}
	parent = dget_parent(dentry);
	printk(KERN_INFO "Parent dentry = %s\n", parent->d_name.name);
	for (i = 0; i <= 1; i++) {
		printk(KERN_INFO"i=%d\n", i);
		wrapfs_get_lower_path_idx(parent, &lower_parent_path, i);

		if (!lower_parent_path.dentry ||
			 !lower_parent_path.dentry->d_inode)
			continue;
		if (!S_ISDIR(lower_parent_path.dentry->d_inode->i_mode))
			continue;
		ret = __wrapfs_lookup(dentry, nd->flags,
						&lower_parent_path, i);

		if (IS_ERR(ret))
			continue;

		printk(KERN_INFO"i = %d\n", i);
		if (ret)
			dentry = ret;
		if (dentry->d_inode)
			fsstack_copy_attr_times(dentry->d_inode,
				wrapfs_lower_inode_idx(dentry->d_inode, i));
		/* update parent directory's atime */
		fsstack_copy_attr_atime(parent->d_inode,
			wrapfs_lower_inode_idx(parent->d_inode, i));
		UDBG;
		goto out;
	}

	printk(KERN_INFO "out_free i = %d\n", i);
	path_put_lowers_all(dentry, false);
	kfree(WRAPFS_D(dentry)->lower_paths);
	WRAPFS_D(dentry)->lower_paths = NULL;
out:
	UDBG;
	wrapfs_put_lower_path(parent, &lower_parent_path);
	dput(parent);
	printk(KERN_INFO "wrapfs_lookup successfull\n");
	return ret;
}
