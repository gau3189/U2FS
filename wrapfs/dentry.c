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


/* Name		: Kunta Gautham Reddy (HW2)
 * Date		: 13-Apr-2014
 * Added        : Modified and added different functions and
 *                structures to support u2fs.
 *
 */
#include "wrapfs.h"

/*
 * returns: -ERRNO if error (returned to user)
 *          0: tell VFS to invalidate dentry
 *          1: dentry is valid
 */
/*static int wrapfs_d_revalidate(struct dentry *dentry, struct nameidata *nd)
{
	int err = 1;
*/	/*struct path lower_path, saved_path;
	struct dentry *lower_dentry;
	int i = 0;
	bool valid = true;
	printk("Entered d_revalidate method\n");
	if (nd && nd->flags & LOOKUP_RCU)
		return -ECHILD;

	for (i = 0; i <= 1; i++) {
		printk(KERN_INFO"i = %d\n",i);
		lower_dentry = wrapfs_lower_dentry_idx(dentry, i);
		if (!lower_dentry || !lower_dentry->d_op
			|| !lower_dentry->d_op->d_revalidate)
			continue;
	}
	if (!dentry->d_inode) {
		valid = false;
		goto out;
	}

	if (valid) {
		printk(KERN_INFO" valid = %d\n",valid);
		fsstack_copy_attr_all(dentry->d_inode,
				wrapfs_lower_inode(dentry->d_inode));
		fsstack_copy_inode_size(dentry->d_inode,
				wrapfs_lower_inode(dentry->d_inode));
	}
	printk(KERN_INFO" successful done\n");
out :
	return valid;
*//*
	printk("path = %s\n",WRAPFS_D(dentry)->lower_paths[0]);
	wrapfs_get_lower_path(dentry, &lower_path);

	printk(" wrapfs_get_lower_path successful\n %s",
				lower_path.dentry->d_name.name);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_op || !lower_dentry->d_op->d_revalidate)
		goto out;

	pathcpy(&saved_path, &nd->path);
	pathcpy(&nd->path, &lower_path);
	printk(" pathcpy successful\n");
	err = lower_dentry->d_op->d_revalidate(lower_dentry, nd);
	pathcpy(&nd->path, &saved_path);
out:
	printk(" In out calling wrapfs_put_lower_path\n");
	wrapfs_put_lower_path(dentry, &lower_path);
*/
/*	return err;

}*/

static void wrapfs_d_release(struct dentry *dentry)
{
	if (!dentry)
		goto out;
	if (unlikely(!WRAPFS_D(dentry)))
		goto out;
	UDBG;
/*	wrapfs_lock_dentry(dentry, WRAPFS_DMUTEX_CHILD);
	path_put_lowers_all(dentry, true); */
	UDBG;
	/* release and reset the lower paths */
/*	wrapfs_put_reset_lower_path(dentry);
	wrpafs_unlock_dentry(dentry);
*/
out:
	free_dentry_private_data(dentry);
	return;
}

const struct dentry_operations wrapfs_dops = {
/*	.d_revalidate	= wrapfs_d_revalidate, */
	.d_release	= wrapfs_d_release,
};
