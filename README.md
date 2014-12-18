Subject      : Homework Assignment #2
Name         : Gautham Reddy Kunta
Date         : APR-13-2014

u2fs :
======
u2fs is a stackable unification file system, which can appear to merge the 
contents of two directories (branches), while keeping their physical content 
separate.

GENERAL SYNTAX
==============
 mount -t u2fs -o <BRANCH-OPTIONS> none MOUNTPOINT

BRANCH-OPTIONS are two directory paths ldir and rdir.
1.	u2fs has only two branches, which are identify as the "left branch" (LB
	and the "right branch" (RB). 
2.	 LB has higher priority than RB.  RB should be assumed to be readonly:
	 that is, no file there should be modified, as if it came, say, 
	 from a readonly CDROM;files should be modified in LB only. 

 Pictorially, this could be seen as follows:

                u2fs
                 /\
                /  \
               /    \
             LB      RB

 "ldir=<path>,rdir=<path>"

The syntax for the "ldir=<path>,rdir=<path>" mount option is:

	ldir=/left/dir,rdir=/right/dir

Syntax for mount:
=================
 mount -t u2fs -o ldir=/left/dir,rdir=<paht> null <mount_point>


U2FS FUNCTIONALITY:
==================

Whiteouts:
==========

A whiteout removes a file name from the namespace. Whiteouts are needed when
one attempts to remove a file on a read-only branch.

Suppose we have a two-branch union, where branch 0 is read-write and branch
1 is read-only. And a file 'foo' on branch 1:

./b0/
./b1/
./b1/foo

The unified view would simply be:

./union/
./union/foo

Since 'foo' is stored on a read-only branch, it cannot be removed. A
whiteout is used to remove the name 'foo' from the unified namespace. Again,
since branch 1 is read-only, the whiteout cannot be created there. So, we
try on a higher priority (lower numerically) branch and create the whiteout
there.

./b0/
./b0/.wh.foo
./b1/
./b1/foo

 -->	Added code to create a whiteout for the files which are deleted in the 
	right branch
 -->	used some part of the code from the unionfs and added logic for handling
	the display in the readdir functionality. 

CopyUp:
=====

In writeable mount, u2fs will create new files/dir in the leftmost i.e ldir
branch.  If one tries to modify a file in a read-only branch/media, u2fs
will copyup the file to the leftmost branch and modify it there.  If you try
to modify a file from a right branch which is not the left branch, we copy the
file into the left branch and perform the edit.

Implementation:
==============
	u2fs is modified version of wrapfs with added functionality to u2fs
	branches. The changes done in different file are 

 1.	Modified the mount logic of the wrapfs to accomodate the two branches
	left and right branches. Used the unionfs logic for parsing the mount
	parameters.

 2.	Modified the lookup logic to for parsing for two branches and updated
	the different structures inode_info, file_info, dentry_info etc to
	accomodate the u2fs requirement of two branches.

 3.	Added logic for handling the deletion of files in right branch through 
	whiteout creation of the files in left branch.

 4.	Added logic for eliminating the diplay of duplicates and whiteout
	entries.
	It only displays the contents of left file if a file is present in
	both branches. And if a file in right branch has a whiteout entry in 
	the left branch then we dont display the file.

 5.	Files can be modified in both the branches.
	Files in left side are modified directly while operations on 
	right branch can be done directly so we copy up the file in the 
	left branch and modify it. (CopyUp Logic).


References:
===========
Unionfs
wrapfs
