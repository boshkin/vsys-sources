/*
 *  include/linux/faudit.h
 *
 *  Copyright (C) 2005  SWSoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __FAUDIT_H_
#define __FAUDIT_H_

#include <linux/virtinfo.h>

struct vfsmount;
struct dentry;
struct super_block;
struct kstatfs;
struct kstat;
struct pt_regs;

struct faudit_regs_arg {
	int err;
	struct pt_regs *regs;
};

struct faudit_stat_arg {
	int err;
	struct vfsmount *mnt;
	struct dentry *dentry;
	struct kstat *stat;
};

struct faudit_statfs_arg {
	int err;
	struct super_block *sb;
	struct kstatfs *stat;
};

#define VIRTINFO_FAUDIT			(0)
#define VIRTINFO_FAUDIT_STAT		(VIRTINFO_FAUDIT + 0)
#define VIRTINFO_FAUDIT_STATFS		(VIRTINFO_FAUDIT + 1)

#endif
