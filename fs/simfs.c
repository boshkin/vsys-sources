/*
 *  fs/simfs.c
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/namei.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/vzquota.h>
#include <linux/statfs.h>
#include <linux/virtinfo.h>
#include <linux/faudit.h>
#include <linux/genhd.h>
#include <linux/reiserfs_fs.h>

#include <asm/unistd.h>
#include <asm/uaccess.h>

#define SIMFS_GET_LOWER_FS_SB(sb) sb->s_root->d_sb

static struct super_operations sim_super_ops;

static int sim_getattr(struct vfsmount *mnt, struct dentry *dentry,
		struct kstat *stat)
{
	struct super_block *sb;
	struct inode *inode;

	inode = dentry->d_inode;
	if (!inode->i_op->getattr) {
		generic_fillattr(inode, stat);
		if (!stat->blksize) {
			unsigned blocks;

			sb = inode->i_sb;
			blocks = (stat->size + sb->s_blocksize-1) >>
				sb->s_blocksize_bits;
			stat->blocks = (sb->s_blocksize / 512) * blocks;
			stat->blksize = sb->s_blocksize;
		}
	} else {
		int err;

		err = inode->i_op->getattr(mnt, dentry, stat);
		if (err)
			return err;
	}

	if (!mnt)
		return 0;
	sb = mnt->mnt_sb;
	if (sb->s_op == &sim_super_ops)
		stat->dev = sb->s_dev;
	return 0;
}

static void quota_get_stat(struct super_block *sb, struct kstatfs *buf)
{
	int err;
	struct dq_stat qstat;
	struct virt_info_quota q;
	long free_file, adj_file;
	s64 blk, free_blk, adj_blk;
	int bsize_bits;

	q.super = sb;
	q.qstat = &qstat;
	err = virtinfo_notifier_call(VITYPE_QUOTA, VIRTINFO_QUOTA_GETSTAT, &q);
	if (err != NOTIFY_OK)
		return;

	bsize_bits = ffs(buf->f_bsize) - 1;
	
	if (qstat.bsoftlimit > qstat.bcurrent)
		free_blk = (qstat.bsoftlimit - qstat.bcurrent) >> bsize_bits;
	else
		free_blk = 0;
	/*
	 * In the regular case, we always set buf->f_bfree and buf->f_blocks to
	 * the values reported by quota.  In case of real disk space shortage,
	 * we adjust the values.  We want this adjustment to look as if the
	 * total disk space were reduced, not as if the usage were increased.
	 *    -- SAW
	 */
	adj_blk = 0;
	if (buf->f_bfree < free_blk)
		adj_blk = free_blk - buf->f_bfree;
	buf->f_bfree = free_blk - adj_blk;

	if (free_blk < buf->f_bavail)
		buf->f_bavail = free_blk;

	blk = (qstat.bsoftlimit >> bsize_bits) - adj_blk;
	buf->f_blocks = blk > LONG_MAX ? LONG_MAX : blk;

	free_file = qstat.isoftlimit - qstat.icurrent;
	if (free_file < 0)
		free_file = 0;
	if (buf->f_type == REISERFS_SUPER_MAGIC)
		/*
		 * reiserfs doesn't initialize f_ffree and f_files values of
		 * kstatfs because it doesn't have an inode limit.
		 */
		buf->f_ffree = free_file;
	adj_file = 0;
	if (buf->f_ffree < free_file)
		adj_file = free_file - buf->f_ffree;
	buf->f_ffree = free_file - adj_file;
	buf->f_files = qstat.isoftlimit - adj_file;
}

static int sim_statfs(struct super_block *sb, struct kstatfs *buf)
{
	int err;
	struct super_block *lsb;
	struct kstatfs statbuf;

	err = 0;
	if (sb->s_op != &sim_super_ops)
		return 0;

	memset(&statbuf, 0, sizeof(statbuf));
	lsb = SIMFS_GET_LOWER_FS_SB(sb);

	err = -ENOSYS;
	if (lsb && lsb->s_op && lsb->s_op->statfs)
		err = lsb->s_op->statfs(sb->s_root, &statbuf);
	if (err)
		return err;

	quota_get_stat(sb, &statbuf);

	buf->f_files    = statbuf.f_files;
	buf->f_ffree    = statbuf.f_ffree;
	buf->f_blocks   = statbuf.f_blocks;
	buf->f_bfree    = statbuf.f_bfree;
	buf->f_bavail   = statbuf.f_bavail;
	return 0;
}

static int sim_systemcall(struct vnotifier_block *me, unsigned long n,
		void *d, int old_ret)
{
	int err;

	switch (n) {
	case VIRTINFO_FAUDIT_STAT: {
		struct faudit_stat_arg *arg;

		arg = (struct faudit_stat_arg *)d;
		err = sim_getattr(arg->mnt, arg->dentry, arg->stat);
		arg->err = err;
		}
		break;
	case VIRTINFO_FAUDIT_STATFS: {
		struct faudit_statfs_arg *arg;

		arg = (struct faudit_statfs_arg *)d;
		err = sim_statfs(arg->sb, arg->stat);
		arg->err = err;
		}
		break;
	default:
		return old_ret;
	}
	return (err ? NOTIFY_BAD : NOTIFY_OK);
}

#ifdef CONFIG_QUOTA
static struct inode *sim_quota_root(struct super_block *sb)
{
	return sb->s_root->d_inode;
}
#endif

/*
 * NOTE: We need to setup s_bdev field on super block, since sys_quotactl()
 * does lookup_bdev() and get_super() which are comparing sb->s_bdev.
 * so this is a MUST if we want unmodified sys_quotactl
 * to work correctly on /dev/simfs inside VE
 */
static int sim_init_blkdev(struct super_block *sb)
{
	static struct hd_struct fake_hd;
	struct block_device *blkdev;

	blkdev = bdget(sb->s_dev);
	if (blkdev == NULL)
		return -ENOMEM;

	blkdev->bd_part = &fake_hd;	/* required for bdev_read_only() */
	sb->s_bdev = blkdev;

	return 0;
}

static void sim_free_blkdev(struct super_block *sb)
{
	/* set bd_part back to NULL */
	sb->s_bdev->bd_part = NULL;
	bdput(sb->s_bdev);
}

static void sim_quota_init(struct super_block *sb)
{
	struct virt_info_quota viq;

	viq.super = sb;
	virtinfo_notifier_call(VITYPE_QUOTA, VIRTINFO_QUOTA_ON, &viq);
}

static void sim_quota_free(struct super_block *sb)
{
	struct virt_info_quota viq;

	viq.super = sb;
	virtinfo_notifier_call(VITYPE_QUOTA, VIRTINFO_QUOTA_OFF, &viq);
}

static struct super_operations sim_super_ops = {
#ifdef CONFIG_QUOTA
	.get_quota_root	= sim_quota_root,
#endif
};

static int sim_fill_super(struct super_block *s, void *data)
{
	int err;
	struct nameidata *nd;

	err = set_anon_super(s, NULL);
	if (err)
		goto out;

	err = 0;
	nd = (struct nameidata *)data;
	s->s_fs_info = mntget(nd->path.mnt);
	s->s_root = dget(nd->path.dentry);
	s->s_op = &sim_super_ops;
out:
	return err;
}

static int sim_get_sb(struct file_system_type *type, int flags,
		const char *dev_name, void *opt, struct vfsmount *mnt)
{
	int err;
	struct nameidata nd;
	struct super_block *sb;

	err = -EINVAL;
	if (opt == NULL)
		goto out;

	err = path_lookup(opt, LOOKUP_FOLLOW|LOOKUP_DIRECTORY, &nd);
	if (err)
		goto out;

	sb = sget(type, NULL, sim_fill_super, &nd);
	err = PTR_ERR(sb);
	if (IS_ERR(sb))
		goto out_path;

	err = sim_init_blkdev(sb);
	if (err)
		goto out_killsb;

	sim_quota_init(sb);

	path_put(&nd.path);
	simple_set_mnt(mnt, sb);
	return 0;

out_killsb:
	up_write(&sb->s_umount);
	deactivate_super(sb);
out_path:
	path_put(&nd.path);
out:
	return err;
}

static void sim_kill_sb(struct super_block *sb)
{
	dput(sb->s_root);
	sb->s_root = NULL;
	mntput((struct vfsmount *)(sb->s_fs_info));

	sim_quota_free(sb);
	sim_free_blkdev(sb);

	kill_anon_super(sb);
}

static struct file_system_type sim_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "simfs",
	.get_sb		= sim_get_sb,
	.kill_sb	= sim_kill_sb,
	.fs_flags	= FS_MANGLE_PROC,
};

static struct vnotifier_block sim_syscalls = {
	.notifier_call = sim_systemcall,
};

static int __init init_simfs(void)
{
	int err;

	err = register_filesystem(&sim_fs_type);
	if (err)
		return err;

	virtinfo_notifier_register(VITYPE_FAUDIT, &sim_syscalls);
	return 0;
}

static void __exit exit_simfs(void)
{
	virtinfo_notifier_unregister(VITYPE_FAUDIT, &sim_syscalls);
	unregister_filesystem(&sim_fs_type);
}

MODULE_AUTHOR("SWsoft <info@sw-soft.com>");
MODULE_DESCRIPTION("Open Virtuozzo Simulation of File System");
MODULE_LICENSE("GPL v2");

module_init(init_simfs);
module_exit(exit_simfs);
