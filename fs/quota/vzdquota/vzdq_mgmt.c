/*
 * Copyright (C) 2001, 2002, 2004, 2005  SWsoft
 * All rights reserved.
 * 
 * Licensing governed by "linux/COPYING.SWsoft" file.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/writeback.h>
#include <linux/gfp.h>
#include <linux/module.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/quota.h>
#include <linux/vzctl_quota.h>
#include <linux/vzquota.h>


/* ----------------------------------------------------------------------
 * Switching quota on.
 * --------------------------------------------------------------------- */

/*
 * check limits copied from user
 */
int vzquota_check_sane_limits(struct dq_stat *qstat)
{
	int err;

	err = -EINVAL;

	/* softlimit must be less then hardlimit */
	if (qstat->bsoftlimit > qstat->bhardlimit)
		goto out;

	if (qstat->isoftlimit > qstat->ihardlimit)
		goto out;

	err = 0;
out:
	return err;
}

/*
 * check usage values copied from user
 */
int vzquota_check_sane_values(struct dq_stat *qstat)
{
	int err;

	err = -EINVAL;

	/* expiration time must not be set if softlimit was not exceeded */
	if (qstat->bcurrent < qstat->bsoftlimit && qstat->btime != 0)
		goto out;

	if (qstat->icurrent < qstat->isoftlimit && qstat->itime != 0)
		goto out;

	err = vzquota_check_sane_limits(qstat);
out:
	return err;
}

/*
 * create new quota master block
 * this function should:
 *  - copy limits and usage parameters from user buffer;
 *  - allock, initialize quota block and insert it to hash;
 */
static int vzquota_create(unsigned int quota_id,
		struct vz_quota_stat __user *u_qstat, int compat)
{
	int err;
	struct vz_quota_stat qstat;
	struct vz_quota_master *qmblk;

	mutex_lock(&vz_quota_mutex);

	err = -EFAULT;
	if (!compat) {
		if (copy_from_user(&qstat, u_qstat, sizeof(qstat)))
			goto out;
	} else {
#ifdef CONFIG_COMPAT
		struct compat_vz_quota_stat cqstat;
		if (copy_from_user(&cqstat, u_qstat, sizeof(cqstat)))
			goto out;
		compat_dqstat2dqstat(&cqstat.dq_stat, &qstat.dq_stat);
		compat_dqinfo2dqinfo(&cqstat.dq_info, &qstat.dq_info);
#endif
	}

	err = -EINVAL;
	if (quota_id == 0)
		goto out;

	if (vzquota_check_sane_values(&qstat.dq_stat))
		goto out;
	err = 0;
	qmblk = vzquota_alloc_master(quota_id, &qstat);

	if (IS_ERR(qmblk)) /* ENOMEM or EEXIST */
		err = PTR_ERR(qmblk);
out:
	mutex_unlock(&vz_quota_mutex);

	return err;
}

/**
 * vzquota_on - turn quota on
 *
 * This function should:
 *  - find and get refcnt of directory entry for quota root and corresponding
 *    mountpoint;
 *  - find corresponding quota block and mark it with given path;
 *  - check quota tree;
 *  - initialize quota for the tree root.
 */
static int vzquota_on(unsigned int quota_id, const char __user *quota_root,
					char __user *buf)
{
	int err;
	struct path path;
	struct vz_quota_master *qmblk;
	struct super_block *dqsb;

	dqsb = NULL;
	mutex_lock(&vz_quota_mutex);

	err = -ENOENT;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;

	err = -EBUSY;
	if (qmblk->dq_state != VZDQ_STARTING)
		goto out;

	err = user_path(quota_root, &path);
	if (err)
		goto out;
	/* init path must be a directory */
	err = -ENOTDIR;
	if (!S_ISDIR(path.dentry->d_inode->i_mode))
		goto out_path;

	qmblk->dq_root_path = path;
	qmblk->dq_sb = path.dentry->d_inode->i_sb;
	err = vzquota_get_super(qmblk->dq_sb);
	if (err)
		goto out_super;

	/*
	 * Serialization with quota initialization and operations is performed
	 * through generation check: generation is memorized before qmblk is
	 * found and compared under inode_qmblk_lock with assignment.
	 *
	 * Note that the dentry tree is shrunk only for high-level logical
	 * serialization, purely as a courtesy to the user: to have consistent
	 * quota statistics, files should be closed etc. on quota on.
	 */
	err = vzquota_on_qmblk(qmblk->dq_sb, qmblk->dq_root_path.dentry->d_inode,
			qmblk, buf);
	if (err)
		goto out_init;
	qmblk->dq_state = VZDQ_WORKING;

	mutex_unlock(&vz_quota_mutex);
	return 0;

out_init:
	dqsb = qmblk->dq_sb;
out_super:
	/* clear for qmblk_put/quota_free_master */
	qmblk->dq_sb = NULL;
	qmblk->dq_root_path.dentry = NULL;
	qmblk->dq_root_path.mnt = NULL;
out_path:
	path_put(&path);
out:
	if (dqsb)
		vzquota_put_super(dqsb);
	mutex_unlock(&vz_quota_mutex);
	return err;
}


/* ----------------------------------------------------------------------
 * Switching quota off.
 * --------------------------------------------------------------------- */

/*
 * destroy quota block by ID
 */
static int vzquota_destroy(unsigned int quota_id)
{
	int err;
	struct vz_quota_master *qmblk;
	struct path root;

	mutex_lock(&vz_quota_mutex);

	err = -ENOENT;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;

	err = -EBUSY;
	if (qmblk->dq_state == VZDQ_WORKING)
		goto out; /* quota_off first */

	list_del_init(&qmblk->dq_hash);
	root = qmblk->dq_root_path;
	qmblk->dq_root_path.dentry = NULL;
	qmblk->dq_root_path.mnt = NULL;

	if (qmblk->dq_sb)
		vzquota_put_super(qmblk->dq_sb);
	mutex_unlock(&vz_quota_mutex);

	qmblk_put(qmblk);
	path_put(&root);
	return 0;

out:
	mutex_unlock(&vz_quota_mutex);
	return err;
}

/**
 * vzquota_off - turn quota off
 */

static int __vzquota_sync_list(struct list_head *lh,
		struct vz_quota_master *qmblk,
		enum writeback_sync_modes sync_mode)
{
	struct writeback_control wbc;
	LIST_HEAD(list);
	struct vz_quota_ilink *qlnk;
	struct inode *inode;
	int err, ret;

	memset(&wbc, 0, sizeof(wbc));
	wbc.sync_mode = sync_mode;

	err = ret = 0;
	while (!list_empty(lh)) {
		if (need_resched()) {
			inode_qmblk_unlock(qmblk->dq_sb);
			schedule();
			inode_qmblk_lock(qmblk->dq_sb);
			continue;
		}

		qlnk = list_first_entry(lh, struct vz_quota_ilink, list);
		list_move(&qlnk->list, &list);

		inode = igrab(QLNK_INODE(qlnk));
		if (!inode)
			continue;

		inode_qmblk_unlock(qmblk->dq_sb);

		wbc.nr_to_write = LONG_MAX;
		ret = sync_inode(inode, &wbc);
		if (ret)
			err = ret;
		iput(inode);

		inode_qmblk_lock(qmblk->dq_sb);
	}

	list_splice(&list, lh);
	return err;
}

static int vzquota_sync_list(struct list_head *lh,
		struct vz_quota_master *qmblk)
{
	(void)__vzquota_sync_list(lh, qmblk, WB_SYNC_NONE);
	return __vzquota_sync_list(lh, qmblk, WB_SYNC_ALL);
}

static int vzquota_sync_inodes(struct vz_quota_master *qmblk)
{
	int err;
	LIST_HEAD(qlnk_list);

	list_splice_init(&qmblk->dq_ilink_list, &qlnk_list);
	err = vzquota_sync_list(&qlnk_list, qmblk);
	if (!err && !list_empty(&qmblk->dq_ilink_list))
		err = -EBUSY;
	list_splice(&qlnk_list, &qmblk->dq_ilink_list);

	return err;
}

static int vzquota_off(unsigned int quota_id, char __user *buf, int force)
{
	int err, ret;
	struct vz_quota_master *qmblk;

	mutex_lock(&vz_quota_mutex);

	err = -ENOENT;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;

	err = -EALREADY;
	if (qmblk->dq_state != VZDQ_WORKING)
		goto out;

	inode_qmblk_lock(qmblk->dq_sb); /* protects dq_ilink_list also */
	ret = vzquota_sync_inodes(qmblk);
	inode_qmblk_unlock(qmblk->dq_sb);

	err = vzquota_off_qmblk(qmblk->dq_sb, qmblk, buf, force);
	if (err)
		goto out;

	err = ret;
	/* vzquota_destroy will free resources */
	qmblk->dq_state = VZDQ_STOPING;
out:
	mutex_unlock(&vz_quota_mutex);

	return err;
}


/* ----------------------------------------------------------------------
 * Other VZQUOTA ioctl's.
 * --------------------------------------------------------------------- */

/*
 * this function should:
 * - set new limits/buffer under quota master block lock
 * - if new softlimit less then usage, then set expiration time
 * - no need to alloc ugid hash table - we'll do that on demand
 */
int vzquota_update_limit(struct dq_stat *_qstat,
		struct dq_stat *qstat)
{
	int err;

	err = -EINVAL;
	if (vzquota_check_sane_limits(qstat))
		goto out;

	err = 0;

	/* limits */
	_qstat->bsoftlimit = qstat->bsoftlimit;
	_qstat->bhardlimit = qstat->bhardlimit;
	/*
	 * If the soft limit is exceeded, administrator can override the moment
	 * when the grace period for limit exceeding ends.
	 * Specifying the moment may be useful if the soft limit is set to be
	 * lower than the current usage.  In the latter case, if the grace
	 * period end isn't specified, the grace period will start from the
	 * moment of the first write operation.
	 * There is a race with the user level.  Soft limit may be already
	 * exceeded before the limit change, and grace period end calculated by
	 * the kernel will be overriden.  User level may check if the limit is
	 * already exceeded, but check and set calls are not atomic.
	 * This race isn't dangerous.  Under normal cicrumstances, the
	 * difference between the grace period end calculated by the kernel and
	 * the user level should be not greater than as the difference between
	 * the moments of check and set calls, i.e. not bigger than the quota
	 * timer resolution - 1 sec.
	 */
	if (qstat->btime != (time_t)0 &&
			_qstat->bcurrent >= _qstat->bsoftlimit)
		_qstat->btime = qstat->btime;

	_qstat->isoftlimit = qstat->isoftlimit;
	_qstat->ihardlimit = qstat->ihardlimit;
	if (qstat->itime != (time_t)0 &&
			_qstat->icurrent >= _qstat->isoftlimit)
		_qstat->itime = qstat->itime;

out:
	return err;
}

/*
 * set new quota limits.
 * this function should:
 *  copy new limits from user level
 *  - find quota block
 *  - set new limits and flags.
 */
static int vzquota_setlimit(unsigned int quota_id,
		struct vz_quota_stat __user *u_qstat, int compat)
{
	int err;
	struct vz_quota_stat qstat;
	struct vz_quota_master *qmblk;

	mutex_lock(&vz_quota_mutex); /* for hash list protection */

	err = -ENOENT;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;

	err = -EFAULT;
	if (!compat) {
		if (copy_from_user(&qstat, u_qstat, sizeof(qstat)))
			goto out;
	} else {
#ifdef CONFIG_COMPAT
		struct compat_vz_quota_stat cqstat;
		if (copy_from_user(&cqstat, u_qstat, sizeof(cqstat)))
			goto out;
		compat_dqstat2dqstat(&cqstat.dq_stat, &qstat.dq_stat);
		compat_dqinfo2dqinfo(&cqstat.dq_info, &qstat.dq_info);
#endif
	}

	qmblk_data_write_lock(qmblk);
	err = vzquota_update_limit(&qmblk->dq_stat, &qstat.dq_stat);
	if (err == 0)
		qmblk->dq_info = qstat.dq_info;
	qmblk_data_write_unlock(qmblk);

out:
	mutex_unlock(&vz_quota_mutex);
	return err;
}

/*
 * get quota limits.
 * very simple - just return stat buffer to user
 */
static int vzquota_getstat(unsigned int quota_id,
		struct vz_quota_stat __user *u_qstat, int compat)
{
	int err;
	struct vz_quota_stat qstat;
	struct vz_quota_master *qmblk;

	mutex_lock(&vz_quota_mutex);

	err = -ENOENT;
	qmblk = vzquota_find_master(quota_id);
	if (qmblk == NULL)
		goto out;

	qmblk_data_read_lock(qmblk);
	/* copy whole buffer under lock */
	memcpy(&qstat.dq_stat, &qmblk->dq_stat, sizeof(qstat.dq_stat));
	memcpy(&qstat.dq_info, &qmblk->dq_info, sizeof(qstat.dq_info));
	qmblk_data_read_unlock(qmblk);

	if (!compat)
		err = copy_to_user(u_qstat, &qstat, sizeof(qstat));
	else {
#ifdef CONFIG_COMPAT
		struct compat_vz_quota_stat cqstat;
		dqstat2compat_dqstat(&qstat.dq_stat, &cqstat.dq_stat);
		dqinfo2compat_dqinfo(&qstat.dq_info, &cqstat.dq_info);
		err = copy_to_user(u_qstat, &cqstat, sizeof(cqstat));
#endif
	}
	if (err)
		err = -EFAULT;

out:
	mutex_unlock(&vz_quota_mutex);
	return err;
}

/*
 * This is a system call to turn per-VE disk quota on.
 * Note this call is allowed to run ONLY from VE0
 */
long do_vzquotactl(int cmd, unsigned int quota_id,
		struct vz_quota_stat __user *qstat, const char __user *ve_root,
		int compat)
{
	int ret;
	int force = 0;

	ret = -EPERM;
	/* access allowed only from root of VE0 */
	if (!capable(CAP_SYS_RESOURCE) ||
	    !capable(CAP_SYS_ADMIN))
		goto out;

	switch (cmd) {
		case VZ_DQ_CREATE:
			ret = vzquota_create(quota_id, qstat, compat);
			break;
		case VZ_DQ_DESTROY:
			ret = vzquota_destroy(quota_id);
			break;
		case VZ_DQ_ON:
			/* 
			 * qstat is just a pointer to userspace buffer to
			 * store busy files path in case of vzquota_on fail
			 */
			ret = vzquota_on(quota_id, ve_root, (char *)qstat);
			break;
		case VZ_DQ_OFF_FORCED:
			force = 1;
		case VZ_DQ_OFF:
			/* 
			 * ve_root is just a pointer to userspace buffer to
			 * store busy files path in case of vzquota_off fail
			 */
			ret = vzquota_off(quota_id, (char *)ve_root, force);
			break;
		case VZ_DQ_SETLIMIT:
			ret = vzquota_setlimit(quota_id, qstat, compat);
			break;
		case VZ_DQ_GETSTAT:
			ret = vzquota_getstat(quota_id, qstat, compat);
			break;

		default:
			ret = -EINVAL;
			goto out;
	}

out:
	return ret;
}


/* ----------------------------------------------------------------------
 * Proc filesystem routines
 * ---------------------------------------------------------------------*/

#if defined(CONFIG_PROC_FS)

#define QUOTA_UINT_LEN		15
#define QUOTA_TIME_LEN_FMT_UINT	"%11u"
#define QUOTA_NUM_LEN_FMT_UINT	"%15u"
#define QUOTA_NUM_LEN_FMT_ULL	"%15Lu"
#define QUOTA_TIME_LEN_FMT_STR	"%11s"
#define QUOTA_NUM_LEN_FMT_STR	"%15s"
#define QUOTA_PROC_MAX_LINE_LEN 2048

/*
 * prints /proc/ve_dq header line
 */
static int print_proc_header(char * buffer)
{
	return sprintf(buffer,
		       "%-11s"
		       QUOTA_NUM_LEN_FMT_STR
		       QUOTA_NUM_LEN_FMT_STR
		       QUOTA_NUM_LEN_FMT_STR
		       QUOTA_TIME_LEN_FMT_STR
		       QUOTA_TIME_LEN_FMT_STR
		       "\n",
		       "qid: path", 
		       "usage", "softlimit", "hardlimit", "time", "expire");
}

/*
 * prints proc master record id, dentry path
 */
static int print_proc_master_id(char * buffer, char * path_buf,
		struct vz_quota_master * qp)
{
	char *path;
	int over;

	path = NULL;
	switch (qp->dq_state) {
		case VZDQ_WORKING:
			if (!path_buf) {
				path = "";
				break;
			}
			path = d_path(&qp->dq_root_path, path_buf, PAGE_SIZE);
			if (IS_ERR(path)) {
				path = "";
				break;
			}
			/* do not print large path, truncate it */
			over = strlen(path) -
				(QUOTA_PROC_MAX_LINE_LEN - 3 - 3 -
				 	QUOTA_UINT_LEN);
			if (over > 0) {
				path += over - 3;
				path[0] = path[1] = path[3] = '.';
			}
			break;
		case VZDQ_STARTING:
			path = "-- started --";
			break;
		case VZDQ_STOPING:
			path = "-- stopped --";
			break;
	}

	return sprintf(buffer, "%u: %s\n", qp->dq_id, path);
}

/*
 * prints struct vz_quota_stat data
 */
static int print_proc_stat(char * buffer, struct dq_stat *qs,
		struct dq_info *qi)
{
	return sprintf(buffer,
		       "%11s"
		       QUOTA_NUM_LEN_FMT_ULL
		       QUOTA_NUM_LEN_FMT_ULL
		       QUOTA_NUM_LEN_FMT_ULL
		       QUOTA_TIME_LEN_FMT_UINT
		       QUOTA_TIME_LEN_FMT_UINT
		       "\n"
		       "%11s"
		       QUOTA_NUM_LEN_FMT_UINT
		       QUOTA_NUM_LEN_FMT_UINT
		       QUOTA_NUM_LEN_FMT_UINT
		       QUOTA_TIME_LEN_FMT_UINT
		       QUOTA_TIME_LEN_FMT_UINT
		       "\n",
		       "1k-blocks",
		       (unsigned long long)qs->bcurrent >> 10,
		       (unsigned long long)qs->bsoftlimit >> 10,
		       (unsigned long long)qs->bhardlimit >> 10,
		       (unsigned int)qs->btime,
		       (unsigned int)qi->bexpire,
		       "inodes",
		       qs->icurrent,
		       qs->isoftlimit,
		       qs->ihardlimit,
		       (unsigned int)qs->itime,
		       (unsigned int)qi->iexpire);
}


/*
 * for /proc filesystem output
 */
static int vzquota_read_proc(char *page, char **start, off_t off, int count,
			   int *eof, void *data)
{
	int len, i;
	off_t printed = 0;
	char *p = page;
	struct vz_quota_master *qp;
	struct vz_quota_ilink *ql2;
	struct list_head *listp;
	char *path_buf;

	path_buf = (char*)__get_free_page(GFP_KERNEL);
	if (path_buf == NULL)
		return -ENOMEM;

	len = print_proc_header(p);
	printed += len;
	if (off < printed) /* keep header in output */ {
		*start = p + off;
		p += len;
	}

	mutex_lock(&vz_quota_mutex);

	/* traverse master hash table for all records */
	for (i = 0; i < vzquota_hash_size; i++) {
		list_for_each(listp, &vzquota_hash_table[i]) {
			qp = list_entry(listp,
					struct vz_quota_master, dq_hash);

			/* Skip other VE's information if not root of VE0 */
			if ((!capable(CAP_SYS_ADMIN) ||
			     !capable(CAP_SYS_RESOURCE))) {
				ql2 = INODE_QLNK(current->fs->root.dentry->d_inode);
				if (ql2 == NULL || qp != ql2->qmblk)
					continue;
			}
			/*
			 * Now print the next record
			 */
			len = 0;
			/* we print quotaid and path only in VE0 */
			if (capable(CAP_SYS_ADMIN))
				len += print_proc_master_id(p+len,path_buf, qp);
			len += print_proc_stat(p+len, &qp->dq_stat,
					&qp->dq_info);
			printed += len;
			/* skip unnecessary lines */
			if (printed <= off)
				continue;
			p += len;
			/* provide start offset */
			if (*start == NULL)
				*start = p + (off - printed);
			/* have we printed all requested size? */
			if (PAGE_SIZE - (p - page) < QUOTA_PROC_MAX_LINE_LEN ||
			    (p - *start) >= count)
				goto out;
		}
	}

	*eof = 1; /* checked all hash */
out:
	mutex_unlock(&vz_quota_mutex);

	len = 0;
	if (*start != NULL) {
		len = (p - *start);
		if (len > count)
			len = count;
	}

	if (path_buf)
		free_page((unsigned long) path_buf);

	return len;
}

/*
 * Register procfs read callback
 */
int vzquota_proc_init(void)
{
	struct proc_dir_entry *de;

	de = proc_create("vzquota", S_IFREG|S_IRUSR, proc_vz_dir, NULL);
	if (de == NULL)
		return -EBUSY;

	de->read_proc = vzquota_read_proc;
	de->data = NULL;
	return 0;
}

void vzquota_proc_release(void)
{
	/* Unregister procfs read callback */
	remove_proc_entry("vzquota", proc_vz_dir);
}

#endif
