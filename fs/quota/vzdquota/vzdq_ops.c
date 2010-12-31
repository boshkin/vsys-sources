/*
 * Copyright (C) 2001, 2002, 2004, 2005  SWsoft
 * All rights reserved.
 * 
 * Licensing governed by "linux/COPYING.SWsoft" file.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/quota.h>
#include <linux/vzquota.h>


/* ----------------------------------------------------------------------
 * Quota superblock operations - helper functions.
 * --------------------------------------------------------------------- */

static inline void vzquota_incr_inodes(struct dq_stat *dqstat,
		unsigned long number)
{
	dqstat->icurrent += number;
}

static inline void vzquota_incr_space(struct dq_stat *dqstat,
		__u64 number)
{
	dqstat->bcurrent += number;
}

static inline void vzquota_decr_inodes(struct dq_stat *dqstat,
		unsigned long number)
{
	if (dqstat->icurrent > number)
		dqstat->icurrent -= number;
	else
		dqstat->icurrent = 0;
	if (dqstat->icurrent < dqstat->isoftlimit)
		dqstat->itime = (time_t) 0;
}

static inline void vzquota_decr_space(struct dq_stat *dqstat,
		__u64 number)
{
	if (dqstat->bcurrent > number)
		dqstat->bcurrent -= number;
	else
		dqstat->bcurrent = 0;
	if (dqstat->bcurrent < dqstat->bsoftlimit)
		dqstat->btime = (time_t) 0;
}

/*
 * better printk() message or use /proc/vzquotamsg interface
 * similar to /proc/kmsg
 */
static inline void vzquota_warn(struct dq_info *dq_info, int dq_id, int flag,
		const char *fmt)
{
	if (dq_info->flags & flag) /* warning already printed for this
				       masterblock */
		return;
	printk(fmt, dq_id);
	dq_info->flags |= flag;
}

/*
 * ignore_hardlimit -
 *
 * Intended to allow superuser of VE0 to overwrite hardlimits.
 *
 * ignore_hardlimit() has a very bad feature:
 *
 *	writepage() operation for writable mapping of a file with holes
 *	may trigger get_block() with wrong current and as a consequence,
 *	opens a possibility to overcommit hardlimits
 */
/* for the reason above, it is disabled now */
static inline int ignore_hardlimit(struct dq_info *dqstat)
{
#if 0
	return	ve_is_super(get_exec_env()) &&
		capable(CAP_SYS_RESOURCE) &&
		(dqstat->options & VZ_QUOTA_OPT_RSQUASH);
#else
	return 0;
#endif
}

static int vzquota_check_inodes(struct dq_info *dq_info,
		struct dq_stat *dqstat,
		unsigned long number, int dq_id)
{
	if (number == 0)
		return QUOTA_OK;

	if (dqstat->icurrent + number > dqstat->ihardlimit &&
	    !ignore_hardlimit(dq_info)) {
		vzquota_warn(dq_info, dq_id, VZ_QUOTA_INODES,
			   "VZ QUOTA: file hardlimit reached for id=%d\n");
		return NO_QUOTA;
	}

	if (dqstat->icurrent + number > dqstat->isoftlimit) {
		if (dqstat->itime == (time_t)0) {
			vzquota_warn(dq_info, dq_id, 0,
				"VZ QUOTA: file softlimit exceeded "
				"for id=%d\n");
			dqstat->itime = CURRENT_TIME_SECONDS +
				dq_info->iexpire;
		} else if (CURRENT_TIME_SECONDS >= dqstat->itime &&
			   !ignore_hardlimit(dq_info)) {
			vzquota_warn(dq_info, dq_id, VZ_QUOTA_INODES,
				"VZ QUOTA: file softlimit expired "
				"for id=%d\n");
			return NO_QUOTA;
		}
	}

	return QUOTA_OK;
}

static int vzquota_check_space(struct dq_info *dq_info,
		struct dq_stat *dqstat,
		__u64 number, int dq_id, char prealloc)
{
	if (number == 0)
		return QUOTA_OK;

	if (prealloc == DQUOT_CMD_FORCE)
		return QUOTA_OK;

	if (dqstat->bcurrent + number > dqstat->bhardlimit &&
	    !ignore_hardlimit(dq_info)) {
		if (!prealloc)
			vzquota_warn(dq_info, dq_id, VZ_QUOTA_SPACE,
				"VZ QUOTA: disk hardlimit reached "
				"for id=%d\n");
		return NO_QUOTA;
	}

	if (dqstat->bcurrent + number > dqstat->bsoftlimit) {
		if (dqstat->btime == (time_t)0) {
			if (!prealloc) {
				vzquota_warn(dq_info, dq_id, 0,
					"VZ QUOTA: disk softlimit exceeded "
					"for id=%d\n");
				dqstat->btime = CURRENT_TIME_SECONDS
							+ dq_info->bexpire;
			} else {
				/*
				 * Original Linux quota doesn't allow
				 * preallocation to exceed softlimit so
				 * exceeding will be always printed
				 */
				return NO_QUOTA;
			}
		} else if (CURRENT_TIME_SECONDS >= dqstat->btime &&
			   !ignore_hardlimit(dq_info)) {
			if (!prealloc)
				vzquota_warn(dq_info, dq_id, VZ_QUOTA_SPACE,
					"VZ QUOTA: disk quota "
					"softlimit expired "
					"for id=%d\n");
			return NO_QUOTA;
		}
	}

	return QUOTA_OK;
}

#ifdef CONFIG_VZ_QUOTA_UGID
static int vzquota_check_ugid_inodes(struct vz_quota_master *qmblk,
		struct vz_quota_ugid *qugid[],
		int type, unsigned long number)
{
	struct dq_info *dqinfo;
	struct dq_stat *dqstat;

	if (qugid[type] == NULL)
		return QUOTA_OK;
	if (qugid[type] == VZ_QUOTA_UGBAD)
		return NO_QUOTA;

	if (type == USRQUOTA && !(qmblk->dq_flags & VZDQ_USRQUOTA))
		return QUOTA_OK;
	if (type == GRPQUOTA && !(qmblk->dq_flags & VZDQ_GRPQUOTA))
		return QUOTA_OK;
	if (number == 0)
		return QUOTA_OK;

	dqinfo = &qmblk->dq_ugid_info[type];
	dqstat = &qugid[type]->qugid_stat;

	if (dqstat->ihardlimit != 0 &&
	    dqstat->icurrent + number > dqstat->ihardlimit)
		return NO_QUOTA;

	if (dqstat->isoftlimit != 0 &&
	    dqstat->icurrent + number > dqstat->isoftlimit) {
		if (dqstat->itime == (time_t)0)
			dqstat->itime = CURRENT_TIME_SECONDS +
				dqinfo->iexpire;
		else if (CURRENT_TIME_SECONDS >= dqstat->itime)
			return NO_QUOTA;
	}

	return QUOTA_OK;
}

static int vzquota_check_ugid_space(struct vz_quota_master *qmblk,
		struct vz_quota_ugid *qugid[],
		int type, __u64 number, char prealloc)
{
	struct dq_info *dqinfo;
	struct dq_stat *dqstat;

	if (prealloc == DQUOT_CMD_FORCE)
		return QUOTA_OK;

	if (qugid[type] == NULL)
		return QUOTA_OK;
	if (qugid[type] == VZ_QUOTA_UGBAD)
		return NO_QUOTA;

	if (type == USRQUOTA && !(qmblk->dq_flags & VZDQ_USRQUOTA))
		return QUOTA_OK;
	if (type == GRPQUOTA && !(qmblk->dq_flags & VZDQ_GRPQUOTA))
		return QUOTA_OK;
	if (number == 0)
		return QUOTA_OK;

	dqinfo = &qmblk->dq_ugid_info[type];
	dqstat = &qugid[type]->qugid_stat;

	if (dqstat->bhardlimit != 0 &&
	    dqstat->bcurrent + number > dqstat->bhardlimit)
		return NO_QUOTA;

	if (dqstat->bsoftlimit != 0 &&
	    dqstat->bcurrent + number > dqstat->bsoftlimit) {
		if (dqstat->btime == (time_t)0) {
			if (!prealloc)
				dqstat->btime = CURRENT_TIME_SECONDS
							+ dqinfo->bexpire;
			else
				/*
				 * Original Linux quota doesn't allow
				 * preallocation to exceed softlimit so
				 * exceeding will be always printed
				 */
				return NO_QUOTA;
		} else if (CURRENT_TIME_SECONDS >= dqstat->btime)
			return NO_QUOTA;
	}

	return QUOTA_OK;
}
#endif

/* ----------------------------------------------------------------------
 * Quota superblock operations
 * --------------------------------------------------------------------- */

/*
 * S_NOQUOTA note.
 * In the current kernel (2.6.8.1), S_NOQUOTA flag is set only for
 *  - quota file (absent in our case)
 *  - after explicit DQUOT_DROP (earlier than clear_inode) in functions like
 *    filesystem-specific new_inode, before the inode gets outside links.
 * For the latter case, the only quota operation where care about S_NOQUOTA
 * might be required is vzquota_drop, but there S_NOQUOTA has already been
 * checked in DQUOT_DROP().
 * So, S_NOQUOTA may be ignored for now in the VZDQ code.
 *
 * The above note is not entirely correct.
 * Both for ext2 and ext3 filesystems, DQUOT_FREE_INODE is called from
 * delete_inode if new_inode fails (for example, because of inode quota
 * limits), so S_NOQUOTA check is needed in free_inode.
 * This seems to be the dark corner of the current quota API.
 */

/*
 * Initialize quota operations for the specified inode.
 */
static int vzquota_initialize(struct inode *inode, int type)
{
	vzquota_inode_init_call(inode);
	return 0; /* ignored by caller */
}

/*
 * Release quota for the specified inode.
 */
static int vzquota_drop(struct inode *inode)
{
	vzquota_inode_drop_call(inode);
	return 0; /* ignored by caller */
}

/*
 * Allocate block callback.
 *
 * If (prealloc) disk quota exceeding warning is not printed.
 * See Linux quota to know why.
 *
 * Return:
 *	QUOTA_OK == 0 on SUCCESS
 *	NO_QUOTA == 1 if allocation should fail
 */
static int vzquota_alloc_space(struct inode *inode,
			     qsize_t number, int prealloc)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_datast data;
	int ret = QUOTA_OK;

	qmblk = vzquota_inode_data(inode, &data);
	if (qmblk == VZ_QUOTA_BAD)
		return NO_QUOTA;
	if (qmblk != NULL) {
#ifdef CONFIG_VZ_QUOTA_UGID
		int cnt;
		struct vz_quota_ugid * qugid[MAXQUOTAS];
#endif

		/* checking first */
		ret = vzquota_check_space(&qmblk->dq_info, &qmblk->dq_stat,
				number, qmblk->dq_id, prealloc);
		if (ret == NO_QUOTA)
			goto no_quota;
#ifdef CONFIG_VZ_QUOTA_UGID
		for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
			qugid[cnt] = INODE_QLNK(inode)->qugid[cnt];
			ret = vzquota_check_ugid_space(qmblk, qugid,
					cnt, number, prealloc);
			if (ret == NO_QUOTA)
				goto no_quota;
		}
		/* check ok, may increment */
		for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
			if (qugid[cnt] == NULL)
				continue;
			vzquota_incr_space(&qugid[cnt]->qugid_stat, number);
		}
#endif
		vzquota_incr_space(&qmblk->dq_stat, number);
		vzquota_data_unlock(inode, &data);
	}

	inode_add_bytes(inode, number);
	might_sleep();
	return QUOTA_OK;

no_quota:
	vzquota_data_unlock(inode, &data);
	return NO_QUOTA;
}

/*
 * Allocate inodes callback.
 *
 * Return:
 *	QUOTA_OK == 0 on SUCCESS
 *	NO_QUOTA == 1 if allocation should fail
 */
static int vzquota_alloc_inode(const struct inode *inode, qsize_t number)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_datast data;
	int ret = QUOTA_OK;

	qmblk = vzquota_inode_data((struct inode *)inode, &data);
	if (qmblk == VZ_QUOTA_BAD)
		return NO_QUOTA;
	if (qmblk != NULL) {
#ifdef CONFIG_VZ_QUOTA_UGID
		int cnt;
		struct vz_quota_ugid *qugid[MAXQUOTAS];
#endif

		/* checking first */
		ret = vzquota_check_inodes(&qmblk->dq_info, &qmblk->dq_stat,
				number, qmblk->dq_id);
		if (ret == NO_QUOTA)
			goto no_quota;
#ifdef CONFIG_VZ_QUOTA_UGID
		for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
			qugid[cnt] = INODE_QLNK(inode)->qugid[cnt];
			ret = vzquota_check_ugid_inodes(qmblk, qugid,
					cnt, number);
			if (ret == NO_QUOTA)
				goto no_quota;
		}
		/* check ok, may increment */
		for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
			if (qugid[cnt] == NULL)
				continue;
			vzquota_incr_inodes(&qugid[cnt]->qugid_stat, number);
		}
#endif
		vzquota_incr_inodes(&qmblk->dq_stat, number);
		vzquota_data_unlock((struct inode *)inode, &data);
	}

	might_sleep();
	return QUOTA_OK;

no_quota:
	vzquota_data_unlock((struct inode *)inode, &data);
	return NO_QUOTA;
}

/*
 * Free space callback.
 */
static int vzquota_free_space(struct inode *inode, qsize_t number)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_datast data;

	qmblk = vzquota_inode_data(inode, &data);
	if (qmblk == VZ_QUOTA_BAD)
		return NO_QUOTA; /* isn't checked by the caller */
	if (qmblk != NULL) {
#ifdef CONFIG_VZ_QUOTA_UGID
		int cnt;
		struct vz_quota_ugid * qugid;
#endif

		vzquota_decr_space(&qmblk->dq_stat, number);
#ifdef CONFIG_VZ_QUOTA_UGID
		for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
			qugid = INODE_QLNK(inode)->qugid[cnt];
			if (qugid == NULL || qugid == VZ_QUOTA_UGBAD)
				continue;
			vzquota_decr_space(&qugid->qugid_stat, number);
		}
#endif
		vzquota_data_unlock(inode, &data);
	}
	inode_sub_bytes(inode, number);
	might_sleep();
	return QUOTA_OK;
}

/*
 * Free inodes callback.
 */
static int vzquota_free_inode(const struct inode *inode, qsize_t number)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_datast data;

	qmblk = vzquota_inode_data((struct inode *)inode, &data);
	if (qmblk == VZ_QUOTA_BAD)
		return NO_QUOTA;
	if (qmblk != NULL) {
#ifdef CONFIG_VZ_QUOTA_UGID
		int cnt;
		struct vz_quota_ugid * qugid;
#endif

		vzquota_decr_inodes(&qmblk->dq_stat, number);
#ifdef CONFIG_VZ_QUOTA_UGID
		for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
			qugid = INODE_QLNK(inode)->qugid[cnt];
			if (qugid == NULL || qugid == VZ_QUOTA_UGBAD)
				continue;
			vzquota_decr_inodes(&qugid->qugid_stat, number);
		}
#endif
		vzquota_data_unlock((struct inode *)inode, &data);
	}
	might_sleep();
	return QUOTA_OK;
}

void vzquota_inode_off(struct inode * inode)
{
	struct vz_quota_master *qmblk;
	struct vz_quota_datast data;

	/* The call is made through virtinfo, it can be an inode
	 * not controlled by vzquota.
	 */
	if (inode->i_sb->dq_op != &vz_quota_operations)
		return;

	qmblk = vzquota_inode_data(inode, &data);
	if (qmblk == VZ_QUOTA_BAD)
		return;

	if (qmblk == NULL) {
		/* Tricky place. If qmblk == NULL, it means that this inode
		 * is not in area controlled by vzquota (except for rare
		 * case of already set S_NOQUOTA). But we have to set
		 * S_NOQUOTA in any case because vzquota can be turned
		 * on later, when this inode is invalid from viewpoint
		 * of vzquota.
		 *
		 * To be safe, we reacquire vzquota lock.
		 * The assumption is that it would not hurt to call
		 * vzquota_inode_drop() more than once, but it must
		 * be called at least once after S_NOQUOTA is set.
		 */
		inode_qmblk_lock(inode->i_sb);
		inode->i_flags |= S_NOQUOTA;
		inode_qmblk_unlock(inode->i_sb);
	} else {
		loff_t bytes = inode_get_bytes(inode);
#ifdef CONFIG_VZ_QUOTA_UGID
		int cnt;
		struct vz_quota_ugid * qugid;
#endif

		inode->i_flags |= S_NOQUOTA;

		vzquota_decr_space(&qmblk->dq_stat, bytes);
		vzquota_decr_inodes(&qmblk->dq_stat, 1);
#ifdef CONFIG_VZ_QUOTA_UGID
		for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
			qugid = INODE_QLNK(inode)->qugid[cnt];
			if (qugid == NULL || qugid == VZ_QUOTA_UGBAD)
				continue;
			vzquota_decr_space(&qugid->qugid_stat, bytes);
			vzquota_decr_inodes(&qugid->qugid_stat, 1);
		}
#endif

		vzquota_data_unlock(inode, &data);
	}
	vzquota_inode_drop_call(inode);
}


#ifdef CONFIG_VZ_QUOTA_UGID

/*
 * helper function for quota_transfer
 * check that we can add inode to this quota_id
 */
static int vzquota_transfer_check(struct vz_quota_master *qmblk,
		struct vz_quota_ugid *qugid[],
		unsigned int type, __u64 size)
{
	if (vzquota_check_ugid_space(qmblk, qugid, type, size, 0) != QUOTA_OK ||
	    vzquota_check_ugid_inodes(qmblk, qugid, type, 1) != QUOTA_OK)
		return -1;
	return 0;
}

int vzquota_transfer_usage(struct inode *inode,
		int mask,
		struct vz_quota_ilink *qlnk)
{
	struct vz_quota_ugid *qugid_old;
	__u64 space;
	int i;

	space = inode_get_bytes(inode);
	for (i = 0; i < MAXQUOTAS; i++) {
		if (!(mask & (1 << i)))
			continue;
		/*
		 * Do not permit chown a file if its owner does not have
		 * ugid record. This might happen if we somehow exceeded
		 * the UID/GID (e.g. set uglimit less than number of users).
		 */
		if (INODE_QLNK(inode)->qugid[i] == VZ_QUOTA_UGBAD)
			return -1;
		if (vzquota_transfer_check(qlnk->qmblk, qlnk->qugid, i, space))
			return -1;
	}

	for (i = 0; i < MAXQUOTAS; i++) {
		if (!(mask & (1 << i)))
			continue;
		qugid_old = INODE_QLNK(inode)->qugid[i];
		vzquota_decr_space(&qugid_old->qugid_stat, space);
		vzquota_decr_inodes(&qugid_old->qugid_stat, 1);
		vzquota_incr_space(&qlnk->qugid[i]->qugid_stat, space);
		vzquota_incr_inodes(&qlnk->qugid[i]->qugid_stat, 1);
	}
	return 0;
}

/*
 * Transfer the inode between diffent user/group quotas.
 */
static int vzquota_transfer(struct inode *inode, struct iattr *iattr)
{
	return vzquota_inode_transfer_call(inode, iattr) ?
		NO_QUOTA : QUOTA_OK;
}

static void vzquota_swap_inode(struct inode *inode, struct inode *tmpl)
{
	vzquota_inode_swap_call(inode, tmpl);
}


#else /* CONFIG_VZ_QUOTA_UGID */

static int vzquota_transfer(struct inode *inode, struct iattr *iattr)
{
	return QUOTA_OK;
}

static void vzquota_swap_inode(struct inode *inode, struct inode *tmpl)
{
}
#endif

/*
 * Called under following semaphores:
 *	old_d->d_inode->i_sb->s_vfs_rename_sem
 *	old_d->d_inode->i_sem
 *	new_d->d_inode->i_sem
 * [not verified  --SAW]
 */
static int vzquota_rename(struct inode *inode,
		struct inode *old_dir, struct inode *new_dir)
{
	return vzquota_rename_check(inode, old_dir, new_dir) ?
		NO_QUOTA : QUOTA_OK;
}

extern void vzquota_shutdown_super(struct super_block *sb);

/*
 * Structure of superblock diskquota operations.
 */
struct dquot_operations vz_quota_operations = {
	.initialize	= vzquota_initialize,
	.drop		= vzquota_drop,
	.alloc_space	= vzquota_alloc_space,
	.alloc_inode	= vzquota_alloc_inode,
	.free_space	= vzquota_free_space,
	.free_inode	= vzquota_free_inode,
	.transfer	= vzquota_transfer,
	.rename		= vzquota_rename,

	.swap_inode	= vzquota_swap_inode,
	.shutdown	= vzquota_shutdown_super,
};
