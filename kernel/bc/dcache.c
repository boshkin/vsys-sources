/*
 *  kernel/bc/dcache.c
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/swap.h>
#include <linux/stop_machine.h>
#include <linux/cpumask.h>
#include <linux/nmi.h>
#include <linux/rwsem.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include <asm/bitops.h>

#include <bc/beancounter.h>
#include <bc/kmem.h>
#include <bc/dcache.h>
#include <bc/dcache_op.h>

/*
 * Locking
 *                          traverse  dcache_lock  d_lock
 *        ub_dentry_charge   +         -            +
 *      ub_dentry_uncharge   +         +            -
 * ub_dentry_charge_nofail   +         +            -
 *
 * d_inuse changes are atomic, with special handling of "not in use" <->
 * "in use" (-1 <-> 0) transitions.  We have two sources of non-atomicity
 * here: (1) in many operations we need to change d_inuse of both dentry and
 * its parent, and (2) on state transitions we need to adjust the account.
 *
 * Regarding (1): we do not have (and do not want) a single lock covering all
 * operations, so in general it's impossible to get a consistent view of
 * a tree with respect to d_inuse counters (except by swsuspend).  It also
 * means if a dentry with d_inuse of 0 gets one new in-use child and loses
 * one, it's d_inuse counter will go either 0 -> 1 -> 0 path or 0 -> -1 -> 0,
 * and we can't say which way.
 * Note that path -1 -> 0 -> -1 can't turn into -1 -> -2 -> -1, since
 * uncharge can be done only after return from charge (with d_genocide being
 * the only apparent exception).
 * Regarding (2): there is a similar uncertainty with the dcache account.
 * If the account is equal to the limit, one more dentry is started to be
 * used and one is put, the account will either hit the limit (and an error
 * will be returned), or decrement will happen before increment.
 *
 * These races do not really matter.
 * The only things we want are:
 *  - if a system is suspenede with no in-use dentries, all d_inuse counters
 *    should be correct (-1);
 *  - d_inuse counters should always be >= -1.
 * This holds if ->parent references are accessed and maintained properly.
 * In subtle moments (like d_move) dentries exchanging their parents should
 * both be in-use.  At d_genocide time, lookups and charges are assumed to be
 * impossible.
 */

/*
 * Hierarchical accounting
 * UB argument must NOT be NULL
 */

static int do_charge_dcache(struct user_beancounter *ub, unsigned long size, 
		enum ub_severity sv)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	if (__charge_beancounter_locked(ub, UB_KMEMSIZE, CHARGE_SIZE(size), sv))
		goto out_mem;
	if (__charge_beancounter_locked(ub, UB_DCACHESIZE, size, sv))
		goto out_dcache;
	spin_unlock_irqrestore(&ub->ub_lock, flags);
	return 0;

out_dcache:
	__uncharge_beancounter_locked(ub, UB_KMEMSIZE, CHARGE_SIZE(size));
out_mem:
	spin_unlock_irqrestore(&ub->ub_lock, flags);
	return -ENOMEM;
}

static void do_uncharge_dcache(struct user_beancounter *ub, 
		unsigned long size)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	__uncharge_beancounter_locked(ub, UB_KMEMSIZE, CHARGE_SIZE(size));
	__uncharge_beancounter_locked(ub, UB_DCACHESIZE, size);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

static int charge_dcache(struct user_beancounter *ub, unsigned long size, 
		enum ub_severity sv)
{
	struct user_beancounter *p, *q;

	for (p = ub; p != NULL; p = p->parent) {
		if (do_charge_dcache(p, size, sv))
			goto unroll;
	}
	return 0;

unroll:
	for (q = ub; q != p; q = q->parent)
		do_uncharge_dcache(q, size);
	return -ENOMEM;
}

void uncharge_dcache(struct user_beancounter *ub, unsigned long size)
{
	for (; ub != NULL; ub = ub->parent)
		do_uncharge_dcache(ub, size);
}

/*
 * Simple helpers to do maintain account and d_ub field.
 */

static inline int d_charge(struct dentry_beancounter *d_bc)
{
	struct user_beancounter *ub;

	ub = get_beancounter(get_exec_ub());
	if (charge_dcache(ub, d_bc->d_ubsize, UB_SOFT)) {
		put_beancounter(ub);
		return -1;
	}
	d_bc->d_ub = ub;
	return 0;
}

static inline void d_forced_charge(struct dentry_beancounter *d_bc)
{
	struct user_beancounter *ub;

	ub = get_beancounter(get_exec_ub());
	charge_dcache(ub, d_bc->d_ubsize, UB_FORCE);
	d_bc->d_ub = ub;
}

/*
 * Minor helpers
 */

extern struct kmem_cache *dentry_cache; 
extern struct kmem_cache *inode_cachep;
static struct rw_semaphore ub_dentry_alloc_sem;

static inline unsigned long d_charge_size(struct dentry *dentry)
{
	/* dentry's d_name is already set to appropriate value (see d_alloc) */
	return kmem_cache_objuse(inode_cachep) + kmem_cache_objuse(dentry_cache) +
		(dname_external(dentry) ?
		 kmem_dname_objuse((void *)dentry->d_name.name) : 0);
}

/*
 * Entry points from dcache.c
 */

/* 
 * Set initial d_inuse on d_alloc.
 * Called with no locks, preemption disabled.
 */
int __ub_dentry_alloc(struct dentry *dentry)
{
	struct dentry_beancounter *d_bc;

	d_bc = &dentry->dentry_bc;
	d_bc->d_ub = get_beancounter(get_exec_ub());
	atomic_set(&d_bc->d_inuse, INUSE_INIT); /* see comment in dcache.h */
	d_bc->d_ubsize = d_charge_size(dentry);

	if (charge_dcache(d_bc->d_ub, d_bc->d_ubsize, UB_HARD))
		goto failure;
	return 0;

failure:
	put_beancounter(d_bc->d_ub);
	d_bc->d_ub = NULL;
	return -ENOMEM;
}
void __ub_dentry_alloc_start(void)
{
	down_read(&ub_dentry_alloc_sem);
	current->task_bc.dentry_alloc = 1;
}

void __ub_dentry_alloc_end(void)
{
	current->task_bc.dentry_alloc = 0;
	up_read(&ub_dentry_alloc_sem);
}

/*
 * It is assumed that parent is already in use, so traverse upwards is
 * limited to one ancestor only.
 * Called under d_lock and rcu_read_lock.
 */
int __ub_dentry_charge(struct dentry *dentry)
{
	struct dentry_beancounter *d_bc;
	struct dentry *parent;
	int ret;

	if (ub_dget_testone(dentry)) {
		d_bc = &dentry->dentry_bc;
		/* state transition -1 => 0 */
		if (d_charge(d_bc))
			goto failure;

		if (dentry != dentry->d_parent) {
			parent = dentry->d_parent;
			if (ub_dget_testone(parent))
				BUG();
		}
	}
	return 0;

failure:
	/*
	 * Here we would like to fail the lookup.
	 * It is not easy: if d_lookup fails, callers expect that a dentry
	 * with the given name doesn't exist, and create a new one.
	 * So, first we forcedly charge for this dentry.
	 * Then try to remove it from cache safely.  If it turns out to be
	 * possible, we can return error.
	 */
	d_forced_charge(d_bc);

	if (dentry != dentry->d_parent) {
		parent = dentry->d_parent;
		if (ub_dget_testone(parent))
			BUG();
	}

	ret = 0;
	if (spin_trylock(&dcache_lock)) {
		if (!list_empty(&dentry->d_subdirs)) {
			spin_unlock(&dentry->d_lock);
			spin_unlock(&dcache_lock);
			rcu_read_unlock();
			shrink_dcache_parent(dentry);
			rcu_read_lock();
			spin_lock(&dcache_lock);
			spin_lock(&dentry->d_lock);
		}
		if (atomic_read(&dentry->d_count) == 1) {
			__d_drop(dentry);
			ret = -1;
		}
		spin_unlock(&dcache_lock);
	}

	return ret;
}

/*
 * Go up in the tree decreasing d_inuse.
 * Called under dcache_lock.
 */
void __ub_dentry_uncharge(struct dentry *dentry)
{
	struct dentry *parent;
	struct user_beancounter *ub;
	unsigned long size;

	/* go up until state doesn't change or and root is reached */
	size = dentry->dentry_bc.d_ubsize;
	ub = dentry->dentry_bc.d_ub;
	while (ub_dput_testzero(dentry)) {
		/* state transition 0 => -1 */
		uncharge_dcache(ub, size);
		put_beancounter(ub);

		parent = dentry->d_parent;
		if (dentry == parent)
			break;

		dentry = parent;
		size = dentry->dentry_bc.d_ubsize;
		ub = dentry->dentry_bc.d_ub;
	}
}

/* 
 * Forced charge for __dget_locked, where API doesn't allow to return error.
 * Called under dcache_lock.
 */
void __ub_dentry_charge_nofail(struct dentry *dentry)
{
	struct dentry *parent;

	while (ub_dget_testone(dentry)) {
		/* state transition -1 => 0 */
		d_forced_charge(&dentry->dentry_bc);

		parent = dentry->d_parent;
		if (dentry == parent)
			break;
		dentry = parent;
	}
}

/*
 * Adaptive accounting
 */

int ub_dentry_on = 1;
int ub_dentry_alloc_barrier;
EXPORT_SYMBOL(ub_dentry_on);

static unsigned long checklowat = 0;
static unsigned long checkhiwat = ULONG_MAX;

static int sysctl_ub_dentry_chk = 10;
#define sysctl_ub_lowat	sysctl_ub_watermark[0]
#define sysctl_ub_hiwat sysctl_ub_watermark[1]
static DECLARE_RWSEM(ub_dentry_alloc_sem);
/* 1024th of lowmem size */
static unsigned int sysctl_ub_watermark[2] = {0, 100};

static void ub_dentry_set_limits(unsigned long pages, unsigned long cap)
{
	down_write(&ub_dentry_alloc_sem);
	preempt_disable();
	checklowat = (pages >> 10) * sysctl_ub_lowat;
	checkhiwat = (pages >> 10) * sysctl_ub_hiwat;
	if (checkhiwat > cap) {
		checkhiwat = cap;
		checklowat = cap / sysctl_ub_hiwat * sysctl_ub_lowat;
	}
	preempt_enable();
	up_write(&ub_dentry_alloc_sem);
}

static int ub_dentry_proc_handler(ctl_table *ctl, int write,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int r;

	r = proc_dointvec(ctl, write, buffer, lenp, ppos);
	if (!r && write)
		ub_dentry_set_limits(totalram_pages - totalhigh_pages,
				ULONG_MAX);
	return r;
}

static ctl_table ub_dentry_sysctl_table[] = {
	{
		.procname	= "dentry_check",
		.data		= &sysctl_ub_dentry_chk,
		.maxlen		= sizeof(sysctl_ub_dentry_chk),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "dentry_watermark",
		.data		= &sysctl_ub_lowat,
		.maxlen		= sizeof(sysctl_ub_lowat) * 2,
		.mode		= 0644,
		.proc_handler	= ub_dentry_proc_handler,
	},
	{ .ctl_name = 0 }
};
static ctl_table ub_dentry_sysctl_root[] = {
	{
		.procname	= "ubc",
		.mode		= 0555,
		.child		= ub_dentry_sysctl_table,
	},
	{ .ctl_name = 0 }
};

static int __init ub_dentry_init(void)
{
	/*
	 * Initial watermarks are limited, to limit walk time.
	 * 384MB translates into 0.8 sec on PIII 866MHz.
	 */
	ub_dentry_set_limits(totalram_pages - totalhigh_pages,
			384 * 1024 * 1024 / PAGE_SIZE);
	if (register_sysctl_table(ub_dentry_sysctl_root) == NULL)
		return -ENOMEM;
	return 0;
}
__initcall(ub_dentry_init);
