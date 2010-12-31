/*
 *  include/bc/dcache_op.h
 *
 *  Copyright (C) 2006  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __BC_DCACHE_OP_H_
#define __BC_DCACHE_OP_H_

struct dentry;

#ifdef CONFIG_BEANCOUNTERS

#include <linux/spinlock.h>
#include <bc/dcache.h>
#include <bc/task.h>

extern int ub_dentry_alloc_barrier;
extern spinlock_t dcache_lock;

static inline int ub_dentry_alloc(struct dentry *d)
{
	extern int __ub_dentry_alloc(struct dentry *);

	if (!ub_dentry_on)
		return 0;
	return __ub_dentry_alloc(d);
}

static inline void ub_dentry_alloc_start(void)
{
	extern void __ub_dentry_alloc_start(void);

	if (ub_dentry_alloc_barrier)
		__ub_dentry_alloc_start();
}

static inline void ub_dentry_alloc_end(void)
{
	extern void __ub_dentry_alloc_end(void);

	if (current->task_bc.dentry_alloc)
		__ub_dentry_alloc_end();
}

static inline int ub_dentry_charge(struct dentry *d)
{
	extern int __ub_dentry_charge(struct dentry *);

	if (!ub_dentry_on)
		return 0;
	return __ub_dentry_charge(d);
}

static inline void ub_dentry_charge_nofail(struct dentry *d)
{
	extern void __ub_dentry_charge_nofail(struct dentry *);

	if (!ub_dentry_on)
		return;
	__ub_dentry_charge_nofail(d);
}

static inline void ub_dentry_uncharge_locked(struct dentry *d)
{
	extern void __ub_dentry_uncharge(struct dentry *);

	if (!ub_dentry_on)
		return;
	__ub_dentry_uncharge(d);
}

static inline void ub_dentry_uncharge(struct dentry *d)
{
	extern void __ub_dentry_uncharge(struct dentry *);

	if (!ub_dentry_on)
		return;
	spin_lock(&dcache_lock);
	__ub_dentry_uncharge(d);
	spin_unlock(&dcache_lock);
}

void uncharge_dcache(struct user_beancounter *ub, unsigned long size);
#else /* CONFIG_BEANCOUNTERS */

static inline int ub_dentry_alloc(struct dentry *d) { return 0; }
static inline void ub_dentry_alloc_start(void) { }
static inline void ub_dentry_alloc_end(void) { }
static inline int ub_dentry_charge(struct dentry *d) { return 0; }
static inline void ub_dentry_charge_nofail(struct dentry *d) { }
static inline void ub_dentry_uncharge_locked(struct dentry *d) { }
static inline void ub_dentry_uncharge(struct dentry *d) { }
static inline void uncharge_dcache(struct user_beancounter *ub, unsigned long size) { }

#endif /* CONFIG_BEANCOUNTERS */

#endif /* __dcache_op.h_ */
