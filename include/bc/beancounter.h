/*
 *  include/bc/beancounter.h
 *
 *  Copyright (C) 1999-2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 *  Andrey Savochkin	saw@sw-soft.com
 *
 */

#ifndef _LINUX_BEANCOUNTER_H
#define _LINUX_BEANCOUNTER_H

/*
 * Generic ratelimiting stuff.
 */

struct ub_rate_info {
	int burst;
	int interval; /* jiffy_t per event */
	int bucket; /* kind of leaky bucket */
	unsigned long last; /* last event */
};

/* Return true if rate limit permits. */
int ub_ratelimit(struct ub_rate_info *);


/*
 * This magic is used to distinuish user beancounter and pages beancounter
 * in struct page. page_ub and page_bc are placed in union and MAGIC
 * ensures us that we don't use pbc as ubc in ub_page_uncharge().
 */
#define UB_MAGIC		0x62756275

/*
 *	Resource list.
 */

#define UB_KMEMSIZE	0	/* Unswappable kernel memory size including
				 * struct task, page directories, etc.
				 */
#define UB_LOCKEDPAGES	1	/* Mlock()ed pages. */
#define UB_PRIVVMPAGES	2	/* Total number of pages, counting potentially
				 * private pages as private and used.
				 */
#define UB_SHMPAGES	3	/* IPC SHM segment size. */
#define UB_DUMMY	4	/* Dummy resource (compatibility) */
#define UB_NUMPROC	5	/* Number of processes. */
#define UB_PHYSPAGES	6	/* All resident pages, for swapout guarantee. */
#define UB_VMGUARPAGES	7	/* Guarantee for memory allocation,
				 * checked against PRIVVMPAGES.
				 */
#define UB_OOMGUARPAGES	8	/* Guarantees against OOM kill.
				 * Only limit is used, no accounting.
				 */
#define UB_NUMTCPSOCK	9	/* Number of TCP sockets. */
#define UB_NUMFLOCK	10	/* Number of file locks. */
#define UB_NUMPTY	11	/* Number of PTYs. */
#define UB_NUMSIGINFO	12	/* Number of siginfos. */
#define UB_TCPSNDBUF	13	/* Total size of tcp send buffers. */
#define UB_TCPRCVBUF	14	/* Total size of tcp receive buffers. */
#define UB_OTHERSOCKBUF	15	/* Total size of other socket
				 * send buffers (all buffers for PF_UNIX).
				 */
#define UB_DGRAMRCVBUF	16	/* Total size of other socket
				 * receive buffers.
				 */
#define UB_NUMOTHERSOCK	17	/* Number of other sockets. */
#define UB_DCACHESIZE	18	/* Size of busy dentry/inode cache. */
#define UB_NUMFILE	19	/* Number of open files. */

#define UB_RESOURCES_COMPAT	24

/* Add new resources here */

#define UB_NUMXTENT	23
#define UB_SWAPPAGES	24
#define UB_RESOURCES	25

#define UB_UNUSEDPRIVVM	(UB_RESOURCES + 0)
#define UB_TMPFSPAGES	(UB_RESOURCES + 1)
#define UB_HELDPAGES	(UB_RESOURCES + 2)

struct ubparm {
	/* 
	 * A barrier over which resource allocations are failed gracefully.
	 * If the amount of consumed memory is over the barrier further sbrk()
	 * or mmap() calls fail, the existing processes are not killed. 
	 */
	unsigned long	barrier;
	/* hard resource limit */
	unsigned long	limit;
	/* consumed resources */
	unsigned long	held;
	/* maximum amount of consumed resources through the last period */
	unsigned long	maxheld;
	/* minimum amount of consumed resources through the last period */
	unsigned long	minheld;
	/* count of failed charges */
	unsigned long	failcnt;
};

/*
 * Kernel internal part.
 */

#ifdef __KERNEL__

#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/cache.h>
#include <linux/threads.h>
#include <linux/percpu.h>
#include <linux/percpu_counter.h>
#include <bc/debug.h>
#include <bc/decl.h>
#include <asm/atomic.h>

/*
 * UB_MAXVALUE is essentially LONG_MAX declared in a cross-compiling safe form.
 */
#define UB_MAXVALUE	( (1UL << (sizeof(unsigned long)*8-1)) - 1)


/*
 *	Resource management structures
 * Serialization issues:
 *   beancounter list management is protected via ub_hash_lock
 *   task pointers are set only for current task and only once
 *   refcount is managed atomically
 *   value and limit comparison and change are protected by per-ub spinlock
 */

struct page_beancounter;
struct task_beancounter;
struct sock_beancounter;

struct page_private {
	unsigned long		ubp_unused_privvmpages;
	unsigned long		ubp_tmpfs_respages;
	unsigned long		ubp_pbcs;
	unsigned long long	ubp_held_pages;
};

struct sock_private {
	unsigned long		ubp_rmem_thres;
	unsigned long		ubp_wmem_pressure;
	unsigned long		ubp_maxadvmss;
	unsigned long		ubp_rmem_pressure;
	int			ubp_tw_count;
#define UB_RMEM_EXPAND          0
#define UB_RMEM_KEEP            1
#define UB_RMEM_SHRINK          2
	struct list_head	ubp_other_socks;
	struct list_head	ubp_tcp_socks;
	struct percpu_counter	ubp_orphan_count;
};

struct ub_percpu_struct {
	unsigned long unmap;
	unsigned long swapin;
#ifdef CONFIG_BC_IO_ACCOUNTING
	unsigned long long bytes_wrote;
	unsigned long long bytes_read;
	unsigned long long bytes_cancelled;
#endif
#ifdef CONFIG_BC_DEBUG_KMEM
	long	pages_charged;
	long	vmalloc_charged;
#endif
	unsigned long	sync;
	unsigned long	sync_done;

	unsigned long	fsync;
	unsigned long	fsync_done;

	unsigned long	fdsync;
	unsigned long	fdsync_done;

	unsigned long	frsync;
	unsigned long	frsync_done;

	unsigned long		write;
	unsigned long		read;
	unsigned long long	wchar;
	unsigned long long	rchar;
};

struct user_beancounter
{
	unsigned long		ub_magic;
	atomic_t		ub_refcount;
	struct list_head	ub_list;
	struct hlist_node	ub_hash;

	union {
		struct rcu_head rcu;
		struct execute_work cleanup;
	};

	spinlock_t		ub_lock;
	uid_t			ub_uid;
	unsigned int		ub_cookie;

	struct ub_rate_info	ub_limit_rl;
	int			ub_oom_noproc;

	struct page_private	ppriv;
#define ub_unused_privvmpages	ppriv.ubp_unused_privvmpages
#define ub_tmpfs_respages	ppriv.ubp_tmpfs_respages
#define ub_held_pages		ppriv.ubp_held_pages
#define ub_pbcs			ppriv.ubp_pbcs
	struct sock_private	spriv;
#define ub_rmem_thres		spriv.ubp_rmem_thres
#define ub_maxadvmss		spriv.ubp_maxadvmss
#define ub_rmem_pressure	spriv.ubp_rmem_pressure
#define ub_wmem_pressure	spriv.ubp_wmem_pressure
#define ub_tcp_sk_list		spriv.ubp_tcp_socks
#define ub_other_sk_list	spriv.ubp_other_socks
#define ub_orphan_count		spriv.ubp_orphan_count
#define ub_tw_count		spriv.ubp_tw_count

	struct user_beancounter *parent;
	int			ub_childs;
	void			*private_data;
	unsigned long		ub_aflags;

#ifdef CONFIG_PROC_FS
	struct proc_dir_entry	*proc;
#endif

	/* resources statistic and settings */
	struct ubparm		ub_parms[UB_RESOURCES];
	/* resources statistic for last interval */
	struct ubparm		ub_store[UB_RESOURCES];

	struct ub_percpu_struct	*ub_percpu;
#ifdef CONFIG_BC_IO_ACCOUNTING
	/* these are protected with pb_lock */
	unsigned long long	bytes_wrote;
	unsigned long long	bytes_dirtied;
	unsigned long long	bytes_dirty_missed;
	unsigned long		io_pb_held;
#endif
#ifdef CONFIG_BC_DEBUG_KMEM
	struct list_head	ub_cclist;
#endif
};

extern int ub_count;

enum ub_severity { UB_HARD, UB_SOFT, UB_FORCE };

#define UB_AFLAG_NOTIF_PAGEIN	0

static inline
struct user_beancounter *top_beancounter(struct user_beancounter *ub)
{
	while (ub->parent != NULL)
		ub = ub->parent;
	return ub;
}

static inline int ub_barrier_hit(struct user_beancounter *ub, int resource)
{
	return ub->ub_parms[resource].held > ub->ub_parms[resource].barrier;
}

static inline int ub_hfbarrier_hit(struct user_beancounter *ub, int resource)
{
	return (ub->ub_parms[resource].held > 
		((ub->ub_parms[resource].barrier) >> 1));
}

static inline int ub_barrier_farnr(struct user_beancounter *ub, int resource)
{
	struct ubparm *p;
	p = ub->ub_parms + resource;
	return p->held <= (p->barrier >> 3);
}

static inline int ub_barrier_farsz(struct user_beancounter *ub, int resource)
{
	struct ubparm *p;
	p = ub->ub_parms + resource;
	return p->held <= (p->barrier >> 3) && p->barrier >= 1024 * 1024;
}

#ifndef CONFIG_BEANCOUNTERS

#define ub_percpu_add(ub, f, v)	do { } while (0)
#define ub_percpu_sub(ub, f, v)	do { } while (0)
#define ub_percpu_inc(ub, f)	do { } while (0)
#define ub_percpu_dec(ub, f)	do { } while (0)

#define mm_ub(mm)	(NULL)

extern inline struct user_beancounter *get_beancounter_byuid
		(uid_t uid, int create) { return NULL; }
extern inline struct user_beancounter *get_beancounter
		(struct user_beancounter *ub) { return NULL; }
extern inline void put_beancounter(struct user_beancounter *ub) { }

static inline void ub_init_late(void) { };
static inline void ub_init_early(void) { };

static inline int charge_beancounter(struct user_beancounter *ub,
			int resource, unsigned long val,
			enum ub_severity strict) { return 0; }
static inline void uncharge_beancounter(struct user_beancounter *ub,
			int resource, unsigned long val) { }

#else /* CONFIG_BEANCOUNTERS */

#define ub_percpu_add(ub, field, v)		do {			\
		per_cpu_ptr(ub->ub_percpu, get_cpu())->field += (v);	\
		put_cpu();						\
	} while (0)
#define ub_percpu_inc(ub, field) ub_percpu_add(ub, field, 1)

#define ub_percpu_sub(ub, field, v)		do {			\
		per_cpu_ptr(ub->ub_percpu, get_cpu())->field -= (v);	\
		put_cpu();						\
	} while (0)
#define ub_percpu_dec(ub, field) ub_percpu_sub(ub, field, 1)

#define mm_ub(mm)	((mm)->mm_ub)
/*
 *  Charge/uncharge operations
 */

extern int __charge_beancounter_locked(struct user_beancounter *ub,
		int resource, unsigned long val, enum ub_severity strict);

extern void __uncharge_beancounter_locked(struct user_beancounter *ub,
		int resource, unsigned long val);

extern void put_beancounter_safe(struct user_beancounter *ub);
extern void __put_beancounter(struct user_beancounter *ub);

extern void uncharge_warn(struct user_beancounter *ub, int resource,
		unsigned long val, unsigned long held);

extern const char *ub_rnames[];
/*
 *	Put a beancounter reference
 */

static inline void put_beancounter(struct user_beancounter *ub)
{
	if (unlikely(ub == NULL))
		return;

	/* FIXME - optimize not to disable interrupts and make call */
	__put_beancounter(ub);
}

/* fast put, refcount can't reach zero */
static inline void __put_beancounter_batch(struct user_beancounter *ub, int n)
{
	atomic_sub(n, &ub->ub_refcount);
}

static inline void put_beancounter_batch(struct user_beancounter *ub, int n)
{
	if (n > 1)
		__put_beancounter_batch(ub, n - 1);
	__put_beancounter(ub);
}

/*
 *	Create a new beancounter reference
 */
extern struct user_beancounter *get_beancounter_byuid(uid_t uid, int create);

static inline 
struct user_beancounter *get_beancounter(struct user_beancounter *ub)
{
	if (unlikely(ub == NULL))
		return NULL;

	atomic_inc(&ub->ub_refcount);
	return ub;
}

static inline 
struct user_beancounter *get_beancounter_rcu(struct user_beancounter *ub)
{
	return atomic_inc_not_zero(&ub->ub_refcount) ? ub : NULL;
}

static inline void get_beancounter_batch(struct user_beancounter *ub, int n)
{
	atomic_add(n, &ub->ub_refcount);
}

extern struct user_beancounter *get_subbeancounter_byid(
		struct user_beancounter *,
		int id, int create);

extern void ub_init_late(void);
extern void ub_init_early(void);

extern int print_ub_uid(struct user_beancounter *ub, char *buf, int size);

/*
 *	Resource charging
 * Change user's account and compare against limits
 */

static inline void ub_adjust_maxheld(struct user_beancounter *ub, int resource)
{
	if (ub->ub_parms[resource].maxheld < ub->ub_parms[resource].held)
		ub->ub_parms[resource].maxheld = ub->ub_parms[resource].held;
	if (ub->ub_parms[resource].minheld > ub->ub_parms[resource].held)
		ub->ub_parms[resource].minheld = ub->ub_parms[resource].held;
}

int charge_beancounter(struct user_beancounter *ub, int resource,
		unsigned long val, enum ub_severity strict);
void uncharge_beancounter(struct user_beancounter *ub, int resource,
		unsigned long val);
void __charge_beancounter_notop(struct user_beancounter *ub, int resource,
		unsigned long val);
void __uncharge_beancounter_notop(struct user_beancounter *ub, int resource,
		unsigned long val);

static inline void charge_beancounter_notop(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	if (ub->parent != NULL)
		__charge_beancounter_notop(ub, resource, val);
}

static inline void uncharge_beancounter_notop(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	if (ub->parent != NULL)
		__uncharge_beancounter_notop(ub, resource, val);
}

#endif /* CONFIG_BEANCOUNTERS */

#ifndef CONFIG_BC_RSS_ACCOUNTING
static inline void ub_ini_pbc(void) { }
#else
extern void ub_init_pbc(void);
#endif
#endif /* __KERNEL__ */
#endif /* _LINUX_BEANCOUNTER_H */
