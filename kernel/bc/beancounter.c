/*
 *  linux/kernel/bc/beancounter.c
 *
 *  Copyright (C) 1998  Alan Cox
 *                1998-2000  Andrey V. Savochkin <saw@saw.sw.com.sg>
 *  Copyright (C) 2000-2005 SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 * TODO:
 *   - more intelligent limit check in mremap(): currently the new size is
 *     charged and _then_ old size is uncharged
 *     (almost done: !move_vma case is completely done,
 *      move_vma in its current implementation requires too many conditions to
 *      do things right, because it may be not only expansion, but shrinking
 *      also, plus do_munmap will require an additional parameter...)
 *   - problem: bad pmd page handling
 *   - consider /proc redesign
 *   - TCP/UDP ports
 *   + consider whether __charge_beancounter_locked should be inline
 *
 * Changes:
 *   1999/08/17  Marcelo Tosatti <marcelo@conectiva.com.br>
 *	- Set "barrier" and "limit" parts of limits atomically.
 *   1999/10/06  Marcelo Tosatti <marcelo@conectiva.com.br>
 *	- setublimit system call.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/random.h>

#include <bc/beancounter.h>
#include <bc/hash.h>
#include <bc/vmpages.h>
#include <bc/proc.h>

static struct kmem_cache *ub_cachep;
static struct user_beancounter default_beancounter;
struct user_beancounter ub0;
EXPORT_SYMBOL_GPL(ub0);

const char *ub_rnames[] = {
	"kmemsize",	/* 0 */
	"lockedpages",
	"privvmpages",
	"shmpages",
	"dummy",
	"numproc",	/* 5 */
	"physpages",
	"vmguarpages",
	"oomguarpages",
	"numtcpsock",
	"numflock",	/* 10 */
	"numpty",
	"numsiginfo",
	"tcpsndbuf",
	"tcprcvbuf",
	"othersockbuf",	/* 15 */
	"dgramrcvbuf",
	"numothersock",
	"dcachesize",
	"numfile",
	"dummy",	/* 20 */
	"dummy",
	"dummy",
	"numiptent",
	"swappages",
	"unused_privvmpages",	/* UB_RESOURCES */
	"tmpfs_respages",
	"held_pages",
};

static void init_beancounter_struct(struct user_beancounter *ub);
static void init_beancounter_store(struct user_beancounter *ub);
static void init_beancounter_nolimits(struct user_beancounter *ub);

int print_ub_uid(struct user_beancounter *ub, char *buf, int size)
{
	if (ub->parent != NULL)
		return snprintf(buf, size, "%u.%u",
				ub->parent->ub_uid, ub->ub_uid);
	else
		return snprintf(buf, size, "%u", ub->ub_uid);
}
EXPORT_SYMBOL(print_ub_uid);

#define ub_hash_fun(x) ((((x) >> 8) ^ (x)) & (UB_HASH_SIZE - 1))
#define ub_subhash_fun(p, id) ub_hash_fun((p)->ub_uid + (id) * 17)
struct hlist_head ub_hash[UB_HASH_SIZE];
DEFINE_SPINLOCK(ub_hash_lock);
LIST_HEAD(ub_list_head); /* protected by ub_hash_lock */
EXPORT_SYMBOL(ub_hash);
EXPORT_SYMBOL(ub_hash_lock);
EXPORT_SYMBOL(ub_list_head);

/*
 *	Per user resource beancounting. Resources are tied to their luid.
 *	The resource structure itself is tagged both to the process and
 *	the charging resources (a socket doesn't want to have to search for
 *	things at irq time for example). Reference counters keep things in
 *	hand.
 *
 *	The case where a user creates resource, kills all his processes and
 *	then starts new ones is correctly handled this way. The refcounters
 *	will mean the old entry is still around with resource tied to it.
 */

static struct user_beancounter *alloc_ub(uid_t uid, struct user_beancounter *p)
{
	struct user_beancounter *new_ub;

	ub_debug(UBD_ALLOC, "Creating ub %p\n", new_ub);

	new_ub = (struct user_beancounter *)kmem_cache_alloc(ub_cachep, 
			GFP_KERNEL);
	if (new_ub == NULL)
		return NULL;

	if (p == NULL) {
		memcpy(new_ub, &default_beancounter, sizeof(*new_ub));
		init_beancounter_struct(new_ub);
	} else {
		memset(new_ub, 0, sizeof(*new_ub));
		init_beancounter_struct(new_ub);
		init_beancounter_nolimits(new_ub);
		init_beancounter_store(new_ub);
	}

	if (percpu_counter_init(&new_ub->ub_orphan_count, 0))
		goto fail_pcpu;

	new_ub->ub_percpu = alloc_percpu(struct ub_percpu_struct);
	if (new_ub->ub_percpu == NULL)
		goto fail_free;

	new_ub->ub_uid = uid;
	new_ub->parent = get_beancounter(p);
	return new_ub;

fail_free:
	percpu_counter_destroy(&new_ub->ub_orphan_count);
fail_pcpu:
	kmem_cache_free(ub_cachep, new_ub);
	return NULL;
}

static inline void __free_ub(struct user_beancounter *ub)
{
	free_percpu(ub->ub_percpu);
	kmem_cache_free(ub_cachep, ub);
}

static inline void free_ub(struct user_beancounter *ub)
{
	percpu_counter_destroy(&ub->ub_orphan_count);
	__free_ub(ub);
}

static inline struct user_beancounter *bc_lookup_hash(struct hlist_head *hash,
		uid_t uid, struct user_beancounter *parent)
{
	struct user_beancounter *ub;
	struct hlist_node *ptr;

	hlist_for_each_entry (ub, ptr, hash, ub_hash)
		if (ub->ub_uid == uid && ub->parent == parent)
			return get_beancounter(ub);

	return NULL;
}

int ub_count;

/* next two must be called under ub_hash_lock */
static inline void ub_count_inc(struct user_beancounter *ub)
{
	if (ub->parent)
		ub->parent->ub_childs++;
	else
	       ub_count++;
}

static inline void ub_count_dec(struct user_beancounter *ub)
{
	if (ub->parent)
		ub->parent->ub_childs--;
	else
		ub_count--;
}

struct user_beancounter *get_beancounter_byuid(uid_t uid, int create)
{
	struct user_beancounter *new_ub, *ub;
	unsigned long flags;
	struct hlist_head *hash;

	hash = &ub_hash[ub_hash_fun(uid)];
	new_ub = NULL;
retry:
	spin_lock_irqsave(&ub_hash_lock, flags);
	ub = bc_lookup_hash(hash, uid, NULL);
	if (ub != NULL) {
		spin_unlock_irqrestore(&ub_hash_lock, flags);

		if (new_ub != NULL)
			free_ub(new_ub);
		return ub;
	}

	if (!create) {
		/* no ub found */
		spin_unlock_irqrestore(&ub_hash_lock, flags);
		return NULL;
	}

	if (new_ub != NULL) {
		list_add_rcu(&new_ub->ub_list, &ub_list_head);
		hlist_add_head(&new_ub->ub_hash, hash);
		ub_count_inc(new_ub);
		spin_unlock_irqrestore(&ub_hash_lock, flags);
		return new_ub;
	}
	spin_unlock_irqrestore(&ub_hash_lock, flags);

	new_ub = alloc_ub(uid, NULL);
	if (new_ub == NULL)
		return NULL;

	goto retry;

}
EXPORT_SYMBOL(get_beancounter_byuid);

struct user_beancounter *get_subbeancounter_byid(struct user_beancounter *p,
		int id, int create)
{
	struct user_beancounter *new_ub, *ub;
	unsigned long flags;
	struct hlist_head *hash;

	hash = &ub_hash[ub_subhash_fun(p, id)];
	new_ub = NULL;
retry:
	spin_lock_irqsave(&ub_hash_lock, flags);
	ub = bc_lookup_hash(hash, id, p);
	if (ub != NULL) {
		spin_unlock_irqrestore(&ub_hash_lock, flags);

		if (new_ub != NULL) {
			put_beancounter(new_ub->parent);
			free_ub(new_ub);
		}
		return ub;
	}

	if (!create) {
		/* no ub found */
		spin_unlock_irqrestore(&ub_hash_lock, flags);
		return NULL;
	}

	if (new_ub != NULL) {
		list_add_rcu(&new_ub->ub_list, &ub_list_head);
		hlist_add_head(&new_ub->ub_hash, hash);
		ub_count_inc(new_ub);
		spin_unlock_irqrestore(&ub_hash_lock, flags);
		return new_ub;
	}
	spin_unlock_irqrestore(&ub_hash_lock, flags);

	new_ub = alloc_ub(id, p);
	if (new_ub == NULL)
		return NULL;

	goto retry;
}
EXPORT_SYMBOL(get_subbeancounter_byid);

static void put_warn(struct user_beancounter *ub)
{
	char id[64];

	print_ub_uid(ub, id, sizeof(id));
	printk(KERN_ERR "UB: Bad refcount (%d) on put of %s (%p)\n",
			atomic_read(&ub->ub_refcount), id, ub);
}

#ifdef CONFIG_BC_KEEP_UNUSED
#define release_beancounter(ub)	do { } while (0)
#else
static int verify_res(struct user_beancounter *ub, int resource,
		unsigned long held)
{
	char id[64];

	if (likely(held == 0))
		return 1;

	print_ub_uid(ub, id, sizeof(id));
	printk(KERN_WARNING "Ub %s helds %lu in %s on put\n",
			id, held, ub_rnames[resource]);
	return 0;
}

static inline void bc_verify_held(struct user_beancounter *ub)
{
	int i, clean;

	clean = 1;
	for (i = 0; i < UB_RESOURCES; i++)
		clean &= verify_res(ub, i, ub->ub_parms[i].held);

	clean &= verify_res(ub, UB_UNUSEDPRIVVM, ub->ub_unused_privvmpages);
	clean &= verify_res(ub, UB_TMPFSPAGES, ub->ub_tmpfs_respages);
	clean &= verify_res(ub, UB_HELDPAGES, (unsigned long)ub->ub_held_pages);

	ub_debug_trace(!clean, 5, 60*HZ);
}

static void bc_free_rcu(struct rcu_head *rcu)
{
	struct user_beancounter *ub;

	ub = container_of(rcu, struct user_beancounter, rcu);
	__free_ub(ub);
}

static void delayed_release_beancounter(struct work_struct *w)
{
	struct user_beancounter *ub, *parent;
	unsigned long flags;

	ub = container_of(w, struct user_beancounter, cleanup.work);
again:
	local_irq_save(flags);
	if (!atomic_dec_and_lock(&ub->ub_refcount, &ub_hash_lock)) {
		/* raced with get_beancounter_byuid */
		local_irq_restore(flags);
		return;
	}

	hlist_del(&ub->ub_hash);
	ub_count_dec(ub);
	list_del_rcu(&ub->ub_list);
	spin_unlock_irqrestore(&ub_hash_lock, flags);

	bc_verify_held(ub);
	ub_free_counters(ub);
	percpu_counter_destroy(&ub->ub_orphan_count);

	parent = ub->parent;

	call_rcu(&ub->rcu, bc_free_rcu);
	if (parent) {
		ub = parent;
		goto again;
	}
}

static inline void release_beancounter(struct user_beancounter *ub)
{
	struct execute_work *ew;

	ew = &ub->cleanup;
	INIT_WORK(&ew->work, delayed_release_beancounter);
	schedule_work(&ew->work);
}
#endif

void __put_beancounter(struct user_beancounter *ub)
{
	unsigned long flags;

	/* equevalent to atomic_dec_and_lock_irqsave() */
	local_irq_save(flags);
	if (likely(!atomic_dec_and_lock(&ub->ub_refcount, &ub_hash_lock))) {
		if (unlikely(atomic_read(&ub->ub_refcount) < 0))
			put_warn(ub);
		local_irq_restore(flags);
		return;
	}

	if (unlikely(ub == get_ub0())) {
		printk(KERN_ERR "Trying to put ub0\n");
		spin_unlock_irqrestore(&ub_hash_lock, flags);
		return;
	}

	/* prevent get_beancounter_byuid + put_beancounter() reentrance */
	atomic_inc(&ub->ub_refcount);
	spin_unlock_irqrestore(&ub_hash_lock, flags);

	release_beancounter(ub);
}
EXPORT_SYMBOL(__put_beancounter);

void put_beancounter_safe(struct user_beancounter *ub)
{
	synchronize_rcu();
	__put_beancounter(ub);
}
EXPORT_SYMBOL(put_beancounter_safe);

/*
 *	Generic resource charging stuff
 */

int __charge_beancounter_locked(struct user_beancounter *ub,
		int resource, unsigned long val, enum ub_severity strict)
{
	ub_debug_resource(resource, "Charging %lu for %d of %p with %lu\n",
			val, resource, ub, ub->ub_parms[resource].held);
	/*
	 * ub_value <= UB_MAXVALUE, value <= UB_MAXVALUE, and only one addition
	 * at the moment is possible so an overflow is impossible.  
	 */
	ub->ub_parms[resource].held += val;

	switch (strict) {
		case UB_HARD:
			if (ub->ub_parms[resource].held >
					ub->ub_parms[resource].barrier)
				break;
		case UB_SOFT:
			if (ub->ub_parms[resource].held >
					ub->ub_parms[resource].limit)
				break;
		case UB_FORCE:
			ub_adjust_maxheld(ub, resource);
			return 0;
		default:
			BUG();
	}

	if (strict == UB_SOFT && ub_ratelimit(&ub->ub_limit_rl))
		printk(KERN_INFO "Fatal resource shortage: %s, UB %d.\n",
		       ub_rnames[resource], ub->ub_uid);
	ub->ub_parms[resource].failcnt++;
	ub->ub_parms[resource].held -= val;
	return -ENOMEM;
}

int charge_beancounter(struct user_beancounter *ub,
		int resource, unsigned long val, enum ub_severity strict)
{
	int retval;
	struct user_beancounter *p, *q;
	unsigned long flags;

	retval = -EINVAL;
	if (val > UB_MAXVALUE)
		goto out;

	local_irq_save(flags);
	for (p = ub; p != NULL; p = p->parent) {
		spin_lock(&p->ub_lock);
		retval = __charge_beancounter_locked(p, resource, val, strict);
		spin_unlock(&p->ub_lock);
		if (retval)
			goto unroll;
	}
out_restore:
	local_irq_restore(flags);
out:
	return retval;

unroll:
	for (q = ub; q != p; q = q->parent) {
		spin_lock(&q->ub_lock);
		__uncharge_beancounter_locked(q, resource, val);
		spin_unlock(&q->ub_lock);
	}
	goto out_restore;
}

EXPORT_SYMBOL(charge_beancounter);

void __charge_beancounter_notop(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	struct user_beancounter *p;
	unsigned long flags;

	local_irq_save(flags);
	for (p = ub; p->parent != NULL; p = p->parent) {
		spin_lock(&p->ub_lock);
		__charge_beancounter_locked(p, resource, val, UB_FORCE);
		spin_unlock(&p->ub_lock);
	}
	local_irq_restore(flags);
}

EXPORT_SYMBOL(__charge_beancounter_notop);

void uncharge_warn(struct user_beancounter *ub, int resource,
		unsigned long val, unsigned long held)
{
	char id[64];

	print_ub_uid(ub, id, sizeof(id));
	printk(KERN_ERR "Uncharging too much %lu h %lu, res %s ub %s\n",
			val, held, ub_rnames[resource], id);
	ub_debug_trace(1, 10, 10*HZ);
}

void __uncharge_beancounter_locked(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	ub_debug_resource(resource, "Uncharging %lu for %d of %p with %lu\n",
			val, resource, ub, ub->ub_parms[resource].held);
	if (ub->ub_parms[resource].held < val) {
		uncharge_warn(ub, resource,
				val, ub->ub_parms[resource].held);
		val = ub->ub_parms[resource].held;
	}
	ub->ub_parms[resource].held -= val;
}

void uncharge_beancounter(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	unsigned long flags;
	struct user_beancounter *p;

	for (p = ub; p != NULL; p = p->parent) {
		spin_lock_irqsave(&p->ub_lock, flags);
		__uncharge_beancounter_locked(p, resource, val);
		spin_unlock_irqrestore(&p->ub_lock, flags);
	}
}

EXPORT_SYMBOL(uncharge_beancounter);

void __uncharge_beancounter_notop(struct user_beancounter *ub,
		int resource, unsigned long val)
{
	struct user_beancounter *p;
	unsigned long flags;

	local_irq_save(flags);
	for (p = ub; p->parent != NULL; p = p->parent) {
		spin_lock(&p->ub_lock);
		__uncharge_beancounter_locked(p, resource, val);
		spin_unlock(&p->ub_lock);
	}
	local_irq_restore(flags);
}

EXPORT_SYMBOL(__uncharge_beancounter_notop);


/*
 *	Rate limiting stuff.
 */
int ub_ratelimit(struct ub_rate_info *p)
{
	unsigned long cjif, djif;
	unsigned long flags;
	static spinlock_t ratelimit_lock = SPIN_LOCK_UNLOCKED;
	long new_bucket;

	spin_lock_irqsave(&ratelimit_lock, flags);
	cjif = jiffies;
	djif = cjif - p->last;
	if (djif < p->interval) {
		if (p->bucket >= p->burst) {
			spin_unlock_irqrestore(&ratelimit_lock, flags);
			return 0;
		}
		p->bucket++;
	} else {
		new_bucket = p->bucket - (djif / (unsigned)p->interval);
		if (new_bucket < 0)
			new_bucket = 0;
		p->bucket = new_bucket + 1;
	}
	p->last = cjif;
	spin_unlock_irqrestore(&ratelimit_lock, flags);
	return 1;
}
EXPORT_SYMBOL(ub_ratelimit);


/*
 *	Initialization
 *
 *	struct user_beancounter contains
 *	 - limits and other configuration settings,
 *	   with a copy stored for accounting purposes,
 *	 - structural fields: lists, spinlocks and so on.
 *
 *	Before these parts are initialized, the structure should be memset
 *	to 0 or copied from a known clean structure.  That takes care of a lot
 *	of fields not initialized explicitly.
 */

static void init_beancounter_struct(struct user_beancounter *ub)
{
	ub->ub_magic = UB_MAGIC;
	ub->ub_cookie = get_random_int();
	atomic_set(&ub->ub_refcount, 1);
	spin_lock_init(&ub->ub_lock);
	INIT_LIST_HEAD(&ub->ub_tcp_sk_list);
	INIT_LIST_HEAD(&ub->ub_other_sk_list);
#ifdef CONFIG_BC_DEBUG_KMEM
	INIT_LIST_HEAD(&ub->ub_cclist);
#endif
}

static void init_beancounter_store(struct user_beancounter *ub)
{
	int k;

	for (k = 0; k < UB_RESOURCES; k++) {
		memcpy(&ub->ub_store[k], &ub->ub_parms[k],
				sizeof(struct ubparm));
	}
}

static void init_beancounter_nolimits(struct user_beancounter *ub)
{
	int k;

	for (k = 0; k < UB_RESOURCES; k++) {
		ub->ub_parms[k].limit = UB_MAXVALUE;
		/* FIXME: whether this is right for physpages and guarantees? */
		ub->ub_parms[k].barrier = UB_MAXVALUE;
	}

	/* FIXME: set unlimited rate? */
	ub->ub_limit_rl.burst = 4;
	ub->ub_limit_rl.interval = 300*HZ;
}

static void init_beancounter_syslimits(struct user_beancounter *ub)
{
	unsigned long mp;
	extern int max_threads;
	int k;

	mp = num_physpages;
	ub->ub_parms[UB_KMEMSIZE].limit = 
		mp > (192*1024*1024 >> PAGE_SHIFT) ?
				32*1024*1024 : (mp << PAGE_SHIFT) / 6;
	ub->ub_parms[UB_LOCKEDPAGES].limit = 8;
	ub->ub_parms[UB_PRIVVMPAGES].limit = UB_MAXVALUE;
	ub->ub_parms[UB_SHMPAGES].limit = 64;
	ub->ub_parms[UB_NUMPROC].limit = max_threads / 2;
	ub->ub_parms[UB_NUMTCPSOCK].limit = 1024;
	ub->ub_parms[UB_TCPSNDBUF].limit = 1024*4*1024; /* 4k per socket */
	ub->ub_parms[UB_TCPRCVBUF].limit = 1024*6*1024; /* 6k per socket */
	ub->ub_parms[UB_NUMOTHERSOCK].limit = 256;
	ub->ub_parms[UB_DGRAMRCVBUF].limit = 256*4*1024; /* 4k per socket */
	ub->ub_parms[UB_OTHERSOCKBUF].limit = 256*8*1024; /* 8k per socket */
	ub->ub_parms[UB_NUMFLOCK].limit = 1024;
	ub->ub_parms[UB_NUMPTY].limit = 16;
	ub->ub_parms[UB_NUMSIGINFO].limit = 1024;
	ub->ub_parms[UB_DCACHESIZE].limit = 1024*1024;
	ub->ub_parms[UB_NUMFILE].limit = 1024;
	ub->ub_parms[UB_SWAPPAGES].limit = UB_MAXVALUE;

	for (k = 0; k < UB_RESOURCES; k++)
		ub->ub_parms[k].barrier = ub->ub_parms[k].limit;

	ub->ub_limit_rl.burst = 4;
	ub->ub_limit_rl.interval = 300*HZ;
}

static DEFINE_PER_CPU(struct ub_percpu_struct, ub0_percpu);

void __init ub_init_early(void)
{
	struct user_beancounter *ub;

	init_cache_counters();
	ub = get_ub0();
	memset(ub, 0, sizeof(*ub));
	ub->ub_uid = 0;
	init_beancounter_nolimits(ub);
	init_beancounter_store(ub);
	init_beancounter_struct(ub);
	ub->ub_percpu = &per_cpu__ub0_percpu;

	memset(&current->task_bc, 0, sizeof(struct task_beancounter));
	(void)set_exec_ub(ub);
	current->task_bc.task_ub = get_beancounter(ub);
	__charge_beancounter_locked(ub, UB_NUMPROC, 1, UB_FORCE);
	current->task_bc.fork_sub = get_beancounter(ub);
	ub_init_task_bc(&current->task_bc);
	init_mm.mm_ub = get_beancounter(ub);

	hlist_add_head(&ub->ub_hash, &ub_hash[ub->ub_uid]);
	list_add(&ub->ub_list, &ub_list_head);
	ub_count_inc(ub);
}

void __init ub_init_late(void)
{
	ub_cachep = kmem_cache_create("user_beancounters",
			sizeof(struct user_beancounter),
			0, SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);

	memset(&default_beancounter, 0, sizeof(default_beancounter));
#ifdef CONFIG_BC_UNLIMITED
	init_beancounter_nolimits(&default_beancounter);
#else
	init_beancounter_syslimits(&default_beancounter);
#endif
	init_beancounter_store(&default_beancounter);
	init_beancounter_struct(&default_beancounter);
}
