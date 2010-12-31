/*
 *  kernel/bc/rss_pages.c
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>

#include <bc/beancounter.h>
#include <bc/hash.h>
#include <bc/vmpages.h>
#include <bc/rss_pages.h>
#include <bc/io_acct.h>

static struct kmem_cache *pb_cachep;
spinlock_t pb_lock = SPIN_LOCK_UNLOCKED;
static struct page_beancounter **pb_hash_table;
static unsigned int pb_hash_mask;

/*
 * Auxiliary staff
 */

static inline struct page_beancounter *next_page_pb(struct page_beancounter *p)
{
	return list_entry(p->page_list.next, struct page_beancounter,
			page_list);
}

static inline struct page_beancounter *prev_page_pb(struct page_beancounter *p)
{
	return list_entry(p->page_list.prev, struct page_beancounter,
			page_list);
}

/*
 * Held pages manipulation
 */
static inline void set_held_pages(struct user_beancounter *bc)
{
	/* all three depend on ub_held_pages */
	__ub_update_physpages(bc);
	__ub_update_oomguarpages(bc);
	__ub_update_privvm(bc);
}

static inline void do_dec_held_pages(struct user_beancounter *ub, int value)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	ub->ub_held_pages -= value;
	set_held_pages(ub);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

static void dec_held_pages(struct user_beancounter *ub, int value)
{
	for (; ub != NULL; ub = ub->parent)
		do_dec_held_pages(ub, value);
}

static inline void do_inc_held_pages(struct user_beancounter *ub, int value)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	ub->ub_held_pages += value;
	set_held_pages(ub);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

static void inc_held_pages(struct user_beancounter *ub, int value)
{
	for (; ub != NULL; ub = ub->parent)
		do_inc_held_pages(ub, value);
}

/*
 * ++ and -- beyond are protected with pb_lock
 */

static inline void inc_pbc_count(struct user_beancounter *ub)
{
	for (; ub != NULL; ub = ub->parent)
		ub->ub_pbcs++;
}

static inline void dec_pbc_count(struct user_beancounter *ub)
{
	for (; ub != NULL; ub = ub->parent)
		ub->ub_pbcs--;
}

/*
 * Alloc - free
 */

inline int pb_alloc(struct page_beancounter **pbc)
{
	*pbc = kmem_cache_alloc(pb_cachep, GFP_KERNEL);
	if (*pbc != NULL) {
		(*pbc)->next_hash = NULL;
		(*pbc)->pb_magic = PB_MAGIC;
	}
	return (*pbc == NULL);
}

inline void pb_free(struct page_beancounter **pb)
{
	if (*pb != NULL) {
		kmem_cache_free(pb_cachep, *pb);
		*pb = NULL;
	}
}

void pb_free_list(struct page_beancounter **p_pb)
{
	struct page_beancounter *list, *pb;
	
	list = *p_pb;
	if (list == PBC_COPY_SAME)
		return;

	while (list) {
		pb = list;
		list = list->next_hash;
		pb_free(&pb);
	}
	*p_pb = NULL;
}

/*
 * head -> <new objs> -> <old objs> -> ...
 */
static int __alloc_list(struct page_beancounter **head, int num)
{
	struct page_beancounter *pb;

	while (num > 0) {
		if (pb_alloc(&pb))
			return -1;
		pb->next_hash = *head;
		*head = pb;
		num--;
	}

	return num;
}

/* 
 * Ensure that the list contains at least num elements.
 * p_pb points to an initialized list, may be of the zero length. 
 *
 * mm->page_table_lock should be held
 */
int pb_alloc_list(struct page_beancounter **p_pb, int num)
{
	struct page_beancounter *list;

	for (list = *p_pb; list != NULL && num; list = list->next_hash, num--);
	if (!num)
		return 0;

	/*
	 *  *p_pb(after)       *p_pb (before)
	 *     \                  \
	 *     <new objs> -...-> <old objs> -> ...
	 */
	if (__alloc_list(p_pb, num) < 0)
		goto nomem;
	return 0;

nomem:
	pb_free_list(p_pb);
	return -ENOMEM;
}

/*
 * Allocates a page_beancounter for each
 * user_beancounter in a hash
 */
int pb_alloc_all(struct page_beancounter **pbs)
{
	int need_alloc;
	struct user_beancounter *ub;

	need_alloc = 0;
	rcu_read_lock();
	for_each_beancounter(ub)
		need_alloc++;
	rcu_read_unlock();

	if (!__alloc_list(pbs, need_alloc))
		return 0;

	pb_free_list(pbs);
	return -ENOMEM;
}

/*
 * Hash routines
 */

static inline int pb_hash(struct user_beancounter *ub, struct page *page)
{
	return (page_to_pfn(page) ^ ub->ub_cookie) & pb_hash_mask;
}

/* pb_lock should be held */
static inline void insert_pb(struct page_beancounter *p, struct page *page,
		struct user_beancounter *ub, int hash)
{
	p->page = page;
	p->ub = get_beancounter(ub);
	p->next_hash = pb_hash_table[hash];
	pb_hash_table[hash] = p;
	inc_pbc_count(ub);
}

/*
 * Heart
 */

static int __pb_dup_ref(struct page *page, struct user_beancounter *bc,
		int hash)
{
	struct page_beancounter *p;

	for (p = pb_hash_table[hash];
			p != NULL && (p->page != page || p->ub != bc);
			p = p->next_hash);
	if (p == NULL)
		return -1;

	PB_COUNT_INC(p->refcount);
	return 0;
}

static void __pb_add_ref(struct page *page, struct user_beancounter *bc,
		struct page_beancounter **ppb, int hash)
{
	struct page_beancounter *head, *p, **hp;
	int shift;

	p = *ppb;
	*ppb = p->next_hash;

	insert_pb(p, page, bc, hash);
	hp = page_pblist(page);
	head = *hp;

	if (head != NULL) {
		/* 
		 * Move the first element to the end of the list.
		 * List head (pb_head) is set to the next entry.
		 * Note that this code works even if head is the only element
		 * on the list (because it's cyclic). 
		 */
		BUG_ON(head->pb_magic != PB_MAGIC);
		*hp = next_page_pb(head);
		PB_SHIFT_INC(head->refcount);
		shift = PB_SHIFT_GET(head->refcount);
		/* 
		 * Update user beancounter, the share of head has been changed.
		 * Note that the shift counter is taken after increment. 
		 */
		dec_held_pages(head->ub, UB_PAGE_WEIGHT >> shift);
		/* add the new page beancounter to the end of the list */
		head = *hp;
		list_add_tail(&p->page_list, &head->page_list);
	} else {
		*hp = p;
		shift = 0;
		INIT_LIST_HEAD(&p->page_list);
	}

	p->refcount = PB_REFCOUNT_MAKE(shift, 1);
	/* update user beancounter for the new page beancounter */
	inc_held_pages(bc, UB_PAGE_WEIGHT >> shift);
}

void pb_add_ref(struct page *page, struct mm_struct *mm,
		struct page_beancounter **p_pb)
{
	int hash;
	struct user_beancounter *bc;

	bc = mm->mm_ub;
	if (bc == NULL)
		return;

	if (!PageAnon(page) && is_shmem_mapping(page->mapping))
		return;

	hash = pb_hash(bc, page);

	spin_lock(&pb_lock);
	if (__pb_dup_ref(page, bc, hash))
		__pb_add_ref(page, bc, p_pb, hash);
	spin_unlock(&pb_lock);
}

void pb_dup_ref(struct page *page, struct mm_struct *mm,
		struct page_beancounter **p_pb)
{
	int hash;
	struct user_beancounter *bc;

	bc = mm->mm_ub;
	if (bc == NULL)
		return;

	if (!PageAnon(page) && is_shmem_mapping(page->mapping))
		return;

	hash = pb_hash(bc, page);

	spin_lock(&pb_lock);
	if (*page_pblist(page) == NULL)
		/*
		 * pages like ZERO_PAGE must not be accounted in pbc
		 * so on fork we just skip them
		 */
		goto out_unlock;

	if (unlikely(*p_pb != PBC_COPY_SAME))
		__pb_add_ref(page, bc, p_pb, hash);
	else if (unlikely(__pb_dup_ref(page, bc, hash)))
		WARN_ON(1);
out_unlock:
	spin_unlock(&pb_lock);
}

void pb_remove_ref(struct page *page, struct mm_struct *mm)
{
	int hash;
	struct user_beancounter *bc;
	struct page_beancounter *p, **q, *f;
	int shift, shiftt;

	bc = mm->mm_ub;
	if (bc == NULL)
		return;

	if (!PageAnon(page) && is_shmem_mapping(page->mapping))
		return;

	hash = pb_hash(bc, page);

	spin_lock(&pb_lock);
	for (q = pb_hash_table + hash, p = *q;
			p != NULL && (p->page != page || p->ub != bc);
			q = &p->next_hash, p = *q);
	if (p == NULL)
		goto out_unlock;

	PB_COUNT_DEC(p->refcount);
	if (PB_COUNT_GET(p->refcount))
		/* 
		 * More references from the same user beancounter exist.
		 * Nothing needs to be done. 
		 */
		goto out_unlock;

	/* remove from the hash list */
	f = p;
	*q = p->next_hash;

	shift = PB_SHIFT_GET(p->refcount);

	dec_held_pages(p->ub, UB_PAGE_WEIGHT >> shift);

	q = page_pblist(page);
	if (*q == p) {
		if (list_empty(&p->page_list)) {
			*q = NULL;
			goto out_free;
		}

		*q = next_page_pb(p);
	}
	list_del(&p->page_list);

	/* Now balance the list.  Move the tail and adjust its shift counter. */
	p = prev_page_pb(*q);
	shiftt = PB_SHIFT_GET(p->refcount);
	*q = p;
	PB_SHIFT_DEC(p->refcount);

	inc_held_pages(p->ub, UB_PAGE_WEIGHT >> shiftt);

	/* 
	 * If the shift counter of the moved beancounter is different from the
	 * removed one's, repeat the procedure for one more tail beancounter 
	 */
	if (shiftt > shift) {
		p = prev_page_pb(*q);
		*q = p;
		PB_SHIFT_DEC(p->refcount);
		inc_held_pages(p->ub, UB_PAGE_WEIGHT >> shiftt);
	}
out_free:
	dec_pbc_count(f->ub);
	spin_unlock(&pb_lock);

	put_beancounter(f->ub);
	pb_free(&f);
	return;

out_unlock:
	spin_unlock(&pb_lock);
}

struct user_beancounter *pb_grab_page_ub(struct page *page)
{
	struct page_beancounter *pb;
	struct user_beancounter *ub;

	spin_lock(&pb_lock);
	pb = *page_pblist(page);
	ub = (pb == NULL ? ERR_PTR(-EINVAL) :
			get_beancounter(pb->ub));
	spin_unlock(&pb_lock);
	return ub;
}

void __init ub_init_pbc(void)
{
	unsigned long hash_size;

	pb_cachep = kmem_cache_create("page_beancounter", 
			sizeof(struct page_beancounter), 0,
			SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);
	hash_size = num_physpages >> 2;
	for (pb_hash_mask = 1;
		(hash_size & pb_hash_mask) != hash_size;
		pb_hash_mask = (pb_hash_mask << 1) + 1);
	hash_size = pb_hash_mask + 1;
	printk(KERN_INFO "Page beancounter hash is %lu entries.\n", hash_size);
	pb_hash_table = vmalloc(hash_size * sizeof(struct page_beancounter *));
	memset(pb_hash_table, 0, hash_size * sizeof(struct page_beancounter *));

	ub_init_io(pb_cachep);
}
