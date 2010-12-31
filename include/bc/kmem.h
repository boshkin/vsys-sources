/*
 *  include/bc/kmem.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __UB_SLAB_H_
#define __UB_SLAB_H_

#include <bc/beancounter.h>
#include <bc/decl.h>

/*
 * UB_KMEMSIZE accounting
 */

#ifdef CONFIG_BC_DEBUG_ITEMS
#define CHARGE_ORDER(__o)		(1 << (__o))
#define CHARGE_SIZE(__s)		1
#else
#define CHARGE_ORDER(__o)		(PAGE_SIZE << (__o))
#define CHARGE_SIZE(__s)		(__s)
#endif

#ifdef CONFIG_BEANCOUNTERS
#define page_ub(__page)	((__page)->bc.page_ub)
#else
#define page_ub(__page)	NULL
#endif

struct mm_struct;
struct page;
struct kmem_cache;

UB_DECLARE_FUNC(struct user_beancounter *, vmalloc_ub(void *obj))
UB_DECLARE_FUNC(struct user_beancounter *, mem_ub(void *obj))

UB_DECLARE_FUNC(int, ub_kmemsize_charge(struct user_beancounter *ub,
		unsigned long size, enum ub_severity strict))
UB_DECLARE_VOID_FUNC(ub_kmemsize_uncharge(struct user_beancounter *ub,
		unsigned long size))

UB_DECLARE_FUNC(int, ub_page_charge(struct page *page, int order, gfp_t mask))
UB_DECLARE_VOID_FUNC(ub_page_uncharge(struct page *page, int order))
UB_DECLARE_FUNC(int, ub_slab_charge(struct kmem_cache *cachep,
			void *objp, gfp_t flags))
UB_DECLARE_VOID_FUNC(ub_slab_uncharge(struct kmem_cache *cachep, void *obj))

#ifdef CONFIG_BEANCOUNTERS
static inline int should_charge(unsigned long cflags, gfp_t flags)
{
	if (!(cflags & SLAB_UBC))
		return 0;
	if ((cflags & SLAB_NO_CHARGE) && !(flags & __GFP_UBC))
		return 0;
	return 1;
}

#define should_uncharge(cflags)	should_charge(cflags, __GFP_UBC)
#else
#define should_charge(cflags, f)	0
#define should_uncharge(cflags)		0
#endif

#endif /* __UB_SLAB_H_ */
