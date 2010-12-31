/*
 *  include/bc/rss_pages.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __RSS_PAGES_H_
#define __RSS_PAGES_H_

/*
 * Page_beancounters
 */

struct page;
struct user_beancounter;

#define PB_MAGIC 0x62700001UL

struct page_beancounter {
	unsigned long pb_magic;
	struct page *page;
	struct user_beancounter *ub;
	union {
		struct page_beancounter *next_hash;
		struct page_beancounter *page_pb_list;
	};
	union {
		unsigned refcount;
		unsigned io_debug;
	};
	union {
		struct list_head page_list;
		struct list_head io_list;
	};
};

#define PB_REFCOUNT_BITS 24
#define PB_SHIFT_GET(c) ((c) >> PB_REFCOUNT_BITS)
#define PB_SHIFT_INC(c) ((c) += (1 << PB_REFCOUNT_BITS))
#define PB_SHIFT_DEC(c) ((c) -= (1 << PB_REFCOUNT_BITS))
#define PB_COUNT_GET(c) ((c) & ((1 << PB_REFCOUNT_BITS) - 1))
#define PB_COUNT_INC(c) ((c)++)
#define PB_COUNT_DEC(c) ((c)--)
#define PB_REFCOUNT_MAKE(s, c) (((s) << PB_REFCOUNT_BITS) + (c))

#define page_pbc(__page)        ((__page)->bc.page_pb)

extern spinlock_t pb_lock;

struct address_space;
extern int is_shmem_mapping(struct address_space *);

#endif
