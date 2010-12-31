/*
 *  include/bc/io_acct.h
 *
 *  Copyright (C) 2006 SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 *  Pavel Emelianov <xemul@openvz.org>
 *
 */

#ifndef __UB_IO_ACCT_H_
#define __UB_IO_ACCT_H_

#define PAGE_IO_MARK   (0x1UL)

#ifdef CONFIG_BC_IO_ACCOUNTING
#include <bc/beancounter.h>
#include <bc/rss_pages.h>

#define page_iopb(page)	({			\
		struct page_beancounter *pb;	\
		pb = page_pbc(page);		\
		rmb();				\
		pb;				\
	})

/*
 * IO ub is required in task context only, so if exec_ub is set
 * to NULL this means that uses doesn't need to charge some
 * resources. nevertheless IO activity must be accounted, so we
 * account it to current's task beancounter.
 */

static inline struct user_beancounter *get_io_ub(void)
{
	struct user_beancounter *ub;

	ub = get_exec_ub();
	if (unlikely(ub == NULL))
		ub = get_task_ub(current);

	return top_beancounter(ub);
}

extern struct page_beancounter **page_pblist(struct page *);

extern void ub_io_save_context(struct page *, size_t);
extern void ub_io_release_context(struct page *pg, size_t size);

static inline struct page_beancounter *iopb_to_pb(struct page_beancounter *pb)
{
	if (!((unsigned long)pb & PAGE_IO_MARK))
		return NULL;

	return (struct page_beancounter *)((unsigned long)pb & ~PAGE_IO_MARK);
}

static inline void ub_io_account_read(size_t bytes)
{
	ub_percpu_add(get_io_ub(), bytes_read, bytes);
}

static inline void ub_io_account_write(size_t bytes)
{
	ub_percpu_add(get_io_ub(), bytes_wrote, bytes);
}

static inline void ub_io_account_dirty(struct page *page, size_t bytes)
{
	ub_io_save_context(page, bytes);
}

static inline void ub_io_account_write_cancelled(size_t bytes)
{
	ub_percpu_add(get_io_ub(), bytes_cancelled, bytes);
}

void ub_init_io(struct kmem_cache *);
#else /* BC_IO_ACCOUNTING */
#define page_iopb(page)		(NULL)
#define page_pblist(page)	(&page_pbc(page))

static inline void ub_io_release_context(struct page *pg, size_t bytes)
{
}

static inline void ub_io_account_dirty(struct page *p, size_t bytes)
{
}

static inline void ub_io_account_read(size_t bytes)
{
}

static inline void ub_io_account_write(size_t bytes)
{
}

static inline void ub_io_account_write_cancelled(size_t bytes)
{
}

static inline void ub_init_io(struct kmem_cache *pb_cachep) { };
#endif

#ifdef CONFIG_BC_DEBUG_IO
extern void ub_io_release_debug(struct page *pg);
#else
#define ub_io_release_debug(pg)	do { } while (0)
#endif
#endif
