/*
 *  include/bc/hash.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef _LINUX_UBHASH_H
#define _LINUX_UBHASH_H

#ifdef __KERNEL__

#define UB_HASH_SIZE 256

extern struct hlist_head ub_hash[];
extern spinlock_t ub_hash_lock;
extern struct list_head ub_list_head;

#ifdef CONFIG_BEANCOUNTERS

/*
 * Iterate over beancounters
 * @__ubp - beancounter ptr
 * Can use break :)
 */
#define for_each_beancounter(__ubp)				\
	list_for_each_entry_rcu(__ubp, &ub_list_head, ub_list)	\

#define bc_hash_entry(ptr) hlist_entry(ptr, struct user_beancounter, ub_hash)

#endif /* CONFIG_BEANCOUNTERS */
#endif /* __KERNEL__ */
#endif /* _LINUX_UBHASH_H */
