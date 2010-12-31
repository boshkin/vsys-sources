/*
 *  include/bc/dcache.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __BC_DCACHE_H_
#define __BC_DCACHE_H_

#include <bc/decl.h>

/*
 * UB_DCACHESIZE accounting
 */

struct dentry_beancounter
{
	/*
	 *  d_inuse =
	 *         <number of external refs> +
	 *         <number of 'used' childs>
	 *
	 * d_inuse == -1 means that dentry is unused
	 * state change -1 => 0 causes charge
	 * state change 0 => -1 causes uncharge
	 */
	atomic_t d_inuse;
	/* charged size, including name length if name is not inline */
	unsigned long d_ubsize;
	struct user_beancounter *d_ub;
};

#ifdef CONFIG_BEANCOUNTERS
#define ub_dget_testone(d)  (atomic_inc_and_test(&(d)->dentry_bc.d_inuse))
#define ub_dput_testzero(d) (atomic_add_negative(-1, &(d)->dentry_bc.d_inuse))
#define INUSE_INIT		0

extern int ub_dentry_on;
#else
#define ub_dget_testone(d)	(0)
#define ub_dput_testzero(d)	(0)
#endif
#endif
