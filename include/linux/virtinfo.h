/*
 *  include/linux/virtinfo.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __LINUX_VIRTINFO_H
#define __LINUX_VIRTINFO_H

#include <linux/kernel.h>
#include <linux/page-flags.h>
#include <linux/notifier.h>

struct vnotifier_block
{
	int (*notifier_call)(struct vnotifier_block *self,
			unsigned long, void *, int);
	struct vnotifier_block *next;
	int priority;
};

extern struct semaphore virtinfo_sem;
void __virtinfo_notifier_register(int type, struct vnotifier_block *nb);
void virtinfo_notifier_register(int type, struct vnotifier_block *nb);
void virtinfo_notifier_unregister(int type, struct vnotifier_block *nb);
int virtinfo_notifier_call(int type, unsigned long n, void *data);

struct page_info {
	unsigned long nr_file_dirty;
	unsigned long nr_writeback;
	unsigned long nr_anon_pages;
	unsigned long nr_file_mapped;
	unsigned long nr_slab_rec;
	unsigned long nr_slab_unrec;
	unsigned long nr_pagetable;
	unsigned long nr_unstable_nfs;
	unsigned long nr_bounce;
	unsigned long nr_writeback_temp;
};

struct meminfo {
	struct sysinfo si;
	struct page_info pi;
	unsigned long active, inactive;
	unsigned long cache, swapcache;
	unsigned long committed_space;
	unsigned long allowed;
	unsigned long vmalloc_total, vmalloc_used, vmalloc_largest;
};

#define VIRTINFO_MEMINFO	0
#define VIRTINFO_ENOUGHMEM	1
#define VIRTINFO_DOFORK         2
#define VIRTINFO_DOEXIT         3
#define VIRTINFO_DOEXECVE       4
#define VIRTINFO_DOFORKRET      5
#define VIRTINFO_DOFORKPOST     6
#define VIRTINFO_EXIT           7
#define VIRTINFO_EXITMMAP       8
#define VIRTINFO_EXECMMAP       9
#define VIRTINFO_OUTOFMEM       10
#define VIRTINFO_PAGEIN         11
#define VIRTINFO_SYSINFO        12
#define VIRTINFO_NEWUBC         13
#define VIRTINFO_VMSTAT		14

enum virt_info_types {
	VITYPE_GENERAL,
	VITYPE_FAUDIT,
	VITYPE_QUOTA,
	VITYPE_SCP,

	VIRT_TYPES
};

#ifdef CONFIG_VZ_GENCALLS

static inline int virtinfo_gencall(unsigned long n, void *data)
{
	int r;

	r = virtinfo_notifier_call(VITYPE_GENERAL, n, data);
	if (r & NOTIFY_FAIL)
		return -ENOBUFS;
	if (r & NOTIFY_OK)
		return -ERESTARTNOINTR;
	return 0;
}

#else

#define virtinfo_gencall(n, data)	0

#endif

#endif /* __LINUX_VIRTINFO_H */
