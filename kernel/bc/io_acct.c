/*
 *  kernel/bc/io_acct.c
 *
 *  Copyright (C) 2006  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 *  Pavel Emelianov <xemul@openvz.org>
 *
 */

#include <linux/mm.h>
#include <linux/mempool.h>
#include <linux/proc_fs.h>
#include <linux/virtinfo.h>
#include <linux/pagemap.h>
#include <linux/sched.h>

#include <bc/beancounter.h>
#include <bc/io_acct.h>
#include <bc/rss_pages.h>
#include <bc/vmpages.h>
#include <bc/proc.h>

static struct mempool_s *pb_pool;

#define PB_MIN_IO	(1024)

static inline struct page_beancounter *io_pb_alloc(void)
{
	return mempool_alloc(pb_pool, GFP_ATOMIC);
}

static inline void io_pb_free(struct page_beancounter *pb)
{
	mempool_free(pb, pb_pool);
}

struct page_beancounter **page_pblist(struct page *page)
{
	struct page_beancounter **pb, *iopb;

	pb = &page_pbc(page);
	iopb = iopb_to_pb(*pb);

	return iopb == NULL ? pb : &iopb->page_pb_list;
}

/*
 * We save the context page was set dirty to use it later
 * when the real write starts. If the page is mapped then
 * IO pb is stores like this:
 *
 * Before saving:
 *
 *  +- page -------+
 *  | ...          |
 *  | page_pb      +---+
 *  +--------------+   |   +-----+    +-----+          +-----+
 *                     +-> | pb1 | -> | pb2 | - ... -> | pbN | -+
 *                         +-----+    +-----+          +-----+  |
 *                            ^                                 |
 *                            +---------------------------------+
 *
 * After saving:
 *
 *  +- page -------+      +- io pb ------+
 *  | ...          |      | ...          |
 *  | page_pb      +----> | page_pb_list +-+
 *  +--------------+      +--------------+ |
 *                                         |
 *                     +-------------------+
 *                     |
 *                     |   +-----+    +-----+          +-----+
 *                     +-> | pb1 | -> | pb2 | - ... -> | pbN | -+
 *                         +-----+    +-----+          +-----+  |
 *                            ^                                 |
 *                            +---------------------------------+
 *
 * And the page_pblist(...) function returns pointer to the place that
 * points to this pbX ring.
 */

#ifdef CONFIG_BC_DEBUG_IO
static LIST_HEAD(pb_io_list);
static unsigned long anon_pages, not_released;

static inline void io_debug_save(struct page_beancounter *pb,
		struct page_beancounter *mpb)
{
	pb->io_debug = (mpb == NULL);
	list_add(&pb->io_list, &pb_io_list);
}

static inline void io_debug_release(struct page_beancounter *pb)
{
	list_del(&pb->io_list);
}

void ub_io_release_debug(struct page *page)
{
	struct page_beancounter *pb;
	static int once = 0;

	pb = page_pbc(page);
	if (likely(iopb_to_pb(pb) == NULL))
		return;

	if (!once) {
		printk("BUG: Page has an IO bc but is not expectd to\n");
		dump_stack();
		once = 1;
	}

	spin_lock(&pb_lock);
	not_released++;
	pb = iopb_to_pb(pb);
	page_pbc(page) = NULL;
	io_debug_release(pb);
	pb->ub->io_pb_held--;
	spin_unlock(&pb_lock);

	put_beancounter(pb->ub);
	io_pb_free(pb);
}

static inline int io_debug_precheck_save(struct page *page)
{
	if (unlikely(PageAnon(page))) {
		anon_pages++;
		return 1;
	}

	return 0;
}

static inline int io_debug_precheck_release(struct page *page)
{
	return 0;
}
#else
#define io_debug_save(pb, mpb)	do { } while (0)
#define io_debug_release(pb)	do { } while (0)
#define io_debug_precheck_save(page)		(0)
#define io_debug_precheck_release(p)		(0)
#endif

static inline void set_page_io(struct page *page, struct page_beancounter *pb,
		struct page_beancounter *mapped_pb)
{
	unsigned long val;

	val = (unsigned long)pb | PAGE_IO_MARK;
	pb->page = page;

	page_pbc(page) = (struct page_beancounter *)val;
	io_debug_save(pb, mapped_pb);
	pb->ub->io_pb_held++;
}

static inline void put_page_io(struct page *page, struct page_beancounter *pb)
{
	pb->ub->io_pb_held--;
	io_debug_release(pb);
	page_pbc(page) = pb->page_pb_list;
}

void ub_io_save_context(struct page *page, size_t bytes_dirtied)
{
	struct user_beancounter *ub;
	struct page_beancounter *pb, *mapped_pb, *io_pb;

	if (unlikely(in_interrupt())) {
		WARN_ON_ONCE(1);
		return;
	}

	/*
	 * FIXME - this can happen from atomic context and
	 * it's probably not that good to loose some requests
	 */

	pb = io_pb_alloc();
	io_pb = NULL;

	spin_lock(&pb_lock);
	if (io_debug_precheck_save(page))
		goto out_unlock;

	mapped_pb = page_pbc(page);
	io_pb = iopb_to_pb(mapped_pb);
	if (io_pb != NULL) {
		/*
		 * this page has an IO - release it and force a new one
		 * We could also race with page cleaning - see below
		 */
		mapped_pb = io_pb->page_pb_list;
		put_page_io(page, io_pb);
	}

	/*
	 * If the page is mapped we must save the context
	 * it maps to. If the page isn't mapped we use current
	 * context as this is a regular write.
	 */

	if (mapped_pb != NULL)
		ub = top_beancounter(mapped_pb->ub);
	else
		ub = get_io_ub();

	if (!PageDirty(page)) {
		/*
		 * race with clear_page_dirty(_for_io) - account
		 * writes for ub_io_release_context()
		 */
		if (io_pb != NULL)
			io_pb->ub->bytes_wrote += PAGE_CACHE_SIZE;
		if (pb != NULL)
			io_pb_free(pb);
		goto out_unlock;
	}

	if (pb == NULL) {
		ub->bytes_dirty_missed += bytes_dirtied;
		goto out_unlock;
	}

	/*
	 * the page may become clean here, but the context will be seen
	 * in ub_io_release_context()
	 */

	pb->ub = get_beancounter(ub);
	pb->page_pb_list = mapped_pb;
	ub->bytes_dirtied += bytes_dirtied;

	set_page_io(page, pb, mapped_pb);

out_unlock:
	spin_unlock(&pb_lock);

	if (io_pb != NULL) {
		put_beancounter(io_pb->ub);
		io_pb_free(io_pb);
	}
}

void ub_io_release_context(struct page *page, size_t wrote)
{
	struct page_beancounter *pb;

	if (io_debug_precheck_release(page))
		return;

	if (unlikely(in_interrupt())) {
		WARN_ON_ONCE(1);
		return;
	}

	spin_lock(&pb_lock);
	pb = iopb_to_pb(page_pbc(page));
	if (unlikely(pb == NULL))
		/*
		 * this may happen if we failed to allocate
		 * context in ub_io_save_context or raced with it
		 */
		goto out_unlock;

	if (wrote)
		pb->ub->bytes_wrote += wrote;

	put_page_io(page, pb);
out_unlock:
	spin_unlock(&pb_lock);

	if (pb != NULL) {
		put_beancounter(pb->ub);
		io_pb_free(pb);
	}
}

void __init ub_init_io(struct kmem_cache *pb_cachep)
{
	pb_pool = mempool_create_slab_pool(PB_MIN_IO, pb_cachep);
	if (pb_pool == NULL)
		panic("Can't create pb_pool");
}

#ifdef CONFIG_PROC_FS
#define in_flight(var)	(var > var##_done ? var - var##_done : 0)

static int bc_ioacct_show(struct seq_file *f, void *v)
{
	int i;
	unsigned long long read, write, cancel;
	unsigned long sync, sync_done;
	unsigned long fsync, fsync_done;
	unsigned long fdsync, fdsync_done;
	unsigned long frsync, frsync_done;
	unsigned long reads, writes;
	unsigned long long rchar, wchar;
	struct user_beancounter *ub;

	ub = seq_beancounter(f);

	read = write = cancel = 0;
	sync = sync_done = fsync = fsync_done =
		fdsync = fdsync_done = frsync = frsync_done = 0;
	reads = writes = 0;
	rchar = wchar = 0;
	for_each_online_cpu(i) {
		struct ub_percpu_struct *ub_percpu;
		ub_percpu = per_cpu_ptr(ub->ub_percpu, i);

		read += ub_percpu->bytes_read;
		write += ub_percpu->bytes_wrote;
		cancel += ub_percpu->bytes_cancelled;

		sync += ub_percpu->sync;
		fsync += ub_percpu->fsync;
		fdsync += ub_percpu->fdsync;
		frsync += ub_percpu->frsync;
		sync_done += ub_percpu->sync_done;
		fsync_done += ub_percpu->fsync_done;
		fdsync_done += ub_percpu->fdsync_done;
		frsync_done += ub_percpu->frsync_done;

		reads += ub_percpu->read;
		writes += ub_percpu->write;
		rchar += ub_percpu->rchar;
		wchar += ub_percpu->wchar;
	}

	seq_printf(f, bc_proc_llu_fmt, "read", read);
	seq_printf(f, bc_proc_llu_fmt, "write", ub->bytes_wrote + write);
	seq_printf(f, bc_proc_llu_fmt, "dirty", ub->bytes_dirtied);
	seq_printf(f, bc_proc_llu_fmt, "cancel", cancel);
	seq_printf(f, bc_proc_llu_fmt, "missed", ub->bytes_dirty_missed);

	seq_printf(f, bc_proc_lu_lfmt, "syncs_total", sync);
	seq_printf(f, bc_proc_lu_lfmt, "fsyncs_total", fsync);
	seq_printf(f, bc_proc_lu_lfmt, "fdatasyncs_total", fdsync);
	seq_printf(f, bc_proc_lu_lfmt, "range_syncs_total", frsync);

	seq_printf(f, bc_proc_lu_lfmt, "syncs_active", in_flight(sync));
	seq_printf(f, bc_proc_lu_lfmt, "fsyncs_active", in_flight(fsync));
	seq_printf(f, bc_proc_lu_lfmt, "fdatasyncs_active", in_flight(fsync));
	seq_printf(f, bc_proc_lu_lfmt, "range_syncs_active", in_flight(frsync));

	seq_printf(f, bc_proc_lu_lfmt, "vfs_reads", reads);
	seq_printf(f, bc_proc_llu_fmt, "vfs_read_chars", rchar);
	seq_printf(f, bc_proc_lu_lfmt, "vfs_writes", writes);
	seq_printf(f, bc_proc_llu_fmt, "vfs_write_chars", wchar);

	seq_printf(f, bc_proc_lu_lfmt, "io_pbs", ub->io_pb_held);
	return 0;
}

static struct bc_proc_entry bc_ioacct_entry = {
	.name = "ioacct",
	.u.show = bc_ioacct_show,
};

#ifdef CONFIG_BC_DEBUG_IO
#define PTR_SIZE (int)(sizeof(void *) * 2)
#define INT_SIZE (int)(sizeof(int) * 2)

static int bc_io_show(struct seq_file *f, void *v)
{
	struct list_head *lh;
	struct page_beancounter *pb;
	struct page *pg;

	lh = (struct list_head *)v;
	if (lh == &pb_io_list) {
		seq_printf(f, "Races: anon %lu missed %lu\n",
				anon_pages, not_released);

		seq_printf(f, "%-*s %-1s %-*s %-4s %*s %*s "
				"%-*s %-*s %-1s %-*s %-*s\n",
				PTR_SIZE, "pb", "",
				PTR_SIZE, "page", "flg",
				INT_SIZE, "cnt", INT_SIZE, "mcnt",
				PTR_SIZE, "pb_list",
				PTR_SIZE, "page_pb", "",
				PTR_SIZE, "mapping",
				INT_SIZE, "ub");
		return 0;
	}

	pb = list_entry(lh, struct page_beancounter, io_list);
	pg = pb->page;
	seq_printf(f, "%p %c %p %c%c%c%c %*d %*d %p %p %c %p %d\n",
			pb, pb->io_debug ? 'e' : 'm', pg,
			PageDirty(pg) ? 'D' : 'd',
			PageAnon(pg) ? 'A' : 'a',
			PageWriteback(pg) ? 'W' : 'w',
			PageLocked(pg) ? 'L' : 'l',
			INT_SIZE, page_count(pg),
			INT_SIZE, page_mapcount(pg),
			pb->page_pb_list, page_pbc(pg),
			iopb_to_pb(page_pbc(pg)) == pb ? ' ' : '!',
			pg->mapping, pb->ub->ub_uid);
	return 0;
}

static void *bc_io_start(struct seq_file *f, loff_t *ppos)
{
	spin_lock(&pb_lock);
	return seq_list_start_head(&pb_io_list, *ppos);
}

static void *bc_io_next(struct seq_file *f, void *v, loff_t *ppos)
{
	return seq_list_next(v, &pb_io_list, ppos);
}

static void bc_io_stop(struct seq_file *f, void *v)
{
	spin_unlock(&pb_lock);
}

static struct seq_operations bc_io_seq_ops = {
	.start = bc_io_start,
	.next  = bc_io_next,
	.stop  = bc_io_stop,
	.show  = bc_io_show,
};

static int bc_io_open(struct inode *inode, struct file *filp)
{
	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return -EACCES;

	return seq_open(filp, &bc_io_seq_ops);
}
static struct file_operations bc_io_debug_ops = {
	.open		= bc_io_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static struct bc_proc_entry bc_ioacct_debug_entry = {
	.name		= "ioacct_debug",
	.u.fops		= &bc_io_debug_ops,
};
#endif

static int bc_ioacct_notify(struct vnotifier_block *self,
		unsigned long event, void *arg, int old_ret)
{
	struct user_beancounter *ub;
	unsigned long *vm_events;
	unsigned long long bin, bout;
	int i;

	if (event != VIRTINFO_VMSTAT)
		return old_ret;

	ub = top_beancounter(get_exec_ub());
	if (ub == get_ub0())
		return old_ret;

	/* Think over: do we need to account here bytes_dirty_missed? */
	bout = ub->bytes_wrote;
	bin = 0;
	for_each_online_cpu(i) {
		bout += per_cpu_ptr(ub->ub_percpu, i)->bytes_wrote;
		bin += per_cpu_ptr(ub->ub_percpu, i)->bytes_read;
	}

	/* convert to Kbytes */
	bout >>= 10;
	bin >>= 10;

	vm_events = ((unsigned long *)arg) + NR_VM_ZONE_STAT_ITEMS;
	vm_events[PGPGOUT] = (unsigned long)bout;
	vm_events[PGPGIN] = (unsigned long)bin;
	return NOTIFY_OK;
}

static struct vnotifier_block bc_ioacct_nb = {
	.notifier_call = bc_ioacct_notify,
};

static int __init bc_ioacct_init(void)
{
#ifdef CONFIG_BC_DEBUG_IO
	bc_register_proc_root_entry(&bc_ioacct_debug_entry);
#endif
	bc_register_proc_entry(&bc_ioacct_entry);

	virtinfo_notifier_register(VITYPE_GENERAL, &bc_ioacct_nb);
	return 0;
}

late_initcall(bc_ioacct_init);
#endif
