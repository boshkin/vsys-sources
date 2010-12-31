/*
 *  include/linux/vzstat.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __VZSTAT_H__
#define __VZSTAT_H__

struct swap_cache_info_struct {
	unsigned long add_total;
	unsigned long del_total;
	unsigned long find_success;
	unsigned long find_total;
	unsigned long noent_race;
	unsigned long exist_race;
	unsigned long remove_race;
};

struct kstat_lat_snap_struct {
	cycles_t maxlat, totlat;
	unsigned long count;
};
struct kstat_lat_pcpu_snap_struct {
	cycles_t maxlat, totlat;
	unsigned long count;
	seqcount_t lock;
} ____cacheline_aligned_in_smp;

struct kstat_lat_struct {
	struct kstat_lat_snap_struct cur, last;
	cycles_t avg[3];
};
struct kstat_lat_pcpu_struct {
	struct kstat_lat_pcpu_snap_struct *cur;
	cycles_t max_snap;
	struct kstat_lat_snap_struct last;
	cycles_t avg[3];
};

struct kstat_perf_snap_struct {
	cycles_t wall_tottime, cpu_tottime;
	cycles_t wall_maxdur, cpu_maxdur;
	unsigned long count;
};
struct kstat_perf_struct {
	struct kstat_perf_snap_struct cur, last;
};

struct kstat_zone_avg {
	unsigned long		free_pages_avg[3],
				nr_active_avg[3],
				nr_inactive_avg[3];
};

#define KSTAT_ALLOCSTAT_NR 5

struct kernel_stat_glob {
	unsigned long nr_unint_avg[3];

	unsigned long alloc_fails[KSTAT_ALLOCSTAT_NR];
	struct kstat_lat_struct alloc_lat[KSTAT_ALLOCSTAT_NR];
	struct kstat_lat_pcpu_struct sched_lat;
	struct kstat_lat_struct swap_in;

	struct kstat_perf_struct ttfp, cache_reap,
			refill_inact, shrink_icache, shrink_dcache;

	struct kstat_zone_avg zone_avg[3];	/* MAX_NR_ZONES */
} ____cacheline_aligned;

extern struct kernel_stat_glob kstat_glob ____cacheline_aligned;
extern spinlock_t kstat_glb_lock;

#ifdef CONFIG_VE
#define KSTAT_PERF_ENTER(name)				\
	unsigned long flags;				\
	cycles_t start, sleep_time;			\
							\
	start = get_cycles();				\
	sleep_time = VE_TASK_INFO(current)->sleep_time;	\

#define KSTAT_PERF_LEAVE(name)				\
	spin_lock_irqsave(&kstat_glb_lock, flags);	\
	kstat_glob.name.cur.count++;			\
	start = get_cycles() - start;			\
	if (kstat_glob.name.cur.wall_maxdur < start)	\
		kstat_glob.name.cur.wall_maxdur = start;\
	kstat_glob.name.cur.wall_tottime += start;	\
	start -= VE_TASK_INFO(current)->sleep_time -	\
					sleep_time;	\
	if (kstat_glob.name.cur.cpu_maxdur < start)	\
		kstat_glob.name.cur.cpu_maxdur = start;	\
	kstat_glob.name.cur.cpu_tottime += start;	\
	spin_unlock_irqrestore(&kstat_glb_lock, flags);	\

#else
#define KSTAT_PERF_ENTER(name)
#define KSTAT_PERF_LEAVE(name)
#endif

/*
 * Add another statistics reading.
 * Serialization is the caller's due.
 */
static inline void KSTAT_LAT_ADD(struct kstat_lat_struct *p,
		cycles_t dur)
{
	p->cur.count++;
	if (p->cur.maxlat < dur)
		p->cur.maxlat = dur;
	p->cur.totlat += dur;
}

static inline void KSTAT_LAT_PCPU_ADD(struct kstat_lat_pcpu_struct *p, int cpu,
		cycles_t dur)
{
	struct kstat_lat_pcpu_snap_struct *cur;

	cur = per_cpu_ptr(p->cur, cpu);
	write_seqcount_begin(&cur->lock);
	cur->count++;
	if (cur->maxlat < dur)
		cur->maxlat = dur;
	cur->totlat += dur;
	write_seqcount_end(&cur->lock);
}

/*
 * Move current statistics to last, clear last.
 * Serialization is the caller's due.
 */
static inline void KSTAT_LAT_UPDATE(struct kstat_lat_struct *p)
{
	cycles_t m;
	memcpy(&p->last, &p->cur, sizeof(p->last));
	p->cur.maxlat = 0;
	m = p->last.maxlat;
	CALC_LOAD(p->avg[0], EXP_1, m)
	CALC_LOAD(p->avg[1], EXP_5, m)
	CALC_LOAD(p->avg[2], EXP_15, m)
}

static inline void KSTAT_LAT_PCPU_UPDATE(struct kstat_lat_pcpu_struct *p)
{
	unsigned i, cpu;
	struct kstat_lat_pcpu_snap_struct snap, *cur;
	cycles_t m;

	memset(&p->last, 0, sizeof(p->last));
	for_each_online_cpu(cpu) {
		cur = per_cpu_ptr(p->cur, cpu);
		do {
			i = read_seqcount_begin(&cur->lock);
			memcpy(&snap, cur, sizeof(snap));
		} while (read_seqcount_retry(&cur->lock, i));
		/* 
		 * read above and this update of maxlat is not atomic,
		 * but this is OK, since it happens rarely and losing
		 * a couple of peaks is not essential. xemul
		 */
		cur->maxlat = 0;

		p->last.count += snap.count;
		p->last.totlat += snap.totlat;
		if (p->last.maxlat < snap.maxlat)
			p->last.maxlat = snap.maxlat;
	}

	m = (p->last.maxlat > p->max_snap ? p->last.maxlat : p->max_snap);
	CALC_LOAD(p->avg[0], EXP_1, m);
	CALC_LOAD(p->avg[1], EXP_5, m);
	CALC_LOAD(p->avg[2], EXP_15, m);
	/* reset max_snap to calculate it correctly next time */
	p->max_snap = 0;
}

#endif /* __VZSTAT_H__ */
