/*
 *  kernel/bc/misc.c
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/signal.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/module.h>

#include <bc/beancounter.h>
#include <bc/kmem.h>
#include <bc/proc.h>

#define UB_FILE_MINQUANT	3
#define UB_FILE_MAXQUANT	10
#define UB_FILE_INIQUANT	4

static unsigned long ub_file_precharge(struct task_beancounter *task_bc,
		struct user_beancounter *ub, unsigned long *kmemsize);

static inline unsigned long ub_file_kmemsize(unsigned long nr)
{
	return CHARGE_SIZE(kmem_cache_objuse(filp_cachep)) * nr;
}

/*
 * Task staff
 */

static void init_task_sub(struct task_struct *parent,
		struct task_struct *tsk,
  		struct task_beancounter *old_bc)
{
	struct task_beancounter *new_bc;
	struct user_beancounter *sub;

	new_bc = &tsk->task_bc;
	sub = old_bc->fork_sub;
	new_bc->fork_sub = get_beancounter(sub);
	new_bc->task_fnode = NULL;
	new_bc->task_freserv = old_bc->task_freserv;
	old_bc->task_freserv = NULL;
	memset(&new_bc->task_data, 0, sizeof(new_bc->task_data));
	new_bc->pgfault_handle = 0;
	new_bc->pgfault_allot = 0;
}

void ub_init_task_bc(struct task_beancounter *tbc)
{
	tbc->file_precharged = 0;
	tbc->file_quant = UB_FILE_INIQUANT;
	tbc->file_count = 0;

	tbc->kmem_precharged = 0;
	tbc->dentry_alloc = 0;
}

int ub_task_charge(struct task_struct *parent, struct task_struct *task)
{
	struct task_beancounter *old_bc;
	struct task_beancounter *new_bc;
	struct user_beancounter *ub, *pub;
	unsigned long file_nr, kmemsize;
	unsigned long flags;

	old_bc = &parent->task_bc;
	ub = old_bc->fork_sub;
	new_bc = &task->task_bc;
	new_bc->task_ub = get_beancounter(ub);
	new_bc->exec_ub = get_beancounter(ub);

	pub = top_beancounter(ub);
	spin_lock_irqsave(&pub->ub_lock, flags);
	if (unlikely(__charge_beancounter_locked(pub, UB_NUMPROC,
					1, UB_HARD) < 0))
		goto out_numproc;

	ub_init_task_bc(new_bc);
	file_nr = ub_file_precharge(new_bc, pub, &kmemsize);
	spin_unlock_irqrestore(&pub->ub_lock, flags);

	charge_beancounter_notop(ub, UB_NUMPROC, 1);
	if (likely(file_nr)) {
		charge_beancounter_notop(ub, UB_NUMFILE, file_nr);
		charge_beancounter_notop(ub, UB_KMEMSIZE, kmemsize);
	}

	init_task_sub(parent, task, old_bc);
	return 0;

out_numproc:
	spin_unlock_irqrestore(&pub->ub_lock, flags);
	__put_beancounter_batch(ub, 2);
	return -ENOMEM;
}

extern atomic_t dbgpre;

void ub_task_uncharge(struct task_struct *task)
{
	struct task_beancounter *task_bc;
	struct user_beancounter *pub;
	unsigned long file_nr, file_kmemsize;
	unsigned long flags;

	task_bc = &task->task_bc;
	pub = top_beancounter(task_bc->task_ub);
	spin_lock_irqsave(&pub->ub_lock, flags);
	__uncharge_beancounter_locked(pub, UB_NUMPROC, 1);
	file_nr = task_bc->file_precharged;
	if (likely(file_nr))
		__uncharge_beancounter_locked(pub,
				UB_NUMFILE, file_nr);

	/* see comment in ub_file_charge */
	task_bc->file_precharged = 0;
	file_kmemsize = ub_file_kmemsize(file_nr);
	if (likely(file_kmemsize))
		__uncharge_beancounter_locked(pub,
				UB_KMEMSIZE, file_kmemsize);
	spin_unlock_irqrestore(&pub->ub_lock, flags);

	uncharge_beancounter_notop(task_bc->task_ub, UB_NUMPROC, 1);
	if (likely(file_nr)) {
		uncharge_beancounter_notop(task_bc->task_ub,
				UB_NUMFILE, file_nr);
		__put_beancounter_batch(task_bc->task_ub, file_nr);
	}
	if (likely(file_kmemsize))
		uncharge_beancounter_notop(task_bc->task_ub,
				UB_KMEMSIZE, file_kmemsize);
}

void ub_task_put(struct task_struct *task)
{
	struct task_beancounter *task_bc;
	struct user_beancounter *pub;
	unsigned long kmemsize, flags;

	task_bc = &task->task_bc;

	pub = top_beancounter(task_bc->task_ub);
	spin_lock_irqsave(&pub->ub_lock, flags);
	kmemsize = task_bc->kmem_precharged;
	task_bc->kmem_precharged = 0;
	if (likely(kmemsize))
		__uncharge_beancounter_locked(pub, UB_KMEMSIZE, kmemsize);
	spin_unlock_irqrestore(&pub->ub_lock, flags);
	if (likely(kmemsize))
		uncharge_beancounter_notop(task_bc->task_ub, UB_KMEMSIZE, kmemsize);

	put_beancounter(task_bc->exec_ub);
	put_beancounter(task_bc->task_ub);
	put_beancounter(task_bc->fork_sub);
	/* can't be freed elsewhere, failures possible in the middle of fork */
	if (task_bc->task_freserv != NULL)
		kfree(task_bc->task_freserv);

	task_bc->exec_ub = (struct user_beancounter *)0xdeadbcbc;
	task_bc->task_ub = (struct user_beancounter *)0xdead100c;
	BUG_ON(task_bc->kmem_precharged != 0);
}

/*
 * Files and file locks.
 */
/*
 * For NUMFILE, we do not take a lock and call charge function
 * for every file.  We try to charge in batches, keeping local reserve on
 * task.  For experimental purposes, batch size is adaptive and depends
 * on numfile barrier, number of processes, and the history of successes and
 * failures of batch charges.
 *
 * Per-task fields have the following meaning
 *   file_precharged    number of files charged to beancounter in advance,
 *   file_quant         logarithm of batch size
 *   file_count         counter of charge successes, to reduce batch size
 *                      fluctuations.
 */
static unsigned long ub_file_precharge(struct task_beancounter *task_bc,
		struct user_beancounter *ub, unsigned long *kmemsize)
{
	unsigned long n, kmem;

	n = 1UL << task_bc->file_quant;
	if (ub->ub_parms[UB_NUMPROC].held >
			(ub->ub_parms[UB_NUMFILE].barrier >>
						task_bc->file_quant))
		goto nopre;
	if (unlikely(__charge_beancounter_locked(ub, UB_NUMFILE, n, UB_HARD)))
		goto nopre;
	kmem = ub_file_kmemsize(n);
	if (unlikely(__charge_beancounter_locked(ub, UB_KMEMSIZE,
					kmem, UB_HARD)))
		goto nopre_kmem;

	task_bc->file_precharged += n;
	get_beancounter_batch(task_bc->task_ub, n);
	task_bc->file_count++;
	if (task_bc->file_quant < UB_FILE_MAXQUANT &&
	    task_bc->file_count >= task_bc->file_quant) {
		task_bc->file_quant++;
		task_bc->file_count = 0;
	}
	*kmemsize = kmem;
	return n;

nopre_kmem:
	__uncharge_beancounter_locked(ub, UB_NUMFILE, n);
nopre:
	if (task_bc->file_quant > UB_FILE_MINQUANT)
		task_bc->file_quant--;
	task_bc->file_count = 0;
	return 0;
}

int ub_file_charge(struct file *f)
{
	struct user_beancounter *ub, *pub;
	struct task_beancounter *task_bc;
	unsigned long file_nr, kmem;
	unsigned long flags;
	int err;

	task_bc = &current->task_bc;
	ub = get_exec_ub();
	if (unlikely(ub != task_bc->task_ub))
		goto just_charge;

	if (likely(task_bc->file_precharged > 0)) {
		/*
		 * files are put via RCU in 2.6.16 so during
		 * this decrement an IRQ can happen and called
		 * ub_files_uncharge() will mess file_precharged
		 *
		 * ub_task_uncharge() is called via RCU also so no
		 * protection is needed there
		 *
		 * Xemul
		 */

		local_irq_save(flags);
		task_bc->file_precharged--;
		local_irq_restore(flags);

		f->f_ub = ub;
		return 0;
	}

	pub = top_beancounter(ub);
	spin_lock_irqsave(&pub->ub_lock, flags);
	file_nr = ub_file_precharge(task_bc, pub, &kmem);
	if (unlikely(!file_nr))
		goto last_try;
	spin_unlock(&pub->ub_lock);
	task_bc->file_precharged--;
	local_irq_restore(flags);

	charge_beancounter_notop(ub, UB_NUMFILE, file_nr);
	charge_beancounter_notop(ub, UB_KMEMSIZE, kmem);
	f->f_ub = ub;
	return 0;

just_charge:
	pub = top_beancounter(ub);
	spin_lock_irqsave(&pub->ub_lock, flags);
last_try:
	kmem = ub_file_kmemsize(1);
	err = __charge_beancounter_locked(pub, UB_NUMFILE, 1, UB_HARD);
	if (likely(!err)) {
		err = __charge_beancounter_locked(pub, UB_KMEMSIZE,
				kmem, UB_HARD);
		if (unlikely(err))
			__uncharge_beancounter_locked(pub, UB_NUMFILE, 1);
	}
	spin_unlock_irqrestore(&pub->ub_lock, flags);
	if (likely(!err)) {
		charge_beancounter_notop(ub, UB_NUMFILE, 1);
		charge_beancounter_notop(ub, UB_KMEMSIZE, kmem);
		f->f_ub = get_beancounter(ub);
	}
	return err;
}

static inline int task_precharge_farnr(struct task_beancounter *task_bc)
{
       return (task_bc->file_precharged < (1UL << task_bc->file_quant));
}

void ub_file_uncharge(struct file *f)
{
	struct user_beancounter *ub, *pub;
	struct task_beancounter *task_bc;
	int nr;

	ub = f->f_ub;
	task_bc = &current->task_bc;
	if (likely(ub == task_bc->task_ub)) {
		task_bc->file_precharged++;
		pub = top_beancounter(ub);
		if (task_precharge_farnr(task_bc) &&
				ub_barrier_farsz(pub, UB_KMEMSIZE))
			return;
		nr = task_bc->file_precharged
			- (1UL << (task_bc->file_quant - 1));
		if (nr > 0) {
			task_bc->file_precharged -= nr;
			__put_beancounter_batch(ub, nr);
			uncharge_beancounter(ub, UB_NUMFILE, nr);
			uncharge_beancounter(ub, UB_KMEMSIZE,
					ub_file_kmemsize(nr));
		}
	} else {
		uncharge_beancounter(ub, UB_NUMFILE, 1);
		uncharge_beancounter(ub, UB_KMEMSIZE, ub_file_kmemsize(1));
		put_beancounter(ub);
	}
}

int ub_flock_charge(struct file_lock *fl, int hard)
{
	struct user_beancounter *ub;
	int err;

	/* No need to get_beancounter here since it's already got in slab */
	ub = slab_ub(fl);
	if (ub == NULL)
		return 0;

	err = charge_beancounter(ub, UB_NUMFLOCK, 1, hard ? UB_HARD : UB_SOFT);
	if (!err)
		fl->fl_charged = 1;
	return err;
}

void ub_flock_uncharge(struct file_lock *fl)
{
	struct user_beancounter *ub;

	/* Ub will be put in slab */
	ub = slab_ub(fl);
	if (ub == NULL || !fl->fl_charged)
		return;

	uncharge_beancounter(ub, UB_NUMFLOCK, 1);
	fl->fl_charged = 0;
}

/*
 * Signal handling
 */

static int do_ub_siginfo_charge(struct user_beancounter *ub,
		unsigned long size)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	if (__charge_beancounter_locked(ub, UB_KMEMSIZE, size, UB_HARD))
		goto out_kmem;

	if (__charge_beancounter_locked(ub, UB_NUMSIGINFO, 1, UB_HARD))
		goto out_num;

	spin_unlock_irqrestore(&ub->ub_lock, flags);
	return 0;

out_num:
	__uncharge_beancounter_locked(ub, UB_KMEMSIZE, size);
out_kmem:
	spin_unlock_irqrestore(&ub->ub_lock, flags);
	return -ENOMEM;
}

static void do_ub_siginfo_uncharge(struct user_beancounter *ub,
		unsigned long size)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	__uncharge_beancounter_locked(ub, UB_KMEMSIZE, size);
	__uncharge_beancounter_locked(ub, UB_NUMSIGINFO, 1);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

int ub_siginfo_charge(struct sigqueue *sq, struct user_beancounter *ub)
{
	unsigned long size;
	struct user_beancounter *p, *q;

	size = CHARGE_SIZE(kmem_obj_objuse(sq));
	for (p = ub; p != NULL; p = p->parent) {
		if (do_ub_siginfo_charge(p, size))
			goto unroll;
	}

	sq->sig_ub = get_beancounter(ub);
	return 0;

unroll:
	for (q = ub; q != p; q = q->parent)
		do_ub_siginfo_uncharge(q, size);
	return -ENOMEM;
}
EXPORT_SYMBOL(ub_siginfo_charge);

void ub_siginfo_uncharge(struct sigqueue *sq)
{
	unsigned long size;
	struct user_beancounter *ub, *p;

	p = ub = sq->sig_ub;
	sq->sig_ub = NULL;
	size = CHARGE_SIZE(kmem_obj_objuse(sq));
	for (; ub != NULL; ub = ub->parent)
		do_ub_siginfo_uncharge(ub, size);
	put_beancounter(p);
}

/*
 * PTYs
 */

int ub_pty_charge(struct tty_struct *tty)
{
	struct user_beancounter *ub;
	int retval;

	ub = slab_ub(tty);
	retval = 0;
	if (ub && tty->driver->subtype == PTY_TYPE_MASTER &&
			!test_bit(TTY_CHARGED, &tty->flags)) {
		retval = charge_beancounter(ub, UB_NUMPTY, 1, UB_HARD);
		if (!retval)
			set_bit(TTY_CHARGED, &tty->flags);
	}
	return retval;
}

void ub_pty_uncharge(struct tty_struct *tty)
{
	struct user_beancounter *ub;

	ub = slab_ub(tty);
	if (ub && tty->driver->subtype == PTY_TYPE_MASTER &&
			test_bit(TTY_CHARGED, &tty->flags)) {
		uncharge_beancounter(ub, UB_NUMPTY, 1);
		clear_bit(TTY_CHARGED, &tty->flags);
	}
}
