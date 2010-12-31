/*
 *  include/bc/misc.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __BC_MISC_H_
#define __BC_MISC_H_

#include <bc/decl.h>

struct tty_struct;
struct file;
struct file_lock;
struct sigqueue;

UB_DECLARE_FUNC(int, ub_file_charge(struct file *f))
UB_DECLARE_VOID_FUNC(ub_file_uncharge(struct file *f))
UB_DECLARE_FUNC(int, ub_flock_charge(struct file_lock *fl, int hard))
UB_DECLARE_VOID_FUNC(ub_flock_uncharge(struct file_lock *fl))
UB_DECLARE_FUNC(int, ub_siginfo_charge(struct sigqueue *q,
			struct user_beancounter *ub))
UB_DECLARE_VOID_FUNC(ub_siginfo_uncharge(struct sigqueue *q))
UB_DECLARE_FUNC(int, ub_task_charge(struct task_struct *parent,
			struct task_struct *task))
UB_DECLARE_VOID_FUNC(ub_task_uncharge(struct task_struct *task))
UB_DECLARE_VOID_FUNC(ub_task_put(struct task_struct *task))
UB_DECLARE_FUNC(int, ub_pty_charge(struct tty_struct *tty))
UB_DECLARE_VOID_FUNC(ub_pty_uncharge(struct tty_struct *tty))

#ifdef CONFIG_BEANCOUNTERS
#define set_flock_charged(fl)	do { (fl)->fl_charged = 1; } while (0)
#define unset_flock_charged(fl)	do {		\
		WARN_ON((fl)->fl_charged == 0);	\
		(fl)->fl_charged = 0;		\
	} while (0)
#define set_mm_ub(mm, tsk)	do {				\
		(mm)->mm_ub = get_beancounter(tsk != current ?	\
			tsk->task_bc.task_ub : get_exec_ub());	\
	} while (0)
#define put_mm_ub(mm)		do {				\
		put_beancounter((mm)->mm_ub);			\
		(mm)->mm_ub = NULL;				\
	} while (0)
#else
#define set_flock_charged(fl)	do { } while (0)
#define unset_flock_charged(fl)	do { } while (0)
#define set_mm_ub(mm, tsk)	do { } while (0)
#define put_mm_ub(mm)		do { } while (0)
#endif
#endif
