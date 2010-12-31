#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/cpuset.h>
#include <linux/module.h>

#include <bc/beancounter.h>
#include <bc/oom_kill.h>
#include <bc/hash.h>

#define UB_OOM_TIMEOUT	(5 * HZ)

int oom_generation;
int oom_kill_counter;
static DEFINE_SPINLOCK(oom_lock);
static DECLARE_WAIT_QUEUE_HEAD(oom_wq);

static inline int ub_oom_completed(struct task_struct *tsk)
{
	if (test_tsk_thread_flag(tsk, TIF_MEMDIE))
		/* we were oom killed - just die */
		return 1;
	if (tsk->task_bc.oom_generation != oom_generation)
		/* some task was succesfully killed */
		return 1;
	return 0;
}

static void ub_clear_oom(void)
{
	struct user_beancounter *ub;

	rcu_read_lock();
	for_each_beancounter(ub)
		ub->ub_oom_noproc = 0;
	rcu_read_unlock();
}

int ub_oom_lock(void)
{
	int timeout;
	DEFINE_WAIT(oom_w);
	struct task_struct *tsk;

	tsk = current;

	spin_lock(&oom_lock);
	if (!oom_kill_counter)
		goto out_do_oom;

	timeout = UB_OOM_TIMEOUT;
	while (1) {
		if (ub_oom_completed(tsk)) {
			spin_unlock(&oom_lock);
			return -EINVAL;
		}

		if (timeout == 0)
			break;

		__set_current_state(TASK_UNINTERRUPTIBLE);
		add_wait_queue(&oom_wq, &oom_w);
		spin_unlock(&oom_lock);

		timeout = schedule_timeout(timeout);

		spin_lock(&oom_lock);
		remove_wait_queue(&oom_wq, &oom_w);
	}

out_do_oom:
	ub_clear_oom();
	return 0;
}

static inline long ub_current_overdraft(struct user_beancounter *ub)
{
	return ub->ub_parms[UB_OOMGUARPAGES].held +
		((ub->ub_parms[UB_KMEMSIZE].held
		  + ub->ub_parms[UB_TCPSNDBUF].held
		  + ub->ub_parms[UB_TCPRCVBUF].held
		  + ub->ub_parms[UB_OTHERSOCKBUF].held
		  + ub->ub_parms[UB_DGRAMRCVBUF].held)
		 >> PAGE_SHIFT) - ub->ub_parms[UB_OOMGUARPAGES].barrier;
}

int ub_oom_task_skip(struct user_beancounter *ub, struct task_struct *tsk)
{
	struct user_beancounter *mm_ub;

	if (ub == NULL)
		return 0;

	task_lock(tsk);
	if (tsk->mm == NULL)
		mm_ub = NULL;
	else
		mm_ub = tsk->mm->mm_ub;

	while (mm_ub != NULL && mm_ub != ub)
		mm_ub = mm_ub->parent;
	task_unlock(tsk);

	return mm_ub != ub;
}

struct user_beancounter *ub_oom_select_worst(void)
{
	struct user_beancounter *ub, *walkp;
	long ub_maxover;

	ub_maxover = 0;
	ub = NULL;

	rcu_read_lock();
	for_each_beancounter (walkp) {
		long ub_overdraft;

		if (walkp->parent != NULL)
			continue;
		if (walkp->ub_oom_noproc)
			continue;

		ub_overdraft = ub_current_overdraft(walkp);
		if (ub_overdraft > ub_maxover && get_beancounter_rcu(walkp)) {
			put_beancounter(ub);
			ub = walkp;
			ub_maxover = ub_overdraft;
		}
	}

	if (ub)
		ub->ub_oom_noproc = 1;
	rcu_read_unlock();

	return ub;
}

void ub_oom_mm_killed(struct user_beancounter *ub)
{
	static struct ub_rate_info ri = { 5, 60*HZ };

	/* increment is serialized with oom_lock */
	ub->ub_parms[UB_OOMGUARPAGES].failcnt++;

	if (ub_ratelimit(&ri))
		show_mem();
}

void ub_oom_unlock(void)
{
	spin_unlock(&oom_lock);
}

void ub_oom_task_dead(struct task_struct *tsk)
{
	spin_lock(&oom_lock);
	oom_kill_counter = 0;
	oom_generation++;

	printk("OOM killed process %s (pid=%d, ve=%d) exited, "
			"free=%lu gen=%d.\n",
			tsk->comm, tsk->pid, VEID(tsk->ve_task_info.owner_env),
			nr_free_pages(), oom_generation);
	/* if there is time to sleep in ub_oom_lock -> sleep will continue */
	wake_up_all(&oom_wq);
	spin_unlock(&oom_lock);
}

void ub_out_of_memory(struct user_beancounter *scope)
{
	struct user_beancounter *ub;
	struct task_struct *p;

	spin_lock(&oom_lock);
	ub_clear_oom();
	ub = get_beancounter(scope);

	read_lock(&tasklist_lock);
retry:
	p = select_bad_process(ub, NULL);
	if (p == NULL || PTR_ERR(p) == -1UL)
		goto unlock;

	if (oom_kill_process(p, (gfp_t)-1, -1, NULL, "UB Out of memory"))
		goto retry;

	put_beancounter(ub);

unlock:
	read_unlock(&tasklist_lock);
	spin_unlock(&oom_lock);
}
EXPORT_SYMBOL(ub_out_of_memory);
