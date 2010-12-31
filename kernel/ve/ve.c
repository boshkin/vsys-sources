/*
 *  linux/kernel/ve/ve.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

/*
 * 've.c' helper file performing VE sub-system initialization
 */

#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/capability.h>
#include <linux/ve.h>
#include <linux/smp_lock.h>
#include <linux/init.h>

#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/sys.h>
#include <linux/kdev_t.h>
#include <linux/termios.h>
#include <linux/tty_driver.h>
#include <linux/netdevice.h>
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/ve_proto.h>
#include <linux/devpts_fs.h>
#include <linux/user_namespace.h>

#include <linux/vzcalluser.h>

unsigned long vz_rstamp = 0x37e0f59d;

#ifdef CONFIG_MODULES
struct module no_module = { .state = MODULE_STATE_GOING };
EXPORT_SYMBOL(no_module);
#endif

#if defined(CONFIG_VE_CALLS_MODULE) || defined(CONFIG_VE_CALLS)
void (*do_env_free_hook)(struct ve_struct *ve);
EXPORT_SYMBOL(do_env_free_hook);

void do_env_free(struct ve_struct *env)
{
	BUG_ON(atomic_read(&env->pcounter) > 0);
	BUG_ON(env->is_running);

	preempt_disable();
	do_env_free_hook(env);
	preempt_enable();
}
EXPORT_SYMBOL(do_env_free);
#endif

int (*do_ve_enter_hook)(struct ve_struct *ve, unsigned int flags);
EXPORT_SYMBOL(do_ve_enter_hook);

struct ve_struct ve0 = {
	.counter		= ATOMIC_INIT(1),
	.pcounter		= ATOMIC_INIT(1),
	.ve_list		= LIST_HEAD_INIT(ve0.ve_list),
	.vetask_lh		= LIST_HEAD_INIT(ve0.vetask_lh),
	.start_jiffies		= INITIAL_JIFFIES,
	.ve_ns			= &init_nsproxy,
	.ve_netns		= &init_net,
	.user_ns		= &init_user_ns,
	.is_running		= 1,
	.op_sem			= __RWSEM_INITIALIZER(ve0.op_sem),
#ifdef CONFIG_VE_IPTABLES
	.ipt_mask 		= VE_IP_ALL,
	._iptables_modules	= VE_IP_ALL,
#endif
	.features		= VE_FEATURE_SIT | VE_FEATURE_IPIP |
				VE_FEATURE_PPP,
	._randomize_va_space	=
#ifdef CONFIG_COMPAT_BRK
					1,
#else
					2,
#endif
};

EXPORT_SYMBOL(ve0);

LIST_HEAD(ve_list_head);
rwlock_t ve_list_lock = RW_LOCK_UNLOCKED;

LIST_HEAD(ve_cleanup_list);
DEFINE_SPINLOCK(ve_cleanup_lock);
struct task_struct *ve_cleanup_thread;

EXPORT_SYMBOL(ve_list_lock);
EXPORT_SYMBOL(ve_list_head);
EXPORT_SYMBOL(ve_cleanup_lock);
EXPORT_SYMBOL(ve_cleanup_list);
EXPORT_SYMBOL(ve_cleanup_thread);

static DEFINE_PER_CPU(struct ve_cpu_stats, ve0_cpustats);
static DEFINE_PER_CPU(struct kstat_lat_pcpu_snap_struct, ve0_lat_stats);

void init_ve0(void)
{
	struct ve_struct *ve;

	ve = get_ve0();
	ve->cpu_stats = &per_cpu__ve0_cpustats;
	ve->sched_lat_ve.cur = &per_cpu__ve0_lat_stats;
	list_add(&ve->ve_list, &ve_list_head);
}

void ve_cleanup_schedule(struct ve_struct *ve)
{
	BUG_ON(ve_cleanup_thread == NULL);

	spin_lock(&ve_cleanup_lock);
	list_add_tail(&ve->cleanup_list, &ve_cleanup_list);
	spin_unlock(&ve_cleanup_lock);

	wake_up_process(ve_cleanup_thread);
}

#ifdef CONFIG_BLK_CGROUP
extern int blkiocg_set_weight(struct cgroup *cgroup, u64 val);

static u64 ioprio_weight[VE_IOPRIO_MAX] = {200, 275, 350, 425, 500, 575, 650, 725};

int ve_set_ioprio(int veid, int ioprio)
{
	struct ve_struct *ve;
	int ret;

	if (ioprio < VE_IOPRIO_MIN || ioprio >= VE_IOPRIO_MAX)
		return -ERANGE;

	ret = -ESRCH;
	read_lock(&ve_list_lock);
	for_each_ve(ve) {
		if (ve->veid != veid)
			continue;
		ret = blkiocg_set_weight(ve->ve_cgroup, ioprio_weight[ioprio]);
		break;
	}
	read_unlock(&ve_list_lock);

	return ret;
}
#else
int ve_set_ioprio(int veid, int ioprio)
{
	return -EINVAL;
}
#endif /* CONFIG_BLK_CGROUP */
