/*
 * Fair Scheduler
 *
 * Copyright (C) 2000-2008  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef __LINUX_FAIRSCHED_H__
#define __LINUX_FAIRSCHED_H__

#define FAIRSCHED_SET_RATE      0
#define FAIRSCHED_DROP_RATE     1
#define FAIRSCHED_GET_RATE      2

#ifdef __KERNEL__

/* refcnt change protected with tasklist write lock */
struct fairsched_node {
	struct task_group *tg;
	int refcnt;
	unsigned id;
	struct list_head nodelist;

	unsigned weight;
	unsigned char rate_limited;
	unsigned rate;
#ifdef CONFIG_VE
	struct ve_struct *owner_env;
#endif
};

#ifdef CONFIG_VZ_FAIRSCHED

#define FAIRSCHED_INIT_NODE_ID		INT_MAX

extern struct fairsched_node fairsched_init_node;

void fairsched_init_early(void);
void fairsched_init_late(void);

static inline int task_fairsched_node_id(struct task_struct *p)
{
	return p->fsched_node->id;
}

/* must called with tasklist write locked */
static inline void get_task_fairsched_node(struct task_struct *p)
{
	p->fsched_node->refcnt++;
}
static inline void put_task_fairsched_node(struct task_struct *p)
{
	p->fsched_node->refcnt--;
}

#define	INIT_VZ_FAIRSCHED		.fsched_node = &fairsched_init_node,

#define FSCHWEIGHT_MAX                  ((1 << 16) - 1)
#define FSCHRATE_SHIFT                  10
#define FSCH_TIMESLICE                  16

asmlinkage int sys_fairsched_mknod(unsigned int parent, unsigned int weight,
		unsigned int newid);
asmlinkage int sys_fairsched_rmnod(unsigned int id);
asmlinkage int sys_fairsched_mvpr(pid_t pid, unsigned int nodeid);
asmlinkage int sys_fairsched_vcpus(unsigned int id, unsigned int vcpus);
asmlinkage int sys_fairsched_chwt(unsigned int id, unsigned int weight);
asmlinkage int sys_fairsched_rate(unsigned int id, int op, unsigned rate);

int fairsched_new_node(int id, unsigned int vcpus);
void fairsched_drop_node(int id);

#else /* CONFIG_VZ_FAIRSCHED */

static inline void fairsched_init_early(void) { }
static inline void fairsched_init_late(void) { }
static inline int task_fairsched_node_id(struct task_struct *p) { return 0; }
static inline void get_task_fairsched_node(struct task_struct *p) { }
static inline void put_task_fairsched_node(struct task_struct *p) { }

static inline int fairsched_new_node(int id, unsigned int vcpus) { return 0; }
static inline void fairsched_drop_node(int id) { }

#define	INIT_VZ_FAIRSCHED

#endif /* CONFIG_VZ_FAIRSCHED */
#endif /* __KERNEL__ */

#endif /* __LINUX_FAIRSCHED_H__ */
