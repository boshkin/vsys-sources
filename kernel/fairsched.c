/*
 * Fair Scheduler
 *
 * Copyright (C) 2000-2008  SWsoft
 * All rights reserved.
 *
 * Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/sched.h>
#include <linux/fairsched.h>
#include <linux/err.h>
#include <linux/module.h>

struct fairsched_node fairsched_init_node = {
	.id		= FAIRSCHED_INIT_NODE_ID,
	.tg		= &init_task_group,
#ifdef CONFIG_VE
	.owner_env	= get_ve0(),
#endif
	.weight		= 1,
};

static DEFINE_MUTEX(fairsched_mutex);

/* list protected with fairsched_mutex */
static LIST_HEAD(fairsched_node_head);
static int fairsched_nr_nodes;

void __init fairsched_init_early(void)
{
       list_add(&fairsched_init_node.nodelist, &fairsched_node_head);
       fairsched_nr_nodes++;
}

#define FSCHWEIGHT_BASE		512000

/******************************************************************************
 * cfs group shares = FSCHWEIGHT_BASE / fairsched weight
 *
 * vzctl cpuunits default 1000
 * cfs shares default value is 1024 (see init_task_group_load in sched.c)
 * cpuunits = 1000 --> weight = 500000 / cpuunits = 500 --> shares = 1024
 *                              ^--- from vzctl
 * weight in 1..65535  -->  shares in 7..512000
 * shares should be >1 (see comment in sched_group_set_shares function)
 *****************************************************************************/

static struct fairsched_node *fairsched_find(unsigned int id)
{
	struct fairsched_node *p;
	list_for_each_entry(p, &fairsched_node_head, nodelist) {
		if (p->id == id)
			return p;
	}
	return NULL;
}

/******************************************************************************
 * System calls
 *
 * All do_xxx functions are called under fairsched mutex and after
 * capability check.
 *
 * The binary interfaces follow some other Fair Scheduler implementations
 * (although some system call arguments are not needed for our implementation).
 *****************************************************************************/

static int do_fairsched_mknod(unsigned int parent, unsigned int weight,
		unsigned int newid)
{
	struct fairsched_node *node;
	int retval;

	retval = -EINVAL;
	if (weight < 1 || weight > FSCHWEIGHT_MAX)
		goto out;
	if (newid < 0 || newid > INT_MAX)
		goto out;

	retval = -EBUSY;
	if (fairsched_find(newid) != NULL)
		goto out;

	retval = -ENOMEM;
	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (node == NULL)
		goto out;

	node->tg = sched_create_group(&init_task_group);
	if (IS_ERR(node->tg))
		goto out_free;

	node->id = newid;
	node->weight = weight;
	sched_group_set_shares(node->tg, FSCHWEIGHT_BASE / weight);
#ifdef CONFIG_VE
	node->owner_env = get_exec_env();
#endif
	list_add(&node->nodelist, &fairsched_node_head);
	fairsched_nr_nodes++;

	retval = newid;
out:
	return retval;

out_free:
	kfree(node);
	return retval;
}

asmlinkage int sys_fairsched_mknod(unsigned int parent, unsigned int weight,
				    unsigned int newid)
{
	int retval;

	if (!capable_setveid())
		return -EPERM;

	mutex_lock(&fairsched_mutex);
	retval = do_fairsched_mknod(parent, weight, newid);
	mutex_unlock(&fairsched_mutex);

	return retval;
}
EXPORT_SYMBOL(sys_fairsched_mknod);

static int do_fairsched_rmnod(unsigned int id)
{
	struct fairsched_node *node;
	int retval;

	retval = -EINVAL;
	node = fairsched_find(id);
	if (node == NULL)
		goto out;
        if (node == &fairsched_init_node)
                goto out;

	retval = -EBUSY;
	if (node->refcnt)
		goto out;

	list_del(&node->nodelist);
	fairsched_nr_nodes--;

	sched_destroy_group(node->tg);
	kfree(node);
	retval = 0;
out:
	return retval;
}

asmlinkage int sys_fairsched_rmnod(unsigned int id)
{
	int retval;

	if (!capable_setveid())
		return -EPERM;

	mutex_lock(&fairsched_mutex);
	retval = do_fairsched_rmnod(id);
	mutex_unlock(&fairsched_mutex);

	return retval;
}
EXPORT_SYMBOL(sys_fairsched_rmnod);

static int do_fairsched_chwt(unsigned int id, unsigned weight)
{
	struct fairsched_node *node;

	if (id == 0)
		return -EINVAL;
	if (weight < 1 || weight > FSCHWEIGHT_MAX)
		return -EINVAL;

	node = fairsched_find(id);
	if (node == NULL)
		return -ENOENT;

	node->weight = weight;
	sched_group_set_shares(node->tg, FSCHWEIGHT_BASE / weight);

	return 0;
}

asmlinkage int sys_fairsched_chwt(unsigned int id, unsigned weight)
{
	int retval;

	if (!capable_setveid())
		return -EPERM;

	mutex_lock(&fairsched_mutex);
	retval = do_fairsched_chwt(id, weight);
	mutex_unlock(&fairsched_mutex);

	return retval;
}

static int do_fairsched_vcpus(unsigned int id, unsigned int vcpus)
{
	struct fairsched_node *node;

	if (id == 0)
		return -EINVAL;

	node = fairsched_find(id);
	if (node == NULL)
		return -ENOENT;

	return 0;
}

asmlinkage int sys_fairsched_vcpus(unsigned int id, unsigned int vcpus)
{
	int retval;

	if (!capable_setveid())
		return -EPERM;

	mutex_lock(&fairsched_mutex);
	retval = do_fairsched_vcpus(id, vcpus);
	mutex_unlock(&fairsched_mutex);

	return retval;
}
EXPORT_SYMBOL(sys_fairsched_vcpus);

static int do_fairsched_rate(unsigned int id, int op, unsigned rate)
{
	struct fairsched_node *node;
	int retval;

	if (id == 0)
		return -EINVAL;
	if (op == FAIRSCHED_SET_RATE && (rate < 1 || rate >= (1UL << 31)))
		return -EINVAL;

	node = fairsched_find(id);
	if (node == NULL)
		return -ENOENT;

	retval = -EINVAL;
	switch (op) {
	case FAIRSCHED_SET_RATE:
		node->rate = rate;
		node->rate_limited = 1;
		retval = rate;
		break;
	case FAIRSCHED_DROP_RATE:
		node->rate = 0;
		node->rate_limited = 0;
		retval = 0;
		break;
	case FAIRSCHED_GET_RATE:
		if (node->rate_limited)
			retval = node->rate;
		else
			retval = -ENODATA;
		break;
	}
	return retval;
}

asmlinkage int sys_fairsched_rate(unsigned int id, int op, unsigned rate)
{
	int retval;

	if (!capable_setveid())
		return -EPERM;

	mutex_lock(&fairsched_mutex);
	retval = do_fairsched_rate(id, op, rate);
	mutex_unlock(&fairsched_mutex);

	return retval;
}

static int do_fairsched_mvpr(pid_t pid, unsigned int nodeid)
{
	struct task_struct *p;
	struct fairsched_node *node;
	int retval;

	retval = -ENOENT;
	node = fairsched_find(nodeid);
	if (node == NULL)
		goto out;

	write_lock_irq(&tasklist_lock);
	retval = -ESRCH;
	p = find_task_by_vpid(pid);
	if (p == NULL)
		goto out_unlock;

	get_task_struct(p);
	put_task_fairsched_node(p);
	p->fsched_node = node;
	get_task_fairsched_node(p);
	write_unlock_irq(&tasklist_lock);

	smp_wmb();
	sched_move_task(p);
	put_task_struct(p);
	return 0;

out_unlock:
	write_unlock_irq(&tasklist_lock);
out:
	return retval;
}

asmlinkage int sys_fairsched_mvpr(pid_t pid, unsigned int nodeid)
{
	int retval;

	if (!capable_setveid())
		return -EPERM;

	mutex_lock(&fairsched_mutex);
	retval = do_fairsched_mvpr(pid, nodeid);
	mutex_unlock(&fairsched_mutex);

	return retval;
}
EXPORT_SYMBOL(sys_fairsched_mvpr);

int fairsched_new_node(int id, unsigned int vcpus)
{
	int err;

	mutex_lock(&fairsched_mutex);
	/*
	 * We refuse to switch to an already existing node since nodes
	 * keep a pointer to their ve_struct...
	 */
	err = do_fairsched_mknod(0, 1, id);
	if (err < 0) {
		printk(KERN_WARNING "Can't create fairsched node %d\n", id);
		goto out;
	}
#if 0
	err = do_fairsched_vcpus(id, vcpus);
	if (err) {
		printk(KERN_WARNING "Can't set sched vcpus on node %d\n", id);
		goto cleanup;
	}
#endif
	err = do_fairsched_mvpr(current->pid, id);
	if (err) {
		printk(KERN_WARNING "Can't switch to fairsched node %d\n", id);
		goto cleanup;
	}
	mutex_unlock(&fairsched_mutex);
	return 0;

cleanup:
	if (do_fairsched_rmnod(id))
		printk(KERN_ERR "Can't clean fairsched node %d\n", id);
out:
	mutex_unlock(&fairsched_mutex);
	return err;
}
EXPORT_SYMBOL(fairsched_new_node);

void fairsched_drop_node(int id)
{
	mutex_lock(&fairsched_mutex);
	if (task_fairsched_node_id(current) == id)
		if (do_fairsched_mvpr(current->pid, FAIRSCHED_INIT_NODE_ID))
			printk(KERN_WARNING "Can't leave sched node %d\n", id);
	if (do_fairsched_rmnod(id))
		printk(KERN_ERR "Can't remove fairsched node %d\n", id);
	mutex_unlock(&fairsched_mutex);
}
EXPORT_SYMBOL(fairsched_drop_node);

#ifdef CONFIG_PROC_FS

/*********************************************************************/
/*
 * proc interface
 */
/*********************************************************************/

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/vmalloc.h>

struct fairsched_node_dump {
	int id;
	unsigned weight;
	unsigned rate;
	int rate_limited;
	int nr_pcpu;
	int nr_tasks, nr_runtasks;
};

struct fairsched_dump {
	int len;
	struct fairsched_node_dump nodes[0];
};

static struct fairsched_dump *fairsched_do_dump(int compat)
{
	int nr_nodes;
	int len;
	struct fairsched_dump *dump;
	struct fairsched_node *node;
	struct fairsched_node_dump *p;

	mutex_lock(&fairsched_mutex);
	nr_nodes = (ve_is_super(get_exec_env()) ? fairsched_nr_nodes + 16 : 1);
	len = sizeof(*dump) + nr_nodes * sizeof(dump->nodes[0]);
	dump = ub_vmalloc(len);
	if (dump == NULL)
		goto out;

	p = dump->nodes;
	list_for_each_entry_reverse(node, &fairsched_node_head, nodelist) {
		if ((char *)p - (char *)dump >= len)
			break;
		p->nr_tasks = 0;
		p->nr_runtasks = 0;
#ifdef CONFIG_VE
		if (!ve_accessible(node->owner_env, get_exec_env()))
			continue;
		p->nr_tasks = atomic_read(&node->owner_env->pcounter);
		p->nr_runtasks = nr_running_ve(node->owner_env);
#endif
		p->id = node->id;
		p->weight = node->weight;
		p->rate = node->rate;
		p->rate_limited = node->rate_limited;
		p->nr_pcpu = num_online_cpus();
		p++;
	}
	dump->len = p - dump->nodes;
out:
	mutex_unlock(&fairsched_mutex);
	return dump;
}

#define FAIRSCHED_PROC_HEADLINES 2

#define FAIRSHED_DEBUG          " debug"

#ifdef CONFIG_VE
/*
 * File format is dictated by compatibility reasons.
 */
static int fairsched_seq_show(struct seq_file *m, void *v)
{
	struct fairsched_dump *dump;
	struct fairsched_node_dump *p;
	unsigned vid, nid, pid, r;

	dump = m->private;
	p = (struct fairsched_node_dump *)((unsigned long)v & ~3UL);
	if (p - dump->nodes < FAIRSCHED_PROC_HEADLINES) {
		if (p == dump->nodes)
			seq_printf(m, "Version: 2.6 debug\n");
		else if (p == dump->nodes + 1)
			seq_printf(m,
				       "      veid "
				       "        id "
				       "    parent "
				       "weight "
				       " rate "
				       "tasks "
				       "  run "
				       "cpus"
				       " "
				       "flg "
				       "ready "
				       "           start_tag "
				       "               value "
				       "               delay"
				       "\n");
	} else {
		p -= FAIRSCHED_PROC_HEADLINES;
		vid = nid = pid = 0;
		r = (unsigned long)v & 3;
		if (p == dump->nodes) {
			if (r == 2)
				nid = p->id;
		} else {
			if (!r)
				nid = p->id;
			else if (r == 1)
				vid = pid = p->id;
			else
				vid = p->id, nid = 1;
		}
		seq_printf(m,
			       "%10u "
			       "%10u %10u %6u %5u %5u %5u %4u"
			       " "
			       " %c%c %5u %20Lu %20Lu %20Lu"
			       "\n",
			       vid,
			       nid,
			       pid,
			       p->weight,
			       p->rate,
			       p->nr_tasks,
			       p->nr_runtasks,
			       p->nr_pcpu,
			       p->rate_limited ? 'L' : '.',
			       '.',
			       p->nr_runtasks,
			       0ll, 0ll, 0ll);
	}

	return 0;
}

static void *fairsched_seq_start(struct seq_file *m, loff_t *pos)
{
	struct fairsched_dump *dump;
	unsigned long l;

	dump = m->private;
	if (*pos >= dump->len * 3 - 1 + FAIRSCHED_PROC_HEADLINES)
		return NULL;
	if (*pos < FAIRSCHED_PROC_HEADLINES)
		return dump->nodes + *pos;
	/* guess why... */
	l = (unsigned long)(dump->nodes +
		((unsigned long)*pos + FAIRSCHED_PROC_HEADLINES * 2 + 1) / 3);
	l |= ((unsigned long)*pos + FAIRSCHED_PROC_HEADLINES * 2 + 1) % 3;
	return (void *)l;
}
static void *fairsched_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return fairsched_seq_start(m, pos);
}
#endif /* CONFIG_VE */

static int fairsched2_seq_show(struct seq_file *m, void *v)
{
	struct fairsched_dump *dump;
	struct fairsched_node_dump *p;

	dump = m->private;
	p = v;
	if (p - dump->nodes < FAIRSCHED_PROC_HEADLINES) {
		if (p == dump->nodes)
			seq_printf(m, "Version: 2.7" FAIRSHED_DEBUG "\n");
		else if (p == dump->nodes + 1)
			seq_printf(m,
				       "        id "
				       "weight "
				       " rate "
				       "  run "
				       "cpus"
#ifdef FAIRSHED_DEBUG
				       " "
				       "flg "
				       "ready "
				       "           start_tag "
				       "               value "
				       "               delay"
#endif
				       "\n");
	} else {
		p -= FAIRSCHED_PROC_HEADLINES;
		seq_printf(m,
			       "%10u %6u %5u %5u %4u"
#ifdef FAIRSHED_DEBUG
			       " "
			       " %c%c %5u %20Lu %20Lu %20Lu"
#endif
			       "\n",
			       p->id,
			       p->weight,
			       p->rate,
			       p->nr_runtasks,
			       p->nr_pcpu
#ifdef FAIRSHED_DEBUG
			       ,
			       p->rate_limited ? 'L' : '.',
			       '.',
			       p->nr_runtasks,
			       0ll, 0ll, 0ll
#endif
			       );
	}

	return 0;
}

static void *fairsched2_seq_start(struct seq_file *m, loff_t *pos)
{
	struct fairsched_dump *dump;

	dump = m->private;
	if (*pos >= dump->len + FAIRSCHED_PROC_HEADLINES)
		return NULL;
	return dump->nodes + *pos;
}
static void *fairsched2_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return fairsched2_seq_start(m, pos);
}
static void fairsched2_seq_stop(struct seq_file *m, void *v)
{
}

#ifdef CONFIG_VE
static struct seq_operations fairsched_seq_op = {
	.start		= fairsched_seq_start,
	.next		= fairsched_seq_next,
	.stop		= fairsched2_seq_stop,
	.show		= fairsched_seq_show
};
#endif
static struct seq_operations fairsched2_seq_op = {
	.start		= fairsched2_seq_start,
	.next		= fairsched2_seq_next,
	.stop		= fairsched2_seq_stop,
	.show		= fairsched2_seq_show
};
static int fairsched_seq_open(struct inode *inode, struct file *file)
{
	int ret;
	struct seq_file *m;
	int compat;

#ifdef CONFIG_VE
	compat = (file->f_dentry->d_name.len == sizeof("fairsched") - 1);
	ret = seq_open(file, compat ? &fairsched_seq_op : &fairsched2_seq_op);
#else
	compat = 0;
	ret = seq_open(file, &fairsched2_seq_op);
#endif
	if (ret)
		return ret;
	m = file->private_data;
	m->private = fairsched_do_dump(compat);
	if (m->private == NULL) {
		seq_release(inode, file);
		ret = -ENOMEM;
	}
	return ret;
}
static int fairsched_seq_release(struct inode *inode, struct file *file)
{
	struct seq_file *m;
	struct fairsched_dump *dump;

	m = file->private_data;
	dump = m->private;
	m->private = NULL;
	vfree(dump);
	seq_release(inode, file);
	return 0;
}
static struct file_operations proc_fairsched_operations = {
	.open		= fairsched_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= fairsched_seq_release
};

void __init fairsched_init_late(void)
{
	proc_create("fairsched", S_IRUGO, &glob_proc_root,
			&proc_fairsched_operations);
	proc_create("fairsched2", S_IRUGO, &glob_proc_root,
			&proc_fairsched_operations);
}

#else

void __init fairsched_init_late(void) { }

#endif /* CONFIG_PROC_FS */
