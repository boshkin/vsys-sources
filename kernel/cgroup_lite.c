/*
 * lite cgroups engine
 */

#include <linux/cgroup.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
#include <linux/ve.h>
#include <linux/proc_fs.h>
#include <linux/module.h>

#define SUBSYS(_x) &_x ## _subsys,

static struct cgroup_subsys *subsys[] = {
#include <linux/cgroup_subsys.h>
};

static struct css_set init_css_set;
static struct cgroup init_cgroup;
static struct cftype *subsys_cftypes[CGROUP_SUBSYS_COUNT];

static struct idr cgroup_idr;
static DEFINE_SPINLOCK(cgroup_idr_lock);

unsigned short css_id(struct cgroup_subsys_state *css)
{
	return css->cgroup->cgroup_lite_id;
}

unsigned short css_depth(struct cgroup_subsys_state *css)
{
	return (css->cgroup == &init_cgroup) ? 0 : 1;
}

int cgroup_path(const struct cgroup *cgrp, char *buf, int buflen)
{
	snprintf(buf, buflen, "/%d", cgrp->cgroup_lite_id);
	return 0;
}

struct cgroup_subsys_state *css_lookup(struct cgroup_subsys *ss, int id)
{
	struct cgroup *g;

	BUG_ON(!ss->use_id);
	g = idr_find(&cgroup_idr, id);
	if (!g)
		return NULL;
	return g->subsys[ss->subsys_id];
}

void free_css_id(struct cgroup_subsys *ss, struct cgroup_subsys_state *css)
{
}

static int init_cgroup_id(struct cgroup *g)
{
	int err, id;

	if (unlikely(!idr_pre_get(&cgroup_idr, GFP_KERNEL)))
		return -ENOMEM;

	spin_lock(&cgroup_idr_lock);
	err = idr_get_new_above(&cgroup_idr, g, 1, &id);
	spin_unlock(&cgroup_idr_lock);

	if (err)
		return err;

	if (id > USHORT_MAX) {
		spin_lock(&cgroup_idr_lock);
		idr_remove(&cgroup_idr, id);
		spin_unlock(&cgroup_idr_lock);
		return -ENOSPC;
	}

	g->cgroup_lite_id = id;

	return 0;
}

static void fini_cgroup_id(struct cgroup *g)
{
	spin_lock(&cgroup_idr_lock);
	idr_remove(&cgroup_idr, g->cgroup_lite_id);
	spin_unlock(&cgroup_idr_lock);
}

void __css_put(struct cgroup_subsys_state *css)
{
	atomic_dec(&css->refcnt);
}

static int init_css_set_subsystems(struct cgroup *g, struct css_set *set)
{
	int i;
	struct cgroup_subsys_state *ss;

	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		struct cgroup_subsys *cs = subsys[i];

		ss = cs->create(cs, g);
		if (IS_ERR(ss))
			goto destroy;

		g->subsys[i] = ss;
		set->subsys[i] = ss;
		atomic_set(&ss->refcnt, 1);
		ss->cgroup = g;
	}
	return 0;

destroy:
	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		struct cgroup_subsys *cs = subsys[i];

		if (g->subsys[i])
			cs->destroy(cs, g);
	}
	return PTR_ERR(ss);
}

int init_ve_cgroups(struct ve_struct *ve)
{
	int err = -ENOMEM;
	struct cgroup *g;
	struct css_set *cs;

	g = kzalloc(sizeof(struct cgroup), GFP_KERNEL);
	if (g == NULL)
		goto err_galloc;

	cs = kzalloc(sizeof(struct css_set), GFP_KERNEL);
	if (cs == NULL)
		goto err_calloc;

	err = init_cgroup_id(g);
	if (err)
		goto err_id;

	g->parent = &init_cgroup;
	err = init_css_set_subsystems(g, cs);
	if (err)
		goto err_subsys;

	g->parent = &init_cgroup;
	ve->ve_cgroup = g;
	ve->ve_css_set = cs;
	return 0;

err_subsys:
	fini_cgroup_id(g);
err_id:
	kfree(cs);
err_calloc:
	kfree(g);
err_galloc:
	return err;
}
EXPORT_SYMBOL(init_ve_cgroups);

void fini_ve_cgroups(struct ve_struct *ve)
{
	int i;
	struct cgroup *g = ve->ve_cgroup;
	struct css_set *css = ve->ve_css_set;

	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		struct cgroup_subsys *cs = subsys[i];
		struct cgroup_subsys_state *ss = css->subsys[i];

		BUG_ON(ss != g->subsys[i]);

		if (cs->pre_destroy)
			cs->pre_destroy(cs, g);

		if (atomic_read(&ss->refcnt) != 1)
			printk(KERN_ERR "CG: leaking %d/%s subsys\n",
					ve->veid, subsys[i]->name);
		else
			cs->destroy(cs, g);
	}

	fini_cgroup_id(g);
	kfree(g);
	kfree(css);
	ve->ve_cgroup = NULL;
	ve->ve_css_set = NULL;
}
EXPORT_SYMBOL(fini_ve_cgroups);

/*
 * task lifecycle
 */

void cgroup_fork(struct task_struct *child)
{
	child->cgroups = current->cgroups;
}

void cgroup_fork_callbacks(struct task_struct *child)
{
}

void cgroup_post_fork(struct task_struct *child)
{
}

void cgroup_exit(struct task_struct *tsk, int dummy)
{
	tsk->cgroups = &init_css_set;
}

int cgroupstats_build(struct cgroupstats *stats, struct dentry *dentry)
{
	return -ENODATA;
}

int cgroup_set_task_css(struct task_struct *tsk, struct css_set *css)
{
	int i, err;
	struct cgroup_subsys *cs;
	struct css_set *old_css;

	old_css = tsk->cgroups;

	if (old_css == css)
		return 0;

	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		cs = subsys[i];
		if (!cs->can_attach)
			continue;
		err = cs->can_attach(cs, css->subsys[i]->cgroup, tsk, false);
		if (err)
			return err;
	}

	tsk->cgroups = css;

	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
		cs = subsys[i];
		if (!cs->attach)
			continue;
		cs->attach(cs, css->subsys[i]->cgroup,
				old_css->subsys[i]->cgroup, tsk, false);
	}

	return 0;
}
EXPORT_SYMBOL(cgroup_set_task_css);

/*
 * proc struts
 */

static int proc_cgroup_show(struct seq_file *m, void *v)
{
	struct task_struct *tsk;

	tsk = pid_task((struct pid *)m->private, PIDTYPE_PID);
	seq_printf(m, "%p\n", tsk->cgroups);
	return 0;
}

static int cgroup_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return single_open(file, proc_cgroup_show, PROC_I(inode)->pid);
}

const struct file_operations proc_cgroup_operations = {
	.open		= cgroup_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/*
 * cgroups misc struts
 */

int cgroup_add_files(struct cgroup *cgrp, struct cgroup_subsys *subsys,
		const struct cftype cft[], int count)
{
	int idx = subsys->subsys_id;
	static DEFINE_SPINLOCK(add_files_lock);

	if (unlikely(subsys_cftypes[idx] == NULL)) {
		spin_lock(&add_files_lock);
		if (subsys_cftypes[idx] == NULL)
			subsys_cftypes[idx] = (struct cftype *)cft;
		spin_unlock(&add_files_lock);
	}

	BUG_ON(subsys_cftypes[idx] != cft);
	return 0;
}

void cgroup_lock(void)
{
}

void cgroup_unlock(void)
{
}

bool cgroup_lock_live_group(struct cgroup *cg)
{
	return 1;
}


int cgroup_is_removed(const struct cgroup *cgrp)
{
	return 0;
}

int __init cgroup_init_early(void)
{
	int i;

	init_task.cgroups = &init_css_set;
	for (i = 0; i < CGROUP_SUBSYS_COUNT; i++)
		BUG_ON(subsys[i]->early_init);

	return 0;
}

int __init cgroup_init(void)
{
	get_ve0()->ve_cgroup = &init_cgroup;
	get_ve0()->ve_css_set = &init_css_set;
	idr_init(&cgroup_idr);
	if (init_cgroup_id(&init_cgroup))
		panic("CG: Can't init initial cgroup id\n");
	if (init_css_set_subsystems(&init_cgroup, &init_css_set) != 0)
		panic("CG: Can't init initial set\n");
	return 0;
}
