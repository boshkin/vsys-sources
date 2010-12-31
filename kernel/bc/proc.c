/*
 *  kernel/bc/proc.c 
 *
 *  Copyright (C) 2006 OpenVZ. SWsoft Inc.
 *
 */

#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/module.h>

#include <bc/beancounter.h>
#include <bc/hash.h>
#include <bc/rss_pages.h>
#include <bc/proc.h>

/* Generic output formats */
#if BITS_PER_LONG == 32
const char *bc_proc_lu_fmt = "\t%-20s %10lu\n";
const char *bc_proc_lu_lfmt = "\t%-20s %21lu\n";
const char *bc_proc_llu_fmt = "\t%-20s %21llu\n";
const char *bc_proc_lu_lu_fmt = "\t%-20s %10lu %10lu\n";
#else
const char *bc_proc_lu_fmt = "\t%-20s %21lu\n";
const char *bc_proc_lu_lfmt = "\t%-20s %21lu\n";
const char *bc_proc_llu_fmt = "\t%-20s %21llu\n";
const char *bc_proc_lu_lu_fmt = "\t%-20s %21lu %21lu\n";
#endif

#if BITS_PER_LONG == 32
static const char *head_fmt = "%10s  %-12s %10s %10s %10s %10s %10s\n";
static const char *res_fmt = "%10s  %-12s %10lu %10lu %10lu %10lu %10lu\n";
#else
static const char *head_fmt = "%10s  %-12s %20s %20s %20s %20s %20s\n";
static const char *res_fmt = "%10s  %-12s %20lu %20lu %20lu %20lu %20lu\n";
#endif

static void ub_show_res(struct seq_file *f, struct user_beancounter *ub,
		int r, int show_uid)
{
	int len;
	char ub_uid[64];

	if (show_uid && r == 0) {
		len = print_ub_uid(ub, ub_uid, sizeof(ub_uid) - 2);
		ub_uid[len] = ':';
		ub_uid[len + 1] = '\0';
	} else
		strcpy(ub_uid, "");

	seq_printf(f, res_fmt, ub_uid, ub_rnames[r],
			ub->ub_parms[r].held,
			ub->ub_parms[r].maxheld,
			ub->ub_parms[r].barrier,
			ub->ub_parms[r].limit,
			ub->ub_parms[r].failcnt);
}

static void __show_resources(struct seq_file *f, struct user_beancounter *ub,
		int show_uid)
{
	int i;

	for (i = 0; i < UB_RESOURCES_COMPAT; i++)
		if (strcmp(ub_rnames[i], "dummy") != 0)
			ub_show_res(f, ub, i, show_uid);

	for (i = UB_RESOURCES_COMPAT; i < UB_RESOURCES; i++)
		ub_show_res(f, ub, i, show_uid);
}

static int bc_resources_show(struct seq_file *f, void *v)
{
	__show_resources(f, seq_beancounter(f), 0);
	return 0;
}

static struct bc_proc_entry bc_resources_entry = {
	.name = "resources",
	.u.show = bc_resources_show,
};

#ifdef CONFIG_UBC_DEBUG
static int bc_debug_show(struct seq_file *f, void *v)
{
	struct user_beancounter *ub;
	char buf[64];

	ub = seq_beancounter(f);
	print_ub_uid(ub, buf, sizeof(buf));
	seq_printf(f, "uid: %s\n", buf);
	seq_printf(f, "ref: %d\n", atomic_read(&ub->ub_refcount));

	seq_printf(f, "bc: %p\n", ub);
	seq_printf(f, "par: %p\n", ub->parent);
	seq_printf(f, "priv: %p\n", ub->private_data);
	return 0;
}

static struct bc_proc_entry bc_debug_entry = {
	.name = "debug",
	.u.show = bc_debug_show,
};
#endif

static int ub_show(struct seq_file *f, void *v)
{
	int i;

	for (i = 0; i < UB_RESOURCES_COMPAT; i++)
		ub_show_res(f, (struct user_beancounter *)v, i, 1);
	return 0;
}

static int res_show(struct seq_file *f, void *v)
{
	__show_resources(f, (struct user_beancounter *)v, 1);
	return 0;
}

static int ub_accessible(struct user_beancounter *exec,
		struct user_beancounter *target)
{
	struct user_beancounter *p, *q;

	p = top_beancounter(exec);
	q = top_beancounter(target);

	return (p == get_ub0() || p == q);
}

static void ub_show_header(struct seq_file *f)
{
	seq_printf(f, "Version: 2.5\n");
	seq_printf(f, head_fmt, "uid", "resource",
			"held", "maxheld", "barrier", "limit", "failcnt");
}

static void *ub_start(struct seq_file *f, loff_t *ppos)
{
	struct user_beancounter *ub;
	struct user_beancounter *exec_ub; 
	unsigned long pos;

	pos = *ppos;
	if (pos == 0)
		ub_show_header(f);

	exec_ub = get_exec_ub();

	rcu_read_lock();
	for_each_beancounter(ub) {
		if (ub->parent != NULL)
			continue;
		if (!ub_accessible(exec_ub, ub))
			continue;
		if (pos-- == 0)
			return ub;
	}
	return NULL;
}

static void *ub_next(struct seq_file *f, void *v, loff_t *ppos)
{
	struct user_beancounter *ub;
	struct list_head *entry;
	struct user_beancounter *exec_ub;

	exec_ub = get_exec_ub();
	ub = (struct user_beancounter *)v;

	entry = &ub->ub_list;

	list_for_each_continue_rcu(entry, &ub_list_head) {
		ub = list_entry(entry, struct user_beancounter, ub_list);
		if (ub->parent != NULL)
			continue;
		if (!ub_accessible(exec_ub, ub))
			continue;

		(*ppos)++;
		return ub;
	}
	return NULL;
}

static void ub_stop(struct seq_file *f, void *v)
{
	rcu_read_unlock();
}

static struct seq_operations ub_seq_ops = {
	.start = ub_start,
	.next  = ub_next,
	.stop  = ub_stop,
	.show  = ub_show,
};

static int ub_open(struct inode *inode, struct file *filp)
{
	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return -EACCES;

	return seq_open(filp, &ub_seq_ops);
}

static struct file_operations ub_file_operations = {
	.open		= ub_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static struct seq_operations res_seq_ops = {
	.start = ub_start,
	.next  = ub_next,
	.stop  = ub_stop,
	.show  = res_show,
};

static int res_open(struct inode *inode, struct file *filp)
{
	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return -EACCES;

	return seq_open(filp, &res_seq_ops);
}

static struct file_operations resources_operations = {
	.open		= res_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static struct bc_proc_entry bc_all_resources_entry = {
	.name = "resources",
	.u.fops = &resources_operations,
};

/*
 * Generic showing stuff
 */

static int cookies, num_entries;
static struct bc_proc_entry *bc_entries __read_mostly;
static struct bc_proc_entry *bc_root_entries __read_mostly;
static DEFINE_SPINLOCK(bc_entries_lock);
static struct proc_dir_entry *bc_proc_root;

void bc_register_proc_entry(struct bc_proc_entry *e)
{
	spin_lock(&bc_entries_lock);
	e->cookie = ++cookies;
	e->next = bc_entries;
	bc_entries = e;
	num_entries++;
	spin_unlock(&bc_entries_lock);
}

EXPORT_SYMBOL(bc_register_proc_entry);

void bc_register_proc_root_entry(struct bc_proc_entry *e)
{
	spin_lock(&bc_entries_lock);
	e->cookie = ++cookies;
	e->next = bc_root_entries;
	bc_root_entries = e;
	bc_proc_root->nlink++;
	spin_unlock(&bc_entries_lock);
}

EXPORT_SYMBOL(bc_register_proc_root_entry);

/*
 * small helpers
 */

static inline unsigned long bc_make_ino(struct user_beancounter *ub)
{
	unsigned long ret;

	ret = 0xbc000000;
	if (ub->parent)
		ret |= ((ub->parent->ub_uid + 1) << 4);
	ret |= (ub->ub_uid + 1);
	return ret;
}

static inline unsigned long bc_make_file_ino(struct bc_proc_entry *de)
{
	return 0xbe000000 + de->cookie;
}

static int bc_d_delete(struct dentry *d)
{
	return 1;
}

static void bc_d_release(struct dentry *d)
{
	put_beancounter((struct user_beancounter *)d->d_fsdata);
}

static struct inode_operations bc_entry_iops;
static struct file_operations bc_entry_fops;
static struct dentry_operations bc_dentry_ops = {
	.d_delete = bc_d_delete,
	.d_release = bc_d_release,
};

/*
 * common directory operations' helpers
 */

static int bc_readdir(struct file *file, filldir_t filler, void *data,
		struct user_beancounter *parent)
{
	int err = 0;
	loff_t pos, filled;
	struct user_beancounter *ub, *prev;
	struct bc_proc_entry *pde;

	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return -EPERM;

	pos = file->f_pos;
	if (pos == 0) {
		err = (*filler)(data, ".", 1, pos,
				file->f_dentry->d_inode->i_ino, DT_DIR);
		if (err < 0) {
			err = 0;
			goto out;
		}
		pos++;
	}

	if (pos == 1) {
		err = (*filler)(data, "..", 2, pos,
				parent_ino(file->f_dentry), DT_DIR);
		if (err < 0) {
			err = 0;
			goto out;
		}
		pos++;
	}

	filled = 2;
	for (pde = (parent == NULL ? bc_root_entries : bc_entries);
			pde != NULL; pde = pde->next) {
		if (filled++ < pos)
			continue;

		err = (*filler)(data, pde->name, strlen(pde->name), pos,
				bc_make_file_ino(pde), DT_REG);
		if (err < 0) {
			err = 0;
			goto out;
		}
		pos++;
	}

	rcu_read_lock();
	prev = NULL;
	ub = list_entry(&ub_list_head, struct user_beancounter, ub_list);
	while (1) {
		int len;
		unsigned long ino;
		char buf[64];

		ub = list_entry(rcu_dereference(ub->ub_list.next),
				struct user_beancounter, ub_list);
		if (&ub->ub_list == &ub_list_head)
			break;

		if (ub->parent != parent)
			continue;

		if (filled++ < pos)
			continue;

		if (!get_beancounter_rcu(ub))
			continue;

		rcu_read_unlock();
		put_beancounter(prev);

		len = print_ub_uid(ub, buf, sizeof(buf));
		ino = bc_make_ino(ub);

		err = (*filler)(data, buf, len, pos, ino, DT_DIR);
		if (err < 0) {
			err = 0;
			put_beancounter(ub);
			goto out;
		}

		rcu_read_lock();
		prev = ub;
		pos++;
	}
	rcu_read_unlock();
	put_beancounter(prev);
out:
	file->f_pos = pos;
	return err;
}

static int bc_looktest(struct inode *ino, void *data)
{
	return ino->i_op == &bc_entry_iops && ino->i_private == data;
}

static int bc_lookset(struct inode *ino, void *data)
{
	struct user_beancounter *ub;

	ub = (struct user_beancounter *)data;
	ino->i_private = data;
	ino->i_ino = bc_make_ino(ub);
	ino->i_fop = &bc_entry_fops;
	ino->i_op = &bc_entry_iops;
	ino->i_mode = S_IFDIR | S_IRUSR | S_IXUSR;
	/* subbeancounters are not included, but who cares? */
	ino->i_nlink = num_entries + 2;
	ino->i_gid = 0;
	ino->i_uid = 0;
	return 0;
}

static struct dentry *bc_lookup(struct user_beancounter *ub, struct inode *dir,
		struct dentry *dentry)
{
	struct inode *ino;

	ino = iget5_locked(dir->i_sb, ub->ub_uid, bc_looktest, bc_lookset, ub);
	if (ino == NULL)
		goto out_put;

	unlock_new_inode(ino);
	dentry->d_op = &bc_dentry_ops;
	dentry->d_fsdata = ub;
	d_add(dentry, ino);
	return NULL;

out_put:
	put_beancounter(ub);
	return ERR_PTR(-ENOENT);
}

/*
 * files (bc_proc_entry) manipulations
 */

static struct dentry *bc_lookup_file(struct inode *dir,
		struct dentry *dentry, struct bc_proc_entry *root,
		int (*test)(struct inode *, void *),
		int (*set)(struct inode *, void *))
{
	struct bc_proc_entry *pde;
	struct inode *ino;

	for (pde = root; pde != NULL; pde = pde->next)
		if (strcmp(pde->name, dentry->d_name.name) == 0)
			break;

	if (pde == NULL)
		return ERR_PTR(-ESRCH);

	ino = iget5_locked(dir->i_sb, pde->cookie, test, set, pde);
	if (ino == NULL)
		return ERR_PTR(-ENOENT);

	unlock_new_inode(ino);
	dentry->d_op = &bc_dentry_ops;
	d_add(dentry, ino);
	return NULL;
}

static int bc_file_open(struct inode *ino, struct file *filp)
{
	struct bc_proc_entry *de;
	struct user_beancounter *ub;

	de = (struct bc_proc_entry *)ino->i_private;
	ub = (struct user_beancounter *)filp->f_dentry->d_parent->d_fsdata;
	BUG_ON(ub->ub_magic != UB_MAGIC);

	/*
	 * ub can't disappear: we hold d_parent, he holds the beancounter
	 */
	return single_open(filp, de->u.show, ub);
}

static struct file_operations bc_file_ops = {
	.open		= bc_file_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int bc_looktest_entry(struct inode *ino, void *data)
{
	return ino->i_fop == &bc_file_ops && ino->i_private == data;
}

static int bc_lookset_entry(struct inode *ino, void *data)
{
	struct bc_proc_entry *de;

	de = (struct bc_proc_entry *)data;
	ino->i_private = data;
	ino->i_ino = bc_make_file_ino(de);
	ino->i_fop = &bc_file_ops,
	ino->i_mode = S_IFREG | S_IRUSR;
	ino->i_nlink = 1;
	ino->i_gid = 0;
	ino->i_uid = 0;
	return 0;
}

static inline struct dentry *bc_lookup_files(struct inode *dir,
		struct dentry *de)
{
	return bc_lookup_file(dir, de, bc_entries,
			bc_looktest_entry, bc_lookset_entry);
}

static int bc_looktest_root_entry(struct inode *ino, void *data)
{
	struct bc_proc_entry *de;

	de = (struct bc_proc_entry *)data;
	return ino->i_fop == de->u.fops && ino->i_private == data;
}

static int bc_lookset_root_entry(struct inode *ino, void *data)
{
	struct bc_proc_entry *de;

	de = (struct bc_proc_entry *)data;
	ino->i_private = data;
	ino->i_ino = bc_make_file_ino(de);
	ino->i_fop = de->u.fops;
	ino->i_mode = S_IFREG | S_IRUSR;
	ino->i_nlink = 1;
	ino->i_gid = 0;
	ino->i_uid = 0;
	return 0;
}

static inline struct dentry *bc_lookup_root_files(struct inode *dir,
		struct dentry *de)
{
	return bc_lookup_file(dir, de, bc_root_entries,
			bc_looktest_root_entry, bc_lookset_root_entry);
}

/*
 * /proc/bc/.../<id> directory operations
 */

static int bc_entry_readdir(struct file *file, void *data, filldir_t filler)
{
	return bc_readdir(file, filler, data,
			(struct user_beancounter *)file->f_dentry->d_fsdata);
}

static struct dentry *bc_entry_lookup(struct inode *dir, struct dentry *dentry,
		struct nameidata *nd)
{
	int id;
	char *end;
	struct user_beancounter *par, *ub;
	struct dentry *de;

	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return ERR_PTR(-EPERM);

	de = bc_lookup_files(dir, dentry);
	if (de != ERR_PTR(-ESRCH))
		return de;

	id = simple_strtol(dentry->d_name.name, &end, 10);
	if (*end != '.')
		return ERR_PTR(-ENOENT);

	par = (struct user_beancounter *)dir->i_private;
	if (par->ub_uid != id)
		return ERR_PTR(-ENOENT);

	id = simple_strtol(end + 1, &end, 10);
	if (*end != '\0')
		return ERR_PTR(-ENOENT);

	ub = get_subbeancounter_byid(par, id, 0);
	if (ub == NULL)
		return ERR_PTR(-ENOENT);

	return bc_lookup(ub, dir, dentry);
}

static int bc_entry_getattr(struct vfsmount *mnt, struct dentry *dentry,
		struct kstat *stat)
{
	struct user_beancounter *ub;

	generic_fillattr(dentry->d_inode, stat);
	ub = (struct user_beancounter *)dentry->d_fsdata;
	stat->nlink = ub->ub_childs + 2;
	return 0;
}

static struct file_operations bc_entry_fops = {
	.read = generic_read_dir,
	.readdir = bc_entry_readdir,
};

static struct inode_operations bc_entry_iops = {
	.lookup = bc_entry_lookup,
	.getattr = bc_entry_getattr,
};

/*
 * /proc/bc directory operations
 */

static int bc_root_readdir(struct file *file, void *data, filldir_t filler)
{
	return bc_readdir(file, filler, data, NULL);
}

static struct dentry *bc_root_lookup(struct inode *dir, struct dentry *dentry,
		struct nameidata *nd)
{
	int id;
	char *end;
	struct user_beancounter *ub;
	struct dentry *de;

	if (!(capable(CAP_DAC_OVERRIDE) && capable(CAP_DAC_READ_SEARCH)))
		return ERR_PTR(-EPERM);

	de = bc_lookup_root_files(dir, dentry);
	if (de != ERR_PTR(-ESRCH))
		return de;

	id = simple_strtol(dentry->d_name.name, &end, 10);
	if (*end != '\0')
		return ERR_PTR(-ENOENT);

	ub = get_beancounter_byuid(id, 0);
	if (ub == NULL)
		return ERR_PTR(-ENOENT);

	return bc_lookup(ub, dir, dentry);
}

static int bc_root_getattr(struct vfsmount *mnt, struct dentry *dentry,
	struct kstat *stat)
{
	generic_fillattr(dentry->d_inode, stat);
	stat->nlink = ub_count + 2;
	return 0;
}

static struct file_operations bc_root_fops = {
	.read = generic_read_dir,
	.readdir = bc_root_readdir,
};

static struct inode_operations bc_root_iops = {
	.lookup = bc_root_lookup,
	.getattr = bc_root_getattr,
};

static int __init ub_init_proc(void)
{
	struct proc_dir_entry *entry;

	bc_proc_root = create_proc_entry("bc",
			S_IFDIR | S_IRUSR | S_IXUSR, NULL);
	if (bc_proc_root == NULL)
		panic("Can't create /proc/bc entry");

	bc_proc_root->proc_fops = &bc_root_fops;
	bc_proc_root->proc_iops = &bc_root_iops;

	bc_register_proc_entry(&bc_resources_entry);
#ifdef CONFIG_UBC_DEBUG
	bc_register_proc_entry(&bc_debug_entry);
#endif
	bc_register_proc_root_entry(&bc_all_resources_entry);

	entry = proc_create("user_beancounters",
			S_IRUSR, &glob_proc_root, &ub_file_operations);
	return 0;
}

core_initcall(ub_init_proc);
