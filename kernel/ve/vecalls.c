/*
 *  linux/kernel/ve/vecalls.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 */

/*
 * 'vecalls.c' is file with basic VE support. It provides basic primities
 * along with initialization script
 */

#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/capability.h>
#include <linux/ve.h>
#include <linux/smp_lock.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sys.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/mnt_namespace.h>
#include <linux/termios.h>
#include <linux/tty_driver.h>
#include <linux/netdevice.h>
#include <linux/wait.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/utsname.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/devpts_fs.h>
#include <linux/shmem_fs.h>
#include <linux/user_namespace.h>
#include <linux/sysfs.h>
#include <linux/seq_file.h>
#include <linux/kernel_stat.h>
#include <linux/module.h>
#include <linux/suspend.h>
#include <linux/rcupdate.h>
#include <linux/in.h>
#include <linux/idr.h>
#include <linux/inetdevice.h>
#include <linux/pid.h>
#include <net/pkt_sched.h>
#include <bc/beancounter.h>
#include <linux/nsproxy.h>
#include <linux/kobject.h>
#include <linux/freezer.h>
#include <linux/pid_namespace.h>
#include <linux/tty.h>
#include <linux/mount.h>
#include <linux/kthread.h>
#include <linux/oom.h>

#include <net/route.h>
#include <net/ip_fib.h>
#include <net/ip6_route.h>
#include <net/arp.h>
#include <net/ipv6.h>

#include <linux/ve_proto.h>
#include <linux/venet.h>
#include <linux/vzctl.h>
#include <linux/vzcalluser.h>
#ifdef CONFIG_VZ_FAIRSCHED
#include <linux/fairsched.h>
#endif

#include <linux/virtinfo.h>
#include <linux/utsrelease.h>
#include <linux/major.h>

int nr_ve = 1;	/* One VE always exists. Compatibility with vestat */
EXPORT_SYMBOL(nr_ve);

static int	do_env_enter(struct ve_struct *ve, unsigned int flags);
static int	alloc_ve_tty_drivers(struct ve_struct* ve);
static void	free_ve_tty_drivers(struct ve_struct* ve);
static int	register_ve_tty_drivers(struct ve_struct* ve);
static void	unregister_ve_tty_drivers(struct ve_struct* ve);
static int	init_ve_tty_drivers(struct ve_struct *);
static void	fini_ve_tty_drivers(struct ve_struct *);
static void	clear_termios(struct tty_driver* driver );

static void vecalls_exit(void);

struct ve_struct *__find_ve_by_id(envid_t veid)
{
	struct ve_struct *ve;

	for_each_ve(ve) {
		if (ve->veid == veid)
			return ve;
	}
	return NULL;
}
EXPORT_SYMBOL(__find_ve_by_id);

struct ve_struct *get_ve_by_id(envid_t veid)
{
	struct ve_struct *ve;
	read_lock(&ve_list_lock);
	ve = __find_ve_by_id(veid);
	get_ve(ve);
	read_unlock(&ve_list_lock);
	return ve;
}
EXPORT_SYMBOL(get_ve_by_id);

/*
 * real_put_ve() MUST be used instead of put_ve() inside vecalls.
 */
static void real_do_env_free(struct ve_struct *ve);
static inline void real_put_ve(struct ve_struct *ve)
{
	if (ve && atomic_dec_and_test(&ve->counter)) {
		BUG_ON(atomic_read(&ve->pcounter) > 0);
		BUG_ON(ve->is_running);
		real_do_env_free(ve);
	}
}

static int ve_get_cpu_stat(envid_t veid, struct vz_cpu_stat __user *buf)
{
	struct ve_struct *ve;
	struct vz_cpu_stat *vstat;
	int retval;
	int i, cpu;
	unsigned long tmp;

	if (!ve_is_super(get_exec_env()) && (veid != get_exec_env()->veid))
		return -EPERM;
	if (veid == 0)
		return -ESRCH;

	vstat = kzalloc(sizeof(*vstat), GFP_KERNEL);
	if (!vstat)
		return -ENOMEM;
	
	retval = -ESRCH;
	read_lock(&ve_list_lock);
	ve = __find_ve_by_id(veid);
	if (ve == NULL)
		goto out_unlock;
	for_each_online_cpu(cpu) {
		struct ve_cpu_stats *st;

		st = VE_CPU_STATS(ve, cpu);
		vstat->user_jif += (unsigned long)cputime64_to_clock_t(st->user);
		vstat->nice_jif += (unsigned long)cputime64_to_clock_t(st->nice);
		vstat->system_jif += (unsigned long)cputime64_to_clock_t(st->system);
		vstat->idle_clk += ve_sched_get_idle_time(ve, cpu);
	}
	vstat->uptime_clk = get_cycles() - ve->start_cycles;
	vstat->uptime_jif = (unsigned long)cputime64_to_clock_t(
				get_jiffies_64() - ve->start_jiffies);
	for (i = 0; i < 3; i++) {
		tmp = ve->avenrun[i] + (FIXED_1/200);
		vstat->avenrun[i].val_int = LOAD_INT(tmp);
		vstat->avenrun[i].val_frac = LOAD_FRAC(tmp);
	}
	read_unlock(&ve_list_lock);

	retval = 0;
	if (copy_to_user(buf, vstat, sizeof(*vstat)))
		retval = -EFAULT;
out_free:
	kfree(vstat);
	return retval;

out_unlock:
	read_unlock(&ve_list_lock);
	goto out_free;
}

static int real_setdevperms(envid_t veid, unsigned type,
		dev_t dev, unsigned mask)
{
	struct ve_struct *ve;
	int err;

	if (!capable_setveid() || veid == 0)
		return -EPERM;

	if ((ve = get_ve_by_id(veid)) == NULL)
		return -ESRCH;

	down_read(&ve->op_sem);
	err = -ESRCH;
	if (ve->is_running)
		err = set_device_perms_ve(ve, type, dev, mask);
	up_read(&ve->op_sem);
	real_put_ve(ve);
	return err;
}

/**********************************************************************
 **********************************************************************
 *
 * VE start: subsystems
 *
 **********************************************************************
 **********************************************************************/

static int prepare_proc_root(struct ve_struct *ve)
{
	struct proc_dir_entry *de;

	de = kzalloc(sizeof(struct proc_dir_entry) + 6, GFP_KERNEL);
	if (de == NULL)
		return -ENOMEM;

	memcpy(de + 1, "/proc", 6);
	de->name = (char *)(de + 1);
	de->namelen = 5;
	de->mode = S_IFDIR | S_IRUGO | S_IXUGO;
	de->nlink = 2;
	atomic_set(&de->count, 1);

	ve->proc_root = de;
	return 0;
}

#ifdef CONFIG_PROC_FS
static int init_ve_proc(struct ve_struct *ve)
{
	int err;

	err = prepare_proc_root(ve);
	if (err)
		goto out_root;

	err = register_ve_fs_type(ve, &proc_fs_type,
			&ve->proc_fstype, &ve->proc_mnt);
	if (err)
		goto out_reg;

#ifdef CONFIG_PRINTK
	proc_create("kmsg", S_IRUSR, ve->proc_root, &proc_kmsg_operations);
#endif
	proc_mkdir("vz", ve->proc_root);

	ve->ve_ns->pid_ns->proc_mnt = mntget(ve->proc_mnt);
	return 0;

out_reg:
	/* proc_fstype and proc_root are freed in real_put_ve -> free_ve_proc */
	;
out_root:
	return err;
}

static void fini_ve_proc(struct ve_struct *ve)
{
	remove_proc_entry("vz", ve->proc_root);
	remove_proc_entry("kmsg", ve->proc_root);
	unregister_ve_fs_type(ve->proc_fstype, ve->proc_mnt);
	ve->proc_mnt = NULL;
}

static void free_ve_proc(struct ve_struct *ve)
{
	/* proc filesystem frees proc_dir_entries on remove_proc_entry() only,
	   so we check that everything was removed and not lost */
	if (ve->proc_root && ve->proc_root->subdir) {
		struct proc_dir_entry *p = ve->proc_root;
		printk(KERN_WARNING "CT: %d: proc entry /proc", ve->veid);
		while ((p = p->subdir) != NULL)
			printk("/%s", p->name);
		printk(" is not removed!\n");
	}

	kfree(ve->proc_root);
	kfree(ve->proc_fstype);

	ve->proc_fstype = NULL;
	ve->proc_root = NULL;
}
#else
#define init_ve_proc(ve)	(0)
#define fini_ve_proc(ve)	do { } while (0)
#define free_ve_proc(ve)	do { } while (0)
#endif

#ifdef CONFIG_UNIX98_PTYS
#include <linux/devpts_fs.h>

/*
 * DEVPTS needs a virtualization: each environment should see each own list of
 * pseudo-terminals.
 * To implement it we need to have separate devpts superblocks for each
 * VE, and each VE should mount its own one.
 * Thus, separate vfsmount structures are required.
 * To minimize intrusion into vfsmount lookup code, separate file_system_type
 * structures are created.
 *
 * In addition to this, patch fo character device itself is required, as file
 * system itself is used only for MINOR/MAJOR lookup.
 */

static int init_ve_devpts(struct ve_struct *ve)
{
	return register_ve_fs_type(ve, &devpts_fs_type,
			&ve->devpts_fstype, &ve->devpts_mnt);
}

static void fini_ve_devpts(struct ve_struct *ve)
{
	unregister_ve_fs_type(ve->devpts_fstype, ve->devpts_mnt);
}
#else
#define init_ve_devpts(ve)	(0)
#define fini_ve_devpts(ve)	do { } while (0)
#endif

static int init_ve_shmem(struct ve_struct *ve)
{
	return register_ve_fs_type(ve,
				   &tmpfs_fs_type,
				   &ve->shmem_fstype,
				   &ve->shmem_mnt);
}

static void fini_ve_shmem(struct ve_struct *ve)
{
	unregister_ve_fs_type(ve->shmem_fstype, ve->shmem_mnt);
	/* shmem_fstype is freed in real_put_ve -> free_ve_filesystems */
	ve->shmem_mnt = NULL;
}

#ifdef CONFIG_SYSFS
static int init_ve_sysfs_root(struct ve_struct *ve)
{
	struct sysfs_dirent *sysfs_root;

	sysfs_root = kzalloc(sizeof(struct sysfs_dirent), GFP_KERNEL);
	if (sysfs_root == NULL)
		return -ENOMEM;
	sysfs_root->s_name = "";
	atomic_set(&sysfs_root->s_count, 1);
	sysfs_root->s_flags = SYSFS_DIR;
	sysfs_root->s_mode = S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO;
	sysfs_root->s_ino = 1;

	ve->_sysfs_root = sysfs_root;
	return 0;
}
#endif

#if defined(CONFIG_NET) && defined(CONFIG_SYSFS)
extern struct device_attribute ve_net_class_attributes[];
static inline int init_ve_netclass(void)
{
	struct class *nc;
	int err;

	nc = kzalloc(sizeof(*nc), GFP_KERNEL);
	if (!nc)
		return -ENOMEM;

	nc->name = net_class.name;
	nc->dev_release = net_class.dev_release;
	nc->dev_uevent = net_class.dev_uevent;
	nc->dev_attrs = ve_net_class_attributes;

	err = class_register(nc);
	if (!err) {
		get_exec_env()->net_class = nc;
		return 0;
	}
	kfree(nc);	
	return err;
}

static inline void fini_ve_netclass(void)
{
	struct ve_struct *ve = get_exec_env();

	class_unregister(ve->net_class);
	kfree(ve->net_class);
	ve->net_class = NULL;
}
#else
static inline int init_ve_netclass(void) { return 0; }
static inline void fini_ve_netclass(void) { ; }
#endif

static const struct {
	unsigned	minor;
	char		*name;
} mem_class_devices [] = {
	{3, "null"},
	{5, "zero"},
	{7, "full"},
	{8, "random"},
	{9, "urandom"},
	{0, NULL},
};

static int init_ve_mem_class(void)
{
	int i;
	struct class *ve_mem_class;

	ve_mem_class = class_create(THIS_MODULE, "mem");
	if (IS_ERR(ve_mem_class))
		return -ENOMEM;

	for (i = 0; mem_class_devices[i].name; i++)
		device_create(ve_mem_class, NULL,
				MKDEV(MEM_MAJOR, mem_class_devices[i].minor),
				NULL, mem_class_devices[i].name);

	get_exec_env()->mem_class = ve_mem_class;
	return 0;
}


void fini_ve_mem_class(void)
{
	int i;
	struct class *ve_mem_class = get_exec_env()->mem_class;

	for (i = 0; mem_class_devices[i].name; i++)
		device_destroy(ve_mem_class,
				MKDEV(MEM_MAJOR, mem_class_devices[i].minor));
	class_destroy(ve_mem_class);
}

static int init_ve_sysfs(struct ve_struct *ve)
{
	int err;

#ifdef CONFIG_SYSFS
	err = 0;
	if (ve->features & VE_FEATURE_SYSFS) {
		err = init_ve_sysfs_root(ve);
		if (err != 0)
			goto out;
		err = register_ve_fs_type(ve,
				   &sysfs_fs_type,
				   &ve->sysfs_fstype,
				   &ve->sysfs_mnt);
		if (err != 0)
			goto out_fs_type;
	}
#endif

	err = classes_init();
	if (err != 0)
		goto err_classes;

	err = devices_init();
	if (err != 0)
		goto err_devices;

	err = init_ve_netclass();
	if (err != 0)
		goto err_net;

	err = init_ve_tty_class();
	if (err != 0)
		goto err_tty;

	err = init_ve_mem_class();
	if (err != 0)
		goto err_mem;

	return 0;

err_mem:
	fini_ve_tty_class();
err_tty:
	fini_ve_netclass();
err_net:
	devices_fini();
err_devices:
	classes_fini();
err_classes:
#ifdef CONFIG_SYSFS
	unregister_ve_fs_type(ve->sysfs_fstype, ve->sysfs_mnt);
	/* sysfs_fstype is freed in real_put_ve -> free_ve_filesystems */
out_fs_type:
	kfree(ve->_sysfs_root);
	ve->_sysfs_root = NULL;
out:
#endif
	return err;
}

static void fini_ve_sysfs(struct ve_struct *ve)
{
	fini_ve_mem_class();
	fini_ve_tty_class();
	fini_ve_netclass();
	devices_fini();
	classes_fini();
#ifdef CONFIG_SYSFS
	unregister_ve_fs_type(ve->sysfs_fstype, ve->sysfs_mnt);
	ve->sysfs_mnt = NULL;
	kfree(ve->_sysfs_root);
	ve->_sysfs_root = NULL;
	/* sysfs_fstype is freed in real_put_ve -> free_ve_filesystems */
#endif
}

static void free_ve_filesystems(struct ve_struct *ve)
{
#ifdef CONFIG_SYSFS
	kfree(ve->sysfs_fstype);
	ve->sysfs_fstype = NULL;
#endif
	kfree(ve->shmem_fstype);
	ve->shmem_fstype = NULL;

	kfree(ve->devpts_fstype);
	ve->devpts_fstype = NULL;

	free_ve_proc(ve);
}

static int init_printk(struct ve_struct *ve)
{
	struct ve_prep_printk {
		wait_queue_head_t       log_wait;
		unsigned		log_start;
		unsigned		log_end;
		unsigned		logged_chars;
	} *tmp;

	tmp = kzalloc(sizeof(struct ve_prep_printk), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	init_waitqueue_head(&tmp->log_wait);
	ve->_log_wait = &tmp->log_wait;
	ve->_log_start = &tmp->log_start;
	ve->_log_end = &tmp->log_end;
	ve->_logged_chars = &tmp->logged_chars;
	/* ve->log_buf will be initialized later by ve_log_init() */
	return 0;
}

static void fini_printk(struct ve_struct *ve)
{
	/* 
	 * there is no spinlock protection here because nobody can use
	 * log_buf at the moments when this code is called. 
	 */
	kfree(ve->log_buf);
	kfree(ve->_log_wait);
}

static void fini_venet(struct ve_struct *ve)
{
#ifdef CONFIG_INET
	tcp_v4_kill_ve_sockets(ve);
	synchronize_net();
#endif
}

static int init_ve_sched(struct ve_struct *ve)
{
	int err;

	err = fairsched_new_node(ve->veid, 0);
	if (err == 0)
		ve_sched_attach(ve);

	return err;
}

static void fini_ve_sched(struct ve_struct *ve)
{
	fairsched_drop_node(ve->veid);
}

/*
 * Namespaces
 */

static inline int init_ve_namespaces(struct ve_struct *ve,
		struct nsproxy **old)
{
	int err;
	struct task_struct *tsk;
	struct nsproxy *cur;

	tsk = current;
	cur = tsk->nsproxy;

	err = copy_namespaces(CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWPID,
			tsk, 1);
	if (err < 0)
		return err;

	ve->ve_ns = get_nsproxy(tsk->nsproxy);
	memcpy(ve->ve_ns->uts_ns->name.release, virt_utsname.release,
			sizeof(virt_utsname.release));

	if (cur->pid_ns->flags & PID_NS_HIDE_CHILD)
		ve->ve_ns->pid_ns->flags |= PID_NS_HIDDEN;

	*old = cur;
	return 0;
}

static inline void fini_ve_namespaces(struct ve_struct *ve,
		struct nsproxy *old)
{
	struct task_struct *tsk = current;
	struct nsproxy *tmp;

	if (old) {
		tmp = tsk->nsproxy;
		tsk->nsproxy = get_nsproxy(old);
		put_nsproxy(tmp);
		tmp = ve->ve_ns;
		ve->ve_ns = get_nsproxy(old);
		put_nsproxy(tmp);
	} else {
		put_user_ns(ve->user_ns);
		put_nsproxy(ve->ve_ns);
		ve->ve_ns = NULL;
	}
}

static int init_ve_netns(struct ve_struct *ve, struct nsproxy **old)
{
	int err;
	struct task_struct *tsk;
	struct nsproxy *cur;

	tsk = current;
	cur = tsk->nsproxy;

	err = copy_namespaces(CLONE_NEWNET, tsk, 1);
	if (err < 0)
		return err;

	put_nsproxy(ve->ve_ns);
	ve->ve_ns = get_nsproxy(tsk->nsproxy);
	ve->ve_netns = get_net(ve->ve_ns->net_ns);
	*old = cur;
	return 0;
}

static inline void switch_ve_namespaces(struct ve_struct *ve,
		struct task_struct *tsk)
{
	struct nsproxy *old_ns;
	struct nsproxy *new_ns;

	BUG_ON(tsk != current);
	old_ns = tsk->nsproxy;
	new_ns = ve->ve_ns;

	if (old_ns != new_ns) {
		tsk->nsproxy = get_nsproxy(new_ns);
		put_nsproxy(old_ns);
	}
}

static __u64 get_ve_features(env_create_param_t *data, int datalen)
{
	__u64 known_features;

	if (datalen < sizeof(struct env_create_param3))
		/* this version of vzctl is aware of VE_FEATURES_OLD only */
		known_features = VE_FEATURES_OLD;
	else
		known_features = data->known_features;

	/*
	 * known features are set as required
	 * yet unknown features are set as in VE_FEATURES_DEF
	 */
	return (data->feature_mask & known_features) |
		(VE_FEATURES_DEF & ~known_features);
}

static int init_ve_struct(struct ve_struct *ve, envid_t veid,
		u32 class_id, env_create_param_t *data, int datalen)
{
	(void)get_ve(ve);
	ve->veid = veid;
	ve->class_id = class_id;
	ve->features = get_ve_features(data, datalen);
	INIT_LIST_HEAD(&ve->vetask_lh);
	init_rwsem(&ve->op_sem);

	ve->start_timespec = current->start_time;
	/* The value is wrong, but it is never compared to process
	 * start times */
	ve->start_jiffies = get_jiffies_64();
	ve->start_cycles = get_cycles();

	ve->_randomize_va_space = ve0._randomize_va_space;
 
	return 0;
}

/**********************************************************************
 **********************************************************************
 *
 * /proc/meminfo virtualization
 *
 **********************************************************************
 **********************************************************************/
static int ve_set_meminfo(envid_t veid, unsigned long val)
{
#ifdef CONFIG_BEANCOUNTERS
	struct ve_struct *ve;

	ve = get_ve_by_id(veid);
	if (!ve)
		return -EINVAL;

	if (val == 0)
		val = VE_MEMINFO_SYSTEM;
	else if (val == 1)
		val = VE_MEMINFO_DEFAULT;

	ve->meminfo_val = val;
	real_put_ve(ve);
	return 0;
#else
	return -ENOTTY;
#endif
}

static int init_ve_meminfo(struct ve_struct *ve)
{
	ve->meminfo_val = VE_MEMINFO_DEFAULT;
	return 0;
}

static inline void fini_ve_meminfo(struct ve_struct *ve)
{
}

static void set_ve_root(struct ve_struct *ve, struct task_struct *tsk)
{
	read_lock(&tsk->fs->lock);
	ve->root_path = tsk->fs->root;
	read_unlock(&tsk->fs->lock);
	mark_tree_virtual(&ve->root_path);
}

static void set_ve_caps(struct ve_struct *ve, struct task_struct *tsk)
{
	/* required for real_setdevperms from register_ve_<fs> above */
	memcpy(&ve->ve_cap_bset, &tsk->cred->cap_effective, sizeof(kernel_cap_t));
}

static int ve_list_add(struct ve_struct *ve)
{
	write_lock_irq(&ve_list_lock);
	if (__find_ve_by_id(ve->veid) != NULL)
		goto err_exists;

	list_add(&ve->ve_list, &ve_list_head);
	nr_ve++;
	write_unlock_irq(&ve_list_lock);
	return 0;

err_exists:
	write_unlock_irq(&ve_list_lock);
	return -EEXIST;
}

static void ve_list_del(struct ve_struct *ve)
{
	write_lock_irq(&ve_list_lock);
	list_del(&ve->ve_list);
	nr_ve--;
	write_unlock_irq(&ve_list_lock);
}

static void set_task_ve_caps(struct ve_struct *ve, struct cred *new)
{
	const struct cred *cur;
	kernel_cap_t bset;

	bset = ve->ve_cap_bset;
	cur = current_cred();
	new->cap_effective = cap_intersect(cur->cap_effective, bset);
	new->cap_inheritable = cap_intersect(cur->cap_inheritable, bset);
	new->cap_permitted = cap_intersect(cur->cap_permitted, bset);
	new->cap_bset = cap_intersect(cur->cap_bset, bset);

	if (commit_creds(new))
		/* too late to rollback, but commit currently just works */
		BUG();
}

void ve_move_task(struct task_struct *tsk, struct ve_struct *new, struct cred *new_creds)
{
	struct ve_struct *old;

	might_sleep();
	BUG_ON(tsk != current);
	BUG_ON(!(thread_group_leader(tsk) && thread_group_empty(tsk)));

	/* this probihibts ptracing of task entered to VE from host system */
	if (tsk->mm)
		tsk->mm->vps_dumpable = 0;
	/* setup capabilities before enter */
	set_task_ve_caps(new, new_creds);

	/* Drop OOM protection. */
	if (tsk->signal->oom_adj == OOM_DISABLE)
		tsk->signal->oom_adj = 0;

	old = tsk->ve_task_info.owner_env;
	tsk->ve_task_info.owner_env = new;
	tsk->ve_task_info.exec_env = new;

	write_lock_irq(&tasklist_lock);
	list_del_rcu(&tsk->ve_task_info.vetask_list);
	write_unlock_irq(&tasklist_lock);

	synchronize_rcu();

	write_lock_irq(&tasklist_lock);
	list_add_tail_rcu(&tsk->ve_task_info.vetask_list,
			&new->vetask_lh);
	write_unlock_irq(&tasklist_lock);

	atomic_dec(&old->pcounter);
	real_put_ve(old);

	atomic_inc(&new->pcounter);
	get_ve(new);

	cgroup_set_task_css(tsk, new->ve_css_set);

	new->user_ns = get_user_ns(new_creds->user->user_ns);
}

EXPORT_SYMBOL(ve_move_task);

#ifdef CONFIG_VE_IPTABLES

static __u64 setup_iptables_mask(__u64 init_mask)
{
	/* Remove when userspace will start supplying IPv6-related bits. */
	init_mask &= ~VE_IP_IPTABLES6;
	init_mask &= ~VE_IP_FILTER6;
	init_mask &= ~VE_IP_MANGLE6;
	init_mask &= ~VE_IP_IPTABLE_NAT_MOD;
	init_mask &= ~VE_NF_CONNTRACK_MOD;

	if (mask_ipt_allow(init_mask, VE_IP_IPTABLES))
		init_mask |= VE_IP_IPTABLES6;
	if (mask_ipt_allow(init_mask, VE_IP_FILTER))
		init_mask |= VE_IP_FILTER6;
	if (mask_ipt_allow(init_mask, VE_IP_MANGLE))
		init_mask |= VE_IP_MANGLE6;
	if (mask_ipt_allow(init_mask, VE_IP_NAT))
		init_mask |= VE_IP_IPTABLE_NAT;
	if (mask_ipt_allow(init_mask, VE_IP_CONNTRACK))
		init_mask |= VE_NF_CONNTRACK;

	return init_mask;
}

#endif

static inline int init_ve_cpustats(struct ve_struct *ve)
{
	ve->cpu_stats = alloc_percpu(struct ve_cpu_stats);
	if (ve->cpu_stats == NULL)
		return -ENOMEM;
	ve->sched_lat_ve.cur = alloc_percpu(struct kstat_lat_pcpu_snap_struct);
	if (ve == NULL)
		goto fail;
	return 0;

fail:
	free_percpu(ve->cpu_stats);
	return -ENOMEM;
}

static inline void free_ve_cpustats(struct ve_struct *ve)
{
	free_percpu(ve->cpu_stats);
	ve->cpu_stats = NULL;
	free_percpu(ve->sched_lat_ve.cur);
	ve->sched_lat_ve.cur = NULL;
}

static int alone_in_pgrp(struct task_struct *tsk)
{
	struct task_struct *p;
	int alone = 0;

	read_lock(&tasklist_lock);
	do_each_pid_task(task_pid(tsk), PIDTYPE_PGID, p) {
		if (p != tsk)
			goto out;
	} while_each_pid_task(task_pid(tsk), PIDTYPE_PGID, p);
	do_each_pid_task(task_pid(tsk), PIDTYPE_SID, p) {
		if (p != tsk)
			goto out;
	} while_each_pid_task(task_pid(tsk), PIDTYPE_SID, p);
	alone = 1;
out:
	read_unlock(&tasklist_lock);
	return alone;
}

static int do_env_create(envid_t veid, unsigned int flags, u32 class_id,
			 env_create_param_t *data, int datalen)
{
	struct task_struct *tsk;
	struct cred *new_creds;
	struct ve_struct *old;
	struct ve_struct *old_exec;
	struct ve_struct *ve;
 	__u64 init_mask;
	int err;
	struct nsproxy *old_ns, *old_ns_net;
	DECLARE_COMPLETION_ONSTACK(sysfs_completion);

	tsk = current;
	old = VE_TASK_INFO(tsk)->owner_env;

	if (!thread_group_leader(tsk) || !thread_group_empty(tsk))
		return -EINVAL;

	if (tsk->signal->tty) {
		printk("ERR: CT init has controlling terminal\n");
		return -EINVAL;
	}
	if (task_pgrp(tsk) != task_pid(tsk) ||
			task_session(tsk) != task_pid(tsk)) {
		int may_setsid;

		read_lock(&tasklist_lock);
		may_setsid = !tsk->signal->leader &&
			!pid_task(find_pid_ns(task_pid_nr(tsk), &init_pid_ns), PIDTYPE_PGID);
		read_unlock(&tasklist_lock);

		if (!may_setsid) {
			printk("ERR: CT init is process group leader\n");
			return -EINVAL;
		}
	}
	/* Check that the process is not a leader of non-empty group/session.
	 * If it is, we cannot virtualize its PID and must fail. */
	if (!alone_in_pgrp(tsk)) {
		printk("ERR: CT init is not alone in process group\n");
		return -EINVAL;
	}


	VZTRACE("%s: veid=%d classid=%d pid=%d\n",
		__FUNCTION__, veid, class_id, current->pid);

	err = -ENOMEM;
	ve = kzalloc(sizeof(struct ve_struct), GFP_KERNEL);
	if (ve == NULL)
		goto err_struct;

	init_ve_struct(ve, veid, class_id, data, datalen);
	__module_get(THIS_MODULE);
	down_write(&ve->op_sem);
	if (flags & VE_LOCK)
		ve->is_locked = 1;

	/*
	 * this should be done before adding to list
	 * because if calc_load_ve finds this ve in
	 * list it will be very surprised
	 */
	if ((err = init_ve_cpustats(ve)) < 0)
		goto err_cpu_stats;

	if ((err = ve_list_add(ve)) < 0)
		goto err_exist;

	/* this should be done before context switching */
	if ((err = init_printk(ve)) < 0)
		goto err_log_wait;

	old_exec = set_exec_env(ve);

	if ((err = init_ve_sched(ve)) < 0)
		goto err_sched;

	set_ve_root(ve, tsk);

	if ((err = init_ve_sysfs(ve)))
		goto err_sysfs;

	if ((err = init_ve_namespaces(ve, &old_ns)))
		goto err_ns;

	if ((err = init_ve_proc(ve)))
		goto err_proc;


	init_mask = data ? data->iptables_mask : VE_IP_DEFAULT;

#ifdef CONFIG_VE_IPTABLES
	/* Set up ipt_mask as it will be used during
	 * net namespace initialization
	 */
	init_mask = setup_iptables_mask(init_mask);
	ve->ipt_mask = init_mask;
#endif

	if ((err = init_ve_netns(ve, &old_ns_net)))
		goto err_netns;

	if ((err = init_ve_cgroups(ve)))
		goto err_cgroup;

	if ((err = init_ve_tty_drivers(ve)) < 0)
		goto err_tty;

	if ((err = init_ve_shmem(ve)))
		goto err_shmem;

	if ((err = init_ve_devpts(ve)))
		goto err_devpts;

	if((err = init_ve_meminfo(ve)))
		goto err_meminf;

	set_ve_caps(ve, tsk);

	if ((err = pid_ns_attach_init(ve->ve_ns->pid_ns, tsk)) < 0)
		goto err_vpid;

	new_creds = prepare_creds();
	if (new_creds == NULL)
		goto err_creds;

	if ((err = create_user_ns(new_creds)) < 0)
		goto err_uns;

	if ((err = ve_hook_iterate_init(VE_SS_CHAIN, ve)) < 0)
		goto err_ve_hook;

	put_nsproxy(old_ns);
	put_nsproxy(old_ns_net);

	/* finally: set vpids and move inside */
	ve_move_task(tsk, ve, new_creds);

	ve->is_running = 1;
	up_write(&ve->op_sem);

	printk(KERN_INFO "CT: %d: started\n", veid);
	return veid;

err_ve_hook:
	/* creds will put user and user ns */
err_uns:
	abort_creds(new_creds);
err_creds:
	mntget(ve->proc_mnt);
err_vpid:
	fini_venet(ve);
	fini_ve_meminfo(ve);
err_meminf:
	fini_ve_devpts(ve);
err_devpts:
	fini_ve_shmem(ve);
err_shmem:
	fini_ve_tty_drivers(ve);
err_tty:
	fini_ve_cgroups(ve);
err_cgroup:
	fini_ve_namespaces(ve, old_ns_net);
	put_nsproxy(old_ns_net);
	ve->ve_netns->sysfs_completion = &sysfs_completion;
	put_net(ve->ve_netns);
	wait_for_completion(&sysfs_completion);
err_netns:
	/*
	 * If process hasn't become VE's init, proc_mnt won't be put during
	 * pidns death, so this mntput by hand is needed. If it has, we
	 * compensate with mntget above.
	 */
	mntput(ve->proc_mnt);
	fini_ve_proc(ve);
err_proc:
	/* free_ve_utsname() is called inside real_put_ve() */
	fini_ve_namespaces(ve, old_ns);
	put_nsproxy(old_ns);
	/*
	 * We need to compensate, because fini_ve_namespaces() assumes
	 * ve->ve_ns will continue to be used after, but VE will be freed soon
	 * (in kfree() sense).
	 */
	put_nsproxy(ve->ve_ns);
err_ns:
	fini_ve_sysfs(ve);
err_sysfs:
	/* It is safe to restore current->envid here because
	 * ve_fairsched_detach does not use current->envid. */
	/* Really fairsched code uses current->envid in sys_fairsched_mknod 
	 * only.  It is correct if sys_fairsched_mknod is called from
	 * userspace.  If sys_fairsched_mknod is called from
	 * ve_fairsched_attach, then node->envid and node->parent_node->envid
	 * are explicitly set to valid value after the call. */
	/* FIXME */
	VE_TASK_INFO(tsk)->owner_env = old;
	VE_TASK_INFO(tsk)->exec_env = old_exec;

	fini_ve_sched(ve);
err_sched:
	(void)set_exec_env(old_exec);

	/* we can jump here having incorrect envid */
	VE_TASK_INFO(tsk)->owner_env = old;
	fini_printk(ve);
err_log_wait:
	/* cpustats will be freed in do_env_free */
	ve_list_del(ve);
	up_write(&ve->op_sem);

	real_put_ve(ve);
err_struct:
	printk(KERN_INFO "CT: %d: failed to start with err=%d\n", veid, err);
	return err;

err_exist:
	free_ve_cpustats(ve);
err_cpu_stats:
	kfree(ve);
	module_put(THIS_MODULE);
	goto err_struct;
}


/**********************************************************************
 **********************************************************************
 *
 * VE start/stop callbacks
 *
 **********************************************************************
 **********************************************************************/

int real_env_create(envid_t veid, unsigned flags, u32 class_id,
			env_create_param_t *data, int datalen)
{
	int status;
	struct ve_struct *ve;

	if (!flags) {
		status = get_exec_env()->veid;
		goto out;
	}

	status = -EPERM;
	if (!capable_setveid())
		goto out;

	status = -EINVAL;
	if ((flags & VE_TEST) && (flags & (VE_ENTER|VE_CREATE)))
		goto out;

	status = -EINVAL;
	ve = get_ve_by_id(veid);
	if (ve) {
		if (flags & VE_TEST) {
			status = 0;
			goto out_put;
		}
		if (flags & VE_EXCLUSIVE) {
			status = -EACCES;
			goto out_put;
		}
		if (flags & VE_CREATE) {
			flags &= ~VE_CREATE;
			flags |= VE_ENTER;
		}
	} else {
		if (flags & (VE_TEST|VE_ENTER)) {
			status = -ESRCH;
			goto out;
		}
	}

	if (flags & VE_CREATE) {
		status = do_env_create(veid, flags, class_id, data, datalen);
		goto out;
	} else if (flags & VE_ENTER)
		status = do_env_enter(ve, flags);

	/* else: returning EINVAL */

out_put:
	real_put_ve(ve);
out:
	return status;
}
EXPORT_SYMBOL(real_env_create);

static int do_env_enter(struct ve_struct *ve, unsigned int flags)
{
	struct task_struct *tsk = current;
	struct cred *new_creds;
	int err;

	VZTRACE("%s: veid=%d\n", __FUNCTION__, ve->veid);

	err = -EBUSY;
	down_read(&ve->op_sem);
	if (!ve->is_running)
		goto out_up;
	if (ve->is_locked && !(flags & VE_SKIPLOCK))
		goto out_up;
	err = -EINVAL;
	if (!thread_group_leader(tsk) || !thread_group_empty(tsk))
		goto out_up;

	new_creds = prepare_creds();
	if (new_creds == NULL)
		goto out_up;

#ifdef CONFIG_VZ_FAIRSCHED
	err = sys_fairsched_mvpr(task_pid_vnr(current), ve->veid);
	if (err) {
		abort_creds(new_creds);
		goto out_up;
	}
#endif
	ve_sched_attach(ve);
	switch_ve_namespaces(ve, tsk);
	ve_move_task(current, ve, new_creds);

	/* Check that the process is not a leader of non-empty group/session.
	 * If it is, we cannot virtualize its PID. Do not fail, just leave
	 * it non-virtual.
	 */
	if (alone_in_pgrp(tsk) && !(flags & VE_SKIPLOCK))
		pid_ns_attach_task(ve->ve_ns->pid_ns, tsk);

	/* Unlike VE_CREATE, we do not setsid() in VE_ENTER.
	 * Process is allowed to be in an external group/session.
	 * If user space callers wants, it will do setsid() after
	 * VE_ENTER.
	 */
	err = VE_TASK_INFO(tsk)->owner_env->veid;
	tsk->did_ve_enter = 1;

out_up:
	up_read(&ve->op_sem);
	return err;
}

static void env_cleanup(struct ve_struct *ve)
{
	struct ve_struct *old_ve;
	DECLARE_COMPLETION_ONSTACK(sysfs_completion);

	VZTRACE("real_do_env_cleanup\n");

	down_read(&ve->op_sem);
	old_ve = set_exec_env(ve);

	ve_hook_iterate_fini(VE_SS_CHAIN, ve);

	fini_venet(ve);

	/* no new packets in flight beyond this point */

	fini_ve_sched(ve);

	fini_ve_devpts(ve);
	fini_ve_shmem(ve);
	unregister_ve_tty_drivers(ve);
	fini_ve_meminfo(ve);

	fini_ve_cgroups(ve);

	fini_ve_namespaces(ve, NULL);
	ve->ve_netns->sysfs_completion = &sysfs_completion;
	put_net(ve->ve_netns);
	wait_for_completion(&sysfs_completion);
	fini_ve_proc(ve);
	fini_ve_sysfs(ve);

	(void)set_exec_env(old_ve);
	fini_printk(ve);	/* no printk can happen in ve context anymore */

	ve_list_del(ve);
	up_read(&ve->op_sem);

	real_put_ve(ve);
}

static DECLARE_COMPLETION(vzmond_complete);
static int vzmond_helper(void *arg)
{
	char name[18];
	struct ve_struct *ve;

	ve = (struct ve_struct *)arg;
	snprintf(name, sizeof(name), "vzmond/%d", ve->veid);
	daemonize(name);
	env_cleanup(ve);
	module_put_and_exit(0);
}

static void do_pending_env_cleanups(void)
{
	int err;
	struct ve_struct *ve;

	spin_lock(&ve_cleanup_lock);
	while (1) {
		if (list_empty(&ve_cleanup_list) || need_resched())
			break;

		ve = list_first_entry(&ve_cleanup_list,
				struct ve_struct, cleanup_list);
		list_del(&ve->cleanup_list);
		spin_unlock(&ve_cleanup_lock);

		__module_get(THIS_MODULE);
		err = kernel_thread(vzmond_helper, (void *)ve, 0);
		if (err < 0) {
			env_cleanup(ve);
			module_put(THIS_MODULE);
		}

		spin_lock(&ve_cleanup_lock);
	}
	spin_unlock(&ve_cleanup_lock);
}

static inline int have_pending_cleanups(void)
{
	return !list_empty(&ve_cleanup_list);
}

static int vzmond(void *arg)
{
	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop() || have_pending_cleanups()) {
		schedule();
		try_to_freeze();
		if (signal_pending(current))
			flush_signals(current);

		do_pending_env_cleanups();
		set_current_state(TASK_INTERRUPTIBLE);
		if (have_pending_cleanups())
			__set_current_state(TASK_RUNNING);
	}

	__set_task_state(current, TASK_RUNNING);
	complete_and_exit(&vzmond_complete, 0);
}

static int __init init_vzmond(void)
{
	ve_cleanup_thread = kthread_run(vzmond, NULL, "vzmond");
	if (IS_ERR(ve_cleanup_thread))
		return PTR_ERR(ve_cleanup_thread);
	else
		return 0;
}

static void fini_vzmond(void)
{
	kthread_stop(ve_cleanup_thread);
	WARN_ON(!list_empty(&ve_cleanup_list));
}

static void real_do_env_free(struct ve_struct *ve)
{
	VZTRACE("real_do_env_free\n");

	free_ve_tty_drivers(ve);
	free_ve_filesystems(ve);
	free_ve_cpustats(ve);
	printk(KERN_INFO "CT: %d: stopped\n", VEID(ve));
	kfree(ve);

	module_put(THIS_MODULE);
}

/**********************************************************************
 **********************************************************************
 *
 * VE TTY handling
 *
 **********************************************************************
 **********************************************************************/

static struct tty_driver *alloc_ve_tty_driver(struct tty_driver *base,
					   struct ve_struct *ve)
{
	size_t size;
	struct tty_driver *driver;

	/* FIXME: make it a normal way (or wait till ms version) */

	driver = kmalloc(sizeof(struct tty_driver), GFP_KERNEL_UBC);
	if (!driver)
		goto out;

	memcpy(driver, base, sizeof(struct tty_driver));

	driver->driver_state = NULL;

	size = base->num * 3 * sizeof(void *);
	if (!(driver->flags & TTY_DRIVER_DEVPTS_MEM)) {
		void **p;
		p = kzalloc(size, GFP_KERNEL_UBC);
		if (!p)
			goto out_free;

		driver->ttys = (struct tty_struct **)p;
		driver->termios = (struct ktermios **)(p + driver->num);
		driver->termios_locked = (struct ktermios **)
			(p + driver->num * 2);
	} else {
		driver->ttys = NULL;
		driver->termios = NULL;
		driver->termios_locked = NULL;
	}

	driver->owner_env = ve;
	driver->flags |= TTY_DRIVER_INSTALLED;
	kref_init(&driver->kref);

	return driver;

out_free:
	kfree(driver);
out:
	return NULL;
}

static void free_ve_tty_driver(struct tty_driver *driver)
{
	if (!driver)
		return;

	clear_termios(driver);
	kfree(driver->ttys);
	kfree(driver);
}

static int alloc_ve_tty_drivers(struct ve_struct* ve)
{
#ifdef CONFIG_LEGACY_PTYS
	/* Traditional BSD devices */
	ve->pty_driver = alloc_ve_tty_driver(pty_driver, ve);
	if (!ve->pty_driver)
		goto out_mem;

	ve->pty_slave_driver = alloc_ve_tty_driver(pty_slave_driver, ve);
	if (!ve->pty_slave_driver)
		goto out_mem;

	ve->pty_driver->other       = ve->pty_slave_driver;
	ve->pty_slave_driver->other = ve->pty_driver;
#endif	

#ifdef CONFIG_UNIX98_PTYS
	ve->ptm_driver = alloc_ve_tty_driver(ptm_driver, ve);
	if (!ve->ptm_driver)
		goto out_mem;

	ve->pts_driver = alloc_ve_tty_driver(pts_driver, ve);
	if (!ve->pts_driver)
		goto out_mem;

	ve->ptm_driver->other = ve->pts_driver;
	ve->pts_driver->other = ve->ptm_driver;

	ve->allocated_ptys = kmalloc(sizeof(*ve->allocated_ptys),
			GFP_KERNEL_UBC);
	if (!ve->allocated_ptys)
		goto out_mem;
	ida_init(ve->allocated_ptys);
#endif
	return 0;

out_mem:
	free_ve_tty_drivers(ve);
	return -ENOMEM;
}

static void free_ve_tty_drivers(struct ve_struct* ve)
{
#ifdef CONFIG_LEGACY_PTYS
	free_ve_tty_driver(ve->pty_driver);
	free_ve_tty_driver(ve->pty_slave_driver);
	ve->pty_driver = ve->pty_slave_driver = NULL;
#endif	
#ifdef CONFIG_UNIX98_PTYS
	free_ve_tty_driver(ve->ptm_driver);
	free_ve_tty_driver(ve->pts_driver);
	if (ve->allocated_ptys)
		ida_destroy(ve->allocated_ptys);
	kfree(ve->allocated_ptys);
	ve->ptm_driver = ve->pts_driver = NULL;
	ve->allocated_ptys = NULL;
#endif
}

static inline void __register_tty_driver(struct tty_driver *driver)
{
	list_add(&driver->tty_drivers, &tty_drivers);
}

static inline void __unregister_tty_driver(struct tty_driver *driver)
{
	if (!driver)
		return;
	list_del(&driver->tty_drivers);
}

static int register_ve_tty_drivers(struct ve_struct* ve)
{
	mutex_lock(&tty_mutex);
#ifdef CONFIG_UNIX98_PTYS
	__register_tty_driver(ve->ptm_driver);
	__register_tty_driver(ve->pts_driver);
#endif
#ifdef CONFIG_LEGACY_PTYS
	__register_tty_driver(ve->pty_driver);
	__register_tty_driver(ve->pty_slave_driver);
#endif	
	mutex_unlock(&tty_mutex);

	return 0;
}

static void unregister_ve_tty_drivers(struct ve_struct* ve)
{
	VZTRACE("unregister_ve_tty_drivers\n");

	mutex_lock(&tty_mutex);
#ifdef CONFIG_LEGACY_PTYS
	__unregister_tty_driver(ve->pty_driver);
	__unregister_tty_driver(ve->pty_slave_driver);
#endif
#ifdef CONFIG_UNIX98_PTYS
	__unregister_tty_driver(ve->ptm_driver);
	__unregister_tty_driver(ve->pts_driver);
#endif
	mutex_unlock(&tty_mutex);
}

static int init_ve_tty_drivers(struct ve_struct *ve)
{
	int err;

	if ((err = alloc_ve_tty_drivers(ve)))
		goto err_ttyalloc;
	if ((err = register_ve_tty_drivers(ve)))
		goto err_ttyreg;
	return 0;

err_ttyreg:
	free_ve_tty_drivers(ve);
err_ttyalloc:
	return err;
}

static void fini_ve_tty_drivers(struct ve_struct *ve)
{
	unregister_ve_tty_drivers(ve);
	free_ve_tty_drivers(ve);
}

/*
 * Free the termios and termios_locked structures because
 * we don't want to get memory leaks when modular tty
 * drivers are removed from the kernel.
 */
static void clear_termios(struct tty_driver *driver)
{
	int i;
	struct ktermios *tp;

	if (driver->termios == NULL)
		return;
	for (i = 0; i < driver->num; i++) {
		tp = driver->termios[i];
		if (tp) {
			driver->termios[i] = NULL;
			kfree(tp);
		}
		tp = driver->termios_locked[i];
		if (tp) {
			driver->termios_locked[i] = NULL;
			kfree(tp);
		}
	}
}


/**********************************************************************
 **********************************************************************
 *
 * Pieces of VE network
 *
 **********************************************************************
 **********************************************************************/

#ifdef CONFIG_NET
#include <asm/uaccess.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/route.h>
#include <net/ip_fib.h>
#endif

static int ve_dev_add(envid_t veid, char *dev_name)
{
	struct net_device *dev;
	struct ve_struct *dst_ve;
	struct net *dst_net;
	int err = -ESRCH;

	dst_ve = get_ve_by_id(veid);
	if (dst_ve == NULL)
		goto out;

	dst_net = dst_ve->ve_netns;

	rtnl_lock();
	read_lock(&dev_base_lock);
	dev = __dev_get_by_name(&init_net, dev_name);
	read_unlock(&dev_base_lock);
	if (dev == NULL)
		goto out_unlock;

	err = __dev_change_net_namespace(dev, dst_net, dev_name, get_exec_ub());
out_unlock:
	rtnl_unlock();
	real_put_ve(dst_ve);

	if (dev == NULL)
		printk(KERN_WARNING "%s: device %s not found\n",
			__func__, dev_name);
out:
	return err;
}

static int ve_dev_del(envid_t veid, char *dev_name)
{
	struct net_device *dev;
	struct ve_struct *src_ve;
	struct net *src_net;
	int err = -ESRCH;

	src_ve = get_ve_by_id(veid);
	if (src_ve == NULL)
		goto out;

	src_net = src_ve->ve_netns;

	rtnl_lock();

	read_lock(&dev_base_lock);
	dev = __dev_get_by_name(src_net, dev_name);
	read_unlock(&dev_base_lock);
	if (dev == NULL)
		goto out_unlock;

	err = __dev_change_net_namespace(dev, &init_net, dev_name,
					 netdev_bc(dev)->owner_ub);
out_unlock:
	rtnl_unlock();
	real_put_ve(src_ve);

	if (dev == NULL)
		printk(KERN_WARNING "%s: device %s not found\n",
			__func__, dev_name);
out:
	return err;
}

int real_ve_dev_map(envid_t veid, int op, char *dev_name)
{
	if (!capable_setveid())
		return -EPERM;
	switch (op) {
	case VE_NETDEV_ADD:
		return ve_dev_add(veid, dev_name);
	case VE_NETDEV_DEL:
		return ve_dev_del(veid, dev_name);
	default:
		return -EINVAL;
	}
}

/**********************************************************************
 **********************************************************************
 *
 * VE information via /proc
 *
 **********************************************************************
 **********************************************************************/
#ifdef CONFIG_PROC_FS
#if BITS_PER_LONG == 32
#define VESTAT_LINE_WIDTH (6 * 11 + 6 * 21)
#define VESTAT_LINE_FMT "%10u %10lu %10lu %10lu %10Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %10lu\n"
#define VESTAT_HEAD_FMT "%10s %10s %10s %10s %10s %20s %20s %20s %20s %20s %20s %10s\n"
#else
#define VESTAT_LINE_WIDTH (12 * 21)
#define VESTAT_LINE_FMT "%20u %20lu %20lu %20lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20Lu %20lu\n"
#define VESTAT_HEAD_FMT "%20s %20s %20s %20s %20s %20s %20s %20s %20s %20s %20s %20s\n"
#endif

static int vestat_seq_show(struct seq_file *m, void *v)
{
	struct list_head *entry;
	struct ve_struct *ve;
	struct ve_struct *curve;
	int cpu;
	unsigned long user_ve, nice_ve, system_ve;
	unsigned long long uptime;
	cycles_t uptime_cycles, idle_time, strv_time, used;

	entry = (struct list_head *)v;
	ve = list_entry(entry, struct ve_struct, ve_list);

	curve = get_exec_env();
	if (entry == ve_list_head.next ||
	    (!ve_is_super(curve) && ve == curve)) {
		/* print header */
		seq_printf(m, "%-*s\n",
			VESTAT_LINE_WIDTH - 1,
			"Version: 2.2");
		seq_printf(m, VESTAT_HEAD_FMT, "VEID",
					"user", "nice", "system",
					"uptime", "idle",
					"strv", "uptime", "used",
					"maxlat", "totlat", "numsched");
	}

	if (ve == get_ve0())
		return 0;

	user_ve = nice_ve = system_ve = 0;
	idle_time = strv_time = used = 0;

	for_each_online_cpu(cpu) {
		struct ve_cpu_stats *st;

		st = VE_CPU_STATS(ve, cpu);
		user_ve += st->user;
		nice_ve += st->nice;
		system_ve += st->system;
		used += st->used_time;
		idle_time += ve_sched_get_idle_time(ve, cpu);
	}
	uptime_cycles = get_cycles() - ve->start_cycles;
	uptime = get_jiffies_64() - ve->start_jiffies;

	seq_printf(m, VESTAT_LINE_FMT, ve->veid,
				user_ve, nice_ve, system_ve,
				(unsigned long long)uptime,
				(unsigned long long)idle_time, 
				(unsigned long long)strv_time,
				(unsigned long long)uptime_cycles,
				(unsigned long long)used,
				(unsigned long long)ve->sched_lat_ve.last.maxlat,
				(unsigned long long)ve->sched_lat_ve.last.totlat,
				ve->sched_lat_ve.last.count);
	return 0;
}

void *ve_seq_start(struct seq_file *m, loff_t *pos)
{
	struct ve_struct *curve;

	curve = get_exec_env();
	read_lock(&ve_list_lock);
	if (!ve_is_super(curve)) {
		if (*pos != 0)
			return NULL;
		return curve;
	}

	return seq_list_start(&ve_list_head, *pos);
}
EXPORT_SYMBOL(ve_seq_start);

void *ve_seq_next(struct seq_file *m, void *v, loff_t *pos)
{
	if (!ve_is_super(get_exec_env()))
		return NULL;
	else
		return seq_list_next(v, &ve_list_head, pos);
}
EXPORT_SYMBOL(ve_seq_next);

void ve_seq_stop(struct seq_file *m, void *v)
{
	read_unlock(&ve_list_lock);
}
EXPORT_SYMBOL(ve_seq_stop);

static struct seq_operations vestat_seq_op = {
        .start	= ve_seq_start,
        .next	= ve_seq_next,
        .stop	= ve_seq_stop,
        .show	= vestat_seq_show
};

static int vestat_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &vestat_seq_op);
}

static struct file_operations proc_vestat_operations = {
        .open	 = vestat_open,
        .read	 = seq_read,
        .llseek	 = seq_lseek,
        .release = seq_release
};

static struct seq_operations devperms_seq_op = {
	.start  = ve_seq_start,
	.next   = ve_seq_next,
	.stop   = ve_seq_stop,
	.show   = devperms_seq_show,
};

static int devperms_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &devperms_seq_op);
}

static struct file_operations proc_devperms_ops = {
	.open           = devperms_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

static int vz_version_show(struct seq_file *file, void* v)
{
	static const char ver[] = VZVERSION "\n";

	return seq_puts(file, ver);
}

static int vz_version_open(struct inode *inode, struct file *file)
{
	return single_open(file, vz_version_show, NULL);
}

static struct file_operations proc_vz_version_oparations = {
	.open    = vz_version_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static inline unsigned long ve_used_mem(struct user_beancounter *ub)
{
	extern int glob_ve_meminfo;
	return glob_ve_meminfo ? ub->ub_parms[UB_OOMGUARPAGES].held :
				 ub->ub_parms[UB_PRIVVMPAGES].held ;
}

static void ve_swapinfo(struct sysinfo *val, struct user_beancounter *ub)
{
	unsigned long size, used;

	size = ub->ub_parms[UB_SWAPPAGES].limit;
	used = ub->ub_parms[UB_SWAPPAGES].held;

	if (size == UB_MAXVALUE)
		size = 0;

	val->totalswap = size;
	val->freeswap = size > used ? size - used : 0;
}

static inline int ve_mi_replace(struct meminfo *mi, int old_ret)
{
#ifdef CONFIG_BEANCOUNTERS
	struct user_beancounter *ub;
	unsigned long meminfo_val;
	unsigned long nodettram;
	unsigned long usedmem;

	meminfo_val = get_exec_env()->meminfo_val;
	if (meminfo_val == VE_MEMINFO_DEFAULT)
		return old_ret; /* Default behaviour */

	if (meminfo_val == VE_MEMINFO_SYSTEM)
		return NOTIFY_DONE | NOTIFY_STOP_MASK; /* No virtualization */

	nodettram = mi->si.totalram;
	ub = top_beancounter(current->mm->mm_ub);
	usedmem = ve_used_mem(ub);

	memset(mi, 0, sizeof(*mi));

	mi->si.totalram = (meminfo_val > nodettram) ?
			nodettram : meminfo_val;
	mi->si.freeram = (mi->si.totalram > usedmem) ?
			(mi->si.totalram - usedmem) : 0;

	ve_swapinfo(&mi->si, ub);

	return NOTIFY_OK | NOTIFY_STOP_MASK;
#else
	return NOTIFY_DONE;
#endif
}

static int meminfo_call(struct vnotifier_block *self,
                unsigned long event, void *arg, int old_ret)
{
	if (event != VIRTINFO_MEMINFO)
		return old_ret;

	return ve_mi_replace((struct meminfo *)arg, old_ret);
}


static struct vnotifier_block meminfo_notifier_block = {
	.notifier_call = meminfo_call
};

/* /proc/vz/veinfo */

static ve_seq_print_t veaddr_seq_print_cb;

void vzmon_register_veaddr_print_cb(ve_seq_print_t cb)
{
	rcu_assign_pointer(veaddr_seq_print_cb, cb);
}
EXPORT_SYMBOL(vzmon_register_veaddr_print_cb);

void vzmon_unregister_veaddr_print_cb(ve_seq_print_t cb)
{
	rcu_assign_pointer(veaddr_seq_print_cb, NULL);
	synchronize_rcu();
}
EXPORT_SYMBOL(vzmon_unregister_veaddr_print_cb);

static int veinfo_seq_show(struct seq_file *m, void *v)
{
	struct ve_struct *ve;
	ve_seq_print_t veaddr_seq_print;

	ve = list_entry((struct list_head *)v, struct ve_struct, ve_list);

	seq_printf(m, "%10u %5u %5u", ve->veid,
			ve->class_id, atomic_read(&ve->pcounter));

	rcu_read_lock();
	veaddr_seq_print = rcu_dereference(veaddr_seq_print_cb);
	if (veaddr_seq_print)
		veaddr_seq_print(m, ve);
	rcu_read_unlock();

	seq_putc(m, '\n');
	return 0;
}

static struct seq_operations veinfo_seq_op = {
	.start	= ve_seq_start,
	.next	=  ve_seq_next,
	.stop	=  ve_seq_stop,
	.show	=  veinfo_seq_show,
};

static int veinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &veinfo_seq_op);
}

static struct file_operations proc_veinfo_operations = {
	.open		= veinfo_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init init_vecalls_proc(void)
{
	struct proc_dir_entry *de;

	de = proc_create("vestat", S_IFREG | S_IRUSR, proc_vz_dir,
			&proc_vestat_operations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make vestat proc entry\n");

	de = proc_create("devperms", S_IFREG | S_IRUSR, proc_vz_dir,
			&proc_devperms_ops);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make devperms proc entry\n");

	de = proc_create("version", S_IFREG | S_IRUGO, proc_vz_dir,
			&proc_vz_version_oparations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make version proc entry\n");

	de = proc_create("veinfo", S_IFREG | S_IRUSR, proc_vz_dir,
			&proc_veinfo_operations);
	if (!de)
		printk(KERN_WARNING "VZMON: can't make veinfo proc entry\n");

	virtinfo_notifier_register(VITYPE_GENERAL, &meminfo_notifier_block);
	return 0;
}

static void fini_vecalls_proc(void)
{
	remove_proc_entry("version", proc_vz_dir);
	remove_proc_entry("devperms", proc_vz_dir);
	remove_proc_entry("vestat", proc_vz_dir);
	remove_proc_entry("veinfo", proc_vz_dir);
	virtinfo_notifier_unregister(VITYPE_GENERAL, &meminfo_notifier_block);
}
#else
#define init_vecalls_proc()	(0)
#define fini_vecalls_proc()	do { } while (0)
#endif /* CONFIG_PROC_FS */


/**********************************************************************
 **********************************************************************
 *
 * User ctl
 *
 **********************************************************************
 **********************************************************************/

int vzcalls_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;

	err = -ENOTTY;
	switch(cmd) {
	    case VZCTL_MARK_ENV_TO_DOWN: {
		        /* Compatibility issue */
		        err = 0;
		}
		break;
	    case VZCTL_SETDEVPERMS: {
			/* Device type was mistakenly declared as dev_t
			 * in the old user-kernel interface.
			 * That's wrong, dev_t is a kernel internal type.
			 * I use `unsigned' not having anything better in mind.
			 * 2001/08/11  SAW  */
			struct vzctl_setdevperms s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = real_setdevperms(s.veid, s.type,
					new_decode_dev(s.dev), s.mask);
		}
		break;
#ifdef CONFIG_INET
	    case VZCTL_VE_NETDEV: {
			struct vzctl_ve_netdev d;
			char *s;
			err = -EFAULT;
			if (copy_from_user(&d, (void __user *)arg, sizeof(d)))
				break;
			err = -ENOMEM;
			s = kmalloc(IFNAMSIZ+1, GFP_KERNEL);
			if (s == NULL)
				break;
			err = -EFAULT;
			if (strncpy_from_user(s, d.dev_name, IFNAMSIZ) > 0) {
				s[IFNAMSIZ] = 0;
				err = real_ve_dev_map(d.veid, d.op, s);
			}
			kfree(s);
		}
		break;
#endif
	    case VZCTL_ENV_CREATE: {
			struct vzctl_env_create s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = real_env_create(s.veid, s.flags, s.class_id,
				NULL, 0);
		}
		break;
	    case VZCTL_ENV_CREATE_DATA: {
			struct vzctl_env_create_data s;
			env_create_param_t *data;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err=-EINVAL;
			if (s.datalen < VZCTL_ENV_CREATE_DATA_MINLEN ||
			    s.datalen > VZCTL_ENV_CREATE_DATA_MAXLEN ||
			    s.data == 0)
				break;
			err = -ENOMEM;
			data = kzalloc(sizeof(*data), GFP_KERNEL);
			if (!data)
				break;

			err = -EFAULT;
			if (copy_from_user(data, (void __user *)s.data,
						s.datalen))
				goto free_data;
			err = real_env_create(s.veid, s.flags, s.class_id,
				data, s.datalen);
free_data:
			kfree(data);
		}
		break;
	    case VZCTL_GET_CPU_STAT: {
			struct vzctl_cpustatctl s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = ve_get_cpu_stat(s.veid, s.cpustat);
		}
		break;
	    case VZCTL_VE_MEMINFO: {
			struct vzctl_ve_meminfo s;
			err = -EFAULT;
			if (copy_from_user(&s, (void __user *)arg, sizeof(s)))
				break;
			err = ve_set_meminfo(s.veid, s.val);
		}
		break;
	}
	return err;
}

#ifdef CONFIG_COMPAT
int compat_vzcalls_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{
	int err;

	switch(cmd) {
	case VZCTL_GET_CPU_STAT: {
		/* FIXME */
	}
	case VZCTL_COMPAT_ENV_CREATE_DATA: {
		struct compat_vzctl_env_create_data cs;
		struct vzctl_env_create_data __user *s;

		s = compat_alloc_user_space(sizeof(*s));
		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;

		if (put_user(cs.veid, &s->veid) ||
		    put_user(cs.flags, &s->flags) ||
		    put_user(cs.class_id, &s->class_id) ||
		    put_user(compat_ptr(cs.data), &s->data) ||
		    put_user(cs.datalen, &s->datalen))
			break;
		err = vzcalls_ioctl(file, VZCTL_ENV_CREATE_DATA,
						(unsigned long)s);
		break;
	}
#ifdef CONFIG_NET
	case VZCTL_COMPAT_VE_NETDEV: {
		struct compat_vzctl_ve_netdev cs;
		struct vzctl_ve_netdev __user *s;

		s = compat_alloc_user_space(sizeof(*s));
		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;

		if (put_user(cs.veid, &s->veid) ||
		    put_user(cs.op, &s->op) ||
		    put_user(compat_ptr(cs.dev_name), &s->dev_name))
			break;
		err = vzcalls_ioctl(file, VZCTL_VE_NETDEV, (unsigned long)s);
		break;
	}
#endif
	case VZCTL_COMPAT_VE_MEMINFO: {
		struct compat_vzctl_ve_meminfo cs;
		err = -EFAULT;
		if (copy_from_user(&cs, (void *)arg, sizeof(cs)))
			break;
		err = ve_set_meminfo(cs.veid, cs.val);
		break;
	}
	default:
		err = vzcalls_ioctl(file, cmd, arg);
		break;
	}
	return err;
}
#endif

static struct vzioctlinfo vzcalls = {
	.type		= VZCTLTYPE,
	.ioctl		= vzcalls_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= compat_vzcalls_ioctl,
#endif
	.owner		= THIS_MODULE,
};


/**********************************************************************
 **********************************************************************
 *
 * Init/exit stuff
 *
 **********************************************************************
 **********************************************************************/

static inline __init int init_vecalls_ioctls(void)
{
	vzioctl_register(&vzcalls);
	return 0;
}

static inline void fini_vecalls_ioctls(void)
{
	vzioctl_unregister(&vzcalls);
}

#ifdef CONFIG_SYSCTL
static struct ctl_table_header *table_header;

static ctl_table kernel_table[] = {
	{
		.procname	= "ve_allow_kthreads",
		.data		= &ve_allow_kthreads,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{ 0 }
};

static ctl_table root_table[] =  {
	{CTL_KERN, "kernel",  NULL, 0, 0555, kernel_table},
	{ 0 }
};

static int init_vecalls_sysctl(void)
{
	table_header = register_sysctl_table(root_table);
	if (!table_header)
		return -ENOMEM ;
	return 0;
}

static void fini_vecalls_sysctl(void)
{
	unregister_sysctl_table(table_header);
} 
#else
static int init_vecalls_sysctl(void) { return 0; }
static void fini_vecalls_sysctl(void) { ; }
#endif

static int __init vecalls_init(void)
{
	int err;

	err = init_vecalls_sysctl();
	if (err)
		goto out_vzmond;

	err = init_vzmond();
	if (err < 0)
		goto out_sysctl;

	err = init_vecalls_proc();
	if (err < 0)
		goto out_proc;

	err = init_vecalls_ioctls();
	if (err < 0)
		goto out_ioctls;

	/* We can easy dereference this hook if VE is running
	 * because in this case vzmon refcount > 0
	 */
	do_ve_enter_hook = do_env_enter;
	/*
	 * This one can also be dereferenced since not freed
	 * VE holds reference on module
	 */
	do_env_free_hook = real_do_env_free;

	return 0;

out_ioctls:
	fini_vecalls_proc();
out_proc:
	fini_vzmond();
out_sysctl:
	fini_vecalls_sysctl();
out_vzmond:
	return err;
}

static void vecalls_exit(void)
{
	do_env_free_hook = NULL;
	do_ve_enter_hook = NULL;
	fini_vecalls_ioctls();
	fini_vecalls_proc();
	fini_vzmond();
	fini_vecalls_sysctl();
}

MODULE_AUTHOR("SWsoft <info@sw-soft.com>");
MODULE_DESCRIPTION("Virtuozzo Control");
MODULE_LICENSE("GPL v2");

module_init(vecalls_init)
module_exit(vecalls_exit)
