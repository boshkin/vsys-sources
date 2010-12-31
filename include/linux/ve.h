/*
 *  include/linux/ve.h
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#ifndef _LINUX_VE_H
#define _LINUX_VE_H

#include <linux/types.h>
#include <linux/capability.h>
#include <linux/sysctl.h>
#include <linux/net.h>
#include <linux/vzstat.h>
#include <linux/kobject.h>
#include <linux/pid.h>
#include <linux/socket.h>
#include <net/inet_frag.h>

#ifdef VZMON_DEBUG
#  define VZTRACE(fmt,args...) \
	printk(KERN_DEBUG fmt, ##args)
#else
#  define VZTRACE(fmt,args...)
#endif /* VZMON_DEBUG */

struct tty_driver;
struct task_struct;
struct new_utsname;
struct file_system_type;
struct icmp_mib;
struct ip_mib;
struct tcp_mib;
struct udp_mib;
struct linux_mib;
struct fib_info;
struct fib_rule;
struct veip_struct;
struct ve_monitor;
struct nsproxy;

#if defined(CONFIG_VE) && defined(CONFIG_INET)
struct fib_table;
#ifdef CONFIG_VE_IPTABLES
struct xt_table;
struct nf_conn;

#define FRAG6Q_HASHSZ   64

struct ve_nf_conntrack {
	struct hlist_head		*_bysource;
	struct nf_nat_protocol		**_nf_nat_protos;
	int				_nf_nat_vmalloced;
	struct xt_table			*_nf_nat_table;
	struct nf_conntrack_l3proto	*_nf_nat_l3proto;
	atomic_t			_nf_conntrack_count;
	int				_nf_conntrack_max;
	struct hlist_head		*_nf_conntrack_hash;
	int				_nf_conntrack_checksum;
	int				_nf_conntrack_vmalloc;
	struct hlist_head		_unconfirmed;
	struct hlist_head		*_nf_ct_expect_hash;
	unsigned int			_nf_ct_expect_vmalloc;
	unsigned int			_nf_ct_expect_count;
	unsigned int			_nf_ct_expect_max;
	struct hlist_head		*_nf_ct_helper_hash;
	unsigned int			_nf_ct_helper_vmalloc;
#ifdef CONFIG_SYSCTL
	/* l4 stuff: */
	unsigned long			_nf_ct_icmp_timeout;
	unsigned long			_nf_ct_icmpv6_timeout;
	unsigned int			_nf_ct_udp_timeout;
	unsigned int			_nf_ct_udp_timeout_stream;
	unsigned int			_nf_ct_generic_timeout;
	unsigned int			_nf_ct_log_invalid;
	unsigned int			_nf_ct_tcp_timeout_max_retrans;
	unsigned int			_nf_ct_tcp_timeout_unacknowledged;
	int				_nf_ct_tcp_be_liberal;
	int				_nf_ct_tcp_loose;
	int				_nf_ct_tcp_max_retrans;
	unsigned int			_nf_ct_tcp_timeouts[10];
	struct ctl_table_header		*_icmp_sysctl_header;
	unsigned int			_tcp_sysctl_table_users;
	struct ctl_table_header		*_tcp_sysctl_header;
	unsigned int			_udp_sysctl_table_users;
	struct ctl_table_header		*_udp_sysctl_header;
	struct ctl_table_header		*_icmpv6_sysctl_header;
	struct ctl_table_header		*_generic_sysctl_header;
#ifdef CONFIG_NF_CONNTRACK_PROC_COMPAT
	struct ctl_table_header		*_icmp_compat_sysctl_header;
	struct ctl_table_header		*_tcp_compat_sysctl_header;
	struct ctl_table_header		*_udp_compat_sysctl_header;
	struct ctl_table_header		*_generic_compat_sysctl_header;
#endif
	/* l4 protocols sysctl tables: */
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_icmp;
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_tcp4;
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_icmpv6;
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_tcp6;
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_udp4;
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_udp6;
	struct nf_conntrack_l4proto	*_nf_conntrack_l4proto_generic;
	struct nf_conntrack_l4proto	**_nf_ct_protos[PF_MAX];
	/* l3 protocols sysctl tables: */
	struct nf_conntrack_l3proto	*_nf_conntrack_l3proto_ipv4;
	struct nf_conntrack_l3proto	*_nf_conntrack_l3proto_ipv6;
	struct nf_conntrack_l3proto	*_nf_ct_l3protos[AF_MAX];
	/* sysctl standalone stuff: */
	struct ctl_table_header		*_nf_ct_sysctl_header;
	ctl_table			*_nf_ct_sysctl_table;
	ctl_table			*_nf_ct_netfilter_table;
	ctl_table			*_nf_ct_net_table;
	ctl_table			*_ip_ct_netfilter_table;
	struct ctl_table_header		*_ip_ct_sysctl_header;
	int				_nf_ct_log_invalid_proto_min;
	int				_nf_ct_log_invalid_proto_max;
#endif /* CONFIG_SYSCTL */
};
#endif
#endif

struct ve_cpu_stats {
	cycles_t	idle_time;
	cycles_t	iowait_time;
	cycles_t	strt_idle_time;
	cycles_t	used_time;
	seqcount_t	stat_lock;
	unsigned long	nr_running;
	unsigned long	nr_unint;
	unsigned long	nr_iowait;
	cputime64_t	user;
	cputime64_t	nice;
	cputime64_t	system;
} ____cacheline_aligned;

struct ve_ipt_recent;
struct ve_xt_hashlimit;
struct svc_rqst;

struct cgroup;
struct css_set;

struct ve_struct {
	struct list_head	ve_list;

	envid_t			veid;
	struct list_head	vetask_lh;
	/* capability bounding set */
	kernel_cap_t		ve_cap_bset;
	atomic_t		pcounter;
	/* ref counter to ve from ipc */
	atomic_t		counter;
	unsigned int		class_id;
	struct rw_semaphore	op_sem;
	int			is_running;
	int			is_locked;
	atomic_t		suspend;
	unsigned long		flags;
	/* see vzcalluser.h for VE_FEATURE_XXX definitions */
	__u64			features;

/* VE's root */
	struct path		root_path;

	struct file_system_type *proc_fstype;
	struct vfsmount		*proc_mnt;
	struct proc_dir_entry	*proc_root;

/* BSD pty's */
#ifdef CONFIG_LEGACY_PTYS
	struct tty_driver       *pty_driver;
	struct tty_driver       *pty_slave_driver;
#endif
#ifdef CONFIG_UNIX98_PTYS
	struct tty_driver	*ptm_driver;
	struct tty_driver	*pts_driver;
	struct ida		*allocated_ptys;
	struct file_system_type *devpts_fstype;
	struct vfsmount		*devpts_mnt;
	struct dentry		*devpts_root;
	struct devpts_config	*devpts_config;
#endif

	struct ve_nfs_context	*nfs_context;

	struct file_system_type *shmem_fstype;
	struct vfsmount		*shmem_mnt;
#ifdef CONFIG_SYSFS
	struct file_system_type *sysfs_fstype;
	struct vfsmount		*sysfs_mnt;
	struct super_block	*sysfs_sb;
	struct sysfs_dirent	*_sysfs_root;
#endif
	struct kobject		*_virtual_dir;
	struct kset		*class_kset;
	struct kset		*devices_kset;
	struct kobject		*dev_kobj;
	struct kobject		*dev_char_kobj;
	struct kobject		*dev_block_kobj;
	struct class		*tty_class;
	struct class		*mem_class;

#ifdef CONFIG_NET
	struct class		*net_class;
#ifdef CONFIG_INET
 	unsigned long		rt_flush_required;
#endif
#endif
#if defined(CONFIG_VE_NETDEV) || defined (CONFIG_VE_NETDEV_MODULE)
	struct veip_struct	*veip;
	struct net_device	*_venet_dev;
#endif

/* per VE CPU stats*/
	struct timespec		start_timespec;
	u64			start_jiffies;	/* Deprecated */
	cycles_t 		start_cycles;
	unsigned long		avenrun[3];	/* loadavg data */

	cycles_t 		cpu_used_ve;
	struct kstat_lat_pcpu_struct	sched_lat_ve;

#ifdef CONFIG_INET
	struct venet_stat       *stat;
#ifdef CONFIG_VE_IPTABLES
/* core/netfilter.c virtualization */
	struct xt_table		*_ve_ipt_filter_pf; /* packet_filter struct */
	struct xt_table		*_ve_ip6t_filter_pf;
	struct xt_table		*_ipt_mangle_table;
	struct xt_table		*_ip6t_mangle_table;
	struct list_head	_xt_tables[NPROTO];

	__u64			ipt_mask;
	__u64			_iptables_modules;
	struct ve_nf_conntrack	*_nf_conntrack;
	struct ve_ipt_recent	*_ipt_recent;
	struct ve_xt_hashlimit	*_xt_hashlimit;
#endif /* CONFIG_VE_IPTABLES */
#endif
	wait_queue_head_t	*_log_wait;
	unsigned		*_log_start;
	unsigned		*_log_end;
	unsigned		*_logged_chars;
	char			*log_buf;
#define VE_DEFAULT_LOG_BUF_LEN	4096

	struct ve_cpu_stats	*cpu_stats;
	unsigned long		down_at;
	struct list_head	cleanup_list;
#if defined(CONFIG_FUSE_FS) || defined(CONFIG_FUSE_FS_MODULE)
	struct list_head	_fuse_conn_list;
	struct super_block	*_fuse_control_sb;

	struct file_system_type	*fuse_fs_type;
	struct file_system_type	*fuse_ctl_fs_type;
#endif
	unsigned long		jiffies_fixup;
	unsigned char		disable_net;
	struct ve_monitor	*monitor;
	struct proc_dir_entry	*monitor_proc;
	unsigned long		meminfo_val;
	int _randomize_va_space;

#if defined(CONFIG_NFS_FS) || defined(CONFIG_NFS_FS_MODULE) \
	|| defined(CONFIG_NFSD) || defined(CONFIG_NFSD_MODULE)
	unsigned int		_nlmsvc_users;
	struct task_struct*	_nlmsvc_task;
	unsigned long		_nlmsvc_grace_period;
	unsigned long		_nlmsvc_timeout;
	struct svc_rqst*	_nlmsvc_rqst;
#endif

#if defined(CONFIG_BINFMT_MISC) || defined(CONFIG_BINFMT_MISC_MODULE)
	struct file_system_type	*bm_fs_type;
	struct vfsmount		*bm_mnt;
	int			bm_enabled;
	int			bm_entry_count;
	struct list_head	bm_entries;
#endif

	struct nsproxy		*ve_ns;
	struct user_namespace	*user_ns;
	struct net		*ve_netns;
	struct cgroup		*ve_cgroup;
	struct css_set		*ve_css_set;
};

#define VE_MEMINFO_DEFAULT      1       /* default behaviour */
#define VE_MEMINFO_SYSTEM       0       /* disable meminfo virtualization */

enum {
	VE_REBOOT,
};

int init_ve_cgroups(struct ve_struct *ve);
void fini_ve_cgroups(struct ve_struct *ve);

extern struct ve_cpu_stats static_ve_cpu_stats;
static inline struct ve_cpu_stats *VE_CPU_STATS(struct ve_struct *ve, int cpu)
{
	return per_cpu_ptr(ve->cpu_stats, cpu);
}

extern int nr_ve;
extern struct proc_dir_entry *proc_vz_dir;
extern struct proc_dir_entry *glob_proc_vz_dir;

#ifdef CONFIG_VE

void do_update_load_avg_ve(void);
void do_env_free(struct ve_struct *ptr);

static inline struct ve_struct *get_ve(struct ve_struct *ptr)
{
	if (ptr != NULL)
		atomic_inc(&ptr->counter);
	return ptr;
}

static inline void put_ve(struct ve_struct *ptr)
{
	if (ptr && atomic_dec_and_test(&ptr->counter))
		do_env_free(ptr);
}

static inline void pget_ve(struct ve_struct *ptr)
{
	atomic_inc(&ptr->pcounter);
}

void ve_cleanup_schedule(struct ve_struct *);
static inline void pput_ve(struct ve_struct *ptr)
{
	if (unlikely(atomic_dec_and_test(&ptr->pcounter)))
		ve_cleanup_schedule(ptr);
}

extern spinlock_t ve_cleanup_lock;
extern struct list_head ve_cleanup_list;
extern struct task_struct *ve_cleanup_thread;

extern int (*do_ve_enter_hook)(struct ve_struct *ve, unsigned int flags);
extern void (*do_env_free_hook)(struct ve_struct *ve);

extern unsigned long long ve_relative_clock(struct timespec * ts);

#ifdef CONFIG_FAIRSCHED
#define ve_cpu_online_map(ve, mask) fairsched_cpu_online_map(ve->veid, mask)
#else
#define ve_cpu_online_map(ve, mask) do { *(mask) = cpu_online_map; } while (0)
#endif
#else	/* CONFIG_VE */
#define ve_utsname	system_utsname
#define get_ve(ve)	(NULL)
#define put_ve(ve)	do { } while (0)
#define pget_ve(ve)	do { } while (0)
#define pput_ve(ve)	do { } while (0)
#endif	/* CONFIG_VE */

#endif /* _LINUX_VE_H */
