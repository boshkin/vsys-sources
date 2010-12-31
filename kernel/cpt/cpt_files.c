/*
 *
 *  kernel/cpt/cpt_files.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/pipe_fs_i.h>
#include <linux/mman.h>
#include <linux/mnt_namespace.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/smp_lock.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/vzcalluser.h>
#include <linux/ve_proto.h>
#include <bc/kmem.h>
#include <linux/cpt_image.h>
#include <linux/if_tun.h>
#include <linux/fdtable.h>
#include <linux/shm.h>
#include <linux/signalfd.h>
#include <linux/nsproxy.h>
#include <linux/fs_struct.h>
#include <linux/miscdevice.h>

#include "cpt_obj.h"
#include "cpt_context.h"
#include "cpt_mm.h"
#include "cpt_files.h"
#include "cpt_socket.h"
#include "cpt_kernel.h"
#include "cpt_fsmagic.h"
#include "cpt_syscalls.h"

static inline int is_signalfd_file(struct file *file)
{
	/* no other users of it yet */
	return file->f_op == &signalfd_fops;
}

void cpt_printk_dentry(struct dentry *d, struct vfsmount *mnt)
{
	char *path;
	struct path p;
	unsigned long pg = __get_free_page(GFP_KERNEL);

	if (!pg)
		return;

	p.dentry = d;
	p.mnt = mnt;
	path = d_path(&p, (char *)pg, PAGE_SIZE);

	if (!IS_ERR(path))
		eprintk("<%s>", path);
	free_page(pg);
}

int cpt_verify_overmount(char *path, struct dentry *d, struct vfsmount *mnt,
			 int verify, cpt_context_t *ctx)
{
	if (d->d_inode->i_sb->s_magic == FSMAGIC_PROC &&
	    proc_dentry_of_dead_task(d))
		return 0;

	if (path[0] == '/' && !(!IS_ROOT(d) && d_unhashed(d))) {
		struct nameidata nd;
		if (path_lookup(path, 0, &nd)) {
			eprintk_ctx("d_path cannot be looked up %s\n", path);
			return -EINVAL;
		}
		if (nd.path.dentry != d || (verify && nd.path.mnt != mnt)) {
			if (!strcmp(path, "/dev/null")) {
				/*
				 * epic kludge to workaround the case, when the
				 * init opens a /dev/null and then udevd
				 * overmounts the /dev with tmpfs
				 */
				path_put(&nd.path);
				return 0;
			}

			eprintk_ctx("d_path is invisible %s\n", path);
			path_put(&nd.path);
			return -EINVAL;
		}
		path_put(&nd.path);
	}
	return 0;
}

static int
cpt_replaced(struct dentry * de, struct vfsmount *mnt, cpt_context_t * ctx)
{
	int result = 0;

#if defined(CONFIG_VZFS_FS) || defined(CONFIG_VZFS_FS_MODULE)
	char *path;
	unsigned long pg;
	struct dentry * renamed_dentry;
	struct path p;

	if (de->d_sb->s_magic != FSMAGIC_VEFS)
		return 0;
	if (de->d_inode->i_nlink != 0 ||
	    atomic_read(&de->d_inode->i_writecount) > 0) 
		return 0;

	renamed_dentry = vefs_replaced_dentry(de);
	if (renamed_dentry == NULL)
		return 0;

	pg = __get_free_page(GFP_KERNEL);
	if (!pg)
		return 0;

	p.dentry = de;
	p.mnt = mnt;
	path = d_path(&p, (char *)pg, PAGE_SIZE);
	if (!IS_ERR(path)) {
		int len;
		struct nameidata nd;

		len = pg + PAGE_SIZE - 1 - (unsigned long)path;
		if (len >= sizeof("(deleted) ") - 1 &&
		    !memcmp(path, "(deleted) ", sizeof("(deleted) ") - 1)) {
			len -= sizeof("(deleted) ") - 1;
			path += sizeof("(deleted) ") - 1;
		}

		if (path_lookup(path, 0, &nd) == 0) {
			if (mnt == nd.path.mnt &&
			    vefs_is_renamed_dentry(nd.path.dentry, renamed_dentry))
				result = 1;
			path_put(&nd.path);
		}
	}
	free_page(pg);
#endif
	return result;
}

static int cpt_dump_dentry(struct dentry *d, struct vfsmount *mnt,
			   int replaced, int verify, cpt_context_t *ctx)
{
	int len;
	char *path;
	struct path p;
	char *pg = cpt_get_buf(ctx);
	loff_t saved;

	p.dentry = d;
	p.mnt = mnt;
	path = d_path(&p, pg, PAGE_SIZE);
	len = PTR_ERR(path);

	if (IS_ERR(path)) {
		struct cpt_object_hdr o;
		char tmp[1];

		/* VZ changes d_path() to return EINVAL, when path
		 * is not supposed to be visible inside VE.
		 * This changes behaviour of d_path() comparing
		 * to mainstream kernel, f.e. d_path() fails
		 * on any kind of shared memory. Maybe, there are
		 * another cases, but I am aware only about this one.
		 * So, we just ignore error on shmem mounts and proceed.
		 * Otherwise, checkpointing is prohibited because
		 * of reference to an invisible file.
		 */
		if (len != -EINVAL ||
		    mnt != get_exec_env()->shmem_mnt)
			eprintk_ctx("d_path err=%d\n", len);
		else
			len = 0;

		cpt_push_object(&saved, ctx);
		cpt_open_object(NULL, ctx);
		o.cpt_next = CPT_NULL;
		o.cpt_object = CPT_OBJ_NAME;
		o.cpt_hdrlen = sizeof(o);
		o.cpt_content = CPT_CONTENT_NAME;
		tmp[0] = 0;

		ctx->write(&o, sizeof(o), ctx);
		ctx->write(tmp, 1, ctx);
		ctx->align(ctx);
		cpt_close_object(ctx);
		cpt_pop_object(&saved, ctx);

		__cpt_release_buf(ctx);
		return len;
	} else {
		struct cpt_object_hdr o;

		len = pg + PAGE_SIZE - 1 - path;
		if (replaced &&
		    len >= sizeof("(deleted) ") - 1 &&
		    !memcmp(path, "(deleted) ", sizeof("(deleted) ") - 1)) {
			len -= sizeof("(deleted) ") - 1;
			path += sizeof("(deleted) ") - 1;
		}
		o.cpt_next = CPT_NULL;
		o.cpt_object = CPT_OBJ_NAME;
		o.cpt_hdrlen = sizeof(o);
		o.cpt_content = CPT_CONTENT_NAME;
		path[len] = 0;

		if (cpt_verify_overmount(path, d, mnt, verify, ctx)) {
			__cpt_release_buf(ctx);
			return -EINVAL;
		}

		cpt_push_object(&saved, ctx);
		cpt_open_object(NULL, ctx);
		ctx->write(&o, sizeof(o), ctx);
		ctx->write(path, len+1, ctx);
		ctx->align(ctx);
		cpt_close_object(ctx);
		cpt_pop_object(&saved, ctx);
		__cpt_release_buf(ctx);
	}
	return 0;
}

int cpt_dump_string(const char *s, struct cpt_context *ctx)
{
	int len;
	struct cpt_object_hdr o;

	cpt_open_object(NULL, ctx);
	len = strlen(s);
	o.cpt_next = CPT_NULL;
	o.cpt_object = CPT_OBJ_NAME;
	o.cpt_hdrlen = sizeof(o);
	o.cpt_content = CPT_CONTENT_NAME;

	ctx->write(&o, sizeof(o), ctx);
	ctx->write(s, len+1, ctx);
	ctx->align(ctx);
	cpt_close_object(ctx);
	return 0;
}

static int
cpt_dump_filename(struct file *file, int replaced, cpt_context_t *ctx)
{
	return cpt_dump_dentry(file->f_dentry, file->f_vfsmnt, replaced, 1, ctx);
}

int cpt_dump_inode(struct dentry *d, struct vfsmount *mnt, struct cpt_context *ctx)
{
	int err;
	struct cpt_inode_image *v = cpt_get_buf(ctx);
	struct kstat sbuf;

	v->cpt_next = sizeof(*v);
	v->cpt_object = CPT_OBJ_INODE;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	if ((err = vfs_getattr(mnt, d, &sbuf)) != 0) {
		cpt_release_buf(ctx);
		return err;
	}

	v->cpt_dev	= d->d_inode->i_sb->s_dev;
	v->cpt_ino	= d->d_inode->i_ino;
	v->cpt_mode	= sbuf.mode;
	v->cpt_nlink	= sbuf.nlink;
	v->cpt_uid	= sbuf.uid;
	v->cpt_gid	= sbuf.gid;
	v->cpt_rdev	= d->d_inode->i_rdev;
	v->cpt_size	= sbuf.size;
	v->cpt_atime	= cpt_timespec_export(&sbuf.atime);
	v->cpt_mtime	= cpt_timespec_export(&sbuf.mtime);
	v->cpt_ctime	= cpt_timespec_export(&sbuf.ctime);
	v->cpt_blksize	= sbuf.blksize;
	v->cpt_blocks	= sbuf.blocks;
	v->cpt_sb	= d->d_inode->i_sb->s_magic;

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);
	return 0;
}

int cpt_collect_files(cpt_context_t * ctx)
{
	int err;
	cpt_object_t *obj;
	int index = 0;

	/* Collect process fd sets */
	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;
		if (tsk->files && cpt_object_add(CPT_OBJ_FILES, tsk->files, ctx) == NULL)
			return -ENOMEM;
	}

	/* Collect files from fd sets */
	for_each_object(obj, CPT_OBJ_FILES) {
		int fd;
		struct files_struct *f = obj->o_obj;

		cpt_obj_setindex(obj, index++, ctx);

		if (obj->o_count != atomic_read(&f->count)) {
			eprintk_ctx("files_struct is referenced outside %d %d\n", obj->o_count, atomic_read(&f->count));
			return -EBUSY;
		}

		for (fd = 0; fd < f->fdt->max_fds; fd++) {
			struct file *file = fcheck_files(f, fd);
			if (file && cpt_object_add(CPT_OBJ_FILE, file, ctx) == NULL)
				return -ENOMEM;
		}
	}

	/* Collect files queued by AF_UNIX sockets. */
	if ((err = cpt_collect_passedfds(ctx)) < 0)
		return err;

	/* OK. At this point we should count all the references. */
	for_each_object(obj, CPT_OBJ_FILE) {
		struct file *file = obj->o_obj;
		struct file *parent;
		cpt_object_t *ino_obj;

		if (obj->o_count != atomic_long_read(&file->f_count)) {
			eprintk_ctx("file struct is referenced outside %d %ld\n", obj->o_count, atomic_long_read(&file->f_count));
			cpt_printk_dentry(file->f_dentry, file->f_vfsmnt);
			return -EBUSY;
		}

		switch (file->f_dentry->d_inode->i_sb->s_magic) {
		case FSMAGIC_FUTEX:
		case FSMAGIC_MQUEUE:
		case FSMAGIC_BDEV:
#ifndef CONFIG_INOTIFY_USER
		case FSMAGIC_INOTIFY:
#endif
			eprintk_ctx("file on unsupported FS: magic %08lx\n", file->f_dentry->d_inode->i_sb->s_magic);
			return -EBUSY;
		}

		/* Collect inode. It is necessary mostly to resolve deleted
		 * hard links. */
		ino_obj = cpt_object_add(CPT_OBJ_INODE, file->f_dentry->d_inode, ctx);
		if (ino_obj == NULL)
			return -ENOMEM;

		parent = ino_obj->o_parent;
		if (!parent || (!IS_ROOT(parent->f_dentry) && d_unhashed(parent->f_dentry)))
			ino_obj->o_parent = file;

		if (S_ISCHR(file->f_dentry->d_inode->i_mode)) {
			int maj = imajor(file->f_dentry->d_inode);
			if (maj == PTY_MASTER_MAJOR ||
			    (maj >= UNIX98_PTY_MASTER_MAJOR &&
			     maj < UNIX98_PTY_MASTER_MAJOR+UNIX98_PTY_MAJOR_COUNT) ||
			    maj == PTY_SLAVE_MAJOR ||
			    maj == UNIX98_PTY_SLAVE_MAJOR ||
			    maj == TTYAUX_MAJOR) {
				err = cpt_collect_tty(file, ctx);
				if (err)
					return err;
			}
		}

		if (S_ISSOCK(file->f_dentry->d_inode->i_mode)) {
			err = cpt_collect_socket(file, ctx);
			if (err)
				return err;
		}
	}

	err = cpt_index_sockets(ctx);

	return err;
}

/* /dev/ptmx is special, all the files share one inode, but real tty backend
 * is attached via file->private_data.
 */

static inline int is_cloning_inode(struct inode *ino)
{
	return S_ISCHR(ino->i_mode) && 
		ino->i_rdev == MKDEV(TTYAUX_MAJOR,2);
}

static int dump_one_flock(struct file_lock *fl, int owner, struct cpt_context *ctx)
{
	pid_t pid;
	struct cpt_flock_image *v = cpt_get_buf(ctx);

	v->cpt_next = sizeof(*v);
	v->cpt_object = CPT_OBJ_FLOCK;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_VOID;

	v->cpt_owner = owner;

	pid = fl->fl_pid;
	if (pid) {
		pid = pid_to_vpid(fl->fl_pid);
		if (pid == -1) {
			if (!(fl->fl_flags&FL_FLOCK)) {
				eprintk_ctx("posix lock from another container?\n");
				cpt_release_buf(ctx);
				return -EBUSY;
			}
			pid = 0;
		}
	}

	v->cpt_pid = pid;
	v->cpt_start = fl->fl_start;
	v->cpt_end = fl->fl_end;
	v->cpt_flags = fl->fl_flags;
	v->cpt_type = fl->fl_type;

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);
	return 0;
}


int cpt_dump_flock(struct file *file, struct cpt_context *ctx)
{
	int err = 0;
	struct file_lock *fl;

	lock_kernel();
	for (fl = file->f_dentry->d_inode->i_flock;
	     fl; fl = fl->fl_next) {
		if (file != fl->fl_file)
			continue;
		if (fl->fl_flags & FL_LEASE) {
			eprintk_ctx("lease lock is not supported\n");
			err = -EINVAL;
			break;
		}
		if (fl->fl_flags & FL_POSIX) {
			cpt_object_t *obj;
			obj = lookup_cpt_object(CPT_OBJ_FILES, fl->fl_owner, ctx);
			if (obj) {
				dump_one_flock(fl, obj->o_index, ctx);
				continue;
			} else {
				eprintk_ctx("unknown lock owner %p\n", fl->fl_owner);
				err = -EINVAL;
			}
		}
		if (fl->fl_flags & FL_FLOCK) {
			dump_one_flock(fl, -1, ctx);
			continue;
		}
	}
	unlock_kernel();
	return err;
}

static int dump_one_file(cpt_object_t *obj, struct file *file, cpt_context_t *ctx)
{
	int err = 0;
	cpt_object_t *iobj;
	struct cpt_file_image *v = cpt_get_buf(ctx);
	struct kstat sbuf;
	int replaced = 0;

	cpt_open_object(obj, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_FILE;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_flags = file->f_flags;
	v->cpt_mode = file->f_mode;
	v->cpt_pos = file->f_pos;
	v->cpt_uid = file->f_cred->uid;
	v->cpt_gid = file->f_cred->gid;

	vfs_getattr(file->f_vfsmnt, file->f_dentry, &sbuf);

	v->cpt_i_mode = sbuf.mode;
	v->cpt_lflags = 0;

	if (file->f_dentry->d_inode->i_sb->s_magic == FSMAGIC_PROC) {
		v->cpt_lflags |= CPT_DENTRY_PROC;
		if (proc_dentry_of_dead_task(file->f_dentry))
			v->cpt_lflags |= CPT_DENTRY_PROCPID_DEAD;
	}

	if (IS_ROOT(file->f_dentry))
		v->cpt_lflags |= CPT_DENTRY_ROOT;
	else if (d_unhashed(file->f_dentry)) {
		if (cpt_replaced(file->f_dentry, file->f_vfsmnt, ctx)) {
			v->cpt_lflags |= CPT_DENTRY_REPLACED;
			replaced = 1;
		} else if (!(v->cpt_lflags & CPT_DENTRY_PROCPID_DEAD))
			v->cpt_lflags |= CPT_DENTRY_DELETED;
	}
	if (is_cloning_inode(file->f_dentry->d_inode))
		v->cpt_lflags |= CPT_DENTRY_CLONING;

	v->cpt_inode = CPT_NULL;
	if (!(v->cpt_lflags & CPT_DENTRY_REPLACED)) {
		iobj = lookup_cpt_object(CPT_OBJ_INODE, file->f_dentry->d_inode, ctx);
		if (iobj) {
			v->cpt_inode = iobj->o_pos;
			if (iobj->o_flags & CPT_INODE_HARDLINKED)
				v->cpt_lflags |= CPT_DENTRY_HARDLINKED;
		}
	}
	v->cpt_priv = CPT_NULL;
	v->cpt_fown_fd = -1;
	if (S_ISCHR(v->cpt_i_mode)) {
		iobj = lookup_cpt_object(CPT_OBJ_TTY, file->private_data, ctx);
		if (iobj) {
			v->cpt_priv = iobj->o_pos;
			if (file->f_flags&FASYNC)
				v->cpt_fown_fd = cpt_tty_fasync(file, ctx);
		}
		if (imajor(file->f_dentry->d_inode) == MISC_MAJOR &&
				iminor(file->f_dentry->d_inode) == TUN_MINOR)
			v->cpt_lflags |= CPT_DENTRY_TUNTAP;
	}
	if (S_ISSOCK(v->cpt_i_mode)) {
		if (obj->o_index < 0) {
			eprintk_ctx("BUG: no socket index\n");
			cpt_release_buf(ctx);
			return -EINVAL;
		}
		v->cpt_priv = obj->o_index;
		if (file->f_flags&FASYNC)
			v->cpt_fown_fd = cpt_socket_fasync(file, ctx);
	}
	if (file->f_op == &eventpoll_fops) {
		v->cpt_priv = file->f_dentry->d_inode->i_ino;
		v->cpt_lflags |= CPT_DENTRY_EPOLL;
	}
	if (file->f_dentry->d_inode->i_sb->s_magic == FSMAGIC_INOTIFY) {
		v->cpt_priv = file->f_dentry->d_inode->i_ino;
		v->cpt_lflags |= CPT_DENTRY_INOTIFY;
	}

	v->cpt_fown_pid = (file->f_owner.pid == NULL ?
			CPT_FOWN_STRAY_PID : pid_vnr(file->f_owner.pid));
	v->cpt_fown_uid = file->f_owner.uid;
	v->cpt_fown_euid = file->f_owner.euid;
	v->cpt_fown_signo = file->f_owner.signum;

	if (is_signalfd_file(file)) {
		struct signalfd_ctx *ctx = file->private_data;
		v->cpt_lflags |= CPT_DENTRY_SIGNALFD;
		v->cpt_priv = cpt_sigset_export(&ctx->sigmask);
	}

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	if (!S_ISSOCK(v->cpt_i_mode)) {
		err = cpt_dump_filename(file, replaced, ctx);
		if (err)
			return err;
		if ((file->f_mode & FMODE_WRITE) &&
				file->f_dentry->d_inode->i_sb->s_magic == FSMAGIC_VEFS)
			vefs_track_notify(file->f_dentry, 1);
	}

	if (file->f_dentry->d_inode->i_flock)
		err = cpt_dump_flock(file, ctx);

	cpt_close_object(ctx);

	return err;
}

/* About this weird function... Crappy code dealing with SYSV shared memory 
 * defines TMPFS inode and file with f_op doing only mmap. So...
 * Maybe, this is wrong and leaks something. It is clear access to
 * SYSV shmem via mmap is quite unusual and impossible from user space.
 */
static int dump_content_shm(struct file *file, struct cpt_context *ctx)
{
	struct cpt_obj_bits *v;
	loff_t saved_pos;
	unsigned long addr;

	addr = do_mmap_pgoff(file, 0, file->f_dentry->d_inode->i_size,
			     PROT_READ, MAP_SHARED, 0);
	if (IS_ERR((void*)addr))
		return PTR_ERR((void*)addr);

	cpt_push_object(&saved_pos, ctx);
	cpt_open_object(NULL, ctx);
	v = cpt_get_buf(ctx);
	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_BITS;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_DATA;
	v->cpt_size = file->f_dentry->d_inode->i_size;
	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);
	ctx->write((void*)addr, file->f_dentry->d_inode->i_size, ctx);
	ctx->align(ctx);
	do_munmap(current->mm, addr, file->f_dentry->d_inode->i_size);

	cpt_close_object(ctx);
	cpt_pop_object(&saved_pos, ctx);
	return 0;
}

static int data_is_zero(char *addr, int len)
{
	int i;
	unsigned long zerolong = 0;

	for (i=0; i<len/sizeof(unsigned long); i++) {
		if (((unsigned long*)(addr))[i] != 0)
			return 0;
	}
	i = len % sizeof(unsigned long);
	if (!i)
		return 1;
	return memcmp(addr + len - i, &zerolong, i) == 0;
}


static int dump_content_regular(struct file *file, struct cpt_context *ctx)
{
	loff_t saved_pos;
	loff_t pos = 0;
	loff_t obj_opened = CPT_NULL;
	struct cpt_page_block pgb;
	ssize_t (*do_read)(struct file *, char __user *, size_t, loff_t *);

	if (file->f_op == NULL)
		return -EINVAL;

	do_read = file->f_op->read;

	if (file->f_op == &shm_file_operations ||
	    file->f_op == &shmem_file_operations) {

		/* shmget uses shm ops  */
		if (file->f_op == &shm_file_operations) {
			struct shm_file_data *sfd = file->private_data;
			file = sfd->file;
		}

		cpt_dump_content_sysvshm(file, ctx);

		do_read = file->f_dentry->d_inode->i_fop->read;
		if (!do_read) {
			wprintk_ctx("TMPFS is not configured?\n");
			return dump_content_shm(file, ctx);
		}
	}

	if (!(file->f_mode & FMODE_READ) ||
	    (file->f_flags & O_DIRECT)) {
		struct file *filp;
		filp = dentry_open(dget(file->f_dentry),
				   mntget(file->f_vfsmnt),
				   O_RDONLY | O_LARGEFILE,
				   NULL /* not checked */);
		if (IS_ERR(filp)) {
			cpt_printk_dentry(file->f_dentry, file->f_vfsmnt);
			eprintk_ctx("cannot reopen file for read %ld\n", PTR_ERR(filp));
			return PTR_ERR(filp);
		}
		file = filp;
	} else {
		atomic_long_inc(&file->f_count);
	}

	for (;;) {
		mm_segment_t oldfs;
		int err;

		(void)cpt_get_buf(ctx);

		oldfs = get_fs(); set_fs(KERNEL_DS);
		err = do_read(file, ctx->tmpbuf, PAGE_SIZE, &pos);
		set_fs(oldfs);
		if (err < 0) {
			eprintk_ctx("dump_content_regular: do_read: %d", err);
			fput(file);
			__cpt_release_buf(ctx);
			return err;
		}
		if (err == 0) {
			__cpt_release_buf(ctx);
			break;
		}
		if (data_is_zero(ctx->tmpbuf, err)) {
			if (obj_opened != CPT_NULL) {
				ctx->pwrite(&pgb.cpt_end, 8, ctx, obj_opened + offsetof(struct cpt_page_block, cpt_end));
				ctx->align(ctx);
				cpt_close_object(ctx);
				cpt_pop_object(&saved_pos, ctx);
				obj_opened = CPT_NULL;
			}
		} else {
			if (obj_opened == CPT_NULL) {
				cpt_push_object(&saved_pos, ctx);
				cpt_open_object(NULL, ctx);
				obj_opened = ctx->file->f_pos;
				pgb.cpt_next = CPT_NULL;
				pgb.cpt_object = CPT_OBJ_PAGES;
				pgb.cpt_hdrlen = sizeof(pgb);
				pgb.cpt_content = CPT_CONTENT_DATA;
				pgb.cpt_start = pos - err;
				pgb.cpt_end = pgb.cpt_start;
				ctx->write(&pgb, sizeof(pgb), ctx);
			}
			ctx->write(ctx->tmpbuf, err, ctx);
			pgb.cpt_end += err;
		}
		__cpt_release_buf(ctx);
	}

	fput(file);

	if (obj_opened != CPT_NULL) {
		ctx->pwrite(&pgb.cpt_end, 8, ctx, obj_opened + offsetof(struct cpt_page_block, cpt_end));
		ctx->align(ctx);
		cpt_close_object(ctx);
		cpt_pop_object(&saved_pos, ctx);
		obj_opened = CPT_NULL;
	}
	return 0;
}


static int dump_content_chrdev(struct file *file, struct cpt_context *ctx)
{
	struct inode *ino = file->f_dentry->d_inode;
	int maj;

	maj = imajor(ino);
	if (maj == MEM_MAJOR) {
		/* Well, OK. */
		return 0;
	}
	if (maj == PTY_MASTER_MAJOR ||
	    (maj >= UNIX98_PTY_MASTER_MAJOR &&
	     maj < UNIX98_PTY_MASTER_MAJOR+UNIX98_PTY_MAJOR_COUNT) ||
	    maj == PTY_SLAVE_MAJOR ||
	    maj == UNIX98_PTY_SLAVE_MAJOR ||
	    maj == TTYAUX_MAJOR) {
		return cpt_dump_content_tty(file, ctx);
	}
	if (maj == MISC_MAJOR && iminor(ino) == TUN_MINOR)
		return 0;

	eprintk_ctx("unsupported chrdev %d/%d\n", maj, iminor(ino));
	return -EINVAL;
}

static int dump_content_blkdev(struct file *file, struct cpt_context *ctx)
{
	struct inode *ino = file->f_dentry->d_inode;

	/* We are not going to transfer them. */
	eprintk_ctx("unsupported blkdev %d/%d\n", imajor(ino), iminor(ino));
	return -EINVAL;
}

static int dump_content_fifo(struct file *file, struct cpt_context *ctx)
{
	struct inode *ino = file->f_dentry->d_inode;
	cpt_object_t *obj;
	loff_t saved_pos;
	int readers;
	int writers;
	int anon = 0;

	mutex_lock(&ino->i_mutex);
	readers = ino->i_pipe->readers;
	writers = ino->i_pipe->writers;
	for_each_object(obj, CPT_OBJ_FILE) {
		struct file *file1 = obj->o_obj;
		if (file1->f_dentry->d_inode == ino) {
			if (file1->f_mode & FMODE_READ)
				readers--;
			if (file1->f_mode & FMODE_WRITE)
				writers--;
		}
	}	
	mutex_unlock(&ino->i_mutex);
	if (readers || writers) {
		struct dentry *dr = file->f_dentry->d_sb->s_root;
		if (dr->d_name.len == 7 && memcmp(dr->d_name.name,"pipefs:",7) == 0)
			anon = 1;

		if (anon) {
			eprintk_ctx("pipe has %d/%d external readers/writers\n", readers, writers);
			return -EBUSY;
		}
		/* If fifo has external readers/writers, we are in troubles.
		 * If the buffer is not empty, we must move its content.
		 * But if the fifo is owned by a service, we cannot do
		 * this. See?
		 *
		 * For now we assume, that if fifo is opened by another
		 * process, we do not own it and, hence, migrate without
		 * data.
		 */
		return 0;
	}

	/* OK, we must save fifo state. No semaphores required. */

	if (ino->i_pipe->nrbufs) {
		struct cpt_obj_bits *v = cpt_get_buf(ctx);
		struct pipe_inode_info *info;
		int count, buf, nrbufs;

		mutex_lock(&ino->i_mutex);
		info =  ino->i_pipe;
		count = 0;
		buf = info->curbuf;
		nrbufs = info->nrbufs;
		while (--nrbufs >= 0) {
			if (!info->bufs[buf].ops->can_merge) {
				mutex_unlock(&ino->i_mutex);
				eprintk_ctx("unknown format of pipe buffer\n");
				return -EINVAL;
			}
			count += info->bufs[buf].len;
			buf = (buf+1) & (PIPE_BUFFERS-1);
		}

		if (!count) {
			mutex_unlock(&ino->i_mutex);
			return 0;
		}

		cpt_push_object(&saved_pos, ctx);
		cpt_open_object(NULL, ctx);
		v->cpt_next = CPT_NULL;
		v->cpt_object = CPT_OBJ_BITS;
		v->cpt_hdrlen = sizeof(*v);
		v->cpt_content = CPT_CONTENT_DATA;
		v->cpt_size = count;
		ctx->write(v, sizeof(*v), ctx);
		cpt_release_buf(ctx);

		count = 0;
		buf = info->curbuf;
		nrbufs = info->nrbufs;
		while (--nrbufs >= 0) {
			struct pipe_buffer *b = info->bufs + buf;
			/* need to ->pin first? */
			void * addr = b->ops->map(info, b, 0);
			ctx->write(addr + b->offset, b->len, ctx);
			b->ops->unmap(info, b, addr);
			buf = (buf+1) & (PIPE_BUFFERS-1);
		}

		mutex_unlock(&ino->i_mutex);

		ctx->align(ctx);
		cpt_close_object(ctx);
		cpt_pop_object(&saved_pos, ctx);
	}

	return 0;
}

static int dump_content_socket(struct file *file, struct cpt_context *ctx)
{
	return 0;
}

struct cpt_dirent {
	unsigned long	ino;
	char		*name;
	int		namelen;
	int		found;
};

static int cpt_filldir(void * __buf, const char * name, int namelen,
		loff_t offset, u64 ino, unsigned int d_type)
{
	struct cpt_dirent * dirent = __buf;

	if ((ino == dirent->ino) && (namelen < PAGE_SIZE - 1)) {
		memcpy(dirent->name, name, namelen);
		dirent->name[namelen] = '\0';
		dirent->namelen = namelen;
		dirent->found = 1;
		return 1;
	}
	return 0;
}

static int find_linked_dentry(struct dentry *d, struct vfsmount *mnt,
		struct inode *ino, struct cpt_context *ctx)
{
	int err = -EBUSY;
	struct file *f = NULL;
	struct cpt_dirent entry;
	struct dentry *de, *found = NULL;

	dprintk_ctx("deleted reference to existing inode, try to find file\n");
	/* 1. Try to find not deleted dentry in ino->i_dentry list */
	spin_lock(&dcache_lock);
	list_for_each_entry(de, &ino->i_dentry, d_alias) {
		if (!IS_ROOT(de) && d_unhashed(de))
			continue;
		found = de;
		dget_locked(found);
		break;
	}
	spin_unlock(&dcache_lock);
	if (found) {
		err = cpt_dump_dentry(found, mnt, 0, 1, ctx);
		dput(found);
		if (!err) {
			dprintk_ctx("dentry found in aliases\n");
			return 0;
		}
	}

	/* 2. Try to find file in current dir */
	de = dget_parent(d);
	if (!de)
		return -EINVAL;

	mntget(mnt);
	f = dentry_open(de, mnt, O_RDONLY | O_LARGEFILE, NULL);
	if (IS_ERR(f))
		return PTR_ERR(f);

	entry.ino = ino->i_ino;
	entry.name = cpt_get_buf(ctx);
	entry.found = 0;
	err = vfs_readdir(f, cpt_filldir, &entry);
	if (err || !entry.found) {
		err = err ? err : -ENOENT;
		goto err_readdir;
	}

	found = lookup_one_len(entry.name, de, entry.namelen);
	if (IS_ERR(found)) {
		err = PTR_ERR(found);
		goto err_readdir;
	}

	err = -ENOENT;
	if (found->d_inode != ino)
		goto err_lookup;

	dprintk_ctx("dentry found in dir\n");
	__cpt_release_buf(ctx);
	err = cpt_dump_dentry(found, mnt, 0, 1, ctx);

err_lookup:
	dput(found);
err_readdir:
	fput(f);
	__cpt_release_buf(ctx);
	return err;
}

static struct dentry *find_linkdir(struct vfsmount *mnt, struct cpt_context *ctx)
{
	int i;

	for (i = 0; i < ctx->linkdirs_num; i++)
		if (ctx->linkdirs[i]->f_vfsmnt == mnt)
			return ctx->linkdirs[i]->f_dentry;
	return NULL;
}

struct dentry *cpt_fake_link(struct dentry *d, struct vfsmount *mnt,
		struct inode *ino, struct cpt_context *ctx)
{
	int err;
	int order = 8;
	const char *prefix = ".cpt_hardlink.";
	int preflen = strlen(prefix) + order;
	char name[preflen + 1];
	struct dentry *dirde, *hardde;

	dirde = find_linkdir(mnt, ctx);
	if (!dirde) {
		err = -ENOENT;
		goto out;
	}

	ctx->linkcnt++;
	snprintf(name, sizeof(name), "%s%0*u", prefix, order, ctx->linkcnt);

	mutex_lock(&dirde->d_inode->i_mutex);
	hardde = lookup_one_len(name, dirde, strlen(name));
	if (IS_ERR(hardde)) {
		err = PTR_ERR(hardde);
		goto out_unlock;
	}

	if (hardde->d_inode) {
		/* Userspace should clean hardlinked files from previous
		 * dump/undump
		 */
		eprintk_ctx("Hardlinked file already exists: %s\n", name);
		err = -EEXIST;
		goto out_put;
	}

	if (d == NULL)
		err = vfs_create(dirde->d_inode, hardde, 0600, NULL);
	else
		err = vfs_link(d, dirde->d_inode, hardde);
	if (err) {
		eprintk_ctx("error hardlink %s, %d\n", name, err);
		goto out_put;
	}

out_unlock:
	mutex_unlock(&dirde->d_inode->i_mutex);
out:
	return err ? ERR_PTR(err) : hardde;

out_put:
	dput(hardde);
	goto out_unlock;
}

static int create_dump_hardlink(struct dentry *d, struct vfsmount *mnt,
				struct inode *ino, struct cpt_context *ctx)
{
	int err;
	struct dentry *hardde;

	hardde = cpt_fake_link(d, mnt, ino, ctx);
	if (IS_ERR(hardde))
		return PTR_ERR(hardde);

	err = cpt_dump_dentry(hardde, mnt, 0, 1, ctx);
	dput(hardde);

	return err;
}

static int dump_one_inode(struct file *file, struct dentry *d,
			  struct vfsmount *mnt, struct cpt_context *ctx)
{
	int err = 0;
	struct inode *ino = d->d_inode;
	cpt_object_t *iobj;
	int dump_it = 0;

	iobj = lookup_cpt_object(CPT_OBJ_INODE, ino, ctx);
	if (!iobj)
		return -EINVAL;

	if (iobj->o_pos >= 0)
		return 0;

	if (ino->i_sb->s_magic == FSMAGIC_PROC &&
	    proc_dentry_of_dead_task(d))
		return 0;

	if ((!IS_ROOT(d) && d_unhashed(d)) &&
	    !cpt_replaced(d, mnt, ctx))
		dump_it = 1;
	if (!S_ISREG(ino->i_mode) && !S_ISDIR(ino->i_mode)) {
		if (file->f_op == &eventpoll_fops ||
		    is_signalfd_file(file))
			return 0;
		dump_it = 1;
	}

	if (!dump_it)
		return 0;

	cpt_open_object(iobj, ctx);
	cpt_dump_inode(d, mnt, ctx);

	if (!IS_ROOT(d) && d_unhashed(d)) {
		struct file *parent;
		parent = iobj->o_parent;
		if (!parent ||
		    (!IS_ROOT(parent->f_dentry) && d_unhashed(parent->f_dentry))) {
			/* Inode is not deleted, but it does not
			 * have references from inside checkpointed
			 * process group. */
			if (ino->i_nlink != 0) {
				err = find_linked_dentry(d, mnt, ino, ctx);
				if (err && S_ISREG(ino->i_mode)) {
					err = create_dump_hardlink(d, mnt, ino, ctx);
					iobj->o_flags |= CPT_INODE_HARDLINKED;
				} else if (S_ISCHR(ino->i_mode) ||
					   S_ISBLK(ino->i_mode) ||
					   S_ISFIFO(ino->i_mode))
					err = 0;

				if (err) {
					eprintk_ctx("deleted reference to existing inode, checkpointing is impossible: %d\n", err);
					return -EBUSY;
				}
				if (S_ISREG(ino->i_mode) || S_ISDIR(ino->i_mode))
					dump_it = 0;
			}
		} else {
			/* Refer to _another_ file name. */
			err = cpt_dump_filename(parent, 0, ctx);
			if (err)
				return err;
			if (S_ISREG(ino->i_mode) || S_ISDIR(ino->i_mode))
				dump_it = 0;
		}
	}
	if (dump_it) {
		if (S_ISREG(ino->i_mode)) {
			if ((err = dump_content_regular(file, ctx)) != 0) {
				eprintk_ctx("dump_content_regular ");
				cpt_printk_dentry(d, mnt);
			}
		} else if (S_ISDIR(ino->i_mode)) {
			/* We cannot do anything. The directory should be
			 * empty, so it is not a big deal.
			 */
		} else if (S_ISCHR(ino->i_mode)) {
			err = dump_content_chrdev(file, ctx);
		} else if (S_ISBLK(ino->i_mode)) {
			err = dump_content_blkdev(file, ctx);
		} else if (S_ISFIFO(ino->i_mode)) {
			err = dump_content_fifo(file, ctx);
		} else if (S_ISSOCK(ino->i_mode)) {
			err = dump_content_socket(file, ctx);
		} else {
			eprintk_ctx("unknown inode mode %o, magic 0x%lx\n", ino->i_mode & S_IFMT, ino->i_sb->s_magic);
			err = -EINVAL;
		}
	}
	cpt_close_object(ctx);

	return err;
}

int cpt_dump_files(struct cpt_context *ctx)
{
	int epoll_nr, inotify_nr;
	cpt_object_t *obj;

	cpt_open_section(ctx, CPT_SECT_TTY);
	for_each_object(obj, CPT_OBJ_TTY) {
		int err;

		if ((err = cpt_dump_tty(obj, ctx)) != 0)
			return err;
	}
	cpt_close_section(ctx);

	cpt_open_section(ctx, CPT_SECT_INODE);
	for_each_object(obj, CPT_OBJ_FILE) {
		struct file *file = obj->o_obj;
		int err;

		if ((err = dump_one_inode(file, file->f_dentry,
					  file->f_vfsmnt, ctx)) != 0)
			return err;
	}
	for_each_object(obj, CPT_OBJ_FS) {
		struct fs_struct *fs = obj->o_obj;
		int err;

		if (fs->root.dentry &&
		    (err = dump_one_inode(NULL, fs->root.dentry, fs->root.mnt, ctx)) != 0)
			return err;
		if (fs->pwd.dentry &&
		    (err = dump_one_inode(NULL, fs->pwd.dentry, fs->pwd.mnt, ctx)) != 0)
			return err;
	}
	cpt_close_section(ctx);

	epoll_nr = 0;
	inotify_nr = 0;
	cpt_open_section(ctx, CPT_SECT_FILES);
	for_each_object(obj, CPT_OBJ_FILE) {
		struct file *file = obj->o_obj;
		int err;

		if ((err = dump_one_file(obj, file, ctx)) != 0)
			return err;
		if (file->f_op == &eventpoll_fops)
			epoll_nr++;
		if (file->f_dentry->d_inode->i_sb->s_magic == FSMAGIC_INOTIFY)
			inotify_nr++;
	}
	cpt_close_section(ctx);

	if (epoll_nr) {
		cpt_open_section(ctx, CPT_SECT_EPOLL);
		for_each_object(obj, CPT_OBJ_FILE) {
			struct file *file = obj->o_obj;
			if (file->f_op == &eventpoll_fops) {
				int err;
				if ((err = cpt_dump_epolldev(obj, ctx)) != 0)
					return err;
			}
		}
		cpt_close_section(ctx);
	}

	if (inotify_nr) {
		cpt_open_section(ctx, CPT_SECT_INOTIFY);
		for_each_object(obj, CPT_OBJ_FILE) {
			struct file *file = obj->o_obj;
			if (file->f_dentry->d_inode->i_sb->s_magic == FSMAGIC_INOTIFY) {
				int err = -EINVAL;
#ifdef CONFIG_INOTIFY_USER
				if ((err = cpt_dump_inotify(obj, ctx)) != 0)
#endif
					return err;
			}
		}
		cpt_close_section(ctx);
	}

	cpt_open_section(ctx, CPT_SECT_SOCKET);
	for_each_object(obj, CPT_OBJ_SOCKET) {
		int err;

		if ((err = cpt_dump_socket(obj, obj->o_obj, obj->o_index, -1, ctx)) != 0)
			return err;
	}
	cpt_close_section(ctx);

	return 0;
}

static int dump_filedesc(int fd, struct file *file,
			 struct files_struct *f, struct cpt_context *ctx)
{
	struct cpt_fd_image *v = cpt_get_buf(ctx);
	cpt_object_t *obj;

	cpt_open_object(NULL, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_FILEDESC;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_VOID;

	v->cpt_fd = fd;
	obj = lookup_cpt_object(CPT_OBJ_FILE, file, ctx);
	if (!obj) BUG();
	v->cpt_file = obj->o_pos;
	v->cpt_flags = 0;
	if (FD_ISSET(fd, f->fdt->close_on_exec))
		v->cpt_flags = CPT_FD_FLAG_CLOSEEXEC;

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);
	cpt_close_object(ctx);

	return 0;
}

static int dump_one_file_struct(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct files_struct *f = obj->o_obj;
	struct cpt_files_struct_image *v = cpt_get_buf(ctx);
	int fd;
	loff_t saved_obj;

	cpt_open_object(obj, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_FILES;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_index = obj->o_index;
	v->cpt_max_fds = f->fdt->max_fds;
	v->cpt_next_fd = f->next_fd;

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	cpt_push_object(&saved_obj, ctx);
	for (fd = 0; fd < f->fdt->max_fds; fd++) {
		struct file *file = fcheck_files(f, fd);
		if (file)
			dump_filedesc(fd, file, f, ctx);
	}
	cpt_pop_object(&saved_obj, ctx);

	cpt_close_object(ctx);

	return 0;
}

int cpt_dump_files_struct(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	cpt_open_section(ctx, CPT_SECT_FILES_STRUCT);

	for_each_object(obj, CPT_OBJ_FILES) {
		int err;

		if ((err = dump_one_file_struct(obj, ctx)) != 0)
			return err;
	}

	cpt_close_section(ctx);
	return 0;
}

int cpt_collect_fs(cpt_context_t * ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;
		if (tsk->fs) {
			if (cpt_object_add(CPT_OBJ_FS, tsk->fs, ctx) == NULL)
				return -ENOMEM;
			if (tsk->fs->pwd.dentry &&
			    cpt_object_add(CPT_OBJ_INODE, tsk->fs->pwd.dentry->d_inode, ctx) == NULL)
				return -ENOMEM;
			if (tsk->fs->root.dentry &&
			    cpt_object_add(CPT_OBJ_INODE, tsk->fs->root.dentry->d_inode, ctx) == NULL)
				return -ENOMEM;
		}
	}
	return 0;
}

int cpt_dump_dir(struct dentry *d, struct vfsmount *mnt, struct cpt_context *ctx)
{
	struct file file;

	memset(&file, 0, sizeof(file));

	file.f_dentry = d;
	file.f_vfsmnt = mnt;
	file.f_mode = FMODE_READ|FMODE_PREAD|FMODE_LSEEK;
	file.f_cred = current->cred;

	return dump_one_file(NULL, &file, ctx);
}

static int dump_one_fs(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct fs_struct *fs = obj->o_obj;
	struct cpt_fs_struct_image *v = cpt_get_buf(ctx);
	loff_t saved_obj;
	int err;

	cpt_open_object(obj, ctx);

	v->cpt_next = CPT_NULL;
	v->cpt_object = CPT_OBJ_FS;
	v->cpt_hdrlen = sizeof(*v);
	v->cpt_content = CPT_CONTENT_ARRAY;

	v->cpt_umask = fs->umask;

	ctx->write(v, sizeof(*v), ctx);
	cpt_release_buf(ctx);

	cpt_push_object(&saved_obj, ctx);
	err = cpt_dump_dir(fs->root.dentry, fs->root.mnt, ctx);
	if (!err)
		err = cpt_dump_dir(fs->pwd.dentry, fs->pwd.mnt, ctx);

	cpt_pop_object(&saved_obj, ctx);

	cpt_close_object(ctx);

	return err;
}

int cpt_dump_fs_struct(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	cpt_open_section(ctx, CPT_SECT_FS);

	for_each_object(obj, CPT_OBJ_FS) {
		int err;

		if ((err = dump_one_fs(obj, ctx)) != 0)
			return err;
	}

	cpt_close_section(ctx);
	return 0;
}

static int check_one_namespace(cpt_object_t *obj, struct cpt_context *ctx)
{
	int err = 0;
	struct mnt_namespace *n = obj->o_obj;
	struct list_head *p;
	char *path_buf, *path;

	path_buf = (char *) __get_free_page(GFP_KERNEL);
	if (!path_buf)
		return -ENOMEM;

	down_read(&namespace_sem);
	list_for_each(p, &n->list) {
		struct path pt;
		struct vfsmount *mnt = list_entry(p, struct vfsmount, mnt_list);

		pt.dentry = mnt->mnt_root;
		pt.mnt = mnt;
		path = d_path(&pt, path_buf, PAGE_SIZE);
		if (IS_ERR(path))
			continue;

		if (check_one_vfsmount(mnt)) {
			eprintk_ctx("unsupported fs type %s\n", mnt->mnt_sb->s_type->name);
			err = -EINVAL;
			break;
		}
	}
	up_read(&namespace_sem);

	free_page((unsigned long) path_buf);

	return err;
}

int cpt_collect_namespace(cpt_context_t * ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_TASK) {
		struct task_struct *tsk = obj->o_obj;
		if (tsk->nsproxy && tsk->nsproxy->mnt_ns &&
				cpt_object_add(CPT_OBJ_NAMESPACE,
					tsk->nsproxy->mnt_ns, ctx) == NULL)
			return -ENOMEM;
	}

	for_each_object(obj, CPT_OBJ_NAMESPACE) {
		int err;
		if ((err = check_one_namespace(obj, ctx)) != 0)
			return err;
	}

	return 0;
}

struct args_t
{
	int* pfd;
	char* path;
	envid_t veid;
};

static int dumptmpfs(void *arg)
{
	int i;
	struct args_t *args = arg;
	int *pfd = args->pfd;
	int fd0, fd2;
	char *path = args->path;
	char *argv[] = { "tar", "-c", "-S", "--numeric-owner", path, NULL };

	i = real_env_create(args->veid, VE_ENTER|VE_SKIPLOCK, 2, NULL, 0);
	if (i < 0) {
		eprintk("cannot enter ve to dump tmpfs\n");
		module_put(THIS_MODULE);
		return 255 << 8;
	}

	if (pfd[1] != 1)
		sc_dup2(pfd[1], 1);
	set_fs(KERNEL_DS);
	fd0 = sc_open("/dev/null", O_RDONLY, 0);
	fd2 = sc_open("/dev/null", O_WRONLY, 0);
	if (fd0 < 0 || fd2 < 0) {
		eprintk("can not open /dev/null for tar: %d %d\n", fd0, fd2);
		module_put(THIS_MODULE);
		return 255 << 8;
	}
	if (fd0 != 0)
		sc_dup2(fd0, 0);
	if (fd2 != 2)
		sc_dup2(fd2, 2);

	for (i = 3; i < current->files->fdt->max_fds; i++) {
		sc_close(i);
	}

	module_put(THIS_MODULE);

	i = sc_execve("/bin/tar", argv, NULL);
	eprintk("failed to exec /bin/tar: %d\n", i);
	return 255 << 8;
}

static int cpt_dump_tmpfs(char *path, struct cpt_context *ctx)
{
	int err;
	int pid;
	int pfd[2];
	struct file *f;
	struct cpt_object_hdr v;
	char buf[16];
	int n;
	loff_t saved_obj;
	struct args_t args;
	int status;
	mm_segment_t oldfs;
	sigset_t ignore, blocked;
	struct ve_struct *oldenv;
	
	err = sc_pipe(pfd);
	if (err < 0)
		return err;
	args.pfd = pfd;
	args.path = path;
	args.veid = VEID(get_exec_env());
	ignore.sig[0] = CPT_SIG_IGNORE_MASK;
	sigprocmask(SIG_BLOCK, &ignore, &blocked);
	oldenv = set_exec_env(get_ve0());
	err = pid = local_kernel_thread(dumptmpfs, (void*)&args,
			SIGCHLD | CLONE_VFORK, 0);
	set_exec_env(oldenv);
	if (err < 0) {
		eprintk_ctx("tmpfs local_kernel_thread: %d\n", err);
		goto out;
	}
	f = fget(pfd[0]);
	sc_close(pfd[1]);
	sc_close(pfd[0]);

	cpt_push_object(&saved_obj, ctx);
	cpt_open_object(NULL, ctx);
	v.cpt_next = CPT_NULL;
	v.cpt_object = CPT_OBJ_NAME;
	v.cpt_hdrlen = sizeof(v);
	v.cpt_content = CPT_CONTENT_NAME;

	ctx->write(&v, sizeof(v), ctx);

	do {
		oldfs = get_fs(); set_fs(KERNEL_DS);
		n = f->f_op->read(f, buf, sizeof(buf), &f->f_pos);
		set_fs(oldfs);
		if (n > 0)
			ctx->write(buf, n, ctx);
	} while (n > 0);

	fput(f);

	oldfs = get_fs(); set_fs(KERNEL_DS);
	if ((err = sc_waitx(pid, 0, &status)) < 0)
		eprintk_ctx("wait4: %d\n", err);
	else if ((status & 0x7f) == 0) {
		err = (status & 0xff00) >> 8;
		if (err != 0) {
			eprintk_ctx("tar exited with %d\n", err);
			err = -EINVAL;
		}
	} else {
		eprintk_ctx("tar terminated\n");
		err = -EINVAL;
	}
	set_fs(oldfs);
	sigprocmask(SIG_SETMASK, &blocked, NULL);

	buf[0] = 0;
	ctx->write(buf, 1, ctx);
	ctx->align(ctx);
	cpt_close_object(ctx);
	cpt_pop_object(&saved_obj, ctx);
	return n ? : err;

out:
	if (pfd[1] >= 0)
		sc_close(pfd[1]);
	if (pfd[0] >= 0)
		sc_close(pfd[0]);
	sigprocmask(SIG_SETMASK, &blocked, NULL);
	return err;
}

static int loopy_root(struct vfsmount *mnt)
{
	struct list_head *p;

	list_for_each(p, &mnt->mnt_ns->list) {
		struct vfsmount * m = list_entry(p, struct vfsmount, mnt_list);
		if (m == mnt)
			return 0;
		if (m->mnt_sb == mnt->mnt_sb)
			return 1;
	}
	/* Cannot happen */
	return 0;
}

static int cpt_dump_bind_mnt(struct vfsmount * mnt, cpt_context_t * ctx)
{
	struct list_head *p;
	int err = -EINVAL;

	/* One special case: mount --bind /a /a */
	if (mnt->mnt_root == mnt->mnt_mountpoint)
		return cpt_dump_dentry(mnt->mnt_root, mnt, 0, 0, ctx);

	list_for_each_prev(p, &mnt->mnt_list) {
		struct vfsmount * m;

		if (p == &mnt->mnt_ns->list)
			break;

		m = list_entry(p, struct vfsmount, mnt_list);

		if (m->mnt_sb != mnt->mnt_sb)
			continue;

		err = cpt_dump_dentry(mnt->mnt_root, m, 0, 1, ctx);
		if (err == 0)
			break;
	}
	return err;
}

static int dump_vfsmount(struct vfsmount *mnt, struct cpt_context *ctx)
{
	int err = 0;
	struct cpt_vfsmount_image v;
	loff_t saved_obj;
	char *path_buf, *path;
	struct path p;

	path_buf = (char *) __get_free_page(GFP_KERNEL);
	if (!path_buf)
		return -ENOMEM;

	p.dentry = mnt->mnt_root;
	p.mnt = mnt;
	path = d_path(&p, path_buf, PAGE_SIZE);
	if (IS_ERR(path)) {
		free_page((unsigned long) path_buf);
		return PTR_ERR(path) == -EINVAL ? 0 : PTR_ERR(path);
	}

	cpt_open_object(NULL, ctx);

	v.cpt_next = CPT_NULL;
	v.cpt_object = CPT_OBJ_VFSMOUNT;
	v.cpt_hdrlen = sizeof(v);
	v.cpt_content = CPT_CONTENT_ARRAY;

	v.cpt_mntflags = mnt->mnt_flags;
	if (top_beancounter(slab_ub(mnt)) != top_beancounter(get_exec_ub())) {
		v.cpt_mntflags |= CPT_MNT_EXT;
	} else {
		if (mnt->mnt_root != mnt->mnt_sb->s_root || loopy_root(mnt))
			v.cpt_mntflags |= CPT_MNT_BIND;
	}
	v.cpt_flags = mnt->mnt_sb->s_flags;

	ctx->write(&v, sizeof(v), ctx);

	cpt_push_object(&saved_obj, ctx);
	cpt_dump_string(mnt->mnt_devname ? : "none", ctx);
	cpt_dump_string(path, ctx);
	cpt_dump_string(mnt->mnt_sb->s_type->name, ctx);

	if (v.cpt_mntflags & CPT_MNT_BIND) {
		err = cpt_dump_bind_mnt(mnt, ctx);

		/* Temporary solution for Ubuntu 8.04 */
		if (err == -EINVAL && !strcmp(path, "/dev/.static/dev")) {
			cpt_dump_string("/dev", ctx);
			err = 0;
		}
	}
	else if (!(v.cpt_mntflags & CPT_MNT_EXT)) {

		if (mnt->mnt_sb->s_type->fs_flags & FS_REQUIRES_DEV) {
			eprintk_ctx("Checkpoint supports only nodev fs: %s\n",
				    mnt->mnt_sb->s_type->name);
			err = -EXDEV;
		} else if (!strcmp(mnt->mnt_sb->s_type->name, "tmpfs")) {
			mntget(mnt);
			up_read(&namespace_sem);
			err = cpt_dump_tmpfs(path, ctx);
			down_read(&namespace_sem);
			if (!err && list_empty(&mnt->mnt_list))
				err = -EBUSY;
			mntput(mnt);
		}
	}

	cpt_pop_object(&saved_obj, ctx);

	cpt_close_object(ctx);
	if (!err && mnt->mnt_sb->s_magic == FSMAGIC_VEFS)
		vefs_track_force_stop(mnt->mnt_sb);

	free_page((unsigned long) path_buf);

	return err;
}

static int dump_one_namespace(cpt_object_t *obj, struct cpt_context *ctx)
{
	struct mnt_namespace *n = obj->o_obj;
	struct cpt_object_hdr v;
	struct vfsmount *rootmnt, *p;
	loff_t saved_obj;
	int err = 0;

	cpt_open_object(obj, ctx);

	v.cpt_next = -1;
	v.cpt_object = CPT_OBJ_NAMESPACE;
	v.cpt_hdrlen = sizeof(v);
	v.cpt_content = CPT_CONTENT_ARRAY;

	ctx->write(&v, sizeof(v), ctx);

	cpt_push_object(&saved_obj, ctx);

	down_read(&namespace_sem);
	rootmnt = n->root;
	for (p = rootmnt; p; p = next_mnt(p, rootmnt)) {
		err = dump_vfsmount(p, ctx);
		if (err)
			break;
	}
	up_read(&namespace_sem);

	cpt_pop_object(&saved_obj, ctx);

	cpt_close_object(ctx);

	return err;
}

int cpt_dump_namespace(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	cpt_open_section(ctx, CPT_SECT_NAMESPACE);

	for_each_object(obj, CPT_OBJ_NAMESPACE) {
		int err;

		if ((err = dump_one_namespace(obj, ctx)) != 0)
			return err;
	}

	cpt_close_section(ctx);
	return 0;
}
