/*
 *
 *  kernel/cpt/cpt_proc.c
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
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/smp_lock.h>
#include <asm/uaccess.h>
#include <linux/cpt_ioctl.h>
#include <linux/delay.h>

#include "cpt_obj.h"
#include "cpt_context.h"
#include "cpt_dump.h"
#include "cpt_mm.h"
#include "cpt_kernel.h"

MODULE_AUTHOR("Alexey Kuznetsov <alexey@sw.ru>");
MODULE_LICENSE("GPL");

/* List of contexts and lock protecting the list */
static struct list_head cpt_context_list;
static spinlock_t cpt_context_lock;

static int proc_read(char *buffer, char **start, off_t offset,
		     int length, int *eof, void *data)
{
	off_t pos = 0;
	off_t begin = 0;
	int len = 0;
	cpt_context_t *ctx;

	len += sprintf(buffer, "Ctx      Id       VE       State\n");

	spin_lock(&cpt_context_lock);

	list_for_each_entry(ctx, &cpt_context_list, ctx_list) {
		len += sprintf(buffer+len,"%p %08x %-8u %d",
			       ctx,
			       ctx->contextid,
			       ctx->ve_id,
			       ctx->ctx_state
			       );

		buffer[len++] = '\n';

		pos = begin+len;
		if (pos < offset) {
			len = 0;
			begin = pos;
		}
		if (pos > offset+length)
			goto done;
	}
	*eof = 1;

done:
	spin_unlock(&cpt_context_lock);
	*start = buffer + (offset - begin);
	len -= (offset - begin);
	if(len > length)
		len = length;
	if(len < 0)
		len = 0;
	return len;
}

void cpt_context_release(cpt_context_t *ctx)
{
	int i;

	list_del(&ctx->ctx_list);
	spin_unlock(&cpt_context_lock);

	if (ctx->ctx_state > 0)
		cpt_resume(ctx);
	ctx->ctx_state = CPT_CTX_ERROR;

#ifdef CONFIG_VZ_CHECKPOINT_LAZY
	if (ctx->pgin_task)
		put_task_struct(ctx->pgin_task);
	if (ctx->pgin_dir)
		cpt_free_pgin_dir(ctx);
	if (ctx->pagein_file_out)
		fput(ctx->pagein_file_out);
	if (ctx->pagein_file_in)
		fput(ctx->pagein_file_in);
#endif
	if (ctx->objcount)
		eprintk_ctx("%d objects leaked\n", ctx->objcount);
	if (ctx->file)
		fput(ctx->file);
	cpt_flush_error(ctx);
	if (ctx->errorfile) {
		fput(ctx->errorfile);
		ctx->errorfile = NULL;
	}
	for (i = 0; i < ctx->linkdirs_num; i++)
		fput(ctx->linkdirs[i]);
	if (ctx->error_msg) {
		free_page((unsigned long)ctx->error_msg);
		ctx->error_msg = NULL;
	}
	if (ctx->statusfile)
		fput(ctx->statusfile);
	if (ctx->lockfile)
		fput(ctx->lockfile);
	kfree(ctx);

	spin_lock(&cpt_context_lock);
}

static void __cpt_context_put(cpt_context_t *ctx)
{
	if (!--ctx->refcount)
		cpt_context_release(ctx);
}

static void cpt_context_put(cpt_context_t *ctx)
{
	spin_lock(&cpt_context_lock);
	__cpt_context_put(ctx);
	spin_unlock(&cpt_context_lock);
}

cpt_context_t * cpt_context_open(void)
{
	cpt_context_t *ctx;

	if ((ctx = kmalloc(sizeof(*ctx), GFP_KERNEL)) != NULL) {
		cpt_context_init(ctx);
		spin_lock(&cpt_context_lock);
		list_add_tail(&ctx->ctx_list, &cpt_context_list);
		spin_unlock(&cpt_context_lock);
		ctx->error_msg = (char*)__get_free_page(GFP_KERNEL);
		if (ctx->error_msg != NULL)
			ctx->error_msg[0] = 0;
	}
	return ctx;
}

static cpt_context_t * cpt_context_lookup(unsigned int contextid)
{
	cpt_context_t *ctx;

	spin_lock(&cpt_context_lock);
	list_for_each_entry(ctx, &cpt_context_list, ctx_list) {
		if (ctx->contextid == contextid) {
			ctx->refcount++;
			spin_unlock(&cpt_context_lock);
			return ctx;
		}
	}
	spin_unlock(&cpt_context_lock);
	return NULL;
}

int cpt_context_lookup_veid(unsigned int veid)
{
	cpt_context_t *ctx;

	spin_lock(&cpt_context_lock);
	list_for_each_entry(ctx, &cpt_context_list, ctx_list) {
		if (ctx->ve_id == veid && ctx->ctx_state > 0) {
			spin_unlock(&cpt_context_lock);
			return 1;
		}
	}
	spin_unlock(&cpt_context_lock);
	return 0;
}

static int cpt_ioctl(struct inode * inode, struct file * file, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	cpt_context_t *ctx;
	struct file *dfile = NULL;
	int try;

	unlock_kernel();

	if (cmd == CPT_VMPREP) {
#ifdef CONFIG_VZ_CHECKPOINT_LAZY
		err = cpt_mm_prepare(arg);
#else
		err = -EINVAL;
#endif
		goto out_lock;
	}

	if (cmd == CPT_TEST_CAPS) {
		unsigned int src_flags, dst_flags = arg;

		err = 0;
		src_flags = test_cpu_caps_and_features();
		test_one_flag_old(src_flags, dst_flags, CPT_CPU_X86_CMOV, "cmov", err);
		test_one_flag_old(src_flags, dst_flags, CPT_CPU_X86_FXSR, "fxsr", err);
		test_one_flag_old(src_flags, dst_flags, CPT_CPU_X86_SSE, "sse", err);
		test_one_flag_old(src_flags, dst_flags, CPT_CPU_X86_SSE2, "sse2", err);
		test_one_flag_old(src_flags, dst_flags, CPT_CPU_X86_MMX, "mmx", err);
		test_one_flag_old(src_flags, dst_flags, CPT_CPU_X86_3DNOW, "3dnow", err);
		test_one_flag_old(src_flags, dst_flags, CPT_CPU_X86_3DNOW2, "3dnowext", err);
		test_one_flag_old(src_flags, dst_flags, CPT_CPU_X86_SEP, "sysenter", err);
		goto out_lock;
	}

	if (cmd == CPT_JOIN_CONTEXT || cmd == CPT_PUT_CONTEXT) {
		cpt_context_t *old_ctx;

		ctx = NULL;
		if (cmd == CPT_JOIN_CONTEXT) {
			err = -ENOENT;
			ctx = cpt_context_lookup(arg);
			if (!ctx)
				goto out_lock;
		}

		spin_lock(&cpt_context_lock);
		old_ctx = (cpt_context_t*)file->private_data;
		file->private_data = ctx;

		if (old_ctx) {
			if (cmd == CPT_PUT_CONTEXT && old_ctx->sticky) {
				old_ctx->sticky = 0;
				old_ctx->refcount--;
			}
			__cpt_context_put(old_ctx);
		}
		spin_unlock(&cpt_context_lock);
		err = 0;
		goto out_lock;
	}

	spin_lock(&cpt_context_lock);
	ctx = (cpt_context_t*)file->private_data;
	if (ctx)
		ctx->refcount++;
	spin_unlock(&cpt_context_lock);

	if (!ctx) {
		cpt_context_t *old_ctx;

		err = -ENOMEM;
		ctx = cpt_context_open();
		if (!ctx)
			goto out_lock;

		spin_lock(&cpt_context_lock);
		old_ctx = (cpt_context_t*)file->private_data;
		if (!old_ctx) {
			ctx->refcount++;
			file->private_data = ctx;
		} else {
			old_ctx->refcount++;
		}
		if (old_ctx) {
			__cpt_context_put(ctx);
			ctx = old_ctx;
		}
		spin_unlock(&cpt_context_lock);
	}

	if (cmd == CPT_GET_CONTEXT) {
		unsigned int contextid = (unsigned int)arg;

		if (ctx->contextid && ctx->contextid != contextid) {
			err = -EINVAL;
			goto out_nosem;
		}
		if (!ctx->contextid) {
			cpt_context_t *c1 = cpt_context_lookup(contextid);
			if (c1) {
				cpt_context_put(c1);
				err = -EEXIST;
				goto out_nosem;
			}
			ctx->contextid = contextid;
		}
		spin_lock(&cpt_context_lock);
		if (!ctx->sticky) {
			ctx->sticky = 1;
			ctx->refcount++;
		}
		spin_unlock(&cpt_context_lock);
		goto out_nosem;
	}

	down(&ctx->main_sem);

	err = -EBUSY;
	if (ctx->ctx_state < 0)
		goto out;

	err = 0;
	switch (cmd) {
	case CPT_SET_DUMPFD:
		if (ctx->ctx_state == CPT_CTX_DUMPING) {
			err = -EBUSY;
			break;
		}
		if (arg >= 0) {
			err = -EBADF;
			dfile = fget(arg);
			if (dfile == NULL)
				break;
			if (dfile->f_op == NULL ||
			    dfile->f_op->write == NULL) {
				fput(dfile);
				break;
			}
			err = 0;
		}
		if (ctx->file)
			fput(ctx->file);
		ctx->file = dfile;
		break;
	case CPT_LINKDIR_ADD:
		if (ctx->linkdirs_num >= CPT_MAX_LINKDIRS) {
			err = -EMLINK;
			break;
		}

		dfile = fget(arg);
		if (!dfile) {
			err = -EBADFD;
			break;
		}

		if (!S_ISDIR(dfile->f_dentry->d_inode->i_mode)) {
			err = -ENOTDIR;
			fput(dfile);
			break;
		}

		ctx->linkdirs[ctx->linkdirs_num++] = dfile;
		break;
	case CPT_SET_ERRORFD:
		if (arg >= 0) {
			dfile = fget(arg);
			if (dfile == NULL) {
				err = -EBADF;
				break;
			}
		}
		if (ctx->errorfile)
			fput(ctx->errorfile);
		ctx->errorfile = dfile;
		break;
#ifdef CONFIG_VZ_CHECKPOINT_LAZY
	case CPT_SET_PAGEINFDIN:
		if (arg >= 0) {
			dfile = fget(arg);
			if (dfile == NULL) {
				err = -EBADF;
				break;
			}
		}
		if (ctx->pagein_file_in)
			fput(ctx->pagein_file_in);
		ctx->pagein_file_in = dfile;
		break;
	case CPT_SET_PAGEINFDOUT:
		if (arg >= 0) {
			dfile = fget(arg);
			if (dfile == NULL) {
				err = -EBADF;
				break;
			}
		}
		if (ctx->pagein_file_out)
			fput(ctx->pagein_file_out);
		ctx->pagein_file_out = dfile;
		break;
	case CPT_SET_LAZY:
		ctx->lazy_vm = arg;
		break;
	case CPT_ITER:
		err = cpt_iteration(ctx);
		break;
	case CPT_PAGEIND:
		err = cpt_start_pagein(ctx);
		break;
#endif
	case CPT_SET_VEID:
		if (ctx->ctx_state > 0) {
			err = -EBUSY;
			break;
		}
		ctx->ve_id = arg;
		break;
	case CPT_SET_CPU_FLAGS:
		if (ctx->ctx_state > 0) {
			err = -EBUSY;
			break;
		}
		ctx->dst_cpu_flags = arg;
		ctx->src_cpu_flags = test_cpu_caps_and_features();
		break;
	case CPT_SUSPEND:
		if (cpt_context_lookup_veid(ctx->ve_id) ||
		    ctx->ctx_state > 0) {
			err = -EBUSY;
			break;
		}
		ctx->ctx_state = CPT_CTX_SUSPENDING;
		try = 0;
		do {
			err = cpt_vps_suspend(ctx);
			if (err)
				cpt_resume(ctx);
			if (err == -EAGAIN)
				msleep(1000);
			try++;
		} while (err == -EAGAIN && try < 3);
		if (err) {
			ctx->ctx_state = CPT_CTX_IDLE;
		} else {
			ctx->ctx_state = CPT_CTX_SUSPENDED;
		}
		break;
	case CPT_DUMP:
		if (!ctx->ctx_state) {
			err = -ENOENT;
			break;
		}
		if (!ctx->file) {
			err = -EBADF;
			break;
		}
		err = cpt_dump(ctx);
		break;
	case CPT_RESUME:
		if (ctx->ctx_state == CPT_CTX_IDLE) {
			err = -ENOENT;
			break;
		}
		err = cpt_resume(ctx);
		if (!err)
			ctx->ctx_state = CPT_CTX_IDLE;
		break;
	case CPT_KILL:
		if (ctx->ctx_state == CPT_CTX_IDLE) {
			err = -ENOENT;
			break;
		}
		err = cpt_kill(ctx);
		if (!err)
			ctx->ctx_state = CPT_CTX_IDLE;
		break;
	case CPT_TEST_VECAPS:
	{
		__u32 dst_flags = arg;
		__u32 src_flags;

		err = cpt_vps_caps(ctx, &src_flags);
		if (err)
			break;

		test_one_flag(src_flags, dst_flags, CPT_CPU_X86_CMOV, "cmov", err);
		test_one_flag(src_flags, dst_flags, CPT_CPU_X86_FXSR, "fxsr", err);
		test_one_flag(src_flags, dst_flags, CPT_CPU_X86_SSE, "sse", err);
		test_one_flag(src_flags, dst_flags, CPT_CPU_X86_SSE2, "sse2", err);
		test_one_flag(src_flags, dst_flags, CPT_CPU_X86_MMX, "mmx", err);
		test_one_flag(src_flags, dst_flags, CPT_CPU_X86_3DNOW, "3dnow", err);
		test_one_flag(src_flags, dst_flags, CPT_CPU_X86_3DNOW2, "3dnowext", err);
		test_one_flag(src_flags, dst_flags, CPT_CPU_X86_SEP, "sysenter", err);
		test_one_flag(src_flags, dst_flags, CPT_CPU_X86_EMT64, "emt64", err);
		test_one_flag(src_flags, dst_flags, CPT_CPU_X86_IA64, "ia64", err);
		test_one_flag(src_flags, dst_flags, CPT_CPU_X86_SYSCALL, "syscall", err);
		test_one_flag(src_flags, dst_flags, CPT_CPU_X86_SYSCALL32, "syscall32", err);
		if (dst_flags & (1 << CPT_SLM_DMPRST)) {
			eprintk_ctx("SLM is enabled on destination node, but slm_dmprst module is not loaded\n");
			err = 1;
		}

		if (src_flags & CPT_UNSUPPORTED_MASK)
			err = 2;
		break;
	}
	default:
		err = -EINVAL;
		break;
	}

out:
	cpt_flush_error(ctx);
	up(&ctx->main_sem);
out_nosem:
	cpt_context_put(ctx);
out_lock:
	lock_kernel();
	if (err == -ERESTARTSYS || err == -ERESTARTNOINTR ||
	    err == -ERESTARTNOHAND || err == -ERESTART_RESTARTBLOCK)
		err = -EINTR;
	return err;
}

static int cpt_open(struct inode *inode, struct file *file)
{
	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	return 0;
}

static int cpt_release(struct inode * inode, struct file * file)
{
	cpt_context_t *ctx;

	spin_lock(&cpt_context_lock);
	ctx = (cpt_context_t*)file->private_data;
	file->private_data = NULL;

	if (ctx)
		__cpt_context_put(ctx);
	spin_unlock(&cpt_context_lock);

	module_put(THIS_MODULE);
	return 0;
}


static struct file_operations cpt_fops = {
	.owner	 = THIS_MODULE,
	.open    = cpt_open,
	.release = cpt_release,
	.ioctl	 = cpt_ioctl,
};

static struct proc_dir_entry *proc_ent;

static struct ctl_table_header *ctl_header;

static ctl_table debug_table[] = {
	{
		.procname	= "cpt",
		.data		= &debug_level,
		.maxlen		= sizeof(debug_level),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec,
	},
	{ .ctl_name = 0 }
};
static ctl_table root_table[] = {
	{
		.ctl_name	= CTL_DEBUG,
		.procname	= "debug",
		.mode		= 0555,
		.child		= debug_table,
	},
	{ .ctl_name = 0 }
};

static int __init init_cpt(void)
{
	int err;

	err = -ENOMEM;
	ctl_header = register_sysctl_table(root_table);
	if (!ctl_header)
		goto err_mon;

	spin_lock_init(&cpt_context_lock);
	INIT_LIST_HEAD(&cpt_context_list);

	err = -EINVAL;
	proc_ent = proc_create("cpt", 0600, NULL, NULL);
	if (!proc_ent)
		goto err_out;

	cpt_fops.read = proc_ent->proc_fops->read;
	cpt_fops.write = proc_ent->proc_fops->write;
	cpt_fops.llseek = proc_ent->proc_fops->llseek;
	proc_ent->proc_fops = &cpt_fops;

	proc_ent->read_proc = proc_read;
	proc_ent->data = NULL;
	return 0;

err_out:
	unregister_sysctl_table(ctl_header);
err_mon:
	return err;
}
module_init(init_cpt);

static void __exit exit_cpt(void)
{
	remove_proc_entry("cpt", NULL);
	unregister_sysctl_table(ctl_header);

	spin_lock(&cpt_context_lock);
	while (!list_empty(&cpt_context_list)) {
		cpt_context_t *ctx;
		ctx = list_entry(cpt_context_list.next, cpt_context_t, ctx_list);

		if (!ctx->sticky)
			ctx->refcount++;
		ctx->sticky = 0;

		BUG_ON(ctx->refcount != 1);

		__cpt_context_put(ctx);
	}
	spin_unlock(&cpt_context_lock);
}
module_exit(exit_cpt);
