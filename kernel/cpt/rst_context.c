/*
 *
 *  kernel/cpt/rst_context.c
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
#include <linux/pagemap.h>
#include <linux/cpt_image.h>
#include <linux/cpt_export.h>

#include "cpt_obj.h"
#include "cpt_context.h"
#include "cpt_files.h"

static ssize_t file_read(void *addr, size_t count, struct cpt_context *ctx)
{
	mm_segment_t oldfs;
	ssize_t err = -EBADF;
	struct file *file = ctx->file;

	oldfs = get_fs(); set_fs(KERNEL_DS);
	if (file)
		err = file->f_op->read(file, addr, count, &file->f_pos);
	set_fs(oldfs);
	if (err != count)
		return err >= 0 ? -EIO : err;
	return 0;
}

static ssize_t file_pread(void *addr, size_t count, struct cpt_context *ctx, loff_t pos)
{
	mm_segment_t oldfs;
	ssize_t err = -EBADF;
	struct file *file = ctx->file;

	oldfs = get_fs(); set_fs(KERNEL_DS);
	if (file)
		err = file->f_op->read(file, addr, count, &pos);
	set_fs(oldfs);
	if (err != count)
		return err >= 0 ? -EIO : err;
	return 0;
}

static void file_align(struct cpt_context *ctx)
{
	struct file *file = ctx->file;

	if (file)
		file->f_pos = CPT_ALIGN(file->f_pos);
}

int rst_get_section(int type, struct cpt_context *ctx, loff_t *start, loff_t *end)
{
	struct cpt_section_hdr hdr;
	int err;
	loff_t pos;

	pos = ctx->sections[type];
	*start = *end = pos;

	if (pos != CPT_NULL) {
		if ((err = ctx->pread(&hdr, sizeof(hdr), ctx, pos)) != 0)
			return err;
		if (hdr.cpt_section != type || hdr.cpt_hdrlen < sizeof(hdr))
			return -EINVAL;
		*start = pos + hdr.cpt_hdrlen;
		*end = pos + hdr.cpt_next;
	}
	return 0;
}
EXPORT_SYMBOL(rst_get_section);

void rst_context_init(struct cpt_context *ctx)
{
	int i;

	memset(ctx, 0, sizeof(*ctx));

	init_MUTEX(&ctx->main_sem);
	ctx->refcount = 1;

	ctx->current_section = -1;
	ctx->current_object = -1;
	ctx->pagesize = PAGE_SIZE;
	ctx->read = file_read;
	ctx->pread = file_pread;
	ctx->align = file_align;
	for (i=0; i < CPT_SECT_MAX; i++)
		ctx->sections[i] = CPT_NULL;
#ifdef CONFIG_VZ_CHECKPOINT_LAZY
	init_completion(&ctx->pgin_notify);
#endif
	cpt_object_init(ctx);
}

static int parse_sections(loff_t start, loff_t end, cpt_context_t *ctx)
{
	struct cpt_section_hdr h;

	while (start < end) {
		int err;

		err = ctx->pread(&h, sizeof(h), ctx, start);
		if (err)
			return err;
		if (h.cpt_hdrlen < sizeof(h) ||
		    h.cpt_next < h.cpt_hdrlen ||
		    start + h.cpt_next > end)
			return -EINVAL;
		if (h.cpt_section >= CPT_SECT_MAX)
			return -EINVAL;
		ctx->sections[h.cpt_section] = start;
		start += h.cpt_next;
	}
	return 0;
}

int rst_open_dumpfile(struct cpt_context *ctx)
{
	int err;
	struct cpt_major_tail *v;
	struct cpt_major_hdr  h;
	unsigned long size;

	err = -EBADF;
	if (!ctx->file)
		goto err_out;

	err = -ENOMEM;
	ctx->tmpbuf = (char*)__get_free_page(GFP_KERNEL);
	if (ctx->tmpbuf == NULL)
		goto err_out;
	__cpt_release_buf(ctx);

	size = ctx->file->f_dentry->d_inode->i_size;

	if (size & 7) {
		err = -EINVAL;
		goto err_out;
	}
	if (size < sizeof(struct cpt_major_hdr) +
	    sizeof(struct cpt_major_tail)) {
		err = -EINVAL;
		goto err_out;
	}
	err = ctx->pread(&h, sizeof(h), ctx, 0);
	if (err) {
		eprintk_ctx("too short image 1 %d\n", err);
		goto err_out;
	}
	if (h.cpt_signature[0] != CPT_SIGNATURE0 ||
	    h.cpt_signature[1] != CPT_SIGNATURE1 ||
	    h.cpt_signature[2] != CPT_SIGNATURE2 ||
	    h.cpt_signature[3] != CPT_SIGNATURE3) {
		err = -EINVAL;
		goto err_out;
	}
	if (h.cpt_hz != HZ) {
		err = -EINVAL;
		eprintk_ctx("HZ mismatch: %d != %d\n", h.cpt_hz, HZ);
		goto err_out;
	}
	ctx->virt_jiffies64 = h.cpt_start_jiffies64;
	ctx->start_time.tv_sec = h.cpt_start_sec;
	ctx->start_time.tv_nsec = h.cpt_start_nsec;
	ctx->kernel_config_flags = h.cpt_kernel_config[0];
	ctx->iptables_mask = h.cpt_iptables_mask;
	if (h.cpt_image_version > CPT_CURRENT_VERSION ||
			CPT_VERSION_MINOR(h.cpt_image_version) >
			CPT_VERSION_MINOR(CPT_CURRENT_VERSION)) {
		eprintk_ctx("Unknown image version: %x. Can't restore.\n",
				h.cpt_image_version);
		err = -EINVAL;
		goto err_out;
	}
	ctx->image_version = h.cpt_image_version;
	ctx->features = (__u64)((__u64)h.cpt_ve_features2<<32 | h.cpt_ve_features);
	ctx->image_arch = h.cpt_os_arch;

	v = cpt_get_buf(ctx);
	err = ctx->pread(v, sizeof(*v), ctx, size - sizeof(*v));
	if (err) {
		eprintk_ctx("too short image 2 %d\n", err);
		cpt_release_buf(ctx);
		goto err_out;
	}
	if (v->cpt_signature[0] != CPT_SIGNATURE0 ||
	    v->cpt_signature[1] != CPT_SIGNATURE1 ||
	    v->cpt_signature[2] != CPT_SIGNATURE2 ||
	    v->cpt_signature[3] != CPT_SIGNATURE3 ||
	    v->cpt_nsect != CPT_SECT_MAX_INDEX) {
		err = -EINVAL;
		cpt_release_buf(ctx);
		goto err_out;
	}
	if ((err = parse_sections(h.cpt_hdrlen, size - sizeof(*v) - sizeof(struct cpt_section_hdr), ctx)) < 0) {
		cpt_release_buf(ctx);
		goto err_out;
	}
#ifdef CONFIG_VZ_CHECKPOINT_LAZY
	ctx->lazypages = v->cpt_lazypages;
#endif
	ctx->tasks64 = v->cpt_64bit;
	cpt_release_buf(ctx);
	return 0;

err_out:
	if (ctx->tmpbuf) {
		free_page((unsigned long)ctx->tmpbuf);
		ctx->tmpbuf = NULL;
	}
	return err;
}

void rst_close_dumpfile(struct cpt_context *ctx)
{
	if (ctx->file) {
		fput(ctx->file);
		ctx->file = NULL;
	}
	if (ctx->tmpbuf) {
		free_page((unsigned long)ctx->tmpbuf);
		ctx->tmpbuf = NULL;
	}
}

int _rst_get_object(int type, loff_t pos, void *tmp, int size, struct cpt_context *ctx)
{
	int err;
	struct cpt_object_hdr *hdr = tmp;
	err = ctx->pread(hdr, sizeof(struct cpt_object_hdr), ctx, pos);
	if (err)
		return err;
	if (type > 0 && type != hdr->cpt_object)
		return -EINVAL;
	if (hdr->cpt_hdrlen > hdr->cpt_next)
		return -EINVAL;
	if (hdr->cpt_hdrlen < sizeof(struct cpt_object_hdr))
		return -EINVAL;
	if (size < sizeof(*hdr))
		return -EINVAL;
	if (size > hdr->cpt_hdrlen)
		size = hdr->cpt_hdrlen;
	if (size > sizeof(*hdr))
		err = ctx->pread(hdr+1, size - sizeof(*hdr),
				 ctx, pos + sizeof(*hdr));
	return err;
}
EXPORT_SYMBOL(_rst_get_object);

void * __rst_get_object(int type, loff_t pos, struct cpt_context *ctx)
{
	int err;
	void *tmp;
	struct cpt_object_hdr hdr;
	err = ctx->pread(&hdr, sizeof(hdr), ctx, pos);
	if (err)
		return NULL;
	if (type > 0 && type != hdr.cpt_object)
		return NULL;
	if (hdr.cpt_hdrlen > hdr.cpt_next)
		return NULL;
	if (hdr.cpt_hdrlen < sizeof(struct cpt_object_hdr))
		return NULL;
	tmp = kmalloc(hdr.cpt_hdrlen, GFP_KERNEL);
	if (!tmp)
		return NULL;
	err = ctx->pread(tmp, hdr.cpt_hdrlen, ctx, pos);
	if (!err)
		return tmp;
	kfree(tmp);
	return NULL;
}
EXPORT_SYMBOL(__rst_get_object);

__u8 *__rst_get_name(loff_t *pos_p, struct cpt_context *ctx)
{
	int err;
	struct cpt_object_hdr hdr;
	__u8 *name;

	err = rst_get_object(CPT_OBJ_NAME, *pos_p, &hdr, ctx);
	if (err)
		return NULL;
	if (hdr.cpt_next - hdr.cpt_hdrlen > PAGE_SIZE)
		return NULL;
	name = (void*)__get_free_page(GFP_KERNEL);
	if (!name)
		return NULL;
	err = ctx->pread(name, hdr.cpt_next - hdr.cpt_hdrlen,
		   ctx, *pos_p + hdr.cpt_hdrlen);
	if (err) {
		free_page((unsigned long)name);
		return NULL;
	}
	*pos_p += hdr.cpt_next;
	return name;
}

__u8 *rst_get_name(loff_t pos, struct cpt_context *ctx)
{
	return __rst_get_name(&pos, ctx);
}

void rst_put_name(__u8 *name, struct cpt_context *ctx)
{
	unsigned long addr = (unsigned long)name;

	if (addr)
		free_page(addr&~(PAGE_SIZE-1));
}

struct rst_ops rst_ops = {
	.get_object = _rst_get_object,
	.rst_file = rst_file,
};
