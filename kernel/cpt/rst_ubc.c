/*
 *
 *  kernel/cpt/rst_ubc.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <bc/beancounter.h>
#include <asm/signal.h>

#include "cpt_obj.h"
#include "cpt_context.h"

struct user_beancounter *rst_lookup_ubc(__u64 pos, struct cpt_context *ctx)
{
	cpt_object_t *obj;

	obj = lookup_cpt_obj_bypos(CPT_OBJ_UBC, pos, ctx);
	if (obj == NULL) {
		eprintk("RST: unknown ub @%Ld\n", (long long)pos);
		return get_beancounter(get_exec_ub());
	}
	return get_beancounter(obj->o_obj);
}

void copy_one_ubparm(struct ubparm *from, struct ubparm *to, int bc_parm_id)
{
	to[bc_parm_id].barrier = from[bc_parm_id].barrier;
	to[bc_parm_id].limit = from[bc_parm_id].limit;
}

void set_one_ubparm_to_max(struct ubparm *ubprm, int bc_parm_id)
{
	ubprm[bc_parm_id].barrier = UB_MAXVALUE;
	ubprm[bc_parm_id].limit = UB_MAXVALUE;
}

static void restore_one_bc_parm(struct cpt_ubparm *dmp, struct ubparm *prm,
		int held)
{
	prm->barrier = (dmp->barrier == CPT_NULL ? UB_MAXVALUE : dmp->barrier);
	prm->limit = (dmp->limit == CPT_NULL ? UB_MAXVALUE : dmp->limit);
	if (held)
		prm->held = dmp->held;
	prm->maxheld = dmp->maxheld;
	prm->minheld = dmp->minheld;
	prm->failcnt = dmp->failcnt;
}

static int restore_one_bc(struct cpt_beancounter_image *v,
		cpt_object_t *obj, struct cpt_context *ctx)
{
	struct user_beancounter *bc;
	cpt_object_t *pobj;
	int resources, i;

	if (v->cpt_parent != CPT_NULL) {
		pobj = lookup_cpt_obj_bypos(CPT_OBJ_UBC, v->cpt_parent, ctx);
		if (pobj == NULL)
			return -ESRCH;
		bc = get_subbeancounter_byid(pobj->o_obj, v->cpt_id, 1);
	} else {
		bc = get_exec_ub();
		while (bc->parent)
			bc = bc->parent;
		get_beancounter(bc);
	}
	if (bc == NULL)
		return -ENOMEM;
	obj->o_obj = bc;

	if (ctx->image_version < CPT_VERSION_18 &&
			CPT_VERSION_MINOR(ctx->image_version) < 1)
		goto out;

	if (v->cpt_content == CPT_CONTENT_ARRAY)
		resources = v->cpt_ub_resources;
	else
		resources = UB_RESOURCES_COMPAT;

	if (resources > UB_RESOURCES)
		return -EINVAL;

	for (i = 0; i < resources; i++) {
		restore_one_bc_parm(v->cpt_parms + i * 2, bc->ub_parms + i, 0);
		restore_one_bc_parm(v->cpt_parms + i * 2 + 1,
				bc->ub_store + i, 1);
	}

out:
	if (!bc->parent)
		for (i = 0; i < UB_RESOURCES; i++)
			copy_one_ubparm(bc->ub_parms, ctx->saved_ubc, i);

	return 0;
}

int rst_undump_ubc(struct cpt_context *ctx)
{
	loff_t start, end;
	struct cpt_beancounter_image *v;
	cpt_object_t *obj;
	int err;

	err = rst_get_section(CPT_SECT_UBC, ctx, &start, &end);
	if (err)
		return err;

	while (start < end) {
		v = cpt_get_buf(ctx);
		err = rst_get_object(CPT_OBJ_UBC, start, v, ctx);
		if (err) {
			cpt_release_buf(ctx);
			return err;
		}

		obj = alloc_cpt_object(GFP_KERNEL, ctx);
		cpt_obj_setpos(obj, start, ctx);
		intern_cpt_object(CPT_OBJ_UBC, obj, ctx);

		err = restore_one_bc(v, obj, ctx);

		cpt_release_buf(ctx);
		if (err)
			return err;

		start += v->cpt_next;
	}
	return 0;
}

void rst_finish_ubc(struct cpt_context *ctx)
{
	cpt_object_t *obj;

	for_each_object(obj, CPT_OBJ_UBC)
		put_beancounter(obj->o_obj);
}
