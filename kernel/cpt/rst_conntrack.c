/*
 *
 *  kernel/cpt/rst_conntrack.c
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
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/rtnetlink.h>
#include <linux/unistd.h>
#include <linux/ve.h>
#include <linux/vzcalluser.h>
#include <linux/cpt_image.h>
#include <linux/icmp.h>
#include <linux/ip.h>

#if defined(CONFIG_VE_IPTABLES) && \
    (defined(CONFIG_IP_NF_CONNTRACK) || defined(CONFIG_IP_NF_CONNTRACK_MODULE))

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4/ip_conntrack.h>
#include <linux/netfilter_ipv4/ip_nat.h>
#include <linux/netfilter_ipv4/ip_conntrack_protocol.h>
#include <linux/netfilter_ipv4/ip_conntrack_helper.h>
#include <linux/netfilter_ipv4/ip_conntrack_core.h>
#include <linux/netfilter_ipv4/ip_nat_helper.h>
#include <linux/netfilter_ipv4/ip_nat_core.h>

#define ASSERT_READ_LOCK(x) do { } while (0)
#define ASSERT_WRITE_LOCK(x) do { } while (0)


#include "cpt_obj.h"
#include "cpt_context.h"

struct ct_holder
{
	struct ct_holder *next;
	struct ip_conntrack *ct;
	int index;
};

static int decode_tuple(struct cpt_ipct_tuple *v,
			 struct ip_conntrack_tuple *tuple, int dir,
			 cpt_context_t *ctx)
{
	tuple->dst.ip = v->cpt_dst;
	tuple->dst.u.all = v->cpt_dstport;
	if (ctx->image_version < CPT_VERSION_16) {
		/* In 2.6.9 kernel protonum has short type */
		__u16 protonum = *(__u16 *)&v->cpt_protonum;
		if (protonum > 0xff && protonum < 0xffff) {
			eprintk_ctx("tuple: protonum > 255: %u\n", protonum);
			return -EINVAL;
		}
		tuple->dst.protonum = protonum;
		tuple->dst.dir = dir;
	} else {
		tuple->dst.protonum = v->cpt_protonum;
		tuple->dst.dir = v->cpt_dir;
		if (dir != tuple->dst.dir) {
			eprintk_ctx("dir != tuple->dst.dir\n");
			return -EINVAL;
		}
	}

	tuple->src.ip = v->cpt_src;
	tuple->src.u.all = v->cpt_srcport;
	return 0;
}


static int undump_expect_list(struct ip_conntrack *ct,
			      struct cpt_ip_conntrack_image *ci,
			      loff_t pos, struct ct_holder *ct_list,
			      cpt_context_t *ctx)
{
	loff_t end;
	int err;

	end = pos + ci->cpt_next;
	pos += ci->cpt_hdrlen;
	while (pos < end) {
		struct cpt_ip_connexpect_image v;
		struct ip_conntrack_expect *exp;
		struct ip_conntrack *sibling;

		err = rst_get_object(CPT_OBJ_NET_CONNTRACK_EXPECT, pos, &v, ctx);
		if (err)
			return err;

		sibling = NULL;
		if (v.cpt_sibling_conntrack) {
			struct ct_holder *c;

			for (c = ct_list; c; c = c->next) {
				if (c->index == v.cpt_sibling_conntrack) {
					sibling = c->ct;
					break;
				}
			}
			if (!sibling) {
				eprintk_ctx("lost sibling of expectation\n");
				return -EINVAL;
			}
		}

		write_lock_bh(&ip_conntrack_lock);

		/* It is possible. Helper module could be just unregistered,
		 * if expectation were on the list, it would be destroyed. */
		if (ct->helper == NULL) {
			write_unlock_bh(&ip_conntrack_lock);
			dprintk_ctx("conntrack: no helper and non-trivial expectation\n");
			continue;
		}

		exp = ip_conntrack_expect_alloc(NULL);
		if (exp == NULL) {
			write_unlock_bh(&ip_conntrack_lock);
			return -ENOMEM;
		}

		if (decode_tuple(&v.cpt_tuple, &exp->tuple, 0, ctx) ||
		    decode_tuple(&v.cpt_mask, &exp->mask, 0, ctx)) {
			ip_conntrack_expect_put(exp);
			write_unlock_bh(&ip_conntrack_lock);
			return -EINVAL;
		}

		exp->master = ct;
		nf_conntrack_get(&ct->ct_general);
		ip_conntrack_expect_insert(exp);
#if 0
		if (sibling) {
			exp->sibling = sibling;
			sibling->master = exp;
			LIST_DELETE(&ve_ip_conntrack_expect_list, exp);
			ct->expecting--;
			nf_conntrack_get(&master_ct(sibling)->infos[0]);
		} else
#endif
		if (ct->helper->timeout) {
			mod_timer(&exp->timeout, jiffies + v.cpt_timeout);
		}
		write_unlock_bh(&ip_conntrack_lock);

		ip_conntrack_expect_put(exp);

		pos += v.cpt_next;
	}
	return 0;
}

static int undump_one_ct(struct cpt_ip_conntrack_image *ci, loff_t pos,
			 struct ct_holder **ct_list, cpt_context_t *ctx)
{
	int err = 0;
	struct ip_conntrack *conntrack;
	struct ct_holder *c;
	struct ip_conntrack_tuple orig, repl;

	c = kmalloc(sizeof(struct ct_holder), GFP_KERNEL);
	if (c == NULL)
		return -ENOMEM;

	if (decode_tuple(&ci->cpt_tuple[0], &orig, 0, ctx) ||
	    decode_tuple(&ci->cpt_tuple[1], &repl, 1, ctx)) {
		kfree(c);
		return -EINVAL;
	}

	conntrack = ip_conntrack_alloc(&orig, &repl, get_exec_env()->_ip_conntrack->ub);
	if (!conntrack || IS_ERR(conntrack)) {
		kfree(c);
		return -ENOMEM;
	}

	c->ct = conntrack;
	c->next = *ct_list;
	*ct_list = c;
	c->index = ci->cpt_index;

	conntrack->status = ci->cpt_status;

	memcpy(&conntrack->proto, ci->cpt_proto_data, sizeof(conntrack->proto));
	memcpy(&conntrack->help, ci->cpt_help_data, sizeof(conntrack->help));

#if defined(CONFIG_IP_NF_CONNTRACK_MARK)
	conntrack->mark = ci->cpt_mark;
#endif

#ifdef CONFIG_IP_NF_NAT_NEEDED
#if defined(CONFIG_IP_NF_TARGET_MASQUERADE) || \
	defined(CONFIG_IP_NF_TARGET_MASQUERADE_MODULE)
	conntrack->nat.masq_index = ci->cpt_masq_index;
#endif
	if (ci->cpt_initialized) {
		conntrack->nat.info.seq[0].correction_pos = ci->cpt_nat_seq[0].cpt_correction_pos;
		conntrack->nat.info.seq[0].offset_before = ci->cpt_nat_seq[0].cpt_offset_before;
		conntrack->nat.info.seq[0].offset_after = ci->cpt_nat_seq[0].cpt_offset_after;
		conntrack->nat.info.seq[1].correction_pos = ci->cpt_nat_seq[1].cpt_correction_pos;
		conntrack->nat.info.seq[1].offset_before = ci->cpt_nat_seq[1].cpt_offset_before;
		conntrack->nat.info.seq[1].offset_after = ci->cpt_nat_seq[1].cpt_offset_after;
	}
	if (conntrack->status & IPS_NAT_DONE_MASK)
		ip_nat_hash_conntrack(conntrack);
#endif

	if (ci->cpt_ct_helper) {
		conntrack->helper = ip_conntrack_helper_find_get(&conntrack->tuplehash[1].tuple);
		if (conntrack->helper == NULL) {
			eprintk_ctx("conntrack: cannot find helper, some module is not loaded\n");
			err = -EINVAL;
		}
	}

	ip_conntrack_hash_insert(conntrack);
	conntrack->timeout.expires = jiffies + ci->cpt_timeout;

	if (err == 0 && ci->cpt_next > ci->cpt_hdrlen)
		err = undump_expect_list(conntrack, ci, pos, *ct_list, ctx);

	if (conntrack->helper)
		ip_conntrack_helper_put(conntrack->helper);

	return err;
}

static void convert_conntrack_image(struct cpt_ip_conntrack_image *ci)
{
	struct cpt_ip_conntrack_image_compat img;

	memcpy(&img, ci, sizeof(struct cpt_ip_conntrack_image_compat));
	/* 
	 * Size of cpt_help_data in 2.6.9 kernel is 16 bytes,
	 * in 2.6.18 cpt_help_data size is 24 bytes, so zero the rest 8 bytes
	 */
	memset(ci->cpt_help_data + 4, 0, 8);
	ci->cpt_initialized = img.cpt_initialized;
	ci->cpt_num_manips = img.cpt_num_manips;
	memcpy(ci->cpt_nat_manips, img.cpt_nat_manips, sizeof(img.cpt_nat_manips));
	memcpy(ci->cpt_nat_seq, img.cpt_nat_seq, sizeof(img.cpt_nat_seq));
	ci->cpt_masq_index = img.cpt_masq_index;
	/* Id will be assigned in ip_conntrack_hash_insert(), so make it 0 here */
	ci->cpt_id = 0;
	/* mark was not supported in 2.6.9, so set it to default 0 value */
	ci->cpt_mark = 0;

}

int rst_restore_ip_conntrack(struct cpt_context * ctx)
{
	int err = 0;
	loff_t sec = ctx->sections[CPT_SECT_NET_CONNTRACK];
	loff_t endsec;
	struct cpt_section_hdr h;
	struct cpt_ip_conntrack_image ci;
	struct ct_holder *c;
	struct ct_holder *ct_list = NULL;

	if (sec == CPT_NULL)
		return 0;

	if (sizeof(ci.cpt_proto_data) != sizeof(union ip_conntrack_proto)) {
		eprintk_ctx("conntrack module ct->proto version mismatch\n");
		return -EINVAL;
	}

	err = ctx->pread(&h, sizeof(h), ctx, sec);
	if (err)
		return err;
	if (h.cpt_section != CPT_SECT_NET_CONNTRACK || h.cpt_hdrlen < sizeof(h))
		return -EINVAL;

	endsec = sec + h.cpt_next;
	sec += h.cpt_hdrlen;
	while (sec < endsec) {
		err = rst_get_object(CPT_OBJ_NET_CONNTRACK, sec, &ci, ctx);
		if (err)
			break;
		if (ctx->image_version < CPT_VERSION_16)
			convert_conntrack_image(&ci);
		err = undump_one_ct(&ci, sec, &ct_list, ctx);
		if (err)
			break;
		sec += ci.cpt_next;
	}

	while ((c = ct_list) != NULL) {
		ct_list = c->next;
		if (c->ct)
			add_timer(&c->ct->timeout);
		kfree(c);
	}

	return err;
}

#else

#include "cpt_obj.h"
#include "cpt_context.h"

int rst_restore_ip_conntrack(struct cpt_context * ctx)
{
	if (ctx->sections[CPT_SECT_NET_CONNTRACK] != CPT_NULL)
		return -EINVAL;
	return 0;
}

#endif
