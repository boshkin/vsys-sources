/*
 *  open_vznet.c
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

/*
 * Virtual Networking device used to change VE ownership on packets
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/seq_file.h>

#include <linux/inet.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <linux/venet.h>

void veip_stop(struct ve_struct *ve)
{
	struct list_head *p, *tmp;

	write_lock_irq(&veip_hash_lock);
	if (ve->veip == NULL)
		goto unlock;
	list_for_each_safe(p, tmp, &ve->veip->ip_lh) {
		struct ip_entry_struct *ptr;
		ptr = list_entry(p, struct ip_entry_struct, ve_list);
		ptr->active_env = NULL;
		list_del(&ptr->ve_list);
		list_del(&ptr->ip_hash);
		kfree(ptr);
	}
	veip_put(ve->veip);
	ve->veip = NULL;
	if (!ve_is_super(ve))
		module_put(THIS_MODULE);
unlock:
	write_unlock_irq(&veip_hash_lock);
}

int veip_start(struct ve_struct *ve)
{
	int err, get;

	err = 0;
	write_lock_irq(&veip_hash_lock);
	get = ve->veip == NULL;
	ve->veip = veip_findcreate(ve->veid);
	if (ve->veip == NULL)
		err = -ENOMEM;
	write_unlock_irq(&veip_hash_lock);
	if (err == 0 && get && !ve_is_super(ve))
		__module_get(THIS_MODULE);
	return err;
}

int veip_entry_add(struct ve_struct *ve, struct ve_addr_struct *addr)
{
	struct ip_entry_struct *entry, *found;
	int err;

	entry = kzalloc(sizeof(struct ip_entry_struct), GFP_KERNEL);
	if (entry == NULL)
		return -ENOMEM;

	if (ve->veip == NULL) {
		/* This can happen if we load venet AFTER ve was started */
	       	err = veip_start(ve);
		if (err < 0)
			goto out;
	}

	write_lock_irq(&veip_hash_lock);
	err = -EADDRINUSE;
	found = venet_entry_lookup(addr);
	if (found != NULL)
		goto out_unlock;

	entry->active_env = ve;
	entry->addr = *addr;
	ip_entry_hash(entry, ve->veip);

	err = 0;
	entry = NULL;
out_unlock:
	write_unlock_irq(&veip_hash_lock);
out:
	if (entry != NULL)
		kfree(entry);
	return err;
}

int veip_entry_del(envid_t veid, struct ve_addr_struct *addr)
{
	struct ip_entry_struct *found;
	int err;

	err = -EADDRNOTAVAIL;
	write_lock_irq(&veip_hash_lock);
	found = venet_entry_lookup(addr);
	if (found == NULL)
		goto out;
	if (found->active_env->veid != veid)
		goto out;

	err = 0;
	found->active_env = NULL;

	list_del(&found->ip_hash);
	list_del(&found->ve_list);
	kfree(found);
out:
	write_unlock_irq(&veip_hash_lock);
	return err;
}

static int skb_extract_addr(struct sk_buff *skb,
		struct ve_addr_struct *addr, int dir)
{
	switch (skb->protocol) {
	case __constant_htons(ETH_P_IP):
		addr->family = AF_INET;
		addr->key[0] = 0;
		addr->key[1] = 0;
		addr->key[2] = 0;
		addr->key[3] = (dir ? ip_hdr(skb)->daddr : ip_hdr(skb)->saddr);
		return 0;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	case __constant_htons(ETH_P_IPV6):
		addr->family = AF_INET6;
		memcpy(&addr->key, dir ?
				ipv6_hdr(skb)->daddr.s6_addr32 :
				ipv6_hdr(skb)->saddr.s6_addr32,
				sizeof(addr->key));
		return 0;
#endif
	}

	return -EAFNOSUPPORT;
}

static struct ve_struct *venet_find_ve(struct sk_buff *skb, int dir)
{
	struct ip_entry_struct *entry;
	struct ve_addr_struct addr;

	if (skb_extract_addr(skb, &addr, dir) < 0)
		return NULL;

	entry = venet_entry_lookup(&addr);
	if (entry == NULL)
		return NULL;

	return entry->active_env;
}

int venet_change_skb_owner(struct sk_buff *skb)
{
	struct ve_struct *ve, *ve_old;

	ve_old = skb->owner_env;

	read_lock(&veip_hash_lock);
	if (!ve_is_super(ve_old)) {
		/* from VE to host */
		ve = venet_find_ve(skb, 0);
		if (ve == NULL)
			goto out_drop;
		if (!ve_accessible_strict(ve, ve_old))
			goto out_source;
		skb->owner_env = get_ve0();
	} else {
		/* from host to VE */
		ve = venet_find_ve(skb, 1);
		if (ve == NULL)
			goto out_drop;
		skb->owner_env = ve;
	}
	read_unlock(&veip_hash_lock);

	return 0;

out_drop:
	read_unlock(&veip_hash_lock);
	return -ESRCH;

out_source:
	read_unlock(&veip_hash_lock);
	if (net_ratelimit() && skb->protocol == __constant_htons(ETH_P_IP)) {
		printk(KERN_WARNING "Dropped packet, source wrong "
		       "veid=%u src-IP=%u.%u.%u.%u "
		       "dst-IP=%u.%u.%u.%u\n",
		       skb->owner_env->veid,
		       NIPQUAD(ip_hdr(skb)->saddr),
		       NIPQUAD(ip_hdr(skb)->daddr));
	}
	return -EACCES;
}

#ifdef CONFIG_PROC_FS
int veip_seq_show(struct seq_file *m, void *v)
{
	struct list_head *p;
	struct ip_entry_struct *entry;
	char s[40];

	p = (struct list_head *)v;
	if (p == ip_entry_hash_table) {
		seq_puts(m, "Version: 2.5\n");
		return 0;
	}
	entry = list_entry(p, struct ip_entry_struct, ip_hash);
	veaddr_print(s, sizeof(s), &entry->addr);
	seq_printf(m, "%39s %10u\n", s, 0);
	return 0;
}
#endif

__exit void veip_cleanup(void)
{
	int i;

	write_lock_irq(&veip_hash_lock);
	for (i = 0; i < VEIP_HASH_SZ; i++)
		while (!list_empty(ip_entry_hash_table + i)) {
			struct ip_entry_struct *entry;

			entry = list_first_entry(ip_entry_hash_table + i,
					struct ip_entry_struct, ip_hash);
			list_del(&entry->ip_hash);
			kfree(entry);
		}
	write_unlock_irq(&veip_hash_lock);
}

MODULE_AUTHOR("SWsoft <info@sw-soft.com>");
MODULE_DESCRIPTION("Virtuozzo Virtual Network Device");
MODULE_LICENSE("GPL v2");
