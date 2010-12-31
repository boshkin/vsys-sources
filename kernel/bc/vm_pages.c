/*
 *  kernel/bc/vm_pages.c
 *
 *  Copyright (C) 2005  SWsoft
 *  All rights reserved.
 *  
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/virtinfo.h>
#include <linux/module.h>
#include <linux/shmem_fs.h>
#include <linux/vmalloc.h>
#include <linux/init.h>

#include <asm/pgtable.h>
#include <asm/page.h>

#include <bc/beancounter.h>
#include <bc/vmpages.h>
#include <bc/proc.h>

static inline unsigned long pages_in_pte_range(struct vm_area_struct *vma,
		pmd_t *pmd, unsigned long addr, unsigned long end,
		unsigned long *ret)
{
	pte_t *pte;
	spinlock_t *ptl;

	pte = pte_offset_map_lock(vma->vm_mm, pmd, addr, &ptl);
	do {
		if (!pte_none(*pte) && pte_present(*pte))
			(*ret)++;
	} while (pte++, addr += PAGE_SIZE, (addr != end));
	pte_unmap_unlock(pte - 1, ptl);

	return addr;
}

static inline unsigned long pages_in_pmd_range(struct vm_area_struct *vma,
		pud_t *pud, unsigned long addr, unsigned long end,
		unsigned long *ret)
{
	pmd_t *pmd;
	unsigned long next;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (pmd_none_or_clear_bad(pmd))
			continue;
		next = pages_in_pte_range(vma, pmd, addr, next, ret);
	} while (pmd++, addr = next, (addr != end));

	return addr;
}

static inline unsigned long pages_in_pud_range(struct vm_area_struct *vma,
		pgd_t *pgd, unsigned long addr, unsigned long end,
		unsigned long *ret)
{
	pud_t *pud;
	unsigned long next;

	pud = pud_offset(pgd, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_none_or_clear_bad(pud))
			continue;
		next = pages_in_pmd_range(vma, pud, addr, next, ret);
	} while (pud++, addr = next, (addr != end));

	return addr;
}

unsigned long pages_in_vma_range(struct vm_area_struct *vma,
		unsigned long addr, unsigned long end)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long ret;

	ret = 0;
	BUG_ON(addr >= end);
	pgd = pgd_offset(vma->vm_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		next = pages_in_pud_range(vma, pgd, addr, next, &ret);
	} while (pgd++, addr = next, (addr != end));
	return ret;
}

void __ub_update_physpages(struct user_beancounter *ub)
{
	ub->ub_parms[UB_PHYSPAGES].held = ub->ub_tmpfs_respages
		+ (ub->ub_held_pages >> UB_PAGE_WEIGHT_SHIFT);
	ub_adjust_maxheld(ub, UB_PHYSPAGES);
}

void __ub_update_oomguarpages(struct user_beancounter *ub)
{
	ub->ub_parms[UB_OOMGUARPAGES].held =
		ub->ub_parms[UB_PHYSPAGES].held +
		ub->ub_parms[UB_SWAPPAGES].held;
	ub_adjust_maxheld(ub, UB_OOMGUARPAGES);
}

void __ub_update_privvm(struct user_beancounter *ub)
{
	ub->ub_parms[UB_PRIVVMPAGES].held =
		(ub->ub_held_pages >> UB_PAGE_WEIGHT_SHIFT)
		+ ub->ub_unused_privvmpages
		+ ub->ub_parms[UB_SHMPAGES].held;
	ub_adjust_maxheld(ub, UB_PRIVVMPAGES);
}

static inline int __charge_privvm_locked(struct user_beancounter *ub, 
		unsigned long s, enum ub_severity strict)
{
	if (__charge_beancounter_locked(ub, UB_PRIVVMPAGES, s, strict) < 0)
		return -ENOMEM;

	ub->ub_unused_privvmpages += s;
	return 0;
}

static void __unused_privvm_dec_locked(struct user_beancounter *ub, 
		long size)
{
	/* catch possible overflow */
	if (ub->ub_unused_privvmpages < size) {
		uncharge_warn(ub, UB_UNUSEDPRIVVM,
				size, ub->ub_unused_privvmpages);
		size = ub->ub_unused_privvmpages;
	}
	ub->ub_unused_privvmpages -= size;
	__ub_update_privvm(ub);
}

void __ub_unused_privvm_dec(struct mm_struct *mm, long size)
{
	unsigned long flags;
	struct user_beancounter *ub;

	ub = mm->mm_ub;
	if (ub == NULL)
		return;

	ub = top_beancounter(ub);
	spin_lock_irqsave(&ub->ub_lock, flags);
	__unused_privvm_dec_locked(ub, size);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

void ub_unused_privvm_sub(struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long count)
{
	if (VM_UB_PRIVATE(vma->vm_flags, vma->vm_file))
		__ub_unused_privvm_dec(mm, count);
}

void ub_unused_privvm_add(struct mm_struct *mm,
		struct vm_area_struct *vma, unsigned long size)
{
	unsigned long flags;
	struct user_beancounter *ub;

	ub = mm->mm_ub;
	if (ub == NULL || !VM_UB_PRIVATE(vma->vm_flags, vma->vm_file))
		return;

	ub = top_beancounter(ub);
	spin_lock_irqsave(&ub->ub_lock, flags);
	ub->ub_unused_privvmpages += size;
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

int ub_protected_charge(struct mm_struct *mm, unsigned long size,
		unsigned long newflags, struct vm_area_struct *vma)
{
	unsigned long flags;
	struct file *file;
	struct user_beancounter *ub;

	ub = mm->mm_ub;
	if (ub == NULL)
		return PRIVVM_NO_CHARGE;

	flags = vma->vm_flags;
	if (!((newflags ^ flags) & VM_WRITE))
		return PRIVVM_NO_CHARGE;

	file = vma->vm_file;
	if (!VM_UB_PRIVATE(newflags | VM_WRITE, file))
		return PRIVVM_NO_CHARGE;

	if (flags & VM_WRITE)
		return PRIVVM_TO_SHARED;

	ub = top_beancounter(ub);
	spin_lock_irqsave(&ub->ub_lock, flags);
	if (__charge_privvm_locked(ub, size, UB_SOFT) < 0)
		goto err;
	spin_unlock_irqrestore(&ub->ub_lock, flags);
	return PRIVVM_TO_PRIVATE;

err:
	spin_unlock_irqrestore(&ub->ub_lock, flags);
	return PRIVVM_ERROR;
}

int ub_memory_charge(struct mm_struct *mm, unsigned long size,
		unsigned vm_flags, struct file *vm_file, int sv)
{
	struct user_beancounter *ub, *ubl;
	unsigned long flags;

	ub = mm->mm_ub;
	if (ub == NULL)
		return 0;

	size >>= PAGE_SHIFT;
	if (size > UB_MAXVALUE)
		return -EINVAL;

	BUG_ON(sv != UB_SOFT && sv != UB_HARD);

	if (vm_flags & VM_LOCKED) {
		if (charge_beancounter(ub, UB_LOCKEDPAGES, size, sv))
			goto out_err;
	}
	if (VM_UB_PRIVATE(vm_flags, vm_file)) {
		ubl = top_beancounter(ub);
		spin_lock_irqsave(&ubl->ub_lock, flags);
		if (__charge_privvm_locked(ubl, size, sv))
			goto out_private;
		spin_unlock_irqrestore(&ubl->ub_lock, flags);
	}
	return 0;

out_private:
	spin_unlock_irqrestore(&ubl->ub_lock, flags);
	if (vm_flags & VM_LOCKED)
		uncharge_beancounter(ub, UB_LOCKEDPAGES, size);
out_err:
	return -ENOMEM;
}

void ub_memory_uncharge(struct mm_struct *mm, unsigned long size,
		unsigned vm_flags, struct file *vm_file)
{
	struct user_beancounter *ub;
	unsigned long flags;

	ub = mm->mm_ub;
	if (ub == NULL)
		return;

	size >>= PAGE_SHIFT;

	if (vm_flags & VM_LOCKED)
		uncharge_beancounter(ub, UB_LOCKEDPAGES, size);
	if (VM_UB_PRIVATE(vm_flags, vm_file)) {
		ub = top_beancounter(ub);
		spin_lock_irqsave(&ub->ub_lock, flags);
		__unused_privvm_dec_locked(ub, size);
		spin_unlock_irqrestore(&ub->ub_lock, flags);
	}
}

int ub_locked_charge(struct mm_struct *mm, unsigned long size)
{
	struct user_beancounter *ub;

	ub = mm->mm_ub;
	if (ub == NULL)
		return 0;

	return charge_beancounter(ub, UB_LOCKEDPAGES,
			size >> PAGE_SHIFT, UB_HARD);
}

void ub_locked_uncharge(struct mm_struct *mm, unsigned long size)
{
	struct user_beancounter *ub;

	ub = mm->mm_ub;
	if (ub == NULL)
		return;

	uncharge_beancounter(ub, UB_LOCKEDPAGES, size >> PAGE_SHIFT);
}

int ub_lockedshm_charge(struct shmem_inode_info *shi, unsigned long size)
{
	struct user_beancounter *ub;

	ub = shi->shmi_ub;
	if (ub == NULL)
		return 0;

	return charge_beancounter(ub, UB_LOCKEDPAGES,
			size >> PAGE_SHIFT, UB_HARD);
}

void ub_lockedshm_uncharge(struct shmem_inode_info *shi, unsigned long size)
{
	struct user_beancounter *ub;

	ub = shi->shmi_ub;
	if (ub == NULL)
		return;

	uncharge_beancounter(ub, UB_LOCKEDPAGES, size >> PAGE_SHIFT);
}


static inline void do_ub_tmpfs_respages_inc(struct user_beancounter *ub)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	ub->ub_tmpfs_respages++;
	__ub_update_physpages(ub);
	__ub_update_oomguarpages(ub);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

void ub_tmpfs_respages_inc(struct shmem_inode_info *shi)
{
	struct user_beancounter *ub;

	for (ub = shi->shmi_ub; ub != NULL; ub = ub->parent)
		do_ub_tmpfs_respages_inc(ub);
}

static inline void do_ub_tmpfs_respages_sub(struct user_beancounter *ub,
		unsigned long size)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	/* catch possible overflow */
	if (ub->ub_tmpfs_respages < size) {
		uncharge_warn(ub, UB_TMPFSPAGES,
				size, ub->ub_tmpfs_respages);
		size = ub->ub_tmpfs_respages;
	}
	ub->ub_tmpfs_respages -= size;
	/* update values what is the most interesting */
	__ub_update_physpages(ub);
	__ub_update_oomguarpages(ub);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

void ub_tmpfs_respages_sub(struct shmem_inode_info *shi,
		unsigned long size)
{
	struct user_beancounter *ub;

	for (ub = shi->shmi_ub; ub != NULL; ub = ub->parent)
		do_ub_tmpfs_respages_sub(ub, size);
}

int ub_shmpages_charge(struct shmem_inode_info *shi, unsigned long size)
{
	int ret;
	unsigned long flags;
	struct user_beancounter *ub;

	ub = shi->shmi_ub;
	if (ub == NULL)
		return 0;

	ub = top_beancounter(ub);
	spin_lock_irqsave(&ub->ub_lock, flags);
	ret = __charge_beancounter_locked(ub, UB_SHMPAGES, size, UB_HARD);
	if (ret == 0)
		__ub_update_privvm(ub);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
	return ret;
}

void ub_shmpages_uncharge(struct shmem_inode_info *shi, unsigned long size)
{
	unsigned long flags;
	struct user_beancounter *ub;

	ub = shi->shmi_ub;
	if (ub == NULL)
		return;

	ub = top_beancounter(ub);
	spin_lock_irqsave(&ub->ub_lock, flags);
	__uncharge_beancounter_locked(ub, UB_SHMPAGES, size);
	__ub_update_privvm(ub);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

#ifdef CONFIG_BC_SWAP_ACCOUNTING
static inline void do_ub_swapentry_inc(struct user_beancounter *ub)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	__charge_beancounter_locked(ub, UB_SWAPPAGES, 1, UB_FORCE);
	__ub_update_oomguarpages(ub);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

void ub_swapentry_inc(struct swap_info_struct *si, pgoff_t num,
		struct user_beancounter *ub)
{
	si->swap_ubs[num] = get_beancounter(ub);
	for (; ub != NULL; ub = ub->parent)
		do_ub_swapentry_inc(ub);
}
EXPORT_SYMBOL(ub_swapentry_inc);

static inline void do_ub_swapentry_dec(struct user_beancounter *ub)
{
	unsigned long flags;

	spin_lock_irqsave(&ub->ub_lock, flags);
	__uncharge_beancounter_locked(ub, UB_SWAPPAGES, 1);
	__ub_update_oomguarpages(ub);
	spin_unlock_irqrestore(&ub->ub_lock, flags);
}

void ub_swapentry_dec(struct swap_info_struct *si, pgoff_t num)
{
	struct user_beancounter *ub, *ubp;

	ub = si->swap_ubs[num];
	si->swap_ubs[num] = NULL;
	for (ubp = ub; ubp != NULL; ubp = ubp->parent)
		do_ub_swapentry_dec(ubp);
	put_beancounter(ub);
}
EXPORT_SYMBOL(ub_swapentry_dec);

int ub_swap_init(struct swap_info_struct *si, pgoff_t num)
{
	struct user_beancounter **ubs;

	ubs = vmalloc(num * sizeof(struct user_beancounter *));
	if (ubs == NULL)
		return -ENOMEM;

	memset(ubs, 0, num * sizeof(struct user_beancounter *));
	si->swap_ubs = ubs;
	return 0;
}

void ub_swap_fini(struct swap_info_struct *si)
{
	if (si->swap_ubs) {
		vfree(si->swap_ubs);
		si->swap_ubs = NULL;
	}
}
#endif

static int vmguar_enough_memory(struct vnotifier_block *self,
		unsigned long event, void *arg, int old_ret)
{
	struct user_beancounter *ub;

	if (event != VIRTINFO_ENOUGHMEM)
		return old_ret;
	/*
	 * If it's a kernel thread, don't care about it.
	 * Added in order aufsd to run smoothly over ramfs.
	 */
	if (!current->mm)
		return NOTIFY_DONE;

	ub = top_beancounter(current->mm->mm_ub);
	if (ub->ub_parms[UB_PRIVVMPAGES].held >
			ub->ub_parms[UB_VMGUARPAGES].barrier)
		return old_ret;

	return NOTIFY_OK;
}

static struct vnotifier_block vmguar_notifier_block = {
	.notifier_call = vmguar_enough_memory
};

static int __init init_vmguar_notifier(void)
{
	virtinfo_notifier_register(VITYPE_GENERAL, &vmguar_notifier_block);
	return 0;
}

static void __exit fini_vmguar_notifier(void)
{
	virtinfo_notifier_unregister(VITYPE_GENERAL, &vmguar_notifier_block);
}

module_init(init_vmguar_notifier);
module_exit(fini_vmguar_notifier);

#ifdef CONFIG_PROC_FS
static int bc_vmaux_show(struct seq_file *f, void *v)
{
	struct user_beancounter *ub;
	unsigned long swap, unmap;
	int i;

	ub = seq_beancounter(f);

	swap = unmap = 0;
	for_each_online_cpu(i) {
		swap += per_cpu_ptr(ub->ub_percpu, i)->swapin;
		unmap += per_cpu_ptr(ub->ub_percpu, i)->unmap;
	}

	seq_printf(f, bc_proc_lu_fmt, ub_rnames[UB_UNUSEDPRIVVM],
			ub->ub_unused_privvmpages);
	seq_printf(f, bc_proc_lu_fmt, ub_rnames[UB_TMPFSPAGES],
			ub->ub_tmpfs_respages);
	seq_printf(f, bc_proc_lu_fmt, "rss", ub->ub_pbcs);

	seq_printf(f, bc_proc_lu_fmt, "swapin", swap);
	seq_printf(f, bc_proc_lu_fmt, "unmap", unmap);
	return 0;
}
static struct bc_proc_entry bc_vmaux_entry = {
	.name = "vmaux",
	.u.show = bc_vmaux_show,
};

static int __init bc_vmaux_init(void)
{
	bc_register_proc_entry(&bc_vmaux_entry);
	return 0;
}

late_initcall(bc_vmaux_init);
#endif
