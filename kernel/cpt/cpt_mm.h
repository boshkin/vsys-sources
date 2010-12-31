int cpt_collect_mm(cpt_context_t *);

int cpt_dump_vm(struct cpt_context *ctx);

__u32 rst_mm_flag(struct cpt_task_image *ti, struct cpt_context *ctx);
int rst_mm_basic(cpt_object_t *obj, struct cpt_task_image *ti, struct cpt_context *ctx);
int rst_mm_complete(struct cpt_task_image *ti, struct cpt_context *ctx);

int cpt_mm_prepare(unsigned long veid);

int cpt_free_pgin_dir(struct cpt_context *);
int cpt_start_pagein(struct cpt_context *);
int rst_setup_pagein(struct cpt_context *);
int rst_complete_pagein(struct cpt_context *, int);
int rst_pageind(struct cpt_context *);
int cpt_iteration(cpt_context_t *ctx);
int rst_iteration(cpt_context_t *ctx);
void rst_drop_iter_dir(cpt_context_t *ctx);
int rst_iter(struct vm_area_struct *vma, u64 pfn,
	     unsigned long addr, cpt_context_t * ctx);

int rst_swapoff(struct cpt_context *);

#ifdef ARCH_HAS_SETUP_ADDITIONAL_PAGES
struct linux_binprm;
extern int arch_setup_additional_pages(struct linux_binprm *bprm, int exstack,
				       unsigned long map_address);
#endif

#ifdef CONFIG_X86
extern struct page *vdso32_pages[1];
#define vsyscall_addr page_address(vdso32_pages[0])
#endif

extern struct vm_operations_struct special_mapping_vmops;
