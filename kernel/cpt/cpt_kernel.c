/*
 *
 *  kernel/cpt/cpt_kernel.c
 *
 *  Copyright (C) 2000-2005  SWsoft
 *  All rights reserved.
 *
 *  Licensing governed by "linux/COPYING.SWsoft" file.
 *
 */

#define __KERNEL_SYSCALLS__ 1

#include <linux/version.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#ifdef CONFIG_X86
#include <asm/cpufeature.h>
#endif
#include <linux/cpt_image.h>
#include <linux/virtinfo.h>
#include <linux/virtinfoscp.h>

#include "cpt_kernel.h"
#include "cpt_syscalls.h"

int debug_level = 1;

#ifdef CONFIG_X86_32

/*
 * Create a kernel thread
 */
extern void kernel_thread_helper(void);
int asm_kernel_thread(int (*fn)(void *), void * arg, unsigned long flags, pid_t pid)
{
	struct pt_regs regs;

	memset(&regs, 0, sizeof(regs));

	regs.bx = (unsigned long) fn;
	regs.dx = (unsigned long) arg;

	regs.ds = __USER_DS;
	regs.es = __USER_DS;
	regs.fs = __KERNEL_PERCPU;
	regs.gs = __KERNEL_STACK_CANARY;
	regs.orig_ax = -1;
	regs.ip = (unsigned long) kernel_thread_helper;
	regs.cs = __KERNEL_CS | get_kernel_rpl();
	regs.flags = X86_EFLAGS_IF | X86_EFLAGS_SF | X86_EFLAGS_PF | 0x2;

	/* Ok, create the new process.. */
	return do_fork_pid(flags | CLONE_UNTRACED, 0, &regs, 0, NULL, NULL, pid);
}
#endif

#ifdef CONFIG_IA64
pid_t
asm_kernel_thread (int (*fn)(void *), void *arg, unsigned long flags, pid_t pid)
{
	extern void start_kernel_thread (void);
	unsigned long *helper_fptr = (unsigned long *) &start_kernel_thread;
	struct {
		struct switch_stack sw;
		struct pt_regs pt;
	} regs;

	memset(&regs, 0, sizeof(regs));
	regs.pt.cr_iip = helper_fptr[0];	/* set entry point (IP) */
	regs.pt.r1 = helper_fptr[1];		/* set GP */
	regs.pt.r9 = (unsigned long) fn;	/* 1st argument */
	regs.pt.r11 = (unsigned long) arg;	/* 2nd argument */
	/* Preserve PSR bits, except for bits 32-34 and 37-45, which we can't read.  */
	regs.pt.cr_ipsr = ia64_getreg(_IA64_REG_PSR) | IA64_PSR_BN;
	regs.pt.cr_ifs = 1UL << 63;		/* mark as valid, empty frame */
	regs.sw.ar_fpsr = regs.pt.ar_fpsr = ia64_getreg(_IA64_REG_AR_FPSR);
	regs.sw.ar_bspstore = (unsigned long) current + IA64_RBS_OFFSET;
	regs.sw.pr = (1 << 2 /*PRED_KERNEL_STACK*/);
	return do_fork_pid(flags | CLONE_UNTRACED, 0, &regs.pt, 0, NULL, NULL, pid);
}
#endif

int local_kernel_thread(int (*fn)(void *), void * arg, unsigned long flags, pid_t pid)
{
	pid_t ret;

	if (current->fs == NULL) {
		/* do_fork_pid() hates processes without fs, oopses. */
		printk("CPT BUG: local_kernel_thread: current->fs==NULL\n");
		return -EINVAL;
	}
	if (!try_module_get(THIS_MODULE))
		return -EBUSY;
	while ((ret = asm_kernel_thread(fn, arg, flags, pid)) ==
							-ERESTARTNOINTR)
		cond_resched();
	if (ret < 0)
		module_put(THIS_MODULE);
	return ret;
}

#ifdef __i386__
int __execve(const char *file, char **argv, char **envp)
{
	long res;
	__asm__ volatile ("int $0x80"
	: "=a" (res)
	: "0" (__NR_execve),"b" ((long)(file)),"c" ((long)(argv)),
		  "d" ((long)(envp)) : "memory");
	return (int)res;
}
#endif

int sc_execve(char *cmd, char **argv, char **env)
{
	int ret;
#ifndef __i386__
	ret = kernel_execve(cmd, argv, env);
#else
	ret = __execve(cmd, argv, env);
#endif
	return ret;
}

unsigned int test_cpu_caps_and_features(void)
{
	unsigned int flags = 0;

#ifdef CONFIG_X86
	if (boot_cpu_has(X86_FEATURE_CMOV))
		flags |= 1 << CPT_CPU_X86_CMOV;
	if (cpu_has_fxsr)
		flags |= 1 << CPT_CPU_X86_FXSR;
	if (cpu_has_xmm)
		flags |= 1 << CPT_CPU_X86_SSE;
#ifndef CONFIG_X86_64
	if (cpu_has_xmm2)
#endif
		flags |= 1 << CPT_CPU_X86_SSE2;
	if (cpu_has_mmx)
		flags |= 1 << CPT_CPU_X86_MMX;
	if (boot_cpu_has(X86_FEATURE_3DNOW))
		flags |= 1 << CPT_CPU_X86_3DNOW;
	if (boot_cpu_has(X86_FEATURE_3DNOWEXT))
		flags |= 1 << CPT_CPU_X86_3DNOW2;
	if (boot_cpu_has(X86_FEATURE_SYSCALL))
		flags |= 1 << CPT_CPU_X86_SYSCALL;
#ifdef CONFIG_X86_64
	if (boot_cpu_has(X86_FEATURE_SYSCALL) &&
			boot_cpu_data.x86_vendor != X86_VENDOR_INTEL)
		flags |= 1 << CPT_CPU_X86_SYSCALL32;
#endif
	if (boot_cpu_has(X86_FEATURE_SEP)
#ifdef CONFIG_X86_64
			&& boot_cpu_data.x86_vendor == X86_VENDOR_INTEL
#endif
	   )
		flags |= ((1 << CPT_CPU_X86_SEP) | (1 << CPT_CPU_X86_SEP32));
#ifdef CONFIG_X86_64
	flags |= 1 << CPT_CPU_X86_EMT64;
#endif
#endif
#ifdef CONFIG_IA64
	flags |= 1 << CPT_CPU_X86_IA64;
	flags |= 1 << CPT_CPU_X86_FXSR;
#endif
	if (virtinfo_notifier_call(VITYPE_SCP,
				VIRTINFO_SCP_TEST, NULL) & NOTIFY_FAIL)
		flags |= 1 << CPT_SLM_DMPRST;
	return flags;
}

unsigned int test_kernel_config(void)
{
	unsigned int flags = 0;
#ifdef CONFIG_X86
#if defined(CONFIG_X86_PAE) || defined(CONFIG_X86_64)
	flags |= 1 << CPT_KERNEL_CONFIG_PAE;
#endif
#endif
	return flags;
}
