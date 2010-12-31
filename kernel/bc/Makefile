#
# User resources part (UBC)
#
# Copyright (C) 2005  SWsoft
# All rights reserved.
#
# Licensing governed by "linux/COPYING.SWsoft" file.

obj-y := sys.o beancounter.o dcache.o kmem.o misc.o \
	 vm_pages.o statd.o oom_kill.o

obj-$(CONFIG_NET) += net.o
obj-$(CONFIG_BC_RSS_ACCOUNTING) += rss_pages.o
obj-$(CONFIG_BC_PROC)  += proc.o
obj-$(CONFIG_BC_IO_ACCOUNTING) += io_acct.o
