#
# Makefile for the kernel block device drivers.
#

CFLAGS_loop.o := $(shell if test -r $(srctree)/include/linux/sched.h; then if sed -e '1,/^struct task_struct {$$/ d' $(srctree)/include/linux/sched.h | sed -e '/^};$$/,$$ d' | grep -q -s 'struct rlimit rlim.RLIM_NLIMITS.;'; then echo "-DOLD_PER_THREAD_RLIMITS"; fi; fi)
CFLAGS_loop.o += $(shell if test -r $(srctree)/include/linux/timer.h; then if ! sed -e '1,/^struct timer_list {$$/ d' $(srctree)/include/linux/timer.h | sed -e '/^};$$/,$$ d' | grep -q -s 'unsigned long data;'; then echo "-DNEW_TIMER_VOID_PTR_PARAM"; fi; fi)
CFLAGS_loop.o += $(shell if test -r $(srctree)/include/linux/buffer_head.h; then if grep -q -s '^void invalidate_bdev.*struct block_device.*int' $(srctree)/include/linux/buffer_head.h; then echo "-DOLD_INVALIDATE_BDEV_INTERFACE"; fi; fi)

# 12 June 2000, Christoph Hellwig <hch@infradead.org>
# Rewritten to use lists instead of if-statements.
# 

obj-$(CONFIG_MAC_FLOPPY)	+= swim3.o
obj-$(CONFIG_BLK_DEV_SWIM)	+= swim_mod.o
obj-$(CONFIG_BLK_DEV_FD)	+= floppy.o
obj-$(CONFIG_AMIGA_FLOPPY)	+= amiflop.o
obj-$(CONFIG_PS3_DISK)		+= ps3disk.o
obj-$(CONFIG_PS3_VRAM)		+= ps3vram.o
obj-$(CONFIG_ATARI_FLOPPY)	+= ataflop.o
obj-$(CONFIG_AMIGA_Z2RAM)	+= z2ram.o
obj-$(CONFIG_BLK_DEV_RAM)	+= brd.o
obj-$(CONFIG_BLK_DEV_LOOP)	+= loop.o
obj-$(CONFIG_BLK_DEV_XD)	+= xd.o
obj-$(CONFIG_BLK_CPQ_DA)	+= cpqarray.o
obj-$(CONFIG_BLK_CPQ_CISS_DA)  += cciss.o
obj-$(CONFIG_BLK_DEV_DAC960)	+= DAC960.o
obj-$(CONFIG_XILINX_SYSACE)	+= xsysace.o
obj-$(CONFIG_CDROM_PKTCDVD)	+= pktcdvd.o
obj-$(CONFIG_MG_DISK)		+= mg_disk.o
obj-$(CONFIG_SUNVDC)		+= sunvdc.o
obj-$(CONFIG_BLK_DEV_OSD)	+= osdblk.o

obj-$(CONFIG_BLK_DEV_UMEM)	+= umem.o
obj-$(CONFIG_BLK_DEV_NBD)	+= nbd.o
obj-$(CONFIG_BLK_DEV_CRYPTOLOOP) += cryptoloop.o
obj-$(CONFIG_VIRTIO_BLK)	+= virtio_blk.o

obj-$(CONFIG_VIODASD)		+= viodasd.o
obj-$(CONFIG_BLK_DEV_SX8)	+= sx8.o
obj-$(CONFIG_BLK_DEV_UB)	+= ub.o
obj-$(CONFIG_BLK_DEV_HD)	+= hd.o

obj-$(CONFIG_XEN_BLKDEV_FRONTEND)	+= xen-blkfront.o
obj-$(CONFIG_BLK_DEV_DRBD)     += drbd/

swim_mod-objs	:= swim.o swim_asm.o
