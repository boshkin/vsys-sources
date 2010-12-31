/*
 *  linux/drivers/block/loop.c
 *
 *  Written by Theodore Ts'o, 3/29/93
 *
 * Copyright 1993 by Theodore Ts'o.  Redistribution of this file is
 * permitted under the GNU General Public License.
 *
 * DES encryption plus some minor changes by Werner Almesberger, 30-MAY-1993
 * more DES encryption plus IDEA encryption by Nicholas J. Leon, June 20, 1996
 *
 * Modularized and updated for 1.1.16 kernel - Mitch Dsouza 28th May 1994
 * Adapted for 1.3.59 kernel - Andries Brouwer, 1 Feb 1996
 *
 * Fixed do_loop_request() re-entrancy - Vincent.Renardias@waw.com Mar 20, 1997
 *
 * Added devfs support - Richard Gooch <rgooch@atnf.csiro.au> 16-Jan-1998
 *
 * Handle sparse backing files correctly - Kenn Humborg, Jun 28, 1998
 *
 * Loadable modules and other fixes by AK, 1998
 *
 * Make real block number available to downstream transfer functions, enables
 * CBC (and relatives) mode encryption requiring unique IVs per data block.
 * Reed H. Petty, rhp@draper.net
 *
 * Maximum number of loop devices now dynamic via max_loop module parameter.
 * Russell Kroll <rkroll@exploits.org> 19990701
 *
 * Maximum number of loop devices when compiled-in now selectable by passing
 * max_loop=<1-255> to the kernel on boot.
 * Erik I. Bolsø, <eriki@himolde.no>, Oct 31, 1999
 *
 * Completely rewrite request handling to be make_request_fn style and
 * non blocking, pushing work to a helper thread. Lots of fixes from
 * Al Viro too.
 * Jens Axboe <axboe@suse.de>, Nov 2000
 *
 * Support up to 256 loop devices
 * Heinz Mauelshagen <mge@sistina.com>, Feb 2002
 *
 * AES transfer added. IV is now passed as (512 byte) sector number.
 * Jari Ruusu, May 18 2001
 *
 * External encryption module locking bug fixed.
 * Ingo Rohloff <rohloff@in.tum.de>, June 21 2001
 *
 * Make device backed loop work with swap (pre-allocated buffers + queue rewrite).
 * Jari Ruusu, September 2 2001
 *
 * Ported 'pre-allocated buffers + queue rewrite' to BIO for 2.5 kernels
 * Ben Slusky <sluskyb@stwing.org>, March 1 2002
 * Jari Ruusu, March 27 2002
 *
 * File backed code now uses file->f_op->read/write. Based on Andrew Morton's idea.
 * Jari Ruusu, May 23 2002
 *
 * Exported hard sector size correctly, fixed file-backed-loop-on-tmpfs bug,
 * plus many more enhancements and optimizations.
 * Adam J. Richter <adam@yggdrasil.com>, Aug 2002
 *
 * Added support for removing offset from IV computations.
 * Jari Ruusu, September 21 2003
 *
 * Added support for MD5 IV computation and multi-key operation.
 * Jari Ruusu, October 8 2003
 *
 *
 * Still To Fix:
 * - Advisory locking is ignored here.
 * - Should use an own CAP_* category instead of CAP_SYS_ADMIN
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/bio.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/wait.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/init.h>
#ifdef CONFIG_DEVFS_FS
# include <linux/devfs_fs_kernel.h>
#endif
#include <linux/smp_lock.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/loop.h>
#include <linux/suspend.h>
#include <linux/writeback.h>
#include <linux/buffer_head.h>		/* for invalidate_bdev() */
#include <linux/completion.h>
#if LINUX_VERSION_CODE >= 0x20613
# include <linux/kthread.h>
#endif
#if defined(CONFIG_COMPAT) && defined(HAVE_COMPAT_IOCTL)
# include <linux/compat.h>
#endif
#if LINUX_VERSION_CODE >= 0x20606
# include <linux/mqueue.h>
#endif
#include <linux/spinlock.h>

#include <asm/uaccess.h>
#include <asm/byteorder.h>
#if (defined(CONFIG_BLK_DEV_LOOP_PADLOCK) || defined(CONFIG_BLK_DEV_LOOP_INTELAES)) && (defined(CONFIG_X86) || defined(CONFIG_X86_64))
# include <asm/processor.h>
#endif
#if defined(CONFIG_BLK_DEV_LOOP_INTELAES) && (defined(CONFIG_X86) || defined(CONFIG_X86_64))
# include <asm/i387.h>
#endif

#if defined(CONFIG_X86) && !defined(CONFIG_X86_64)
# define X86_ASM  1
#endif
#if defined(CONFIG_X86_64)
# define AMD64_ASM  1
#endif

#include "../misc/aes.h"
#include "../misc/md5.h"

#if defined(CONFIG_COMPAT) && !defined(HAVE_COMPAT_IOCTL)
# include <linux/ioctl32.h>
# define IOCTL32_COMPATIBLE_PTR ((void*)0)
#endif

#if LINUX_VERSION_CODE >= 0x20614
# define LOOP_COMPAT_F_DENTRY f_path.dentry
#else
# define LOOP_COMPAT_F_DENTRY f_dentry
#endif

#if (LINUX_VERSION_CODE < 0x20609) || defined(QUEUE_FLAG_ORDERED)
# define QUEUE_ORDERED_NONE  0
#endif

#if (LINUX_VERSION_CODE >= 0x20618) || defined(bio_empty_barrier)
# define LOOP_IO_END_RETURN_VOID_TYPE  1
#endif

#if (LINUX_VERSION_CODE >= 0x20609) && (LINUX_VERSION_CODE < 0x20618) && !defined(bio_empty_barrier)
# define LOOP_HAVE_ISSUE_FLUSH_FN  1
#endif

static int max_loop = 8;

#ifdef MODULE
module_param(max_loop, int, 0);
MODULE_PARM_DESC(max_loop, "Maximum number of loop devices (1-256)");
#else
static int __init max_loop_setup(char *str)
{
	int y;

	if (get_option(&str, &y) == 1)
		max_loop = y;
	return 1;
}
__setup("max_loop=", max_loop_setup);
#endif

static struct gendisk **disks;

/*
 * Transfer functions
 */
static int transfer_none(struct loop_device *lo, int cmd, char *raw_buf,
			 char *loop_buf, int size, sector_t real_block)
{
	/* this code is only called from file backed loop  */
	/* and that code expects this function to be no-op */

	cond_resched();
	return 0;
}

static int transfer_xor(struct loop_device *lo, int cmd, char *raw_buf,
			char *loop_buf, int size, sector_t real_block)
{
	char	*in, *out, *key;
	int	i, keysize;

	if (cmd == READ) {
		in = raw_buf;
		out = loop_buf;
	} else {
		in = loop_buf;
		out = raw_buf;
	}

	key = lo->lo_encrypt_key;
	keysize = lo->lo_encrypt_key_size;
	for (i = 0; i < size; i++)
		*out++ = *in++ ^ key[(i & 511) % keysize];
	cond_resched();
	return 0;
}

static int xor_init(struct loop_device *lo, struct loop_info64 *info)
{
	if (info->lo_encrypt_key_size <= 0)
		return -EINVAL;
	return 0;
}

static struct loop_func_table none_funcs = {
	.number = LO_CRYPT_NONE,
	.transfer = transfer_none,
};

static struct loop_func_table xor_funcs = {
	.number = LO_CRYPT_XOR,
	.transfer = transfer_xor,
	.init = xor_init,
};

#ifdef CONFIG_BLK_DEV_LOOP_AES
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
# define KEY_ALLOC_COUNT  128
#else
# define KEY_ALLOC_COUNT  64
#endif

typedef struct {
    aes_context *keyPtr[KEY_ALLOC_COUNT];
    unsigned    keyMask;
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    u_int32_t   *partialMD5;
    u_int32_t   partialMD5buf[8];
    rwlock_t    rwlock;
    unsigned    reversed;
    unsigned    blocked;
    struct timer_list timer;
#else
    u_int32_t   partialMD5[4];
#endif
#if defined(CONFIG_BLK_DEV_LOOP_PADLOCK) && (defined(CONFIG_X86) || defined(CONFIG_X86_64))
    u_int32_t   padlock_cw_e;
    u_int32_t   padlock_cw_d;
#endif
} AESmultiKey;

#if (defined(CONFIG_BLK_DEV_LOOP_PADLOCK) || defined(CONFIG_BLK_DEV_LOOP_INTELAES)) && (defined(CONFIG_X86) || defined(CONFIG_X86_64))
/* This function allocates AES context structures at special address such */
/* that returned address % 16 == 8 . That way expanded encryption and */
/* decryption keys in AES context structure are always 16 byte aligned */
static void *specialAligned_kmalloc(size_t size, unsigned int flags)
{
    void *pn, **ps;
    pn = kmalloc(size + (16 + 8), flags);
    if(!pn) return (void *)0;
    ps = (void **)((((unsigned long)pn + 15) & ~((unsigned long)15)) + 8);
    *(ps - 1) = pn;
    return (void *)ps;
}
static void specialAligned_kfree(void *ps)
{
    if(ps) kfree(*((void **)ps - 1));
}
# define specialAligned_ctxSize     ((sizeof(aes_context) + 15) & ~15)
#else
# define specialAligned_kmalloc     kmalloc
# define specialAligned_kfree       kfree
# define specialAligned_ctxSize     sizeof(aes_context)
#endif

#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
static void keyScrubWork(AESmultiKey *m)
{
    aes_context *a0, *a1;
    u_int32_t *p;
    int x, y, z;

    z = m->keyMask + 1;
    for(x = 0; x < z; x++) {
        a0 = m->keyPtr[x];
        a1 = m->keyPtr[x + z];
        memcpy(a1, a0, sizeof(aes_context));
        m->keyPtr[x] = a1;
        m->keyPtr[x + z] = a0;
        p = (u_int32_t *) a0;
        y = sizeof(aes_context) / sizeof(u_int32_t);
        while(y > 0) {
            *p ^= 0xFFFFFFFF;
            p++;
            y--;
        }
    }

    x = m->reversed;    /* x is 0 or 4 */
    m->reversed ^= 4;
    y = m->reversed;    /* y is 4 or 0 */
    p = &m->partialMD5buf[x];
    memcpy(&m->partialMD5buf[y], p, 16);
    m->partialMD5 = &m->partialMD5buf[y];
    p[0] ^= 0xFFFFFFFF;
    p[1] ^= 0xFFFFFFFF;
    p[2] ^= 0xFFFFFFFF;
    p[3] ^= 0xFFFFFFFF;

    /* try to flush dirty cache data to RAM */
#if !defined(CONFIG_XEN) && (defined(CONFIG_X86_64) || (defined(CONFIG_X86) && !defined(CONFIG_M386) && !defined(CONFIG_CPU_386)))
    __asm__ __volatile__ ("wbinvd": : :"memory");
#else
    mb();
#endif
}

/* called only from loop thread process context */
static void keyScrubThreadFn(AESmultiKey *m)
{
    write_lock(&m->rwlock);
    if(!m->blocked) keyScrubWork(m);
    write_unlock(&m->rwlock);
}

#if defined(NEW_TIMER_VOID_PTR_PARAM)
# define KeyScrubTimerFnParamType void *
#else
# define KeyScrubTimerFnParamType unsigned long
#endif

static void keyScrubTimerFn(KeyScrubTimerFnParamType);

static void keyScrubTimerInit(struct loop_device *lo)
{
    AESmultiKey     *m;
    unsigned long   expire;

    m = (AESmultiKey *)lo->key_data;
    expire = jiffies + HZ;
    init_timer(&m->timer);
    m->timer.expires = expire;
    m->timer.data = (KeyScrubTimerFnParamType)lo;
    m->timer.function = keyScrubTimerFn;
    add_timer(&m->timer);
}

/* called only from timer handler context */
static void keyScrubTimerFn(KeyScrubTimerFnParamType d)
{
    struct loop_device *lo = (struct loop_device *)d;
    extern void loop_add_keyscrub_fn(struct loop_device *, void (*)(void *), void *);

    /* rw lock needs process context, so make loop thread do scrubbing */
    loop_add_keyscrub_fn(lo, (void (*)(void*))keyScrubThreadFn, lo->key_data);
    /* start timer again */
    keyScrubTimerInit(lo);
}
#endif

static AESmultiKey *allocMultiKey(void)
{
    AESmultiKey *m;
    aes_context *a;
    int x = 0, n;

    m = (AESmultiKey *) kmalloc(sizeof(AESmultiKey), GFP_KERNEL);
    if(!m) return 0;
    memset(m, 0, sizeof(AESmultiKey));
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    m->partialMD5 = &m->partialMD5buf[0];
    rwlock_init(&m->rwlock);
    init_timer(&m->timer);
    again:
#endif

    n = PAGE_SIZE / specialAligned_ctxSize;
    if(!n) n = 1;

    a = (aes_context *) specialAligned_kmalloc(specialAligned_ctxSize * n, GFP_KERNEL);
    if(!a) {
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
        if(x) specialAligned_kfree(m->keyPtr[0]);
#endif
        kfree(m);
        return 0;
    }

    while((x < KEY_ALLOC_COUNT) && n) {
        m->keyPtr[x] = a;
        a = (aes_context *)((unsigned char *)a + specialAligned_ctxSize);
        x++;
        n--;
    }
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    if(x < 2) goto again;
#endif
    return m;
}

static void clearAndFreeMultiKey(AESmultiKey *m)
{
    aes_context *a;
    int x, n;

#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    /* stop scrub timer. loop thread was killed earlier */
    del_timer_sync(&m->timer);
    /* make sure allocated keys are in original order */
    if(m->reversed) keyScrubWork(m);
#endif
    n = PAGE_SIZE / specialAligned_ctxSize;
    if(!n) n = 1;

    x = 0;
    while(x < KEY_ALLOC_COUNT) {
        a = m->keyPtr[x];
        if(!a) break;
        memset(a, 0, specialAligned_ctxSize * n);
        specialAligned_kfree(a);
        x += n;
    }

    memset(m, 0, sizeof(AESmultiKey));
    kfree(m);
}

static int multiKeySetup(struct loop_device *lo, unsigned char *k, int version3)
{
    AESmultiKey *m;
    aes_context *a;
    int x, y, n, err = 0;
    union {
        u_int32_t     w[16];
        unsigned char b[64];
    } un;

#if LINUX_VERSION_CODE >= 0x2061c
    if(lo->lo_key_owner != current_uid() && !capable(CAP_SYS_ADMIN))
        return -EPERM;
#else
    if(lo->lo_key_owner != current->uid && !capable(CAP_SYS_ADMIN))
        return -EPERM;
#endif

    m = (AESmultiKey *)lo->key_data;
    if(!m) return -ENXIO;

#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    /* temporarily prevent loop thread from messing with keys */
    write_lock(&m->rwlock);
    m->blocked = 1;
    /* make sure allocated keys are in original order */
    if(m->reversed) keyScrubWork(m);
    write_unlock(&m->rwlock);
#endif
    n = PAGE_SIZE / specialAligned_ctxSize;
    if(!n) n = 1;

    x = 0;
    while(x < KEY_ALLOC_COUNT) {
        if(!m->keyPtr[x]) {
            a = (aes_context *) specialAligned_kmalloc(specialAligned_ctxSize * n, GFP_KERNEL);
            if(!a) {
                err = -ENOMEM;
                goto error_out;
            }
            y = x;
            while((y < (x + n)) && (y < KEY_ALLOC_COUNT)) {
                m->keyPtr[y] = a;
                a = (aes_context *)((unsigned char *)a + specialAligned_ctxSize);
                y++;
            }
        }
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
        if(x >= 64) {
            x++;
            continue;
        }
#endif
        if(copy_from_user(&un.b[0], k, 32)) {
            err = -EFAULT;
            goto error_out;
        }
        aes_set_key(m->keyPtr[x], &un.b[0], lo->lo_encrypt_key_size, 0);
        k += 32;
        x++;
    }

    m->partialMD5[0] = 0x67452301;
    m->partialMD5[1] = 0xefcdab89;
    m->partialMD5[2] = 0x98badcfe;
    m->partialMD5[3] = 0x10325476;
    if(version3) {
        /* only first 128 bits of iv-key is used */
        if(copy_from_user(&un.b[0], k, 16)) {
            err = -EFAULT;
            goto error_out;
        }
#if defined(__BIG_ENDIAN)
        un.w[0] = cpu_to_le32(un.w[0]);
        un.w[1] = cpu_to_le32(un.w[1]);
        un.w[2] = cpu_to_le32(un.w[2]);
        un.w[3] = cpu_to_le32(un.w[3]);
#endif
        memset(&un.b[16], 0, 48);
        md5_transform_CPUbyteorder(&m->partialMD5[0], &un.w[0]);
        lo->lo_flags |= 0x080000;  /* multi-key-v3 (info exported to user space) */
    }

    m->keyMask = 0x3F;          /* range 0...63 */
    lo->lo_flags |= 0x100000;   /* multi-key (info exported to user space) */
    memset(&un.b[0], 0, 32);
error_out:
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    /* re-enable loop thread key scrubbing */
    write_lock(&m->rwlock);
    m->blocked = 0;
    write_unlock(&m->rwlock);
#endif
    return err;
}

static int keySetup_aes(struct loop_device *lo, struct loop_info64 *info)
{
    AESmultiKey     *m;
    union {
        u_int32_t     w[8]; /* needed for 4 byte alignment for b[] */
        unsigned char b[32];
    } un;

    lo->key_data = m = allocMultiKey();
    if(!m) return(-ENOMEM);
    memcpy(&un.b[0], &info->lo_encrypt_key[0], 32);
    aes_set_key(m->keyPtr[0], &un.b[0], info->lo_encrypt_key_size, 0);
    memset(&info->lo_encrypt_key[0], 0, sizeof(info->lo_encrypt_key));
    memset(&un.b[0], 0, 32);
#if defined(CONFIG_BLK_DEV_LOOP_PADLOCK) && (defined(CONFIG_X86) || defined(CONFIG_X86_64))
    switch(info->lo_encrypt_key_size) {
    case 256:   /* bits */
    case 32:    /* bytes */
        /* 14 rounds, AES, software key gen, normal oper, encrypt, 256-bit key */
        m->padlock_cw_e = 14 | (1<<7) | (2<<10);
        /* 14 rounds, AES, software key gen, normal oper, decrypt, 256-bit key */
        m->padlock_cw_d = 14 | (1<<7) | (1<<9) | (2<<10);
        break;
    case 192:   /* bits */
    case 24:    /* bytes */
        /* 12 rounds, AES, software key gen, normal oper, encrypt, 192-bit key */
        m->padlock_cw_e = 12 | (1<<7) | (1<<10);
        /* 12 rounds, AES, software key gen, normal oper, decrypt, 192-bit key */
        m->padlock_cw_d = 12 | (1<<7) | (1<<9) | (1<<10);
        break;
    default:
        /* 10 rounds, AES, software key gen, normal oper, encrypt, 128-bit key */
        m->padlock_cw_e = 10 | (1<<7);
        /* 10 rounds, AES, software key gen, normal oper, decrypt, 128-bit key */
        m->padlock_cw_d = 10 | (1<<7) | (1<<9);
        break;
    }
#endif
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    keyScrubTimerInit(lo);
#endif
    return(0);
}

static int keyClean_aes(struct loop_device *lo)
{
    if(lo->key_data) {
        clearAndFreeMultiKey((AESmultiKey *)lo->key_data);
        lo->key_data = 0;
    }
    return(0);
}

static int handleIoctl_aes(struct loop_device *lo, int cmd, unsigned long arg)
{
    int err;

    switch (cmd) {
    case LOOP_MULTI_KEY_SETUP:
        err = multiKeySetup(lo, (unsigned char *)arg, 0);
        break;
    case LOOP_MULTI_KEY_SETUP_V3:
        err = multiKeySetup(lo, (unsigned char *)arg, 1);
        break;
    default:
        err = -EINVAL;
    }
    return err;
}

void loop_compute_sector_iv(sector_t devSect, u_int32_t *ivout)
{
    if(sizeof(sector_t) == 8) {
        ivout[0] = cpu_to_le32(devSect);
        ivout[1] = cpu_to_le32((u_int64_t)devSect>>32);
        ivout[3] = ivout[2] = 0;
    } else {
        ivout[0] = cpu_to_le32(devSect);
        ivout[3] = ivout[2] = ivout[1] = 0;
    }
}

void loop_compute_md5_iv_v3(sector_t devSect, u_int32_t *ivout, u_int32_t *data)
{
    int         x;
#if defined(__BIG_ENDIAN)
    int         y, e;
#endif
    u_int32_t   buf[16];

#if defined(__BIG_ENDIAN)
    y = 7;
    e = 16;
    do {
        if (!y) {
            e = 12;
            /* md5_transform_CPUbyteorder wants data in CPU byte order */
            /* devSect is already in CPU byte order -- no need to convert */
            if(sizeof(sector_t) == 8) {
                /* use only 56 bits of sector number */
                buf[12] = devSect;
                buf[13] = (((u_int64_t)devSect >> 32) & 0xFFFFFF) | 0x80000000;
            } else {
                /* 32 bits of sector number + 24 zero bits */
                buf[12] = devSect;
                buf[13] = 0x80000000;
            }
            /* 4024 bits == 31 * 128 bit plaintext blocks + 56 bits of sector number */
            /* For version 3 on-disk format this really should be 4536 bits, but can't be */
            /* changed without breaking compatibility. V3 uses MD5-with-wrong-length IV */
            buf[14] = 4024;
            buf[15] = 0;
        }
        x = 0;
        do {
            buf[x    ] = cpu_to_le32(data[0]);
            buf[x + 1] = cpu_to_le32(data[1]);
            buf[x + 2] = cpu_to_le32(data[2]);
            buf[x + 3] = cpu_to_le32(data[3]);
            x += 4;
            data += 4;
        } while (x < e);
        md5_transform_CPUbyteorder(&ivout[0], &buf[0]);
    } while (--y >= 0);
    ivout[0] = cpu_to_le32(ivout[0]);
    ivout[1] = cpu_to_le32(ivout[1]);
    ivout[2] = cpu_to_le32(ivout[2]);
    ivout[3] = cpu_to_le32(ivout[3]);
#else
    x = 6;
    do {
        md5_transform_CPUbyteorder(&ivout[0], data);
        data += 16;
    } while (--x >= 0);
    memcpy(buf, data, 48);
    /* md5_transform_CPUbyteorder wants data in CPU byte order */
    /* devSect is already in CPU byte order -- no need to convert */
    if(sizeof(sector_t) == 8) {
        /* use only 56 bits of sector number */
        buf[12] = devSect;
        buf[13] = (((u_int64_t)devSect >> 32) & 0xFFFFFF) | 0x80000000;
    } else {
        /* 32 bits of sector number + 24 zero bits */
        buf[12] = devSect;
        buf[13] = 0x80000000;
    }
    /* 4024 bits == 31 * 128 bit plaintext blocks + 56 bits of sector number */
    /* For version 3 on-disk format this really should be 4536 bits, but can't be */
    /* changed without breaking compatibility. V3 uses MD5-with-wrong-length IV */
    buf[14] = 4024;
    buf[15] = 0;
    md5_transform_CPUbyteorder(&ivout[0], &buf[0]);
#endif
}

/* this function exists for compatibility with old external cipher modules */
void loop_compute_md5_iv(sector_t devSect, u_int32_t *ivout, u_int32_t *data)
{
    ivout[0] = 0x67452301;
    ivout[1] = 0xefcdab89;
    ivout[2] = 0x98badcfe;
    ivout[3] = 0x10325476;
    loop_compute_md5_iv_v3(devSect, ivout, data);
}

/* Some external modules do not know if md5_transform_CPUbyteorder() */
/* is asmlinkage or not, so here is C language wrapper for them. */
void md5_transform_CPUbyteorder_C(u_int32_t *hash, u_int32_t const *in)
{
    md5_transform_CPUbyteorder(hash, in);
}

#if defined(CONFIG_X86_64) && defined(AMD64_ASM)
# define HAVE_MD5_2X_IMPLEMENTATION  1
#endif
#if defined(HAVE_MD5_2X_IMPLEMENTATION)
/*
 * This 2x code is currently only available on little endian AMD64
 * This 2x code assumes little endian byte order
 * Context A input data is at zero offset, context B at data + 512 bytes
 * Context A ivout at zero offset, context B at ivout + 16 bytes
 */
void loop_compute_md5_iv_v3_2x(sector_t devSect, u_int32_t *ivout, u_int32_t *data)
{
    int         x;
    u_int32_t   buf[2*16];

    x = 6;
    do {
        md5_transform_CPUbyteorder_2x(&ivout[0], data, data + (512/4));
        data += 16;
    } while (--x >= 0);
    memcpy(&buf[0], data, 48);
    memcpy(&buf[16], data + (512/4), 48);
    /* md5_transform_CPUbyteorder wants data in CPU byte order */
    /* devSect is already in CPU byte order -- no need to convert */
    if(sizeof(sector_t) == 8) {
        /* use only 56 bits of sector number */
        buf[12] = devSect;
        buf[13] = (((u_int64_t)devSect >> 32) & 0xFFFFFF) | 0x80000000;
        buf[16 + 12] = ++devSect;
        buf[16 + 13] = (((u_int64_t)devSect >> 32) & 0xFFFFFF) | 0x80000000;
    } else {
        /* 32 bits of sector number + 24 zero bits */
        buf[12] = devSect;
        buf[16 + 13] = buf[13] = 0x80000000;
        buf[16 + 12] = ++devSect;
    }
    /* 4024 bits == 31 * 128 bit plaintext blocks + 56 bits of sector number */
    /* For version 3 on-disk format this really should be 4536 bits, but can't be */
    /* changed without breaking compatibility. V3 uses MD5-with-wrong-length IV */
    buf[16 + 14] = buf[14] = 4024;
    buf[16 + 15] = buf[15] = 0;
    md5_transform_CPUbyteorder_2x(&ivout[0], &buf[0], &buf[16]);
}
#endif /* defined(HAVE_MD5_2X_IMPLEMENTATION) */

/*
 * Special requirements for transfer functions:
 * (1) Plaintext data (loop_buf) may change while it is being read.
 * (2) On 2.2 and older kernels ciphertext buffer (raw_buf) may be doing
 *     writes to disk at any time, so it can't be used as temporary buffer.
 */
static int transfer_aes(struct loop_device *lo, int cmd, char *raw_buf,
          char *loop_buf, int size, sector_t devSect)
{
    aes_context     *a;
    AESmultiKey     *m;
    int             x;
    unsigned        y;
    u_int64_t       iv[4], *dip;

    if(!size || (size & 511)) {
        return -EINVAL;
    }
    m = (AESmultiKey *)lo->key_data;
    y = m->keyMask;
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    read_lock(&m->rwlock);
#endif
    if(cmd == READ) {
#if defined(HAVE_MD5_2X_IMPLEMENTATION)
        /* if possible, use faster 2x MD5 implementation, currently AMD64 only (#6) */
        while((size >= (2*512)) && y) {
            /* multi-key mode, decrypt 2 sectors at a time */
            a = m->keyPtr[((unsigned)devSect    ) & y];
            /* decrypt using fake all-zero IV, first sector */
            memset(iv, 0, 16);
            x = 15;
            do {
                memcpy(&iv[2], raw_buf, 16);
                aes_decrypt(a, raw_buf, loop_buf);
                *((u_int64_t *)(&loop_buf[0])) ^= iv[0];
                *((u_int64_t *)(&loop_buf[8])) ^= iv[1];
                raw_buf += 16;
                loop_buf += 16;
                memcpy(iv, raw_buf, 16);
                aes_decrypt(a, raw_buf, loop_buf);
                *((u_int64_t *)(&loop_buf[0])) ^= iv[2];
                *((u_int64_t *)(&loop_buf[8])) ^= iv[3];
                raw_buf += 16;
                loop_buf += 16;
            } while(--x >= 0);
            a = m->keyPtr[((unsigned)devSect + 1) & y];
            /* decrypt using fake all-zero IV, second sector */
            memset(iv, 0, 16);
            x = 15;
            do {
                memcpy(&iv[2], raw_buf, 16);
                aes_decrypt(a, raw_buf, loop_buf);
                *((u_int64_t *)(&loop_buf[0])) ^= iv[0];
                *((u_int64_t *)(&loop_buf[8])) ^= iv[1];
                raw_buf += 16;
                loop_buf += 16;
                memcpy(iv, raw_buf, 16);
                aes_decrypt(a, raw_buf, loop_buf);
                *((u_int64_t *)(&loop_buf[0])) ^= iv[2];
                *((u_int64_t *)(&loop_buf[8])) ^= iv[3];
                raw_buf += 16;
                loop_buf += 16;
            } while(--x >= 0);
            /* compute correct IV */
            memcpy(&iv[0], &m->partialMD5[0], 16);
            memcpy(&iv[2], &m->partialMD5[0], 16);
            loop_compute_md5_iv_v3_2x(devSect, (u_int32_t *)iv, (u_int32_t *)(loop_buf - 1008));
            /* XOR with correct IV now */
            *((u_int64_t *)(loop_buf - 1024)) ^= iv[0];
            *((u_int64_t *)(loop_buf - 1016)) ^= iv[1];
            *((u_int64_t *)(loop_buf - 512)) ^= iv[2];
            *((u_int64_t *)(loop_buf - 504)) ^= iv[3];
            size -= 2*512;
            devSect += 2;
        }
#endif /* defined(HAVE_MD5_2X_IMPLEMENTATION) */
        while(size) {
            /* decrypt one sector at a time */
            a = m->keyPtr[((unsigned)devSect) & y];
            /* decrypt using fake all-zero IV */
            memset(iv, 0, 16);
            x = 15;
            do {
                memcpy(&iv[2], raw_buf, 16);
                aes_decrypt(a, raw_buf, loop_buf);
                *((u_int64_t *)(&loop_buf[0])) ^= iv[0];
                *((u_int64_t *)(&loop_buf[8])) ^= iv[1];
                raw_buf += 16;
                loop_buf += 16;
                memcpy(iv, raw_buf, 16);
                aes_decrypt(a, raw_buf, loop_buf);
                *((u_int64_t *)(&loop_buf[0])) ^= iv[2];
                *((u_int64_t *)(&loop_buf[8])) ^= iv[3];
                raw_buf += 16;
                loop_buf += 16;
            } while(--x >= 0);
            if(y) {
                /* multi-key mode, compute correct IV */
                memcpy(iv, &m->partialMD5[0], 16);
                loop_compute_md5_iv_v3(devSect, (u_int32_t *)iv, (u_int32_t *)(loop_buf - 496));
            } else {
                /* single-key mode, compute correct IV  */
                loop_compute_sector_iv(devSect, (u_int32_t *)iv);
            }
            /* XOR with correct IV now */
            *((u_int64_t *)(loop_buf - 512)) ^= iv[0];
            *((u_int64_t *)(loop_buf - 504)) ^= iv[1];
            size -= 512;
            devSect++;
        }
    } else {
#if defined(HAVE_MD5_2X_IMPLEMENTATION) && (LINUX_VERSION_CODE >= 0x20400)
        /* if possible, use faster 2x MD5 implementation, currently AMD64 only (#5) */
        while((size >= (2*512)) && y) {
            /* multi-key mode, encrypt 2 sectors at a time */
            memcpy(raw_buf, loop_buf, 2*512);
            memcpy(&iv[0], &m->partialMD5[0], 16);
            memcpy(&iv[2], &m->partialMD5[0], 16);
            loop_compute_md5_iv_v3_2x(devSect, (u_int32_t *)iv, (u_int32_t *)(&raw_buf[16]));
            /* first sector */
            a = m->keyPtr[((unsigned)devSect    ) & y];
            dip = &iv[0];
            x = 15;
            do {
                *((u_int64_t *)(&raw_buf[0])) ^= dip[0];
                *((u_int64_t *)(&raw_buf[8])) ^= dip[1];
                aes_encrypt(a, raw_buf, raw_buf);
                dip = (u_int64_t *)raw_buf;
                raw_buf += 16;
                *((u_int64_t *)(&raw_buf[0])) ^= dip[0];
                *((u_int64_t *)(&raw_buf[8])) ^= dip[1];
                aes_encrypt(a, raw_buf, raw_buf);
                dip = (u_int64_t *)raw_buf;
                raw_buf += 16;
            } while(--x >= 0);
            /* second sector */
            a = m->keyPtr[((unsigned)devSect + 1) & y];
            dip = &iv[2];
            x = 15;
            do {
                *((u_int64_t *)(&raw_buf[0])) ^= dip[0];
                *((u_int64_t *)(&raw_buf[8])) ^= dip[1];
                aes_encrypt(a, raw_buf, raw_buf);
                dip = (u_int64_t *)raw_buf;
                raw_buf += 16;
                *((u_int64_t *)(&raw_buf[0])) ^= dip[0];
                *((u_int64_t *)(&raw_buf[8])) ^= dip[1];
                aes_encrypt(a, raw_buf, raw_buf);
                dip = (u_int64_t *)raw_buf;
                raw_buf += 16;
            } while(--x >= 0);
            loop_buf += 2*512;
            size -= 2*512;
            devSect += 2;
        }
#endif /* defined(HAVE_MD5_2X_IMPLEMENTATION) && (LINUX_VERSION_CODE >= 0x20400) */
        while(size) {
            /* encrypt one sector at a time */
            a = m->keyPtr[((unsigned)devSect) & y];
            if(y) {
                /* multi-key mode encrypt, linux 2.4 and newer */
                memcpy(raw_buf, loop_buf, 512);
                memcpy(iv, &m->partialMD5[0], 16);
                loop_compute_md5_iv_v3(devSect, (u_int32_t *)iv, (u_int32_t *)(&raw_buf[16]));
                dip = iv;
                x = 15;
                do {
                    *((u_int64_t *)(&raw_buf[0])) ^= dip[0];
                    *((u_int64_t *)(&raw_buf[8])) ^= dip[1];
                    aes_encrypt(a, raw_buf, raw_buf);
                    dip = (u_int64_t *)raw_buf;
                    raw_buf += 16;
                    *((u_int64_t *)(&raw_buf[0])) ^= dip[0];
                    *((u_int64_t *)(&raw_buf[8])) ^= dip[1];
                    aes_encrypt(a, raw_buf, raw_buf);
                    dip = (u_int64_t *)raw_buf;
                    raw_buf += 16;
                } while(--x >= 0);
                loop_buf += 512;
            } else {
                /* single-key mode encrypt */
                loop_compute_sector_iv(devSect, (u_int32_t *)iv);
                dip = iv;
                x = 15;
                do {
                    iv[2] = *((u_int64_t *)(&loop_buf[0])) ^ dip[0];
                    iv[3] = *((u_int64_t *)(&loop_buf[8])) ^ dip[1];
                    aes_encrypt(a, (unsigned char *)(&iv[2]), raw_buf);
                    dip = (u_int64_t *)raw_buf;
                    loop_buf += 16;
                    raw_buf += 16;
                    iv[2] = *((u_int64_t *)(&loop_buf[0])) ^ dip[0];
                    iv[3] = *((u_int64_t *)(&loop_buf[8])) ^ dip[1];
                    aes_encrypt(a, (unsigned char *)(&iv[2]), raw_buf);
                    dip = (u_int64_t *)raw_buf;
                    loop_buf += 16;
                    raw_buf += 16;
                } while(--x >= 0);
            }
            size -= 512;
            devSect++;
        }
    }
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    read_unlock(&m->rwlock);
#endif
    cond_resched();
    return(0);
}

#if defined(CONFIG_BLK_DEV_LOOP_PADLOCK) && (defined(CONFIG_X86) || defined(CONFIG_X86_64))
static __inline__ void padlock_flush_key_context(void)
{
    __asm__ __volatile__("pushf; popf" : : : "cc");
}

static __inline__ void padlock_rep_xcryptcbc(void *cw, void *k, void *s, void *d, void *iv, unsigned long cnt)
{
    __asm__ __volatile__(".byte 0xF3,0x0F,0xA7,0xD0"
                         : "+a" (iv), "+c" (cnt), "+S" (s), "+D" (d) /*output*/
                         : "b" (k), "d" (cw) /*input*/
                         : "cc", "memory" /*modified*/ );
}

typedef struct {
#if defined(HAVE_MD5_2X_IMPLEMENTATION)
    u_int64_t   iv[2*2];
#else
    u_int64_t   iv[2];
#endif
    u_int32_t   cw[4];
    u_int32_t   dummy1[4];
} Padlock_IV_CW;

static int transfer_padlock_aes(struct loop_device *lo, int cmd, char *raw_buf,
          char *loop_buf, int size, sector_t devSect)
{
    aes_context     *a;
    AESmultiKey     *m;
    unsigned        y;
    Padlock_IV_CW   ivcwua;
    Padlock_IV_CW   *ivcw;

    /* ivcw->iv and ivcw->cw must have 16 byte alignment */
    ivcw = (Padlock_IV_CW *)(((unsigned long)&ivcwua + 15) & ~((unsigned long)15));
    ivcw->cw[3] = ivcw->cw[2] = ivcw->cw[1] = 0;

    if(!size || (size & 511) || (((unsigned long)raw_buf | (unsigned long)loop_buf) & 15)) {
        return -EINVAL;
    }
    m = (AESmultiKey *)lo->key_data;
    y = m->keyMask;
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    read_lock(&m->rwlock);
#endif
    if(cmd == READ) {
        ivcw->cw[0] = m->padlock_cw_d;
#if defined(HAVE_MD5_2X_IMPLEMENTATION)
        /* if possible, use faster 2x MD5 implementation, currently AMD64 only (#4) */
        while((size >= (2*512)) && y) {
            /* decrypt using fake all-zero IV */
            memset(&ivcw->iv[0], 0, 2*16);
            a = m->keyPtr[((unsigned)devSect    ) & y];
            padlock_flush_key_context();
            padlock_rep_xcryptcbc(&ivcw->cw[0], &a->aes_d_key[0], raw_buf, loop_buf, &ivcw->iv[0], 32);
            a = m->keyPtr[((unsigned)devSect + 1) & y];
            padlock_flush_key_context();
            padlock_rep_xcryptcbc(&ivcw->cw[0], &a->aes_d_key[0], raw_buf + 512, loop_buf + 512, &ivcw->iv[2], 32);
            /* compute correct IV */
            memcpy(&ivcw->iv[0], &m->partialMD5[0], 16);
            memcpy(&ivcw->iv[2], &m->partialMD5[0], 16);
            loop_compute_md5_iv_v3_2x(devSect, (u_int32_t *)(&ivcw->iv[0]), (u_int32_t *)(&loop_buf[16]));
            /* XOR with correct IV now */
            *((u_int64_t *)(&loop_buf[0])) ^= ivcw->iv[0];
            *((u_int64_t *)(&loop_buf[8])) ^= ivcw->iv[1];
            *((u_int64_t *)(&loop_buf[512 + 0])) ^= ivcw->iv[2];
            *((u_int64_t *)(&loop_buf[512 + 8])) ^= ivcw->iv[3];
            size -= 2*512;
            raw_buf += 2*512;
            loop_buf += 2*512;
            devSect += 2;
        }
#endif /* defined(HAVE_MD5_2X_IMPLEMENTATION) */
        while(size) {
            a = m->keyPtr[((unsigned)devSect) & y];
            padlock_flush_key_context();
            if(y) {
                /* decrypt using fake all-zero IV */
                memset(&ivcw->iv[0], 0, 16);
                padlock_rep_xcryptcbc(&ivcw->cw[0], &a->aes_d_key[0], raw_buf, loop_buf, &ivcw->iv[0], 32);
                /* compute correct IV */
                memcpy(&ivcw->iv[0], &m->partialMD5[0], 16);
                loop_compute_md5_iv_v3(devSect, (u_int32_t *)(&ivcw->iv[0]), (u_int32_t *)(&loop_buf[16]));
                /* XOR with correct IV now */
                *((u_int64_t *)(&loop_buf[ 0])) ^= ivcw->iv[0];
                *((u_int64_t *)(&loop_buf[ 8])) ^= ivcw->iv[1];
            } else {
                loop_compute_sector_iv(devSect, (u_int32_t *)(&ivcw->iv[0]));
                padlock_rep_xcryptcbc(&ivcw->cw[0], &a->aes_d_key[0], raw_buf, loop_buf, &ivcw->iv[0], 32);
            }
            size -= 512;
            raw_buf += 512;
            loop_buf += 512;
            devSect++;
        }
    } else {
        ivcw->cw[0] = m->padlock_cw_e;
#if defined(HAVE_MD5_2X_IMPLEMENTATION)
        /* if possible, use faster 2x MD5 implementation, currently AMD64 only (#3) */
        while((size >= (2*512)) && y) {
            memcpy(raw_buf, loop_buf, 2*512);
            memcpy(&ivcw->iv[0], &m->partialMD5[0], 16);
            memcpy(&ivcw->iv[2], &m->partialMD5[0], 16);
            loop_compute_md5_iv_v3_2x(devSect, (u_int32_t *)(&ivcw->iv[0]), (u_int32_t *)(&raw_buf[16]));
            a = m->keyPtr[((unsigned)devSect    ) & y];
            padlock_flush_key_context();
            padlock_rep_xcryptcbc(&ivcw->cw[0], &a->aes_e_key[0], raw_buf, raw_buf, &ivcw->iv[0], 32);
            a = m->keyPtr[((unsigned)devSect + 1) & y];
            padlock_flush_key_context();
            padlock_rep_xcryptcbc(&ivcw->cw[0], &a->aes_e_key[0], raw_buf + 512, raw_buf + 512, &ivcw->iv[2], 32);
            size -= 2*512;
            raw_buf += 2*512;
            loop_buf += 2*512;
            devSect += 2;
        }
#endif /* defined(HAVE_MD5_2X_IMPLEMENTATION) */
        while(size) {
            a = m->keyPtr[((unsigned)devSect) & y];
            padlock_flush_key_context();
            if(y) {
                memcpy(raw_buf, loop_buf, 512);
                memcpy(&ivcw->iv[0], &m->partialMD5[0], 16);
                loop_compute_md5_iv_v3(devSect, (u_int32_t *)(&ivcw->iv[0]), (u_int32_t *)(&raw_buf[16]));
                padlock_rep_xcryptcbc(&ivcw->cw[0], &a->aes_e_key[0], raw_buf, raw_buf, &ivcw->iv[0], 32);
            } else {
                loop_compute_sector_iv(devSect, (u_int32_t *)(&ivcw->iv[0]));
                padlock_rep_xcryptcbc(&ivcw->cw[0], &a->aes_e_key[0], loop_buf, raw_buf, &ivcw->iv[0], 32);
            }
            size -= 512;
            raw_buf += 512;
            loop_buf += 512;
            devSect++;
        }
    }
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    read_unlock(&m->rwlock);
#endif
    cond_resched();
    return(0);
}
#endif

#if defined(CONFIG_BLK_DEV_LOOP_INTELAES) && (defined(CONFIG_X86) || defined(CONFIG_X86_64))
asmlinkage extern void intel_aes_cbc_encrypt(const aes_context *, void *src, void *dst, size_t len, void *iv);
asmlinkage extern void intel_aes_cbc_decrypt(const aes_context *, void *src, void *dst, size_t len, void *iv);
asmlinkage extern void intel_aes_cbc_enc_4x512(aes_context **, void *src, void *dst, void *iv);

static int transfer_intel_aes(struct loop_device *lo, int cmd, char *raw_buf,
          char *loop_buf, int size, sector_t devSect)
{
    aes_context     *acpa[4];
    AESmultiKey     *m;
    unsigned        y;
    u_int64_t       ivua[(4*2)+2];
    u_int64_t       *iv;

    /* make iv 16 byte aligned */
    iv = (u_int64_t *)(((unsigned long)&ivua + 15) & ~((unsigned long)15));

    if(!size || (size & 511) || (((unsigned long)raw_buf | (unsigned long)loop_buf) & 15)) {
        return -EINVAL;
    }
    m = (AESmultiKey *)lo->key_data;
    y = m->keyMask;
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    read_lock(&m->rwlock);
#endif
    kernel_fpu_begin(); /* intel_aes_* code uses xmm registers */
    if(cmd == READ) {
#if defined(HAVE_MD5_2X_IMPLEMENTATION)
        /* if possible, use faster 2x MD5 implementation, currently AMD64 only (#2) */
        while((size >= (2*512)) && y) {
            acpa[0] = m->keyPtr[((unsigned)devSect    ) & y];
            acpa[1] = m->keyPtr[((unsigned)devSect + 1) & y];
            /* decrypt using fake all-zero IV */
            memset(iv, 0, 2*16);
            intel_aes_cbc_decrypt(acpa[0], raw_buf,       loop_buf,       512, &iv[0]);
            intel_aes_cbc_decrypt(acpa[1], raw_buf + 512, loop_buf + 512, 512, &iv[2]);
            /* compute correct IV, use 2x parallelized version */
            memcpy(&iv[0], &m->partialMD5[0], 16);
            memcpy(&iv[2], &m->partialMD5[0], 16);
            loop_compute_md5_iv_v3_2x(devSect, (u_int32_t *)iv, (u_int32_t *)(&loop_buf[16]));
            /* XOR with correct IV now */
            *((u_int64_t *)(&loop_buf[0])) ^= iv[0];
            *((u_int64_t *)(&loop_buf[8])) ^= iv[1];
            *((u_int64_t *)(&loop_buf[512 + 0])) ^= iv[2];
            *((u_int64_t *)(&loop_buf[512 + 8])) ^= iv[3];
            size -= 2*512;
            raw_buf += 2*512;
            loop_buf += 2*512;
            devSect += 2;
        }
#endif /* defined(HAVE_MD5_2X_IMPLEMENTATION) */
        while(size) {
            acpa[0] = m->keyPtr[((unsigned)devSect) & y];
            if(y) {
                /* decrypt using fake all-zero IV */
                memset(iv, 0, 16);
                intel_aes_cbc_decrypt(acpa[0], raw_buf, loop_buf, 512, iv);
                /* compute correct IV */
                memcpy(iv, &m->partialMD5[0], 16);
                loop_compute_md5_iv_v3(devSect, (u_int32_t *)iv, (u_int32_t *)(&loop_buf[16]));
                /* XOR with correct IV now */
                *((u_int64_t *)(&loop_buf[0])) ^= iv[0];
                *((u_int64_t *)(&loop_buf[8])) ^= iv[1];
            } else {
                loop_compute_sector_iv(devSect, (u_int32_t *)iv);
                intel_aes_cbc_decrypt(acpa[0], raw_buf, loop_buf, 512, iv);
            }
            size -= 512;
            raw_buf += 512;
            loop_buf += 512;
            devSect++;
        }
    } else {
        /* if possible, use faster 4-chains at a time encrypt implementation (#1) */
        while(size >= (4*512)) {
            acpa[0] = m->keyPtr[((unsigned)devSect    ) & y];
            acpa[1] = m->keyPtr[((unsigned)devSect + 1) & y];
            acpa[2] = m->keyPtr[((unsigned)devSect + 2) & y];
            acpa[3] = m->keyPtr[((unsigned)devSect + 3) & y];
            if(y) {
                memcpy(raw_buf, loop_buf, 4*512);
                memcpy(&iv[0], &m->partialMD5[0], 16);
                memcpy(&iv[2], &m->partialMD5[0], 16);
                memcpy(&iv[4], &m->partialMD5[0], 16);
                memcpy(&iv[6], &m->partialMD5[0], 16);
#if defined(HAVE_MD5_2X_IMPLEMENTATION)
                /* use 2x parallelized version */
                loop_compute_md5_iv_v3_2x(devSect,     (u_int32_t *)(&iv[0]), (u_int32_t *)(&raw_buf[        16]));
                loop_compute_md5_iv_v3_2x(devSect + 2, (u_int32_t *)(&iv[4]), (u_int32_t *)(&raw_buf[0x400 + 16]));
#else
                loop_compute_md5_iv_v3(devSect,     (u_int32_t *)(&iv[0]), (u_int32_t *)(&raw_buf[        16]));
                loop_compute_md5_iv_v3(devSect + 1, (u_int32_t *)(&iv[2]), (u_int32_t *)(&raw_buf[0x200 + 16]));
                loop_compute_md5_iv_v3(devSect + 2, (u_int32_t *)(&iv[4]), (u_int32_t *)(&raw_buf[0x400 + 16]));
                loop_compute_md5_iv_v3(devSect + 3, (u_int32_t *)(&iv[6]), (u_int32_t *)(&raw_buf[0x600 + 16]));
#endif
                intel_aes_cbc_enc_4x512(&acpa[0], raw_buf, raw_buf, iv);
            } else {
                loop_compute_sector_iv(devSect,     (u_int32_t *)(&iv[0]));
                loop_compute_sector_iv(devSect + 1, (u_int32_t *)(&iv[2]));
                loop_compute_sector_iv(devSect + 2, (u_int32_t *)(&iv[4]));
                loop_compute_sector_iv(devSect + 3, (u_int32_t *)(&iv[6]));
                intel_aes_cbc_enc_4x512(&acpa[0], loop_buf, raw_buf, iv);
            }
            size -= 4*512;
            raw_buf += 4*512;
            loop_buf += 4*512;
            devSect += 4;
        }
        /* encrypt the rest (if any) using slower 1-chain at a time implementation */
        while(size) {
            acpa[0] = m->keyPtr[((unsigned)devSect) & y];
            if(y) {
                memcpy(raw_buf, loop_buf, 512);
                memcpy(iv, &m->partialMD5[0], 16);
                loop_compute_md5_iv_v3(devSect, (u_int32_t *)iv, (u_int32_t *)(&raw_buf[16]));
                intel_aes_cbc_encrypt(acpa[0], raw_buf, raw_buf, 512, iv);
            } else {
                loop_compute_sector_iv(devSect, (u_int32_t *)iv);
                intel_aes_cbc_encrypt(acpa[0], loop_buf, raw_buf, 512, iv);
            }
            size -= 512;
            raw_buf += 512;
            loop_buf += 512;
            devSect++;
        }
    }
    kernel_fpu_end(); /* intel_aes_* code uses xmm registers */
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
    read_unlock(&m->rwlock);
#endif
    cond_resched();
    return(0);
}
#endif

static struct loop_func_table funcs_aes = {
    number:     16,     /* 16 == AES */
    transfer:   transfer_aes,
    init:       keySetup_aes,
    release:    keyClean_aes,
    ioctl:      handleIoctl_aes
};

#if defined(CONFIG_BLK_DEV_LOOP_PADLOCK) && (defined(CONFIG_X86) || defined(CONFIG_X86_64))
static struct loop_func_table funcs_padlock_aes = {
    number:     16,     /* 16 == AES */
    transfer:   transfer_padlock_aes,
    init:       keySetup_aes,
    release:    keyClean_aes,
    ioctl:      handleIoctl_aes
};
#endif

#if defined(CONFIG_BLK_DEV_LOOP_INTELAES) && (defined(CONFIG_X86) || defined(CONFIG_X86_64))
static struct loop_func_table funcs_intel_aes = {
    number:     16,     /* 16 == AES */
    transfer:   transfer_intel_aes,
    init:       keySetup_aes,
    release:    keyClean_aes,
    ioctl:      handleIoctl_aes
};
#endif

#if defined(CONFIG_BLK_DEV_LOOP_PADLOCK) && (defined(CONFIG_X86) || defined(CONFIG_X86_64))
static int CentaurHauls_ID_and_enabled_ACE(void)
{
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;

    /* check for "CentaurHauls" ID string, and enabled ACE */
    cpuid(0x00000000, &eax, &ebx, &ecx, &edx);
    if((ebx == 0x746e6543) && (edx == 0x48727561) && (ecx == 0x736c7561)
      && (cpuid_eax(0xC0000000) >= 0xC0000001)
      && ((cpuid_edx(0xC0000001) & 0xC0) == 0xC0)) {
        return 1;   /* ACE enabled */
    }
    return 0;
}
#endif

EXPORT_SYMBOL(loop_compute_sector_iv);
EXPORT_SYMBOL(loop_compute_md5_iv_v3);
EXPORT_SYMBOL(loop_compute_md5_iv);
EXPORT_SYMBOL(md5_transform_CPUbyteorder_C);
#endif /* CONFIG_BLK_DEV_LOOP_AES */

/* xfer_funcs[0] is special - its release function is never called */
static struct loop_func_table *xfer_funcs[MAX_LO_CRYPT] = {
	&none_funcs,
	&xor_funcs,
#ifdef CONFIG_BLK_DEV_LOOP_AES
        [LO_CRYPT_AES] = &funcs_aes,
#endif
};

/*
 *  First number of 'lo_prealloc' is the default number of RAM pages
 *  to pre-allocate for each device backed loop. Every (configured)
 *  device backed loop pre-allocates this amount of RAM pages unless
 *  later 'lo_prealloc' numbers provide an override. 'lo_prealloc'
 *  overrides are defined in pairs: loop_index,number_of_pages
 */
static int lo_prealloc[9] = { 125, -1, 0, -1, 0, -1, 0, -1, 0 };
#define LO_PREALLOC_MIN 4    /* minimum user defined pre-allocated RAM pages */
#define LO_PREALLOC_MAX 4096 /* maximum user defined pre-allocated RAM pages */

#ifdef MODULE
static int dummy1;
#if LINUX_VERSION_CODE >= 0x2060a
module_param_array(lo_prealloc, int, &dummy1, 0);
#else
module_param_array(lo_prealloc, int, dummy1, 0);
#endif
MODULE_PARM_DESC(lo_prealloc, "Number of pre-allocated pages [,index,pages]...");
#else
static int __init lo_prealloc_setup(char *str)
{
	int x, y, z;

	for (x = 0; x < (sizeof(lo_prealloc) / sizeof(int)); x++) {
		z = get_option(&str, &y);
		if (z > 0)
			lo_prealloc[x] = y;
		if (z < 2)
			break;
	}
	return 1;
}
__setup("lo_prealloc=", lo_prealloc_setup);
#endif

/*
 * This is loop helper thread nice value in range
 * from 0 (low priority) to -20 (high priority).
 */
static int lo_nice = -1;

#ifdef MODULE
module_param(lo_nice, int, 0);
MODULE_PARM_DESC(lo_nice, "Loop thread scheduler nice (0 ... -20)");
#else
static int __init lo_nice_setup(char *str)
{
	int y;

	if (get_option(&str, &y) == 1)
		lo_nice = y;
	return 1;
}
__setup("lo_nice=", lo_nice_setup);
#endif

struct loop_bio_extension {
	struct bio		*bioext_merge;
	struct loop_device	*bioext_loop;
	sector_t		bioext_iv;
	int			bioext_index;
	int			bioext_size;
};	

static struct loop_device **loop_dev_ptr_arr;

static void loop_prealloc_cleanup(struct loop_device *lo)
{
	struct bio *bio;

	while ((bio = lo->lo_bio_free0)) {
		lo->lo_bio_free0 = bio->bi_next;
		__free_page(bio->bi_io_vec[0].bv_page);
		kfree(bio->bi_private);
		bio->bi_next = NULL;
		bio_put(bio);
	}
	while ((bio = lo->lo_bio_free1)) {
		lo->lo_bio_free1 = bio->bi_next;
		/* bi_flags was used for other purpose */
		bio->bi_flags = 0;
		/* bi_size was used for other purpose */
		bio->bi_size = 0;
		/* bi_cnt was used for other purpose */
		atomic_set(&bio->bi_cnt, 1);
		bio->bi_next = NULL;
		bio_put(bio);
	}
}

static int loop_prealloc_init(struct loop_device *lo, int y)
{
	struct bio *bio;
	int x;

	if(!y) {
		y = lo_prealloc[0];
		for (x = 1; x < (sizeof(lo_prealloc) / sizeof(int)); x += 2) {
			if (lo_prealloc[x + 1] && (lo->lo_number == lo_prealloc[x])) {
				y = lo_prealloc[x + 1];
				break;
			}
		}
	}
	lo->lo_bio_flsh = (y * 3) / 4;

	for (x = 0; x < y; x++) {
		bio = bio_alloc(GFP_KERNEL, 1);
		if (!bio) {
			fail1:
			loop_prealloc_cleanup(lo);
			return 1;
		}
		bio->bi_io_vec[0].bv_page = alloc_page(GFP_KERNEL);
		if (!bio->bi_io_vec[0].bv_page) {
			fail2:
			bio->bi_next = NULL;
			bio_put(bio);
			goto fail1;
		}
		memset(page_address(bio->bi_io_vec[0].bv_page), 0, PAGE_SIZE);
		bio->bi_vcnt = 1;
		bio->bi_private = kmalloc(sizeof(struct loop_bio_extension), GFP_KERNEL);
		if (!bio->bi_private)
			goto fail2;
		bio->bi_next = lo->lo_bio_free0;
		lo->lo_bio_free0 = bio;

		bio = bio_alloc(GFP_KERNEL, 1);
		if (!bio)
			goto fail1;
		bio->bi_vcnt = 1;
		bio->bi_next = lo->lo_bio_free1;
		lo->lo_bio_free1 = bio;
	}
	return 0;
}

static void loop_add_queue_last(struct loop_device *lo, struct bio *bio, struct bio **q)
{
	unsigned long flags;

	spin_lock_irqsave(&lo->lo_lock, flags);
	if (*q) {
		bio->bi_next = (*q)->bi_next;
		(*q)->bi_next = bio;
	} else {
		bio->bi_next = bio;
	}
	*q = bio;
	spin_unlock_irqrestore(&lo->lo_lock, flags);

	if (waitqueue_active(&lo->lo_bio_wait))
		wake_up_interruptible(&lo->lo_bio_wait);
}

static void loop_add_queue_first(struct loop_device *lo, struct bio *bio, struct bio **q)
{
	spin_lock_irq(&lo->lo_lock);
	if (*q) {
		bio->bi_next = (*q)->bi_next;
		(*q)->bi_next = bio;
	} else {
		bio->bi_next = bio;
		*q = bio;
	}
	spin_unlock_irq(&lo->lo_lock);
}

static struct bio *loop_get_bio(struct loop_device *lo, int *list_nr)
{
	struct bio *bio = NULL, *last;

	spin_lock_irq(&lo->lo_lock);
	if ((last = lo->lo_bio_que0)) {
		bio = last->bi_next;
		if (bio == last)
			lo->lo_bio_que0 = NULL;
		else
			last->bi_next = bio->bi_next;
		bio->bi_next = NULL;
		*list_nr = 0;
	} else if ((last = lo->lo_bio_que1)) {
		bio = last->bi_next;
		if (bio == last)
			lo->lo_bio_que1 = NULL;
		else
			last->bi_next = bio->bi_next;
		bio->bi_next = NULL;
		*list_nr = 1;
	} else if ((last = lo->lo_bio_que2)) {
		bio = last->bi_next;
		if (bio == last)
			lo->lo_bio_que2 = NULL;
		else
			last->bi_next = bio->bi_next;
		bio->bi_next = NULL;
		*list_nr = 2;
	}
	spin_unlock_irq(&lo->lo_lock);
	return bio;
}

static void loop_put_buffer(struct loop_device *lo, struct bio *b, int flist)
{
	unsigned long flags;
	int wk;

	spin_lock_irqsave(&lo->lo_lock, flags);
	if(!flist) {
		b->bi_next = lo->lo_bio_free0;
		lo->lo_bio_free0 = b;
		wk = lo->lo_bio_need & 1;
	} else {
		b->bi_next = lo->lo_bio_free1;
		lo->lo_bio_free1 = b;
		wk = lo->lo_bio_need & 2;
	}
	spin_unlock_irqrestore(&lo->lo_lock, flags);

	if (wk && waitqueue_active(&lo->lo_bio_wait))
		wake_up_interruptible(&lo->lo_bio_wait);
}

#if defined(LOOP_IO_END_RETURN_VOID_TYPE)
static void loop_end_io_transfer(struct bio *bio, int err)
#else
static int loop_end_io_transfer(struct bio *bio, unsigned int bytes_done, int err)
#endif
{
	struct loop_bio_extension *extension = bio->bi_private;
	struct bio *merge = extension->bioext_merge;
	struct loop_device *lo = extension->bioext_loop;
	struct bio *origbio = merge->bi_private;

	if (err) {
		merge->bi_size = err; /* used as error code */
		if(err == -EIO)
			clear_bit(0, &merge->bi_flags);
		printk(KERN_ERR "loop%d: loop_end_io_transfer err=%d bi_rw=0x%lx\n", lo->lo_number, err, bio->bi_rw);
	}
#if !defined(LOOP_IO_END_RETURN_VOID_TYPE)
	if (bio->bi_size)
		return 1;
#endif
	if (bio_rw(bio) == WRITE) {
		loop_put_buffer(lo, bio, 0);
		if (!atomic_dec_and_test(&merge->bi_cnt)) {
#if defined(LOOP_IO_END_RETURN_VOID_TYPE)
			return;
#else
			return 0;
#endif
		}
		origbio->bi_next = NULL;
#if defined(LOOP_IO_END_RETURN_VOID_TYPE)
		bio_endio(origbio, test_bit(0, &merge->bi_flags) ? (int)merge->bi_size : -EIO);
#else
		bio_endio(origbio, origbio->bi_size, test_bit(0, &merge->bi_flags) ? (int)merge->bi_size : -EIO);
#endif
		loop_put_buffer(lo, merge, 1);
		if (atomic_dec_and_test(&lo->lo_pending))
			wake_up_interruptible(&lo->lo_bio_wait);
	} else {
		loop_add_queue_last(lo, bio, &lo->lo_bio_que0);
	}
#if !defined(LOOP_IO_END_RETURN_VOID_TYPE)
	return 0;
#endif
}

static struct bio *loop_get_buffer(struct loop_device *lo, struct bio *orig_bio,
		int from_thread, struct bio **merge_ptr, int *isBarrBioPtr)
{
	struct bio *bio = NULL, *merge = *merge_ptr;
	struct loop_bio_extension *extension;
	unsigned long flags;
	int len;

	/*
	 * If called from make_request and if there are unprocessed
	 * barrier requests, fail allocation so that request is
	 * inserted to end of no-merge-allocated list. This guarantees
	 * FIFO processing order of requests.
	 */
	if (!from_thread && atomic_read(&lo->lo_bio_barr))
		return NULL;

	spin_lock_irqsave(&lo->lo_lock, flags);
	if (!merge) {
		merge = lo->lo_bio_free1;
		if (merge) {
			lo->lo_bio_free1 = merge->bi_next;
			if (from_thread)
				lo->lo_bio_need = 0;
		} else {
			if (from_thread)
				lo->lo_bio_need = 2;
		}
	}

	/*
	 * If there are unprocessed barrier requests and a merge-bio was just
	 * allocated, do not allocate a buffer-bio yet. This causes request
	 * to be moved from head of no-merge-allocated list to end of
	 * merge-allocated list. This guarantees FIFO processing order
	 * of requests.
	 */
	if (merge && (*merge_ptr || !atomic_read(&lo->lo_bio_barr))) {
		bio = lo->lo_bio_free0;
		if (bio) {
			lo->lo_bio_free0 = bio->bi_next;
			if (from_thread)
				lo->lo_bio_need = 0;
		} else {
			if (from_thread)
				lo->lo_bio_need = 1;
		}
	}
	spin_unlock_irqrestore(&lo->lo_lock, flags);

	if (!(*merge_ptr) && merge) {
		/*
		 * initialize "merge-bio" which is used as
		 * rendezvous point among multiple vecs
		 */
		*merge_ptr = merge;
		merge->bi_sector = orig_bio->bi_sector + lo->lo_offs_sec;
		merge->bi_size = 0; /* used as error code */
		set_bit(0, &merge->bi_flags);
		merge->bi_idx = orig_bio->bi_idx;
		atomic_set(&merge->bi_cnt, orig_bio->bi_vcnt - orig_bio->bi_idx);
		merge->bi_private = orig_bio;
	}

	if (!bio)
		return NULL;

	/*
	 * initialize one page "buffer-bio"
	 */
	bio->bi_sector = merge->bi_sector;
	bio->bi_next = NULL;
	bio->bi_bdev = lo->lo_device;
	bio->bi_flags = (1 << BIO_UPTODATE);
#if (LINUX_VERSION_CODE >= 0x2061c) || ((LINUX_VERSION_CODE >= 0x2061b) && defined(BIO_CPU_AFFINE))
	if(orig_bio->bi_flags & (1 << BIO_CPU_AFFINE)) {
		bio->bi_comp_cpu = orig_bio->bi_comp_cpu;
		bio->bi_flags |= (1 << BIO_CPU_AFFINE);
	}
#endif
	/* read-ahead bit needs to be cleared to work around kernel bug */
	/* that causes I/O errors on -EWOULDBLOCK I/O elevator failures */
	bio->bi_rw = orig_bio->bi_rw & ~((1 << BIO_RW_BARRIER) | (1 << BIO_RW_AHEAD));
#if defined(BIO_RW_NOIDLE) || (LINUX_VERSION_CODE >= 0x2061f)
	bio->bi_rw &= ~(1 << BIO_RW_NOIDLE);
#endif
	if (orig_bio->bi_rw & (1 << BIO_RW_BARRIER)) {
		if(merge->bi_idx == (orig_bio->bi_vcnt - 1)) {
#if LINUX_VERSION_CODE >= 0x20609
			setBarr2:
#if (LINUX_VERSION_CODE >= 0x2061c) || ((LINUX_VERSION_CODE >= 0x2061b) && !defined(BIOVEC_VIRT_START_SIZE))
			orig_bio->bi_seg_front_size = 0;
#else
			orig_bio->bi_hw_front_size = 0;
#endif
#endif
			*isBarrBioPtr = 1;
			setBarr1:
			bio->bi_rw |= (1 << BIO_RW_BARRIER);
		} else if(merge->bi_idx == orig_bio->bi_idx) {
			goto setBarr1;
		}
	}
#if LINUX_VERSION_CODE >= 0x20609
#if (LINUX_VERSION_CODE >= 0x2061c) || ((LINUX_VERSION_CODE >= 0x2061b) && !defined(BIOVEC_VIRT_START_SIZE))
	else if(orig_bio->bi_seg_front_size == 1536) {
		goto setBarr2;
	}
#else
	else if(orig_bio->bi_hw_front_size == 1536) {
		goto setBarr2;
	}
#endif
#endif
#if defined(BIO_RW_SYNC) || defined(BIO_RW_SYNCIO) || (LINUX_VERSION_CODE >= 0x20620)
#if !defined(BIO_RW_SYNCIO) && defined(BIO_RW_SYNC)
# define BIO_RW_SYNCIO BIO_RW_SYNC
#endif
	bio->bi_rw &= ~(1 << BIO_RW_SYNCIO);
	if ((orig_bio->bi_rw & (1 << BIO_RW_SYNCIO)) && (merge->bi_idx == (orig_bio->bi_vcnt - 1)))
		bio->bi_rw |= (1 << BIO_RW_SYNCIO);
#endif
	bio->bi_vcnt = 1;
	bio->bi_idx = 0;
	bio->bi_phys_segments = 0;
#if (LINUX_VERSION_CODE < 0x2061c) && ((LINUX_VERSION_CODE < 0x2061b) || defined(BIOVEC_VIRT_START_SIZE))
	bio->bi_hw_segments = 0;
#endif
	bio->bi_size = len = orig_bio->bi_io_vec[merge->bi_idx].bv_len;
#if defined(BIOVEC_VIRT_START_SIZE) || (LINUX_VERSION_CODE >= 0x20608)
#if (LINUX_VERSION_CODE >= 0x2061c) || ((LINUX_VERSION_CODE >= 0x2061b) && !defined(BIOVEC_VIRT_START_SIZE))
	bio->bi_seg_front_size = 0;
	bio->bi_seg_back_size = 0;
#else
	bio->bi_hw_front_size = 0;
	bio->bi_hw_back_size = 0;
#endif
#endif
	/* bio->bi_max_vecs not touched */
	bio->bi_io_vec[0].bv_len = len;
	bio->bi_io_vec[0].bv_offset = 0;
	bio->bi_end_io = loop_end_io_transfer;
	/* bio->bi_cnt not touched */
	/* bio->bi_private not touched */
	/* bio->bi_destructor not touched */

	/*
	 * initialize "buffer-bio" extension. This extension is
	 * permanently glued to above "buffer-bio" via bio->bi_private
	 */
	extension = bio->bi_private;
	extension->bioext_merge = merge;
	extension->bioext_loop = lo;
	extension->bioext_iv = merge->bi_sector - lo->lo_iv_remove;
	extension->bioext_index = merge->bi_idx;
	extension->bioext_size = len;

	/*
	 * prepare "merge-bio" for next vec
	 */
	merge->bi_sector += len >> 9;
	merge->bi_idx++;

	return bio;
}

static int figure_loop_size(struct loop_device *lo, struct block_device *bdev)
{
	loff_t size, offs;
	sector_t x;
	int err = 0;

	size = i_size_read(lo->lo_backing_file->LOOP_COMPAT_F_DENTRY->d_inode->i_mapping->host);
	offs = lo->lo_offset;
	if (!(lo->lo_flags & LO_FLAGS_DO_BMAP))
		offs &= ~((loff_t)511);
	if ((offs > 0) && (offs < size)) {
		size -= offs;
	} else {
		if (offs)
			err = -EINVAL;
		lo->lo_offset = 0;
		lo->lo_offs_sec = lo->lo_iv_remove = 0;
	}
	if ((lo->lo_sizelimit > 0) && (lo->lo_sizelimit <= size)) {
		size = lo->lo_sizelimit;
	} else {
		if (lo->lo_sizelimit)
			err = -EINVAL;
		lo->lo_sizelimit = 0;
	}
	size >>= 9;

	/*
	 * Unfortunately, if we want to do I/O on the device,
	 * the number of 512-byte sectors has to fit into a sector_t.
	 */
	x = (sector_t)size;
	if ((loff_t)x != size) {
		err = -EFBIG;
		size = 0;
	}

	set_capacity(disks[lo->lo_number], size);	/* 512 byte units */
	i_size_write(bdev->bd_inode, size << 9);	/* byte units */
	return err;
}

static inline int lo_do_transfer(struct loop_device *lo, int cmd, char *rbuf,
				 char *lbuf, int size, sector_t rblock)
{
	if (!lo->transfer)
		return 0;

	return lo->transfer(lo, cmd, rbuf, lbuf, size, rblock);
}

static int loop_file_io(struct file *file, char *buf, int size, loff_t *ppos, int w)
{
	mm_segment_t fs;
	int x, y, z;

	y = 0;
	do {
		z = size - y;
		fs = get_fs();
		set_fs(get_ds());
		if (w) {
			x = file->f_op->write(file, buf + y, z, ppos);
			set_fs(fs);
		} else {
			x = file->f_op->read(file, buf + y, z, ppos);
			set_fs(fs);
			if (!x)
				return 1;
		}
		if (x < 0) {
			if ((x == -EAGAIN) || (x == -ENOMEM) || (x == -ERESTART) || (x == -EINTR)) {
				set_current_state(TASK_INTERRUPTIBLE);
				schedule_timeout(HZ / 2);
				continue;
			}
			return 1;
		}
		y += x;
	} while (y < size);
	return 0;
}

static int do_bio_filebacked(struct loop_device *lo, struct bio *bio)
{
	loff_t pos;
	struct file *file = lo->lo_backing_file;
	char *data, *buf;
	unsigned int size, len;
	sector_t IV;
	struct page *pg;

	if(!bio->bi_size)
		return 0;

	pos = ((loff_t) bio->bi_sector << 9) + lo->lo_offset;
	buf = page_address(lo->lo_bio_free0->bi_io_vec[0].bv_page);
	IV = bio->bi_sector;
	if (!lo->lo_iv_remove)
		IV += lo->lo_offs_sec;
	do {
		pg = bio->bi_io_vec[bio->bi_idx].bv_page;
		len = bio->bi_io_vec[bio->bi_idx].bv_len;
		data = kmap(pg) + bio->bi_io_vec[bio->bi_idx].bv_offset;
		while (len > 0) {
			if (!lo->lo_encryption) {
				/* this code relies that NONE transfer is a no-op */
				buf = data;
			}
			size = PAGE_CACHE_SIZE;
			if (size > len)
				size = len;
			if (bio_rw(bio) == WRITE) {
				if (lo_do_transfer(lo, WRITE, buf, data, size, IV)) {
					printk(KERN_ERR "loop%d: write transfer error, sector %llu\n", lo->lo_number, (unsigned long long)IV);
					goto kunmap_and_out;
				}
				if (loop_file_io(file, buf, size, &pos, 1)) {
					printk(KERN_ERR "loop%d: write i/o error, sector %llu\n", lo->lo_number, (unsigned long long)IV);
					goto kunmap_and_out;
				}
			} else {
				if (loop_file_io(file, buf, size, &pos, 0)) {
					printk(KERN_ERR "loop%d: read i/o error, sector %llu\n", lo->lo_number, (unsigned long long)IV);
					goto kunmap_and_out;
				}
				if (lo_do_transfer(lo, READ, buf, data, size, IV)) {
					printk(KERN_ERR "loop%d: read transfer error, sector %llu\n", lo->lo_number, (unsigned long long)IV);
					goto kunmap_and_out;
				}
				flush_dcache_page(pg);
			}
			data += size;
			len -= size;
			IV += size >> 9;
		}
		kunmap(pg);
	} while (++bio->bi_idx < bio->bi_vcnt);
	return 0;

kunmap_and_out:
	kunmap(pg);
	return -EIO;
}

#if defined(LOOP_HAVE_ISSUE_FLUSH_FN)
static int loop_issue_flush(struct request_queue *q, struct gendisk *disk, sector_t *error_sector)
{
	struct loop_device *lo = q->queuedata;
	struct block_device *bdev;
	struct request_queue *bqu;
	sector_t sect;
	int ret;

	if(!lo)
		return 0;
	if(lo->lo_flags & LO_FLAGS_DO_BMAP)
		return 0;
	bdev = lo->lo_device;
	if(!bdev)
		return 0;
	bqu = bdev_get_queue(bdev);
	if(!bqu)
		return 0;
	if(!bqu->issue_flush_fn)
		return -EOPNOTSUPP;
	if(!lo->lo_encryption) {
		/* bdev & sector remapped for NONE transfer */
		sect = 0;
		ret = bqu->issue_flush_fn(bqu, bdev->bd_disk, &sect);
		if(ret && error_sector) {
			if(sect >= lo->lo_offs_sec) {
				sect -= lo->lo_offs_sec;
			} else {
				sect = 0;
			}
			*error_sector = sect;
		}
		return ret;
	}
#if !defined(QUEUE_FLAG_ORDERED)
	if(bqu->ordered != QUEUE_ORDERED_TAG)
#else
	if(!(bqu->queue_flags & (1 << QUEUE_FLAG_ORDERED)))
#endif
		return -EOPNOTSUPP;
	/* encrypted loop is not flushed now, but next request that */
	/* arrives at loop_make_request_real() gets tagged as barrier */
	set_bit(0, &lo->lo_bio_flag);
	return 0;
}
#endif

static int loop_make_request_err(struct request_queue *q, struct bio *old_bio)
{
	old_bio->bi_next = NULL;
#if defined(LOOP_IO_END_RETURN_VOID_TYPE)
	bio_io_error(old_bio);
#else
	bio_io_error(old_bio, old_bio->bi_size);
#endif
	return 0;
}

static int loop_make_request_real(struct request_queue *q, struct bio *old_bio)
{
	struct bio *new_bio, *merge;
	struct loop_device *lo = q->queuedata;
	struct loop_bio_extension *extension;
	int rw = bio_rw(old_bio), y;
	char *md;

	set_current_state(TASK_RUNNING);
	if (!lo)
		goto out;
	if ((rw == WRITE) && (lo->lo_flags & LO_FLAGS_READ_ONLY))
		goto out;
	atomic_inc(&lo->lo_pending);

	/*
	 * file backed, queue for loop_thread to handle
	 */
	if (lo->lo_flags & LO_FLAGS_DO_BMAP) {
		loop_add_queue_last(lo, old_bio, &lo->lo_bio_que0);
		return 0;
	}

	/*
	 * device backed, just remap bdev & sector for NONE transfer
	 */
	if (!lo->lo_encryption) {
		old_bio->bi_sector += lo->lo_offs_sec;
		old_bio->bi_bdev = lo->lo_device;
		generic_make_request(old_bio);
#if defined(LOOP_IO_END_RETURN_VOID_TYPE)
		outDecPending:
#endif
		if (atomic_dec_and_test(&lo->lo_pending))
			wake_up_interruptible(&lo->lo_bio_wait);
		return 0;
	}

#if defined(LOOP_IO_END_RETURN_VOID_TYPE)
	/*
	 * Deal with empty barrier bio.
	 */
	if(bio_empty_barrier(old_bio)) {
		/* encrypted loop is not flushed now, but next request that */
		/* arrives at loop_make_request_real() gets tagged as barrier */
		set_bit(0, &lo->lo_bio_flag);
		old_bio->bi_next = NULL;
		bio_endio(old_bio, 0);
		goto outDecPending;
	}
#endif

	/*
	 * device backed, start reads and writes now if buffer available
	 */
	merge = NULL;
#if LINUX_VERSION_CODE >= 0x20609
#if (LINUX_VERSION_CODE >= 0x2061c) || ((LINUX_VERSION_CODE >= 0x2061b) && !defined(BIOVEC_VIRT_START_SIZE))
	old_bio->bi_seg_front_size = 0;
#else
	old_bio->bi_hw_front_size = 0;
#endif
#endif
	if(test_and_clear_bit(0, &lo->lo_bio_flag) || (old_bio->bi_rw & (1 << BIO_RW_BARRIER))) {
		atomic_inc(&lo->lo_bio_barr);
#if LINUX_VERSION_CODE >= 0x20609
#if (LINUX_VERSION_CODE >= 0x2061c) || ((LINUX_VERSION_CODE >= 0x2061b) && !defined(BIOVEC_VIRT_START_SIZE))
		old_bio->bi_seg_front_size = 1536;
#else
		old_bio->bi_hw_front_size = 1536;
#endif
#endif
	}
	try_next_old_bio_vec:
	/* Passing isBarrBioPtr as NULL. All barriers are sent from helper thread */
	/* If loop_get_buffer() incorrectly attempts to return barrier bio here, */
	/* then that function fails with NULL pointer dereference */
	new_bio = loop_get_buffer(lo, old_bio, 0, &merge, NULL);
	if (!new_bio) {
		/* just queue request and let thread handle allocs later */
		if (merge)
			loop_add_queue_last(lo, merge, &lo->lo_bio_que1);
		else
			loop_add_queue_last(lo, old_bio, &lo->lo_bio_que2);
		return 0;
	}
	if (rw == WRITE) {
		extension = new_bio->bi_private;
		y = extension->bioext_index;
		md = kmap(old_bio->bi_io_vec[y].bv_page) + old_bio->bi_io_vec[y].bv_offset;
		if (lo_do_transfer(lo, WRITE, page_address(new_bio->bi_io_vec[0].bv_page), md, extension->bioext_size, extension->bioext_iv)) {
			clear_bit(0, &merge->bi_flags);
		}
		kunmap(old_bio->bi_io_vec[y].bv_page);
	}

	/* merge & old_bio may vanish during generic_make_request() */
	/* if last vec gets processed before function returns   */
	y = (merge->bi_idx < old_bio->bi_vcnt) ? 1 : 0;
	generic_make_request(new_bio);

	/* other vecs may need processing too */
	if (y)
		goto try_next_old_bio_vec;
	return 0;

out:
	old_bio->bi_next = NULL;
#if defined(LOOP_IO_END_RETURN_VOID_TYPE)
	bio_io_error(old_bio);
#else
	bio_io_error(old_bio, old_bio->bi_size);
#endif
	return 0;
}

static void loop_unplug_backingdev(struct request_queue *bq)
{
#if (LINUX_VERSION_CODE >= 0x20610) && !defined(QUEUE_FLAG_PLUGGED)
	if(bq && bq->request_fn)
		blk_run_queue(bq);
#elif defined(QUEUE_FLAG_PLUGGED)
	if(bq && bq->unplug_fn)
		bq->unplug_fn(bq);
#else
	blk_run_queues();
#endif
}

#if defined(QUEUE_FLAG_PLUGGED)
static void loop_unplug_loopdev(struct request_queue *mq)
{
	struct loop_device	*lo;
	struct file		*f;

	clear_bit(QUEUE_FLAG_PLUGGED, &mq->queue_flags);
	lo = mq->queuedata;
	if(!lo)
		return;
	f = lo->lo_backing_file;
	if(!f)
		return;
	blk_run_address_space(f->f_mapping);
}
#endif

struct loop_switch_request {
	struct file *file;
	struct completion wait;
};

static void do_loop_switch(struct loop_device *lo, struct loop_switch_request *p)
{
	struct file *file = p->file;
	struct file *old_file=lo->lo_backing_file;
	struct address_space *mapping = file->LOOP_COMPAT_F_DENTRY->d_inode->i_mapping;
	
	/* This code runs on file backed loop only */
	/* no need to worry about -1 old_gfp_mask */
	mapping_set_gfp_mask(old_file->LOOP_COMPAT_F_DENTRY->d_inode->i_mapping, lo->old_gfp_mask);
	lo->lo_backing_file = file;
	memset(lo->lo_file_name, 0, LO_NAME_SIZE);
	lo->old_gfp_mask = mapping_gfp_mask(mapping);
	mapping_set_gfp_mask(mapping, (lo->old_gfp_mask & ~(__GFP_IO|__GFP_FS)) | __GFP_HIGH);
	complete(&p->wait);
}

/*
 * worker thread that handles reads/writes to file backed loop devices,
 * to avoid blocking in our make_request_fn. it also does loop decrypting
 * on reads for block backed loop, as that is too heavy to do from
 * b_end_io context where irqs may be disabled.
 */
static int loop_thread(void *data)
{
	struct loop_device *lo = data;
	struct bio *bio, *xbio, *merge;
	struct loop_bio_extension *extension;
	int x = 0, y, flushcnt = 0, isBarrBio;
	wait_queue_t waitq;
	char *md;
	struct request_queue *backingQueue;
	static const struct rlimit loop_rlim_defaults[RLIM_NLIMITS] = INIT_RLIMITS;

	init_waitqueue_entry(&waitq, current);
#if !defined(OLD_PER_THREAD_RLIMITS)
	memcpy(&current->signal->rlim[0], &loop_rlim_defaults[0], sizeof(current->signal->rlim));
#else
	memcpy(&current->rlim[0], &loop_rlim_defaults[0], sizeof(current->rlim));
#endif

#if LINUX_VERSION_CODE < 0x20613
	/* 2.6.18 and older kernels */
	daemonize("loop%d", lo->lo_number);
#endif

	if(lo->lo_device)
		backingQueue = bdev_get_queue(lo->lo_device);
	else
		backingQueue = NULL;

	/*
	 * loop can be used in an encrypted device,
	 * hence, it mustn't be stopped at all
	 * because it could be indirectly used during suspension
	 */
#if defined(PF_NOFREEZE)
	current->flags |= PF_NOFREEZE;
#elif defined(PF_IOTHREAD)
	current->flags |= PF_IOTHREAD;
#endif
	current->flags |= PF_LESS_THROTTLE;

	if (lo_nice > 0)
		lo_nice = 0;
	if (lo_nice < -20)
		lo_nice = -20;
	set_user_nice(current, lo_nice);

	atomic_inc(&lo->lo_pending);

	/*
	 * up sem, we are running
	 */
	complete(&lo->lo_done);

	for (;;) {
		add_wait_queue(&lo->lo_bio_wait, &waitq);
		for (;;) {
			set_current_state(TASK_INTERRUPTIBLE);
			if (!atomic_read(&lo->lo_pending))
				break;

			x = 0;
			spin_lock_irq(&lo->lo_lock);
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
			if(lo->lo_keyscrub_fn) x = 1;
#endif
			if (lo->lo_bio_que0) {
				/* don't sleep if device backed READ needs processing */
				/* don't sleep if file backed READ/WRITE needs processing */
				x = 1;
			} else if (lo->lo_bio_que1) {
				/* don't sleep if a buffer-bio is available */
				/* don't sleep if need-buffer-bio request is not set */
				if (lo->lo_bio_free0 || !(lo->lo_bio_need & 1))
					x = 1;
			} else if (lo->lo_bio_que2) {
				/* don't sleep if a merge-bio is available */
				/* don't sleep if need-merge-bio request is not set */
				if (lo->lo_bio_free1 || !(lo->lo_bio_need & 2))
					x = 1;
			}
			spin_unlock_irq(&lo->lo_lock);
			if (x)
				break;

			schedule();
		}
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&lo->lo_bio_wait, &waitq);

#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
		if(lo->lo_keyscrub_fn) {
			(*lo->lo_keyscrub_fn)(lo->lo_keyscrub_ptr);
			lo->lo_keyscrub_fn = 0;
		}
#endif
		/*
		 * could be woken because of tear-down, not because of
		 * pending work
		 */
		if (!atomic_read(&lo->lo_pending))
			break;

		bio = loop_get_bio(lo, &x);
		if (!bio)
			continue;

		/*
		 *  x  list tag         usage(has-buffer,has-merge)
		 * --- ---------------  ---------------------------
		 *  0  lo->lo_bio_que0  dev-r(y,y) / file-rw
		 *  1  lo->lo_bio_que1  dev-rw(n,y)
		 *  2  lo->lo_bio_que2  dev-rw(n,n)
		 */
		if (x >= 1) {
			/* loop_make_request_real didn't allocate a buffer, do that now */
			if (x == 1) {
				merge = bio;
				bio = merge->bi_private;
			} else {
				merge = NULL;
			}
			try_next_bio_vec:
			isBarrBio = 0;
			xbio = loop_get_buffer(lo, bio, 1, &merge, &isBarrBio);
			if (!xbio) {
				loop_unplug_backingdev(backingQueue);
				flushcnt = 0;
				if (merge)
					loop_add_queue_first(lo, merge, &lo->lo_bio_que1);
				else
					loop_add_queue_first(lo, bio, &lo->lo_bio_que2);
				/* lo->lo_bio_need should be non-zero now, go back to sleep */
				continue;
			}
			if (bio_rw(bio) == WRITE) {
				extension = xbio->bi_private;
				y = extension->bioext_index;
				md = kmap(bio->bi_io_vec[y].bv_page) + bio->bi_io_vec[y].bv_offset;
				if (lo_do_transfer(lo, WRITE, page_address(xbio->bi_io_vec[0].bv_page), md, extension->bioext_size, extension->bioext_iv)) {
					clear_bit(0, &merge->bi_flags);
				}
				kunmap(bio->bi_io_vec[y].bv_page);
			}

			/* merge & bio may vanish during generic_make_request() */
			/* if last vec gets processed before function returns   */
			y = (merge->bi_idx < bio->bi_vcnt) ? 1 : 0;

			/* check if backing device should be unplugged */
			x = 0;
			spin_lock_irq(&lo->lo_lock);
			if (!y && !lo->lo_bio_que1 && !lo->lo_bio_que2) {
				x = 1;
			}
			spin_unlock_irq(&lo->lo_lock);
			if (++flushcnt >= lo->lo_bio_flsh) {
				x = 1;
			}

#if defined(BIO_RW_NOIDLE) || (LINUX_VERSION_CODE >= 0x2061f)
			/*
			 * if kernel supports BIO_RW_NOIDLE, and if it looks like there
			 * won't be more requests, or enough have already been submitted,
			 * then set the BIO_RW_NOIDLE bit in the request.
			 */
			if (x) {
				xbio->bi_rw |= (1 << BIO_RW_NOIDLE);
			}
#endif

			generic_make_request(xbio);

			/* maybe just submitted bio was a barrier bio */
			if (isBarrBio) {
				atomic_dec(&lo->lo_bio_barr);
			}

			/* start I/O if there are no more requests lacking buffers */
			if (x) {
				loop_unplug_backingdev(backingQueue);
				flushcnt = 0;
			}

			/* other vecs may need processing too */
			if (y)
				goto try_next_bio_vec;

			/* request not completely processed yet */
 			continue;
 		}

		if (lo->lo_flags & LO_FLAGS_DO_BMAP) {
			/* request is for file backed device */
			if(unlikely(!bio->bi_bdev)) {
				do_loop_switch(lo, bio->bi_private);
				bio->bi_next = NULL;
				bio_put(bio);
			} else {
				y = do_bio_filebacked(lo, bio);
				bio->bi_next = NULL;
#if defined(LOOP_IO_END_RETURN_VOID_TYPE)
				bio_endio(bio, y);
#else
				bio_endio(bio, bio->bi_size, y);
#endif
			}
		} else {
			/* device backed read has completed, do decrypt now */
			extension = bio->bi_private;
			merge = extension->bioext_merge;
			y = extension->bioext_index;
			xbio = merge->bi_private;
			md = kmap(xbio->bi_io_vec[y].bv_page) + xbio->bi_io_vec[y].bv_offset;
			if (lo_do_transfer(lo, READ, page_address(bio->bi_io_vec[0].bv_page), md, extension->bioext_size, extension->bioext_iv)) {
				clear_bit(0, &merge->bi_flags);
			}
			flush_dcache_page(xbio->bi_io_vec[y].bv_page);
			kunmap(xbio->bi_io_vec[y].bv_page);
			loop_put_buffer(lo, bio, 0);
			if (!atomic_dec_and_test(&merge->bi_cnt))
				continue;
			xbio->bi_next = NULL;
#if defined(LOOP_IO_END_RETURN_VOID_TYPE)
			bio_endio(xbio, test_bit(0, &merge->bi_flags) ? (int)merge->bi_size : -EIO);
#else
			bio_endio(xbio, xbio->bi_size, test_bit(0, &merge->bi_flags) ? (int)merge->bi_size : -EIO);
#endif
			loop_put_buffer(lo, merge, 1);
		}

		/*
		 * woken both for pending work and tear-down, lo_pending
		 * will hit zero then
		 */
		if (atomic_dec_and_test(&lo->lo_pending))
			break;
	}

	complete(&lo->lo_done);
	return 0;
}

static void loop_set_softblksz(struct loop_device *lo, struct block_device *bdev)
{
	int	bs, x;

	if (lo->lo_device)
		bs = block_size(lo->lo_device);
	else
		bs = PAGE_SIZE;
	if (lo->lo_flags & LO_FLAGS_DO_BMAP) {
		x = (int) bdev->bd_inode->i_size;
		if ((bs == 8192) && (x & 0x1E00))
			bs = 4096;
		if ((bs == 4096) && (x & 0x0E00))
			bs = 2048;
		if ((bs == 2048) && (x & 0x0600))
			bs = 1024;
		if ((bs == 1024) && (x & 0x0200))
			bs = 512;
	}
	set_blocksize(bdev, bs);
}

/* 
 * loop_change_fd switches the backing store of a loopback device to a 
 * new file. This is useful for operating system installers to free up the
 * original file and in High Availability environments to switch to an 
 * alternative location for the content in case of server meltdown.
 * This can only work if the loop device is used read-only, file backed,
 * and if the new backing store is the same size and type as the old
 * backing store.
 */
static int loop_change_fd(struct loop_device *lo, unsigned int arg)
{
	struct file *file, *old_file;
	struct inode *inode;
	struct loop_switch_request w;
	struct bio *bio;
	int error;

	error = -EINVAL;
	/* loop must be read-only */
	if (!(lo->lo_flags & LO_FLAGS_READ_ONLY))
		goto out;

	/* loop must be file backed */
	if (!(lo->lo_flags & LO_FLAGS_DO_BMAP))
		goto out;

	error = -EBADF;
	file = fget(arg);
	if (!file)
		goto out;

	inode = file->LOOP_COMPAT_F_DENTRY->d_inode;
	old_file = lo->lo_backing_file;

	error = -EINVAL;
	/* new backing store must be file backed */
	if (!S_ISREG(inode->i_mode))
		goto out_putf;

	/* new backing store must support reads */
	if (!file->f_op || !file->f_op->read)
		goto out_putf;

	/* new backing store must be same size as the old one */
	if(i_size_read(inode) != i_size_read(old_file->LOOP_COMPAT_F_DENTRY->d_inode))
		goto out_putf;

	/* loop must be in properly initialized state */
	if(lo->lo_queue->make_request_fn != loop_make_request_real)
		goto out_putf;

	error = -ENOMEM;
	bio = bio_alloc(GFP_KERNEL, 1);
	if (!bio)
		goto out_putf;

	/* wait for loop thread to do the switch */
	init_completion(&w.wait);
	w.file = file;
	bio->bi_private = &w;
	bio->bi_bdev = NULL;
	bio->bi_rw = 0;
	loop_make_request_real(lo->lo_queue, bio);
	wait_for_completion(&w.wait);

	fput(old_file);
	return 0;
	
out_putf:
	fput(file);
out:
	return error;
}

#if defined(blk_fua_rq) || defined(REQ_FUA)
# define loop_blk_queue_ordered(a,b) blk_queue_ordered(a,b,NULL)
#else
# define loop_blk_queue_ordered(a,b) blk_queue_ordered(a,b)
#endif

static int loop_set_fd(struct loop_device *lo, unsigned int ldom,
		       struct block_device *bdev, unsigned int arg)
{
	struct file	*file;
	struct inode	*inode;
	struct block_device *lo_device = NULL;
	int		lo_flags = 0;
	int		error;

	error = -EBADF;
	file = fget(arg);
	if (!file)
		goto out;

	error = -EINVAL;
	inode = file->LOOP_COMPAT_F_DENTRY->d_inode;

	if (!(file->f_mode & FMODE_WRITE))
		lo_flags |= LO_FLAGS_READ_ONLY;

	init_completion(&lo->lo_done);
	spin_lock_init(&lo->lo_lock);
	init_waitqueue_head(&lo->lo_bio_wait);
	atomic_set(&lo->lo_pending, 0);
	atomic_set(&lo->lo_bio_barr, 0);
	clear_bit(0, &lo->lo_bio_flag);
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
	lo->lo_keyscrub_fn = 0;
#endif
	lo->lo_offset = lo->lo_sizelimit = 0;
	lo->lo_offs_sec = lo->lo_iv_remove = 0;
	lo->lo_encryption = NULL;
	lo->lo_encrypt_key_size = 0;
	lo->transfer = NULL;
	lo->lo_crypt_name[0] = 0;
	lo->lo_file_name[0] = 0;
	lo->lo_init[1] = lo->lo_init[0] = 0;
	lo->lo_key_owner = 0;
	lo->ioctl = NULL;
	lo->key_data = NULL;	
	lo->lo_bio_que2 = lo->lo_bio_que1 = lo->lo_bio_que0 = NULL;
	lo->lo_bio_free1 = lo->lo_bio_free0 = NULL;
	lo->lo_bio_flsh = lo->lo_bio_need = 0;

	if (S_ISBLK(inode->i_mode)) {
		lo_device = inode->i_bdev;
		if (lo_device == bdev) {
			error = -EBUSY;
			goto out_putf;
		}
		if (loop_prealloc_init(lo, 0)) {
			error = -ENOMEM;
			goto out_putf;
		}
		if (bdev_read_only(lo_device))
			lo_flags |= LO_FLAGS_READ_ONLY;
		else
			filemap_fdatawrite(inode->i_mapping);
	} else if (S_ISREG(inode->i_mode)) {
		/*
		 * If we can't read - sorry. If we only can't write - well,
		 * it's going to be read-only.
		 */
		if (!file->f_op || !file->f_op->read)
			goto out_putf;

		if (!file->f_op->write)
			lo_flags |= LO_FLAGS_READ_ONLY;

		lo_flags |= LO_FLAGS_DO_BMAP;
		if (loop_prealloc_init(lo, 1)) {
			error = -ENOMEM;
			goto out_putf;
		}
	} else
		goto out_putf;

	get_file(file);

	if (!(ldom & FMODE_WRITE))
		lo_flags |= LO_FLAGS_READ_ONLY;

	set_device_ro(bdev, (lo_flags & LO_FLAGS_READ_ONLY) != 0);

	lo->lo_device = lo_device;
	lo->lo_flags = lo_flags;
	if(lo_flags & LO_FLAGS_READ_ONLY)
		lo->lo_flags |= 0x200000; /* export to user space */
	lo->lo_backing_file = file;
	if (figure_loop_size(lo, bdev)) {
		error = -EFBIG;
		goto out_cleanup;
	}

	/*
	 * set queue make_request_fn, and add limits based on lower level
	 * device
	 */
	blk_queue_make_request(lo->lo_queue, loop_make_request_err);
	blk_queue_bounce_limit(lo->lo_queue, BLK_BOUNCE_ANY);
	blk_queue_max_segment_size(lo->lo_queue, PAGE_CACHE_SIZE);
	blk_queue_segment_boundary(lo->lo_queue, PAGE_CACHE_SIZE - 1);
#if LINUX_VERSION_CODE >= 0x20622
	blk_queue_max_segments(lo->lo_queue, BLK_MAX_SEGMENTS);
	blk_queue_max_hw_sectors(lo->lo_queue, BLK_SAFE_MAX_SECTORS);
#else
	blk_queue_max_phys_segments(lo->lo_queue, MAX_PHYS_SEGMENTS);
	blk_queue_max_hw_segments(lo->lo_queue, MAX_HW_SEGMENTS);
#if !defined(MAX_SECTORS)
# define MAX_SECTORS SAFE_MAX_SECTORS
#endif
	blk_queue_max_sectors(lo->lo_queue, MAX_SECTORS);
#endif
	lo->lo_queue->queue_flags &= ~(1 << QUEUE_FLAG_CLUSTER);
#if (LINUX_VERSION_CODE >= 0x20609) || defined(QUEUE_FLAG_ORDERED)
	loop_blk_queue_ordered(lo->lo_queue, QUEUE_ORDERED_NONE);
#endif
#if defined(LOOP_HAVE_ISSUE_FLUSH_FN)
	blk_queue_issue_flush_fn(lo->lo_queue, NULL);
#endif

	/*
	 * we remap to a block device, make sure we correctly stack limits
	 */
	if (S_ISBLK(inode->i_mode) && lo_device) {
		struct request_queue *q = bdev_get_queue(lo_device);

#if LINUX_VERSION_CODE >= 0x2061f
		blk_queue_logical_block_size(lo->lo_queue, queue_logical_block_size(q));
#else
		blk_queue_hardsect_size(lo->lo_queue, q->hardsect_size);
#endif
#if (LINUX_VERSION_CODE >= 0x20609) && !defined(QUEUE_FLAG_ORDERED)
		if(q->ordered == QUEUE_ORDERED_TAG) {
			loop_blk_queue_ordered(lo->lo_queue, QUEUE_ORDERED_TAG);
#if defined(LOOP_HAVE_ISSUE_FLUSH_FN)
			if(q->issue_flush_fn) {
				blk_queue_issue_flush_fn(lo->lo_queue, loop_issue_flush);
			}
#endif
		}
#elif (LINUX_VERSION_CODE >= 0x20609) || defined(QUEUE_FLAG_ORDERED)
		if(q->queue_flags & (1 << QUEUE_FLAG_ORDERED)) {
			loop_blk_queue_ordered(lo->lo_queue, 1);
#if defined(LOOP_HAVE_ISSUE_FLUSH_FN)
			if(q->issue_flush_fn) {
				blk_queue_issue_flush_fn(lo->lo_queue, loop_issue_flush);
			}
#endif
		}
#endif
	}

	if (lo_flags & LO_FLAGS_DO_BMAP) {
		lo->old_gfp_mask = mapping_gfp_mask(inode->i_mapping);
		mapping_set_gfp_mask(inode->i_mapping, (lo->old_gfp_mask & ~(__GFP_IO|__GFP_FS)) | __GFP_HIGH);
	} else {
		lo->old_gfp_mask = -1;
	}

	loop_set_softblksz(lo, bdev);

#if LINUX_VERSION_CODE < 0x20613
	/* 2.6.18 and older kernels */
	error = kernel_thread(loop_thread, lo, CLONE_KERNEL);
	if(error < 0)
		goto out_mapping;
#else
	/* 2.6.19 and newer kernels */
	{
		struct task_struct *t;
		t = kthread_create(loop_thread, lo, "loop%d", lo->lo_number);
		if (IS_ERR(t)) {
			error = PTR_ERR(t);
			goto out_mapping;
		}
		wake_up_process(t);
	}
#endif

	wait_for_completion(&lo->lo_done);
	fput(file);
#if defined(QUEUE_FLAG_PLUGGED)
	lo->lo_queue->unplug_fn = loop_unplug_loopdev;
#endif
	lo->lo_queue->queuedata = lo;
	__module_get(THIS_MODULE);
	return 0;

 out_mapping:
	if(lo->old_gfp_mask != -1)
		mapping_set_gfp_mask(inode->i_mapping, lo->old_gfp_mask);
 out_cleanup:
	loop_prealloc_cleanup(lo);
	fput(file);
 out_putf:
	fput(file);
 out:
	return error;
}

static int loop_release_xfer(struct loop_device *lo)
{
	int err = 0;
	struct loop_func_table *xfer = lo->lo_encryption;

	if (xfer) {
		lo->transfer = NULL;
		if (xfer->release)
			err = xfer->release(lo);
		lo->lo_encryption = NULL;
		module_put(xfer->owner);
	}
	return err;
}

static int loop_init_xfer(struct loop_device *lo, struct loop_func_table *xfer, struct loop_info64 *i)
{
	int err = 0;

	if (xfer) {
		struct module *owner = xfer->owner;

		if(!try_module_get(owner))
			return -EINVAL;
		if (xfer->init)
			err = xfer->init(lo, i);
		if (err)
			module_put(owner);
		else
			lo->lo_encryption = xfer;
	}
	return err;
}

static int loop_clr_fd(struct loop_device *lo, struct block_device *bdev)
{
	struct file *filp = lo->lo_backing_file;
	int gfp = lo->old_gfp_mask;

	if (bdev->bd_openers != 1)	/* one for this fd being open */
		return -EBUSY;
	if (filp==NULL)
		return -EINVAL;

	lo->lo_queue->queuedata = NULL;
	lo->lo_queue->make_request_fn = loop_make_request_err;
	if (atomic_dec_and_test(&lo->lo_pending))
		wake_up_interruptible(&lo->lo_bio_wait);
	wait_for_completion(&lo->lo_done);

#if (LINUX_VERSION_CODE >= 0x20609) || defined(QUEUE_FLAG_ORDERED)
	loop_blk_queue_ordered(lo->lo_queue, QUEUE_ORDERED_NONE);
#endif
	loop_prealloc_cleanup(lo);
	lo->lo_backing_file = NULL;
	loop_release_xfer(lo);
	lo->transfer = NULL;
	lo->ioctl = NULL;
	lo->lo_device = NULL;
	lo->lo_encryption = NULL;
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
	lo->lo_keyscrub_fn = 0;
#endif
	lo->lo_offset = lo->lo_sizelimit = 0;
	lo->lo_offs_sec = lo->lo_iv_remove = 0;
	lo->lo_encrypt_key_size = 0;
	lo->lo_flags = 0;
	lo->lo_init[1] = lo->lo_init[0] = 0;
	lo->lo_key_owner = 0;
	lo->key_data = NULL;
	memset(lo->lo_encrypt_key, 0, LO_KEY_SIZE);
	memset(lo->lo_crypt_name, 0, LO_NAME_SIZE);
	memset(lo->lo_file_name, 0, LO_NAME_SIZE);
#if !defined(OLD_INVALIDATE_BDEV_INTERFACE)
	invalidate_bdev(bdev);
#else
	invalidate_bdev(bdev, 0);
#endif
	set_capacity(disks[lo->lo_number], 0);
	if (gfp != -1)
		mapping_set_gfp_mask(filp->LOOP_COMPAT_F_DENTRY->d_inode->i_mapping, gfp);
	fput(filp);
	module_put(THIS_MODULE);
	return 0;
}

static int loop_set_status(struct loop_device *lo, struct block_device *bdev, struct loop_info64 *info)
{
	int err;
	struct loop_func_table *xfer = NULL;
#if LINUX_VERSION_CODE >= 0x2061c
	uid_t uid = current_uid();
#else
	uid_t uid = current->uid;
#endif

	if (lo->lo_encrypt_key_size && lo->lo_key_owner != uid &&
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;
	if ((unsigned int) info->lo_encrypt_key_size > LO_KEY_SIZE)
		return -EINVAL;

	err = loop_release_xfer(lo);
	if (err)
		return err;

	if ((loff_t)info->lo_offset < 0) {
		/* negative offset == remove offset from IV computations */
		lo->lo_offset = -(info->lo_offset);
		lo->lo_iv_remove = lo->lo_offset >> 9;
	} else {
		/* positive offset == include offset in IV computations */
		lo->lo_offset = info->lo_offset;
		lo->lo_iv_remove = 0;
	}
	lo->lo_offs_sec = lo->lo_offset >> 9;
	lo->lo_sizelimit = info->lo_sizelimit;
	err = figure_loop_size(lo, bdev);
	if (err)
		return err;
	loop_set_softblksz(lo, bdev);

	if (info->lo_encrypt_type) {
		unsigned int type = info->lo_encrypt_type;

		if (type >= MAX_LO_CRYPT)
			return -EINVAL;
		xfer = xfer_funcs[type];
		if (xfer == NULL)
			return -EINVAL;
	} else if(!(lo->lo_flags & LO_FLAGS_DO_BMAP)) {
#if LINUX_VERSION_CODE >= 0x20622
		blk_queue_max_hw_sectors(lo->lo_queue, PAGE_CACHE_SIZE >> 9);
#else
		blk_queue_max_sectors(lo->lo_queue, PAGE_CACHE_SIZE >> 9);
#endif
	}
	err = loop_init_xfer(lo, xfer, info);
	if (err)
		return err;

	if (!xfer)
		xfer = &none_funcs;
	lo->transfer = xfer->transfer;
	lo->ioctl = xfer->ioctl;
	
	memcpy(lo->lo_file_name, info->lo_file_name, LO_NAME_SIZE);
	memcpy(lo->lo_crypt_name, info->lo_crypt_name, LO_NAME_SIZE);
	lo->lo_file_name[LO_NAME_SIZE-1] = 0;
	lo->lo_crypt_name[LO_NAME_SIZE-1] = 0;
	lo->lo_encrypt_key_size = info->lo_encrypt_key_size;
	lo->lo_init[0] = info->lo_init[0];
	lo->lo_init[1] = info->lo_init[1];
	if (info->lo_encrypt_key_size) {
		memcpy(lo->lo_encrypt_key, info->lo_encrypt_key,
		       info->lo_encrypt_key_size);
		lo->lo_key_owner = uid;
	}	

	lo->lo_queue->make_request_fn = loop_make_request_real;
	return 0;
}

static int loop_get_status(struct loop_device *lo, struct loop_info64 *info)
{
	struct file *file = lo->lo_backing_file;
	struct kstat stat;
	int error;

	error = vfs_getattr(file->f_vfsmnt, file->LOOP_COMPAT_F_DENTRY, &stat);
	if (error)
		return error;
	memset(info, 0, sizeof(*info));
	info->lo_number = lo->lo_number;
	info->lo_device = huge_encode_dev(stat.dev);
	info->lo_inode = stat.ino;
	info->lo_rdevice = huge_encode_dev(lo->lo_device ? stat.rdev : stat.dev);
	info->lo_offset = lo->lo_iv_remove ? -(lo->lo_offset) : lo->lo_offset;
	info->lo_sizelimit = lo->lo_sizelimit;
	info->lo_flags = lo->lo_flags;
	memcpy(info->lo_file_name, lo->lo_file_name, LO_NAME_SIZE);
	memcpy(info->lo_crypt_name, lo->lo_crypt_name, LO_NAME_SIZE);
	info->lo_encrypt_type = lo->lo_encryption ? lo->lo_encryption->number : 0;
	if (lo->lo_encrypt_key_size && capable(CAP_SYS_ADMIN)) {
		info->lo_encrypt_key_size = lo->lo_encrypt_key_size;
		memcpy(info->lo_encrypt_key, lo->lo_encrypt_key,
		       lo->lo_encrypt_key_size);
		info->lo_init[0] = lo->lo_init[0];
		info->lo_init[1] = lo->lo_init[1];
	}
	return 0;
}

static void
loop_info64_from_old(const struct loop_info *info, struct loop_info64 *info64)
{
	memset(info64, 0, sizeof(*info64));
	info64->lo_number = info->lo_number;
	info64->lo_device = info->lo_device;
	info64->lo_inode = info->lo_inode;
	info64->lo_rdevice = info->lo_rdevice;
	info64->lo_offset = info->lo_offset;
	info64->lo_encrypt_type = info->lo_encrypt_type;
	info64->lo_encrypt_key_size = info->lo_encrypt_key_size;
	info64->lo_flags = info->lo_flags;
	info64->lo_init[0] = info->lo_init[0];
	info64->lo_init[1] = info->lo_init[1];
	if (info->lo_encrypt_type == LO_CRYPT_CRYPTOAPI)
		memcpy(info64->lo_crypt_name, info->lo_name, LO_NAME_SIZE);
	else
		memcpy(info64->lo_file_name, info->lo_name, LO_NAME_SIZE);
	memcpy(info64->lo_encrypt_key, info->lo_encrypt_key, LO_KEY_SIZE);
}

static int
loop_info64_to_old(struct loop_info64 *info64, struct loop_info *info)
{
	memset(info, 0, sizeof(*info));
	info->lo_number = info64->lo_number;
	info->lo_device = info64->lo_device;
	info->lo_inode = info64->lo_inode;
	info->lo_rdevice = info64->lo_rdevice;
	info->lo_offset = info64->lo_offset;
	info->lo_encrypt_type = info64->lo_encrypt_type;
	info->lo_encrypt_key_size = info64->lo_encrypt_key_size;
	info->lo_flags = info64->lo_flags;
	info->lo_init[0] = info64->lo_init[0];
	info->lo_init[1] = info64->lo_init[1];
	if (info->lo_encrypt_type == LO_CRYPT_CRYPTOAPI)
		memcpy(info->lo_name, info64->lo_crypt_name, LO_NAME_SIZE);
	else
		memcpy(info->lo_name, info64->lo_file_name, LO_NAME_SIZE);
	memcpy(info->lo_encrypt_key, info64->lo_encrypt_key, LO_KEY_SIZE);

	/* error in case values were truncated */
	if (info->lo_device != info64->lo_device ||
	    info->lo_rdevice != info64->lo_rdevice ||
	    info->lo_inode != info64->lo_inode ||
	    info->lo_offset != info64->lo_offset ||
	    info64->lo_sizelimit)
		return -EOVERFLOW;

	return 0;
}

static int
loop_set_status_old(struct loop_device *lo, struct block_device *bdev, const struct loop_info *arg)
{
	struct loop_info info;
	struct loop_info64 info64;

	if (copy_from_user(&info, arg, sizeof (struct loop_info)))
		return -EFAULT;
	loop_info64_from_old(&info, &info64);
	memset(&info.lo_encrypt_key[0], 0, sizeof(info.lo_encrypt_key));
	return loop_set_status(lo, bdev, &info64);
}

static int
loop_set_status64(struct loop_device *lo, struct block_device *bdev, struct loop_info64 *arg)
{
	struct loop_info64 info64;

	if (copy_from_user(&info64, arg, sizeof (struct loop_info64)))
		return -EFAULT;
	return loop_set_status(lo, bdev, &info64);
}

static int
loop_get_status_old(struct loop_device *lo, struct loop_info *arg) {
	struct loop_info info;
	struct loop_info64 info64;
	int err = 0;

	if (!arg)
		err = -EINVAL;
	if (!err)
		err = loop_get_status(lo, &info64);
	if (!err)
		err = loop_info64_to_old(&info64, &info);
	if (!err && copy_to_user(arg, &info, sizeof(info)))
		err = -EFAULT;

	return err;
}

static int
loop_get_status64(struct loop_device *lo, struct loop_info64 *arg) {
	struct loop_info64 info64;
	int err = 0;

	if (!arg)
		err = -EINVAL;
	if (!err)
		err = loop_get_status(lo, &info64);
	if (!err && copy_to_user(arg, &info64, sizeof(info64)))
		err = -EFAULT;

	return err;
}

#if LINUX_VERSION_CODE >= 0x2061c
static int lo_ioctl(struct block_device *bdev, fmode_t ldom, unsigned int cmd, unsigned long arg)
{
#else
static int lo_ioctl(struct inode *inode, struct file * file, unsigned int cmd, unsigned long arg)
{
	struct block_device *bdev = inode->i_bdev;
	unsigned int ldom = file ? file->f_mode : 0;
#endif
	struct loop_device *lo = bdev->bd_disk->private_data;
	int err;
	wait_queue_t waitq;

	/*
	 * mutual exclusion - lock
	 */
	init_waitqueue_entry(&waitq, current);
	add_wait_queue(&lo->lo_ioctl_wait, &waitq);
	for (;;) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		spin_lock(&lo->lo_ioctl_spin);
		err = lo->lo_ioctl_busy;
		if(!err) lo->lo_ioctl_busy = 1;
		spin_unlock(&lo->lo_ioctl_spin);
		if(!err) break;
		schedule();
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&lo->lo_ioctl_wait, &waitq);

	/*
	 * LOOP_SET_FD can only be called when no device is attached.
	 * All other ioctls can only be called when a device is attached.
	 */
	if (bdev->bd_disk->queue->queuedata != NULL) {
		if (cmd == LOOP_SET_FD) {
			err = -EBUSY;
			goto out_err;
		}
	} else {
		if (cmd != LOOP_SET_FD) {
			err = -ENXIO;
			goto out_err;
		}
	}

	switch (cmd) {
	case LOOP_SET_FD:
		err = loop_set_fd(lo, ldom, bdev, arg);
		break;
	case LOOP_CHANGE_FD:
		err = loop_change_fd(lo, arg);
		break;
	case LOOP_CLR_FD:
		err = loop_clr_fd(lo, bdev);
		break;
	case LOOP_SET_STATUS:
		err = loop_set_status_old(lo, bdev, (struct loop_info *) arg);
		break;
	case LOOP_GET_STATUS:
		err = loop_get_status_old(lo, (struct loop_info *) arg);
		break;
	case LOOP_SET_STATUS64:
		err = loop_set_status64(lo, bdev, (struct loop_info64 *) arg);
		break;
	case LOOP_GET_STATUS64:
		err = loop_get_status64(lo, (struct loop_info64 *) arg);
		break;
	case LOOP_RECOMPUTE_DEV_SIZE:
		err = figure_loop_size(lo, bdev);
		break;
	default:
		err = lo->ioctl ? lo->ioctl(lo, cmd, arg) : -EINVAL;
	}
out_err:
	/*
	 * mutual exclusion - unlock
	 */
	spin_lock(&lo->lo_ioctl_spin);
	lo->lo_ioctl_busy = 0;
	spin_unlock(&lo->lo_ioctl_spin);
	wake_up_all(&lo->lo_ioctl_wait);

	return err;
}

#if defined(CONFIG_COMPAT) && defined(HAVE_COMPAT_IOCTL)
struct loop_info32 {
	compat_int_t	lo_number;      /* ioctl r/o */
	compat_dev_t	lo_device;      /* ioctl r/o */
	compat_ulong_t	lo_inode;       /* ioctl r/o */
	compat_dev_t	lo_rdevice;     /* ioctl r/o */
	compat_int_t	lo_offset;
	compat_int_t	lo_encrypt_type;
	compat_int_t	lo_encrypt_key_size;    /* ioctl w/o */
	compat_int_t	lo_flags;       /* ioctl r/o */
	char		lo_name[LO_NAME_SIZE];
	unsigned char	lo_encrypt_key[LO_KEY_SIZE]; /* ioctl w/o */
	compat_ulong_t	lo_init[2];
	char		reserved[4];
};

#if LINUX_VERSION_CODE >= 0x2061c
static int lo_compat_ioctl(struct block_device *p1, fmode_t p2, unsigned int cmd, unsigned long arg)
{
#else
static long lo_compat_ioctl(struct file *p2, unsigned int cmd, unsigned long arg)
{
	struct inode *p1 = p2->LOOP_COMPAT_F_DENTRY->d_inode;
#endif
	mm_segment_t old_fs = get_fs();
	struct loop_info l;
	struct loop_info32 *ul = (struct loop_info32 *)arg;
	int err = -ENOIOCTLCMD;

	switch (cmd) {
	case LOOP_SET_FD:
	case LOOP_CLR_FD:
	case LOOP_SET_STATUS64:
	case LOOP_GET_STATUS64:
	case LOOP_CHANGE_FD:
	case LOOP_MULTI_KEY_SETUP:
	case LOOP_MULTI_KEY_SETUP_V3:
	case LOOP_RECOMPUTE_DEV_SIZE:
		err = lo_ioctl(p1, p2, cmd, arg);
		break;
	case LOOP_SET_STATUS:
		memset(&l, 0, sizeof(l));
		err = get_user(l.lo_number, &ul->lo_number);
		err |= get_user(l.lo_device, &ul->lo_device);
		err |= get_user(l.lo_inode, &ul->lo_inode);
		err |= get_user(l.lo_rdevice, &ul->lo_rdevice);
		err |= copy_from_user(&l.lo_offset, &ul->lo_offset,
		        8 + (unsigned long)l.lo_init - (unsigned long)&l.lo_offset);
		if (err) {
			err = -EFAULT;
		} else {
			set_fs (KERNEL_DS);
			err = lo_ioctl(p1, p2, cmd, (unsigned long)&l);
			set_fs (old_fs);
		}
		memset(&l, 0, sizeof(l));
		break;
	case LOOP_GET_STATUS:
		set_fs (KERNEL_DS);
		err = lo_ioctl(p1, p2, cmd, (unsigned long)&l);
		set_fs (old_fs);
		if (!err) {
			err = put_user(l.lo_number, &ul->lo_number);
			err |= put_user(l.lo_device, &ul->lo_device);
			err |= put_user(l.lo_inode, &ul->lo_inode);
			err |= put_user(l.lo_rdevice, &ul->lo_rdevice);
			err |= copy_to_user(&ul->lo_offset, &l.lo_offset,
				(unsigned long)l.lo_init - (unsigned long)&l.lo_offset);
			if (err)
				err = -EFAULT;
		}
		memset(&l, 0, sizeof(l));
		break;

	}
	return err;
}
#endif

static struct block_device_operations lo_fops = {
	.owner =	THIS_MODULE,
	.ioctl =	lo_ioctl,
#if defined(CONFIG_COMPAT) && defined(HAVE_COMPAT_IOCTL)
	.compat_ioctl = lo_compat_ioctl,
#endif
};

/*
 * And now the modules code and kernel interface.
 */
MODULE_LICENSE("GPL");
MODULE_ALIAS_BLOCKDEV_MAJOR(LOOP_MAJOR);

int loop_register_transfer(struct loop_func_table *funcs)
{
	unsigned int n = funcs->number;

	if (n >= MAX_LO_CRYPT || xfer_funcs[n])
		return -EINVAL;
	xfer_funcs[n] = funcs;
	return 0;
}

int loop_unregister_transfer(int number)
{
	unsigned int n = number;
	struct loop_device *lo;
	struct loop_func_table *xfer;
	int x;

	if (n == 0 || n >= MAX_LO_CRYPT || (xfer = xfer_funcs[n]) == NULL)
		return -EINVAL;
	xfer_funcs[n] = NULL;
	for (x = 0; x < max_loop; x++) {
		lo = loop_dev_ptr_arr[x];
		if (!lo)
			continue;
		if (lo->lo_encryption == xfer)
			loop_release_xfer(lo);
	}
	return 0;
}

EXPORT_SYMBOL(loop_register_transfer);
EXPORT_SYMBOL(loop_unregister_transfer);

int __init loop_init(void)
{
	int	i;

#ifdef CONFIG_BLK_DEV_LOOP_AES
#if defined(CONFIG_BLK_DEV_LOOP_PADLOCK) && (defined(CONFIG_X86) || defined(CONFIG_X86_64))
	if((boot_cpu_data.x86 >= 6) && CentaurHauls_ID_and_enabled_ACE()) {
		xfer_funcs[LO_CRYPT_AES] = &funcs_padlock_aes;
		printk(KERN_INFO "loop: padlock hardware AES enabled\n");
	} else
#endif
#if defined(CONFIG_BLK_DEV_LOOP_INTELAES) && (defined(CONFIG_X86) || defined(CONFIG_X86_64))
	if((boot_cpu_data.x86 >= 6) && ((cpuid_ecx(1) & 0x02000000) == 0x02000000)) {
		xfer_funcs[LO_CRYPT_AES] = &funcs_intel_aes;
		printk("loop: Intel hardware AES enabled\n");
	} else
#endif
#endif
	{ } /* needed because of above else statements */

	if ((max_loop < 1) || (max_loop > 256)) {
		printk(KERN_WARNING "loop: invalid max_loop (must be between"
				    " 1 and 256), using default (8)\n");
		max_loop = 8;
	}

	if (register_blkdev(LOOP_MAJOR, "loop"))
		return -EIO;

	loop_dev_ptr_arr = kmalloc(max_loop * sizeof(struct loop_device *), GFP_KERNEL);
	if (!loop_dev_ptr_arr)
		goto out_mem1;

	disks = kmalloc(max_loop * sizeof(struct gendisk *), GFP_KERNEL);
	if (!disks)
		goto out_mem2;

	for (i = 0; i < max_loop; i++) {
		loop_dev_ptr_arr[i] = kmalloc(sizeof(struct loop_device), GFP_KERNEL);
		if (!loop_dev_ptr_arr[i])
			goto out_mem3;
	}

	for (i = 0; i < max_loop; i++) {
		disks[i] = alloc_disk(1);
		if (!disks[i])
			goto out_mem4;
	}

	for (i = 0; i < max_loop; i++) {
		disks[i]->queue = blk_alloc_queue(GFP_KERNEL);
		if (!disks[i]->queue)
			goto out_mem5;
		disks[i]->queue->queuedata = NULL;
		blk_queue_make_request(disks[i]->queue, loop_make_request_err);
	}

	for (i = 0; i < (sizeof(lo_prealloc) / sizeof(int)); i += 2) {
		if (!lo_prealloc[i])
			continue;
		if (lo_prealloc[i] < LO_PREALLOC_MIN)
			lo_prealloc[i] = LO_PREALLOC_MIN;
		if (lo_prealloc[i] > LO_PREALLOC_MAX)
			lo_prealloc[i] = LO_PREALLOC_MAX;
	}

#if defined(IOCTL32_COMPATIBLE_PTR)
	register_ioctl32_conversion(LOOP_MULTI_KEY_SETUP, IOCTL32_COMPATIBLE_PTR);
	register_ioctl32_conversion(LOOP_MULTI_KEY_SETUP_V3, IOCTL32_COMPATIBLE_PTR);
	register_ioctl32_conversion(LOOP_RECOMPUTE_DEV_SIZE, IOCTL32_COMPATIBLE_PTR);
#endif

#ifdef CONFIG_DEVFS_FS
	devfs_mk_dir("loop");
#endif

	for (i = 0; i < max_loop; i++) {
		struct loop_device *lo = loop_dev_ptr_arr[i];
		struct gendisk *disk = disks[i];
		memset(lo, 0, sizeof(struct loop_device));
		lo->lo_number = i;
		lo->lo_queue = disk->queue;
		spin_lock_init(&lo->lo_ioctl_spin);
		init_waitqueue_head(&lo->lo_ioctl_wait);
		disk->major = LOOP_MAJOR;
		disk->first_minor = i;
		disk->fops = &lo_fops;
		sprintf(disk->disk_name, "loop%d", i);
#ifdef CONFIG_DEVFS_FS
		sprintf(disk->devfs_name, "loop/%d", i);
#endif
		disk->private_data = lo;
		add_disk(disk);
	}

#ifdef CONFIG_BLK_DEV_LOOP_AES
#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
	printk(KERN_INFO "loop: AES key scrubbing enabled\n");
#endif
#endif
	printk(KERN_INFO "loop: loaded (max %d devices)\n", max_loop);
	return 0;

out_mem5:
	while (i--)
		blk_cleanup_queue(disks[i]->queue);
	i = max_loop;
out_mem4:
	while (i--)
		put_disk(disks[i]);
	i = max_loop;
out_mem3:
	while (i--)
		kfree(loop_dev_ptr_arr[i]);
	kfree(disks);
out_mem2:
	kfree(loop_dev_ptr_arr);
out_mem1:
	unregister_blkdev(LOOP_MAJOR, "loop");
	printk(KERN_ERR "loop: ran out of memory\n");
	return -ENOMEM;
}

void loop_exit(void)
{
	int i;

	for (i = 0; i < max_loop; i++) {
		del_gendisk(disks[i]);
		put_disk(disks[i]);
		blk_cleanup_queue(loop_dev_ptr_arr[i]->lo_queue);
		kfree(loop_dev_ptr_arr[i]);
	}
#ifdef CONFIG_DEVFS_FS
	devfs_remove("loop");
#endif
	unregister_blkdev(LOOP_MAJOR, "loop");
	kfree(disks);
	kfree(loop_dev_ptr_arr);

#if defined(IOCTL32_COMPATIBLE_PTR)
	unregister_ioctl32_conversion(LOOP_MULTI_KEY_SETUP);
	unregister_ioctl32_conversion(LOOP_MULTI_KEY_SETUP_V3);
	unregister_ioctl32_conversion(LOOP_RECOMPUTE_DEV_SIZE);
#endif
}

module_init(loop_init);
module_exit(loop_exit);

#ifdef CONFIG_BLK_DEV_LOOP_KEYSCRUB
void loop_add_keyscrub_fn(struct loop_device *lo, void (*fn)(void *), void *ptr)
{
    lo->lo_keyscrub_ptr = ptr;
    wmb();
    lo->lo_keyscrub_fn = fn;
    wake_up_interruptible(&lo->lo_bio_wait);
}
EXPORT_SYMBOL(loop_add_keyscrub_fn);
#endif
