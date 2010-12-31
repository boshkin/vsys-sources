#ifndef __VIRTINFO_SCP_H__
#define __VIRTINFO_SCP_H__

/*
 * Dump and restore operations are non-symmetric.
 * With respect to finish/fail hooks, 2 dump hooks are called from
 * different proc operations, but restore hooks are called from a single one.
 */
#define VIRTINFO_SCP_COLLECT    0x10
#define VIRTINFO_SCP_DUMP       0x11
#define VIRTINFO_SCP_DMPFIN     0x12
#define VIRTINFO_SCP_RSTCHECK   0x13
#define VIRTINFO_SCP_RESTORE    0x14
#define VIRTINFO_SCP_RSTFAIL    0x15

#define VIRTINFO_SCP_RSTTSK     0x20
#define VIRTINFO_SCP_RSTMM      0x21

#define VIRTINFO_SCP_TEST	0x30

#define VIRTNOTIFY_CHANGE       0x100 

#endif /* __VIRTINFO_SCP_H__ */
