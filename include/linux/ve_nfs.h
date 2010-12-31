/*
 * linux/include/ve_nfs.h
 *
 * VE context for NFS
 *
 * Copyright (C) 2007 SWsoft
 */

#ifndef __VE_NFS_H__
#define __VE_NFS_H__

#ifdef CONFIG_VE

#include <linux/ve.h>

#define NFS_CTX_FIELD(arg)  (get_exec_env()->_##arg)

#else /* CONFIG_VE */

#define NFS_CTX_FIELD(arg)	_##arg

#endif /* CONFIG_VE */

#define nlmsvc_grace_period	NFS_CTX_FIELD(nlmsvc_grace_period)
#define nlmsvc_timeout		NFS_CTX_FIELD(nlmsvc_timeout)
#define nlmsvc_users		NFS_CTX_FIELD(nlmsvc_users)
#define nlmsvc_task		NFS_CTX_FIELD(nlmsvc_task)
#define nlmsvc_rqst		NFS_CTX_FIELD(nlmsvc_rqst)

#endif
