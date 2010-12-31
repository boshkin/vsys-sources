int cpt_collect_files(cpt_context_t *);
int cpt_collect_fs(cpt_context_t *);
int cpt_collect_namespace(cpt_context_t *);
int cpt_collect_sysvsem_undo(cpt_context_t *);
int cpt_collect_tty(struct file *, cpt_context_t *);
int cpt_dump_files(struct cpt_context *ctx);
int cpt_dump_files_struct(struct cpt_context *ctx);
int cpt_dump_fs_struct(struct cpt_context *ctx);
int cpt_dump_content_sysvshm(struct file *file, struct cpt_context *ctx);
int cpt_dump_content_tty(struct file *file, struct cpt_context *ctx);
int cpt_dump_tty(cpt_object_t *, struct cpt_context *ctx);
struct file * rst_sysv_shm_vma(struct cpt_vma_image *vmai, struct cpt_context *ctx);
struct file * rst_sysv_shm_itself(loff_t pos, struct cpt_context *ctx);
struct file * rst_open_tty(struct cpt_file_image *fi, struct cpt_inode_image *ii, unsigned flags, struct cpt_context *ctx);
__u32 cpt_tty_fasync(struct file *file, struct cpt_context *ctx);

int rst_posix_locks(struct cpt_context *ctx);

struct file *rst_file(loff_t pos, int fd, struct cpt_context *ctx);
int rst_files_complete(struct cpt_task_image *ti, struct cpt_context *ctx);
int rst_files_std(struct cpt_task_image *ti, struct cpt_context *ctx);
__u32 rst_files_flag(struct cpt_task_image *ti, struct cpt_context *ctx);
int rst_fs_complete(struct cpt_task_image *ti, struct cpt_context *ctx);
int rst_restore_fs(struct cpt_context *ctx);

int cpt_collect_sysv(cpt_context_t *);
int cpt_dump_sysvsem(struct cpt_context *ctx);
int cpt_dump_sysvmsg(struct cpt_context *ctx);
int rst_sysv_ipc(struct cpt_context *ctx);
int rst_semundo_complete(struct cpt_task_image *ti, struct cpt_context *ctx);
__u32 rst_semundo_flag(struct cpt_task_image *ti, struct cpt_context *ctx);

int cpt_dump_namespace(struct cpt_context *ctx);
int rst_root_namespace(struct cpt_context *ctx);

int rst_stray_files(struct cpt_context *ctx);
int rst_tty_jobcontrol(struct cpt_context *ctx);

void rst_flush_filejobs(struct cpt_context *);
int rst_do_filejobs(struct cpt_context *);

extern struct file_operations eventpoll_fops;
extern struct file_operations signalfd_fops;

int rst_eventpoll(struct cpt_context *);
struct file *cpt_open_epolldev(struct cpt_file_image *fi,
			       unsigned flags,
			       struct cpt_context *ctx);
int cpt_dump_epolldev(cpt_object_t *obj, struct cpt_context *);

int cpt_dump_dir(struct dentry *d, struct vfsmount *mnt, struct cpt_context *ctx);
int cpt_get_dentry(struct dentry **dp, struct vfsmount **mp,
		   loff_t *pos, struct cpt_context *ctx);

int cpt_dump_inotify(cpt_object_t *obj, cpt_context_t *ctx);
int rst_inotify(cpt_context_t *ctx);
struct file *rst_open_inotify(struct cpt_file_image *fi,
			      unsigned flags,
			      struct cpt_context *ctx);

struct dentry *cpt_fake_link(struct dentry *d, struct vfsmount *mnt,
		struct inode *ino, struct cpt_context *ctx);

int cpt_verify_overmount(char *path, struct dentry *d, struct vfsmount *mnt,
			 int verify, cpt_context_t *ctx);

#define check_one_vfsmount(mnt) \
	(strcmp(mnt->mnt_sb->s_type->name, "rootfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "ext3") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "ext2") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "simfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "unionfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "tmpfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "devpts") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "proc") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "sysfs") != 0 && \
	 strcmp(mnt->mnt_sb->s_type->name, "binfmt_misc") != 0)
