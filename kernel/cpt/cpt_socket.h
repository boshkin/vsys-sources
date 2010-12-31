struct sock;

int cpt_collect_passedfds(cpt_context_t *);
int cpt_index_sockets(cpt_context_t *);
int cpt_collect_socket(struct file *, cpt_context_t *);
int cpt_dump_socket(cpt_object_t *obj, struct sock *sk, int index, int parent, struct cpt_context *ctx);
int cpt_dump_accept_queue(struct sock *sk, int index, struct cpt_context *ctx);
int cpt_dump_synwait_queue(struct sock *sk, int index, struct cpt_context *ctx);
int rst_sockets(struct cpt_context *ctx);
int rst_sockets_complete(struct cpt_context *ctx);
int cpt_dump_orphaned_sockets(struct cpt_context *ctx);

int rst_sock_attr(loff_t *pos_p, struct sock *sk, cpt_context_t *ctx);
struct sk_buff * rst_skb(struct sock *sk, loff_t *pos_p, __u32 *owner,
			 __u32 *queue, struct cpt_context *ctx);

void cpt_unlock_sockets(cpt_context_t *);
void cpt_kill_sockets(cpt_context_t *);


int cpt_kill_socket(struct sock *, cpt_context_t *);
int cpt_dump_socket_in(struct cpt_sock_image *, struct sock *, struct cpt_context*);
int rst_socket_in(struct cpt_sock_image *si, loff_t pos, struct sock *, struct cpt_context *ctx);
int rst_listen_socket_in(struct sock *sk, struct cpt_sock_image *si,
			 loff_t pos, struct cpt_context *ctx);
__u32 cpt_socket_fasync(struct file *file, struct cpt_context *ctx);
int cpt_attach_accept(struct sock *lsk, struct sock *sk, cpt_context_t *);
int rst_restore_synwait_queue(struct sock *sk, struct cpt_sock_image *si, loff_t pos, struct cpt_context *ctx);
int cpt_dump_ofo_queue(int idx, struct sock *sk, struct cpt_context *ctx);
int cpt_dump_skb(int type, int owner, struct sk_buff *skb, struct sock *sk,
		 struct cpt_context *ctx);
int cpt_dump_mcfilter(struct sock *sk, struct cpt_context *ctx);

int rst_sk_mcfilter_in(struct sock *sk, struct cpt_sockmc_image *v,
		       loff_t pos, cpt_context_t *ctx);
int rst_sk_mcfilter_in6(struct sock *sk, struct cpt_sockmc_image *v,
			loff_t pos, cpt_context_t *ctx);
