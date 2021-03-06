#include "ceph_debug.h"

#include <linux/types.h>
#include <linux/random.h>
#include <linux/sched.h>

#include "mon_client.h"
#include "super.h"
#include "auth.h"
#include "decode.h"

/*
 * Interact with Ceph monitor cluster.  Handle requests for new map
 * versions, and periodically resend as needed.  Also implement
 * statfs() and umount().
 *
 * A small cluster of Ceph "monitors" are responsible for managing critical
 * cluster configuration and state information.  An odd number (e.g., 3, 5)
 * of cmon daemons use a modified version of the Paxos part-time parliament
 * algorithm to manage the MDS map (mds cluster membership), OSD map, and
 * list of clients who have mounted the file system.
 *
 * We maintain an open, active session with a monitor at all times in order to
 * receive timely MDSMap updates.  We periodically send a keepalive byte on the
 * TCP socket to ensure we detect a failure.  If the connection does break, we
 * randomly hunt for a new monitor.  Once the connection is reestablished, we
 * resend any outstanding requests.
 */

const static struct ceph_connection_operations mon_con_ops;

static int __validate_auth(struct ceph_mon_client *monc);

/*
 * Decode a monmap blob (e.g., during mount).
 */
struct ceph_monmap *ceph_monmap_decode(void *p, void *end)
{
	struct ceph_monmap *m = NULL;
	int i, err = -EINVAL;
	struct ceph_fsid fsid;
	u32 epoch, num_mon;
	u16 version;
	u32 len;

	ceph_decode_32_safe(&p, end, len, bad);
	ceph_decode_need(&p, end, len, bad);

	dout("monmap_decode %p %p len %d\n", p, end, (int)(end-p));

	ceph_decode_16_safe(&p, end, version, bad);

	ceph_decode_need(&p, end, sizeof(fsid) + 2*sizeof(u32), bad);
	ceph_decode_copy(&p, &fsid, sizeof(fsid));
	epoch = ceph_decode_32(&p);

	num_mon = ceph_decode_32(&p);
	ceph_decode_need(&p, end, num_mon*sizeof(m->mon_inst[0]), bad);

	if (num_mon >= CEPH_MAX_MON)
		goto bad;
	m = kmalloc(sizeof(*m) + sizeof(m->mon_inst[0])*num_mon, GFP_NOFS);
	if (m == NULL)
		return ERR_PTR(-ENOMEM);
	m->fsid = fsid;
	m->epoch = epoch;
	m->num_mon = num_mon;
	ceph_decode_copy(&p, m->mon_inst, num_mon*sizeof(m->mon_inst[0]));
	for (i = 0; i < num_mon; i++)
		ceph_decode_addr(&m->mon_inst[i].addr);

	dout("monmap_decode epoch %d, num_mon %d\n", m->epoch,
	     m->num_mon);
	for (i = 0; i < m->num_mon; i++)
		dout("monmap_decode  mon%d is %s\n", i,
		     pr_addr(&m->mon_inst[i].addr.in_addr));
	return m;

bad:
	dout("monmap_decode failed with %d\n", err);
	kfree(m);
	return ERR_PTR(err);
}

/*
 * return true if *addr is included in the monmap.
 */
int ceph_monmap_contains(struct ceph_monmap *m, struct ceph_entity_addr *addr)
{
	int i;

	for (i = 0; i < m->num_mon; i++)
		if (memcmp(addr, &m->mon_inst[i].addr, sizeof(*addr)) == 0)
			return 1;
	return 0;
}

/*
 * Send an auth request.
 */
static void __send_prepared_auth_request(struct ceph_mon_client *monc, int len)
{
	monc->pending_auth = 1;
	monc->m_auth->front.iov_len = len;
	monc->m_auth->hdr.front_len = cpu_to_le32(len);
	ceph_msg_get(monc->m_auth);  /* keep our ref */
	ceph_con_send(monc->con, monc->m_auth);
}

/*
 * Close monitor session, if any.
 */
static void __close_session(struct ceph_mon_client *monc)
{
	if (monc->con) {
		dout("__close_session closing mon%d\n", monc->cur_mon);
		ceph_con_revoke(monc->con, monc->m_auth);
		ceph_con_close(monc->con);
		monc->cur_mon = -1;
		monc->pending_auth = 0;
		ceph_auth_reset(monc->auth);
	}
}

/*
 * Open a session with a (new) monitor.
 */
static int __open_session(struct ceph_mon_client *monc)
{
	char r;
	int ret;

	if (monc->cur_mon < 0) {
		get_random_bytes(&r, 1);
		monc->cur_mon = r % monc->monmap->num_mon;
		dout("open_session num=%d r=%d -> mon%d\n",
		     monc->monmap->num_mon, r, monc->cur_mon);
		monc->sub_sent = 0;
		monc->sub_renew_after = jiffies;  /* i.e., expired */
		monc->want_next_osdmap = !!monc->want_next_osdmap;

		dout("open_session mon%d opening\n", monc->cur_mon);
		monc->con->peer_name.type = CEPH_ENTITY_TYPE_MON;
		monc->con->peer_name.num = cpu_to_le64(monc->cur_mon);
		ceph_con_open(monc->con,
			      &monc->monmap->mon_inst[monc->cur_mon].addr);

		/* initiatiate authentication handshake */
		ret = ceph_auth_build_hello(monc->auth,
					    monc->m_auth->front.iov_base,
					    monc->m_auth->front_max);
		__send_prepared_auth_request(monc, ret);
	} else {
		dout("open_session mon%d already open\n", monc->cur_mon);
	}
	return 0;
}

static bool __sub_expired(struct ceph_mon_client *monc)
{
	return time_after_eq(jiffies, monc->sub_renew_after);
}

/*
 * Reschedule delayed work timer.
 */
static void __schedule_delayed(struct ceph_mon_client *monc)
{
	unsigned delay;

	if (monc->cur_mon < 0 || __sub_expired(monc))
		delay = 10 * HZ;
	else
		delay = 20 * HZ;
	dout("__schedule_delayed after %u\n", delay);
	schedule_delayed_work(&monc->delayed_work, delay);
}

/*
 * Send subscribe request for mdsmap and/or osdmap.
 */
static void __send_subscribe(struct ceph_mon_client *monc)
{
	dout("__send_subscribe sub_sent=%u exp=%u want_osd=%d\n",
	     (unsigned)monc->sub_sent, __sub_expired(monc),
	     monc->want_next_osdmap);
	if ((__sub_expired(monc) && !monc->sub_sent) ||
	    monc->want_next_osdmap == 1) {
		struct ceph_msg *msg;
		struct ceph_mon_subscribe_item *i;
		void *p, *end;

		msg = ceph_msg_new(CEPH_MSG_MON_SUBSCRIBE, 96, 0, 0, NULL);
		if (!msg)
			return;

		p = msg->front.iov_base;
		end = p + msg->front.iov_len;

		dout("__send_subscribe to 'mdsmap' %u+\n",
		     (unsigned)monc->have_mdsmap);
		if (monc->want_next_osdmap) {
			dout("__send_subscribe to 'osdmap' %u\n",
			     (unsigned)monc->have_osdmap);
			ceph_encode_32(&p, 3);
			ceph_encode_string(&p, end, "osdmap", 6);
			i = p;
			i->have = cpu_to_le64(monc->have_osdmap);
			i->onetime = 1;
			p += sizeof(*i);
			monc->want_next_osdmap = 2;  /* requested */
		} else {
			ceph_encode_32(&p, 2);
		}
		ceph_encode_string(&p, end, "mdsmap", 6);
		i = p;
		i->have = cpu_to_le64(monc->have_mdsmap);
		i->onetime = 0;
		p += sizeof(*i);
		ceph_encode_string(&p, end, "monmap", 6);
		i = p;
		i->have = 0;
		i->onetime = 0;
		p += sizeof(*i);

		msg->front.iov_len = p - msg->front.iov_base;
		msg->hdr.front_len = cpu_to_le32(msg->front.iov_len);
		ceph_con_send(monc->con, msg);

		monc->sub_sent = jiffies | 1;  /* never 0 */
	}
}

static void handle_subscribe_ack(struct ceph_mon_client *monc,
				 struct ceph_msg *msg)
{
	unsigned seconds;
	struct ceph_mon_subscribe_ack *h = msg->front.iov_base;

	if (msg->front.iov_len < sizeof(*h))
		goto bad;
	seconds = le32_to_cpu(h->duration);

	mutex_lock(&monc->mutex);
	if (monc->hunting) {
		pr_info("mon%d %s session established\n",
			monc->cur_mon, pr_addr(&monc->con->peer_addr.in_addr));
		monc->hunting = false;
	}
	dout("handle_subscribe_ack after %d seconds\n", seconds);
	monc->sub_renew_after = monc->sub_sent + (seconds >> 1)*HZ - 1;
	monc->sub_sent = 0;
	mutex_unlock(&monc->mutex);
	return;
bad:
	pr_err("got corrupt subscribe-ack msg\n");
	ceph_msg_dump(msg);
}

/*
 * Keep track of which maps we have
 */
int ceph_monc_got_mdsmap(struct ceph_mon_client *monc, u32 got)
{
	mutex_lock(&monc->mutex);
	monc->have_mdsmap = got;
	mutex_unlock(&monc->mutex);
	return 0;
}

int ceph_monc_got_osdmap(struct ceph_mon_client *monc, u32 got)
{
	mutex_lock(&monc->mutex);
	monc->have_osdmap = got;
	monc->want_next_osdmap = 0;
	mutex_unlock(&monc->mutex);
	return 0;
}

/*
 * Register interest in the next osdmap
 */
void ceph_monc_request_next_osdmap(struct ceph_mon_client *monc)
{
	dout("request_next_osdmap have %u\n", monc->have_osdmap);
	mutex_lock(&monc->mutex);
	if (!monc->want_next_osdmap)
		monc->want_next_osdmap = 1;
	if (monc->want_next_osdmap < 2)
		__send_subscribe(monc);
	mutex_unlock(&monc->mutex);
}

/*
 *
 */
int ceph_monc_open_session(struct ceph_mon_client *monc)
{
	if (!monc->con) {
		monc->con = kmalloc(sizeof(*monc->con), GFP_KERNEL);
		if (!monc->con)
			return -ENOMEM;
		ceph_con_init(monc->client->msgr, monc->con);
		monc->con->private = monc;
		monc->con->ops = &mon_con_ops;
	}

	mutex_lock(&monc->mutex);
	__open_session(monc);
	__schedule_delayed(monc);
	mutex_unlock(&monc->mutex);
	return 0;
}

/*
 * The monitor responds with mount ack indicate mount success.  The
 * included client ticket allows the client to talk to MDSs and OSDs.
 */
static void ceph_monc_handle_map(struct ceph_mon_client *monc,
				 struct ceph_msg *msg)
{
	struct ceph_client *client = monc->client;
	struct ceph_monmap *monmap = NULL, *old = monc->monmap;
	void *p, *end;

	mutex_lock(&monc->mutex);

	dout("handle_monmap\n");
	p = msg->front.iov_base;
	end = p + msg->front.iov_len;

	monmap = ceph_monmap_decode(p, end);
	if (IS_ERR(monmap)) {
		pr_err("problem decoding monmap, %d\n",
		       (int)PTR_ERR(monmap));
		goto out;
	}

	if (ceph_check_fsid(monc->client, &monmap->fsid) < 0) {
		kfree(monmap);
		goto out;
	}

	client->monc.monmap = monmap;
	kfree(old);

out:
	mutex_unlock(&monc->mutex);
	wake_up(&client->auth_wq);
}

/*
 * statfs
 */
static struct ceph_mon_statfs_request *__lookup_statfs(
	struct ceph_mon_client *monc, u64 tid)
{
	struct ceph_mon_statfs_request *req;
	struct rb_node *n = monc->statfs_request_tree.rb_node;

	while (n) {
		req = rb_entry(n, struct ceph_mon_statfs_request, node);
		if (tid < req->tid)
			n = n->rb_left;
		else if (tid > req->tid)
			n = n->rb_right;
		else
			return req;
	}
	return NULL;
}

static void __insert_statfs(struct ceph_mon_client *monc,
			    struct ceph_mon_statfs_request *new)
{
	struct rb_node **p = &monc->statfs_request_tree.rb_node;
	struct rb_node *parent = NULL;
	struct ceph_mon_statfs_request *req = NULL;

	while (*p) {
		parent = *p;
		req = rb_entry(parent, struct ceph_mon_statfs_request, node);
		if (new->tid < req->tid)
			p = &(*p)->rb_left;
		else if (new->tid > req->tid)
			p = &(*p)->rb_right;
		else
			BUG();
	}

	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, &monc->statfs_request_tree);
}

static void handle_statfs_reply(struct ceph_mon_client *monc,
				struct ceph_msg *msg)
{
	struct ceph_mon_statfs_request *req;
	struct ceph_mon_statfs_reply *reply = msg->front.iov_base;
	u64 tid;

	if (msg->front.iov_len != sizeof(*reply))
		goto bad;
	tid = le64_to_cpu(msg->hdr.tid);
	dout("handle_statfs_reply %p tid %llu\n", msg, tid);

	mutex_lock(&monc->mutex);
	req = __lookup_statfs(monc, tid);
	if (req) {
		*req->buf = reply->st;
		req->result = 0;
	}
	mutex_unlock(&monc->mutex);
	if (req)
		complete(&req->completion);
	return;

bad:
	pr_err("corrupt statfs reply, no tid\n");
	ceph_msg_dump(msg);
}

/*
 * (re)send a statfs request
 */
static int send_statfs(struct ceph_mon_client *monc,
		       struct ceph_mon_statfs_request *req)
{
	struct ceph_msg *msg;
	struct ceph_mon_statfs *h;

	dout("send_statfs tid %llu\n", req->tid);
	msg = ceph_msg_new(CEPH_MSG_STATFS, sizeof(*h), 0, 0, NULL);
	if (IS_ERR(msg))
		return PTR_ERR(msg);
	req->request = msg;
	msg->hdr.tid = cpu_to_le64(req->tid);
	h = msg->front.iov_base;
	h->monhdr.have_version = 0;
	h->monhdr.session_mon = cpu_to_le16(-1);
	h->monhdr.session_mon_tid = 0;
	h->fsid = monc->monmap->fsid;
	ceph_con_send(monc->con, msg);
	return 0;
}

/*
 * Do a synchronous statfs().
 */
int ceph_monc_do_statfs(struct ceph_mon_client *monc, struct ceph_statfs *buf)
{
	struct ceph_mon_statfs_request req;
	int err;

	req.buf = buf;
	init_completion(&req.completion);

	/* allocate memory for reply */
	err = ceph_msgpool_resv(&monc->msgpool_statfs_reply, 1);
	if (err)
		return err;

	/* register request */
	mutex_lock(&monc->mutex);
	req.tid = ++monc->last_tid;
	req.last_attempt = jiffies;
	req.delay = BASE_DELAY_INTERVAL;
	__insert_statfs(monc, &req);
	monc->num_statfs_requests++;
	mutex_unlock(&monc->mutex);

	/* send request and wait */
	err = send_statfs(monc, &req);
	if (!err)
		err = wait_for_completion_interruptible(&req.completion);

	mutex_lock(&monc->mutex);
	rb_erase(&req.node, &monc->statfs_request_tree);
	monc->num_statfs_requests--;
	ceph_msgpool_resv(&monc->msgpool_statfs_reply, -1);
	mutex_unlock(&monc->mutex);

	if (!err)
		err = req.result;
	return err;
}

/*
 * Resend pending statfs requests.
 */
static void __resend_statfs(struct ceph_mon_client *monc)
{
	struct ceph_mon_statfs_request *req;
	struct rb_node *p;

	for (p = rb_first(&monc->statfs_request_tree); p; p = rb_next(p)) {
		req = rb_entry(p, struct ceph_mon_statfs_request, node);
		send_statfs(monc, req);
	}
}

/*
 * Delayed work.  If we haven't mounted yet, retry.  Otherwise,
 * renew/retry subscription as needed (in case it is timing out, or we
 * got an ENOMEM).  And keep the monitor connection alive.
 */
static void delayed_work(struct work_struct *work)
{
	struct ceph_mon_client *monc =
		container_of(work, struct ceph_mon_client, delayed_work.work);

	dout("monc delayed_work\n");
	mutex_lock(&monc->mutex);
	if (monc->hunting) {
		__close_session(monc);
		__open_session(monc);  /* continue hunting */
	} else {
		ceph_con_keepalive(monc->con);

		__validate_auth(monc);

		if (monc->auth->ops->is_authenticated(monc->auth))
			__send_subscribe(monc);
	}
	__schedule_delayed(monc);
	mutex_unlock(&monc->mutex);
}

/*
 * On startup, we build a temporary monmap populated with the IPs
 * provided by mount(2).
 */
static int build_initial_monmap(struct ceph_mon_client *monc)
{
	struct ceph_mount_args *args = monc->client->mount_args;
	struct ceph_entity_addr *mon_addr = args->mon_addr;
	int num_mon = args->num_mon;
	int i;

	/* build initial monmap */
	monc->monmap = kzalloc(sizeof(*monc->monmap) +
			       num_mon*sizeof(monc->monmap->mon_inst[0]),
			       GFP_KERNEL);
	if (!monc->monmap)
		return -ENOMEM;
	for (i = 0; i < num_mon; i++) {
		monc->monmap->mon_inst[i].addr = mon_addr[i];
		monc->monmap->mon_inst[i].addr.nonce = 0;
		monc->monmap->mon_inst[i].name.type =
			CEPH_ENTITY_TYPE_MON;
		monc->monmap->mon_inst[i].name.num = cpu_to_le64(i);
	}
	monc->monmap->num_mon = num_mon;
	monc->have_fsid = false;

	/* release addr memory */
	kfree(args->mon_addr);
	args->mon_addr = NULL;
	args->num_mon = 0;
	return 0;
}

int ceph_monc_init(struct ceph_mon_client *monc, struct ceph_client *cl)
{
	int err = 0;

	dout("init\n");
	memset(monc, 0, sizeof(*monc));
	monc->client = cl;
	monc->monmap = NULL;
	mutex_init(&monc->mutex);

	err = build_initial_monmap(monc);
	if (err)
		goto out;

	monc->con = NULL;

	/* authentication */
	monc->auth = ceph_auth_init(cl->mount_args->name,
				    cl->mount_args->secret);
	if (IS_ERR(monc->auth))
		return PTR_ERR(monc->auth);
	monc->auth->want_keys =
		CEPH_ENTITY_TYPE_AUTH | CEPH_ENTITY_TYPE_MON |
		CEPH_ENTITY_TYPE_OSD | CEPH_ENTITY_TYPE_MDS;

	/* msg pools */
	err = ceph_msgpool_init(&monc->msgpool_subscribe_ack,
			       sizeof(struct ceph_mon_subscribe_ack), 1, false);
	if (err < 0)
		goto out_monmap;
	err = ceph_msgpool_init(&monc->msgpool_statfs_reply,
				sizeof(struct ceph_mon_statfs_reply), 0, false);
	if (err < 0)
		goto out_pool1;
	err = ceph_msgpool_init(&monc->msgpool_auth_reply, 4096, 1, false);
	if (err < 0)
		goto out_pool2;

	monc->m_auth = ceph_msg_new(CEPH_MSG_AUTH, 4096, 0, 0, NULL);
	monc->pending_auth = 0;
	if (IS_ERR(monc->m_auth)) {
		err = PTR_ERR(monc->m_auth);
		monc->m_auth = NULL;
		goto out_pool3;
	}

	monc->cur_mon = -1;
	monc->hunting = true;
	monc->sub_renew_after = jiffies;
	monc->sub_sent = 0;

	INIT_DELAYED_WORK(&monc->delayed_work, delayed_work);
	monc->statfs_request_tree = RB_ROOT;
	monc->num_statfs_requests = 0;
	monc->last_tid = 0;

	monc->have_mdsmap = 0;
	monc->have_osdmap = 0;
	monc->want_next_osdmap = 1;
	return 0;

out_pool3:
	ceph_msgpool_destroy(&monc->msgpool_auth_reply);
out_pool2:
	ceph_msgpool_destroy(&monc->msgpool_subscribe_ack);
out_pool1:
	ceph_msgpool_destroy(&monc->msgpool_statfs_reply);
out_monmap:
	kfree(monc->monmap);
out:
	return err;
}

void ceph_monc_stop(struct ceph_mon_client *monc)
{
	dout("stop\n");
	cancel_delayed_work_sync(&monc->delayed_work);

	mutex_lock(&monc->mutex);
	__close_session(monc);
	if (monc->con) {
		monc->con->private = NULL;
		monc->con->ops->put(monc->con);
		monc->con = NULL;
	}
	mutex_unlock(&monc->mutex);

	ceph_auth_destroy(monc->auth);

	ceph_msg_put(monc->m_auth);
	ceph_msgpool_destroy(&monc->msgpool_subscribe_ack);
	ceph_msgpool_destroy(&monc->msgpool_statfs_reply);
	ceph_msgpool_destroy(&monc->msgpool_auth_reply);

	kfree(monc->monmap);
}

static void handle_auth_reply(struct ceph_mon_client *monc,
			      struct ceph_msg *msg)
{
	int ret;

	mutex_lock(&monc->mutex);
	monc->pending_auth = 0;
	ret = ceph_handle_auth_reply(monc->auth, msg->front.iov_base,
				     msg->front.iov_len,
				     monc->m_auth->front.iov_base,
				     monc->m_auth->front_max);
	if (ret < 0) {
		monc->client->auth_err = ret;
		wake_up(&monc->client->auth_wq);
	} else if (ret > 0) {
		__send_prepared_auth_request(monc, ret);
	} else if (monc->auth->ops->is_authenticated(monc->auth)) {
		dout("authenticated, starting session\n");

		monc->client->msgr->inst.name.type = CEPH_ENTITY_TYPE_CLIENT;
		monc->client->msgr->inst.name.num = monc->auth->global_id;

		__send_subscribe(monc);
		__resend_statfs(monc);
	}
	mutex_unlock(&monc->mutex);
}

static int __validate_auth(struct ceph_mon_client *monc)
{
	int ret;

	if (monc->pending_auth)
		return 0;

	ret = ceph_build_auth(monc->auth, monc->m_auth->front.iov_base,
			      monc->m_auth->front_max);
	if (ret <= 0)
		return ret; /* either an error, or no need to authenticate */
	__send_prepared_auth_request(monc, ret);
	return 0;
}

int ceph_monc_validate_auth(struct ceph_mon_client *monc)
{
	int ret;

	mutex_lock(&monc->mutex);
	ret = __validate_auth(monc);
	mutex_unlock(&monc->mutex);
	return ret;
}

/*
 * handle incoming message
 */
static void dispatch(struct ceph_connection *con, struct ceph_msg *msg)
{
	struct ceph_mon_client *monc = con->private;
	int type = le16_to_cpu(msg->hdr.type);

	if (!monc)
		return;

	switch (type) {
	case CEPH_MSG_AUTH_REPLY:
		handle_auth_reply(monc, msg);
		break;

	case CEPH_MSG_MON_SUBSCRIBE_ACK:
		handle_subscribe_ack(monc, msg);
		break;

	case CEPH_MSG_STATFS_REPLY:
		handle_statfs_reply(monc, msg);
		break;

	case CEPH_MSG_MON_MAP:
		ceph_monc_handle_map(monc, msg);
		break;

	case CEPH_MSG_MDS_MAP:
		ceph_mdsc_handle_map(&monc->client->mdsc, msg);
		break;

	case CEPH_MSG_OSD_MAP:
		ceph_osdc_handle_map(&monc->client->osdc, msg);
		break;

	default:
		pr_err("received unknown message type %d %s\n", type,
		       ceph_msg_type_name(type));
	}
	ceph_msg_put(msg);
}

/*
 * Allocate memory for incoming message
 */
static struct ceph_msg *mon_alloc_msg(struct ceph_connection *con,
				      struct ceph_msg_header *hdr,
				      int *skip)
{
	struct ceph_mon_client *monc = con->private;
	int type = le16_to_cpu(hdr->type);
	int front_len = le32_to_cpu(hdr->front_len);
	struct ceph_msg *m;

	*skip = 0;

	switch (type) {
	case CEPH_MSG_MON_SUBSCRIBE_ACK:
		m = ceph_msgpool_get(&monc->msgpool_subscribe_ack, front_len);
		break;
	case CEPH_MSG_STATFS_REPLY:
		m = ceph_msgpool_get(&monc->msgpool_statfs_reply, front_len);
		break;
	case CEPH_MSG_AUTH_REPLY:
		m = ceph_msgpool_get(&monc->msgpool_auth_reply, front_len);
		break;
	default:
		return NULL;
	}

	if (!m)
		*skip = 1;

	return m;
}

/*
 * If the monitor connection resets, pick a new monitor and resubmit
 * any pending requests.
 */
static void mon_fault(struct ceph_connection *con)
{
	struct ceph_mon_client *monc = con->private;

	if (!monc)
		return;

	dout("mon_fault\n");
	mutex_lock(&monc->mutex);
	if (!con->private)
		goto out;

	if (monc->con && !monc->hunting)
		pr_info("mon%d %s session lost, "
			"hunting for new mon\n", monc->cur_mon,
			pr_addr(&monc->con->peer_addr.in_addr));

	__close_session(monc);
	if (!monc->hunting) {
		/* start hunting */
		monc->hunting = true;
		__open_session(monc);
	} else {
		/* already hunting, let's wait a bit */
		__schedule_delayed(monc);
	}
out:
	mutex_unlock(&monc->mutex);
}

const static struct ceph_connection_operations mon_con_ops = {
	.get = ceph_con_get,
	.put = ceph_con_put,
	.dispatch = dispatch,
	.fault = mon_fault,
	.alloc_msg = mon_alloc_msg,
};
