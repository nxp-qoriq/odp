/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/queue.h>
#include <odp_queue_internal.h>
#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <odp/api/buffer.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/schedule.h>
#include <odp_schedule_internal.h>
#include <odp_config_internal.h>
#include <odp_packet_io_queue.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/sync.h>

#ifdef USE_TICKETLOCK
#include <odp/api/ticketlock.h>
#define LOCK(a)      odp_ticketlock_lock(a)
#define UNLOCK(a)    odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)
#define LOCK_TRY(a)  odp_ticketlock_trylock(a)
#else
#include <odp/api/spinlock.h>
#define LOCK(a)      odp_spinlock_lock(a)
#define UNLOCK(a)    odp_spinlock_unlock(a)
#define LOCK_INIT(a) odp_spinlock_init(a)
#define LOCK_TRY(a)  odp_spinlock_trylock(a)
#endif


#include <configs/odp_config_platform.h>
/* FSL headers*/
#include <usdpaa/fsl_usd.h>
#include <usdpaa/dma_mem.h>

#include <assert.h>

static u32 sdqcr_vdq, pchannel_vdq;

typedef struct queue_table_t {
	queue_entry_t  queue[ODP_CONFIG_QUEUES];
} queue_table_t;

static queue_table_t *queue_tbl;


inline queue_entry_t *get_qentry(uint32_t queue_id)
{
	return &queue_tbl->queue[queue_id];
}

inline uint32_t get_qid(queue_entry_t *qentry)
{
	return (qentry - &queue_tbl->queue[0]);
}

/* ERN callback for POLL/SCHED */
void ern_cb(struct qman_portal *p __always_unused,
		   struct qman_fq *fq __always_unused,
		   const struct qm_mr_entry *msg __always_unused)
{
	queue_entry_t *qentry = QENTRY_FROM_FQ(fq);
	ODP_ERR("ODP queue %s : fqid %d rc = %x, seqnum = %x\n",
		qentry->s.name, fq->fqid, msg->ern.rc, msg->ern.seqnum);
}

/* ERN callback for ODP fqs */
void orp_ern_cb(struct qman_portal *p __always_unused,
		       struct qman_fq *fq __always_unused,
		       const struct qm_mr_entry *msg __always_unused)
{
	queue_entry_t *qentry = QENTRY_FROM_ORP_FQ(fq);
	ODP_ERR("ODP queue %s : orp fqid %d rc = %x, seqnum = %x\n",
		qentry->s.name, fq->fqid, msg->ern.rc, msg->ern.seqnum);
}

/*
 * Initializes an ORP fq.
 * An ORDERED ODP queue has an ORP fq.
 * */
int queue_init_orp_fq(struct qman_fq *orp_fq)
{
	int ret;
	struct qm_mcc_initfq opts;
	ret = qman_create_fq(0, QMAN_FQ_FLAG_DYNAMIC_FQID, orp_fq);
	if (ret)
		return ret;

	memset(&opts, 0, sizeof(opts));
	opts.we_mask = QM_INITFQ_WE_FQCTRL | QM_INITFQ_WE_ORPC;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE | QM_FQCTRL_ORP;
	opts.fqd.orprws = ORP_WINDOW_SIZE;
	opts.fqd.oa = ORP_AUTO_ADVANCE;
	opts.fqd.olws = ORP_ACCEPT_LATE;
	ret = qman_init_fq(orp_fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	if (ret)
		qman_destroy_fq(orp_fq, 0);
	return ret;
}

/*
 * Initializes a frame queue for core packet receive.
 *
 * */
int queue_init_rx_fq(struct qman_fq *fq, uint16_t channel)
{
	int ret;
	struct qm_mcc_initfq opts;
	queue_entry_t *qentry = QENTRY_FROM_FQ(fq);

	/* setup ORP for ORDERED queues */
	if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED) {
		ret = queue_init_orp_fq(&qentry->s.orp_fq);
		if (ret)
			return ret;
		qentry->s.orp_fq.cb.ern = orp_ern_cb;
	}
	memset(&opts, 0, sizeof(opts));
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
			QM_INITFQ_WE_CONTEXTA | QM_INITFQ_WE_CONTEXTB /*|
			QM_INITFQ_WE_TDTHRESH*/;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = qentry->s.param.sched.prio;
	if (qentry->s.type != ODP_QUEUE_TYPE_PLAIN)
		opts.fqd.fq_ctrl = QM_FQCTRL_CTXASTASHING |
				   QM_FQCTRL_PREFERINCACHE;

	/* order preservation/restoration requires HOLDACTIVE */
	if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC /*||
	    qentry->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED*/) {
		opts.fqd.fq_ctrl |= QM_FQCTRL_HOLDACTIVE /*|
				    QM_FQCTRL_TDE*/;
		/*qm_fqd_taildrop_set(&opts.fqd.td, TD_THRESH, 1);*/
	}

	/* no ordering */
	if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_PARALLEL)
		opts.fqd.fq_ctrl |= QM_FQCTRL_AVOIDBLOCK;

	/* Have annotation stashing for one cache line only as parse
	 * results are in the first cache line */
	if (qentry->s.type != ODP_QUEUE_TYPE_PLAIN) {
		opts.fqd.context_a.stashing.annotation_cl = 1;
		opts.fqd.context_a.stashing.data_cl = 1;
		opts.fqd.context_a.stashing.context_cl = 0;
	}

	ret = qman_init_fq(fq, 0, &opts);
	if (ret)
		ODP_ERR("qman_init_fq ret %d\n", ret);

	return ret;
}

/*
 * Enqueue for transmission - takes into account the source queue
 * Source queue ATOMIC - acknowledge DQRR consumption
 * Source queue ORDERED - enqueue to ORP
 * */
inline int queue_enqueue_tx_fq(struct qman_fq *tx_fq, struct qm_fd *fd,
			odp_buffer_hdr_t *buf_hdr , queue_entry_t *in_qentry)
{
	int ret;

	if (in_qentry->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC) {
		/* input queue is ATOMIC - acknowledge DQRR consumption */
		const struct qm_dqrr_entry      *dqrr = buf_hdr->dqrr;
retry:
		ret = qman_enqueue(tx_fq, fd, QMAN_ENQUEUE_FLAG_DCA |
			QMAN_ENQUEUE_FLAG_DCA_PTR((uintptr_t)dqrr));
		if (ret) {
			cpu_spin(CPU_BACKOFF_CYCLES);
			goto retry;
		}
	} else if (in_qentry->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED) {
		/* input queue is ORDERED - enqueue to ORP */
		ret = qman_enqueue_orp(tx_fq, fd, /*buf_hdr->orp.flags*/0,
				       &in_qentry->s.orp_fq,
				       buf_hdr->orp.seqnum);
	} else
		ret = qman_enqueue(tx_fq, fd, 0);
	return ret;
}

unsigned do_volatile_deq(struct qman_fq *fq, unsigned len, bool exact)
{
	unsigned pkts = 0;
	int ret;
	struct qm_mcr_queryfq_np np;
	enum qman_fq_state state;
	uint32_t flags;
	uint32_t vdqcr;

	qman_query_fq_np(fq, &np);
	if (np.frm_cnt) {
		vdqcr = QM_VDQCR_NUMFRAMES_SET(len);
		if (exact)
			vdqcr |= QM_VDQCR_EXACT;
		ret = qman_volatile_dequeue(fq, 0, vdqcr);
		if (ret)
			return 0;
		do {
			pkts += qman_poll_dqrr(len);
			qman_fq_state(fq, &state, &flags);
		} while (flags & QMAN_FQ_STATE_VDQCR);
	}
	return pkts;
}


/* POLL queue RAW buffer enqueue */
static int raw_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr)
{
	struct qm_fd fd;
	odp_queue_t inq;
	queue_entry_t *in_qentry = NULL;
	int ret;

	fd.cmd = 0;
	fd.format = qm_fd_contig;
	fd.addr = (uintptr_t)buf_hdr;
	fd.offset = FD_DEFAULT_OFFSET;
	fd.length20 = buf_hdr->size;
	inq = buf_hdr->inq;
	if (inq != ODP_QUEUE_INVALID) {
		in_qentry = queue_to_qentry(inq);
	}

	if (!in_qentry) {
		ret = qman_enqueue(&qentry->s.fq, &fd, 0);
		return ret;
	}

	return queue_enqueue_tx_fq(&qentry->s.fq, &fd, buf_hdr, in_qentry);
}

/* POLL queue PACKET buffer enqueue */
static int pkt_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr)
{
	odp_packet_t pkt;
	odp_pool_t pool_id;
	pool_entry_t *pool_entry;
	size_t len, off;
	struct qm_fd fd;
	odp_queue_t inq;
	queue_entry_t *in_qentry = NULL;
	int ret;

	pool_id = buf_hdr->pool_hdl;
	pool_entry = odp_pool_to_entry(pool_id);

	pkt = (odp_packet_t)buf_hdr;
	len = odp_packet_len(pkt);
	off = odp_packet_l2_offset(pkt) + odp_packet_headroom(pkt);
	inq = buf_hdr->inq;
	if (inq != ODP_QUEUE_INVALID)
		in_qentry = queue_to_qentry(inq);

	__config_fd(&fd, buf_hdr, off, len, pool_entry->s.pool_id, qentry);

	if (in_qentry && in_qentry->s.type != ODP_QUEUE_TYPE_PLAIN)
		ret = queue_enqueue_tx_fq(&qentry->s.fq, &fd, buf_hdr,
					  in_qentry);
	else
		ret = qman_enqueue(&qentry->s.fq, &fd, 0);
	return ret;
}

static enum qman_cb_dqrr_result dqrr_cb(struct qman_fq *fq,
					const struct qm_dqrr_entry *dqrr,
					uint64_t *user_context)
{
	const struct qm_fd *fd = &dqrr->fd;
	queue_entry_t *qentry = QENTRY_FROM_FQ(fq);
	odp_buffer_hdr_t *buf_hdr;

	assert(dqrr->stat & QM_DQRR_STAT_FD_VALID);
	assert(fd->offset == FD_DEFAULT_OFFSET);

	/* previous buffer has been consumed */
	assert(qentry->s.buf_hdr == NULL);

	buf_hdr = (odp_buffer_hdr_t *)(uintptr_t)(fd->addr);
	buf_set_input_queue(buf_hdr, queue_from_id(get_qid(qentry)));
	*user_context = buf_hdr;

	if (qentry->s.type == ODP_QUEUE_TYPE_PLAIN) {
		qentry->s.buf_hdr = buf_hdr;
		return qman_cb_dqrr_consume;
	}
	/* SCHED */
	if (buf_hdr->type == ODP_EVENT_PACKET) {
		pool_entry_t *pool;
		odp_packet_hdr_t *pkthdr;
		size_t off;
		struct qm_sg_entry *sgt;
		void *fd_addr;

		off = fd->offset;
		pool  = get_pool_entry(fd->bpid);
		if (fd->format == qm_fd_sg) {
			unsigned	sgcnt;

			sgt = (struct qm_sg_entry *)(
				__dma_mem_ptov(fd->addr) + fd->offset);
			/* On LE CPUs, converts the SG entry from the BE format
			 * as is provided by the HW to LE as expected by the
			 * LE CPUs, on BE CPUs does nothing */
			hw_sg_to_cpu(&sgt[0]);

			/* first sg entry */
			fd_addr = __dma_mem_ptov(qm_sg_addr(sgt));

			buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);
			off = sgt->offset;
			sgcnt = 1;
			do {
				hw_sg_to_cpu(&sgt[sgcnt]);

				buf_hdr->addr[sgcnt] = __dma_mem_ptov(
						       qm_sg_addr(&sgt[sgcnt]));
				sgcnt++;
			} while (sgt[sgcnt - 1].final != 1);
			buf_hdr->addr[sgcnt] = __dma_mem_ptov(qm_fd_addr(fd));
			buf_hdr->segcount = sgcnt;
			fd_addr = buf_hdr->addr[sgcnt];
		} else {
			fd_addr = buf_hdr->addr[0];
		}
		pkthdr = (odp_packet_hdr_t *)buf_hdr;
		pkthdr->headroom = pool->s.headroom;
		pkthdr->tailroom = pool->s.tailroom;

		_odp_packet_parse(pkthdr, fd->length20, off, fd_addr);

		if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC) {
			pkthdr->dqrr = dqrr;
			return qman_cb_dqrr_defer;
		}
		return qman_cb_dqrr_consume;
	} else {
		/* save sequence number when input queue is ORDERED */
		if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED)
			buf_hdr->orp.seqnum = dqrr->seqnum;

		if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC) {
			buf_hdr->dqrr = dqrr;
			return qman_cb_dqrr_defer;
		}
	}


	return qman_cb_dqrr_consume;
}

static void queue_init(queue_entry_t *queue, const char *name,
		       odp_queue_type_t type, odp_queue_param_t *param)
{
	strncpy(queue->s.name, name, ODP_QUEUE_NAME_LEN - 1);
	queue->s.type = type;

	if (param) {
		memcpy(&queue->s.param, param, sizeof(odp_queue_param_t));
	} else {
		/* Defaults */
		memset(&queue->s.param, 0, sizeof(odp_queue_param_t));
		queue->s.param.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
		queue->s.param.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
		queue->s.param.sched.group = ODP_SCHED_GROUP_ALL;
	}
	queue->s.enqueue = queue_enq;
	queue->s.dequeue = queue_deq;
	queue->s.enqueue_multi = queue_enq_multi;
	queue->s.dequeue_multi = queue_deq_multi;
	queue->s.head = NULL;
	queue->s.tail = NULL;
	queue->s.pri_queue = ODP_QUEUE_INVALID;
}

int odp_queue_init_global(void)
{
	uint32_t i;
	int ret;

	ODP_DBG("Queue init ...\n");

	queue_tbl = __dma_mem_memalign(L1_CACHE_BYTES,
				       sizeof(queue_table_t));

	ret = qman_alloc_pool_range(&pchannel_vdq, 1, 1, 0);
	if (ret != 1)
		return -1;

	sdqcr_vdq = QM_SDQCR_CHANNELS_POOL_CONV(pchannel_vdq);


	if (queue_tbl == NULL)
		return -1;

	memset(queue_tbl, 0, sizeof(queue_table_t));

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue = get_qentry(i);
		LOCK_INIT(&queue->s.lock);
		queue->s.handle = queue_from_id(i);
	}

	ODP_DBG("done\n");
	ODP_DBG("Queue init global\n");
	ODP_DBG("  struct queue_entry_s size %zu\n",
		sizeof(struct queue_entry_s));
	ODP_DBG("  queue_entry_t size	     %zu\n",
		sizeof(queue_entry_t));
	ODP_DBG("\n");

	return 0;
}

int  odp_queue_term_global(void)
{

	ODP_DBG("odp_queue_term_global\n");

	qman_release_pool_range(pchannel_vdq, 1);
	return 0;
}

odp_queue_type_t odp_queue_type(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.type;
}

odp_schedule_sync_t odp_queue_sched_type(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.param.sched.sync;
}

odp_schedule_prio_t odp_queue_sched_prio(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.param.sched.prio;
}

odp_schedule_group_t odp_queue_sched_group(odp_queue_t handle)
{
	odp_schedule_group_t ret = ODP_SCHED_GROUP_INVALID;
	queue_entry_t *queue = queue_to_qentry(handle);

	if (queue)
		ret = queue->s.param.sched.group;

	return ret;
}

odp_queue_t odp_queue_create(const char *name, const odp_queue_param_t *param)
{
	uint32_t i;
	int ret;
	uint16_t channel;
	uint32_t flags  = QMAN_FQ_FLAG_DYNAMIC_FQID;
	odp_queue_type_t type;
	queue_entry_t *queue;
	odp_queue_t handle = ODP_QUEUE_INVALID;
	odp_queue_param_t default_param;

	if (param == NULL) {
		odp_queue_param_init(&default_param);
		param = &default_param;
	}
	type = param->type;

	/* cannot create queue if local initialization was not completed */
	if (!sched_local.init_done)
		return handle;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue = &queue_tbl->queue[i];

		if (queue->s.status != QUEUE_STATUS_FREE)
			continue;

		LOCK(&queue->s.lock);

		if (queue->s.status == QUEUE_STATUS_FREE) {
			queue_init(queue, name, type, param);
			if (type == ODP_QUEUE_TYPE_SCHED)
				queue->s.status = QUEUE_STATUS_NOTSCHED;
			else
				queue->s.status = QUEUE_STATUS_READY;

			handle = queue->s.handle;

			UNLOCK(&queue->s.lock);
			break;
		}

		UNLOCK(&queue->s.lock);
	}

	/* create a HW queue for SCHED/POLL queues
	 - after thread initialization */
	ret = qman_create_fq(0, flags, &queue->s.fq);

	if (ret) {
		queue->s.status = QUEUE_STATUS_FREE;
		return ODP_QUEUE_INVALID;
	}

	if (type == ODP_QUEUE_TYPE_SCHED) {
		/* distinguish between named group or otherwise */
		if (param->sched.group > ODP_SCHED_GROUP_CONTROL) {
			if (get_group_channel(param->sched.group,
			    &channel))
				ODP_ERR("Could not get channel");
		} else {
			channel = get_next_rx_channel();
		}
	} else {/* POLL */
		channel = pchannel_vdq;
	}

	queue->s.fq.cb.dqrr_ctx = dqrr_cb;
	queue->s.fq.cb.ern = ern_cb;
	ret = queue_init_rx_fq(&queue->s.fq, channel);
	if (ret)
		goto out;
	if (type == ODP_QUEUE_TYPE_SCHED)
		ret = qman_schedule_fq(&queue->s.fq);
		queue->s.status = QUEUE_STATUS_SCHED;
	if (ret)
		goto out;

	if (type == ODP_QUEUE_TYPE_SCHED &&
	    queue->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED) {
		queue->s.orp_fq.cb.ern = orp_ern_cb;
		ret = queue_init_orp_fq(&queue->s.orp_fq);
		if (ret) {
			/*TODO - teardown queue->s.fq */
			goto out;
		}
	}

	return handle;
out:
	queue->s.status = QUEUE_STATUS_FREE;
	qman_destroy_fq(&queue->s.fq, 0);

	channel = qman_affine_channel(-1);
	ret = queue_init_rx_fq(&queue->s.fq, channel);
	if (ret) {
		queue->s.status = QUEUE_STATUS_FREE;
		qman_destroy_fq(&queue->s.fq, 0);
		return ODP_QUEUE_INVALID;
	}

	return handle;
}

int queue_sched_atomic(odp_queue_t handle)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);

	return queue->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC;
}

odp_queue_t odp_queue_lookup(const char *name)
{
	uint32_t i;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue_entry_t *queue = &queue_tbl->queue[i];

		if (queue->s.status == QUEUE_STATUS_FREE)
			continue;

		LOCK(&queue->s.lock);

		if (strcmp(name, queue->s.name) == 0) {
			/* found it */
			UNLOCK(&queue->s.lock);
			return queue->s.handle;
		}

		UNLOCK(&queue->s.lock);
	}

	return ODP_QUEUE_INVALID;
}


int queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr)
{
	int ret = -1;
	if (buf_hdr->type == ODP_EVENT_PACKET)
		ret = pkt_enqueue(queue, buf_hdr);
	else
		ret = raw_enqueue(queue, buf_hdr);
	return ret;
}


int queue_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int ret = -1, count = 0, i;

	for (i = 0; i < num; i++) {
		if (buf_hdr[i]->type == ODP_EVENT_PACKET)
			ret = pkt_enqueue(queue, buf_hdr[i]);
		else
			ret = raw_enqueue(queue, buf_hdr[i]);
		if (!ret)
			count++;
	}

	return count;
}


int odp_queue_enq_multi(odp_queue_t handle, const odp_event_t ev[], int num)
{
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	odp_buffer_t buf;
	queue_entry_t *queue;
	int i;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = queue_to_qentry(handle);

	for (i = 0; i < num; i++) {
		buf = odp_buffer_from_event(ev[i]);
		buf_hdr[i] = odp_buf_to_hdr(buf);
	}

	return queue->s.enqueue_multi(queue, buf_hdr, num);
}


int odp_queue_enq(odp_queue_t handle, odp_event_t ev)
{
	odp_buffer_hdr_t *buf_hdr;
	queue_entry_t *queue;

	assert(ev != ODP_EVENT_INVALID);
	assert(handle != ODP_QUEUE_INVALID);
	queue	= queue_to_qentry(handle);
	assert(queue);

	buf_hdr = odp_buf_to_hdr(odp_buffer_from_event(ev));
	return queue->s.enqueue(queue, buf_hdr);
}


/*
 * Supported only for POLL queues
 * */
odp_buffer_hdr_t *queue_deq(queue_entry_t *queue)
{
	odp_buffer_hdr_t *buf_hdr = NULL;

	if (queue->s.type == ODP_QUEUE_TYPE_SCHED)
		return buf_hdr;

	LOCK(&queue->s.lock);

	qman_static_dequeue_add(sdqcr_vdq);
	do_volatile_deq(&queue->s.fq, 1, true);
	qman_static_dequeue_del(sdqcr_vdq);
	buf_hdr = queue->s.buf_hdr;
	queue->s.buf_hdr = NULL;

	UNLOCK(&queue->s.lock);

	return buf_hdr;
}


int queue_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int count = 0, loop = 0;

	do {
		buf_hdr[count] = queue_deq(queue);
		if (buf_hdr[count] != NULL)
			count++;
		loop++;
	} while (loop <= num);

	return count;
}

/*
 * Supported only for POLL queues
 * */
int odp_queue_deq_multi(odp_queue_t handle, odp_event_t ev[], int num)
{
	queue_entry_t *queue;
	odp_buffer_t buf;
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	int i, ret;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = queue_to_qentry(handle);

	ret = queue->s.dequeue_multi(queue, buf_hdr, num);

	for (i = 0; i < ret; i++) {
		buf = (odp_buffer_t)buf_hdr[i];
		ev[i] = odp_buffer_to_event(buf);
	}

	return ret;
}

odp_event_t odp_queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue;
	odp_buffer_hdr_t *buf_hdr;

	if (unlikely(received_sigint)) {
		odp_term_local();
		pthread_exit(NULL);
	}

	queue	= queue_to_qentry(handle);
	buf_hdr = queue->s.dequeue(queue);

	if (buf_hdr)
		return (odp_event_t)buf_hdr;

	return ODP_EVENT_INVALID;
}


void queue_lock(queue_entry_t *queue)
{
	LOCK(&queue->s.lock);
}


void queue_unlock(queue_entry_t *queue)
{
	UNLOCK(&queue->s.lock);
}

void odp_queue_param_init(odp_queue_param_t *params)
{
        memset(params, 0, sizeof(odp_queue_param_t));
}

inline void odp_queue_set_input(odp_buffer_t buf, odp_queue_t queue)
{
	odp_buf_to_hdr(buf)->inq = queue;
}

void teardown_fq(struct qman_fq *fq)
{
	u32 flags;
	int s = qman_retire_fq(fq, &flags);
	if (s == 1) {
		/* Retire is non-blocking, poll for completion */
		enum qman_fq_state state;
		do {
			qman_poll();
			qman_fq_state(fq, &state, &flags);
		} while (state != qman_fq_state_retired);
		if (flags & QMAN_FQ_STATE_NE) {
			/* FQ isn't empty, drain it */
			s = qman_volatile_dequeue(fq, 0,
				QM_VDQCR_NUMFRAMES_TILLEMPTY);
			BUG_ON(s);
			/* Poll for completion */
			do {
				qman_poll();
				qman_fq_state(fq, &state, &flags);
			} while (flags & QMAN_FQ_STATE_VDQCR);
		}
	}
	s = qman_oos_fq(fq);
	assert(s == 0);
	if (!(fq->flags & QMAN_FQ_FLAG_DYNAMIC_FQID))
		qman_release_fqid(fq->fqid);
	qman_destroy_fq(fq, 0);
}

int odp_queue_destroy(odp_queue_t queue)
{
	queue_entry_t *qentry;

	qentry = queue_to_qentry(queue);

	if (!qentry)
		return -1;

	if (qentry->s.status == QUEUE_STATUS_FREE)
		return -1;

	LOCK(&qentry->s.lock);

	if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED)
		teardown_fq(&qentry->s.orp_fq);

	teardown_fq(&qentry->s.fq);

	qentry->s.status = QUEUE_STATUS_FREE;
	qentry->s.head = NULL;
	qentry->s.tail = NULL;
	qentry->s.pri_queue = ODP_QUEUE_INVALID;
	UNLOCK(&qentry->s.lock);

	return 0;
}

int odp_queue_context_set(odp_queue_t handle, void *context,
			  uint32_t len ODP_UNUSED)
{
        queue_entry_t *queue;
        queue = queue_to_qentry(handle);
	odp_mb_full();
        queue->s.param.context = context;
	odp_mb_full();
        return 0;
}

void *odp_queue_context(odp_queue_t handle)
{
        queue_entry_t *queue;
        queue = queue_to_qentry(handle);
        return queue->s.param.context;
}

void odp_schedule_order_lock(unsigned lock_index ODP_UNUSED)
{
        ODP_UNIMPLEMENTED();
}

void odp_schedule_order_unlock(unsigned lock_index ODP_UNUSED)
{
        ODP_UNIMPLEMENTED();
}

int odp_queue_capability(odp_queue_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_queue_capability_t));

	/* Reserve some queues for internal use */
	capa->max_queues        = ODP_CONFIG_QUEUES;
	capa->max_ordered_locks = ODP_CONFIG_MAX_ORDERED_LOCKS_PER_QUEUE;
	capa->max_sched_groups  = ODP_CONFIG_SCHED_GRPS;
	capa->sched_prios       = ODP_CONFIG_SCHED_PRIOS;

	return 0;
}

int odp_queue_info(odp_queue_t handle, odp_queue_info_t *info)
{
	uint32_t queue_id;
	queue_entry_t *queue;
	int status;

	if (odp_unlikely(info == NULL)) {
		ODP_ERR("Unable to store info, NULL ptr given\n");
		return -1;
	}

	queue_id = queue_to_id(handle);

	if (odp_unlikely(queue_id >= ODP_CONFIG_QUEUES)) {
		ODP_ERR("Invalid queue handle:%" PRIu64 "\n",
			odp_queue_to_u64(handle));
		return -1;
	}

	queue = get_qentry(queue_id);

	LOCK(&queue->s.lock);
	status = queue->s.status;

	if (odp_unlikely(status == QUEUE_STATUS_FREE ||
			 status == QUEUE_STATUS_DESTROYED)) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("Invalid queue status:%d\n", status);
		return -1;
	}

	info->name = queue->s.name;
	info->param = queue->s.param;

	UNLOCK(&queue->s.lock);

	return 0;
}

int odp_queue_lock_count(odp_queue_t handle ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}
