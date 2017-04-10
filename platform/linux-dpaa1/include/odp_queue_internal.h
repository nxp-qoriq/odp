/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
/**
 * @file
 *
 * ODP queue - implementation internal
 */

#ifndef ODP_QUEUE_INTERNAL_H_
#define ODP_QUEUE_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp/api/queue.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp/api/packet_io.h>
#include <odp/api/align.h>


#define USE_TICKETLOCK

#ifdef USE_TICKETLOCK
#include <odp/api/ticketlock.h>
#else
#include <odp/api/spinlock.h>
#endif

#include <usdpaa/fsl_usd.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fman.h>
#include <usdpaa/dma_mem.h>

/* It indicates number of rx fq mentioned in policy file executed using fmc*/
#define QUEUE_MULTI_MAX 32

#define QUEUE_STATUS_FREE     0
#define QUEUE_STATUS_READY    1
#define QUEUE_STATUS_NOTSCHED 2
#define QUEUE_STATUS_SCHED    3
#define QUEUE_STATUS_DESTROYED    4

#define CPU_BACKOFF_CYCLES 512
/* forward declaration */
union queue_entry_u;

typedef int (*enq_func_t)(union queue_entry_u *, odp_buffer_hdr_t *);
typedef	odp_buffer_hdr_t *(*deq_func_t)(union queue_entry_u *);

typedef int (*enq_multi_func_t)(union queue_entry_u *,
		odp_buffer_hdr_t **, int);
typedef	int (*deq_multi_func_t)(union queue_entry_u *,
				odp_buffer_hdr_t **, int);
struct queue_entry_s {
#ifdef USE_TICKETLOCK
	odp_ticketlock_t  lock ODP_ALIGNED_CACHE;
#else
	odp_spinlock_t	  lock ODP_ALIGNED_CACHE;
#endif

	odp_buffer_hdr_t *head;
	odp_buffer_hdr_t *tail;
	int		  status;

	enq_func_t	 enqueue ODP_ALIGNED_CACHE;
	deq_func_t	 dequeue;
	enq_multi_func_t enqueue_multi;
	deq_multi_func_t dequeue_multi;

	odp_queue_t       handle;
	odp_queue_t       pri_queue;
	odp_event_t       cmd_ev;
	odp_queue_type_t  type;
	odp_queue_param_t param;
	odp_pktio_t	  pktin;
	odp_bool_t        poll_pktin;
	odp_pktio_t	  pktout;
	char		  name[ODP_QUEUE_NAME_LEN + 1];
	struct qman_fq	  fq;
	struct qman_fq	  orp_fq;
	odp_buffer_hdr_t *buf_hdr;
};

#define QENTRY_FROM_FQ(fq)	\
	((queue_entry_t *)container_of(fq, struct queue_entry_s, fq))

#define QENTRY_FROM_ORP_FQ(fq)	\
	((queue_entry_t *)container_of(fq, struct queue_entry_s, orp_fq))

typedef union queue_entry_u {
	struct queue_entry_s s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct queue_entry_s))];
} queue_entry_t;


queue_entry_t *get_qentry(uint32_t queue_id);

uint32_t get_qid(queue_entry_t *qentry);

int queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr);
odp_buffer_hdr_t *queue_deq(queue_entry_t *queue);

int queue_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num);
int queue_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num);

void queue_lock(queue_entry_t *queue);
void queue_unlock(queue_entry_t *queue);

int queue_sched_atomic(odp_queue_t handle);

void ern_cb(struct qman_portal *p __always_unused,
	    struct qman_fq *fq __always_unused,
	    const struct qm_mr_entry *msg __always_unused);

void orp_ern_cb(struct qman_portal *p __always_unused,
		struct qman_fq *fq __always_unused,
		const struct qm_mr_entry *msg __always_unused);

static inline uint32_t queue_to_id(odp_queue_t handle)
{
	return _odp_typeval(handle) - 1;
}

static inline odp_queue_t queue_from_id(uint32_t queue_id)
{
	return _odp_cast_scalar(odp_queue_t, queue_id + 1);
}

static inline queue_entry_t *queue_to_qentry(odp_queue_t handle)
{

	uint32_t queue_id;

	queue_id = queue_to_id(handle);
	return get_qentry(queue_id);
}

/* configure fd for contig or sg frames */
static inline void __config_fd(struct qm_fd *fd,
			      const odp_buffer_hdr_t *buf_hdr,
			      size_t off, size_t len,
			      queue_entry_t *qentry)
{
	struct qm_sg_entry *sgt;
	dma_addr_t addr;
	unsigned seg;
	size_t sg_len;

	/**
	 * For FMANv2(e.g p4080), disable L4 chksum validation (O/H port).
	 * Chksum is not available for FMANv2 devices.(valid only for FMANv3)
	 * For FMANv3(e.g t1040), L4 chksum will be enabled.
	 */
#if defined(P4080)
	fd->cmd = 0x10000000;
#else
	fd->cmd = 0;
#endif
	fd->opaque_addr = 0;
	fd->opaque = buf_hdr->frame_len;
	fd->opaque |= (off << 20);

	if (buf_hdr->segcount > 1) {
		pool_entry_t *pool_entry;
		pool_entry = odp_pool_to_entry(buf_hdr->pool_hdl);
		fd->format = qm_fd_sg;
		sgt = (typeof(sgt))(buf_hdr->addr[buf_hdr->segcount] +
				    pool_entry->s.headroom);
		/* save the annotation info in this space */
		fd->offset = pool_entry->s.headroom;
		sg_len = pool_entry->s.params.pkt.len -
			 pool_entry->s.headroom;
		for (seg = 0; seg < buf_hdr->segcount; seg++) {
			/* Reserved & BPID */
			sgt[seg].__reserved2 = 0;
			sgt[seg].bpid = (uint8_t)pool_entry->s.pool_id;
			/* Reserved & Offset */
			sgt[seg].__reserved3 = 0;
			sgt[seg].offset = (seg == 0) ?
					pool_entry->s.headroom : 0;
			/* E & F & Length */
			sgt[seg].extension = 0;
			sgt[seg].final = (seg + 1 == buf_hdr->segcount) ? 1 : 0;
			sgt[seg].length = sg_len;
			addr = __dma_mem_vtop(buf_hdr->addr[seg]);
			/* Reserved & Address */
			sgt[seg].__notaddress = 0;
			sgt[seg].addr = addr;
			len -= sg_len;
			if (len <= pool_entry->s.params.pkt.len)
				sg_len = len;
			else
				sg_len = pool_entry->s.params.pkt.len;
			/* On LE CPUs, converts the SG entry to BE format as
			 * expected by the HW, on BE CPUs does nothing */
			cpu_to_hw_sg(&sgt[seg]);
		}

		fd->addr = __dma_mem_vtop(buf_hdr->addr[seg]);
		fd->bpid = buf_hdr->bpid;

	} else {
		if (qentry->s.type == ODP_QUEUE_TYPE_PLAIN) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			fd->opaque_addr = buf_hdr->phy_addr;
#else
			fd->opaque_addr = buf_hdr->phy_addr << 24;
#endif
		} else {
			fd->addr = (intptr_t)buf_hdr;
		}
		fd->bpid = buf_hdr->bpid;
	}

	return;
}

void odp_queue_set_input(odp_buffer_t buf, odp_queue_t queue);

int queue_init_rx_fq(struct qman_fq *fq, uint16_t channel);

int queue_init_orp_fq(struct qman_fq *orp_fq);

int queue_enqueue_tx_fq(struct qman_fq *tx_fq, struct qm_fd *fd,
			odp_buffer_hdr_t *buf_hdr, queue_entry_t *in_qentry);

unsigned do_volatile_deq(struct qman_fq *fq, unsigned len, bool exact);

void teardown_fq(struct qman_fq *fq);

#ifdef __cplusplus
}
#endif

#endif
