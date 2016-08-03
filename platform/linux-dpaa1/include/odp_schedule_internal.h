/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_SCHEDULE_INTERNAL_H_
#define ODP_SCHEDULE_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif


#include <odp/api/buffer.h>
#include <odp/api/queue.h>
#include <odp_packet_internal.h>

#include <usdpaa/fsl_usd.h>
#include <usdpaa/fsl_qman.h>
#include <odp_queue_internal.h>
#include <assert.h>


/* Maximum number of dequeues */
#define MAX_DEQ 16

typedef struct {
	odp_buffer_t buf[MAX_DEQ];
	const void *buf_ctx[MAX_DEQ];
	int num;
	int index;
	bool init_done;
	uint32_t sdqcr;
	/* afine portal */
	struct qman_portal *qp;
} sched_local_t;

extern __thread sched_local_t sched_local;
extern uint32_t sdqcr_default;

typedef uint64_t (*odp_sch_recv_t)(odp_queue_t *out_queue, uint64_t wait,
			  odp_buffer_t out_buf[],
			  unsigned int max_num, unsigned int max_deq);

static inline enum qman_cb_dqrr_result odp_sched_collect_pkt(
				  odp_packet_hdr_t *pkthdr,
				  odp_packet_t pkt,
				  const struct qm_dqrr_entry *dqrr,
				  queue_entry_t *inq)
{
	odp_buffer_hdr_t *buf_hdr = (odp_buffer_hdr_t *)pkthdr;

	buf_hdr->sched_index = sched_local.index;
	assert(sched_local.index < MAX_DEQ);
	assert(sched_local.buf[sched_local.index] == ODP_BUFFER_INVALID);
	/* save sequence number when input queue is ORDERED */
	if (inq->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED) {
		buf_hdr->orp.seqnum = dqrr->seqnum;
		/*buf_hdr->orp.flags = 0;*/
	}
	/* save whole dqrr entry as it is acked on next enqueue
	   dqrr entry is stored outside the buffer because it is
	   released by the port before DCA */
	else if (inq->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC) {
		sched_local.buf_ctx[sched_local.index] = dqrr;
		sched_local.buf[sched_local.index] = _odp_packet_to_buffer(pkt);
		sched_local.index++;
		return qman_cb_dqrr_defer;
	}
	sched_local.buf[sched_local.index] = _odp_packet_to_buffer(pkt);
	sched_local.index++;

	return qman_cb_dqrr_consume;
}

static inline void odp_sched_collect_buf(odp_buffer_t buf,
				  const struct qm_dqrr_entry *dqrr,
				  queue_entry_t *inq)
{
	odp_buffer_hdr_t *buf_hdr = odp_buf_to_hdr(buf);
	buf_hdr->sched_index = sched_local.index;
	assert(sched_local.index < MAX_DEQ);
	assert(sched_local.buf[sched_local.index] == ODP_BUFFER_INVALID);
	sched_local.buf[sched_local.index] = buf;
	if (inq->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC)
		sched_local.buf_ctx[sched_local.index] = dqrr;
	sched_local.index++;
}


#ifdef __cplusplus
}
#endif

#endif
