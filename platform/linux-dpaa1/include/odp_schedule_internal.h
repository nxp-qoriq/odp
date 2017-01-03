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

#ifdef __cplusplus
}
#endif

#endif
