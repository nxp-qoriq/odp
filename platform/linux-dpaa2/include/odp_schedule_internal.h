/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
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
#include <odp/api/thrmask.h>
#include <odp_queue_internal.h>

void odp_schedule_mask_set(odp_queue_t queue, int prio);

odp_buffer_t odp_schedule_buffer_alloc(odp_queue_t queue);

void odp_schedule_queue(queue_entry_t *qentry, int prio, uint8_t vq_id);

int32_t odp_add_queue_to_group(odp_schedule_group_t grp);

int32_t odp_sub_queue_to_group(odp_schedule_group_t grp);

struct dpaa2_dev *odp_get_conc_from_grp(odp_schedule_group_t grp);

int32_t odp_affine_group(odp_schedule_group_t group, const odp_thrmask_t *msk);

int32_t odp_deaffine_group(odp_schedule_group_t group, const odp_thrmask_t *msk);

void odp_schedule_release_context(void);

extern odpfsl_dq_schedule_mode_t dq_schedule_mode;

typedef int32_t (*odp_sch_recv_t)(dpaa2_mbuf_pt mbuf[], int num);


#ifdef __cplusplus
}
#endif

#endif
