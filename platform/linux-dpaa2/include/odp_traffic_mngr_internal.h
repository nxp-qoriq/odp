/* Copyright 2016 NXP
 *
 * Copyright 2015 EZchip Semiconductor Ltd. All Rights Reserved.
 *
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Traffic Manager - implementation internal
 */

#ifndef ODP_TRAFFIC_MNGR_INTERNAL_H_
#define ODP_TRAFFIC_MNGR_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <odp/api/traffic_mngr.h>
#include <odp/api/packet_io.h>
#include <odp_name_table_internal.h>
#include <odp_timer_wheel_internal.h>
#include <odp_pkt_queue_internal.h>
#include <odp_sorted_list_internal.h>
#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <odp_buffer_internal.h>
#include <odp_queue_internal.h>
#include <odp_packet_internal.h>

#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define PERCENTAGE(value, percent) ((value / 100) * percent)

/* Macros to convert handles to internal pointers and vice versa. */

#define MAKE_ODP_TM_HANDLE(tm_system)  ((odp_tm_t)(uintptr_t)tm_system)
#define GET_TM_SYSTEM(odp_tm)          ((tm_system_t *)(uintptr_t)odp_tm)
#define GET_TBL_IDX(profile_handle)  ((profile_handle & 0xFFFFFFF) - 1)

#define MAKE_ODP_TM_NODE(tm_node_obj) ((odp_tm_node_t)(uintptr_t)(tm_node_obj))
#define GET_TM_NODE_OBJ(odp_tm_node) \
	((tm_node_obj_t *)(uintptr_t)(odp_tm_node))

typedef uint64_t tm_handle_t;

#define LOW_DROP_PRECEDENCE      0x02
#define MEDIUM_DROP_PRECEDENCE   0x04
#define HIGH_DROP_PRECEDENCE     0x06
#define DROP_PRECEDENCE_MASK     0x06
#define DSCP_CLASS1              0x08
#define DSCP_CLASS2              0x10
#define DSCP_CLASS3              0x18
#define DSCP_CLASS4              0x20

#define ODP_TM_NUM_PROFILES  4

#define ODP_TM_NAME_LENGTH	32

typedef struct tm_queue_obj_s tm_queue_obj_t;
typedef struct tm_node_obj_s tm_node_obj_t;

typedef struct {
	/* A zero value for max_bytes or max_pkts indicates that this quantity
	 * is not limited, nor has a RED threshold. */
	char	name[ODP_TM_NAME_LENGTH];
	uint64_t	max_pkts;
	uint64_t	max_bytes;
	odp_bool_t enable_max_pkts;
	odp_bool_t enable_max_bytes;
	odp_tm_threshold_t thresholds_profile;
	odp_bool_t taken;
} tm_queue_thresholds_t;

typedef struct {
	char name[ODP_TM_NAME_LENGTH];
	odp_tm_sched_t      sched_profile;
	odp_tm_sched_mode_t sched_modes[ODP_TM_MAX_PRIORITIES];
	uint16_t            inverted_weights[ODP_TM_MAX_PRIORITIES];
} tm_sched_params_t;

typedef struct {
	/* The original commit rate and peak rate are in units of bits per
	 * second.  These values are converted into the number of bytes per
	 * clock cycle using a fixed point integer format with 26 bits of
	 * fractional part, before being stored into the following fields:
	 * commit_rate and peak_rate.  So a raw uint64_t value of 2^33 stored
	 * in either of these fields would represent 2^33 >> 26 = 128 bytes
	 * per clock cycle.
	 * Similarly the original commit_burst and peak_burst parameters -
	 * which are in units of bits are converted to a byte count using a
	 * fixed point integer format with 26 bits of fractional part, */
	uint64_t        commit_rate;
	uint64_t        peak_rate;
	uint32_t commit_burst;
	/** The peak burst tolerance for this shaper profile.  The units for
	 * this field are always bits.  This value sets an upper limit for the
	 * size of the peakCnt. */
	uint32_t peak_burst;
	odp_tm_shaper_t shaper_profile;
	int8_t          len_adjust;
	odp_bool_t      dual_rate;
	char 	name[ODP_TM_NAME_LENGTH];
} tm_shaper_params_t;

typedef struct tm_shaper_obj_s tm_shaper_obj_t;

struct tm_shaper_obj_s {
	tm_shaper_params_t shaper_params;
	tm_sched_params_t sched_params;
	uint8_t taken;
};

struct tm_queue_obj_s {
	odp_tm_queue_params_t params;
	uint8_t tm_idx;
	queue_entry_t tm_qentry;
};

struct tm_node_obj_s {
	void                *user_context;
	odp_tm_shaper_t shaper_profile;
	uint32_t             max_fanin;
	uint32_t             current_tm_queue_fanin;
	uint8_t              is_root_node;  /* Represents the egress. */
	uint8_t              level;   /* Primarily for debugging */
	uint8_t              tm_system_idx;
	uint8_t              tm_idx;
	char	         name[ODP_TM_NAME_LENGTH];
};

typedef struct {
	char name[ODP_TM_NAME_LENGTH];
	tm_queue_obj_t    **queue_num_tbl;
	odp_tm_egress_t       egress;
	odp_tm_requirements_t requirements;
	odp_tm_capabilities_t capabilities;
	uint8_t    tm_idx;
} tm_system_t;

#ifdef __cplusplus
}
#endif

#endif
