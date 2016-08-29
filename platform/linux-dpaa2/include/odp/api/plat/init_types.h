/* Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2016, Freescale Semiconductor Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP initialization extension
 */

#ifndef ODP_INIT_TYPES_H_
#define ODP_INIT_TYPES_H_

#include <odp/api/std_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup odp_initialization
 *  @{
 */

/**
 * @}
 */

typedef uint64_t odp_instance_t;

/**
 * Scheduler Dequeue Modes
 */
typedef enum odpfsl_dq_schedule_mode_t {
	/** HW Scheduler will enqueue the packet/s in Rx Queue on demand */
	ODPFSL_PULL = 0,
	/** HW Scheduler will enqueue the packet/s in RX Queue automatically */
	ODPFSL_PUSH,
	/** HW Scheduler will enqueue the packet/s in RX Queue automatically
	    and HW interrupt will be given to the user*/
	ODPFSL_PUSH_INTR
} odpfsl_dq_schedule_mode_t;
/**
 * ODP platform initialization data
 *
 * @note Application may use PUSH (by H/W) mode for de-queing the packets.
 * Default is PULL (on demand).
 */

typedef struct odp_platform_init_t {
	/** HW Scheduler Mode */
	unsigned int dq_schedule_mode;
	/** size of data memory to be configured */
	uint64_t data_mem_size;
} odp_platform_init_t;

#ifdef __cplusplus
}
#endif

#endif
