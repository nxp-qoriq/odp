/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP event
 */

#ifndef ODP_EVENT_TYPES_H_
#define ODP_EVENT_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/strong_types.h>
#include <odp/api/plat/buffer_types.h>

/** @defgroup odp_event ODP EVENT
 *  Operations on an event.
 *  @{
 */

typedef odp_buffer_t odp_event_t;

#define ODP_EVENT_INVALID _odp_cast_scalar(odp_event_t, 0xffffffff)

/**
 * Event types
 */
typedef enum odp_event_type_t {
	ODP_EVENT_BUFFER       = 0x01,
	ODP_EVENT_PACKET       = 0x02,
	ODP_EVENT_TIMEOUT      = 0x04,
	ODP_EVENT_CRYPTO_COMPL = 0x08,
} odp_event_type_t;

/** Mask for all the event types */
#define ODP_EVENT_TYPES		0x0f

/** Get printable format of odp_event_t */
static inline uint64_t odp_event_to_u64(odp_event_t hdl)
{
	return _odp_pri(hdl);
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
