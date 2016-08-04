/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP timer service
 */

#ifndef ODP_TIMER_TYPES_H_
#define ODP_TIMER_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_timer
 *  @{
 **/

struct odp_timer_pool_s; /**< Forward declaration */

typedef struct odp_timer_pool_s *odp_timer_pool_t;

#define ODP_TIMER_POOL_INVALID NULL

typedef uint32_t odp_timer_t;

#define ODP_TIMER_INVALID ((uint32_t)~0U)

typedef void *odp_timeout_t;

#define ODP_TIMEOUT_INVALID NULL

/** Get printable format of odp_timer_t*/
static inline uint64_t odp_timer_to_u64(odp_timer_t hdl)
{
	return _odp_pri(hdl);
}

/** Get printable format of odp_timeout_t*/
static inline uint64_t odp_timeout_to_u64(odp_timeout_t hdl)
{
	return _odp_pri(hdl);
}

/** Get printable format of odp_timer_pool_t*/
static inline uint64_t odp_timer_pool_to_u64(odp_timer_pool_t hdl)
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
