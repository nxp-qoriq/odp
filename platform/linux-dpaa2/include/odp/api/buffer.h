/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP buffer descriptor
 */

#ifndef ODP_PLAT_BUFFER_H_
#define ODP_PLAT_BUFFER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/event_types.h>
#include <odp/api/plat/buffer_types.h>
#include <odp/api/plat/pool_types.h>

/** @ingroup odp_buffer
 *  @{
 */

/**
 * @}
 */

/**
 * @brief Get the odp_buffer from the raw address
 *
 * @param [in]	addr	Address correspong to the buffer.
 *
 * @return Handle of the buffer
 */
odp_buffer_t odpfsl_buffer_from_addr(void *addr);

#include <odp/api/spec/buffer.h>

#ifdef __cplusplus
}
#endif

#endif
