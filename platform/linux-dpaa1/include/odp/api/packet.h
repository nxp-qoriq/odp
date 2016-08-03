/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_PLAT_PACKET_H_
#define ODP_PLAT_PACKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/event_types.h>
#include <odp/api/plat/packet_io_types.h>
#include <odp/api/plat/packet_types.h>
#include <odp/api/plat/buffer_types.h>
#include <odp/api/plat/pool_types.h>
#include <odp/api/spec/hints.h>
#include <odp/api/debug.h>
/** @ingroup odp_packet
 *  @{
 */

/**
 * @}
 */
static inline uint32_t odp_packet_flow_hash(odp_packet_t pkt ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static inline void odp_packet_flow_hash_set(odp_packet_t pkt ODP_UNUSED, uint32_t flow_hash ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
}

#include <odp/api/spec/packet.h>

#ifdef __cplusplus
}
#endif

#endif
