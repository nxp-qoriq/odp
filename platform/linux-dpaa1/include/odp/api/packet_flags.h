/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet flags
 */

#ifndef ODP_PLAT_PACKET_FLAGS_H_
#define ODP_PLAT_PACKET_FLAGS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/hints.h>
#include <odp/api/plat/packet_types.h>
#include <odp/api/debug.h>
/** @ingroup odp_packet
 *  @{
 */

/**
 * @}
 */

static inline int odp_packet_has_flow_hash(odp_packet_t pkt ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static inline void odp_packet_has_flow_hash_clr(odp_packet_t pkt ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
}

static inline int odp_packet_has_ts(odp_packet_t pkt ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static inline void odp_packet_has_ts_clr(odp_packet_t pkt ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
}

#include <odp/api/spec/packet_flags.h>

#ifdef __cplusplus
}
#endif

#endif
