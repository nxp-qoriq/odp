/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP Packet IO
 */

#ifndef ODP_PACKET_IO_TYPES_H_
#define ODP_PACKET_IO_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/strong_types.h>
#include <odp/api/plat/queue_types.h>

/** @addtogroup odp_packet_io ODP PACKET IO
 *  Operations on a packet.
 *  @{
 */

typedef ODP_HANDLE_T(odp_pktio_t);

typedef	ODP_HANDLE_T(odp_pktin_queue_t);

/** @internal */
typedef struct odp_pktout_queue_s {
	odp_pktio_t pktio; /**< @internal pktio handle */
	odp_queue_t queue;	/**< @internal pktio queue index */
} odp_pktout_queue_t;

#define ODP_PKTIO_INVALID _odp_cast_scalar(odp_pktio_t, 0)

#define ODP_PKTIO_ANY _odp_cast_scalar(odp_pktio_t, ~0)

#define ODP_PKTIO_MACADDR_MAXSIZE 16

#define ODP_PKTIN_NO_WAIT 1
#define ODP_PKTIN_WAIT    0

/** Get printable format of odp_pktio_t */
static inline uint64_t odp_pktio_to_u64(odp_pktio_t hdl)
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
