/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP Packet IO
 */

#ifndef ODP_PLAT_PACKET_IO_H_
#define ODP_PLAT_PACKET_IO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/pool_types.h>
#include <odp/api/plat/classification_types.h>
#include <odp/api/plat/packet_types.h>
#include <odp/api/plat/packet_io_types.h>
#include <odp/api/plat/queue_types.h>

/** @ingroup odp_packet_io
 *  @{
 */

/**
 * set mtu on a packet IO interface.
 *
 * @param[in] pktio	Packet IO handle.
 * @param[in] mtu	mtu value.
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odpfsl_pktio_mtu_set(odp_pktio_t pktio, unsigned new_mtu);

/**
 * Set the default MAC address of a packet IO interface.
 *
 * @param	pktio     Packet IO handle
 * @param[in]	mac_addr  Output buffer (use ODP_PKTIO_MACADDR_MAXSIZE)
 * @param       size      Size of output buffer
 *
 * @return 0 on success
 * @retval <0 on failure
 */
int odpfsl_pktio_mac_addr_set(odp_pktio_t pktio, void *mac_addr, int size);

/**
 * @}
 */

#include <odp/api/spec/packet_io.h>

#ifdef __cplusplus
}
#endif

#endif
