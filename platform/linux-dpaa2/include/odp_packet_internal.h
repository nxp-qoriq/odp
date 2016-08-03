/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet descriptor - implementation internal
 */

#ifndef ODP_PACKET_INTERNAL_H_
#define ODP_PACKET_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp/api/packet.h>
#include <odp/api/packet_flags.h>
#include <odp/api/packet_io.h>
#include <odp/helper/eth.h>

/**
* Internal Packet header
*/
typedef struct {
	/* common buffer header */
	odp_buffer_hdr_t buf_hdr;
} odp_packet_hdr_t;

/**
 * Return the packet header
 */
static inline odp_packet_hdr_t *odp_packet_hdr(odp_packet_t pkt)
{
	return (odp_packet_hdr_t *)odp_buf_to_hdr((odp_buffer_t)pkt);
}

/**
 * Return the Mbuf header
 */
static inline struct dpaa2_mbuf *odp_dpaa2_mbuf_hdr(odp_packet_t pkt)
{
	return (struct dpaa2_mbuf *)odp_buf_to_hdr((odp_buffer_t)pkt);
}

/* Convert a buffer handle to a packet handle */
odp_packet_t _odp_packet_from_buffer(odp_buffer_t buf);

#define ODP_PACKET_UNPARSED ~0

odp_buffer_t _odp_packet_to_buffer(odp_packet_t pkt);


void odp_packet_user_u64_set(odp_packet_t pkt, uint64_t ctx);

#ifdef __cplusplus
}
#endif

#endif
