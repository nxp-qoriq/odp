/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_DPAA2_H
#define ODP_PACKET_DPAA2_H

#include <stdint.h>
#include <net/if.h>

#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp/api/packet.h>

#include <odp_packet_internal.h>
#include <odp/api/pool.h>
#include <odp_pool_internal.h>
#include <odp_buffer_internal.h>

/*DPAA2 header files */
#include <odp/api/plat/sdk/common/dpaa2_common.h>
#include <odp/api/hints.h>
#include <odp/api/plat/sdk/common/dpaa2_cfg.h>
#include <odp/api/std_types.h>
#include <odp/api/plat/sdk/rts/dpaa2_malloc.h>
#include <odp/api/plat/sdk/main/dpaa2_dev.h>


#define ODP_DPAA2_MODE_HW	0
#define ODP_DPAA2_MODE_SW	1

#define DPAA2_BLOCKING_IO

#define MAX_PKT_BURST 1

#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/** Packet socket using dpaa2 mmaped rings for both Rx and Tx */
typedef struct {
	odp_pool_t pool;

	/********************************/
	char ifname[32];
	uint8_t portid;
	uint16_t queueid;
	struct dpaa2_dev *dev;
} pkt_dpaa2_t;

/**
  * externel API to transmit the packet on fqid
  * API added to test the ODP queue's test cases
  */
int32_t dpaa2_eth_xmit_fqid(void *vq, uint32_t num,
				dpaa2_mbuf_pt buf[]);

/**
 * Configure an interface to work in dpaa2 mode
 */
int setup_pkt_dpaa2(pkt_dpaa2_t * const pkt_dpaa2, void *netdev,
					odp_pool_t pool);
/**
 * Switch interface from dpaa2 mode to normal mode
 */
int32_t cleanup_pkt_dpaa2(pkt_dpaa2_t *const pkt_dpaa2);

int start_pkt_dpaa2(pkt_dpaa2_t * const pkt_dpaa2);

int close_pkt_dpaa2(pkt_dpaa2_t * const pkt_dpaa2);

#endif
