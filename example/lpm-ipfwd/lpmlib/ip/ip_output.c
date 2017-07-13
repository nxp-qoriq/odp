/**
 \file ip_output.c
 */
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "ip_output.h"
#include "net/neigh.h"
#include "ip_common.h"
#include "net/ll_cache.h"
#include "ethernet/eth.h"

#include <odp/helper/ip.h>
#include <example_debug.h>
#include <odp.h>

enum IP_STATUS ip_send(odp_packet_t pkt,
		       struct neigh_t *neigh)
{
	int32_t ret;
	odp_pktout_queue_t pktout;
	struct ll_cache_t *ll_cache;

	ll_cache = neigh->ll_cache;

	if (odp_unlikely(ll_cache == NULL)) {
		if (NEIGH_STATE_PENDING == neigh->neigh_state) {
			EXAMPLE_ERR("Discarding packet destined for IP 0x%x\n",
					neigh->proto_addr[0]);
			EXAMPLE_DBG("ARP entry state is pending\n");
			/* Discard successive packet (on the assumption the
			   * packet will be retransmitted by a higher network
			   * layer)
			   */
			odp_packet_free(pkt);
			return IP_STATUS_DROP;
		}
		EXAMPLE_DBG("Could not found ARP cache entries for IP 0x%x\n",
				neigh->proto_addr[0]);

		neigh->neigh_state = NEIGH_STATE_PENDING;
		neigh->retransmit_count = 0;
	} else {
		struct ether_hdr *ll_hdr;
		ll_hdr = (struct ether_hdr *)odp_packet_l2_ptr(pkt, NULL);
		output_header(ll_hdr, ll_cache);


		if (odp_pktout_queue(neigh->pktio, &pktout, 1) != 1) {
			EXAMPLE_ERR(" Error: no pktout queue\n");
			return IP_STATUS_DROP;
		}

		/* Enqueue the packet for output */
		ret = odp_pktout_send(pktout, &pkt, 1);

		if (ret < 1) {
			EXAMPLE_ERR("Packet Transmit Error\n");
			odp_packet_free(pkt);
			return IP_STATUS_DROP;
		}
	}
	return IP_STATUS_ACCEPT;
}

int32_t ip_send_multi(odp_packet_t pkt[],
		      struct neigh_t *neigh, int32_t num_packets)
{
	int32_t ret = 0, loop;
	odp_pktout_queue_t pktout;
	struct ll_cache_t *ll_cache;

	if (odp_unlikely(0 == num_packets)) {
		EXAMPLE_DBG("No Packets are received to transmit\n");
		return ret;
	}

	ll_cache = neigh->ll_cache;
	if (odp_likely((long)ll_cache)) {
		struct ether_hdr *ll_hdr;

		if (odp_pktout_queue(neigh->pktio, &pktout, 1) != 1) {
			EXAMPLE_ERR(" Error: no pktout queue\n");
			loop = 0;
			goto free_packets;
		}

		for (loop = 0; loop < num_packets; loop++) {
			ll_hdr = (struct ether_hdr *)
					odp_packet_l2_ptr(pkt[loop], NULL);
			output_header(ll_hdr, ll_cache);
		}

		/* Enqueue the packet for output */
		ret = odp_pktout_send(pktout, pkt, num_packets);
		if (ret < num_packets) {
			EXAMPLE_DBG("%d packets are transmitted\n", ret);
			loop = ret;
			goto free_packets;
		}
	} else {
		EXAMPLE_DBG("Could not found ARP cache entries for IP 0x%x\n",
			            neigh->proto_addr[0]);
		loop = 0;
		goto free_packets;
	}
	return ret;

free_packets:
	for ( ; loop < num_packets; loop++)
		odp_packet_free(pkt[loop]);
	return ret;
}

