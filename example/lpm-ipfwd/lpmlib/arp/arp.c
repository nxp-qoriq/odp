/*
 * Copyright (C) 2015 - 2016 Freescale Semiconductor, Inc.
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

#include "arp.h"
#include "net/neigh.h"
#include <odp.h>
#include "ip/ip.h"
#ifdef ARP_ENABLE
#include "ip/ip_common.h"
#define	ARP_HDR_LEN	28	/**<ARP Header Length */

extern struct config_info config_info;
static spinlock_t arp_lock = SPIN_LOCK_UNLOCKED;

extern int is_iface_ip(in_addr_t ip_addr);

static int arp_handle_request(odph_ethhdr_t *eth_hdr,
		       struct node_t *node)
{
	struct ether_arp *arp;

	arp = (typeof(arp))(eth_hdr + 1);
	if (memcmp(arp->arp_tpa, &node->ip, arp->arp_pln))
		return -1;

	memcpy(arp->arp_tpa, arp->arp_spa, arp->arp_pln);
	memcpy(arp->arp_spa, &node->ip, arp->arp_pln);
	arp->arp_op = ARPOP_REPLY;
	memcpy(eth_hdr->dst, eth_hdr->src,
		sizeof(eth_hdr->dst));
	memcpy(eth_hdr->src, &node->mac, sizeof(eth_hdr->src));
	memcpy(arp->arp_tha, eth_hdr->dst, arp->arp_hln);
	memcpy(arp->arp_sha, eth_hdr->src, arp->arp_hln);
	return 0;
}

void arp_handler(const odp_packet_t buf, void *data)
{
	const struct ether_arp *arp;

	arp = data + ETHER_HDR_LEN;

	if (arp->arp_op == ARPOP_REQUEST) {
		printf("Got ARP request from IP 0x%x\n", arp_spa);

		memcpy(&new_node.mac, dev->dev_addr, dev->dev_addr_len);
		memcpy(&new_node.ip, arp->arp_tpa, arp->arp_pln);
		arp_handle_request(data, &new_node);
		dev->xmit(dev, buf, NULL);
		printf("Sent ARP reply for IP 0x%x\n", arp_tpa);
	} else {
		odp_packet_free(buf);
	}

#endif	/* ARP_ENABLE */

static void arp_solicit(struct neigh_t *n ODP_UNUSED, odp_packet_t buf)
{
#ifdef STATS_TBD
	odp_atomic_inc_u64(&n->nt->stats->solicit_errors);
#endif
	odp_packet_free(buf);
}

static void arp_error_handler(struct neigh_t *n ODP_UNUSED, odp_packet_t buf)
{
#ifdef STATS_TBD
	odp_atomic_inc_u64(&n->nt->stats->protocol_errors);
#endif
	odp_packet_free(buf);
}

static void arp_constructor(struct neigh_t *n)
{
	n->funcs->solicit = &arp_solicit;
	n->funcs->error_handler = &arp_error_handler;
}

int arp_table_init(struct neigh_table_t *nt)
{
	nt->proto_len = sizeof(in_addr_t);
	nt->constructor = arp_constructor;
	nt->config.base_reachable_timeout = 30;
	nt->config.reachable_timeout = 30;
	nt->config.retrans_timeout = 1;
	nt->config.quiesce_timeout = 5;
	nt->config.solicit_queue_len = 1;

	return 0;
}
