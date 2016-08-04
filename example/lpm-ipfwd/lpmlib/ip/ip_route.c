/**
 \file ip_route.c
 \brief IPv4 Route lookup is done for forwarding decision.
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

#include "ip_route.h"
#include "ip_forward.h"
#include "fib.h"

#include <odp.h>
#include <example_debug.h>

enum IP_STATUS ip_route_input(odp_packet_t buf,
			      odph_ipv4hdr_t *ip_hdr, enum state source)
{
	enum IP_STATUS retval = IP_STATUS_DROP;
	uint32_t gwaddr;
	int ret;
	struct neigh_t neighbor;

	switch (source) {
	case SOURCE_POST_FMAN:
	{
		ret = ip_route_lookup(htonl(ip_hdr->dst_addr), &gwaddr, &neighbor);
		if (odp_unlikely(ret != 0)) {
			EXAMPLE_ERR("error in lookup for IP%x\n", htonl(ip_hdr->dst_addr));
			odp_packet_free(buf);
			return ret;
		}
		retval = ip_route_finish(buf, &neighbor, ip_hdr);
	}
		break;
	default:
		EXAMPLE_ERR("Invalid Case of routing\n");
		break;
	}

	return retval;
}

enum IP_STATUS ip_route_finish(odp_packet_t pkt,
			       struct neigh_t *neigh,
			       odph_ipv4hdr_t *ip_hdr)
{
	/*if (odp_likely(neigh->pktio))*/
	if (neigh->pktio)
		return ip_forward(pkt, neigh, ip_hdr);
	EXAMPLE_ERR("packet drop\n");
	odp_packet_free(pkt);
	return IP_STATUS_DROP;
}
