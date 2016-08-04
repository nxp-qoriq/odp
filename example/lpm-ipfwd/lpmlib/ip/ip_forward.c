/**
 \file ip_forward.c
 \brief Implements forwarding function if routelookup is successful
 */
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

#include "ip_common.h"
#include "ip_forward.h"
#include <net/neigh.h>
#include "ip_output.h"
#include <odp.h>

extern struct ip_stack_t ip_stack;

enum IP_STATUS ip_forward(odp_packet_t pkt,
			  struct neigh_t *neigh,
			  odph_ipv4hdr_t *ip_hdr)
{

	if (odp_likely(ip_hdr->ttl > 1)) {
		ip_hdr->ttl -= 1;
		if (ip_hdr->chksum >= odp_cpu_to_be_16(0xffff - 0x100))
			ip_hdr->chksum += odp_cpu_to_be_16(0x100) + 1;
		else
			ip_hdr->chksum += odp_cpu_to_be_16(0x100);
	} else {
#ifdef STATS_TBD
		odp_atomic_inc_u64(
			&ip_stack.ip_stats->ip_ttl_time_exceeded);
#endif
		odp_packet_free(pkt);
		return IP_STATUS_DROP;
	}
	return ip_send(pkt, neigh);
}
