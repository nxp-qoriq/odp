/**
 \file ip_output.h
 \brief This file captures the post-routing functionality and the
 transmission of the IP packet
 */
/*
 * Copyright (C) 2015,2016 Freescale Semiconductor, Inc.
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

#ifndef __IP_OUTPUT_H
#define __IP_OUTPUT_H

#include "net/rt.h"
#include <odp.h>

/**
 \brief			Sends IP Packet to respective netdev. If packet length > next_hop mtu, call
			ip_fragment
 \param[in] ctxt	Context
 \param[in] notes	Annotations
 \param[in] ip_hdr	Pointer to the IP Header
 */
enum IP_STATUS ip_send(odp_packet_t pkt,
		       struct neigh_t *neigh);

/**
\brief				Sends multiple IP Packets to a netdev.
\param[in] pkt			packet list which is to be sent.
\param[in] neigh		Target node where data is to be sent.
\param[in] num_packets		Number of packets to be sent in a batch.
*/
int32_t ip_send_multi(odp_packet_t pkt[],
		      struct neigh_t *neigh, int32_t num_packets);

#endif	/* __IP_OUTPUT_H */
