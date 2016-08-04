/**
 \file ip_route.h
 \brief This file contains the functionality related to Route Cache LookUp
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

#ifndef __IP_ROUTE_H
#define __IP_ROUTE_H

#include "ip.h"
#include "ip_common.h"
#include "net/rt.h"


/**
 \brief		Does Route Cache LookUp and Forwards/Drops the packet accordingly
 \param[in]	ctxt	Context came in frame descriptor
 \param[in]	notes	Annotation prepended in frame buffer
 \param[in]	ip_hdr	Pointer to the header of the IP Packet
 \return	Status
 */
enum IP_STATUS ip_route_input(odp_packet_t pkt,
			      odph_ipv4hdr_t *ip_hdr,
			      enum state state);

/**
 \brief		Discards the packet as the Route Cache LookUp failed, and Updates the Stats
 \param[in]	ctxt	Context came in frame descriptor
 \param[in]	notes	Annotation prepended in frame buffer
 \param[in]	ip_hdr	Pointer to the header of the IP Packet
 \return	Status
 */
enum IP_STATUS ip_route_input_slow(odp_packet_t pkt,
				   struct neigh_t *neigh,
				   odph_ipv4hdr_t *ip_hdr);

/**
 \brief		Check if the packet is for self or needs to be routed forward, and calls a handling
		API accordingly
 \param[in]	ctxt	Context came in frame descriptor
 \param[in]	notes	Annotation prepended in frame buffer
 \param[in]	ip_hdr	Pointer to the header of the IP Packet
 \return	Status
 */
enum IP_STATUS ip_route_finish(odp_packet_t pkt,
			       struct neigh_t *neigh,
			       odph_ipv4hdr_t *ip_hdr);

#endif	/* __IP_ROUTE_H */
