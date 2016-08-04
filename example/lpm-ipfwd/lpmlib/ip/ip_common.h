/**
 \file ip_common.h
 \brief This file is ip_statistics
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
#ifndef __LIB_IP_IP_COMMON_H
#define __LIB_IP_IP_COMMON_H

#include <statistics.h>
#define L1_CACHE_BYTES 64
/**
\brief Status values
\details This object specifies the Possible Status values
*/
enum IP_STATUS {
	IP_STATUS_ACCEPT = 0,		/**< Packet Accepted */
	IP_STATUS_DROP = 1,		/**< Packet Dropped */
	IP_STATUS_STOLEN = 2,		/**< Packet Fragement Lost */
	IP_STATUS_STOP = 3,		/**< Packet Handler NULL */
	IP_STATUS_REPEAT = 4,		/**< Repeated packet */
	IP_STATUS_HOLD = 5
};

enum state{
	SOURCE_POST_SEC,
	SOURCE_POST_FMAN,
	SOURCE_POST_PME
};

/**
\brief IP Stats Structure
\details This onject specifies the IP Stats for the IP Fwd Application
 */
struct ip_statistics_t {
	stat32_t ip_in_received;
	/**< Number of Packets received */
	stat32_t ip_out_forward;
	/**< Number of Packets transmitted */
	stat32_t ip_local_delivery;
	/**< Number of Packets received for self */
	stat32_t ip_local_frag_reassem_started;
	/**< Number of Packets for which defragmentation started */
	union stat64_t ip_in_hdr_error;
	/**< Number of Packets received having header validation error */
	union stat64_t ip_in_chksum_error;
	/**< Number of Packets received having checksum error */

	union stat64_t ip_route_input_slow;
	/**< Number of Packets dropped because LookUp failed */
	union stat64_t ip_ttl_time_exceeded;
	/**< Number of Packets dropped because ttl exceeded */
	union stat64_t ip_xmit_icmp_redir_in_eq_out;
	/**< Number of ICMP Packets  redirected */
	union stat64_t ip_xmit_icmp_unreach_need_frag;
	/**< Number of ICMP Error Packets sent because needed fragmentation */
	union stat64_t ip_xmit_icmp_unreach_no_egress;
	/**< Number of ICMP Error Packets sent because LookUp failed */
	union stat64_t ip_local_no_l4_proto_handler;
	/**< Number of Packets dropped because L4 proto handler missing */
	union stat64_t ip_output_arp_cache_miss;
	/**< Number of ARP look ups failed*/
	union stat64_t ip_output_create_fragments;
	/**< Number of transmitted Packets that needed fragmentation */
	union stat64_t ip_in_dropped;
	/**< Number of Packets dropped for reasons other than above */
} __attribute__((aligned(L1_CACHE_BYTES)));

#endif /* __LIB_IP_IP_COMMON_H */
