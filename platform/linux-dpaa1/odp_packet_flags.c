/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/packet_flags.h>
#include <odp_packet_internal.h>
#include <odp_debug_internal.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <configs/odp_config_platform.h>

#define L2_ERROR_MASK	  0x001f  /* bits 11:15 */
#define L3_ERROR_MASK	  0x0200 /* bit 6 */
#define L4_ERROR_MASK	  0x10	 /* bit 3 */
#define ETH_LEN_ERR	  2
#define VLAN_LEN_ERR	  4

#define ETH_PRESENT_MASK  0x8000 /* bit 0 */
#define L2_BIT_POS 15		/* bit 0 */
#define ETH_BIT_POS L2_BIT_POS	/* bit 0 */
#define VLAN_PRESENT_MASK 0x4000 /* bit 1 */
#define VLAN_BIT_POS (ETH_BIT_POS - 1) /* bit 1 */
#define QINQ_PRESENT_MASK 0x100 /* bit 7 */
#define VLAN_QINQ_BIT_POS (ETH_BIT_POS - 7) /* bit 7 */

#define FIRST_IPV4_PRESENT_MASK 0x8000 /* bit 0 */
#define L3_BIT_POS 15		/* bit 0 */
#define FIRST_IPV4_BIT_POS 15		/* bit 0 */
#define FIRST_IPV6_PRESENT_MASK 0x4000 /* bit 1 */
#define FIRST_IPV6_BIT_POS (FIRST_IPV4_BIT_POS - 1) /* bit 1 */
#define UNKNOWN_PROTO_MASK	0x0080 /* bit 8 */
#define UNKNOWN_PROTO_BIT_POS	7 /* bit 8 */
#define IPOPT_MASK		0x0100 /* bit 7 */
#define IPOPT_BIT_POS		8 /* bit 7 */
#define IPFRAG_MASK		0x0040 /* bit 9 */
#define IPFRAG_BIT_POS		6 /* bit 9 */

#define L4_TYPE_MASK	0xe0 /* bits 0:2 */
#define L4_BIT_POS 6		/* bit 1 */
#define L4_TYPE_SHIFT	5
#define TCP_PRESENT	1
#define UDP_PRESENT	2
#define IPSEC_PRESENT	3
#define SCTP_PRESENT	4


int odp_packet_has_error(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return (odp_be_to_cpu_16(pa->l2r) & L2_ERROR_MASK) ||
		(odp_be_to_cpu_16(pa->l3r) & L3_ERROR_MASK) ||
		(pa->l4r & L4_ERROR_MASK);
}

/* Get Input Flags */

int odp_packet_has_l2(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return odp_be_to_cpu_16(pa->l2r);
}

int odp_packet_has_l3(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return odp_be_to_cpu_16(pa->l3r);
}

int odp_packet_has_l4(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return pa->l4r;
}

int odp_packet_has_eth(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);

	return odp_be_to_cpu_16(pa->l2r) & ETH_PRESENT_MASK;
}

int odp_packet_has_jumbo(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->jumbo;
}

int odp_packet_has_vlan(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return odp_be_to_cpu_16(pa->l2r) & VLAN_PRESENT_MASK;
}

int odp_packet_has_vlan_qinq(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return (odp_be_to_cpu_16(pa->l2r) & VLAN_PRESENT_MASK) &&
		(odp_be_to_cpu_16(pa->l2r) & QINQ_PRESENT_MASK);
}

int odp_packet_has_arp(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return !(odp_be_to_cpu_16(pa->l3r) & FIRST_IPV4_PRESENT_MASK) &&
		(odp_be_to_cpu_16(pa->l3r) & UNKNOWN_PROTO_MASK) &&
		(odp_be_to_cpu_16(pa->nxthdr) == ODPH_ETHTYPE_ARP);
}

int odp_packet_has_ipv4(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return odp_be_to_cpu_16(pa->l3r) & FIRST_IPV4_PRESENT_MASK;
}

int odp_packet_has_ipv6(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return odp_be_to_cpu_16(pa->l3r) & FIRST_IPV6_PRESENT_MASK;
}

int odp_packet_has_ipfrag(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return odp_be_to_cpu_16(pa->l3r) & IPFRAG_MASK;
}

int odp_packet_has_ipopt(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return odp_be_to_cpu_16(pa->l3r) & IPOPT_MASK;
}

int odp_packet_has_ipsec(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return ((pa->l4r & L4_TYPE_MASK)>>L4_TYPE_SHIFT) == IPSEC_PRESENT;
}

int odp_packet_has_udp(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return ((pa->l4r & L4_TYPE_MASK)>>L4_TYPE_SHIFT) == UDP_PRESENT;
}

int odp_packet_has_tcp(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return ((pa->l4r & L4_TYPE_MASK)>>L4_TYPE_SHIFT) == TCP_PRESENT;
}

int odp_packet_has_sctp(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return ((pa->l4r & L4_TYPE_MASK)>>L4_TYPE_SHIFT) == SCTP_PRESENT;
}

int odp_packet_has_icmp(odp_packet_t pkt)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	return (odp_be_to_cpu_16(pa->l3r) & FIRST_IPV4_PRESENT_MASK) &&
	       (odp_be_to_cpu_16(pa->l3r) & UNKNOWN_PROTO_MASK) &&
	       (odp_be_to_cpu_16(pa->nxthdr) == ODPH_IPPROTO_ICMP);
}

/* Set Input Flags */

void odp_packet_has_l2_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	pa->l2r = odp_cpu_to_be_16(val << L2_BIT_POS);
}

void odp_packet_has_l3_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	pa->l3r = odp_be_to_cpu_16(val << L3_BIT_POS);
}

void odp_packet_has_l4_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	pa->l4r = val << L4_BIT_POS;
}

void odp_packet_has_eth_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);

	pa->l2r = pa->l2r & odp_cpu_to_be_16((uint16_t)~ETH_PRESENT_MASK);
	pa->l2r = pa->l2r | odp_cpu_to_be_16(val << ETH_BIT_POS);
}

void odp_packet_has_jumbo_set(odp_packet_t pkt, int val)
{
	odp_packet_hdr(pkt)->jumbo = val;
}

void odp_packet_has_vlan_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);

	pa->l2r = pa->l2r & odp_cpu_to_be_16(~VLAN_PRESENT_MASK);
	pa->l2r = pa->l2r | odp_cpu_to_be_16(val << VLAN_BIT_POS);
}

void odp_packet_has_vlan_qinq_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);

	pa->l2r = pa->l2r & odp_cpu_to_be_16(~VLAN_PRESENT_MASK);
	pa->l2r = pa->l2r & odp_cpu_to_be_16(~QINQ_PRESENT_MASK);
	pa->l2r = pa->l2r | odp_cpu_to_be_16(val << VLAN_BIT_POS |
			val << VLAN_QINQ_BIT_POS);
}

void odp_packet_has_arp_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);

	pa->l3r = pa->l3r & odp_cpu_to_be_16(
				(uint16_t)~FIRST_IPV4_PRESENT_MASK);
	pa->l3r = pa->l3r & odp_cpu_to_be_16(~UNKNOWN_PROTO_MASK);
	pa->l3r = pa->l3r | odp_cpu_to_be_16(val << UNKNOWN_PROTO_BIT_POS);
	pa->nxthdr = odp_cpu_to_be_16(ODPH_ETHTYPE_ARP);
}

void odp_packet_has_ipv4_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);

	pa->l3r = pa->l3r & odp_cpu_to_be_16(
				(uint16_t)~FIRST_IPV4_PRESENT_MASK);
	pa->l3r = pa->l3r | odp_cpu_to_be_16(val << FIRST_IPV4_BIT_POS);
}

void odp_packet_has_ipv6_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);

	pa->l3r = pa->l3r & odp_cpu_to_be_16(~FIRST_IPV6_PRESENT_MASK);
	pa->l3r = pa->l3r | odp_cpu_to_be_16(val << FIRST_IPV6_BIT_POS);
}

void odp_packet_has_ipfrag_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	pa->l3r = pa->l3r & odp_cpu_to_be_16(~IPFRAG_MASK);
	pa->l3r = pa->l3r | odp_cpu_to_be_16(val <<  IPFRAG_BIT_POS);
}

void odp_packet_has_ipopt_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	pa->l3r = pa->l3r & odp_cpu_to_be_16(~IPOPT_MASK);
	pa->l3r = pa->l3r | odp_cpu_to_be_16(val <<  IPOPT_BIT_POS);
}

void odp_packet_has_ipsec_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	pa->l4r = pa->l4r & ~L4_TYPE_MASK;
	if (val)
		pa->l4r = pa->l4r | (IPSEC_PRESENT << L4_TYPE_SHIFT);
}

void odp_packet_has_udp_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	pa->l4r = pa->l4r & ~L4_TYPE_MASK;
	if (val)
		pa->l4r = pa->l4r | (UDP_PRESENT << L4_TYPE_SHIFT);
}

void odp_packet_has_tcp_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	pa->l4r = pa->l4r & ~L4_TYPE_MASK;
	if (val)
		pa->l4r = pa->l4r | (TCP_PRESENT << L4_TYPE_SHIFT);
}

void odp_packet_has_sctp_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);
	pa->l4r = pa->l4r & ~L4_TYPE_MASK;
	if (val)
		pa->l4r = pa->l4r | (SCTP_PRESENT << L4_TYPE_SHIFT);
}

void odp_packet_has_icmp_set(odp_packet_t pkt, int val)
{
	fm_prs_result_t *pa;
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	pa = GET_PRS_RESULT(pkt_hdr->buf_hdr, pa);

	pa->l3r =  pa->l3r & odp_cpu_to_be_16(
				(uint16_t)~FIRST_IPV4_PRESENT_MASK);
	pa->l3r =  pa->l3r & odp_cpu_to_be_16(~UNKNOWN_PROTO_MASK);

	pa->l3r = pa->l3r | odp_cpu_to_be_16(val << FIRST_IPV4_BIT_POS);
	pa->l3r = pa->l3r | odp_cpu_to_be_16(val << UNKNOWN_PROTO_BIT_POS);

	pa->nxthdr = odp_cpu_to_be_16(ODPH_IPPROTO_ICMP);
}
