/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet descriptor
 */

#ifndef ODP_PLAT_PACKET_H_
#define ODP_PLAT_PACKET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/plat/event_types.h>
#include <odp/api/plat/packet_io_types.h>
#include <odp/api/plat/packet_types.h>
#include <odp/api/plat/buffer_types.h>
#include <odp/api/plat/pool_types.h>
#include <odp/api/plat/sdk/eth/dpaa2_ether.h>
#include <odp/api/byteorder.h>
#include <odp/api/packet_flags.h>
#include <odp/api/plat/packet_annot.h>
#include <odp/api/hints.h>

/*current data pointer may have moved, while the annnotation data is stored
originally w.r.t the original packet headroom - data pointer.
hence offseting it with head and original headroom */

#if 0
#define PUSH_PULL_ADJUST_OFFSET(pkthdr, offset) \
	(offset += (pkthdr->data - pkthdr->head)  - dpaa2_mbuf_head_room)

#define PUSH_PULL_ADJUST_PTR(pkthdr) \
	(pkthdr->head  - dpaa2_mbuf_head_room)
#else
#define PUSH_PULL_ADJUST_OFFSET(pkthdr, offset)

#define PUSH_PULL_ADJUST_PTR(pkthdr) (pkthdr->data)
#endif

/** @ingroup odp_packet
 *  @{
 */
static inline uint32_t odp_packet_len(odp_packet_t pkt)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;

	return pkt_hdr->tot_frame_len;
}

static inline void *odp_packet_data(odp_packet_t pkt)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;

	return pkt_hdr->data;
}

static inline uint32_t odp_packet_l2_offset(odp_packet_t pkt)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	if (!odp_packet_has_l2(pkt))
		return ODP_PACKET_OFFSET_INVALID;

	DPAA2_GET_MBUF_HW_ANNOT(pkt_hdr, annotation);
	return ETH_OFFSET(annotation->word5) >> 32;
}

static inline uint32_t odp_packet_l3_offset(odp_packet_t pkt)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	if (!odp_packet_has_l3(pkt))
		return ODP_PACKET_OFFSET_INVALID;

	DPAA2_GET_MBUF_HW_ANNOT(pkt_hdr, annotation);
	return ARP_OR_IP_OFFSET_1(annotation->word6) >> 32;
}

static inline uint32_t odp_packet_l4_offset(odp_packet_t pkt)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;
	odp_packet_metadata_t *annotation;
	uint32_t offset;

	DPAA2_GET_MBUF_HW_ANNOT(pkt_hdr, annotation);
	offset = L4_OFFSET(annotation->word6) >> 8;

	if (offset == 0xFF) {
		uint32_t l3_offset;

		/** Checking for known L4 protocol**/
		if (!odp_packet_has_l4(pkt))
			return ODP_PACKET_OFFSET_INVALID;

		/**Manually calculating the L4 offset for all other protocols
		  which are known, but not consider as L4 protocols by the hardware**/

		l3_offset = odp_packet_l3_offset(pkt);

		if (BIT_ISSET_AT_POS(annotation->word4, L3_IPV4_1_PRESENT)) {
			uint8_t *ihl;

			ihl = (uint8_t *)(pkt_hdr->data + l3_offset);
			offset = l3_offset + ((*ihl & 0xF) << 2);	/**l3 offset + IPV4_HDR_LEN **/
		} else if (BIT_ISSET_AT_POS(annotation->word4, L3_IPV6_1_PRESENT)) {
			offset = l3_offset + 40;	/**l3 offset + IPV6_HDR_LEN **/
		} else {
			offset = ODP_PACKET_OFFSET_INVALID;
		}
	}
	return offset;
}

static inline void *odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;
	odp_packet_metadata_t *annotation;
	void *l2_ptr;

	if (!odp_packet_has_l2(pkt))
		return NULL;

	DPAA2_GET_MBUF_HW_ANNOT(pkt_hdr, annotation);
	l2_ptr = PUSH_PULL_ADJUST_PTR(pkt_hdr)
			+ (ETH_OFFSET(annotation->word5) >> 32);

	if (len)
		*len = pkt_hdr->frame_len - ((uint8_t *)l2_ptr - pkt_hdr->data);

	return l2_ptr;
}

static inline void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;
	odp_packet_metadata_t *annotation;
	void *l3_ptr;

	if (!odp_packet_has_l3(pkt))
		return NULL;

	DPAA2_GET_MBUF_HW_ANNOT(pkt_hdr, annotation);
	l3_ptr = PUSH_PULL_ADJUST_PTR(pkt_hdr)
		+ (ARP_OR_IP_OFFSET_1(annotation->word6) >> 32);

	if (len)
		*len = pkt_hdr->frame_len - ((uint8_t *)l3_ptr - pkt_hdr->data);

	return l3_ptr;
}

static inline void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;
	void *l4_ptr;

	if (!odp_packet_has_l4(pkt))
		return NULL;

	l4_ptr = PUSH_PULL_ADJUST_PTR(pkt_hdr)
			+ odp_packet_l4_offset(pkt);

	if (len)
		*len = pkt_hdr->frame_len - ((uint8_t *)l4_ptr - pkt_hdr->data);

	return l4_ptr;
}

static inline int odp_packet_l2_offset_set(odp_packet_t pkt, uint32_t offset)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	/*Check that offset is in limit*/
	if (offset < odp_packet_len(pkt)) {
		PUSH_PULL_ADJUST_OFFSET(pkt_hdr, offset);
		DPAA2_GET_MBUF_HW_ANNOT(pkt_hdr, annotation);
		annotation->word5 &= (~0x000000FF00000000);
		annotation->word5 |= ETH_OFFSET(offset << 32);
		/*Set Layer 2 header flag also*/
		odp_packet_has_l2_set(pkt, 1);
		return 0;
	}

	printf("\n%s-Offset is greater that packet length %d %d \n",
		__func__, offset, odp_packet_len(pkt));

	return -1;
}

static inline int odp_packet_l3_offset_set(odp_packet_t pkt, uint32_t offset)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	/*Check that offset is in limit*/
	if (offset < odp_packet_len(pkt)) {
		PUSH_PULL_ADJUST_OFFSET(pkt_hdr, offset);
		DPAA2_GET_MBUF_HW_ANNOT(pkt_hdr, annotation);
		annotation->word6 &= (~0x000000FF00000000);
		annotation->word6 |= ARP_OR_IP_OFFSET_1(offset << 32);
		/*Set Layer 3 header flag also*/
		odp_packet_has_l3_set(pkt, 1);
		return 0;
	}

	printf("\n%s-Offset is greater that packet length %d %d \n",
		__func__, offset, odp_packet_len(pkt));

	return -1;
}

static inline int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	/*Check that offset is in limit*/
	if (offset < odp_packet_len(pkt)) {
		PUSH_PULL_ADJUST_OFFSET(pkt_hdr, offset);
		DPAA2_GET_MBUF_HW_ANNOT(pkt_hdr, annotation);
		annotation->word6 &= (~0x000000000000FF00);
		annotation->word6 |= L4_OFFSET(offset << 8);
		/*Set Layer 4 header flag also*/
		odp_packet_has_l4_set(pkt, 1);
		return 0;
	}

	printf("\n%s-Offset is greater that packet length %d %d \n",
		__func__, offset, odp_packet_len(pkt));

	return -1;
}

static inline uint32_t odp_packet_flow_hash(odp_packet_t pkt)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;

	return pkt_hdr->hash_val;
}

static inline void odp_packet_flow_hash_set(odp_packet_t pkt, uint32_t flow_hash)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)pkt;

	pkt_hdr->hash_val = flow_hash;
	BIT_SET_AT_POS(pkt_hdr->eth_flags, DPAA2BUF_HAS_HASHVAL);
}

/**
 * @brief Get the internal device ID corresponding to the packet pool
 *
 * @param [in]	pkt_pool	ODP packet pool
 *
 * @return Packet pool internal ID (BPID)
 */
uint16_t odpfsl_packet_pool_internal_id(odp_pool_t pkt_pool);

/**
 * @brief Get the odp_packet from a raw address
 *
 * @param [in]	pkt_pool	ODP Packet Pool.
 * @param [in]	addr	Address correspong to the packet.
 *
 * @return Handle of the packet
 */
odp_packet_t odpfsl_packet_from_addr(odp_pool_t pkt_pool, void *addr);

#include <odp/api/spec/packet.h>

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
