/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
/**
 * @file
 *
 * ODP packet descriptor - implementation internal
 */

#ifndef ODP_PACKET_INTERNAL_H_
#define ODP_PACKET_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/align.h>
#include <odp/api/debug.h>
#include <odp/api/spinlock.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_buffer_inlines.h>
#include <odp/api/packet.h>
#include <odp/api/packet_io.h>
#include <odp/api/crypto.h>
#include <odp_crypto_internal.h>
#include <odp_debug_internal.h>

/**
 * Packet input & protocol flags
 */
typedef union {
	/* All input flags */
	uint32_t all;

	struct {
		uint32_t unparsed:1;  /**< Set to inticate parse needed */

		uint32_t l2:1;        /**< known L2 protocol present */
		uint32_t l3:1;        /**< known L3 protocol present */
		uint32_t l4:1;        /**< known L4 protocol present */

		uint32_t eth:1;       /**< Ethernet */
		uint32_t jumbo:1;     /**< Jumbo frame */
		uint32_t vlan:1;      /**< VLAN hdr found */
		uint32_t vlan_qinq:1; /**< Stacked VLAN found, QinQ */

		uint32_t snap:1;      /**< SNAP */
		uint32_t arp:1;       /**< ARP */

		uint32_t ipv4:1;      /**< IPv4 */
		uint32_t ipv6:1;      /**< IPv6 */
		uint32_t ipfrag:1;    /**< IP fragment */
		uint32_t ipopt:1;     /**< IP optional headers */
		uint32_t ipsec:1;     /**< IPSec decryption may be needed */

		uint32_t udp:1;       /**< UDP */
		uint32_t tcp:1;       /**< TCP */
		uint32_t tcpopt:1;    /**< TCP options present */
		uint32_t sctp:1;      /**< SCTP */
		uint32_t icmp:1;      /**< ICMP */
	};
} input_flags_t;

ODP_STATIC_ASSERT((sizeof(input_flags_t) == sizeof(uint32_t)),
		   "INPUT_FLAGS_SIZE_ERROR");

/**
 * Packet error flags
 */
typedef union {
	/* All error flags */
	uint32_t all;

	struct {
		/* Bitfield flags for each detected error */
		uint32_t app_error:1; /**< Error bit for application use */
		uint32_t frame_len:1; /**< Frame length error */
		uint32_t snap_len:1;  /**< Snap length error */
		uint32_t l2_chksum:1; /**< L2 checksum error, checks TBD */
		uint32_t ip_err:1;    /**< IP error,  checks TBD */
		uint32_t tcp_err:1;   /**< TCP error, checks TBD */
		uint32_t udp_err:1;   /**< UDP error, checks TBD */
	};
} error_flags_t;

ODP_STATIC_ASSERT(sizeof(error_flags_t) == sizeof(uint32_t),
		   "ERROR_FLAGS_SIZE_ERROR");

/**
 * Packet output flags
 */
typedef union {
	/* All output flags */
	uint32_t all;

	struct {
		/* Bitfield flags for each output option */
		uint32_t l3_chksum_set:1; /**< L3 chksum bit is valid */
		uint32_t l3_chksum:1;	  /**< L3 chksum override */
		uint32_t l4_chksum_set:1; /**< L3 chksum bit is valid */
		uint32_t l4_chksum:1;	  /**< L4 chksum override  */
	};
} output_flags_t;

ODP_STATIC_ASSERT(sizeof(output_flags_t) == sizeof(uint32_t),
		   "OUTPUT_FLAGS_SIZE_ERROR");

typedef odp_buffer_hdr_t odp_packet_hdr_t;

typedef struct odp_packet_hdr_stride {
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_packet_hdr_t))];
} odp_packet_hdr_stride;

/**
 * Return the packet header
 */
static inline odp_packet_hdr_t *odp_packet_hdr(odp_packet_t pkt)
{
	return (odp_packet_hdr_t *)odp_buf_to_hdr((odp_buffer_t)pkt);
}

/**
 * FMan parse result array
 */
typedef struct ODP_PACKED fm_prs_result {
	 uint8_t     reserved[DEFAULT_ICEOF];
	 uint8_t     lpid;		 /**< Logical port id */
	 uint8_t     shimr;		 /**< Shim header result  */
	 uint16_t    l2r;		 /**< Layer 2 result */
	 uint16_t    l3r;		 /**< Layer 3 result */
	 uint8_t     l4r;		 /**< Layer 4 result */
	 uint8_t     cplan;		 /**< Classification plan id */
	 uint16_t    nxthdr;		 /**< Next Header  */
	 uint16_t    cksum;		 /**< Checksum */
	 uint32_t    lcv;		 /**< LCV */
	 uint8_t     shim_off[3];	 /**< Shim offset */
	 uint8_t     eth_off;		 /**< ETH offset */
	 uint8_t     llc_snap_off;	 /**< LLC_SNAP offset */
	 uint8_t     vlan_off[2];	 /**< VLAN offset */
	 uint8_t     etype_off;		 /**< ETYPE offset */
	 uint8_t     pppoe_off;		 /**< PPP offset */
	 uint8_t     mpls_off[2];	 /**< MPLS offset */
	 uint8_t     ip_off[2];		 /**< IP offset */
	 uint8_t     gre_off;		 /**< GRE offset */
	 uint8_t     l4_off;		 /**< Layer 4 offset */
	 uint8_t     nxthdr_off;	 /**< Parser end point */
	 uint64_t    timestamp;		 /**< TimeStamp */
	 uint64_t    hash_result;	 /**< Hash Result */
} fm_prs_result_t;

/* TODO - This will currently not work for SG and we shall need
 * to add a annotation pointer in packet header */
#define GET_PRS_RESULT(_pkt) ((fm_prs_result_t *)(_pkt->addr[0]))
#define BUF_HDR_OFFSET (ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_packet_hdr_t)) + ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct sg_priv)))

static inline odp_packet_hdr_t
*odp_pkt_hdr_from_addr(void *fd_addr,  pool_entry_t *pool ODP_UNUSED)
{
	return (odp_packet_hdr_t *)(fd_addr - BUF_HDR_OFFSET);
}

static inline odp_buffer_hdr_t
*odp_buf_hdr_from_addr(void *fd_addr,  pool_entry_t *pool ODP_UNUSED)
{
	return (odp_buffer_hdr_t *)(fd_addr - BUF_HDR_OFFSET);
}

/**
 * Initialize packet buffer
 */
static inline void packet_init(pool_entry_t *pool ODP_UNUSED,
			       odp_packet_hdr_t *pkt_hdr,
			       size_t size)
{
	/* reset the annotation area */
	memset(pkt_hdr->addr[0], 0, pool->s.headroom);

	 /* Set metadata items that initialize to non-zero values */
	pkt_hdr->l2_offset = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->l3_offset = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->l4_offset = ODP_PACKET_OFFSET_INVALID;
	pkt_hdr->frame_len = size;
	pkt_hdr->headroom  = pool->s.headroom;
	pkt_hdr->tailroom  = pool->s.tailroom;
	pkt_hdr->jumbo = 0;
}

static inline void copy_packet_parser_metadata(odp_packet_hdr_t *src_hdr,
					       odp_packet_hdr_t *dst_hdr)
{
	dst_hdr->l2_offset	= src_hdr->l2_offset;
	dst_hdr->l3_offset	= src_hdr->l3_offset;
	dst_hdr->l4_offset	= src_hdr->l4_offset;
}

static inline void *packet_map(odp_packet_hdr_t *pkt_hdr,
			       uint32_t offset, uint32_t *seglen)
{
	if (offset > pkt_hdr->frame_len)
		return NULL;

	return buffer_map(pkt_hdr,
			  pkt_hdr->headroom + offset, seglen,
			  pkt_hdr->headroom + pkt_hdr->frame_len);
}

static inline void push_head(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	pkt_hdr->headroom  -= len;
	pkt_hdr->frame_len += len;
}

static inline void pull_head(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	pkt_hdr->headroom  += len;
	pkt_hdr->frame_len -= len;
}

static inline void push_tail(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	pkt_hdr->tailroom  -= len;
	pkt_hdr->frame_len += len;
}


static inline void pull_tail(odp_packet_hdr_t *pkt_hdr, size_t len)
{
	pkt_hdr->tailroom  += len;
	pkt_hdr->frame_len -= len;
}

static inline void packet_set_len(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr(pkt)->frame_len = len;
}

static inline void odp_pktio_set_input(odp_packet_hdr_t * pkthdr,
					odp_pktio_t pktio)
{
	pkthdr->input = pktio;
}

static inline void buf_set_input_queue(odp_buffer_hdr_t *buf_hdr,
				       odp_queue_t inq)
{
	buf_hdr->inq = inq;
}

/* Forward declarations */
int _odp_packet_copy_to_packet(odp_packet_t srcpkt, uint32_t srcoffset,
			       odp_packet_t dstpkt, uint32_t dstoffset,
			       uint32_t len);

void _odp_packet_copy_md_to_packet(odp_packet_t srcpkt, odp_packet_t dstpkt);

odp_packet_t _odp_packet_alloc(odp_pool_t pool_hdl);

/**
 * Simple packet parser: eth, VLAN, IP, TCP/UDP/ICMP
 *
 * Internal function: caller is responsible for passing only valid packet
 * handles, lengths and offsets (usually done&called in packet input).
 *
 * @param pkt	     Packet handle
 * @param len	     Packet length in bytes
 * @param offset     offset in fd where packet data starts
 */
static inline void _odp_packet_parse(odp_packet_hdr_t *pkt_hdr, size_t len,
			      size_t offset, void *fd_addr)
{
	fm_prs_result_t *pa = pa = (typeof(pa))((fd_addr) + DEFAULT_ICEOF);

	pkt_hdr->frame_len = len;
	pkt_hdr->l2_offset = offset - pkt_hdr->headroom;
	if (pa->l4r) {
		pkt_hdr->l3_offset = pa->ip_off[0];
		pkt_hdr->l4_offset = pa->l4_off;
	} else {
		pkt_hdr->l4_offset = pa->nxthdr_off;
		if (pa->l3r)
			pkt_hdr->l3_offset = pa->ip_off[0];
		else
			pkt_hdr->l3_offset = pa->nxthdr_off;
	}
}

/* Convert a packet handle to a buffer handle */
static inline odp_buffer_t _odp_packet_to_buffer(odp_packet_t pkt)
{
	return (odp_buffer_t)pkt;
}
/* Convert a buffer handle to a packet handle */
static inline odp_packet_t _odp_packet_from_buffer(odp_buffer_t buf)
{
	return (odp_packet_t)buf;
}

/* Convert a buffer handle to a packet handle */
static inline odp_packet_t _odp_packet_from_pkt_hdr(odp_packet_hdr_t *pkt_hdr)
{
	return (odp_packet_t)pkt_hdr;
}


#ifdef __cplusplus
}
#endif

#endif
