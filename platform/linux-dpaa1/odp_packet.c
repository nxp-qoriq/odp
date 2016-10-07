/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/packet.h>
#include <odp/api/packet_flags.h>
#include <odp_packet_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/byteorder.h>

#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/tcp.h>
#include <odp/helper/udp.h>

#include <string.h>
#include <stdio.h>

#include "configs/odp_config_platform.h"
#include <usdpaa/dma_mem.h>
/*
 *
 * Alloc and free
 * ********************************************************
 *
 */

odp_packet_t odp_packet_alloc(odp_pool_t pool_hdl, uint32_t len)
{
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);
	odp_buffer_hdr_t *buf_hdr;
	odp_packet_hdr_t *pkt_hdr;
	odp_buffer_t buf;
	uintmax_t totsize;

	if (pool->s.params.type != ODP_POOL_PACKET)
		return ODP_PACKET_INVALID;

	buf = odp_buffer_alloc_bman(pool);
	if (buf != ODP_BUFFER_INVALID) {
		totsize = pool->s.headroom + len + pool->s.tailroom;
		buf_hdr = odp_buf_to_hdr(buf);

		if (buf_hdr->size < totsize) {
			intmax_t needed = totsize - buf_hdr->size;
			struct bm_buffer bm_buf;
			uint8_t *addr;
			int ret;

			do {
				ret = bman_acquire(pool->s.bman_pool, &bm_buf,
						   1, 0);
				if (ret < 0)
					return ODP_PACKET_INVALID;

				addr = __dma_mem_ptov(bm_buf_addr(&bm_buf));
				memset(addr, 0, pool->s.headroom +
				       pool->s.blk_size + pool->s.tailroom);
				buf_hdr->addr[buf_hdr->segcount++] = addr;
				needed -= pool->s.seg_size;
			} while (needed > 0);
			/*
			 * segcount contains also the sg table buffer;
			 * size of the packet will be segcount - 1.
			 */
			buf_hdr->size = (buf_hdr->segcount - 1) *
					 pool->s.seg_size;
			/* alloc extra buffer for sg table */
			ret = bman_acquire(pool->s.bman_pool, &bm_buf,
					   1, 0);
			if (ret < 0)
				return ODP_PACKET_INVALID;

			addr = __dma_mem_ptov(bm_buf_addr(&bm_buf));
			buf_hdr->addr[buf_hdr->segcount] = addr;
			memset(addr, 0, pool->s.headroom +
			       pool->s.blk_size + pool->s.tailroom);
		}
		/* input queue must be initialized */
		buf_hdr->inq = ODP_QUEUE_INVALID;
		buf_hdr->allocator = odp_thread_id();
		pkt_hdr = (odp_packet_hdr_t *)buf_hdr;
		pkt_hdr->input = ODP_PKTIO_INVALID;
		packet_init(pool, pkt_hdr, len);
	}

	return (odp_packet_t)buf;
}

void odp_packet_free(odp_packet_t pkt)
{
	odp_buffer_free((odp_buffer_t)pkt);
}

int odp_packet_reset(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);
	pool_entry_t *pool = odp_buf_to_pool(&pkt_hdr->buf_hdr);
	uint32_t totsize = pool->s.headroom + len + pool->s.tailroom;

	if (totsize > pkt_hdr->buf_hdr.size)
		return -1;

	packet_init(pool, pkt_hdr, len);
	return 0;
}

odp_packet_t odp_packet_from_event(odp_event_t ev)
{
	return (odp_packet_t)ev;
}

odp_event_t odp_packet_to_event(odp_packet_t pkt)
{
	return (odp_event_t)pkt;
}

/*
 *
 * Pointers and lengths
 * ********************************************************
 *
 */

void *odp_packet_head(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return buffer_map(&pkt_hdr->buf_hdr, 0, NULL, 0);
}

uint32_t odp_packet_buf_len(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.size;
}

void *odp_packet_data(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return packet_map(pkt_hdr, 0, NULL);
}

uint32_t odp_packet_seg_len(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t seglen;

	/* Call returns length of 1st data segment */
	packet_map(pkt_hdr, 0, &seglen);
	return seglen;
}

uint32_t odp_packet_len(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->frame_len;
}

uint32_t odp_packet_headroom(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->headroom;
}

uint32_t odp_packet_tailroom(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->tailroom;
}

void *odp_packet_tail(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return packet_map(pkt_hdr, pkt_hdr->frame_len, NULL);
}

void *odp_packet_push_head(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (len > pkt_hdr->headroom)
		return NULL;

	push_head(pkt_hdr, len);
	return packet_map(pkt_hdr, 0, NULL);
}

void *odp_packet_pull_head(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (len > pkt_hdr->frame_len)
		return NULL;

	pull_head(pkt_hdr, len);
	return packet_map(pkt_hdr, 0, NULL);
}

void *odp_packet_push_tail(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t origin = pkt_hdr->frame_len;

	if (len > pkt_hdr->tailroom)
		return NULL;

	push_tail(pkt_hdr, len);
	return packet_map(pkt_hdr, origin, NULL);
}

void *odp_packet_pull_tail(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (len > pkt_hdr->frame_len)
		return NULL;

	pull_tail(pkt_hdr, len);
	return packet_map(pkt_hdr, pkt_hdr->frame_len, NULL);
}

void *odp_packet_offset(odp_packet_t pkt, uint32_t offset, uint32_t *len,
			odp_packet_seg_t *seg)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	void *addr = packet_map(pkt_hdr, offset, len);

	if (addr != NULL && seg != NULL) {
		odp_buffer_bits_t seghandle;
		seghandle.handle = (odp_buffer_t)pkt;
		seghandle.seg = (pkt_hdr->headroom + offset) /
			pkt_hdr->buf_hdr.segsize;
		*seg = (odp_packet_seg_t)seghandle.handle;
	}

	return addr;
}

/*
 *
 * Meta-data
 * ********************************************************
 *
 */

odp_pool_t odp_packet_pool(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.pool_hdl;
}

odp_pktio_t odp_packet_input(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->input;
}

void *odp_packet_user_ptr(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.buf_ctx;
}

void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ctx)
{
	odp_packet_hdr(pkt)->buf_hdr.buf_cctx = ctx;
}

void *odp_packet_user_area(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.uarea_addr;
}

uint32_t odp_packet_user_area_size(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.uarea_size;
}

void *odp_packet_l2_ptr(odp_packet_t pkt, uint32_t *len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return packet_map(pkt_hdr, pkt_hdr->l2_offset, len);
}

uint32_t odp_packet_l2_offset(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->l2_offset;
}

int odp_packet_l2_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	fm_prs_result_t		*pa;

	if (offset >= pkt_hdr->frame_len)
		return -1;

	pkt_hdr->l2_offset = offset;

	/* Set offset in the Parse Array */
	pa = (fm_prs_result_t *)(odp_buffer_addr(_odp_packet_to_buffer(pkt)) +
			DEFAULT_ICEOF);
	pa->eth_off = offset;

	return 0;
}

void *odp_packet_l3_ptr(odp_packet_t pkt, uint32_t *len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return packet_map(pkt_hdr, pkt_hdr->l3_offset, len);
}

uint32_t odp_packet_l3_offset(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->l3_offset;
}

int odp_packet_l3_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	fm_prs_result_t		*pa;

	if (offset >= pkt_hdr->frame_len)
		return -1;

	pkt_hdr->l3_offset = offset;

	/* Set offset in the Parse Array */
	pa = (fm_prs_result_t *)(odp_buffer_addr(_odp_packet_to_buffer(pkt)) +
			DEFAULT_ICEOF);
	pa->ip_off[0] = offset;

	return 0;
}

void *odp_packet_l4_ptr(odp_packet_t pkt, uint32_t *len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return packet_map(pkt_hdr, pkt_hdr->l4_offset, len);
}

uint32_t odp_packet_l4_offset(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->l4_offset;
}

int odp_packet_l4_offset_set(odp_packet_t pkt, uint32_t offset)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	fm_prs_result_t		*pa;

	if (offset >= pkt_hdr->frame_len)
		return -1;

	pkt_hdr->l4_offset = offset;

	/* Set offset in the Parse Array */
	pa = (fm_prs_result_t *)(odp_buffer_addr(_odp_packet_to_buffer(pkt)) +
			DEFAULT_ICEOF);
	pa->l4_off = offset;

	return 0;
}

int odp_packet_is_segmented(odp_packet_t pkt)
{
	return odp_packet_hdr(pkt)->buf_hdr.segcount > 1;
}

int odp_packet_num_segs(odp_packet_t pkt)
{
	/* if segcount includes also the sg table buffer, decrement it by 1 */
	return  (odp_packet_hdr(pkt)->buf_hdr.segcount > 1) ?
		 (odp_packet_hdr(pkt)->buf_hdr.segcount - 1) : 1;
}

odp_packet_seg_t odp_packet_first_seg(odp_packet_t pkt)
{
	return (odp_packet_seg_t)pkt;
}

odp_packet_seg_t odp_packet_last_seg(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	odp_buffer_bits_t seghandle;

	seghandle.handle = (odp_buffer_t)pkt;
	seghandle.seg = pkt_hdr->buf_hdr.segcount - 1;
	return (odp_packet_seg_t)seghandle.handle;
}

odp_packet_seg_t odp_packet_next_seg(odp_packet_t pkt, odp_packet_seg_t seg)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return (odp_packet_seg_t)segment_next(&pkt_hdr->buf_hdr,
					      (odp_buffer_seg_t)seg);
}

/*
 *
 * Segment level
 * ********************************************************
 *
 */
void *odp_packet_seg_data(odp_packet_t pkt, odp_packet_seg_t seg)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	return segment_map(&pkt_hdr->buf_hdr, (odp_buffer_seg_t)seg, NULL,
			   pkt_hdr->frame_len, pkt_hdr->headroom);
}

uint32_t odp_packet_seg_data_len(odp_packet_t pkt, odp_packet_seg_t seg)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t seglen = 0;

	segment_map(&pkt_hdr->buf_hdr, (odp_buffer_seg_t)seg, &seglen,
		    pkt_hdr->frame_len, pkt_hdr->headroom);

	return seglen;
}

/*
 *
 * Manipulation
 * ********************************************************
 *
 */

int odp_packet_add_data(odp_packet_t *pkt_ptr, uint32_t offset,
				 uint32_t len)
{
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t pktlen = pkt_hdr->frame_len;
	odp_packet_t newpkt;
	int ret = -1;

	if (offset > pktlen)
		return ret;

	newpkt = odp_packet_alloc(pkt_hdr->buf_hdr.pool_hdl, pktlen + len);

	if (newpkt != ODP_PACKET_INVALID) {
		if (_odp_packet_copy_to_packet(pkt, 0,
					       newpkt, 0, offset) != 0 ||
		    _odp_packet_copy_to_packet(pkt, offset, newpkt,
					       offset + len,
					       pktlen - offset) != 0) {
			odp_packet_free(newpkt);
			newpkt = ODP_PACKET_INVALID;
		} else {
			odp_packet_hdr_t *new_hdr = odp_packet_hdr(newpkt);
			new_hdr->input = pkt_hdr->input;
			new_hdr->buf_hdr.buf_u64 = pkt_hdr->buf_hdr.buf_u64;
			if (new_hdr->buf_hdr.uarea_addr != NULL &&
			    pkt_hdr->buf_hdr.uarea_addr != NULL)
				memcpy(new_hdr->buf_hdr.uarea_addr,
				       pkt_hdr->buf_hdr.uarea_addr,
				       new_hdr->buf_hdr.uarea_size <=
				       pkt_hdr->buf_hdr.uarea_size ?
				       new_hdr->buf_hdr.uarea_size :
				       pkt_hdr->buf_hdr.uarea_size);
			odp_atomic_store_u32(
				&new_hdr->buf_hdr.ref_count,
				odp_atomic_load_u32(
					&pkt_hdr->buf_hdr.ref_count));
			copy_packet_parser_metadata(pkt_hdr, new_hdr);
			odp_packet_free(pkt);
			*pkt_ptr = newpkt;
			ret = 1;
		}
	}

	return ret;
}

int odp_packet_rem_data(odp_packet_t *pkt_ptr, uint32_t offset,
				 uint32_t len)
{
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t pktlen = pkt_hdr->frame_len;
	odp_packet_t newpkt;
	int ret = -1;

	if (offset > pktlen || offset + len > pktlen)
		return ret;

	newpkt = odp_packet_alloc(pkt_hdr->buf_hdr.pool_hdl, pktlen - len);

	if (newpkt != ODP_PACKET_INVALID) {
		if (_odp_packet_copy_to_packet(pkt, 0,
					       newpkt, 0, offset) != 0 ||
		    _odp_packet_copy_to_packet(pkt, offset + len,
					       newpkt, offset,
					       pktlen - offset - len) != 0) {
			odp_packet_free(newpkt);
			newpkt = ODP_PACKET_INVALID;
		} else {
			odp_packet_hdr_t *new_hdr = odp_packet_hdr(newpkt);
			new_hdr->input = pkt_hdr->input;
			new_hdr->buf_hdr.buf_u64 = pkt_hdr->buf_hdr.buf_u64;
			if (new_hdr->buf_hdr.uarea_addr != NULL &&
			    pkt_hdr->buf_hdr.uarea_addr != NULL)
				memcpy(new_hdr->buf_hdr.uarea_addr,
				       pkt_hdr->buf_hdr.uarea_addr,
				       new_hdr->buf_hdr.uarea_size <=
				       pkt_hdr->buf_hdr.uarea_size ?
				       new_hdr->buf_hdr.uarea_size :
				       pkt_hdr->buf_hdr.uarea_size);
			odp_atomic_store_u32(
				&new_hdr->buf_hdr.ref_count,
				odp_atomic_load_u32(
					&pkt_hdr->buf_hdr.ref_count));
			copy_packet_parser_metadata(pkt_hdr, new_hdr);
			odp_packet_free(pkt);
			*pkt_ptr = newpkt;
			ret = 1;
		}
	}

	return ret;
}

/*
 *
 * Copy
 * ********************************************************
 *
 */

odp_packet_t odp_packet_copy(odp_packet_t pkt, odp_pool_t pool)
{
	odp_packet_hdr_t *srchdr = odp_packet_hdr(pkt);
	uint32_t pktlen = srchdr->frame_len;
	odp_packet_t newpkt = odp_packet_alloc(pool, pktlen);

	if (newpkt != ODP_PACKET_INVALID) {
		odp_packet_hdr_t *newhdr = odp_packet_hdr(newpkt);
		uint8_t *newstart, *srcstart;

		/* Must copy metadata first, followed by packet data */
		newstart = (uint8_t *)newhdr->buf_hdr.addr[0] + DEFAULT_ICEOF;
		srcstart = (uint8_t *)srchdr->buf_hdr.addr[0] + DEFAULT_ICEOF;

		memcpy(newstart, srcstart, sizeof(fm_prs_result_t));
		newhdr->jumbo = srchdr->jumbo;
		newhdr->headroom = srchdr->headroom;
		newhdr->tailroom = srchdr->tailroom;
		newhdr->l2_offset = srchdr->l2_offset;
		newhdr->l3_offset = srchdr->l3_offset;
		newhdr->l4_offset = srchdr->l4_offset;
		newhdr->input = srchdr->input;

		if (_odp_packet_copy_to_packet(pkt, 0,
					       newpkt, 0, pktlen) != 0) {
			odp_packet_free(newpkt);
			newpkt = ODP_PACKET_INVALID;
		}
	}

	return newpkt;
}

int odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
			    uint32_t len, void *dst)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */
	uint8_t *dstaddr = (uint8_t *)dst;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (offset + len > pkt_hdr->frame_len)
		return -1;

	mapaddr = packet_map(pkt_hdr, offset, &seglen);
	memcpy(dstaddr, mapaddr, len);

	return 0;
}

int odp_packet_copy_from_mem(odp_packet_t pkt, uint32_t offset,
			   uint32_t len, const void *src)
{
	void *mapaddr;
	uint32_t seglen = 0; /* GCC */

	const uint8_t *srcaddr = (const uint8_t *)src;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	if (offset + len > pkt_hdr->frame_len)
		return -1;

	mapaddr = packet_map(pkt_hdr, offset, &seglen);
	memcpy(mapaddr, srcaddr, len);

	return 0;
}

/*
 *
 * Debugging
 * ********************************************************
 *
 */

void odp_packet_print(odp_packet_t pkt)
{
	int max_len = 512;
	char str[max_len];
	int len = 0;
	int n = max_len-1;
	odp_packet_hdr_t *hdr = odp_packet_hdr(pkt);

	len += snprintf(&str[len], n-len, "Packet ");
	len += odp_buffer_snprint(&str[len], n-len, (odp_buffer_t) pkt);
	len += snprintf(&str[len], n-len,
			"  l2_offset	%u\n", hdr->l2_offset);
	len += snprintf(&str[len], n-len,
			"  l3_offset	%u\n", hdr->l3_offset);
	len += snprintf(&str[len], n-len,
			"  l4_offset	%u\n", hdr->l4_offset);
	len += snprintf(&str[len], n-len,
			"  frame_len	%u\n", hdr->frame_len);
	len += snprintf(&str[len], n-len,
			"  input        %" PRIu64 "\n",
			odp_pktio_to_u64(hdr->input));
	str[len] = '\0';

	ODP_PRINT("\n%s\n", str);
}

int odp_packet_is_valid(odp_packet_t pkt)
{
	odp_buffer_hdr_t *buf = validate_buf((odp_buffer_t)pkt);

	return (buf != NULL && buf->type == ODP_EVENT_PACKET);
}

/*
 *
 * Internal Use Routines
 * ********************************************************
 *
 */
void _odp_packet_copy_md_to_packet(odp_packet_t srcpkt, odp_packet_t dstpkt)
{
	odp_packet_hdr_t *srchdr = odp_packet_hdr(srcpkt);
	odp_packet_hdr_t *dsthdr = odp_packet_hdr(dstpkt);

	dsthdr->input = srchdr->input;
	dsthdr->buf_hdr.buf_u64 = srchdr->buf_hdr.buf_u64;
	if (dsthdr->buf_hdr.uarea_addr != NULL &&
	    srchdr->buf_hdr.uarea_addr != NULL)
		memcpy(dsthdr->buf_hdr.uarea_addr,
		       srchdr->buf_hdr.uarea_addr,
		       dsthdr->buf_hdr.uarea_size <=
		       srchdr->buf_hdr.uarea_size ?
		       dsthdr->buf_hdr.uarea_size :
		       srchdr->buf_hdr.uarea_size);
	odp_atomic_store_u32(
		&dsthdr->buf_hdr.ref_count,
		odp_atomic_load_u32(
			&srchdr->buf_hdr.ref_count));
	copy_packet_parser_metadata(srchdr, dsthdr);
}

int _odp_packet_copy_to_packet(odp_packet_t srcpkt, uint32_t srcoffset,
			       odp_packet_t dstpkt, uint32_t dstoffset,
			       uint32_t len)
{
	odp_packet_hdr_t *srchdr = odp_packet_hdr(srcpkt);
	odp_packet_hdr_t *dsthdr = odp_packet_hdr(dstpkt);
	void *srcmap;
	void *dstmap;
	uint32_t cpylen, minseg;
	uint32_t srcseglen = 0; /* GCC */
	uint32_t dstseglen = 0; /* GCC */

	if (srcoffset + len > srchdr->frame_len ||
	    dstoffset + len > dsthdr->frame_len)
		return -1;

	while (len > 0) {
		srcmap = packet_map(srchdr, srcoffset, &srcseglen);
		dstmap = packet_map(dsthdr, dstoffset, &dstseglen);

		minseg = dstseglen > srcseglen ? srcseglen : dstseglen;
		cpylen = len > minseg ? minseg : len;
		memcpy(dstmap, srcmap, cpylen);

		srcoffset += cpylen;
		dstoffset += cpylen;
		len	  -= cpylen;
	}

	return 0;
}

odp_packet_t _odp_packet_alloc(odp_pool_t pool_hdl)
{
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);

	if (pool->s.params.type != ODP_POOL_PACKET)
		return ODP_PACKET_INVALID;

	return (odp_packet_t)buffer_alloc(pool_hdl,
					  pool->s.params.buf.size);
}

int odp_packet_alloc_multi(odp_pool_t pool_hdl ODP_UNUSED, uint32_t len ODP_UNUSED,
				   odp_packet_t pkt[] ODP_UNUSED, int num ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

void odp_packet_free_multi(const odp_packet_t pkt[] ODP_UNUSED, int num ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
}

int odp_packet_input_index(odp_packet_t pkt ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}

void odp_packet_ts_set(odp_packet_t pkt ODP_UNUSED, odp_time_t timestamp ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
}

odp_time_t odp_packet_ts(odp_packet_t pkt ODP_UNUSED)
{
	odp_time_t ts = {0};
	ODP_UNIMPLEMENTED();
	return ts;
}

void odp_packet_prefetch(odp_packet_t pkt ODP_UNUSED,
								   uint32_t offset ODP_UNUSED,
								   uint32_t len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
}

int odp_packet_extend_head(odp_packet_t *pkt ODP_UNUSED, uint32_t len ODP_UNUSED,
			   void **data_ptr ODP_UNUSED, uint32_t *seg_len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}

int odp_packet_trunc_head(odp_packet_t *pkt ODP_UNUSED, uint32_t len ODP_UNUSED,
			  void **data_ptr ODP_UNUSED, uint32_t *seg_len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}

int odp_packet_extend_tail(odp_packet_t *pkt ODP_UNUSED, uint32_t len ODP_UNUSED,
			   void **data_ptr ODP_UNUSED, uint32_t *seg_len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}
int odp_packet_trunc_tail(odp_packet_t *pkt ODP_UNUSED, uint32_t len ODP_UNUSED,
			  void **tail_ptr ODP_UNUSED, uint32_t *tailroom ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}

int odp_packet_copy_from_pkt(odp_packet_t dst ODP_UNUSED, uint32_t dst_offset ODP_UNUSED,
			     odp_packet_t src ODP_UNUSED, uint32_t src_offset ODP_UNUSED,
			     uint32_t len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}

int odp_packet_concat(odp_packet_t *dst ODP_UNUSED, odp_packet_t src ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}

int odp_packet_split(odp_packet_t *pkt ODP_UNUSED, uint32_t len ODP_UNUSED,
							odp_packet_t *tail ODP_UNUSED)
{
	*tail = ODP_PACKET_INVALID;
	ODP_UNIMPLEMENTED();
	return -1;
}

odp_packet_t odp_packet_copy_part(odp_packet_t pkt ODP_UNUSED, uint32_t offset ODP_UNUSED,
				  uint32_t len ODP_UNUSED, odp_pool_t pool ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return ODP_PACKET_INVALID;
}

int odp_packet_align(odp_packet_t *pkt ODP_UNUSED, uint32_t offset ODP_UNUSED,
							uint32_t len ODP_UNUSED, uint32_t align ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}

int odp_packet_move_data(odp_packet_t pkt ODP_UNUSED, uint32_t dst_offset ODP_UNUSED,
			 uint32_t src_offset ODP_UNUSED, uint32_t len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}

int odp_packet_copy_data(odp_packet_t pkt ODP_UNUSED, uint32_t dst_offset ODP_UNUSED,
			 uint32_t src_offset ODP_UNUSED, uint32_t len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}
