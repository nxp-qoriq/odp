/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/packet.h>
#include <odp_packet_internal.h>
#include <odp_pool_internal.h>
#include <odp_debug_internal.h>
#include <odp/api/hints.h>
#include <odp/api/byteorder.h>

#include <odp_queue_internal.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/tcp.h>
#include <odp/helper/udp.h>

#include <string.h>
#include <stdio.h>
#include <dpaa2_mbuf_priv_ldpaa.h>
#include <dpaa2_mbuf_priv.h>
#include <dpaa2_vq.h>
#include <dpaa2_eth_ldpaa_annot.h>
/*
 *
 * Alloc and free
 * ********************************************************
 *
 */

odp_packet_t odp_packet_alloc(odp_pool_t pool_hdl, uint32_t len)
{
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);
	struct dpaa2_mbuf *first_seg = NULL, *next_seg = NULL, *cur_seg = NULL;
	int32_t length = len;
	int32_t buf_size, tot_buf_size;
	uint32_t is_first_seg = true;
	uint32_t seg_required = false;
	uint64_t hw_annot = 0;

	if (!pool || (pool->s.params.type != ODP_POOL_PACKET)) {
		ODP_ERR("\nInvalid packet pool handle\n", length);
		return ODP_PACKET_INVALID;
	}

	tot_buf_size = bpid_info[pool->s.bpid].size;
	buf_size = tot_buf_size - (DPAA2_MBUF_SW_ANNOTATION +
				DPAA2_MBUF_HW_ANNOTATION);
						/*+ Tailroom*/

	first_seg = dpaa2_mbuf_alloc_from_bpid(pool->s.bpid);
	if (!first_seg) {
		ODP_ERR("Error in mbuf alloc for len =%d\n", len);
		return ODP_PACKET_INVALID;
	}
	length = len + dpaa2_mbuf_head_room;
	if (length > buf_size) {
		first_seg->frame_len = buf_size;
		first_seg->tot_frame_len = buf_size;
		first_seg->data = first_seg->head;
		seg_required = true;
	} else {
		first_seg->frame_len = len;
		first_seg->tot_frame_len = len;
	}
	next_seg = first_seg;
	while (seg_required && length > 0) {
		cur_seg = dpaa2_mbuf_alloc_from_bpid(pool->s.bpid);
		if (!cur_seg) {
			ODP_ERR("Segmented alloc failure for len =%d\n", len);
			goto buffer_cleanup;
		}
		if (is_first_seg) {
			hw_annot = (uint64_t)first_seg->hw_annot;
			first_seg = cur_seg;
			first_seg->tot_frame_len = 0;
			is_first_seg = false;
		}
		cur_seg->head = cur_seg->head - cur_seg->priv_meta_off;
		cur_seg->data = cur_seg->head;
		length = length - tot_buf_size;
		cur_seg->frame_len = tot_buf_size;
		next_seg->next_sg = cur_seg;
		next_seg = cur_seg;
		first_seg->tot_frame_len += tot_buf_size;
	}

	if (seg_required && first_seg) {
		cur_seg->frame_len = length + tot_buf_size;
		first_seg->tot_frame_len -= (tot_buf_size - cur_seg->frame_len);
		first_seg->tot_frame_len -= dpaa2_mbuf_head_room;
		first_seg->data = first_seg->head + dpaa2_mbuf_head_room;
		first_seg->frame_len -= dpaa2_mbuf_head_room;
		first_seg->hw_annot = hw_annot;
		BIT_SET_AT_POS(first_seg->eth_flags, DPAA2BUF_IS_SEGMENTED);
	}

	return (odp_packet_t)first_seg;

buffer_cleanup:
	first_seg->hw_annot = hw_annot;
	dpaa2_mbuf_free(first_seg);
	return ODP_PACKET_INVALID;
}

void odp_packet_free(odp_packet_t pkt)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	dpaa2_mbuf_free((dpaa2_mbuf_pt)pkt_hdr);
}

int odp_packet_reset(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);
	struct dpaa2_mbuf *mbuf = (dpaa2_mbuf_pt)pkt_hdr;

	/*Validate that length does not exeed from buffer length*/
	if (len > (odp_packet_buf_len(pkt) - odp_packet_headroom(pkt)))
		return -1;

	dpaa2_mbuf_reset(mbuf, len);
	mbuf->tot_frame_len = len;
	if (!mbuf->next_sg)
		mbuf->frame_len = mbuf->tot_frame_len;
	_odp_buffer_type_set(mbuf, ODP_EVENT_PACKET);
	return 0;
}

odp_packet_t _odp_packet_from_buffer(odp_buffer_t buf)
{
	return (odp_packet_t)buf;
}

odp_buffer_t _odp_packet_to_buffer(odp_packet_t pkt)
{
	return (odp_buffer_t)pkt;
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
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)odp_packet_hdr(pkt);
	return pkt_hdr->head;
}

uint32_t odp_packet_buf_len(odp_packet_t pkt)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)odp_packet_hdr(pkt);

	return pkt_hdr->tot_frame_len
			+ dpaa2_mbuf_headroom((dpaa2_mbuf_pt)pkt_hdr)
			+ dpaa2_mbuf_tailroom((dpaa2_mbuf_pt)pkt_hdr);
}

uint32_t odp_packet_seg_len(odp_packet_t pkt)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)odp_packet_hdr(pkt);

	return pkt_hdr->frame_len;
}

uint32_t odp_packet_headroom(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return dpaa2_mbuf_headroom((dpaa2_mbuf_pt)pkt_hdr);
}

uint32_t odp_packet_tailroom(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return dpaa2_mbuf_tailroom((struct dpaa2_mbuf *)pkt_hdr);
}

void *odp_packet_tail(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return dpaa2_mbuf_tail((struct dpaa2_mbuf *)pkt_hdr);
}

void *odp_packet_push_head(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return dpaa2_mbuf_push((struct dpaa2_mbuf *)pkt_hdr, len);
}

void *odp_packet_pull_head(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return dpaa2_mbuf_pull((struct dpaa2_mbuf *)pkt_hdr, len);
}

void *odp_packet_push_tail(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return dpaa2_mbuf_push_tail((struct dpaa2_mbuf *)pkt_hdr, len, FALSE);
}

void *odp_packet_pull_tail(odp_packet_t pkt, uint32_t len)
{
	dpaa2_mbuf_pt pkt_hdr = (dpaa2_mbuf_pt)odp_packet_hdr(pkt);
	dpaa2_mbuf_pt last_seg = dpaa2_mbuf_lastseg((dpaa2_mbuf_pt)pkt_hdr);

	DPAA2_TRACE(BUF);
	if (last_seg->frame_len >= (int32_t)len) {
		last_seg->frame_len -= len;
		pkt_hdr->tot_frame_len -= len;
	} else {
		return NULL;
	}

	return last_seg->data + last_seg->frame_len;
}

void *odp_packet_offset(odp_packet_t pkt, uint32_t offset, uint32_t *len,
			odp_packet_seg_t *seg)
{
	dpaa2_mbuf_pt pkt_hdr = (dpaa2_mbuf_pt)odp_packet_hdr(pkt);
	odp_packet_seg_t cur_seg;

	DPAA2_TRACE(BUF);

	/* offset is more than the total frame length */
	if (pkt_hdr->tot_frame_len < offset)
		return NULL;

	cur_seg = odp_packet_first_seg(pkt);
	while (cur_seg) {
		if (cur_seg->frame_len >= offset)
			break;

		offset -= cur_seg->frame_len;
		cur_seg = odp_packet_next_seg(pkt, cur_seg);
	}

	if (seg)
		*seg = cur_seg;
	if (len)
		*len = cur_seg->frame_len - offset;

	return cur_seg->data + offset;
}

/*
 *
 * Meta-data
 * ********************************************************
 *
 */

odp_pool_t odp_packet_pool(odp_packet_t pkt)
{
	odp_buffer_t buf = _odp_packet_to_buffer(pkt);

	return (odp_pool_t)odp_buf_to_pool(buf);
}

odp_pktio_t odp_packet_input(odp_packet_t pkt)
{
	struct dpaa2_mbuf *mbuf = (struct dpaa2_mbuf *)pkt;
	struct dpaa2_vq *vq = (struct dpaa2_vq *)mbuf->vq;

	if (vq) {
		return (odp_pktio_t)vq->dev->pktio;
	} else {
		ODP_ERR("Device pointer is NULL\n");
		return ODP_PKTIO_INVALID;
	}
}

void *odp_packet_user_ptr(odp_packet_t pkt)
{
	struct dpaa2_mbuf *mbuf;

	mbuf = odp_dpaa2_mbuf_hdr(pkt);
	return (void *)mbuf->user_cnxt_ptr;
}

void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ctx)
{
	odp_dpaa2_mbuf_hdr(pkt)->user_cnxt_ptr = (uint64_t)ctx;
}

void *odp_packet_user_area(odp_packet_t pkt)
{
	return (void *)odp_dpaa2_mbuf_hdr(pkt) + sizeof(odp_packet_hdr_t);
}

uint32_t odp_packet_user_area_size(odp_packet_t pkt)
{
	return bpid_info[odp_dpaa2_mbuf_hdr(pkt)->bpid].odp_user_area;
}

void odp_packet_user_u64_set(odp_packet_t pkt, uint64_t ctx)
{
	odp_dpaa2_mbuf_hdr(pkt)->user_cnxt_ptr = ctx;
}


int odp_packet_is_segmented(odp_packet_t pkt)
{
	dpaa2_mbuf_pt mbuf = (dpaa2_mbuf_pt)pkt;

	return ((mbuf->tot_frame_len > mbuf->frame_len) ? TRUE : FALSE);
}

int odp_packet_num_segs(odp_packet_t pkt)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)odp_packet_hdr(pkt);
	int i = 1;
	while(pkt_hdr->next_sg) {
		i++;
		pkt_hdr = pkt_hdr->next_sg;
	}
	return i;
}

odp_packet_seg_t odp_packet_first_seg(odp_packet_t pkt)
{
	return (odp_packet_seg_t)pkt;
}

odp_packet_seg_t odp_packet_last_seg(odp_packet_t pkt)
{
	return dpaa2_mbuf_lastseg(pkt);
}

odp_packet_seg_t odp_packet_next_seg(odp_packet_t pkt ODP_UNUSED, odp_packet_seg_t seg)
{
	return seg->next_sg ? (odp_packet_seg_t)seg->next_sg : ODP_PACKET_SEG_INVALID;
}

/*
 *
 * Segment level
 * ********************************************************
 *
 */

void *odp_packet_seg_data(odp_packet_t pkt ODP_UNUSED, odp_packet_seg_t seg)
{
	if (seg == ODP_SEGMENT_INVALID)
		return NULL;

	return seg->data;
}

uint32_t odp_packet_seg_data_len(odp_packet_t pkt ODP_UNUSED, odp_packet_seg_t seg)
{
	if (seg == ODP_SEGMENT_INVALID)
		return -1;

	return seg->frame_len;
}

/*
 *
 * Manipulation
 * ********************************************************
 *
 */

int odp_packet_add_data(odp_packet_t *pkt_ptr ODP_UNUSED, uint32_t offset ODP_UNUSED,
				 uint32_t len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 1;
#if 0
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t pktlen = pkt_hdr->frame_len;
	odp_packet_t newpkt;

	if (offset > pktlen)
		return ODP_PACKET_INVALID;

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
			odp_atomic_store_u32(
				&new_hdr->buf_hdr.ref_count,
				odp_atomic_load_u32(
					&pkt_hdr->buf_hdr.ref_count));
			copy_packet_parser_metadata(pkt_hdr, new_hdr);
			odp_packet_free(pkt);
		}
	}
	return newpkt;
#endif
}

int odp_packet_rem_data(odp_packet_t *pkt_ptr ODP_UNUSED, uint32_t offset ODP_UNUSED,
				 uint32_t len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 1;
#if 0
	odp_packet_t pkt = *pkt_ptr;
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t pktlen = pkt_hdr->frame_len;
	odp_packet_t newpkt;

	if (offset > pktlen || offset + len > pktlen)
		return ODP_PACKET_INVALID;

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
			odp_atomic_store_u32(
				&new_hdr->buf_hdr.ref_count,
				odp_atomic_load_u32(
					&pkt_hdr->buf_hdr.ref_count));
			copy_packet_parser_metadata(pkt_hdr, new_hdr);
			odp_packet_free(pkt);
		}
	}

	return newpkt;
#endif
}

/*
 *
 * Copy
 * ********************************************************
 *
 */

odp_packet_t odp_packet_copy(odp_packet_t pkt, odp_pool_t pool)
{
	struct dpaa2_mbuf *srchdr, *dsthdr;
	odp_packet_t newpkt;
	pool_entry_t *pool_entry = odp_pool_to_entry(pool);

	if (!pool_type_is_packet(pool)) {
		DPAA2_ERR(BUF, "\nPool is not packet pool\n");
		return ODP_PACKET_INVALID;
	}

	srchdr = (struct dpaa2_mbuf *)odp_packet_hdr(pkt);
	/*Allocate a new packet*/
	newpkt = odp_packet_alloc(pool, srchdr->tot_frame_len);
	if (newpkt == ODP_PACKET_INVALID) {
		DPAA2_ERR(BUF, "\nPacket allocation failure\n");
		return ODP_PACKET_INVALID;
	}

	dsthdr = (struct dpaa2_mbuf *)odp_packet_hdr(newpkt);

	if (dpaa2_mbuf_copy(dsthdr, srchdr)) {
		DPAA2_ERR(BUF, "\nPacket copy failure\n");
		return ODP_PACKET_INVALID;
	}
	dsthdr->bpid = pool_entry->s.bpid;
	return newpkt;
}

int odp_packet_copy_to_mem(odp_packet_t pkt, uint32_t offset,
			    uint32_t len, void *dst)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)odp_packet_hdr(pkt);

	if (offset + len > pkt_hdr->tot_frame_len)
		return -1;

	if (dpaa2_mbuf_data_copy_out(pkt_hdr, dst, offset, len))
		return -1;
	return 0;
}

int odp_packet_copy_from_mem(odp_packet_t pkt, uint32_t offset,
			   uint32_t len, const void *src)
{
	struct dpaa2_mbuf *pkt_hdr = (struct dpaa2_mbuf *)odp_packet_hdr(pkt);
	if (offset + len > pkt_hdr->tot_frame_len)
		return -1;

	if (dpaa2_mbuf_data_copy_in(pkt_hdr, src, offset, len))
		return -1;
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
	odp_packet_hdr_t *hdr = odp_packet_hdr(pkt);
	dpaa2_mbuf_dump_pkt(stdout, (struct dpaa2_mbuf *)hdr);
	//todo print rest of packet headers
}

int odp_packet_is_valid(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr;
	if (pkt == ODP_PACKET_INVALID)
		return 0;
	pkt_hdr = odp_packet_hdr(pkt);
	return ((pkt_hdr) && dpaa2_mbuf_is_valid((struct dpaa2_mbuf *)pkt_hdr));
}

/*
 *
 * ODP Extensions
 * ********************************************************
 *
 */

uint16_t odpfsl_packet_pool_internal_id(odp_pool_t pkt_pool)
{
	pool_entry_t *pool = (pool_entry_t *)pkt_pool;

	return pool->s.bpid;
}

odp_packet_t odpfsl_packet_from_addr(odp_pool_t pkt_pool, void *addr)
{
	pool_entry_t *pool;
	struct dpaa2_bp_list *bp_list;
	void *h_pool_mem = NULL;
	uint8_t *aligned_addr;
	uint8_t *pool_end_addr;
	uint32_t aligned_buffer;
	struct dpaa2_mbuf *mbuf;

	if (pkt_pool == ODP_POOL_INVALID || !addr)
		return ODP_PACKET_INVALID;

	pool = (pool_entry_t *)pkt_pool;

	/* Extracting pool start address from Packet pool handle */
	bp_list = (struct dpaa2_bp_list *)(pool->s.int_hdl);
	h_pool_mem = bp_list->buf_pool[0].h_bpool_mem;

	/* Validating that addr is within h_pool_mem and end of pool address */
	pool_end_addr = (uint8_t *)h_pool_mem + \
					(bp_list->buf_pool[0].buf_size * \
					bp_list->buf_pool[0].num_bufs);
	if (addr <= h_pool_mem || addr > (void *)pool_end_addr)
		return ODP_PACKET_INVALID;

	aligned_buffer = (uint32_t)((uint32_t)(addr - h_pool_mem) / \
				bp_list->buf_pool[0].buf_size);
	aligned_addr = (uint8_t *)h_pool_mem + (aligned_buffer * \
					bp_list->buf_pool[0].buf_size);
	mbuf = (struct dpaa2_mbuf *)aligned_addr;
	mbuf->head = (uint8_t *)aligned_addr +
			bp_list->buf_pool[0].meta_data_size +
			dpaa2_mbuf_sw_annotation + DPAA2_MBUF_HW_ANNOTATION;
	mbuf->hw_annot = (uint64_t)(mbuf->head - DPAA2_MBUF_HW_ANNOTATION);
	mbuf->next_sg = NULL;

	return (odp_packet_t)aligned_addr;
}

int odp_packet_alloc_multi(odp_pool_t pool_hdl, uint32_t len,
			odp_packet_t pkt[], int num)
{
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);
	int count;

	if (!pool || pool->s.params.type != ODP_POOL_PACKET) {
		__odp_errno = EINVAL;
		return -1;
	}

	for (count = 0; count < num; ++count) {
		pkt[count] = odp_packet_alloc(pool_hdl, len);
		if(pkt[count] == ODP_PACKET_INVALID)
			break;
	}

	return count;
}

void odp_packet_free_multi(const odp_packet_t pkt[], int num)
{
	int count;

	for (count = 0; count < num; ++count) {
		odp_packet_free(pkt[count]);
	}
}

int odp_packet_input_index(odp_packet_t pkt)
{
	return odp_pktio_index(odp_packet_input(pkt));
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
}

int odp_packet_extend_head(odp_packet_t *pkt ODP_UNUSED, uint32_t len ODP_UNUSED,
			   void **data_ptr ODP_UNUSED, uint32_t *seg_len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_packet_trunc_head(odp_packet_t *pkt ODP_UNUSED, uint32_t len ODP_UNUSED,
			  void **data_ptr ODP_UNUSED, uint32_t *seg_len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_packet_extend_tail(odp_packet_t *pkt ODP_UNUSED, uint32_t len ODP_UNUSED,
			   void **data_ptr ODP_UNUSED, uint32_t *seg_len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}
int odp_packet_trunc_tail(odp_packet_t *pkt ODP_UNUSED, uint32_t len ODP_UNUSED,
			  void **tail_ptr ODP_UNUSED, uint32_t *tailroom ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_packet_copy_from_pkt(odp_packet_t dst ODP_UNUSED, uint32_t dst_offset ODP_UNUSED,
			     odp_packet_t src ODP_UNUSED, uint32_t src_offset ODP_UNUSED,
			     uint32_t len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_packet_concat(odp_packet_t *dst ODP_UNUSED, odp_packet_t src ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_packet_split(odp_packet_t *pkt ODP_UNUSED, uint32_t len ODP_UNUSED,
							odp_packet_t *tail ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
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
	return 0;
}

int odp_packet_move_data(odp_packet_t pkt ODP_UNUSED, uint32_t dst_offset ODP_UNUSED,
			 uint32_t src_offset ODP_UNUSED, uint32_t len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_packet_copy_data(odp_packet_t pkt ODP_UNUSED, uint32_t dst_offset ODP_UNUSED,
			 uint32_t src_offset ODP_UNUSED, uint32_t len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}
