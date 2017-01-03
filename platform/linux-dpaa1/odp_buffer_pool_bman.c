/*
 * Copyright (c) 2015 - 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */


#include <odp/api/std_types.h>
#include <odp/api/pool.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_queue_internal.h>
#include <odp_schedule_internal.h>
#include <odp_buffer_inlines.h>
#include <odp_packet_internal.h>
#include <odp_timer_internal.h>
#include <odp_align_internal.h>
#include <odp/api/shared_memory.h>
#include <odp/api/align.h>
#include <odp_internal.h>
#include <odp_config_internal.h>
#include <odp/api/hints.h>
#include <odp_debug_internal.h>
#include <odp_atomic_internal.h>
#include <odp_crypto_internal.h>

#include <usdpaa/fsl_usd.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_bman.h>
#include <usdpaa/of.h>
#include <usdpaa/usdpaa_netcfg.h>
#include <usdpaa/dma_mem.h>

odp_pool_t
odp_pool_create_bman(pool_entry_t *pool)
{
	struct bm_buffer bufs[8];
	unsigned int num_bufs = 0;
	int ret = 0;
	uint64_t sz;
	size_t hdr_offset, sg_priv_offset;

	struct bman_pool_params params = {
		.bpid = pool->s.pool_id,
	};

	ODP_ASSERT(pool->s.params.type == ODP_POOL_PACKET);

	pool->s.bman_pool = bman_new_pool(&params);
	if (!pool->s.bman_pool)
		return ODP_POOL_INVALID;
	pool->s.bman_params = params;

	ret = bman_reserve_bpid(pool->s.pool_id);
	if (ret)
		return ODP_POOL_INVALID;

	/* Drain the pool of anything already in it. */
	do {
		if (ret != 1)
			ret = bman_acquire(pool->s.bman_pool, bufs, 8, 0);
		if (ret < 8)
			ret = bman_acquire(pool->s.bman_pool, bufs, 1, 0);
		if (ret > 0)
			num_bufs += ret;
	} while (ret > 0);

	if (num_bufs)
		ODP_DBG("Warn: drained %u bufs from BPID %d\n",
			num_bufs, pool->s.pool_id);
	/* reserve the offset for packet hdr structure */
	sg_priv_offset = ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct sg_priv));
	hdr_offset = ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(odp_packet_hdr_t));
	for (num_bufs = 0; num_bufs < pool->s.buf_num; ) {
		unsigned int loop, rel;
		rel = (pool->s.buf_num - num_bufs) > 8 ? 8 :
		      (pool->s.buf_num - num_bufs);
		sz = sg_priv_offset + hdr_offset +
		     ODP_CONFIG_PACKET_HEADROOM +
		     pool->s.blk_size +
		     ODP_CONFIG_PACKET_TAILROOM;
		for (loop = 0; loop < rel; loop++) {
			void *ptr, *bm_addr;
			ptr = __dma_mem_memalign(ODP_CACHE_LINE_SIZE, sz);
			if (!ptr) {
				ODP_ERR("No buffer space\n");
				return ODP_POOL_INVALID;
			}

			memset(ptr, 0, sz);
			bm_addr = ptr + sg_priv_offset + hdr_offset; /* ODP_CACHE_LINE_ALIGNED */
			bm_buffer_set64(&bufs[loop], __dma_mem_vtop(bm_addr));

			odp_buffer_hdr_t *tmp = (odp_buffer_hdr_t *)ptr;
			/* Initialize buffer metadata */
			tmp->next = NULL;
			tmp->flags.all = 0;
			tmp->flags.zeroized = 0;
			tmp->size = pool->s.blk_size +
				    ODP_CONFIG_PACKET_HEADROOM +
				    ODP_CONFIG_PACKET_TAILROOM;
			odp_atomic_store_u32(&tmp->ref_count, 0);
			tmp->type = pool->s.params.type;
			tmp->event_type = pool->s.params.type;
			tmp->pool_hdl = pool->s.pool_hdl;
			ptr = __dma_mem_memalign(ODP_CACHE_LINE_SIZE,
						 pool->s.params.pkt.uarea_size);
			if (!ptr) {
				ODP_ERR("No buffer space for uarea\n");
				return ODP_POOL_INVALID;
			}

			tmp->uarea_addr = ptr;
			tmp->uarea_size = pool->s.params.pkt.uarea_size;
			tmp->segcount = 1;
			tmp->segsize = pool->s.seg_size;
			tmp->handle.handle = odp_buffer_encode_handle(tmp);

			tmp->bpid = pool->s.pool_id;
			tmp->phy_addr = __dma_mem_vtop(bm_addr);
			tmp->addr[0] = bm_addr;
		}
		do {
			ret = bman_release(pool->s.bman_pool, bufs, rel, 0);
		} while (ret == -EBUSY);

		if (ret)
			ODP_ERR("bman_release()\n");
		num_bufs += rel;
	}
	pool->s.buf_offset = hdr_offset + sg_priv_offset;
	ODP_DBG("Released %u bufs to BPID %d\n", num_bufs, pool->s.pool_id);
	return pool->s.pool_hdl;
}

odp_buffer_t odp_buffer_alloc_bman(pool_entry_t *pool)
{
	struct bm_buffer bm_buf;
	odp_buffer_hdr_t *hdr;
	uint8_t *addr;
	int ret;

	ODP_ASSERT(pool->s.params.type == ODP_POOL_PACKET);
	ret = bman_acquire(pool->s.bman_pool, &bm_buf, 1, 0);
	if (ret < 0)
		return ODP_BUFFER_INVALID;
	addr = __dma_mem_ptov(bm_buf_addr(&bm_buf));
	memset(addr, 0, pool->s.headroom + pool->s.blk_size + pool->s.tailroom);
	hdr = odp_buf_hdr_from_addr(addr, pool);
	hdr->inq = ODP_QUEUE_INVALID;
	hdr->segcount = 1;
	hdr->size = hdr->segcount * pool->s.seg_size;
	((odp_packet_hdr_t *)hdr)->l2_offset = 0;

	return odp_hdr_to_buf(hdr);
}

void odp_buffer_free_bman(odp_buffer_hdr_t *buf_hdr, pool_entry_t *pool)
{
	struct bm_buffer bm_buf;
	int ret;
	unsigned seg;

	ODP_ASSERT(pool->s.params.type == ODP_POOL_PACKET);
	ODP_ASSERT(buf_hdr->type == ODP_EVENT_PACKET);

	for (seg = 0; seg < buf_hdr->segcount; seg++) {
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
		bm_buffer_set64(&bm_buf, __dma_mem_vtop(buf_hdr->addr[seg]));
#else
		/* Address should remain in the CPU endianess. BMAN driver
		 * converts it to BE */
		bm_buf.opaque = __dma_mem_vtop(buf_hdr->addr[seg]);
#endif
		do {
			ret = bman_release(pool->s.bman_pool, &bm_buf, 1, 0);
		} while (ret == -EBUSY);
	}

	/* if there is a compound buffer, release also the sg table buffer */
	if (buf_hdr->segcount > 1) {
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
		bm_buffer_set64(&bm_buf, __dma_mem_vtop(buf_hdr->addr[seg]));
#else
		/* Address should remain in the CPU endianess. BMAN driver
		 * converts it to BE */
		bm_buf.opaque = __dma_mem_vtop(buf_hdr->addr[seg]);
#endif
		do {
			ret = bman_release(pool->s.bman_pool, &bm_buf, 1, 0);
		} while (ret == -EBUSY);
	}

}
