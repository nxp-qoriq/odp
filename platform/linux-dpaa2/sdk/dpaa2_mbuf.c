/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_mbuf.c
 * @brief		Buffer management library services for DPAA2 based
 *		applications.
 *			- Library to alloc/free/manipulate/ to dpaa2 buffers.
 */

/* DPAA2 header files */
#include <odp/api/std_types.h>
#include <dpaa2_common.h>
#include <dpaa2_mbuf.h>
#include <dpaa2_mbuf_priv.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_eth_priv.h>
#include <dpaa2_internal.h>
#include <dpaa2_eth_ldpaa_annot.h>
#include <odp/api/hints.h>
#include <odp/api/plat/packet_annot.h>

#ifndef DPAA2_MBUF_MALLOC
/* @internal DPAA2 Shell mpool name */
char dpaa2_mbuf_shell_mpool_name[] = "DPAA2_SHELL_MPOOL";

/* @internal DPAA2 Shell mpool handle */
void *dpaa2_mbuf_shell_mpool;
#endif

/*!
 * @details	Allocate a DPAA2 buffer of given size from given 'dev'.
 *		If the size is larger than the single available buffer,
 *		Scatter Gather frame will be allocated
 *
 * @param[in]	dev - DPAA2 device. Buffer will be allcoated from the pool
 *		affined to this 'dev'
 *
 * @param[in]	size - the DPAA2 buffer size required.
 *
 * @returns	dpaa2 buffer on success; NULL on failure .
 *
 */

dpaa2_mbuf_pt dpaa2_mbuf_alloc(
		struct dpaa2_dev *dev,
		uint32_t size)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_bp_list *bp_list = dev_priv->bp_list;
	dpaa2_mbuf_pt mbuf;
	int8_t pool_index, num_buf_pools;
	uint16_t bpid = INVALID_BPID;

	DPAA2_TRACE(BUF);

	num_buf_pools = bp_list->num_buf_pools;
	pool_index = 0;

loop:
	/* Get the best fit bpid as per size */
	while (pool_index < num_buf_pools) {
		DPAA2_DBG(BUF, "pool_index :%d,, size = %d", pool_index,
			bp_list->buf_pool[pool_index].size);
		if (size <= bp_list->buf_pool[pool_index].size) {
			bpid = bp_list->buf_pool[pool_index].bpid;
			DPAA2_DBG(BUF, "Best fit bpid found :%d", bpid);
			break;
		}
		pool_index++;
	}

	/* Allocate SG DPAA2 buffer if support is enabled */
	if (pool_index == num_buf_pools) {
			return dpaa2_mbuf_alloc_sg(dev, size);
	}

	/* Allocate buffer from the bpid */
	mbuf = dpaa2_mbuf_alloc_from_bpid(bpid);
	/* In case no buffer is available re-scan the pending list */
	if (!mbuf) {
		pool_index++;
		DPAA2_DBG(BUF, "Retrying from next bpid");
		goto loop;
	}

	/* reset the the annotation data */
	if (mbuf->priv_meta_off)
		memset(mbuf->head - mbuf->priv_meta_off, 0, mbuf->priv_meta_off);

	DPAA2_DBG(BUF, "Buffer allocated");
	return mbuf;
}

/*!
 * @details	Make a complete copy of given DPAA2 buffer
 *
 * @param[out]	to_buf - DPAA2 buffer on which the 'from_buffer' is copied.
 *		'to_buf' should already have the buffer frames in it, and thus
 *		no new frame from any buffer pool will be allocated inside
 *		the function.
 *
 * @param[in]	from_buf - DPAA2 buffer which needs to be copied.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
int dpaa2_mbuf_copy(
		dpaa2_mbuf_pt to_buf,
		dpaa2_mbuf_pt from_buf)
{
	size_t len;
	uint8_t *src, *dst;

	DPAA2_TRACE(BUF);

	/* Validate that source mbuf is scattered or not */
	if (BIT_ISSET_AT_POS(from_buf->eth_flags, DPAA2BUF_IS_SEGMENTED))
		return dpaa2_mbuf_sg_copy(to_buf, from_buf);

	/*Update all metadata first*/
	to_buf->bpid = from_buf->bpid;
	to_buf->end_off = from_buf->end_off;
	to_buf->priv_meta_off = from_buf->priv_meta_off;
	to_buf->frame_len = from_buf->frame_len;
	to_buf->tot_frame_len = from_buf->tot_frame_len;
	to_buf->hw_annot = (uint64_t)(to_buf->head - DPAA2_MBUF_HW_ANNOTATION);
	to_buf->timestamp = from_buf->timestamp;
	to_buf->atomic_cntxt = from_buf->atomic_cntxt;
	to_buf->user_priv_area = to_buf + sizeof(struct dpaa2_mbuf);
	to_buf->flags = from_buf->flags;
	to_buf->usr_flags = from_buf->usr_flags;
	to_buf->eth_flags = from_buf->eth_flags;
	to_buf->hash_val = from_buf->hash_val;
	to_buf->vq = from_buf->vq;
	to_buf->drv_priv_cnxt = from_buf->drv_priv_cnxt;
	to_buf->buf_pool = from_buf->buf_pool;
	to_buf->drv_priv_resv[0] = from_buf->drv_priv_resv[0];
	to_buf->drv_priv_resv[1] = from_buf->drv_priv_resv[1];
	to_buf->next_sg = from_buf->next_sg;
	to_buf->user_cnxt_ptr = from_buf->user_cnxt_ptr;
	to_buf->atomic_cntxt = from_buf->atomic_cntxt;
#ifdef ODP_IPSEC_DEBUG
	to_buf->drv_priv_cnxt1 = from_buf->drv_priv_cnxt1;
#endif
	/*Copy user area first*/
	len = bpid_info[from_buf->bpid].odp_user_area;
	memcpy(to_buf->user_priv_area, from_buf->user_priv_area, len);

	/*Calculate total length to be copied*/
	len = DPAA2_FD_PTA_SIZE + DPAA2_MBUF_HW_ANNOTATION
		+ (to_buf->data - to_buf->head) + from_buf->tot_frame_len;

	dst = (uint8_t *)to_buf->head -
			(DPAA2_FD_PTA_SIZE + DPAA2_MBUF_HW_ANNOTATION);
	src = (uint8_t *)from_buf->head -
			(DPAA2_FD_PTA_SIZE + DPAA2_MBUF_HW_ANNOTATION);

	/* copy the data and other parameters */
	memcpy(dst, src, len);
	DPAA2_DBG(BUF, "buffer copied successfully");
	return DPAA2_SUCCESS;
}

/*!
 * @details	Fill in the DPAA2 buffer with the data provided.
 *		This will also handle SG (in case SG is enabled).
 *		This API will overwrite any old data and will start
 *		writing from the data pointer
 *
 * @param[in]	mbuf - dpaa2 buffer on which the data is to be copied.
 *		This can also be a SG buffer
 *
 * @param[in]	data - data pointer from where copy has to be made
 *
 * @param[in]	offset - the offset at which data to be copied
 *
 * @param[in]	length - the length of data to be copied
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
int dpaa2_mbuf_data_copy_in(
		dpaa2_mbuf_pt mbuf,
		const uint8_t *data,
		uint32_t offset,
		uint32_t length)
{
	dpaa2_mbuf_pt tmp = mbuf;
	void *bdata;
	const void *in_data;
	uint16_t accum_len = 0, avail_len;
	uint16_t final_len = mbuf->tot_frame_len - offset;

	DPAA2_TRACE(BUF);

	/* Check if first segment suffice */
	if (mbuf->frame_len >= final_len)
		goto cur_mbuf;

	tmp = tmp->next_sg;
	/* Break at the segment which is to be the last segment
	 * for offset */
	while (tmp != NULL) {
		if (accum_len + tmp->frame_len > final_len)
			break;

		accum_len += tmp->frame_len;
		tmp = tmp->next_sg;
	}

	if (!tmp) {
		DPAA2_ERR(BUF, "Buffer shorter than requested offset");
		return DPAA2_FAILURE;
	}

cur_mbuf:
	bdata = tmp->data + offset - accum_len;
	avail_len = tmp->end_off - dpaa2_mbuf_headroom(tmp);
	in_data = data;
	while (tmp) {
		avail_len = tmp->end_off - dpaa2_mbuf_headroom(tmp);
		if (length <= avail_len)  {
			memcpy(bdata, in_data, length);
			DPAA2_DBG(BUF, "Copied %d bytes in a segment",
				length);
			return DPAA2_SUCCESS;
		} else {
			memcpy(bdata, in_data, avail_len);
			tmp = tmp->next_sg;
			if (tmp)
				bdata = tmp->data;
			length -= avail_len;
			in_data += avail_len;
			DPAA2_DBG(BUF, "Copied %d bytes in a segment",
				avail_len);
		}
	}
	return DPAA2_FAILURE;
}

int dpaa2_mbuf_data_copy_out(
		dpaa2_mbuf_pt mbuf,
		uint8_t *data,
		uint32_t offset,
		uint32_t length)
{
	dpaa2_mbuf_pt tmp = mbuf;
	void *bdata;
	void *out_data;
	uint16_t accum_len = 0, avail_len;
	uint16_t final_len = mbuf->tot_frame_len - offset;

	DPAA2_TRACE(BUF);

	/* Check if first segment suffice */
	if (mbuf->frame_len >= final_len)
		goto cur_mbuf;

	tmp = tmp->next_sg;
	/* Break at the segment which is to be the last segment
	 * for offset */
	while (tmp != NULL) {
		if (accum_len + tmp->frame_len > final_len)
			break;

		accum_len += tmp->frame_len;
		tmp = tmp->next_sg;
	}

	if (!tmp) {
		DPAA2_ERR(BUF, "Buffer shorter than requested offset");
		return DPAA2_FAILURE;
	}

cur_mbuf:
	bdata = tmp->data + offset - accum_len;
	avail_len = tmp->end_off - dpaa2_mbuf_headroom(tmp);
	out_data = data;
	while (tmp) {
		avail_len = tmp->end_off - dpaa2_mbuf_headroom(tmp);
		if (length <= avail_len)  {
			memcpy(out_data, bdata, length);
			DPAA2_DBG(BUF, "Copied %d bytes from a segment",
				length);
			return DPAA2_SUCCESS;
		} else {
			memcpy(out_data, bdata, avail_len);
			tmp = tmp->next_sg;
			if (tmp)
				bdata = tmp->data;
			length -= avail_len;
			out_data += avail_len;
			DPAA2_DBG(BUF, "Copied %d bytes from a segment",
				avail_len);
		}
	}
	return DPAA2_FAILURE;
}


/*!
 * @details	Dump DPAA2 buffer and its data
 *
 * @param[in]	stream - out device (file or stderr, stdout etc).
 *
 * @param[in]	mbuf - dpaa2 buffer
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_dump_pkt(
		void *stream,
		dpaa2_mbuf_pt mbuf)
{
	dpaa2_mbuf_pt tmp = mbuf;
	int i = 0;

	DPAA2_TRACE(BUF);

	/* TODO use stream */
	while (tmp != NULL) {
		DPAA2_NOTE(BUF, "segment %d:", i++);
		DPAA2_NOTE(BUF, "DPAA2 BUFFER SHELL:");
		dpaa2_memdump(stream, "BufShell", tmp, sizeof(struct dpaa2_mbuf));

		DPAA2_NOTE(BUF, "next_sg: %p", tmp->next_sg);
		DPAA2_NOTE(BUF, "head: %p", tmp->head);
		DPAA2_NOTE(BUF, "data: %p", tmp->data);
		DPAA2_NOTE(BUF, "priv_meta_off: %u", tmp->priv_meta_off);
		DPAA2_NOTE(BUF, "phy_addr: 0x%lx", tmp->phyaddr);
		DPAA2_NOTE(BUF, "end_off: %u", tmp->end_off);
		DPAA2_NOTE(BUF, "frame length: %u", tmp->frame_len);
		DPAA2_NOTE(BUF, "total frame length: %u", tmp->tot_frame_len);
		DPAA2_NOTE(BUF, "bpid: %u", tmp->bpid);
		DPAA2_NOTE(BUF, "flags: %x", tmp->flags);
		DPAA2_NOTE(BUF, "vq: %p", tmp->vq);
		DPAA2_NOTE(BUF, "user_priv_area: %p", tmp->user_priv_area);
		DPAA2_NOTE(BUF, "user_cnxt_ptr: 0x%lx", tmp->user_cnxt_ptr);

		DPAA2_NOTE(BUF, "timestamp: %lu", tmp->timestamp);
		DPAA2_NOTE(BUF, "hash_val: %d", tmp->hash_val);
		DPAA2_NOTE(BUF, "eth_flags: %x", tmp->eth_flags);
		DPAA2_NOTE(BUF, "usr_flags: %x", tmp->usr_flags);
		DPAA2_NOTE(BUF, "hw_annot: %lx\n", tmp->hw_annot);

		dpaa2_hexdump(stream, "BufData", tmp->data, tmp->frame_len);
		tmp = tmp->next_sg;
	}
}

#ifndef DPAA2_MBUF_MALLOC
/** @internal API */
int32_t dpaa2_mbuf_shell_mpool_init(uint32_t num_global_blocks)
{
	struct dpaa2_mpool_cfg mpcfg;

	memset(&mpcfg, 0, sizeof(struct dpaa2_mpool_cfg));
	mpcfg.name = dpaa2_mbuf_shell_mpool_name;
	mpcfg.block_size = sizeof(struct dpaa2_mbuf);
	mpcfg.num_global_blocks = num_global_blocks;
	mpcfg.flags = 0;
	mpcfg.num_threads = 0;
	mpcfg.num_per_thread_blocks = 0;

	dpaa2_mbuf_shell_mpool = dpaa2_mpool_create(&mpcfg, NULL, NULL);
	if (dpaa2_mbuf_shell_mpool == NULL)
		return DPAA2_FAILURE;

	return DPAA2_SUCCESS;
}

/** @internal API */
int32_t dpaa2_mbuf_shell_mpool_exit(void)
{
	return dpaa2_mpool_delete(dpaa2_mbuf_shell_mpool);
}
/* get the first pools bpid */
int dpaa2_mbuf_pool_get_bpid(void *bplist)
{
	struct dpaa2_bp_list *bp_list = (struct dpaa2_bp_list *)bplist;

	return bp_list->buf_pool[0].bpid;
}

#endif
