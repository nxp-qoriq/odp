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
#include <odp/api/hints.h>
#include <odp/api/plat/packet_annot.h>

#ifndef DPAA2_MBUF_MALLOC
/* @internal DPAA2 Shell mpool name */
char dpaa2_mbuf_shell_mpool_name[] = "DPAA2_SHELL_MPOOL";

/* @internal DPAA2 Shell mpool handle */
void *dpaa2_mbuf_shell_mpool;
#endif

bool_t sg_support;

/*!
 * @details	Configures the DPAA2 buffer library e.g. for SG allocation,
 *		inline dpaa2 buffer allocation etc. This API should be called
 *		once during initialization
 *
 * @param[in]	cfg_flags - Flags for DPAA2 buffer library configuration.
 *		User shall use 'DPAA2_CFG_SG_SUPPORT' for cfg_flags
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_lib_config(
		uint32_t cfg_flags)
{
	DPAA2_TRACE(BUF);

	if (cfg_flags & DPAA2_CFG_SG_SUPPORT)
		sg_support = TRUE;
}


/*!
 * @details	Allocate a DPAA2 buffer of given size from given 'dev'.
 *		If the size is larger than the single available buffer,
 *		Scatter Gather frame will be allocated
 *		(provided support is enabled at 'dpaa2_mbuf_lib_config')
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
		if (sg_support) {
			return dpaa2_mbuf_alloc_sg(dev, size);
		} else {
			DPAA2_INFO(BUF, "No more buffers available");
			return NULL;
		}
	}

	/* Allocate buffer from the bpid */
	mbuf = dpaa2_mbuf_alloc_from_bpid(bpid, 0);
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

/**
 * mbuf offset pointer
 *
 * Returns pointer to data in the packet offset. Optionally outputs
 * handle to the segment and number of data bytes in the segment following the
 * pointer.
 *
 * @param      mbuf     Mbuf handle
 * @param      offset   Byte offset into the packet data pointer
 * @param[out] len      Number of data bytes remaining in the segment (output).
 *                      Ignored when NULL.
 * @param[out] seg      Handle to the segment containing the address (output).
 *                      Ignored when NULL.
 *
 * @return data Pointer to the offset
 * @retval NULL  Requested offset exceeds packet length
 */
uint8_t *dpaa2_mbuf_offset(dpaa2_mbuf_pt mbuf, uint32_t offset, uint32_t *len,
			dpaa2_mbuf_pt *seg)
{
	dpaa2_mbuf_pt tmp = mbuf;
	uint16_t accum_len = 0;

	DPAA2_TRACE(BUF);

	/* offset is more than the total frame length */
	if (mbuf->tot_frame_len <= offset)
			return NULL;

	/* Check if first segment suffice */
	if (mbuf->frame_len  >= offset)
		goto cur_mbuf;

	tmp = tmp->next_sg;
	/* Break at the segment which is to be the last segment
	 * for offset */
	while (tmp != NULL) {
		if (accum_len + tmp->frame_len > offset)
			break;

		accum_len += tmp->frame_len;
		tmp = tmp->next_sg;
	}

	if (!tmp) {
		DPAA2_ERR(BUF, "Buffer shorter than requested offset");
		return NULL;
	}

cur_mbuf:

	if (seg)
		*seg = tmp;

	if (len)
		*len = tmp->frame_len - offset;
	return tmp->data + offset - accum_len;
}
/*!
 * @details	Pull the DPAA2 buffer in tail by given size.
 *
 * @param[in]	mbuf - dpaa2 buffer
 *
 * @param[in]	length - length by which the buffer is to be trimmed
 *
 * @param[in]	free_extra - free the remaining segments if any
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
int dpaa2_mbuf_pull_tail(
		dpaa2_mbuf_pt mbuf,
		uint32_t length,
		uint8_t free_extra)
{
	dpaa2_mbuf_pt tmp = mbuf;
	uint16_t accum_len = 0;
	uint16_t final_len = mbuf->tot_frame_len - length;

	DPAA2_TRACE(BUF);

	/* Check if first segment suffice */
	if (mbuf->frame_len >= final_len)
		goto free_mbufs;

	tmp = tmp->next_sg;
	/* Break at the segment which is to be the last segment
	 * after trimming */
	while (tmp != NULL) {
		if (accum_len + tmp->frame_len > final_len)
			break;

		accum_len += tmp->frame_len;
		tmp = tmp->next_sg;
	}

	if (!tmp) {
		DPAA2_ERR(BUF, "Buffer shorter than requested trimming length");
		return DPAA2_FAILURE;
	}

free_mbufs:
	/* adjust the lengths */
	tmp->frame_len = final_len - accum_len;

	mbuf->tot_frame_len = final_len;

	DPAA2_DBG(BUF, "Final total length: %d", mbuf->tot_frame_len);
	DPAA2_DBG(BUF, "Last segment length: %d", tmp->frame_len);

	/* free remaining segments */
	if (free_extra && tmp->next_sg)
		dpaa2_mbuf_free(tmp->next_sg);

	return DPAA2_SUCCESS;
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
	uint32_t avail_len;
	const size_t start_offset = ODP_OFFSETOF(struct dpaa2_mbuf, flags);
	const size_t len = sizeof(struct dpaa2_mbuf);
	uint8_t *src, *dst;

	DPAA2_TRACE(BUF);

	/* If any parameter is SG packet call sg copy */
	if (to_buf->next_sg || from_buf->next_sg)
		return dpaa2_mbuf_sg_copy(to_buf, from_buf);

	to_buf->tot_frame_len = from_buf->tot_frame_len;

	/* Check if required length is available in the to_buf */
	avail_len = dpaa2_mbuf_avail_len(to_buf);
	if (from_buf->frame_len > avail_len) {
		DPAA2_WARN(BUF, "Not enough length in the to_buf");
		return DPAA2_FAILURE;
	}

	dst = (uint8_t *)to_buf + start_offset;
	src = (uint8_t *)from_buf + start_offset;
	memcpy(dst, src, len - start_offset);

	/* copy the data and other parameters */
	if (from_buf->frame_len)
			memcpy(to_buf->data, from_buf->data, from_buf->frame_len);

	/* copy the annotation data */
	if (from_buf->priv_meta_off >= DPAA2_MBUF_HW_ANNOTATION &&
		to_buf->priv_meta_off >= DPAA2_MBUF_HW_ANNOTATION)
		memcpy(to_buf->head - DPAA2_MBUF_HW_ANNOTATION,
				from_buf->head - DPAA2_MBUF_HW_ANNOTATION,
				DPAA2_MBUF_HW_ANNOTATION)
	DPAA2_DBG(BUF, "Non SG buffer copied successfully");
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
