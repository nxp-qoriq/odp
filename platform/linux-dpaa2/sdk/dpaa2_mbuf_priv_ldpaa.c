/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_mbuf_priv_ldpaa.c
 * @brief		Buffer management library services for DPAA2 based applications for LS.
 */


/* Standard header files */
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

/* DPAA2 header files */
#include <odp/api/std_types.h>
#include <dpaa2_mbuf.h>
#include <dpaa2_mbuf_priv.h>
#include <dpaa2_common.h>
#include <dpaa2_malloc.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_mpool.h>
#include <dpaa2_internal.h>
#include <dpaa2_eth_ldpaa_annot.h>
/* MC header files */
#include <fsl_dpbp.h>

/* QBMAN header files */
#include <fsl_qbman_portal.h>
#include <dpaa2_memzone.h>
#include <odp/api/plat/packet_annot.h>
#include <odp_align_internal.h>
#include <odp_packet_internal.h>

struct dpbp_node *g_dpbp_list;
struct dpbp_node *avail_dpbp;

struct dpaa2_bp_list *g_bp_list;
/* TODO use proper algorithm to get bpid size */
struct bp_info bpid_info[MAX_BPID];

/*! Global per thread buffer stockpile info */
__thread struct bpsp *th_bpsp_info[MAX_BPID];

/*!
 * @details	Initializes the dpbp for dpaa2 buffer module
 *
 * @param[in]	portal_vaddr - Pointer to MC portal registers address
 *
 * @param[in]	dpbp_id -DPBP unique ID
 *
 * @returns	DPAA2_SUCESS on success; DPAA2_FAILURE otherwise
 *
 */
int dpaa2_mbuf_dpbp_init(
		uint64_t portal_addr,
		int dpbp_id)
{
	struct dpbp_node *dpbp_node;
	int ret;

	DPAA2_TRACE(BUF);

	if (!portal_addr) {
		DPAA2_ERR(BUF, "Resource allocation failure");
		return DPAA2_FAILURE;
	}

	/* Allocate DPAA2 dpbp handle */
	dpbp_node = (struct dpbp_node *)dpaa2_calloc(NULL, 1,
		sizeof(struct dpbp_node), 0);
	if (!dpbp_node) {
		DPAA2_ERR(BUF, "No memory available");
		return DPAA2_FAILURE;
	}

	/* Open the dpbp object */
	dpbp_node->dpbp.regs = (void *)portal_addr;
	ret = dpbp_open(&(dpbp_node->dpbp), CMD_PRI_LOW, dpbp_id, &(dpbp_node->token));
	if (ret) {
		DPAA2_ERR(BUF, "Resource allocation failure with err code: %d",
			ret);
		dpaa2_free(dpbp_node);
		return DPAA2_FAILURE;
	}

	dpbp_node->dpbp_id = dpbp_id;
	/* Add the dpbp handle into the global list */
	dpbp_node->next = g_dpbp_list;
	g_dpbp_list = dpbp_node;
	avail_dpbp = g_dpbp_list;

	DPAA2_INFO(BUF, "Buffer resource initialized");
	return DPAA2_SUCCESS;
}


/*!
 * @details	Disable all the enabled dpbp's.
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_dpbp_disable_all(void)
{
	struct dpbp_node *dpbp_node;
	int ret;

	DPAA2_TRACE(BUF);

	dpbp_node = g_dpbp_list;

	/* Scan all the allocated dpbp's */
	while (dpbp_node != avail_dpbp) {
		ret = dpbp_disable(&(dpbp_node->dpbp), CMD_PRI_LOW, dpbp_node->token);
		if (ret)
			DPAA2_ERR(BUF, "Resource disable failure with"
				"err code: %d", ret);
		dpbp_node = dpbp_node->next;
	}
	avail_dpbp = g_dpbp_list;
}

/*!
 * @details	Close all the opened dpbp's.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
int dpaa2_mbuf_dpbp_close_all(void)
{
	struct dpbp_node *dpbp_node, *temp;
	int ret;

	DPAA2_TRACE(BUF);

	dpbp_node = g_dpbp_list;

	/* Close all the dpbp's */
	while (dpbp_node) {
		ret = dpbp_close(&(dpbp_node->dpbp), CMD_PRI_LOW, dpbp_node->token);
		if (ret)
			DPAA2_ERR(BUF, "Resource freeing failure with"
				"err code: %d", ret);

		temp = dpbp_node->next;
		dpaa2_free(dpbp_node);
		dpbp_node = temp;
	}
	return DPAA2_SUCCESS;
}


/*!
 * @details	Initializes the buffer pool list. Within this API
 *		memory required will be allocated, dpbp will get initialized,
 *		buffer pool list will be configured
 *
 * @param[in]	bp_list_cfg - buffer pool list configuration
 *
 * @returns	buffer pool list pointer in case of success; NULL otherwise
 *
 */
struct dpaa2_bp_list *dpaa2_mbuf_create_bp_list(
	struct dpaa2_bp_list_cfg *bp_list_cfg)
{
	struct dpaa2_bp_list *bp_list;
	uint8_t *h_bpool_mem;
	uint8_t pool_index;
	struct dpbp_attr dpbp_attr;
	int num_pools;
	uint32_t num_bufs;
	uint32_t buf_size = 0;
	uint16_t bpid;
	struct dpbp_node *temp_dpbp_node;
	int ret;
	struct dpaa2_memzone *bz;
	char memstr[24];

	DPAA2_TRACE(BUF);

	if (!avail_dpbp) {
		DPAA2_ERR(BUF, "No resources available");
		return NULL;
	}

	/* Allocate the bp_list which will be added into global_bp_list */
	bp_list = (struct dpaa2_bp_list *)dpaa2_calloc(NULL, 1,
			sizeof(struct dpaa2_bp_list), 0);
	if (!bp_list) {
		DPAA2_ERR(BUF, "No heap memory available");
		return NULL;
	}

	temp_dpbp_node = avail_dpbp;
	num_pools = bp_list_cfg->num_buf_pools;
	bp_list->num_buf_pools = 0;
	for (pool_index = 0; pool_index < num_pools; pool_index++) {
		if (!avail_dpbp) {
			DPAA2_ERR(BUF, "No resources available");
			goto err;
		}
		ret = dpbp_enable(&(avail_dpbp->dpbp), CMD_PRI_LOW, avail_dpbp->token);
		if (ret != 0) {
			DPAA2_ERR(BUF, "Resource enable failure with"
				"err code: %d", ret);
			goto err;
		}

		ret = dpbp_get_attributes(&(avail_dpbp->dpbp), CMD_PRI_LOW,
			avail_dpbp->token, &dpbp_attr);
		if (ret != 0) {
			DPAA2_ERR(BUF, "Resource read failure with"
				"err code: %d", ret);
			goto err;
		}
		bpid = dpbp_attr.bpid;

		num_bufs = bp_list_cfg->buf_pool[pool_index].num;
		buf_size = bp_list_cfg->buf_pool[pool_index].meta_data_size
				+ dpaa2_mbuf_head_room
				+ DPAA2_MBUF_HW_ANNOTATION
				+ dpaa2_mbuf_sw_annotation
				+ bp_list_cfg->buf_pool[pool_index].size;

		sprintf(memstr, "bufmem-%d", bpid);
		if (bp_list_cfg->buf_pool[pool_index].addr) {
			DPAA2_WARN(BUF, "\nUsing app provided memory for BPOOL");
			DPAA2_WARN(BUF, "Make sure to use SMMU mapped memory");
			DPAA2_ERR(BUF, "\nNot supported");
			goto err;
		} else {
			/* Get the memory from the mempool */
			bz = dpaa2_memzone_reserve(memstr,
				(num_bufs * buf_size), 0, 0);
			if (!bz) {
				DPAA2_ERR(BUF, "Buffer pool not avaialble");
				goto err;
			}
			h_bpool_mem = (uint8_t *)dpaa2_memzone_virt(bz);
		}

		sprintf(avail_dpbp->name, "dpbp.%d", dpbp_attr.id);
		avail_dpbp->name[strlen(avail_dpbp->name)] = '\0';
		/* Set parameters of buffer pool list */
		bp_list->buf_pool[pool_index].buf_size = buf_size;
		bp_list->buf_pool[pool_index].num_bufs = num_bufs;
		bp_list->buf_pool[pool_index].size = buf_size -
			bp_list_cfg->buf_pool[pool_index].meta_data_size;
		bp_list->buf_pool[pool_index].bpid = bpid;
		bp_list->buf_pool[pool_index].odp_user_area =
					bp_list_cfg->buf_pool[pool_index].odp_user_area;
		bp_list->buf_pool[pool_index].meta_data_size =
					bp_list_cfg->buf_pool[pool_index].meta_data_size;
		bp_list->buf_pool[pool_index].h_bpool_mem = h_bpool_mem;
		bp_list->buf_pool[pool_index].dpbp_node = avail_dpbp;
		bp_list->num_buf_pools++;

		/* Increment the available DPBP */
		avail_dpbp = avail_dpbp->next;

		/* Set the buffer pool id's (bpid) in the user bp_list */
		bp_list_cfg->buf_pool[pool_index].bpid = bpid;

		/* if enough buffers to build stockpile, yes otherwise, no use */
		bpid_info[bpid].stockpile = (num_bufs > BMAN_STOCKPILE_SZ) ? 1 : 0;
		bpid_info[bpid].bpid = bpid;
		bpid_info[bpid].size = bp_list->buf_pool[pool_index].size;
		bpid_info[bpid].odp_user_area = bp_list->buf_pool[pool_index].odp_user_area;
		bpid_info[bpid].meta_data_size = bp_list->buf_pool[pool_index].meta_data_size;
		bpid_info[bpid].buf_size = bp_list->buf_pool[pool_index].buf_size;
		DPAA2_INFO(BUF, "BP List created [stockpile in use = %d]\n",
						bpid_info[bpid].stockpile);
	}

	return bp_list;
/* TODO error handling w.r.t memzones */
err:
	/* Free the allocated resources (error case)*/
	avail_dpbp = temp_dpbp_node;
	num_pools = bp_list->num_buf_pools;
	for (pool_index = 0; pool_index < num_pools; pool_index++) {
		ret = dpbp_disable(&(temp_dpbp_node->dpbp), CMD_PRI_LOW,
			temp_dpbp_node->token);
		if (ret)
			DPAA2_ERR(BUF, "Resource disable failure with"
				"err code: %d", ret);
		temp_dpbp_node = temp_dpbp_node->next;
	}

	dpaa2_free(bp_list);
	return NULL;

}


/*!
 * @details	Add the buffer pool list to the global list. Also the buffer
 *		pools in the list are stored in sorted order of size.
 *
 * @param[in]	bp_list - buffer pool list
 *
 * @returns	none
 *
 */
void dpaa2_add_bp_list(
		struct dpaa2_bp_list *bp_list)
{
	struct buf_pool temp_buf_pool;
	uint8_t num_pools;
	int pool_index, i;

	DPAA2_TRACE(BUF);

	num_pools = bp_list->num_buf_pools;
	/* Sort them according to size so they are stored as low to high */
	for (i = 0 ; i < (num_pools - 1); i++) {
		for (pool_index = 0 ; pool_index < num_pools - i - 1;
				pool_index++) {
			if (bp_list->buf_pool[pool_index].size >
				bp_list->buf_pool[pool_index + 1].size) {
				memcpy(&temp_buf_pool,
					&bp_list->buf_pool[pool_index],
					sizeof(struct buf_pool));
				memcpy(&bp_list->buf_pool[pool_index],
					&bp_list->buf_pool[pool_index + 1],
					sizeof(struct buf_pool));
				memcpy(&bp_list->buf_pool[pool_index + 1],
					&temp_buf_pool,
					sizeof(struct buf_pool));
			}
		}
	}

	DPAA2_INFO(BUF, "Buffer pool list added to the global bp list");
	DPAA2_INFO(BUF, "Num buf pools: %d", bp_list->num_buf_pools);
	DPAA2_INFO(BUF, "BP List in sorted order(size)\n");
	for (pool_index = 0; pool_index < num_pools; pool_index++) {
		DPAA2_INFO(BUF, "Size of buffers: %d",
			bp_list->buf_pool[pool_index].size);
		DPAA2_INFO(BUF, "Number of buffers: %d",
			bp_list->buf_pool[pool_index].num_bufs);
		DPAA2_INFO(BUF, "buffer pool id: %d",
			bp_list->buf_pool[pool_index].bpid);
	}

	/* Add to the global buffer pool list */
	bp_list->next = g_bp_list;
	g_bp_list = bp_list;

}

/*!
 * @details	De-initialize the buffer pool list. This will aquire all the
 *		buffers from QBMAN related to the buffer pool list,
 *		so that QBMAN will not have any buffers.
 *
 * @param[in]	bp_list - buffer pool list
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_pool_list_deinit(
		void *bplist)
{
	struct dpaa2_bp_list *bp_list = (struct dpaa2_bp_list *)bplist;
	struct qbman_swp *swp;
	int pool_index, i, any_portal = 0;
	uint64_t bufs[DPAA2_MBUF_MAX_ACQ_REL];
	int num_pools, ret = 0;
	uint16_t bpid, count;

	DPAA2_TRACE(BUF);

	if (!thread_io_info.dpio_dev) {
		int ret;

		ret = dpaa2_thread_affine_io_context(DPAA2_IO_PORTAL_ANY_FREE);
		if (ret) {
			DPAA2_ERR(BUF, "SW portal is not available\n");
			return;
		}
		any_portal = 1;
	}

	swp = thread_io_info.dpio_dev->sw_portal;
	num_pools = bp_list->num_buf_pools;

	/* Aquire all the buffers from QBMAN related to this bp list */
	for (pool_index = 0; pool_index < num_pools; pool_index++) {
		bpid = bp_list->buf_pool[pool_index].bpid;
		count = 0;
		do {
			/* Acquire is all-or-nothing, so we drain in 7s,
			 * then in 1s for the remainder. */
			if (ret != 1) {
				ret = qbman_swp_acquire(swp, bpid, bufs,
					DPAA2_MBUF_MAX_ACQ_REL);
				if (ret == DPAA2_MBUF_MAX_ACQ_REL) {
					count += ret;
					for (i = 0; i < ret; i++)
						DPAA2_DBG(BUF, "Drained"
							"buffer: 0x%"PRIx64"\n",
							bufs[i]);
				}
			}
			if (ret < DPAA2_MBUF_MAX_ACQ_REL) {
				ret = qbman_swp_acquire(swp, bpid, bufs, 1);
				if (ret > 0) {
					DPAA2_DBG(BUF, "Drained buffer: 0x%"PRIx64"\n",
						bufs[1]);
					count += ret;
				}
			}
			if (ret < 0)
				DPAA2_WARN(BUF, "Buffer aquire failed with"
					"err code: %d", ret);
		} while (ret > 0);
		DPAA2_INFO(BUF, "Drained %d buffers from bpid: %d",
			count, bpid);
		if (count != bp_list->buf_pool[pool_index].num_bufs) {
			DPAA2_DBG(BUF, "Buffers drained not equals buffers "
				"initially populated");
			DPAA2_DBG(BUF, "Drained: %d, Initially Poulated: %d",
				count, bp_list->buf_pool[pool_index].num_bufs);
		}
	}

	if (any_portal)
		dpaa2_thread_deaffine_io_context();
}

/*!
 * @details	Allocate a SG DPAA2 buffer of given size from given 'dev'.
 *
 * @param[in]	dev - DPAA2 device. Buffer will be allcoated from the pool
 *		affined to this 'dev'
 *
 * @param[in]	size - the DPAA2 buffer size required.
 *
 * @returns	dpaa2 buffer on success; NULL of failure .
 *
 */
dpaa2_mbuf_pt dpaa2_mbuf_alloc_sg(
		struct dpaa2_dev *dev ODP_UNUSED,
		uint32_t size ODP_UNUSED)
{
	DPAA2_TRACE(BUF);

	return NULL;
}


/*!
 * @details	Allocate SG DPAA2 buffer from given buffer pool.
 *
 * @param[in]	bpid - buffer pool id (which was filled in by DPAA2 at
 *		'dpaa2_create_buf_pool_list'
 *
 * @param[in]	length - if single buffer length is greater than the buffer size
 *		it may allocate SG list.
 *
 * @returns	dpaa2 buffer on success; NULL on failure.
 *
 */
dpaa2_mbuf_pt dpaa2_mbuf_alloc_sg_from_bpid(
		uint16_t bpid ODP_UNUSED,
		int length ODP_UNUSED)
{
	DPAA2_TRACE(BUF);

	return NULL;
}

/*!
 * @details	Make a complete copy of given DPAA2 buffer in case of SG
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
int dpaa2_mbuf_sg_copy(dpaa2_mbuf_pt to_buf, dpaa2_mbuf_pt from_buf)
{
	struct dpaa2_mbuf *src = from_buf;
	struct dpaa2_mbuf *dst = to_buf;
	uint32_t len;
	uint32_t headroom;

	DPAA2_TRACE(BUF);

	src = DPAA2_INLINE_MBUF_FROM_BUF(from_buf->hw_annot - DPAA2_FD_PTA_SIZE,
					 bpid_info[src->bpid].meta_data_size);
	dst = DPAA2_INLINE_MBUF_FROM_BUF(to_buf->hw_annot - DPAA2_FD_PTA_SIZE,
					 bpid_info[src->bpid].meta_data_size);

	dst->bpid = src->bpid;
	dst->end_off = src->end_off;
	dst->priv_meta_off = src->priv_meta_off;
	dst->frame_len = src->frame_len;
	dst->tot_frame_len = src->tot_frame_len;
	dst->timestamp = src->timestamp;
	dst->atomic_cntxt = src->atomic_cntxt;
	dst->flags = src->flags;
	dst->usr_flags = src->usr_flags;
	dst->eth_flags = src->eth_flags;
	dst->hash_val = src->hash_val;
	dst->vq = src->vq;
	dst->drv_priv_cnxt = src->drv_priv_cnxt;
	dst->buf_pool = src->buf_pool;
	dst->drv_priv_resv[0] = src->drv_priv_resv[0];
	dst->drv_priv_resv[1] = src->drv_priv_resv[1];
	dst->user_cnxt_ptr = src->user_cnxt_ptr;
	dst->atomic_cntxt = src->atomic_cntxt;
#ifdef ODP_IPSEC_DEBUG
	dst->drv_priv_cnxt1 = src->drv_priv_cnxt1;
#endif

	/*Copy user area first*/
	len = bpid_info[from_buf->bpid].odp_user_area;
	memcpy(dst->user_priv_area, src->user_priv_area, len);

	/*Calculate total length to be copied*/
	len = src->priv_meta_off + src->end_off;
	memcpy((uint8_t *)(dst->head - dst->priv_meta_off),
	       (uint8_t *)(src->head - src->priv_meta_off), len);

	src = from_buf;
	dst = to_buf;
	while (src) {
		dst->bpid = src->bpid;
		dst->end_off = src->end_off;
		dst->priv_meta_off = src->priv_meta_off;
		dst->frame_len = src->frame_len;
		dst->tot_frame_len = src->tot_frame_len;
		dst->timestamp = src->timestamp;
		dst->atomic_cntxt = src->atomic_cntxt;
		dst->flags = src->flags;
		dst->usr_flags = src->usr_flags;
		dst->eth_flags = src->eth_flags;
		dst->hash_val = src->hash_val;
		dst->vq = src->vq;
		dst->drv_priv_cnxt = src->drv_priv_cnxt;
		dst->buf_pool = src->buf_pool;
		dst->drv_priv_resv[0] = src->drv_priv_resv[0];
		dst->drv_priv_resv[1] = src->drv_priv_resv[1];
		dst->user_cnxt_ptr = src->user_cnxt_ptr;
		dst->atomic_cntxt = src->atomic_cntxt;
#ifdef ODP_IPSEC_DEBUG
		dst->drv_priv_cnxt1 = src->drv_priv_cnxt1;
#endif
		/*Copy user area first*/
		len = bpid_info[from_buf->bpid].odp_user_area;
		memcpy(dst->user_priv_area, src->user_priv_area, len);

		headroom = src->data - src->head;
		len = headroom + src->frame_len;
		/*Copy all data*/
		memcpy((dst->data - headroom), (src->data - headroom), len);

		src = src->next_sg;
		dst = dst->next_sg;
	}

	return DPAA2_SUCCESS;
}
