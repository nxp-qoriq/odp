/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_mbuf_ldpaa.c
 * @brief		Buffer management library services for DPAA2 based for LS
 */

/* Standard header files */
#include <errno.h>
#include <pthread.h>

/* DPAA2 header files */
#include <dpaa2_common.h>
#include <dpaa2_mbuf_priv.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_aiop.h>
#include <dpaa2_vq.h>
#include <dpaa2_memconfig.h>
#include <dpaa2_eth_ldpaa_annot.h>
#include <dpaa2_eth_ldpaa_qbman.h>

/* QBMAN header files */
#include <fsl_qbman_portal.h>

#include <odp/api/plat/event_types.h>
#include <odp/api/plat/packet_annot.h>
#include <odp_buffer_internal.h>
#include <odp_align_internal.h>
#include <odp_config_internal.h>
#include <odp_packet_internal.h>

uint32_t dpaa2_mbuf_head_room;
uint32_t dpaa2_mbuf_tail_room = 128;

/*!
 * @details	Initialize a buffer pool list. This API should be called
 *		when IO context is affined to the thread.
 * @param[in,out]	bp_list_cfg -  Buffer pool list configuration.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
void *dpaa2_mbuf_pool_list_init(
		struct dpaa2_bp_list_cfg *bp_list_cfg)
{
	struct qbman_release_desc releasedesc;
	struct dpaa2_bp_list *bp_list;
	struct qbman_swp *swp;
	int pool_index;
	uint64_t bufs[DPAA2_MBUF_MAX_ACQ_REL];
	int num_pools;

	DPAA2_TRACE(BUF);

	if (!thread_io_info.dpio_dev) {
		DPAA2_ERR(BUF, "No IO context available");
		return NULL;
	}

	/* Check if number of pools are more than the maximum supported */
	num_pools = bp_list_cfg->num_buf_pools;
	if (num_pools > DPAA2_MAX_BUF_POOLS) {
		DPAA2_ERR(BUF, "Invalid number of pools");
		return NULL;
	}

	for (pool_index = 0; pool_index < num_pools; pool_index++) {
		if (bp_list_cfg->buf_pool[pool_index].size <
			DPAA2_MBUF_MIN_SIZE) {
			DPAA2_ERR(BUF, "Invalid size of a pool");
			return NULL;
		}
	}

	/* Create the buffer pool list, initializing dpbp, bufmem etc */
	bp_list = dpaa2_mbuf_create_bp_list(bp_list_cfg);
	if (!bp_list) {
		DPAA2_ERR(BUF, "Unable to create the bp list");
		return NULL;
	}

	swp = thread_io_info.dpio_dev->sw_portal;

	/* Fill the pool, release the buffers to BMAN */
	for (pool_index = 0; pool_index < num_pools; pool_index++) {
		uint32_t num_bufs, buf_size, count;
		uint8_t *h_bpool_mem;
		dpaa2_mbuf_pt	mbuf;
		uint16_t bpid;
		int ret;

		num_bufs = bp_list->buf_pool[pool_index].num_bufs;
		buf_size = bp_list->buf_pool[pool_index].buf_size;

		bpid = bp_list->buf_pool[pool_index].bpid;
		h_bpool_mem = bp_list->buf_pool[pool_index].h_bpool_mem;

		/* Create a release descriptor required for releasing
		 * buffers into BMAN */
		qbman_release_desc_clear(&releasedesc);
		qbman_release_desc_set_bpid(&releasedesc, bpid);

		for (count = 0; count < num_bufs; ) {
			uint8_t i, rel;
			/* In BMAN we can release buffers maximum 7 at a time.
			 * This takes care of it. (hardware stockpile)*/
			rel = (num_bufs - count) > DPAA2_MBUF_MAX_ACQ_REL ?
				DPAA2_MBUF_MAX_ACQ_REL : (num_bufs - count);
			for (i = 0; i < rel; i++) {
				/* Carve out buffers from complete memory
				 * chunk allocated from mempool */
				/* TODO Check of dma memory alignment
				 * (for performance) */
				mbuf = (dpaa2_mbuf_pt)h_bpool_mem;
				bufs[i] = (uint64_t)(h_bpool_mem) +
					bp_list->buf_pool[pool_index].meta_data_size;

				memset(mbuf, 0, sizeof(odp_packet_hdr_t));
				mbuf->priv_meta_off = DPAA2_MBUF_HW_ANNOTATION +
							DPAA2_MBUF_SW_ANNOTATION;
				mbuf->head	= (uint8_t *)bufs[i] + mbuf->priv_meta_off;
				mbuf->data	= mbuf->head + dpaa2_mbuf_head_room;
				mbuf->bpid	= bpid;
				mbuf->end_off	= bpid_info[mbuf->bpid].size;
				mbuf->frame_len  = mbuf->end_off - dpaa2_mbuf_head_room;
				mbuf->tot_frame_len = mbuf->frame_len;
				_odp_buffer_type_set(mbuf, ODP_EVENT_PACKET);
				if (bpid_info[bpid].odp_user_area)
					mbuf->user_priv_area = h_bpool_mem + sizeof(odp_packet_hdr_t);

				mbuf->atomic_cntxt = INVALID_CNTXT_PTR;
				DPAA2_DBG2(BUF, "Releasing memory: %llx",
					bufs[i]);
				h_bpool_mem += buf_size;
				DPAA2_MODIFY_VADDR_TO_IOVA(bufs[i], uint64_t);

			}
			DPAA2_INFO(BUF, "QBMan SW Portal 0x%p\n", swp);
			do {
				/* Release buffer/s into the BMAN */
				ret = qbman_swp_release(swp, &releasedesc,
						bufs, rel);
			} while (ret == -EBUSY);
			count += rel;
			DPAA2_DBG(BUF, "Released %d buffers\n", count);
		}

		DPAA2_INFO(BUF, "Created %u bufs with bpid: %d",
			num_bufs, bpid);
	}

	/* Add into the global buffer pool list. We will keep all the
	 * buffer pool id's, sizes and the memory taken from the memory pool
	 * in this global bp list. */
	dpaa2_add_bp_list(bp_list);

	return (void *)bp_list;
}

static inline uint64_t mfatb(void)
{
	uint64_t ret, ret_new, timeout = 200;
	asm volatile ("mrs %0, cntvct_el0" : "=r" (ret));
	asm volatile ("mrs %0, cntvct_el0" : "=r" (ret_new));
	while (ret != ret_new && timeout--) {
		ret = ret_new;
		asm volatile ("mrs %0, cntvct_el0" : "=r" (ret_new));
	}
	if (!timeout && (ret != ret_new)) {
		DPAA2_ERR(BUF, "BUG: cannot spin\n");
		abort();
	}
	return ret * 64;
}

/* Spin for a few cycles without bothering the bus */
static inline void cpu_spin(int cycles)
{
	uint64_t now = mfatb();
	while (mfatb() < (now + cycles))
	;
}

/*!
 * @details	Allocate DPAA2 buffer from given buffer pool.
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
dpaa2_mbuf_pt dpaa2_mbuf_alloc_from_bpid(uint16_t bpid)
{
	dpaa2_mbuf_pt mbuf = NULL;
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	int ret = 0;
	uint64_t buf;
	struct bpsp *pool = th_bpsp_info[bpid];
	int32_t try_count;

	DPAA2_TRACE(BUF);
	if (bpid_info[bpid].stockpile) {
		/*if the stockpile for this bpid for this thread is not available,
		it will allocate the stockpile for this thread */
		if (odp_unlikely(!pool)) {
			th_bpsp_info[bpid] = dpaa2_calloc(NULL, 1,
						sizeof(struct bpsp), 0);
			if (!th_bpsp_info[bpid]) {
				DPAA2_ERR(BUF, "Fail to create stockpile pool memory");
				return NULL;
			}
			pool = th_bpsp_info[bpid];

			pool->size = bpid_info[bpid].size;
			pool->sp = dpaa2_calloc(NULL, BMAN_STOCKPILE_SZ, 8, 0);
			if (!pool->sp) {
				DPAA2_ERR(BUF, "Fail to allocate stockpile memory");
				dpaa2_free(pool);
				th_bpsp_info[bpid] = NULL;
				return NULL;
			}
			pool->sp_fill = 0;
		}

		/* Only need a h/w op if we'll hit the low-water thresh */
		if (pool->sp_fill < BMAN_STOCKPILE_LOW) {
			/* refill stockpile with max amount, but if max amount
			 * isn't available, try amount the user wants */
			/* Acquire the buffer from BMAN */
			try_count = 50000;/*Number of tries to get buffer*/
			do {
				ret = qbman_swp_acquire(swp, bpid,
						pool->sp + pool->sp_fill, BMAN_STOCKPILE_SIZE);
			} while (ret == -EBUSY);
			if (ret <= 0) {
				/* Maybe buffer pool has less than 7 buffers */
try_again:
				do {
					ret = qbman_swp_acquire(swp, bpid,
							pool->sp + pool->sp_fill, 1);
				} while (ret == -EBUSY);
				/* If still No buffer, retuen NULL if we
				   don't have any in stockpile */
				if (ret <= 0) {
					if (pool->sp_fill == 0) {
						DPAA2_DBG(BUF, "Buffer alloc(bpid %d)fail: err: %x",
										bpid, ret);
						cpu_spin(200);
						if (try_count) {
							try_count--;
							goto try_again;
						}
						return NULL;
					}
					goto provide_rem_buf;
				}
			}
#ifdef DPAA2_MBUF_DEBUG
			else {
				unsigned int i;

				for (i = 0; i < BMAN_STOCKPILE_SZ; i++)
					printf("\n BUF %d - %lx", i, *(pool->sp + i));
			}
#endif
			pool->sp_fill += ret;
		}
provide_rem_buf:
		pool->sp_fill--;

		buf = *((uint64_t *)pool->sp + pool->sp_fill);
		if (buf == 0) {
			DPAA2_ERR(BUF, "Buf alloc(bpid %d)fail: qbman ret: %x ",
				  bpid, ret);
			return NULL;
		}
	} else {
		try_count = 50000;/*Number of tries to get buffer*/
alloc_try_again:
		/* non stockpile use case */
		do {
			/* Acquire the buffer from BMAN */
			ret = qbman_swp_acquire(swp, bpid, &buf, 1);
		} while (ret == -EBUSY);
		if (ret <= 0) {
			DPAA2_DBG(BUF, "Buffer alloc(bpid %d)fail: err: %x",
				bpid, ret);
			cpu_spin(200);
			if (try_count) {
				try_count--;
				goto alloc_try_again;
			}
			return NULL;
		}
	}
	DPAA2_MODIFY_IOVA_TO_VADDR(buf, uint64_t);

	DPAA2_INFO(BUF, "Buffer acquired: %lx", buf);

	mbuf = DPAA2_INLINE_MBUF_FROM_BUF(buf, bpid_info[bpid].meta_data_size);

	dpaa2_inline_mbuf_reset(mbuf);
	_odp_buffer_type_set(mbuf, ODP_EVENT_PACKET);

	mbuf->head = (uint8_t *)(buf + DPAA2_FD_PTA_SIZE +
				DPAA2_MBUF_HW_ANNOTATION);
	mbuf->data = mbuf->head + dpaa2_mbuf_head_room;
	mbuf->priv_meta_off = DPAA2_FD_PTA_SIZE + DPAA2_MBUF_HW_ANNOTATION;
	mbuf->hw_annot = (uint64_t)(mbuf->head - DPAA2_MBUF_HW_ANNOTATION);
	mbuf->frame_len = mbuf->end_off - (mbuf->head - mbuf->data);
	mbuf->tot_frame_len = mbuf->frame_len;
	mbuf->opr.orpid = INVALID_ORPID;

	return mbuf;
}

/*!
 * @details	Free a given DPAA2 buffer
 *
 * @param[in]	mbuf - dpaa2 buffer to be freed
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_free(dpaa2_mbuf_pt mbuf)
{
	struct qbman_release_desc releasedesc;
	dpaa2_mbuf_pt tmp = mbuf, seg;
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	uint64_t buf;
	int ret = 0;
	struct bpsp *pool;
	uint32_t is_sgt_buf = true;

	DPAA2_TRACE(BUF);

	IF_LOG_LEVEL(DPAA2_LOG_INFO) {
		dpaa2_mbuf_dump_pkt(stdout, mbuf);
		printf("\n");
	}
	/* Note: Resetting of Buffer context is not required as
	   it will be done at next odp_schedule / odp_packet_alloc call
	 */
	if (mbuf->index != INVALID_PORTAL_INDEX &&
	    ANY_ATOMIC_CNTXT_TO_FREE(mbuf)) {
		qbman_swp_dqrr_consume(swp, GET_HOLD_DQRR_PTR(mbuf->index));
		MARK_HOLD_DQRR_PTR_INVALID(mbuf->index);
	} else if (mbuf->opr.orpid != INVALID_ORPID) {
		struct eqcr_entry eqcr = {0};
		struct qbman_fd fd;

		eqcr.orpid = mbuf->opr.orpid;
		eqcr.seqnum = mbuf->opr.seqnum;
		eqcr.verb |= (1 << EQCR_ENTRY_ORDER_RES_ENABLE);
		/*calling fake enqueue command to fill ORP gaps*/
		ret = qbman_swp_enqueue(swp, (struct qbman_eq_desc *)&eqcr, &fd);
		if (ret != 0) {
			DPAA2_DBG(ETH, "Error while filling ORP gaps\n");
		}
	}

	seg = DPAA2_INLINE_MBUF_FROM_BUF((mbuf->hw_annot - DPAA2_FD_PTA_SIZE),
					 bpid_info[mbuf->bpid].meta_data_size);
	tmp = seg;
	while (tmp != NULL) {
		if (mbuf->bpid != INVALID_BPID) {
			pool = th_bpsp_info[mbuf->bpid];
			/*if stockpile is not available for this thread, directly release the
			buffers to qbman*/
			if (pool == NULL) {
				/* Create a release descriptor required for releasing
				 * buffers into BMAN */
				qbman_release_desc_clear(&releasedesc);
				qbman_release_desc_set_bpid(&releasedesc,
							    mbuf->bpid);
				if (is_sgt_buf) {
					buf = (uint64_t)(tmp->head -
						DPAA2_MBUF_HW_ANNOTATION -
						DPAA2_FD_PTA_SIZE);
					is_sgt_buf = false;
				} else {
					buf = (uint64_t)tmp->head;
				}
				DPAA2_INFO(BUF, "Releasing buffer: %p\n",
								(void *)buf);
				DPAA2_INFO(BUF, "QBMan SW Portal %p\n", swp);
				do {
					/* Release buffer into the BMAN */
					ret = qbman_swp_release(swp,
								&releasedesc, &buf, 1);
				} while (ret == -EBUSY);
				if (ret) {
					DPAA2_ERR(BUF, "Unable to free data memory "
						"of buffer\n");
					goto release_done;
				}
			} else {
			/* This needs some explanation. Adding the given buffers may take the
			 * stockpile over the threshold, but in fact the stockpile may already
			 * *be* over the threshold if a previous release-to-hw attempt had
			 * failed. So we have 3 cases to cover;
			 *   1. we add to the stockpile and don't hit the threshold,
			 *   2. we add to the stockpile, hit the threshold and release-to-hw,
			 *   3. we have to release-to-hw before adding to the stockpile
			 *	(not enough room in the stockpile for case 2).
			 * Our constraints on thresholds guarantee that in case 3, there must be
			 * at least 8 bufs already in the stockpile, so all release-to-hw ops
			 * are for 8 bufs. Despite all this, the API must indicate whether the
			 * given buffers were taken off the caller's hands, irrespective of
			 * whether a release-to-hw was attempted. */
			/* Add buffers to stockpile if they fit */
			if ((uint32_t)pool->sp_fill < BMAN_STOCKPILE_SZ) {
				if (is_sgt_buf) {
					pool->sp[pool->sp_fill] = (uint64_t)
						(tmp->head -
						DPAA2_MBUF_HW_ANNOTATION -
						DPAA2_FD_PTA_SIZE);
					is_sgt_buf = false;
				} else {
					pool->sp[pool->sp_fill] =
							(uint64_t)tmp->head ;
				}
				DPAA2_INFO(BUF, "Buffer released: %p", (void *)buf);
				pool->sp_fill++;
			}
			/* Do hw op if hitting the high-water threshold */
			if ((uint32_t)pool->sp_fill >= BMAN_STOCKPILE_HIGH) {
				/* Create a release descriptor required for releasing
				 * buffers into BMAN */
				qbman_release_desc_clear(&releasedesc);
				qbman_release_desc_set_bpid(&releasedesc, mbuf->bpid);
				DPAA2_INFO(BUF, "QBMan SW Portal 0x%p\n", swp);
				do {
					/* Release buffer into the BMAN */
					ret = qbman_swp_release(swp,
								&releasedesc,
								pool->sp + (pool->sp_fill - BMAN_STOCKPILE_SIZE),
								BMAN_STOCKPILE_SIZE);
				} while (ret == -EBUSY);
				if (ret) {
					DPAA2_ERR(BUF, "Unable to free data memory "
						"of buffer\n");
					goto release_done;
				}
				pool->sp_fill -= BMAN_STOCKPILE_SIZE;
			}
			}
		}
release_done:
		if (tmp->flags & DPAA2BUF_ALLOCATED_SHELL)
			dpaa2_mbuf_free_shell(tmp);
		tmp = tmp->next_sg;
	}
}


/*!
 * @details	Free a DPAA2 buffer shell without the data frame. It will also
 *		free the aiop_cntx if the DPAA2BUF_AIOP_CNTX_VALID is set.
 *
 * param[in]	dpaa2 buffer shell pointer to be freed.
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_free_shell(
		dpaa2_mbuf_pt mbuf)
{
	DPAA2_TRACE(BUF);

	if (mbuf) {
		if (mbuf->flags & DPAA2BUF_AIOP_CNTX_VALID)
			dpaa2_aiop_cntx_free(mbuf->drv_priv_cnxt);
		if (odp_unlikely(!(mbuf->flags & DPAA2BUF_ALLOCATED_SHELL))) {
			DPAA2_INFO(BUF, "May be an inline buffer");
			return;
		}
#ifdef DPAA2_MBUF_MALLOC
		dpaa2_free(mbuf);
#else
		dpaa2_mpool_relblock(dpaa2_mbuf_shell_mpool, mbuf);
#endif
	}
}


/*!
 * @details	Get the maximum number of buffer pools
 *
 * @returns	Maximum number of buffer pools available to the user
 *
 */
uint32_t dpaa2_mbuf_get_max_pools(void)
{
	struct dpbp_node *dpbp_node;
	int num;

	DPAA2_TRACE(BUF);

	dpbp_node = g_dpbp_list;
	num = 0;

	while (dpbp_node) {
		dpbp_node = dpbp_node->next;
		num++;
	}

	DPAA2_INFO(BUF, "Maximum number of pools: %d", num);
	return num;
}


/*!
 * @details	Clean-up routine for DPAA2 buffer library. This API should be
 *		called when IO context is affined to the thread.
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_finish(void)
{
	struct dpaa2_bp_list *bp_list, *temp;

	DPAA2_TRACE(BUF);

	bp_list = g_bp_list;

	/* De-initialize all the buffer pool lists */
	while (bp_list) {
		dpaa2_mbuf_pool_list_deinit(bp_list);

		temp = bp_list->next;
		dpaa2_free(bp_list);
		bp_list = temp;
	}

	/* De-initialize the dpbp's */
	dpaa2_mbuf_dpbp_disable_all();

	DPAA2_DBG(BUF, "Disabled buffer resources");

}
