/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_mbuf_priv_ldpaa.h
 *
 * @brief		Buffer management requirement for LDPAA.
 */

#ifndef _DPAA2_MBUF_PRIV_LS_H_
#define _DPAA2_MBUF_PRIV_LS_H_

#ifdef __cplusplus
extern "C" {
#endif

/* MC header files */
#include <fsl_dpbp.h>
#include <fsl_mc_sys.h>
#include <odp/api/plat/sdk/rts/dpaa2_mbuf_support.h>

struct dpaa2_bp_list;

/*!
 * Structure representing a private buffer pool
 */
struct buf_pool {
	uint32_t size;
	uint32_t num_bufs;
	uint16_t odp_user_area;
	uint16_t meta_data_size;
	uint32_t buf_size;
	uint16_t bpid;
	uint8_t *h_bpool_mem;
	struct dpbp_node *dpbp_node;
};

/* Stockpile build constants. The _LOW value: when bman_acquire() is called and
 * the stockpile fill-level is <= _LOW, an acquire is attempted from h/w but it
 * might fail (if the buffer pool is depleted). So this value provides some
 * "stagger" in that the bman_acquire() function will only fail if lots of bufs
 * are requested at once or if h/w has been tested a couple of times without
 * luck. The _HIGH value: when bman_release() is called and the stockpile
 * fill-level is >= _HIGH, a release is attempted to h/w but it might fail (if
 * the release ring is full). So this value provides some "stagger" so that
 * ring-access is retried a couple of times prior to the API returning a
 * failure. The following *must* be true;
 *   BMAN_STOCKPILE_HIGH-BMAN_STOCKPILE_LOW > 8
 *     (to avoid thrashing)
 *   BMAN_STOCKPILE_SZ >= 16
 *     (as the release logic expects to either send 8 buffers to hw prior to
 *     adding the given buffers to the stockpile or add the buffers to the
 *     stockpile before sending 8 to hw, as the API must be an all-or-nothing
 *     success/fail.)
 */
#define BMAN_STOCKPILE_SZ   16u /* number of bufs in per-pool cache */
#define BMAN_STOCKPILE_LOW  3u  /* when fill is <= this, acquire from hw */
#define BMAN_STOCKPILE_HIGH 14u /* when fill is >= this, release to hw */
#define BMAN_STOCKPILE_SIZE  7u  /* buffer to be exchanged with hw in one command */

struct bpsp {
	/* stockpile state - NULL unless BMAN_POOL_FLAG_STOCKPILE is set */
	uint64_t *sp;
	uint32_t size;
	uint16_t sp_fill;
};

/*!
 * Structure to store the a dpbp's
 */
struct dpbp_node {
	struct dpbp_node *next;
	struct fsl_mc_io dpbp;
	uint16_t token;
	int dpbp_id;
	char name[8];
};

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
		uint64_t portal_vaddr,
		int dpbp_id);

/*!
 * @details	Disable all the enabled dpbp's.
 *
 * @returns	none
 *
 */
void dpaa2_mbuf_dpbp_disable_all(void);

int dpaa2_mbuf_dpbp_close_all(void);

/*! Global per thread buffer stockpile info */
extern __thread struct bpsp *th_bpsp_info[];

extern struct dpbp_node *g_dpbp_list;

#ifdef __cplusplus
}
#endif

#endif	/* _DPAA2_MBUF_PRIV_LS_H_ */
