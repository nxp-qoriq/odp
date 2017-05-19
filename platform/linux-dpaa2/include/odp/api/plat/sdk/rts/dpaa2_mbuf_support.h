/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_mbuf_support.h
 *
 * @brief		Extended Buffer management library services.
 */

#ifndef _DPAA2_MBUF_SUPPORT_H_
#define _DPAA2_MBUF_SUPPORT_H_

#ifdef __cplusplus
extern "C" {
#endif

/* DPAA2 header files */
#include <odp/api/plat/sdk/common/dpaa2_cfg.h>
#include <odp/api/plat/sdk/rts/dpaa2_mbuf.h>

/* Invalid context pointer value */
#define INVALID_CNTXT_PTR	((void *)0xFFFFFFFF)

/* Invalid context pointer value */
#define INVALID_PORTAL_INDEX	0xff

/* get the first pools bpid */
int dpaa2_mbuf_pool_get_bpid(void *bplist);

/*!
 * @details     Reset a INLINE DPAA2 mbuf shell to default values
 *
 * @param[in]   mbuf - dpaa2 buffer
 *
 * @returns     none
 *
 */
static inline void dpaa2_inline_mbuf_reset(
		struct dpaa2_mbuf *mbuf)
{
	mbuf->flags &= ~(DPAA2BUF_SEC_CNTX_VALID | DPAA2BUF_AIOP_CNTX_VALID);
	mbuf->eth_flags = 0;
	/* No Atomic context for allocated buffer */
	mbuf->atomic_cntxt = INVALID_CNTXT_PTR;

	mbuf->next_sg = 0;
	/*todo - need to reset hash_val, timestamp, destructor also,
	however they are not in use currently*/
	mbuf->index = INVALID_PORTAL_INDEX; /*Setting to invalid portal index*/
}


#ifdef __cplusplus
}
#endif

#endif	/* _DPAA2_MBUF_SUPPORT_H_ */
