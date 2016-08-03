/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_eth_ldpaa_qbman.h
 * @description	Structure & MACRO definitions to support qbman procesing.
 */

#ifndef _DPAA2_ETH_LDPAA_QBMAN_H_
#define _DPAA2_ETH_LDPAA_QBMAN_H_

#include <dpaa2_memconfig.h>

static inline void dpaa2_qbman_pull_desc_channel_set(
		struct qbman_pull_desc *pulldesc,
		uint32_t num,
		uint16_t ch_id,
		struct qbman_result *dq_storage)
{
	qbman_pull_desc_clear(pulldesc);
	qbman_pull_desc_set_numframes(pulldesc, num);
	qbman_pull_desc_set_channel(pulldesc, ch_id,
		qbman_pull_type_active_noics);
	qbman_pull_desc_set_storage(pulldesc, dq_storage,
		(dma_addr_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), TRUE);
}

static inline void dpaa2_qbman_pull_desc_set(
		struct qbman_pull_desc *pulldesc,
		uint32_t num,
		uint32_t fqid,
		struct qbman_result *dq_storage)
{
	qbman_pull_desc_clear(pulldesc);
	qbman_pull_desc_set_numframes(pulldesc, num);
	qbman_pull_desc_set_fq(pulldesc, fqid);
	qbman_pull_desc_set_storage(pulldesc, dq_storage,
		(dma_addr_t)(DPAA2_VADDR_TO_IOVA(dq_storage)), TRUE);
}

#endif /*_DPAA2_ETH_LDPAA_QBMAN_H_*/
