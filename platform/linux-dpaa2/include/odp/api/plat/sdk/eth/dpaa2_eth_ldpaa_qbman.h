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

/* Enqueue with response only, if rejected
   and enqueue target type is QD*/
#define QBMAN_RESP_IF_REJ_QUE_DEST	0x12
#define QBMAN_DQRR_STAT_FQ_ODP_ENABLE	0x02
#define EQCR_ENTRY_ORDER_RES_ENABLE	0x02
#define ENABLE_DCA	0x80
#define INVALID_ORPID	0xFFFF

#if 0
struct dqrr_entry {
        uint8_t         verb;
        uint8_t         stat;
        uint16_t        seqnum; /*!< Order Restoration Sequence Number*/
        uint16_t        orpid;  /*!< Order Restoration Point ID */
        uint8_t         resrvd1;
        uint8_t         token;
        uint32_t        fqid;
        uint32_t        reserved2;
        uint32_t        fq_byte_count;
        uint32_t        fq_frame_count;
        uint64_t        fqd_ctx;
	uint64_t	fd;
} __attribute__((aligned(64), packed));

struct eqcr_entry {
        uint8_t         verb;
        uint8_t         dca;      /*!< DQRR Discrete Consumption Acknowledgment */
        uint16_t        seqnum;   /*!< Order Restoration Sequence Number*/
        uint16_t        orpid;    /*!< Order Restoration Point ID*/
        uint16_t        resrvd1;
        uint32_t        tgtid;    /*!< Enqueue Target ID*/
        uint32_t        tag;      /*!< Enqueue command Tag*/
        uint16_t        qdbin;    /*!< Queuing Destination Bin*/
        uint8_t         qpri;     /*!< Bits 7-4:Reserved; Bits 3-0:Queuing Priority*/
        uint8_t         resrvd2;
        uint16_t        resrvd3;
        uint8_t         wae;      /*!< Bits 7-1:Reserved; Bit 0:Write Allocate Enable*/
        uint8_t         rspid;    /*!< Response ID; Used only if VERB bits 1-0=1*/
        uint64_t        rsp_addr; /*!< Response Address.Used if VERB bits 1-0=1*/
} __attribute__((packed));
#endif

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
