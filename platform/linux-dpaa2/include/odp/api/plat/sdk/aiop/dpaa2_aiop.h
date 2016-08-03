/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	dpaa2_aiop.h
 *
 * @brief	AIOP device related macros & functions support for DPAA2 device
 *	framework based applications.
 *
 * @addtogroup	DPAA2_AIOP
 * @ingroup	DPAA2_DEV
 * @{
 */

#ifndef _DPAA2_AIOP_H_
#define _DPAA2_AIOP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <dpaa2_dev.h>
#include <dpaa2_malloc.h>

/*!
 * Buffer specific information for AIOP (this will go with every packet).
 * In the DPAA2 buffer shell 'aiop_cnxt' will point to this structure
 */
struct aiop_buf_info {
	uint64_t flc; /*!< Flow context from FD */
	uint32_t frc; /*!< Frame context from FD */
	uint8_t error; /*!< Error field from FD */
} __attribute__((aligned(16)));

/*!
 *  Statistics for an AIOP device.
 */
struct dpaa2_aiop_stats {
	uint64_t rx_packets;  /*!< Total number of successfully
				received packets. */
	uint64_t tx_packets;  /*!< Total number of successfully
				transmitted packets.*/
	uint64_t rx_bytes;    /*!< Total number of successfully
				received bytes. */
	uint64_t tx_bytes;    /*!< Total number of successfully
				transmitted bytes. */
	uint64_t rx_errors;   /*!< Total number of erroneous received packets.*/
	uint64_t tx_errors;   /*!< Total number of failed transmitted packets.*/
	uint64_t rx_dropped;  /*!< Total number of drops in received side. */
	uint64_t tx_dropped;  /*!< Total number of drops in transmitted side. */
};


/*!
 * @details	Get I/O statistics of an AIOP device. Setting
 *		reset = 1, will reset all the stats.
 *
 * @param[in]	dev - Pointer to DPAA2 AIOP device
 *
 * @param[out]	aiop_stats - Pointer to DPAA2 AIOP device statistics structure
 *
 * @param[in]	reset - reset = 1 will reset all the counters to 0
 *
 */
extern void dpaa2_aiop_stats_get(
		struct dpaa2_dev *dev,
		struct dpaa2_aiop_stats *aiop_stats,
		int32_t reset);

/*!
 * @details	Allocates the AIOP context
 *
 * @returns	AIOP context i.e. AIOP buffer info pointer; NULL on failure
 *
 */
static inline struct aiop_buf_info *dpaa2_aiop_cntx_alloc(void)
{
	DPAA2_TRACE(CMD);

	return dpaa2_calloc(NULL, 1, sizeof(struct aiop_buf_info), 0);
}

/*!
 * @details	Free's the AIOP context
 *
 * @param[in]	AIOP context i.e. AIOP buffer info pointer
 *
 * @return	none
 *
 */
static inline void dpaa2_aiop_cntx_free(
		struct aiop_buf_info *aiop_cntx)
{
	DPAA2_TRACE(CMD);

	dpaa2_free(aiop_cntx);
}

/*!
 * @details	Get the AIOP device ID. The device ID shall be passed by GPP
 *		to the AIOP using CMDIF commands.
 *
 * @param[in]	dev - dpaa2 AIOP device
 *
 * @return	none
 *
 */
int get_aiop_dev_id(struct dpaa2_dev *dev);


/*! @} */
#endif /* _DPAA2_AIOP_H_ */
