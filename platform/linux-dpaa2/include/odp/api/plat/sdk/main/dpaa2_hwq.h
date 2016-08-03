/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_hwq.h
 * @description	Function for DPAA2 Software Frame Queue
 */

#ifndef _DPAA2_HWQ_H_
#define _DPAA2_HWQ_H_

#ifdef __cplusplus
extern "C" {
#endif

/* DPAA2 include files */
#include <odp/api/plat/sdk/main/dpaa2_dev.h>

/*!
 * @details	Attach the Frame Queue to a concentrator
 *
 * @param[in]	h_dpaa2_hwq - Handle to DPAA2 Frame Queue
 *
 * @param[in]	vq_param - DPAA2 VQ param configuration
 *
 * @returns	DPAA2_SUCCESS on success, DPAA2_FAILURE otherwise
 *
 */
int dpaa2_attach_frameq_to_conc(
		void *h_dpaa2_hwq,
		struct dpaa2_vq_param *vq_param);

int dpaa2_detach_frameq_from_conc(void *h_dpaa2_hwq);

/*!
 * @details	Get a FREE DPAA2 Frame Queue
 *
 * @returns	Handle to the ACQUIRED DPAA2 Frame Queue, NULL incase there
 *		are no FREE Frame Queues
 *
 */
void *dpaa2_get_frameq(void);

/*!
 * @details	Put the Frame Queue back into the FREE list
 *
 * @param[in]	h_dpaa2_hwq - Handle to DPAA2 Frame Queue
 *
 * @returns	none
 *
 */
void dpaa2_put_frameq(void *h_dpaa2_hwq);

/*!
 * @details	Receive a packet from a DPAA2 Frame Queue
 *
 * @param[in]	h_dpaa2_hwq - Handle to DPAA2 Frame Queue
 *
 * @param[in]	buf_list - List of pointers of dpaa2_mbuf's. Received buffers
 *		will be stored in this list.
 *
 * @param[in]	num - number of buffers to receive
 *
 * @returns	number of buffers received, DPAA2_FAILURE on failure
 *
 */
int dpaa2_hwq_recv(void *h_dpaa2_hwq,
		  struct dpaa2_mbuf *buf_list[],
		int num);

/*!
 * @details	Send a packet to a DPAA2 Frame Queue
 *
 * @param[in]	h_dpaa2_hwq - Handle to DPAA2 Frame Queue
 *
 * @param[in]	buf_list - List of pointers of dpaa2_mbuf's to transmit
 *
 * @param[in]	num - number of buffers to transmit
 *
 * @returns	number of buffers transmitted, DPAA2_FAILURE on failure
 *
 */
int dpaa2_hwq_xmit(void *h_dpaa2_hwq,
		  struct dpaa2_mbuf *buf_list[],
		int num);

#ifdef __cplusplus
}
#endif

#endif /* _DPAA2_HWQ_H_ */
