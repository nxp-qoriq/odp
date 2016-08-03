/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_hwq_priv.h
 * @description	Private function & definitions for DPAA2 Frame Queue
 */

#ifndef _DPAA2_HWQ_PRIV_H_
#define _DPAA2_HWQ_PRIV_H_

#ifdef __cplusplus
extern "C" {
#endif

/* DPAA2 include files */
#include <dpaa2_lock.h>
#include <dpaa2_vq.h>

/* Maximum number of frame queues supported */
#define MAX_FRAMEQ 64

enum frameq_state_t {
	FRAMEQ_STATE_INVALID, /* Frame queue is invalid */
	FRAMEQ_STATE_FREE, /* Frame queue is free and can be
		* acquired by a user */
	FRAMEQ_STATE_ACQUIRED, /* Frame queue is in use */
	FRAMEQ_STATE_ATTACHED /* Frame queue is in use and attached to conc */
};

/* DPAA2 Frame Queue structure */
struct dpaa2_hwq_t {
	struct dpaa2_vq dummy_vq; /* Dummy vq structure requied in case
		*  frame queue is attached to concentrator. Concentrator uses
		*  this to determine the callback function to FD
		*  to MBUF conversion */
	enum frameq_state_t state; /* State of the queue */
	uint32_t fqid; /* Frame Queue ID */
	struct fsl_mc_io *mc_io; /* MC IO required to communicate with MC */
	uint16_t token; /* MC token also required to communicate with MC */
};

/*!
 * @details	Probe and initialize a DPAA2 Frame Queue.
 *
 * @param[in]	dev - DPAA2 device. In this case it will be DPCI type of device
 *
 * @returns	DPAA2_DEVICE_CONSUMED on success, DPAA2_FAILURE otherwise
 *
 */
int dpaa2_hwq_probe(struct dpaa2_dev *dev,
		   const void *data);

/*!
 * @details	Cleaup all the DPAA2 Frame Queue devices
 *
 * @returns	none
 *
 */
int dpaa2_hwq_close_all(void);

void *dpaa2_hwq_cb_dqrr_fd_to_mbuf(
		struct qbman_swp *qm,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr);

#ifdef __cplusplus
}
#endif

#endif /* _DPAA2_HWQ_PRIV_H_ */
