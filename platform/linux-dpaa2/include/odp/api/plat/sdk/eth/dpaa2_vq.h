/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_vq.h
 * @description	DPAA2 VQ structure for internal usages.
 */

#ifndef _DPAA2_VQ_H_
#define _DPAA2_VQ_H_

/*Standard header files*/
#include <stddef.h>

/*DPAA2 header files*/
#include <odp/api/plat/sdk/main/dpaa2_dev.h>
#include <odp/api/hints.h>
#include <odp/api/std_types.h>

/*MC header files*/
#include <fsl_dpni.h>
/*QBMAN header files*/
#include <fsl_qbman_portal.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *(dpaa2_vq_cb_dqrr_t)(
		struct qbman_swp *qm,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr);
struct dpaa2_qman_fq {
	dpaa2_vq_cb_dqrr_t *cb; /*! <Callback for handling the dqrr output*/
	int cgr_groupid;
};
/*!
 * The DPAA2 Virtual Queue structure for ethernet driver.
 */
struct dpaa2_vq {
	struct dpaa2_qman_fq qmfq;
	struct dpaa2_dev *dev;	/*! <parent dpaa2 device pointer - required for aggr*/
	enum dpaa2_fq_type fq_type;/*!< Type of this queue i.e. RX or TX
					or TX-conf/error */
	int32_t eventfd;	/*!< Event Fd of this queue */
	uint32_t fqid;		/*!< Unique ID of this queue */
	uint8_t tc_index;	/*!< traffic class identifier */
	uint16_t flow_id;	/*!< To be used by DPAA2 frmework */
	uint64_t usr_ctxt;

	struct qbman_result *dq_storage[2]; /*!< Per VQ storage used in case
			* of DPAA2_PREFETCH_MODE*/
	int toggle; /*!< Toggle to handle the per VQ DQRR storage
			* required to be used */
	uint8_t dqrr_idx; /* The index of the per VQ DQRR storage enrty which
			* is being processed */
	uint8_t		sync;	/*!< Whether queue is atmoic or ordered */
};


#ifdef __cplusplus
}
#endif

#endif /* _DPAA2_VQ_H_ */
