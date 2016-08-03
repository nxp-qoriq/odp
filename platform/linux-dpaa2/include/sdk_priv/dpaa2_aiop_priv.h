/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_aiop_priv.h
 * @description	Private function & definitions for DPAA2 AIOP type Device
 */

#ifndef _DPAA2_AIOP_PRIV_H_
#define _DPAA2_AIOP_PRIV_H_

#ifdef __cplusplus
extern "C" {
#endif

/*DPAA2 header files*/
#include <dpaa2_dev.h>
#include <dpaa2_dev_priv.h>

/* MC header files */
#include <fsl_dpci.h>

/* QBMAN header files */
#include <fsl_qbman_base.h>

#define AIOP_MAX_FQ_PAIRS DPCI_PRIO_NUM

/*AIOP specific macros to define operations on FD*/
#define DPAA2_AIOP_SET_FD_FRC(fd, aiop_cnxt)			\
	fd->simple.frc = aiop_cnxt->frc;
#define DPAA2_AIOP_SET_FD_FLC(fd, aiop_cnxt)			\
	fd->simple.flc_lo =					\
		lower_32_bits((uint64_t)(aiop_cnxt->flc));	\
	fd->simple.flc_hi =					\
		upper_32_bits((uint64_t)(aiop_cnxt->flc));
#define DPAA2_AIOP_SET_FD_ERR(fd, aiop_cnxt) fd->simple.ctrl |= aiop_cnxt->error;
#define DPAA2_AIOP_GET_FRC(fd)	(fd->simple.frc)
#define DPAA2_AIOP_GET_FLC(fd)	((uint64_t)(fd->simple.flc_hi) << 32) + fd->simple.flc_lo;
#define DPAA2_AIOP_GET_ERR(fd)	(uint8_t)(fd->simple.ctrl & 0x000000FF)

/*!
 * The DPAA2 Virtual Queue structure for AIOP driver.
 */
struct aiop_vq {
	int32_t eventfd; /*!< Event Fd of this queue */
	uint16_t fqid;	/*!< Unique ID of this queue */
};

/*!
 * Information private to the AIOP device
 */
struct dpaa2_aiop_priv {
	int id; /*!< DPCI ID */
	uint8_t num_fq_pairs; /*!< Number of FQ pairs */
	struct rx_fq_config { /*!< Structure for RX FQ */
		bool_t use_dpio; /*!< DPIO is to be used for notifications
				      or not */
		bool_t use_dpcon; /*!< DPCON to be used as aggregation device
				       for this RX FQ or not */
		uint16_t dpio_id; /*!< DPIO's ID in case it is being used for
				       notification */
		uint16_t dpcon_id; /*!< DPCON's ID in case it the RX FQ is used
					in aggregation */
		uint8_t prio; /*!< Priority of the RX FQ */
		uint64_t rx_user_ctx; /*!< User specific Rx context */
	} rx_fq[AIOP_MAX_FQ_PAIRS];
};

/*!
 * @details	AIOP driver API to register to DPAA2 framework. It will be
 *		called by DPAA2 and will register its device driver to DPAA2.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_driver_init(void);

/*!
 * @details	AIOP driver API to unregister to DPAA2 framework. It will be
 *		called by DPAA2 and will unregister its device driver to DPAA2.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_driver_exit(void);

/*!
 * @details	AIOP driver default configuration API.
 *
 * @param[in]	dev - Pointer to DPAA2 AIOP device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_defconfig(
		struct dpaa2_dev *dev);

/*!
 * @details	AIOP driver probe function to initialize the device.
 *
 * @param[in]	dev - Pointer to DPAA2 AIOP device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_probe(
		struct dpaa2_dev *dev, const void *data);

/*!
 * @details	AIOP driver remove function to remove the device.
 *
 * @param[in]	dev - Pointer to DPAA2 AIOP device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_remove(
		struct dpaa2_dev *dev);

/*!
 * @details	Start a AIOP device for use of RX/TX.
 *
 * @param[in]	dev - Pointer to DPAA2 AIOP device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_start(
		struct dpaa2_dev *dev);

/*!
 * @details	Setup a RX virtual queues to a AIOP device.
 *
 * @param[in]	dev - Pointer to DPAA2 AIOP device
 *
 * @param[in]	vq_cfg - Pointer to VQ configuration
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_setup_rx_vq(
		struct dpaa2_dev *dev,
		uint8_t vq_index,
		struct dpaa2_vq_param *vq_cfg);

/*!
 * @details	Setup a TX virtual queues to a AIOP device.
 *
 * @param[in]	dev - Pointer to DPAA2 AIOP device
 *
 * @param[in]	num - Number of TX queues
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_setup_tx_vq(
		struct dpaa2_dev *dev,
		uint32_t num, uint32_t action);

/*!
 * @details	Disable a AIOP device for use of RX/TX.
 *
 * @param[in]	dev - Pointer to DPAA2 AIOP device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_stop(
		struct dpaa2_dev *dev);

/*!
 * @details	Receives frames from given DPAA2 device.
 *
 * @param[in]	vq - Pointer to the virtual Queue of a device
 *
 * @param[in]	buf - Pointer to DPAA2 buffer which will be passed to user
 *
 * @returns	Number of packets received if success; error code otherwise.
 *
 */
int32_t dpaa2_aiop_rcv(
		void *vq,
		dpaa2_mbuf_pt *buf);

/*!
 * @details	Transmits frames to given DPAA2 device.
 * @param[in]	vq - Pointer to the virtual Queue of a device
 *
 * @param[in]	buf - Pointer to DPAA2 buffers which are to be transmited.
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_xmit(void *vq,
		dpaa2_mbuf_pt buf);

dpaa2_mbuf_pt dpaa2_aiop_fd_to_mbuf(
		const struct qbman_fd *fd);

void dpaa2_aiop_mbuf_to_fd(
		dpaa2_mbuf_pt mbuf,
		struct qbman_fd *fd);

#ifdef __cplusplus
}
#endif

#endif /* _DPAA2_AIOP_PRIV_H_ */
