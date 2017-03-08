/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	dpaa2_aiop.c
 *
 * @brief	AIOP driver implementation. It contains initialization of
 *	AIOP interfaces for DPAA2 device framework based application.
 *
 * @addtogroup	DPAA2_AIOP
 * @ingroup	DPAA2_DEV
 * @{
 */

/*DPAA2 header files*/
#include <odp/api/std_types.h>
#include <dpaa2_common.h>
#include <dpaa2_dev.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_mbuf.h>
#include <dpaa2_mbuf_priv.h>
#include <dpaa2_malloc.h>
#include <dpaa2_aiop.h>
#include "dpaa2_aiop_priv.h"
#include <dpaa2_time.h>
#include <dpaa2_hwq_priv.h>

 /*MC header files*/
#include <fsl_dpci.h>
#include <fsl_dpci_cmd.h>

/* QBMAN header files */
#include <fsl_qbman_portal.h>

/* Device properties */
#define LDPAA_AIOP_DEV_MAJ_NUM		DPCI_VER_MAJOR
#define LDPAA_AIOP_DEV_MIN_NUM		DPCI_VER_MINOR
#define LDPAA_AIOP_DEV_VENDOR_ID	6487
#define LDPAA_AIOP_DEV_NAME		"ldpaa-aiop"

/* The AIOP device driver structure */
struct dpaa2_driver aiop_driver = {
	.name			=	LDPAA_AIOP_DEV_NAME,
	.vendor_id		=	LDPAA_AIOP_DEV_VENDOR_ID,
	.major			=	LDPAA_AIOP_DEV_MAJ_NUM,
	.minor			=	LDPAA_AIOP_DEV_MIN_NUM,
	.dev_type		=	DPAA2_AIOP_CI,
	.dev_probe		=	dpaa2_aiop_probe,
	.dev_shutdown	=	dpaa2_aiop_remove
};

/*!
 * @details	Function to initialize the AIOP driver. This should be called
 *		by DPAA2 framework when it comes up.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_driver_init(void)
{
	DPAA2_TRACE(CMD);

	/* Register AIOP driver to DPAA2 */
	dpaa2_register_driver(&aiop_driver);
	return DPAA2_SUCCESS;
}

/*!
 * @details	Function to un-initialize the AIOP driver. This should be
 *		called by DPAA2 framework when it exits.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_driver_exit(void)
{
	DPAA2_TRACE(CMD);

	/* De-register AIOP driver to DPAA2 */
	dpaa2_unregister_driver(&aiop_driver);
	return DPAA2_SUCCESS;
}

/*!
 * @details	Initializes the AIOP device.
 *
 * @param[in]	dev - Pointer to the AIOP device structure.
 *
 * @param[in]	data - data pointer.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_probe(
		struct dpaa2_dev *dev,
		const void *data ODP_UNUSED)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_aiop_priv *aiop_priv;
	struct fsl_mc_io *dpci;
	struct dpci_attr attr;
	int32_t ret, i;
	struct aiop_vq *vq_mem;

	DPAA2_TRACE(CMD);

	/* Open the dpaa2 device via MC and save the handle for further use */
	dpci = (struct fsl_mc_io *)dpaa2_calloc(NULL, 1,
		sizeof(struct fsl_mc_io), 0);
	if (!dpci) {
		DPAA2_ERR(CMD, "Memory allocation failure");
		return DPAA2_FAILURE;
	}

	dpci->regs = dev_priv->mc_portal;
	ret = dpci_open(dpci, CMD_PRI_LOW, dev_priv->hw_id, &(dev_priv->token));
	if (ret != 0) {
		DPAA2_ERR(CMD, "Opening device failed with err code: %d", ret);
		goto err1;
	}

	/* Get the device attributes */
	ret = dpci_get_attributes(dpci, CMD_PRI_LOW, dev_priv->token, &attr);
	if (ret != 0) {
		DPAA2_ERR(CMD, "Reading device failed with err code: %d", ret);
		goto err2;
	}

	/* In case the number of priorities are 1, give it to DPAA2 frame Queue
	 * module and close the dpci device */
	if (attr.num_of_priorities == 1) {
		/* Close the device. It will be handled by FrameQ module */
		ret = dpci_close(dpci, CMD_PRI_LOW, dev_priv->token);
		if (ret != 0)
			DPAA2_ERR(CMD, "Closing the device failed with "
				"err code: %d", ret);
		dpaa2_free(dpci);

		/* Now call FrameQ probe */
		ret = dpaa2_hwq_probe(dev, data);
		if (ret != DPAA2_SUCCESS)
			return DPAA2_FAILURE;
		else
			return DPAA2_DEV_CONSUMED;
	}

	/*Allocate space for device specific data*/
	aiop_priv = (struct dpaa2_aiop_priv *)dpaa2_calloc(NULL, 1, sizeof(
			struct dpaa2_aiop_priv) + sizeof(struct aiop_vq) *
			(2 * attr.num_of_priorities), 0);
	if (!aiop_priv) {
		DPAA2_ERR(CMD, "Failure to allocate the memory"
			"for private data");
		goto err2;
	}

	/* Save the RX/TX flow information in dpaa2 device */
	aiop_priv->id = attr.id;
	aiop_priv->num_fq_pairs = attr.num_of_priorities;
	vq_mem = (struct aiop_vq *)(aiop_priv + 1);
	for (i = 0; i < attr.num_of_priorities; i++) {
		dev->rx_vq[i] = vq_mem++;
		dev->tx_vq[i] = vq_mem++;
	}

	/* Configure device specific callbacks to the DPAA2 */
	dev_priv->drv_priv = aiop_priv;
	dev_priv->hw = dpci;

	dev->num_rx_vqueues = aiop_priv->num_fq_pairs;
	dev->num_tx_vqueues = aiop_priv->num_fq_pairs;

	DPAA2_INFO(CMD, "Successfully initialized the AIOP device");

	return DPAA2_SUCCESS;

err2:
	/* Close the device in case of error */
	ret = dpci_close(dpci, CMD_PRI_LOW, dev_priv->token);
	if (ret != 0)
		DPAA2_ERR(CMD, "Closing the device failed with err code: %d",
			ret);
err1:
	dpaa2_free(dpci);

	return DPAA2_FAILURE;
}

/*!
 * @details	Un-initializes the AIOP device.
 *
 * @param[in]	dev - Pointer to the AIOP device structure.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_remove(
		struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_aiop_priv *aiop_priv = dev_priv->drv_priv;
	struct fsl_mc_io *dpci = dev_priv->hw;
	int32_t ret;

	DPAA2_TRACE(CMD);

	/* First close the device at underlying layer */
	ret = dpci_close(dpci, CMD_PRI_LOW, dev_priv->token);
	if (ret != 0)
		DPAA2_ERR(CMD, "Closing the device failed with err code: %d",
			ret);

	/* Free the allocated memory for AIOP private data */
	dpaa2_free(aiop_priv);
	dpaa2_free(dpci);

	DPAA2_INFO(CMD, "Sucessfully closed the device");
	return DPAA2_SUCCESS;
}

/*!
 * @details	Activate/Start an already configured AIOP device.
 *
 * @param[in]	dev - Pointer to the AIOP device structure.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_start(
		struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_aiop_priv *aiop_priv = dev_priv->drv_priv;
	struct fsl_mc_io *dpci = dev_priv->hw;
	struct dpci_rx_queue_attr rx_attr;
	struct dpci_tx_queue_attr tx_attr;
	struct aiop_vq *rx_vq, *tx_vq;
	int ret, i;

	DPAA2_TRACE(CMD);

	/* After enabling a DPNI, Device will be ready for RX/TX. */
	ret = dpci_enable(dpci, CMD_PRI_LOW,  dev_priv->token);
	if (ret != 0) {
		DPAA2_ERR(CMD, "Enabling device failed with err code: %d",
			ret);
		return DPAA2_FAILURE;
	}


	for (i = 0; i < aiop_priv->num_fq_pairs; i++) {
		ret = dpci_get_rx_queue(dpci, CMD_PRI_LOW, dev_priv->token, i, &rx_attr);
		if (ret != 0) {
			DPAA2_ERR(CMD, "Reading device failed with"
				"err code: %d", ret);
			goto err;
		}
		rx_vq = (struct aiop_vq *)(dev->rx_vq[i]);
		rx_vq->fqid = rx_attr.fqid;
		DPAA2_INFO(CMD, "rx_vq->fqid: %x", rx_vq->fqid);
		ret = dpci_get_tx_queue(dpci, CMD_PRI_LOW, dev_priv->token, i, &tx_attr);
		if (ret != 0) {
			DPAA2_ERR(CMD, "Reading device failed with"
				"err code: %d", ret);
			goto err;
		}
		tx_vq = (struct aiop_vq *)(dev->tx_vq[i]);
		tx_vq->fqid = tx_attr.fqid;
		DPAA2_INFO(CMD, "tx_vq->fqid: %x", tx_vq->fqid);
	}

	dev->state = DEV_ACTIVE;

	DPAA2_INFO(CMD, "Device started successfully");
	return DPAA2_SUCCESS;
err:
	/* Disable the DPCI */
	ret = dpci_disable(dpci, CMD_PRI_LOW, dev_priv->token);
	if (ret != 0)
		DPAA2_ERR(CMD, "Disabling device failed with err code: %d",
			ret);

	return DPAA2_FAILURE;
}

/*!
 * @details	De-activate/Stop an active AIOP device. This function should be
 *		invoked only, if the deivce is in active state.
 *
 * @param[in]	dev - Pointer to AIOP device structure.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_stop(
		struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpci = dev_priv->hw;
	int32_t ret;

	DPAA2_TRACE(CMD);

	/* Disable the DPCI */
	ret = dpci_disable(dpci, CMD_PRI_LOW, dev_priv->token);
	if (ret != 0) {
		DPAA2_ERR(CMD, "Disabling device failed with err code: %d",
			ret);
		return DPAA2_FAILURE;
	}
	dev->state = DEV_INACTIVE;

	DPAA2_INFO(CMD, "Device stopped successfully");
	return DPAA2_SUCCESS;
}

/*!
 * @details	Create the DPAA2 buffer from the QBMAN FD.
 *
 * @param[in]	fd - FD using which the DPAA2 buffer has to be created.
 *
 * @returns	pointer to the DPAA2 buffer created.
 *
 */
dpaa2_mbuf_pt dpaa2_aiop_fd_to_mbuf(
		const struct qbman_fd *fd)
{
	dpaa2_mbuf_pt mbuf;
	struct aiop_buf_info *aiop_cnxt;

	DPAA2_TRACE(CMD);

	/* Allocate the DPAA2 buffer shell */
	mbuf = dpaa2_mbuf_alloc_shell();
	if (!mbuf) {
		DPAA2_ERR(CMD, "Error in allocating DPAA2 buffer shell");
		return NULL;
	}

	/* Allocate the aiop context memory */
	aiop_cnxt = dpaa2_aiop_cntx_alloc();
	if (!aiop_cnxt) {
		DPAA2_ERR(CMD, "Error in allocating AIOP context");
		dpaa2_mbuf_free_shell(mbuf);
		return NULL;
	}

	/* Set the DPAA2 buffer parameters */
	mbuf->head = (uint8_t *)DPAA2_GET_FD_ADDR(fd);
	mbuf->data = mbuf->head + DPAA2_GET_FD_OFFSET(fd);
	mbuf->frame_len = DPAA2_GET_FD_LEN(fd);
	mbuf->tot_frame_len = mbuf->frame_len;
	mbuf->bpid = DPAA2_GET_FD_BPID(fd);
	mbuf->end_off = mbuf->frame_len;

	aiop_cnxt->frc = DPAA2_AIOP_GET_FRC(fd);
	aiop_cnxt->flc = DPAA2_AIOP_GET_FLC(fd);
	aiop_cnxt->error = DPAA2_AIOP_GET_ERR(fd);

	mbuf->drv_priv_cnxt = aiop_cnxt;
	mbuf->flags |= DPAA2BUF_AIOP_CNTX_VALID;

#ifdef DPAA2_DEBUG
	dpaa2_mbuf_dump_pkt(stdout, mbuf);
	dpaa2_hexdump(stdout, "AIOP Context", mbuf->drv_priv_cnxt,
		sizeof(struct aiop_buf_info));
#endif

	return mbuf;

}

/*!
 * @details	Create the QBMAN FD from the DPAA2 buffer.
 *
 * @param[in]	mbuf - DPAA2 buffer using which the FD has to be created.
 *
 * @param[out]	fd - pointer to the FD.
 *
 * @returns	none
 *
 */
void dpaa2_aiop_mbuf_to_fd(
		dpaa2_mbuf_pt mbuf,
		struct qbman_fd *fd)
{
	struct aiop_buf_info *aiop_cnxt = mbuf->drv_priv_cnxt;

	DPAA2_TRACE(CMD);

	/* Set some of the FD parameters to 0.
	 * For performance reasons do not memset */
	fd->simple.bpid_offset = 0;
	fd->simple.ctrl = 0;

	DPAA2_SET_FD_ADDR(fd, mbuf->head);
	DPAA2_SET_FD_LEN(fd, mbuf->frame_len);
	DPAA2_SET_FD_BPID(fd, mbuf->bpid);
	DPAA2_SET_FD_OFFSET(fd, (mbuf->data - mbuf->head));

	DPAA2_AIOP_SET_FD_FRC(fd, aiop_cnxt);
	DPAA2_AIOP_SET_FD_FLC(fd, aiop_cnxt);
	DPAA2_AIOP_SET_FD_ERR(fd, aiop_cnxt);

#ifdef DPAA2_DEBUG
	dpaa2_hexdump(stdout, "FD created", fd, sizeof(struct qbman_fd));
#endif
}

/*!
 * @details	Packet receive function for AIOP to recevie packet/s
 *		from a given device queue.
 *
 * @param[in]	vq -  Pointer to virtual queue.
 *
 * @param[out]	buf_list - Pointer to list received buffers.
 * @returns	Number of packets received if success; error code otherwise.
 *
 */
int32_t dpaa2_aiop_rcv(
		void *vq,
		dpaa2_mbuf_pt *mbuf)
{
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	struct qbman_result *dq_storage = thread_io_info.dq_storage;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	struct aiop_vq *rx_vq = (struct aiop_vq *)vq;
	int ret, qbman_try_again = 0;
	uint8_t status;

	DPAA2_TRACE(CMD);

	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_fq(&pulldesc, rx_vq->fqid);
	qbman_pull_desc_set_numframes(&pulldesc, 1);
	qbman_pull_desc_set_storage(&pulldesc, dq_storage,
		(dma_addr_t)dq_storage, TRUE);

try_again:
	/*Issue a volatile dequeue command.*/
	ret = qbman_swp_pull(swp, &pulldesc);
	if (ret < 0) {
		if (ret == -EBUSY) {
			DPAA2_INFO(CMD,
				"VDQ command is not issued. QBMAN is busy\n");
			dpaa2_msleep(5);
			qbman_try_again++;
			if (qbman_try_again > 50)
				return DPAA2_FAILURE;
		} else {
			DPAA2_ERR(CMD,
				"VDQ command is not issued. Err Code = %0x\n",
				ret);
			return DPAA2_FAILURE;
		}
		goto try_again;
	}

	/* Loop until the dq_storage is updated with
	 * new token by QBMAN */
	while (!qbman_result_has_new_result(swp, dq_storage))
		;

	/* Check whether Last Pull command is Expired and
	setting Condition for Loop termination */
	if (qbman_result_DQ_is_pull_complete(dq_storage)) {
		/* Check for valid frame. */
		status = (uint8_t)qbman_result_DQ_flags(dq_storage);
		if (odp_unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
			DPAA2_INFO(CMD, "No frame is delivered\n");
			return 0;
		}
	}

	/* Can avoid "qbman_result_is_DQ" check as
	   we are not expecting Notification on this SW-Portal */

	fd = qbman_result_DQ_fd(dq_storage);
	*mbuf = dpaa2_aiop_fd_to_mbuf(fd);

	DPAA2_INFO(CMD, "packet received");
	return 1;
}

/*!
 * @details	Packet transmit Function for AIOP. This function may be used to
 *		transmit multiple packets at a time.
 *
 * @param[in]	vq -  Pointer to virtual queue.
 *
 * @param[in]	buf_list - Pointer to list of pointers to buffer which
 *		required to be sent.
 * @returns	Packet count xmit'd on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_xmit(void *vq,
		dpaa2_mbuf_pt mbuf)
{
	struct qbman_fd fd;
	struct qbman_eq_desc eqdesc;
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	struct aiop_vq *tx_vq = (struct aiop_vq *)vq;
	int ret;

	DPAA2_TRACE(CMD);

	/* Prepare enqueue descriptor */
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_fq(&eqdesc, tx_vq->fqid);
	qbman_eq_desc_set_no_orp(&eqdesc, 0);
	qbman_eq_desc_set_response(&eqdesc, 0, 0);


	/* Convert dpaa2 buffer into frame descriptor */
	dpaa2_aiop_mbuf_to_fd(mbuf, &fd);

	/* Enqueue a packet to the QBMAN */
	do {
		ret = qbman_swp_enqueue(swp, &eqdesc, &fd);
		if (ret != 0) {
			DPAA2_DBG(CMD, "Transmit failure with err code: %d",
				ret);
		}
	} while (ret == -EBUSY);

	if (mbuf->flags & DPAA2BUF_ALLOCATED_SHELL)
		dpaa2_mbuf_free_shell(mbuf);
	DPAA2_INFO(CMD, "Successfully transmitted a packet");

	/* Returns the number of packets xmit'd */
	return 1;
}

/*!
 * @details	Add a RX side virtual queue/s to the AIOP device.This function
 *		shall get called for each RX VQ for which a thread is suppose
 *		to process the packets. Optionally, A RX VQ may be attached to
 *		an preconfigured Aggregator device.
 *
 * @param[in]	dev - Pointer to AIOP device structure.
 *
 * @param[in]	vq_index - Index of virtual queue out of total available RX VQs.
 *
 * @param[in]	aggr_dev - Pointer aggregator device to which
 *		this VQ should be attached.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_aiop_setup_rx_vq(
		struct dpaa2_dev *dev,
		uint8_t vq_index,
		struct dpaa2_vq_param *vq_cfg ODP_UNUSED)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpci = dev_priv->hw;
	struct dpci_rx_queue_cfg rx_queue_cfg;
	uint32_t max_vq_index;
	int ret;

	DPAA2_TRACE(CMD);

	max_vq_index = dpaa2_dev_get_max_rx_vq(dev);
	if (vq_index >= max_vq_index) {
		DPAA2_ERR(CMD, "Invalid VQ index: %d", vq_index);
		return DPAA2_FAILURE;
	}

	/* Set up the Rx Queue */
	memset(&rx_queue_cfg, 0, sizeof(struct dpci_rx_queue_cfg));
	ret = dpci_set_rx_queue(dpci, CMD_PRI_LOW, dev_priv->token, vq_index, &rx_queue_cfg);
	if (ret) {
		DPAA2_ERR(CMD, "Setting the Rx queue failed with err code: %d",
			ret);
		return DPAA2_FAILURE;
	}

	DPAA2_INFO(CMD, "Sucessfully configured Rx queue");
	return DPAA2_SUCCESS;
}

/* This API is not required for AIOP, but is here in case user calls it */
int32_t dpaa2_aiop_setup_tx_vq(
		struct dpaa2_dev *dev ODP_UNUSED,
		uint32_t num ODP_UNUSED, uint32_t action  ODP_UNUSED)
{
	DPAA2_TRACE(CMD);

	DPAA2_NOTE(CMD, "Tx queues are by default configured for AIOP");
	return DPAA2_SUCCESS;
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
int get_aiop_dev_id(struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_aiop_priv *aiop_priv = dev_priv->drv_priv;

	return aiop_priv->id;
}

/*! @} */
