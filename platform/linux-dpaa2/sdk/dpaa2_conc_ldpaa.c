/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 *
 */

/*!
 * @file	dpaa2_conc_ldpaa.c
 *
 * @brief	Concentrator driver implementation. It contains initialization of
 *		channel interface for DPAA2 device framework based application.
 *
 * @addtogroup	DPAA2_CONC
 * @ingroup	DPAA2_DEV
 * @{
 */

/*Standard header files*/
#include <pthread.h>

/*DPAA2 header files*/
#include <odp/api/std_types.h>
#include <dpaa2_common.h>
#include <dpaa2_dev.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_eth_priv.h>
#include <dpaa2_vq.h>
#include <dpaa2_eth_ldpaa_annot.h>
#include <dpaa2_eth_ldpaa_qbman.h>

#include <dpaa2_mbuf.h>
#include <dpaa2_mbuf_priv.h>
#include <dpaa2_conc_priv.h>
#include <dpaa2_malloc.h>
#include <odp/api/byteorder.h>
#include <dpaa2_time.h>
#include <odp/api/hints.h>

/*MC header files*/
#include <fsl_dpcon.h>
#include <fsl_dpcon_cmd.h>
#include <fsl_mc_sys.h>

#define LDPAA_CONC_DEV_VENDOR_ID		6487
#define LDPAA_CONC_DEV_MAJ_NUM		DPCON_VER_MAJOR
#define LDPAA_CONC_DEV_MIN_NUM		DPCON_VER_MINOR
#define LDPAA_CONC_DEV_NAME		"ldpaa-concentrator"

/*! Concentrator device driver information */
struct dpaa2_driver conc_driver = {
	.name			=	LDPAA_CONC_DEV_NAME,
	.vendor_id		=	LDPAA_CONC_DEV_VENDOR_ID,
	.major			=	LDPAA_CONC_DEV_MAJ_NUM,
	.minor			=	LDPAA_CONC_DEV_MIN_NUM,
	.dev_type		=	DPAA2_CONC,
	.dev_probe		=	dpaa2_conc_probe,
	.dev_shutdown		=	dpaa2_conc_remove
};

int32_t dpaa2_conc_driver_init(void)
{
	/*Register concentrator driver to DPAA2 device framework*/
	dpaa2_register_driver(&conc_driver);
	DPAA2_INFO(CONC, "DPCON device driver is registered\n");
	return DPAA2_SUCCESS;
}

int32_t dpaa2_conc_driver_exit(void)
{
	/*Unregister concentrator driver to DPAA2 device framework*/
	dpaa2_unregister_driver(&conc_driver);
	DPAA2_INFO(CONC, "DPCON device driver is unregistered\n");
	return DPAA2_SUCCESS;
}

int32_t dpaa2_conc_probe(struct dpaa2_dev *dev,
			ODP_UNUSED const void *data)
{
	/*Probe function is responsible to initialize the DPCON devices.
	 * It does the following:
	 * 1. Register device specific callbacks to DPAA2 device framework
	 * 2. Allocate memory for RX/TX VQ's and assign into DPAA2 device
	 *	structure.
	 * 3. Assigns available resource information into DPAA2 device
	 *	structure.
	 */
	struct dpaa2_dev_priv *dev_priv =
				(struct dpaa2_dev_priv *)dev->priv;
	struct dpaa2_conc_priv *drv_priv;
	struct fsl_mc_io *dpconc;
	struct dpcon_attr attr;
	struct conc_attr *conc_mem;
	int32_t retcode, loop = 0;

	/*Allocate space for device specific data*/
	drv_priv = (struct dpaa2_conc_priv *)dpaa2_calloc(NULL, 1,
		sizeof(struct dpaa2_conc_priv) + sizeof(struct conc_attr), 0);
	if (!drv_priv) {
		DPAA2_ERR(CONC, "Failure to allocate the memory for ethernet"
							"private data\n");
		return DPAA2_FAILURE;
	}

	dpconc = (struct fsl_mc_io *)dpaa2_calloc(NULL, 1,
						sizeof(struct fsl_mc_io), 0);
	if (!dpconc) {
		DPAA2_ERR(CONC, "Error in allocating the memory\n");
		goto mem_alloc_failure;
	}

	/*Assigning RX/TX VQs to DPAA2 device structure*/
	conc_mem = (struct conc_attr *)(drv_priv + 1);
	dev->rx_vq[loop] = conc_mem;

	/*Configure device specific callbacks to the DPAA2 framework*/
	dev_priv->drv_priv		= drv_priv;

	/*Open Concentrator device via MC and save the handle for further use
	and token for further use*/
	dpconc->regs = dev_priv->mc_portal;
	retcode = dpcon_open(dpconc, CMD_PRI_LOW, dev_priv->hw_id, &(dev_priv->token));
	if (retcode != 0) {
		DPAA2_ERR(CONC, "Cannot open the device %s: Error Code = %0x\n",
						dev->dev_string, retcode);
		goto dev_open_failure;
	}

	/*Get the resource information i.e. Channel ID, dpconc ID, priority*/
	retcode = dpcon_get_attributes(dpconc, CMD_PRI_LOW, dev_priv->token, &attr);
	if (retcode) {
		DPAA2_ERR(CONC, "DPNI get attribute failed: Error Code = %0x\n",
								retcode);
		goto get_attr_failure;
	}

	/*Updating device information*/
	dev->num_tx_vqueues = 0;
	dev->num_rx_vqueues = 0;
	sprintf(dev->dev_string, "dpconc.%d", dev_priv->hw_id);

	/*Updating device specific private information*/
	dev_priv->hw = dpconc;
	sprintf(drv_priv->name, "dpconc.%d", dev_priv->hw_id);
	conc_mem->obj_id	= attr.id;
	conc_mem->ch_id		= attr.qbman_ch_id;
	conc_mem->num_prio	= attr.num_priorities;

	DPAA2_INFO(CONC, "Total TX VQ = %d\t Total RX VQ = %d Channel ID = %d\t \
		Priority Num = %d Object ID = %d\n", dev->num_tx_vqueues,
				dev->num_rx_vqueues, conc_mem->ch_id,
				conc_mem->num_prio, conc_mem->obj_id);

	dprc_objects.dpconc_count++;
	return DPAA2_SUCCESS;

get_attr_failure:
		dpcon_close(dpconc,  CMD_PRI_LOW, dev_priv->token);
dev_open_failure:
		dpaa2_free(dpconc);
mem_alloc_failure:
		dpaa2_free(drv_priv);
		return DPAA2_FAILURE;
}

int32_t dpaa2_conc_remove(struct dpaa2_dev *dev)
{
	/*Function is reverse of dpaa2_eth_probe.
	 * It does the following:
	 * 1. Reset the DPCONC device to its default state.
	 * 2. Close the DPCONC device.
	 * 3. Free the allocated memory resources.
	 */
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpconc = dev_priv->hw;
	int32_t retcode;

	/*Reset the device to it's default state*/
	retcode = dpcon_reset(dpconc, CMD_PRI_LOW, dev_priv->token);
	if (retcode != 0)
		DPAA2_ERR(CONC, "Error in resetting  the device: ErrorCode = %d\n",
								retcode);
	/*Close the device at underlying layer*/
	retcode = dpcon_close(dpconc, CMD_PRI_LOW, dev_priv->token);
	if (retcode != 0)
		DPAA2_ERR(CONC, "Error in closing the device: ErrorCode = %d\n",
								retcode);

	/*Free the allocated memory for drv's private data and dpconc object*/
	dpaa2_free(dev_priv->drv_priv);
	dpaa2_free(dpconc);

	dprc_objects.dpconc_count--;
	return DPAA2_SUCCESS;
}

int32_t dpaa2_conc_start(struct dpaa2_dev *dev)
{
	/* Function is responsible to create underlying resources and
	 * to make device ready to use for RX/TX.
	 */
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpconc = (struct fsl_mc_io *)dev_priv->hw;
	int32_t retcode;

	/* After enabling a DPCONC, Resources, i.e. RX/TX VQs etc, will be
	 * created and device will be ready for RX/TX.
	*/
	retcode = dpcon_enable(dpconc, CMD_PRI_LOW, dev_priv->token);
	if (retcode != 0) {
		DPAA2_ERR(CONC, "DPCONC is not enabled at MC: Error code = %0x\n",
								retcode);
		return DPAA2_FAILURE;
	}
	dev->state = DEV_ACTIVE;

	return DPAA2_SUCCESS;
}

int32_t dpaa2_conc_stop(struct dpaa2_dev *dev)
{
	int32_t retcode;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpconc = (struct fsl_mc_io *)dev_priv->hw;

	/* Disable the DPCONC device and set dpaa2 device as inactive*/
	retcode = dpcon_disable(dpconc,  CMD_PRI_LOW, dev_priv->token);
	if (retcode != 0) {
		DPAA2_ERR(CONC, "Device cannot be disabled:Error Code = %0x\n",
								retcode);
		return DPAA2_FAILURE;
	}
	/*Set device as inactive*/
	dev->state = DEV_INACTIVE;
	return DPAA2_SUCCESS;
}

extern void *dpaa2_sec_cb_dqrr_fd_to_mbuf(
				struct qbman_swp *qm,
				const struct qbman_fd *fd,
				const struct qbman_result *dqrr);

int32_t dpaa2_conc_recv(struct dpaa2_dev *dev,
			void *vq ODP_UNUSED,
			uint32_t num,
			dpaa2_mbuf_pt mbuf[])
{
	/* Function is responsible to receive frame for a given DPCON device and
		Channel ID.
	*/
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	struct qbman_result *dq_storage = thread_io_info.dq_storage;
	uint16_t ch_id = ((struct conc_attr *)(dev->rx_vq[0]))->ch_id;
	int ret, qbman_try_again = 0, rcvd_pkts = 0;
	uint8_t is_last = 0, status;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	struct dpaa2_vq *rvq;

	dpaa2_qbman_pull_desc_channel_set(&pulldesc, num, ch_id, dq_storage);

try_again:
	/*Issue a volatile dequeue command.*/
	ret = qbman_swp_pull(swp, &pulldesc);
	if (odp_unlikely(ret < 0)) {
		if (ret == -EBUSY) {
			DPAA2_INFO(CONC,
				"VDQ command is not issued. QBMAN is busy\n");
			dpaa2_msleep(5);
			qbman_try_again++;
			if (qbman_try_again > 50)
				return DPAA2_FAILURE;
		} else {
			DPAA2_ERR(CONC,
				"VDQ command is not issued. Err Code = %0x\n",
				ret);
			return DPAA2_FAILURE;
		}
		goto try_again;
	}

	/* Recieve the packets till Last Dequeue entry is found with
	   respect to the above issues PULL command.
	 */
	while (!is_last) {
		/* Loop until the dq_storage is updated with
		 * new result by QBMAN */
		while (!qbman_result_has_new_result(swp, dq_storage))
			;

		/* Check whether Last Pull command is Expired and
		setting Condition for Loop termination */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			is_last = 1;
			/* Check for valid frame. */
			status = (uint8_t)qbman_result_DQ_flags(dq_storage);
			if (odp_unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
				DPAA2_INFO(CONC, "No frame is delivered\n");
				continue;
			}
		}

		/* Can avoid "qbman_result_is_DQ" check as
		   we are not expecting Notification on this SW-Portal */

		fd = qbman_result_DQ_fd(dq_storage);
		/* We must not use FLC to read User context. User context is
		   supposed to be extracted from DQRR entry using following API */
		rvq = (struct dpaa2_vq *)qbman_result_DQ_fqd_ctx(dq_storage);
		if (rvq) {
			/*todo - error checking missing */
			mbuf[rcvd_pkts] = rvq->qmfq.cb(swp, fd, dq_storage);
		} else {
			DPAA2_WARN(CONC, "Null Return VQ recieved\n");
			dq_storage++;
			continue;
		}
		if (mbuf[rcvd_pkts])
			rcvd_pkts++;
		dq_storage++;
	} /* End of Packet Rx loop */

	DPAA2_INFO(CONC, "DPCONC Received %d Packets\n", rcvd_pkts);
	/*Return the total number of packets received to DPAA2 app*/
	return rcvd_pkts;
}

void dpaa2_conc_get_attributes(struct dpaa2_dev *dev, struct conc_attr *attr)
{
	struct dpaa2_dev_priv *dev_priv =
				(struct dpaa2_dev_priv *)(dev->priv);
	struct dpaa2_conc_priv *drv_priv =
				(struct dpaa2_conc_priv *)(dev_priv->drv_priv);
	struct conc_attr *conc_mem = (struct conc_attr *)(drv_priv + 1);

	attr->ch_id	= conc_mem->ch_id;
	attr->num_prio	= conc_mem->num_prio;
	attr->obj_id	= conc_mem->obj_id;

	return;
}

/*! @} */
