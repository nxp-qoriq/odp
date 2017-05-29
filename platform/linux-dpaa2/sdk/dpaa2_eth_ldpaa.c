/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 *
 */

/*!
 * @file	dpaa2_eth_ldpaa.c
 *
 * @brief	Ethernet driver implementation. It contains initialization of
 *		network interface for DPAA2 device framework based application.
 *
 * @addtogroup	DPAA2_ETH
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
#include "dpaa2_eth_priv.h"
#include "dpaa2_vq.h"
#include <dpaa2_eth_ldpaa_annot.h>
#include <dpaa2_eth_ldpaa_qbman.h>
#include <dpaa2_mbuf.h>
#include <dpaa2_mbuf_priv.h>
#include <dpaa2_malloc.h>
#include <odp/api/byteorder.h>
#include <dpaa2_conc_priv.h>
#include <dpaa2_dev_notif.h>
#include <dpaa2_dev_notif_priv.h>
#include <dpaa2_memconfig.h>
#include <odp/api/hints.h>
#include <odp_config_internal.h>
#include <odp_debug_internal.h>
#include <dpaa2_fd_priv.h>
#include <odp_align_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>

/*MC header files*/
#include <fsl_dpni.h>
#include <fsl_dpopr.h>
#include <fsl_dpni_cmd.h>
#include <fsl_mc_sys.h>

/*Macro to define stash line sizes. Below is the configuration offloaded
 * (DPNI_FLC_STASH_FRAME_ANNOTATION << 2 | DPNI_STASH_SIZE_64B << 4)
 */
#define LDPAA_ETH_DEV_STASH_SIZE	0x0000000000000014

#define DPAA2_ASAL_VAL (DPAA2_MBUF_HW_ANNOTATION / 64)

#define LDPAA_ETH_DEV_VENDOR_ID		6487
#define LDPAA_ETH_DEV_MAJ_NUM		DPNI_VER_MAJOR
#define LDPAA_ETH_DEV_MIN_NUM		DPNI_VER_MINOR
#define LDPAA_ETH_DEV_NAME		"ldpaa-ethernet"

/* Number of frames to be received in SC mode */
#define MAX_NUM_RECV_FRAMES	16
/* Short Circuit the Ethernet Driver */
bool eth_short_circuit;
/* Signal caching variable for SC mode */
bool eth_sc_sigint;

int32_t dpaa2_mbuf_sw_annotation;

struct dpaa2_driver eth_driver = {
	.name			=	LDPAA_ETH_DEV_NAME,
	.vendor_id		=	LDPAA_ETH_DEV_VENDOR_ID,
	.major			=	LDPAA_ETH_DEV_MAJ_NUM,
	.minor			=	LDPAA_ETH_DEV_MIN_NUM,
	.dev_type		=	DPAA2_NIC,
	.dev_probe		=	dpaa2_eth_probe,
	.dev_shutdown		=	dpaa2_eth_remove
};

/*Ethernet spcific statistics objects*/
#ifdef DPAA2_DEBUG_XSTATS
struct dpaa2_eth_xstats xstats;
#endif

void *dpaa2_eth_cb_dqrr_fd_to_mbuf(
		struct qbman_swp *qm,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr);

void *dpaa2_eth_cb_dqrr_tx_conf_err(
		struct qbman_swp *qm,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr);

int32_t dpaa2_eth_driver_init(void)
{
	/*Register Ethernet driver to DPAA2 device framework*/
	dpaa2_register_driver(&eth_driver);
	return DPAA2_SUCCESS;
}

int32_t dpaa2_eth_driver_exit(void)
{
	/*Unregister Ethernet driver to DPAA2 device framework*/
	dpaa2_unregister_driver(&eth_driver);
	return DPAA2_SUCCESS;
}

int32_t dpaa2_eth_probe(struct dpaa2_dev *dev,
			const void *data ODP_UNUSED)
{
	int retcode;
	struct dpaa2_dev_priv *dev_priv =
				(struct dpaa2_dev_priv *)dev->priv;
	struct vfio_device_info *obj_info =
		(struct vfio_device_info *)dev_priv->drv_priv;

	/* Get the interrupts for Ethernet device */
	retcode = dpaa2_get_interrupt_info(dev_priv->vfio_fd,
			obj_info, &(dev_priv->intr_handle));
	if (retcode != DPAA2_SUCCESS) {
		DPAA2_ERR(FW, "Unable to get interrupt information\n");
		return DPAA2_FAILURE;
	};
	/*if  headroom is already initialized in the previous device probe*/
	if (!dpaa2_mbuf_head_room) {
		uint32_t tot_size;
		/* ... rx buffer layout ... */
		dpaa2_mbuf_sw_annotation = DPAA2_FD_PTA_SIZE;
		dpaa2_mbuf_head_room	= ODP_CONFIG_PACKET_HEADROOM;

		/*Check alignment for buffer layouts first*/
		tot_size = dpaa2_mbuf_sw_annotation + DPAA2_MBUF_HW_ANNOTATION +
							dpaa2_mbuf_head_room;
		tot_size = ODP_ALIGN_ROUNDUP(tot_size, ODP_PACKET_LAYOUT_ALIGN);
		dpaa2_mbuf_head_room = tot_size - (dpaa2_mbuf_sw_annotation +
						DPAA2_MBUF_HW_ANNOTATION);
	}
	sprintf(dev->dev_string, "dpni.%u", dev_priv->hw_id);
	return DPAA2_SUCCESS;
}

int32_t dpaa2_eth_open(struct dpaa2_dev *dev)
{
	/*eth_open function is responsible to initialize the DPNI devices.
	 * It does the following:
	 * 1. Register device specific callbacks to DPAA2 device framework
	 * 2. Allocate memory for RX/TX VQ's and assign into NADL device
	 *	structure.
	 * 3. Assigns available resource information into DPAA2 device
	 *	structure.
	 */
	struct dpaa2_dev_priv *dev_priv =
				(struct dpaa2_dev_priv *)dev->priv;
	struct dpaa2_eth_priv *epriv = (struct dpaa2_eth_priv *)(dev_priv->drv_priv);
	struct dpaa2_eth_priv *eth_priv;
	struct fsl_mc_io *dpni_dev;
	struct dpni_attr attr;
	int32_t retcode;
	int16_t i, j;
	uint8_t flow_id;
	struct dpaa2_vq *vq_mem;
	struct dpaa2_vq *eth_rx_vq;
	uint8_t bcast_addr[ETH_ADDR_LEN];
	uint8_t mac_addr[ETH_ADDR_LEN];
	struct dpni_buffer_layout layout;
	struct queues_config *q_config;
	struct dpni_tx_priorities_cfg tx_prio_cfg;

	/*Allocate space for device specific data*/
	eth_priv = (struct dpaa2_eth_priv *)dpaa2_calloc(NULL, 1,
		sizeof(struct dpaa2_eth_priv) + sizeof(struct dpaa2_vq) *
		(MAX_RX_VQS + MAX_TX_VQS + MAX_ERR_VQS + MAX_DEF_ERR_VQS), 0);
	if (!eth_priv) {
		DPAA2_ERR(ETH, "Failure to allocate the memory for ethernet"
							"private data\n");
		return DPAA2_FAILURE;
	}

	/*Assigning RX/TX VQs to DPAA2 device structure*/
	vq_mem = (struct dpaa2_vq *)(eth_priv + 1);
	for (i = 0; i < MAX_RX_VQS; i++) {
		vq_mem->dev = dev;
		dev->rx_vq[i] = vq_mem++;
	}
	for (i = 0; i < MAX_TX_VQS; i++) {
		vq_mem->dev = dev;
		dev->tx_vq[i] = vq_mem++;
	};
	for (i = 0; i < MAX_ERR_VQS + MAX_DEF_ERR_VQS; i++) {
		vq_mem->dev = dev;
		dev->err_vq[i] = vq_mem++;
	}

	/*Configure device specific callbacks to the DPAA2 framework*/
	dev_priv->fn_get_vqid	 = dpaa2_eth_get_fqid;
	dev_priv->drv_priv	 = eth_priv;

	/*Open the dpaa2 device via MC and save the handle for further use*/
	dpni_dev = (struct fsl_mc_io *)dpaa2_calloc(NULL, 1,
						sizeof(struct fsl_mc_io), 0);
	if (!dpni_dev) {
		DPAA2_ERR(ETH, "Error in allocating the memory\n");
		goto mem_alloc_failure;
	}
	dpni_dev->regs = dev_priv->mc_portal;
	retcode = dpni_open(dpni_dev, CMD_PRI_LOW, dev_priv->hw_id, &(dev_priv->token));
	if (retcode != 0) {
		DPAA2_ERR(ETH, "Cannot open the device %s: Error Code = %0x\n",
						dev->dev_string, retcode);
		goto dev_open_failure;
	}
	/* Reset the DPNI before use. It's a workaround to
	   enable Stashing via MC configuration */
	retcode = dpni_reset(dpni_dev, CMD_PRI_LOW, dev_priv->token);
	if (retcode)
		DPAA2_ERR(ETH, "Error in Resetting the DPNI"
				" : ErrorCode = %d\n", retcode);
	/*Get the resource information i.e. numner of RX/TX Queues, TC etc*/
	retcode = dpni_get_attributes(dpni_dev, CMD_PRI_LOW, dev_priv->token, &attr);
	if (retcode) {
		DPAA2_ERR(ETH, "DPNI get attribute failed: Error Code = %0x\n",
								retcode);
		goto get_attr_failure;
	}
	q_config = &(eth_priv->q_config);
	q_config->num_tcs = attr.num_tcs;
	/* dev->num_tx_vqueues = attr.num_tcs; */
	/**
	TODO:Using hard coded value for number of TX queues due to dependency
	on MC. Once fix will will available in MC, Change needs to be reverted
	*/
	dev->num_tx_vqueues = 8;

	dev->num_rx_vqueues = 0;

	/*Allocate DMA'ble memory to receieve congestion notifications*/
	dev->notification_mem = dpaa2_data_calloc(NULL, dev->num_tx_vqueues,
					sizeof(struct qbman_result), 16);
	if (!dev->notification_mem) {
		DPAA2_ERR(ETH, "Failure to allocate memory for notification\n");
		goto get_attr_failure;
	}

	j = 0;
	for (i = 0; i < attr.num_tcs; i++) {
		q_config->tc_config[i].num_dist = attr.num_queues;
		for (flow_id = 0; j < q_config->tc_config[i].num_dist; j++) {
			eth_rx_vq = dev->rx_vq[j];
			eth_rx_vq->flow_id = flow_id %
					    q_config->tc_config[i].num_dist;
			eth_rx_vq->tc_index = i;
			flow_id++;
		}
		dev->num_rx_vqueues += q_config->tc_config[i].num_dist;
	}

	/*
	Resetting the "num_rx_vqueues" to equal number of queues in first TC as
	only one TC is supported on Rx Side. Once Multiple TCs will be in use
	for Rx processing then this is required to be changed or removed.
	*/
	dev->num_rx_vqueues = attr.num_queues;

	DPAA2_INFO(ETH, "TX VQ = %d\t RX VQ = %d\n",
		dev->num_tx_vqueues, dev->num_rx_vqueues);
	dev_priv->hw = dpni_dev;
	retcode = dpni_get_primary_mac_addr(dpni_dev, CMD_PRI_LOW, dev_priv->token, mac_addr);
	if (retcode) {
		DPAA2_ERR(ETH, "DPNI get mac address failed:"
					" Error Code = %d\n", retcode);
		goto get_attr_failure;
	}
	printf("\nPort %s = Mac %02X.%02X.%02X.%02X.%02X.%02X", \
			dev->dev_string, mac_addr[0], mac_addr[1], mac_addr[2],
			mac_addr[3], mac_addr[4], mac_addr[5]);
	sprintf((char *)eth_priv->cfg.name, "fsl_dpaa2_eth");
	memcpy(eth_priv->cfg.mac_addr, mac_addr, ETH_ADDR_LEN);
	/* driver may only return MTU in case of IPF/IPR offload support
	 * otherwise it will return 0 in all other cases*/
	eth_priv->cfg.mtu = dpaa2_eth_mtu_get(dev);
	if (0 == eth_priv->cfg.mtu) {
		/* Using Default value */
		eth_priv->cfg.mtu = ETH_MTU;
		retcode = dpaa2_eth_mtu_set(dev, eth_priv->cfg.mtu);
		if (retcode < 0) {
			DPAA2_ERR(ETH, "Fail to set MTU %d\n", retcode);
			goto get_attr_failure;
		}
		printf(" MTU = %d\n", dpaa2_eth_mtu_get(dev));
	}

	/* Set the Max Rx frame length as 9000 Bytes to support
		JUMBO sized packets*/
	retcode = dpni_set_max_frame_length(dpni_dev, CMD_PRI_LOW,
					dev_priv->token,
					ETH_MAX_JUMBO_FRAME_LEN);
	if (retcode) {
		DPAA2_ERR(ETH, "setting the max frame length failed");
		goto get_attr_failure;
	}

	/* WRIOP don't accept packets with broadcast address by default,
	   So adding rule entry for same. */
	DPAA2_INFO(ETH, "Adding Broadcast Address...\n");
	memset(bcast_addr, 0xff, ETH_ADDR_LEN);
	retcode = dpni_add_mac_addr(dpni_dev, CMD_PRI_LOW, dev_priv->token, bcast_addr);
	if (retcode) {
		DPAA2_ERR(ETH, "DPNI set broadcast mac address failed:"
					" Error Code = %0x\n", retcode);
		goto get_attr_failure;
	}

	/*Configure WRIOP to provide parse results, frame annoatation status and
	timestamp*/

	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_FRAME_STATUS |
				DPNI_BUF_LAYOUT_OPT_PARSER_RESULT |
				DPNI_BUF_LAYOUT_OPT_DATA_HEAD_ROOM |
				DPNI_BUF_LAYOUT_OPT_DATA_TAIL_ROOM |
				DPNI_BUF_LAYOUT_OPT_DATA_ALIGN |
				DPNI_BUF_LAYOUT_OPT_PRIVATE_DATA_SIZE;
	layout.pass_frame_status = TRUE;
	layout.data_head_room = dpaa2_mbuf_head_room;
	layout.data_tail_room = dpaa2_mbuf_tail_room;
	layout.private_data_size = dpaa2_mbuf_sw_annotation;
	layout.pass_parser_result = TRUE;
	layout.data_align = 64;
	retcode = dpni_set_buffer_layout(dpni_dev, CMD_PRI_LOW, dev_priv->token,
					 DPNI_QUEUE_RX, &layout);
	if (retcode) {
		DPAA2_ERR(ETH, "Error (%d) in setting rx buffer layout\n",
								retcode);
		goto get_attr_failure;
	}

	/* ... tx buffer layout ... */
	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_FRAME_STATUS;
	layout.pass_frame_status = TRUE;
	retcode = dpni_set_buffer_layout(dpni_dev, CMD_PRI_LOW, dev_priv->token,
					 DPNI_QUEUE_TX, &layout);
	if (retcode) {
		DPAA2_ERR(ETH, "Error (%d) in setting tx buffer layout\n",
								retcode);
		goto get_attr_failure;
	}
	/* ... tx-conf and error buffer layout ... */
	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_FRAME_STATUS;
	layout.pass_frame_status = TRUE;
	retcode = dpni_set_buffer_layout(dpni_dev, CMD_PRI_LOW, dev_priv->token,
					 DPNI_QUEUE_TX_CONFIRM, &layout);
	if (retcode) {
		DPAA2_ERR(ETH, "Error (%d) in setting tx-conf buffer layout\n",
								retcode);
		goto get_attr_failure;
	}

	/*Disabling tx-confirmation. With this setting no tx-confirmation
	queues will be created at H/W*/
	retcode = dpni_set_tx_confirmation_mode(dpni_dev, CMD_PRI_LOW,
						dev_priv->token,
						DPNI_CONF_DISABLE);
	if (retcode) {
		DPAA2_ERR(ETH, "Error in setting tx conf settings\n"
			"ErrorCode = %d", retcode);
		goto get_attr_failure;
	}

	/* Setting the promiscuous mode */
	if (getenv("ENABLE_PROMISC")) {
		retcode = dpni_set_unicast_promisc(dpni_dev, CMD_PRI_LOW, dev_priv->token, 1);
		if (retcode < 0) {
			DPAA2_ERR(ETH, "Unable to enable promiscuous mode");
			goto get_attr_failure;
		}
		epriv->cfg.hw_features |= DPAA2_PROMISCUOUS_ENABLE;
		ODP_PRINT("Promiscous mode enabled at device = %s\n", dev->dev_string);
	}

	/*Configure TX priorities for each TC*/
	memset(&tx_prio_cfg, 0, sizeof(struct dpni_tx_priorities_cfg));
	for (i = 0; i < attr.num_tcs; i++)
		tx_prio_cfg.tc_sched[i].mode = DPNI_TX_SCHED_STRICT_PRIORITY;

	retcode = dpni_set_tx_priorities(dpni_dev, CMD_PRI_LOW,
					dev_priv->token, &tx_prio_cfg);
	if (retcode < 0) {
		DPAA2_ERR(ETH, "Unable to Set Tx Priorities: Error = %d\n", retcode);
		goto get_attr_failure;
	}

	return DPAA2_SUCCESS;

get_attr_failure:
		dpni_close(dpni_dev, CMD_PRI_LOW, dev_priv->token);
dev_open_failure:
		dpaa2_free(dpni_dev);
mem_alloc_failure:
		dpaa2_data_free(dev->notification_mem);
		dpaa2_free(eth_priv);
		return DPAA2_FAILURE;
}

int32_t dpaa2_eth_remove(struct dpaa2_dev *dev ODP_UNUSED)
{
	return DPAA2_SUCCESS;
}

int32_t dpaa2_eth_close(struct dpaa2_dev *dev)
{
	/*Function is reverse of dpaa2_eth_probe.
	 * It does the following:
	 * 1. Detach a DPNI from attached resources i.e. buffer pools, dpbp_id.
	 * 2. Close the DPNI device
	 * 3. Free the allocated reqources.
	 */
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_eth_priv *eth_priv = dev_priv->drv_priv;
	struct fsl_mc_io *dpni = dev_priv->hw;
	int32_t retcode;

	if (!dpni)
		return DPAA2_SUCCESS;

	/* Reset the DPNI device object for next use */
	retcode = dpni_reset(dpni, CMD_PRI_LOW, dev_priv->token);
	if (retcode != 0)
		DPAA2_ERR(ETH, "Error in Resetting the Ethernet"
				" device: ErrorCode = %d\n", retcode);
	/*Close the device at underlying layer*/
	retcode = dpni_close(dpni, CMD_PRI_LOW, dev_priv->token);
	if (retcode != 0)
		DPAA2_ERR(ETH, "Error in closing the Ethernet"
				" device: ErrorCode = %d\n", retcode);
	/*Free the allocated memory for ethernet private data and dpni*/
	dpaa2_data_free(dev->notification_mem);
	dpaa2_free(eth_priv);
	dpaa2_free(dpni);
	dev_priv->hw = NULL;

	return DPAA2_SUCCESS;
}

int32_t dpaa2_eth_start(struct dpaa2_dev *dev)
{
	/* Function is responsible to create underlying resources and to
	 * to make device ready to use for RX/TX.
	 */
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)dev_priv->hw;
	struct dpaa2_eth_priv *eth_priv = dev_priv->drv_priv;
	struct dpni_queue cfg;
	int32_t retcode;
	uint8_t tc_idx;
	uint16_t qdid, dist_idx;
	uint32_t vq_id = 0;
	struct dpaa2_vq *eth_rx_vq;
	struct queues_config *q_config;
	uint16_t num_flows;
	struct dpni_queue_id qid;

	/* After enabling a DPNI, Resources i.e. RX/TX VQs etc will be created
	 * and device will be ready for RX/TX.*/
	retcode = dpni_enable(dpni, CMD_PRI_LOW, dev_priv->token);
	if (retcode != 0) {
		DPAA2_ERR(ETH, "Error in enabling the DPNI to underlying layer"
						"Error code = %0x\n", retcode);
		return DPAA2_FAILURE;
	}

	q_config = &(eth_priv->q_config);
	/*Save the RX/TX flow information in DPAA2 device structure*/
	for (tc_idx = 0; tc_idx < q_config->num_tcs; tc_idx++) {
		if (q_config->tc_config[tc_idx].dist_type == DPAA2_ETH_FLOW_DIST)
			num_flows = q_config->tc_config[tc_idx].num_dist_used;
		else
			num_flows = 1;

		for (dist_idx = 0; dist_idx < num_flows; dist_idx++) {
			retcode = dpni_get_queue(dpni, CMD_PRI_LOW,
						 dev_priv->token, DPNI_QUEUE_RX,
						 tc_idx, dist_idx, &cfg, &qid);
			if (retcode) {
				DPAA2_ERR(ETH, "Error to get flow information"
						"Error code = %0d\n", retcode);
				goto failure;
			}
			eth_rx_vq = (struct dpaa2_vq *)(dev->rx_vq[vq_id]);
			eth_rx_vq->fqid = qid.fqid;
			vq_id++;
			DPAA2_INFO(ETH, "FQID = %d\n", qid.fqid);
		}
	}
	/*Save the respective qdid of DPNI device into DPAA2 device structure*/
	retcode = dpni_get_qdid(dpni, CMD_PRI_LOW, dev_priv->token,
				DPNI_QUEUE_TX, &qdid);
	if (retcode != 0) {
		DPAA2_ERR(ETH, "Error to get qdid:ErrorCode = %d\n", retcode);
		goto failure;
	}
	dev_priv->qdid = qdid;
	DPAA2_INFO(ETH, "QDID = %d\n", qdid);

	/*All Well. Set the device as Active*/
	dev->state = DEV_ACTIVE;

	return DPAA2_SUCCESS;

failure:
	/*Disable the device which is enabled before*/
	dpni_disable(dpni, CMD_PRI_LOW, dev_priv->token);
	return DPAA2_FAILURE;
}

int32_t dpaa2_eth_stop(struct dpaa2_dev *dev)
{
	int32_t retcode;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)dev_priv->hw;

	/* Disable the network interface and set dpaa2 device as inactive*/
	retcode = dpni_disable(dpni, CMD_PRI_LOW, dev_priv->token);
	if (retcode != 0) {
		DPAA2_ERR(ETH, "Device cannot be disabled:Error Code = %0d\n",
								retcode);
		return DPAA2_FAILURE;
	}
	/*Set device as inactive*/
	dev->state = DEV_INACTIVE;
	return DPAA2_SUCCESS;
}

int32_t dpaa2_eth_prefetch_recv(ODP_UNUSED struct dpaa2_dev *dev,
			void *vq,
			uint32_t num,
			dpaa2_mbuf_pt mbuf[])
{
	/* Function is responsible to receive frames for a given device and VQ*/
	struct dpaa2_vq *eth_rx_vq = (struct dpaa2_vq *)(vq);
	uint32_t fqid = eth_rx_vq->fqid;
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	struct qbman_result *dq_storage;
	uint8_t is_last = 0, status;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	uint32_t rcvd_pkts = 0;

	if (eth_rx_vq->toggle == -1) {
		eth_rx_vq->toggle = 0;
		eth_rx_vq->dqrr_idx = 0;
		dq_storage = eth_rx_vq->dq_storage[eth_rx_vq->toggle];
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_numframes(&pulldesc, MAX_NUM_RECV_FRAMES);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			(dma_addr_t)dq_storage, TRUE);

		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				DPAA2_WARN(ETH, "VDQ command is not issued....QBMAN is busy\n");
				/* Portal was busy, try again */
				continue;
			}
			break;
		};
	}

	dq_storage = eth_rx_vq->dq_storage[eth_rx_vq->toggle] +
			eth_rx_vq->dqrr_idx;
	/* Recieve the packets till Last Dequeue entry is found with
	   respect to the above issues PULL command. */
	while (!is_last && rcvd_pkts < num) {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN */
		while (!qbman_result_has_new_result(swp, dq_storage))
			;

		/* Check whether Last Pull command is Expired and
		setting Condition for Loop termination */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			is_last = 1;
			/* Check for valid frame. */
			status = (uint8_t)qbman_result_DQ_flags(dq_storage);
			if (odp_unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
				DPAA2_INFO(ETH, "No frame is delivered\n");
				continue;
			}
		}

		/* Can avoid "qbman_result_is_DQ" check as
		   we are not expecting Notification on this SW-Portal */
		fd = qbman_result_DQ_fd(dq_storage);

		mbuf[rcvd_pkts] = eth_rx_vq->qmfq.cb(swp, fd, dq_storage);
		if (mbuf[rcvd_pkts])
			rcvd_pkts++;

		dq_storage++;
		eth_rx_vq->dqrr_idx++;
	} /* End of Packet Rx loop */

	DPAA2_INFO(ETH, "Ethernet Received %d Packets", rcvd_pkts);

	if (is_last) {
		eth_rx_vq->toggle ^= 1;
		eth_rx_vq->dqrr_idx = 0;
		dq_storage = eth_rx_vq->dq_storage[eth_rx_vq->toggle];
		qbman_pull_desc_clear(&pulldesc);
		qbman_pull_desc_set_numframes(&pulldesc, MAX_NUM_RECV_FRAMES);
		qbman_pull_desc_set_fq(&pulldesc, fqid);
		qbman_pull_desc_set_storage(&pulldesc, dq_storage,
			(dma_addr_t)dq_storage, TRUE);

		while (1) {
			if (qbman_swp_pull(swp, &pulldesc)) {
				DPAA2_WARN(ETH, "VDQ command is not issued....QBMAN is busy\n");
				/* Portal was busy, try again */
				continue;
			}
			break;
		};
	}

	/*Return the total number of packets received to DPAA2 app*/
	return rcvd_pkts;
}

int32_t dpaa2_eth_recv(ODP_UNUSED struct dpaa2_dev *dev,
			void *vq,
			uint32_t num,
			dpaa2_mbuf_pt mbuf[])
{
	/* Function is responsible to receive frames for a given device and VQ*/
	struct dpaa2_vq *eth_vq = (struct dpaa2_vq *)vq;
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	struct qbman_result *dq_storage = thread_io_info.dq_storage;
	uint8_t is_last = 0, status;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	int32_t rcvd_pkts = 0;

	dpaa2_qbman_pull_desc_set(&pulldesc, num, eth_vq->fqid, dq_storage);

	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			DPAA2_WARN(ETH, "VDQ command is not issued....QBMAN is busy\n");
			/* Portal was busy, try again */
			continue;
		}
		break;
	};

	/* Recieve the packets till Last Dequeue entry is found with
	   respect to the above issues PULL command.
	 */
	while (!is_last) {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN */
		while (!qbman_result_has_new_result(swp, dq_storage))
			;

		/* Check whether Last Pull command is Expired and
		setting Condition for Loop termination */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			is_last = 1;
			/* Check for valid frame. */
			status = (uint8_t)qbman_result_DQ_flags(dq_storage);
			if (odp_unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
				DPAA2_INFO(ETH, "No frame is delivered\n");
				continue;
			}
		}

		/* Can avoid "qbman_result_is_DQ" check as
		   we are not expecting Notification on this SW-Portal */

		fd = qbman_result_DQ_fd(dq_storage);

		mbuf[rcvd_pkts] = eth_vq->qmfq.cb(swp, fd, dq_storage);
		if (mbuf[rcvd_pkts])
			rcvd_pkts++;

		dq_storage++;
	} /* End of Packet Rx loop */

	DPAA2_INFO(ETH, "Ethernet Received %d Packets", rcvd_pkts);
	/*Return the total number of packets received to DPAA2 app*/
	return rcvd_pkts;
}

static inline void dpaa2_eth_mbuf_to_sg_fd(
		dpaa2_mbuf_pt mbuf,
		struct qbman_fd *fd)
{
	struct dpaa2_mbuf *cur_seg = mbuf;
	struct dpaa2_sg_entry *sgt, *sge;
	int i;

	/*First Prepare FD to be transmited*/
	/*Resetting the buffer pool id and offset field*/
	fd->simple.bpid_offset = 0;
	DPAA2_SET_FD_ADDR(fd, DPAA2_VADDR_TO_IOVA(
		mbuf->hw_annot - DPAA2_FD_PTA_SIZE));
	DPAA2_SET_FD_LEN(fd, mbuf->tot_frame_len);
	DPAA2_SET_FD_BPID(fd, mbuf->bpid);
	DPAA2_SET_FD_OFFSET(fd, mbuf->priv_meta_off);
	DPAA2_SET_FD_ASAL(fd, DPAA2_ASAL_VAL);
	qbman_fd_set_format(fd, qbman_fd_sg);

	/*Set Scatter gather table and Scatter gather entries*/
	sgt = (struct dpaa2_sg_entry *)
			DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd)
					   + DPAA2_GET_FD_OFFSET(fd));
	i = 0;
	while (cur_seg) {
		/*First Scatter gather entry*/
		sge = &sgt[i++];
		dpaa2_sg_set_addr(sge,
				  (dma_addr_t)DPAA2_VADDR_TO_IOVA(cur_seg->head));
		dpaa2_sg_set_offset(sge, cur_seg->data - cur_seg->head);
		dpaa2_sg_set_len(sge, cur_seg->frame_len);
		dpaa2_sg_set_bpid(sge, cur_seg->bpid);
		cur_seg = cur_seg->next_sg;
	};
	dpaa2_sg_set_final(sge, true);
}

static inline void dpaa2_eth_mbuf_to_contig_fd(
		dpaa2_mbuf_pt mbuf,
		struct qbman_fd *fd)
{
	/*Resetting the buffer pool id and offset field*/
	fd->simple.bpid_offset = 0;
	DPAA2_SET_FD_ADDR(fd, DPAA2_VADDR_TO_IOVA(
		mbuf->head - mbuf->priv_meta_off));
	DPAA2_SET_FD_LEN(fd, mbuf->frame_len);
	DPAA2_SET_FD_BPID(fd, mbuf->bpid);
	DPAA2_SET_FD_OFFSET(fd, (dpaa2_mbuf_headroom(mbuf) +
		mbuf->priv_meta_off));
	DPAA2_SET_FD_ASAL(fd, DPAA2_ASAL_VAL);

	/*TODO: Check whether tx-conf is required for the frame of not*/
	if (mbuf->flags & DPAA2BUF_TX_CONF_REQUIRED) {
		DPAA2_INFO(ETH, "Confirmation is reuired for this buffer\n");
		/*Set the specified bits and fqid in Action descriptor so
		that confirmation*/
	}
}

int32_t dpaa2_eth_xmit(struct dpaa2_dev *dev,
			void *vq,
			uint32_t num,
			const dpaa2_mbuf_pt mbuf[])
{
	/* Function to transmit the frames to given device and VQ*/
	#define QBMAN_IDX_FROM_DQRR(p) (((unsigned long)p & 0x1ff) >> 6)
	#define RETRY_COUNT 10000
	uint32_t loop = 0, ret, retry_count = RETRY_COUNT, num_pkts = 0, i = 0, index = 0;
	struct qbman_fd fd_arr[MAX_TX_RING_SLOTS];
	uint32_t frames_to_send;
	struct qbman_eq_desc eqdesc[MAX_TX_RING_SLOTS] = {{{0}}};
	struct dpaa2_dev_priv *dev_priv =
				(struct dpaa2_dev_priv *)dev->priv;
	struct qbman_swp *swp;
	struct dpaa2_vq *eth_tx_vq = (struct dpaa2_vq *)vq;
	struct eqcr_entry *eqcr = (struct eqcr_entry *)&eqdesc[0];
	struct qbman_result *result =
				(struct qbman_result *)dev->notification_mem;


	swp = thread_io_info.dpio_dev->sw_portal;

	/*Clear the unused FD fields before sending*/
	while (num) {
		if (qbman_result_SCN_state_in_mem(result + eqcr->qpri))
			goto skip_tx;

		frames_to_send = (num >> 3) ? MAX_TX_RING_SLOTS : num;
		/*Prepare each packet which is to be sent*/
		for (loop = 0; loop < frames_to_send; loop++) {
			/*Prepare enqueue descriptor*/
			eqcr->verb = QBMAN_RESP_IF_REJ_QUE_DEST;
			eqcr->tgtid = dev_priv->qdid;
			eqcr->qdbin = eth_tx_vq->flow_id;
			eqcr->qpri = eth_tx_vq->tc_index;
			fd_arr[loop].simple.frc = 0;
			DPAA2_RESET_FD_CTRL((&fd_arr[loop]));
			DPAA2_SET_FD_FLC((&fd_arr[loop]), NULL);

			/* Set DCA for freeing DQRR if required. We are saving
			   DQRR entry index in buffer when using DQRR mode.
			   The same need to be freed by H/W.
			*/
			index = mbuf[loop + num_pkts]->index;
			if (ANY_ATOMIC_CNTXT_TO_FREE(mbuf[loop + num_pkts])) {
				eqcr->dca = ENABLE_DCA |	GET_HOLD_DQRR_IDX(index);
				MARK_HOLD_DQRR_PTR_INVALID(index);
			} else if (mbuf[loop + num_pkts]->opr.orpid != INVALID_ORPID){
				eqcr->orpid = mbuf[loop + num_pkts]->opr.orpid;
				eqcr->seqnum = mbuf[loop + num_pkts]->opr.seqnum;
				eqcr->verb |= (1 << EQCR_ENTRY_ORDER_RES_ENABLE);
			}

			/*Check whether mbuf has multiple segments or not.
			Convert dpaa2 buffer into frame descriptor accordingly*/
			if (!BIT_ISSET_AT_POS(mbuf[loop + num_pkts]->eth_flags,
						DPAA2BUF_IS_SEGMENTED))
				dpaa2_eth_mbuf_to_contig_fd(mbuf[loop + num_pkts], &fd_arr[loop]);
			else
				dpaa2_eth_mbuf_to_sg_fd(mbuf[loop + num_pkts], &fd_arr[loop]);
			eqcr++;
		}
		loop = 0;

		while (retry_count && (loop < frames_to_send)) {
			ret = qbman_swp_send_multiple(swp, &eqdesc[loop],
					&fd_arr[loop], frames_to_send - loop);
			if (!ret)
				retry_count--;
			loop += ret;
			num_pkts += ret;
		}
		while (i < loop) {
			if (mbuf[i]->flags & DPAA2BUF_ALLOCATED_SHELL)
				dpaa2_mbuf_free_shell(mbuf[i]);
			i++;
		}
		i = num_pkts;
		num -= frames_to_send;
	}

skip_tx:
	return num_pkts;
}

int32_t dpaa2_eth_xmit_fqid(void *vq,
			uint32_t num,
			dpaa2_mbuf_pt mbuf[])
{
	/* Function to transmit the frames to given device and VQ*/
	uint32_t loop;
	int32_t ret;
	struct qbman_fd fd;
	struct qbman_eq_desc eqdesc;
	uint64_t eq_storage_phys = NULL;
	struct qbman_swp *swp;
	struct dpaa2_vq *eth_tx_vq = (struct dpaa2_vq *)vq;

	/*Prepare enqueue descriptor*/
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_no_orp(&eqdesc, DPAA2_EQ_RESP_ERR_FQ);
	qbman_eq_desc_set_response(&eqdesc, eq_storage_phys, 0);
	qbman_eq_desc_set_fq(&eqdesc, eth_tx_vq->fqid);
	swp = thread_io_info.dpio_dev->sw_portal;

	/*Clear the unused FD fields before sending*/
	fd.simple.frc = 0;
	DPAA2_RESET_FD_CTRL((&fd));
	DPAA2_SET_FD_FLC((&fd), NULL);

	/*Prepare each packet which is to be sent*/
	for (loop = 0; loop < num; loop++) {
		/*Check whether mbuf has multiple segments or not.
		Convert dpaa2 buffer into frame descriptor accordingly*/
		if (!BIT_ISSET_AT_POS(mbuf[loop]->eth_flags,
					DPAA2BUF_IS_SEGMENTED))
			dpaa2_eth_mbuf_to_contig_fd(mbuf[loop], &fd);
		else
			dpaa2_eth_mbuf_to_sg_fd(mbuf[loop], &fd);

		/*Enqueue a packet to the QBMAN*/
		do {
			ret = qbman_swp_enqueue(swp, &eqdesc, &fd);
			if (ret != 0) {
				DPAA2_DBG(ETH, "Error in transmiting the frame\n");
			}
		} while (ret == -EBUSY);

		if (mbuf[loop]->flags & DPAA2BUF_ALLOCATED_SHELL)
			dpaa2_mbuf_free_shell(mbuf[loop]);
	}
	return loop;
}

int32_t dpaa2_eth_loopback(struct dpaa2_dev *dev,
			void *vq,
			uint32_t num ODP_UNUSED,
			dpaa2_mbuf_pt mbuf[] ODP_UNUSED)
{
	struct dpaa2_dev_priv *dev_priv = (struct dpaa2_dev_priv *)dev->priv;
	uint32_t rx_fqid = ((struct dpaa2_vq *)vq)->fqid;
	struct dpaa2_vq *eth_tx_vq = (struct dpaa2_vq *)(dev->tx_vq[0]);
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	struct qbman_pull_desc pulldesc1, pulldesc2;
	struct qbman_eq_desc eqdesc;
	const struct qbman_fd *fd;
	uint8_t is_last = 0, status;
	struct qbman_result *dq_storage;
	int stash = 1, dq_idx, ret;

	dq_storage = dpaa2_data_malloc(NULL, 2 * MAX_NUM_RECV_FRAMES *
		sizeof(struct qbman_result), ODP_CACHE_LINE_SIZE);
	if (!dq_storage) {
		DPAA2_ERR(ETH, "No memory");
		return DPAA2_FAILURE;
	}

	/* Prepare dequeue descriptors*/
	qbman_pull_desc_clear(&pulldesc1);
	qbman_pull_desc_set_numframes(&pulldesc1,
		MAX_NUM_RECV_FRAMES);
	qbman_pull_desc_set_fq(&pulldesc1, rx_fqid);
	qbman_pull_desc_set_storage(&pulldesc1,
		&(dq_storage[0]), (dma_addr_t)&(dq_storage[0]), stash);

	qbman_pull_desc_clear(&pulldesc2);
	qbman_pull_desc_set_numframes(&pulldesc2,
		MAX_NUM_RECV_FRAMES);
	qbman_pull_desc_set_fq(&pulldesc2, rx_fqid);
	qbman_pull_desc_set_storage(&pulldesc2,
		&(dq_storage[MAX_NUM_RECV_FRAMES]),
		(dma_addr_t)&(dq_storage[MAX_NUM_RECV_FRAMES]), stash);

	/* Prepare enqueue descriptor*/
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_no_orp(&eqdesc, DPAA2_EQ_RESP_ERR_FQ);
	qbman_eq_desc_set_response(&eqdesc, 0, 0);
	qbman_eq_desc_set_qd(&eqdesc, dev_priv->qdid, eth_tx_vq->flow_id,
		eth_tx_vq->tc_index);

	/* Pull to des1 */
	do {
		ret = qbman_swp_pull(swp, &pulldesc1);
	} while (ret == -EBUSY);

	while (!eth_sc_sigint) {
		dq_idx = is_last = 0;
		/* Loop until the first dq_storage is updated with
		 * new token by QBMAN */
		while (!qbman_result_has_new_result(swp,
			&(dq_storage[0])))
			;

		/* Pull to des2 */
		do {
			ret = qbman_swp_pull(swp, &pulldesc2);
		} while (ret == -EBUSY);

		/* Recieve the packets till Last Dequeue entry is found with respect
		 * to the above issues PULL command. */
		while (is_last != 2) {
			if ((is_last == 1) && (dq_idx <= MAX_NUM_RECV_FRAMES)) {
				dq_idx = MAX_NUM_RECV_FRAMES;
				/* Loop until the first dq_storage of second pull is
				 * updated with new token by QBMAN */
				while (!qbman_result_has_new_result(swp,
					&(dq_storage[MAX_NUM_RECV_FRAMES])))
					;

				do {
					ret = qbman_swp_pull(swp, &pulldesc1);
				} while (ret == -EBUSY);
			}

			/* Check whether Last Pull command is Expired and setting
			 * Condition for Loop termination */
			if (odp_unlikely(qbman_result_DQ_is_pull_complete(
					&(dq_storage[dq_idx])))) {
				is_last++;
				/* Check for valid frame. If not then continue */
				status = (uint8_t)qbman_result_DQ_flags(
					&(dq_storage[dq_idx]));
				if (odp_unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0))
					continue;
			}

			/* Dequeue FD from QBMAN*/
			fd = qbman_result_DQ_fd(&(dq_storage[dq_idx]));
			/* Enqueue FD to QBMAN*/
			do {
				ret = qbman_swp_enqueue(swp, &eqdesc, fd);
			} while (ret == -EBUSY);
			dq_idx++;
		}
	}

	return DPAA2_SUCCESS;
}

int32_t dpaa2_eth_setup_rx_vq(struct dpaa2_dev *dev,
				uint8_t vq_id,
				struct dpaa2_vq_param *vq_cfg)
{
	/* Function to setup RX flow information. It contains traffic class ID,
	 * flow ID, destination configuration etc.
	 */
	int32_t retcode;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = dev_priv->hw;
	struct dpni_queue cfg;
	uint8_t tc_id, flow_id;
	struct dpaa2_vq *eth_rx_vq;
	uint8_t options = 0;

	memset(&cfg, 0, sizeof(struct dpni_queue));
	eth_rx_vq = (struct dpaa2_vq *)(dev->rx_vq[vq_id]);
	eth_rx_vq->sync = ODP_SCHED_SYNC_NONE;
	/*Get the tc id and flow id from given VQ id*/
	tc_id = eth_rx_vq->tc_index;
	flow_id = eth_rx_vq->flow_id;
	if (vq_cfg) {
		if (vq_cfg->conc_dev) {
			struct conc_attr attr;
			memset(&attr, 0, sizeof(struct conc_attr));
			/*Get DPCONC object attributes*/
			dpaa2_conc_get_attributes(vq_cfg->conc_dev, &attr);

			/*Do settings to get the frame on a DPCON object*/
			options |= DPNI_QUEUE_OPT_DEST;
			cfg.destination.id      = attr.obj_id;
			cfg.destination.type    = DPNI_DEST_DPCON;
			cfg.destination.hold_active     = 0;
			cfg.destination.priority          = 0;
			dev->conc_dev		= vq_cfg->conc_dev;
			DPAA2_INFO(ETH, "DPCON ID = %d\t Prio = %d\n",
				cfg.destination.id, cfg.destination.priority);
			DPAA2_INFO(ETH, "Attaching Ethernet device %s"
				"with Channel %s\n", dev->dev_string,
				vq_cfg->conc_dev->dev_string);
		}
		if (vq_cfg->sync & ODP_SCHED_SYNC_ATOMIC) {
			options |= DPNI_QUEUE_OPT_HOLD_ACTIVE;
			cfg.destination.hold_active     = TRUE;
		}
		if (vq_cfg->sync & ODP_SCHED_SYNC_ORDERED) {
			struct opr_cfg cfg;
			pool_entry_t *pool;
			pktio_entry_t *pktio_entry;
			struct qbman_swp *swp;
			uint64_t bufs[DPAA2_MBUF_MAX_ACQ_REL];
			int ret = 0, count;
			uint32_t prev_bufs;

			/*FIXME Limiting the buffers in buffer pool upto 512
				for ordered queue. This shoud be fixed after
				the resolution of issues MC-2171 and MC-2172*/
			pktio_entry = get_pktio_entry((odp_pktio_t)dev->pktio);
			if (!pktio_entry) {
				ODP_ERR("pktio entry not found\n");
				return DPAA2_FAILURE;
			}
			pool = odp_pool_to_entry(pktio_entry->s.pkt_dpaa2.pool);
			if (!pool) {
				ODP_ERR("pool not found\n");
				return DPAA2_FAILURE;
			}
			swp = thread_io_info.dpio_dev->sw_portal;
			POOL_LOCK(&pool->s.lock);
			prev_bufs = pool->s.params.pkt.num;
			count = prev_bufs - 512;
			while(count > 0) {
				if (count > DPAA2_MBUF_MAX_ACQ_REL) {
					/*TODO Buffers acquired by the below API should be
						freed using memzone free API for re-use. Currently,
						memzones free support is not available in the
						system, so leaving the code as it*/

					ret = qbman_swp_acquire(swp, pool->s.bpid, bufs,
						DPAA2_MBUF_MAX_ACQ_REL);
					if (ret == DPAA2_MBUF_MAX_ACQ_REL) {
						count -= ret;
						pool->s.params.pkt.num -= ret;
					}
				} else {
					ret = qbman_swp_acquire(swp, pool->s.bpid, bufs, count);
					if (ret > 0) {
						count -= ret;
						pool->s.params.pkt.num -= ret;
					}
				}
			}

			if (prev_bufs != pool->s.params.pkt.num)
				ODP_PRINT("Available buffers in pool \"%s\""
						" is limited to %d\n", pool->s.name, pool->s.params.pkt.num);
			POOL_UNLOCK(&pool->s.lock);

			cfg.oprrws = 5;	/*Restoration window size = 1024 frames*/
			cfg.oa = 0;	/*Auto advance NESN window disabled*/
			cfg.olws = 2;	/*Late arrival window size = 1024 frames*/
			cfg.oeane = 0;	/*ORL resource exhaustaion advance NESN disabled*/
			cfg.oloe = 0;	/*Loose ordering disabled*/
			retcode = dpni_set_opr(dpni, CMD_PRI_LOW, dev_priv->token,
					tc_id, flow_id, OPR_OPT_CREATE, &cfg);
			if (retcode) {
				DPAA2_ERR(ETH, "Error in setting the order restoration: ErrorCode = %d\n",
									retcode);
				return DPAA2_FAILURE;
			}

		}
		eth_rx_vq->sync = vq_cfg->sync;
	}

#if !defined(BUILD_LS2080) && !defined(BUILD_LS2085)
	options |= DPNI_QUEUE_OPT_FLC;
	cfg.flc.stash_control = true;
	cfg.flc.value &= 0xFFFFFFFFFFFFFFC0;
	cfg.flc.value |= LDPAA_ETH_DEV_STASH_SIZE;
#endif
	options |= DPNI_QUEUE_OPT_USER_CTX;
	cfg.user_context = (uint64_t)(eth_rx_vq);
	retcode = dpni_set_queue(dpni, CMD_PRI_LOW, dev_priv->token,
				 DPNI_QUEUE_RX, tc_id, flow_id,
				 options, &cfg);
	if (retcode) {
		DPAA2_ERR(ETH, "Error in setting the rx flow: ErrorCode = %d\n",
								retcode);
		return DPAA2_FAILURE;
	}
	eth_rx_vq->fq_type = DPAA2_FQ_TYPE_RX;
	eth_rx_vq->qmfq.cb = dpaa2_eth_cb_dqrr_fd_to_mbuf;

	/* if prefetch mode is enabled and not the conc device*/
	if ((dev_priv->flags & DPAA2_PREFETCH_MODE)
		&& (!vq_cfg || !vq_cfg->conc_dev)) {
		eth_rx_vq->dq_storage[0] = dpaa2_data_malloc(NULL,
			NUM_MAX_RECV_FRAMES * 2 * sizeof(struct qbman_result),
			ODP_CACHE_LINE_SIZE);
		if (!eth_rx_vq->dq_storage[0]) {
			DPAA2_ERR(FW, "Memory allocation failure");
			return DPAA2_FAILURE;
		}
		eth_rx_vq->dq_storage[1] = eth_rx_vq->dq_storage[0] + NUM_MAX_RECV_FRAMES;
		eth_rx_vq->toggle = -1;
	}

	return DPAA2_SUCCESS;
}

int32_t dpaa2_eth_setup_tx_vq(struct dpaa2_dev *dev, uint32_t num,
					uint32_t action ODP_UNUSED)
{
	/* Function to setup TX flow information. It contains traffic class ID,
	 * flow ID.
	 */
	int32_t retcode;
	uint16_t flow_id = 0;
	 uint8_t tc_index = 0;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = dev_priv->hw;
	struct dpni_queue tx_flow_cfg;
	struct dpni_queue tx_flow_attr;
	struct dpaa2_vq *eth_tx_vq;
	uint8_t options = 0;
	struct dpni_queue_id qid;

	memset(&tx_flow_cfg, 0, sizeof(struct dpni_queue));
	for (tc_index = 0; tc_index < num; tc_index++) {
		retcode = dpni_set_queue(dpni, CMD_PRI_LOW, dev_priv->token,
					 DPNI_QUEUE_TX, tc_index, flow_id,
					options, &tx_flow_cfg);
		if (retcode) {
			DPAA2_ERR(ETH, "Error in setting the tx flow\n"
				"ErrorCode = %d", retcode);
			return DPAA2_FAILURE;
		}
		memset(&qid, 0, sizeof(struct dpni_queue_id));
		retcode = dpni_get_queue(dpni, CMD_PRI_LOW, dev_priv->token,
					 DPNI_QUEUE_TX, tc_index, flow_id,
					&tx_flow_attr, &qid);
		if (retcode) {
			DPAA2_ERR(ETH, "Error in getting the tx flow\n"
				"ErrorCode = %d", retcode);
			return DPAA2_FAILURE;
		}
		eth_tx_vq = (struct dpaa2_vq *)(dev->tx_vq[tc_index]);
		eth_tx_vq->tc_index = tc_index;
		eth_tx_vq->flow_id = flow_id;
		eth_tx_vq->fq_type = DPAA2_FQ_TYPE_TX;
		eth_tx_vq->fqid = qid.fqid;
	}
	return DPAA2_SUCCESS;
}

int dpaa2_eth_set_rx_vq_notification(
		struct dpaa2_dev *dev,
		uint8_t vq_id,
		uint64_t user_context,
		dpaa2_notification_callback_t cb)
{
	/* Function to setup RX flow information. It contains traffic class ID,
	 * flow ID, destination configuration etc.
	 */
	int32_t retcode;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = dev_priv->hw;
	struct dpni_queue cfg;
	struct dpaa2_vq *eth_rx_vq = (struct dpaa2_vq *)(dev->rx_vq[vq_id]);
	uint64_t notifier_context;
	uint8_t options = 0;

	if (!notif_dpio) {
		DPAA2_ERR(ETH, "No notification portal available");
		return DPAA2_FAILURE;
	}

	retcode = dpaa2_reg_with_notifier(user_context, cb,
		&(eth_rx_vq->eventfd), &notifier_context);
	if (retcode != DPAA2_SUCCESS) {
		DPAA2_ERR(ETH, "dpaa2_reg_with_notifier failed");
		return DPAA2_FAILURE;
	}

	memset(&cfg, 0, sizeof(struct dpni_queue));
	options |= DPNI_QUEUE_OPT_USER_CTX;
	options |= DPNI_QUEUE_OPT_DEST;
	cfg.user_context = notifier_context;
	cfg.destination.id	= notif_dpio->hw_id;
	cfg.destination.type	= DPNI_DEST_DPIO;
	cfg.destination.hold_active	= 0;
	retcode = dpni_set_queue(dpni, CMD_PRI_LOW, dev_priv->token,
				 DPNI_QUEUE_RX, eth_rx_vq->tc_index,
				 eth_rx_vq->flow_id, options, &cfg);
	if (retcode) {
		DPAA2_ERR(ETH, "Error in setting the rx flow: ErrorCode = %x\n",
								retcode);
		return DPAA2_FAILURE;
	}

	return DPAA2_SUCCESS;
}

int32_t dpaa2_eth_attach_bp_list(struct dpaa2_dev *dev,
			void *blist)
{
	/* Function to attach a DPNI with a buffer pool list. Buffer pool list
	 * handle is passed in blist.
	 */
	int32_t loop, retcode;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = dev_priv->hw;
	struct dpni_pools_cfg bpool_cfg = {0};
	struct dpaa2_bp_list *bp_list = (struct dpaa2_bp_list *)blist;

	/*Attach buffer pool to the network interface as described by the user*/
	bpool_cfg.num_dpbp = bp_list->num_buf_pools;
	for (loop = 0; loop < bpool_cfg.num_dpbp; loop++) {
		bpool_cfg.pools[loop].dpbp_id =
				bp_list->buf_pool[loop].dpbp_node->dpbp_id;
		bpool_cfg.pools[loop].backup_pool = 0;
		bpool_cfg.pools[loop].buffer_size =
			bp_list->buf_pool[loop].size;
	}

	retcode = dpni_set_pools(dpni, CMD_PRI_LOW, dev_priv->token, &bpool_cfg);
	if (retcode < 0) {
		DPAA2_ERR(ETH, "Error in attaching the buffer pool list"
						"Error code = %d\n", retcode);
		return retcode;
	}

	dev_priv->bp_list = bp_list;
	return DPAA2_SUCCESS;
}

int32_t dpaa2_eth_reset(struct dpaa2_dev *dev)
{
	int32_t retcode;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = dev_priv->hw;

	retcode = dpni_reset(dpni, CMD_PRI_LOW, dev_priv->token);
	if (retcode != 0) {
		DPAA2_ERR(ETH, "Error in Resetting the Ethernet"
				" device: ErrorCode = %d\n", retcode);
	}

	return retcode;
}

int dpaa2_eth_get_eventfd_from_vq(void *vq)
{
	struct dpaa2_vq *rx_vq = vq;
	return rx_vq->eventfd;
}

int dpaa2_eth_get_fqid(void *vq)
{
	struct dpaa2_vq *rx_vq = vq;
	return rx_vq->fqid;
}

static void *dpaa2_eth_sg_fd_to_mbuf(
		struct qbman_swp *qm ODP_UNUSED,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr)
{
	struct dpaa2_sg_entry *sgt, *sge;
	dma_addr_t sg_addr;
	uint32_t sg_length;
	int i = 0;
	uint32_t frc;
	uint64_t fd_addr, p_annotation;
	struct dpaa2_mbuf *first_seg, *next_seg, *cur_seg;

	/*Get annotation pointer*/
	fd_addr = (uint64_t)DPAA2_IOVA_TO_VADDR(DPAA2_GET_FD_ADDR(fd));
	cur_seg = DPAA2_INLINE_MBUF_FROM_BUF(fd_addr,
			bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size);

	/*Get Scatter gather table address*/
	sgt = (struct dpaa2_sg_entry *)(fd_addr + DPAA2_GET_FD_OFFSET(fd));

	sge = &sgt[i++];
	sg_addr = (uint64_t)DPAA2_IOVA_TO_VADDR(dpaa2_sg_get_addr(sge));
	sg_length = dpaa2_sg_get_len(sge);

	/*First Scatter gather entry*/
	first_seg = DPAA2_INLINE_MBUF_FROM_BUF(sg_addr,
			bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size);
	cur_seg->head = (uint8_t *)sgt;
	cur_seg->data = cur_seg->head;
	cur_seg->next_sg = first_seg;
	/*Prepare all the metadata for first segment*/
	dpaa2_inline_mbuf_reset(first_seg);
	_odp_buffer_type_set(first_seg, ODP_EVENT_PACKET);
	first_seg->head = (uint8_t *)sg_addr;
	first_seg->data = (uint8_t *)sg_addr + dpaa2_sg_get_offset(sge);
	first_seg->frame_len    = sg_length;
	first_seg->tot_frame_len = first_seg->frame_len;
	BIT_SET_AT_POS(first_seg->eth_flags, DPAA2BUF_IS_SEGMENTED);

	if (fd->simple.ctrl & DPAA2_FD_CTRL_PTA)
		p_annotation = fd_addr + DPAA2_FD_PTA_SIZE;
	else
		p_annotation = fd_addr;

	first_seg->hw_annot = p_annotation;
	/* Prefetch annotation and data */
	odp_prefetch(first_seg->hw_annot);
	odp_prefetch(first_seg->data);

	frc = DPAA2_GET_FD_FRC(fd);
	if (frc & DPAA2_FD_FRC_FASV)
		first_seg->timestamp = odp_be_to_cpu_64
					(*((uint64_t *)(p_annotation +
					DPAA2_ETH_TIMESTAMP_OFFSET)));

	/* Fetch the User context */
	first_seg->vq = (void *)qbman_result_DQ_fqd_ctx(dqrr);
	cur_seg = first_seg;

	while (!dpaa2_sg_is_final(sge)) {
		sge = &sgt[i++];
		sg_addr = (uint64_t)DPAA2_IOVA_TO_VADDR(dpaa2_sg_get_addr(sge));
		sg_length = dpaa2_sg_get_len(sge);
		next_seg = DPAA2_INLINE_MBUF_FROM_BUF(sg_addr,
				bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size);
		dpaa2_inline_mbuf_reset(next_seg);
		_odp_buffer_type_set(next_seg, ODP_EVENT_PACKET);
		next_seg->head  = (uint8_t *)sg_addr;
		next_seg->data  = (uint8_t *)sg_addr + dpaa2_sg_get_offset(sge);
		next_seg->frame_len     = sg_length;
		first_seg->tot_frame_len += next_seg->frame_len;
		cur_seg->next_sg = next_seg;
		cur_seg = next_seg;
	}

	first_seg->end_off = bpid_info[DPAA2_GET_FD_BPID(fd)].size -
				(DPAA2_FD_PTA_SIZE + DPAA2_MBUF_HW_ANNOTATION);

	/* Detect jumbo frames */
	if (first_seg->tot_frame_len > ODPH_ETH_LEN_MAX)
		BIT_SET_AT_POS(first_seg->eth_flags, DPAA2BUF_IS_JUMBO);

	return (void *)first_seg;
}

static void *dpaa2_eth_contig_fd_to_mbuf(
		struct qbman_swp *qm ODP_UNUSED,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr)
{
	dpaa2_mbuf_pt mbuf;
	uint32_t frc;
	uint8_t *p_annotation;
	uint64_t fd_addr = (uint64_t)(DPAA2_IOVA_TO_VADDR(
		DPAA2_GET_FD_ADDR(fd)));

	if (odp_unlikely(DPAA2_GET_FD_IVP(fd))) {
		mbuf = dpaa2_mbuf_alloc_shell();
		if (!mbuf) {
			DPAA2_ERR(ETH, "Unable to allocate shell");
			return NULL;
		}
		mbuf->bpid = DPAA2_GET_FD_BPID(fd);
		mbuf->priv_meta_off = DPAA2_GET_FD_OFFSET(fd);
		mbuf->head = (uint8_t *)fd_addr + mbuf->priv_meta_off;
		mbuf->end_off = DPAA2_GET_FD_LEN(fd);

	} else {
		mbuf = DPAA2_INLINE_MBUF_FROM_BUF(fd_addr,
			bpid_info[DPAA2_GET_FD_BPID(fd)].meta_data_size);
		dpaa2_inline_mbuf_reset(mbuf);
		_odp_buffer_type_set(mbuf, ODP_EVENT_PACKET);
	}

	p_annotation	= (uint8_t *)fd_addr;
	mbuf->head      = (uint8_t *)fd_addr + DPAA2_FD_PTA_SIZE
					+ DPAA2_MBUF_HW_ANNOTATION;
	mbuf->data	= (uint8_t *)fd_addr + DPAA2_GET_FD_OFFSET(fd);
	mbuf->frame_len	= DPAA2_GET_FD_LEN(fd);
	mbuf->tot_frame_len = mbuf->frame_len;
	mbuf->end_off = bpid_info[DPAA2_GET_FD_BPID(fd)].size -
				(DPAA2_FD_PTA_SIZE + DPAA2_MBUF_HW_ANNOTATION);

	/* Detect jumbo frames */
	if (mbuf->frame_len > ODPH_ETH_LEN_MAX)
		BIT_SET_AT_POS(mbuf->eth_flags, DPAA2BUF_IS_JUMBO);

	if (fd->simple.ctrl & DPAA2_FD_CTRL_PTA)
		p_annotation += DPAA2_FD_PTA_SIZE;

	mbuf->hw_annot = (uint64_t)p_annotation;
	/* Prefetch annotation and data */
	odp_prefetch(mbuf->hw_annot);
	odp_prefetch(mbuf->data);

	frc = DPAA2_GET_FD_FRC(fd);
	if (frc & DPAA2_FD_FRC_FASV)
		mbuf->timestamp = odp_be_to_cpu_64
			(*((uint64_t *)(p_annotation +
			DPAA2_ETH_TIMESTAMP_OFFSET)));

	/* Fetch the User context */
	mbuf->vq = (void *)qbman_result_DQ_fqd_ctx(dqrr);

	/*TODO - based on vq type, store the DQRR in mbuf*/
	return (void *)mbuf;
}

inline void *dpaa2_eth_cb_dqrr_fd_to_mbuf(
		struct qbman_swp *qm ODP_UNUSED,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr)
{
	enum qbman_fd_format fmt;

	/*First check FD format i.e. contigous or S/G ?*/
	fmt = qbman_fd_get_format(fd);
	if (fmt == qbman_fd_single)
		return dpaa2_eth_contig_fd_to_mbuf(qm, fd, dqrr);
	else if (fmt == qbman_fd_sg)
		return dpaa2_eth_sg_fd_to_mbuf(qm, fd, dqrr);
	else
		return NULL;	/*Not supported FD format*/
}

static inline void dpaa2_eth_parse_tx_conf_error(const struct qbman_fd *fd,
				dpaa2_mbuf_pt mbuf)
{
	uint32_t status, errors = (fd->simple).ctrl;
	struct dpaa2_fas *fas;

	DPAA2_INFO(ETH, "Errors returned = %0x\n", errors);
	/*First - Check error in FD Error bits*/
	if (errors & DPAA2_FD_CTRL_FSE) {
		DPAA2_DBG(ETH, "Frame size too long\n");
		mbuf->eth_flags =
			mbuf->eth_flags |
			DPAA2BUF_ERROR_FRAME_TOO_LONG | DPAA2BUF_ERROR_TX;
#ifdef DPAA2_DEBUG_XSTATS
		xstats.tx_frm_len_err++;
#endif
	}
	if (errors & DPAA2_FD_CTRL_SBE) {
		DPAA2_DBG(ETH, "System bus error while transmitting\n");
		mbuf->eth_flags =
			mbuf->eth_flags |
			DPAA2BUF_ERROR_SYSTEM_BUS_ERROR |
			DPAA2BUF_ERROR_TX;
#ifdef DPAA2_DEBUG_XSTATS
		xstats.tx_sys_bus_err++;
#endif
	}
	if (errors & DPAA2_FD_CTRL_UFD) {
		DPAA2_DBG(ETH, "Unsupported frame format\n");
		mbuf->eth_flags =
			mbuf->eth_flags | DPAA2BUF_ERROR_TX;
	}
	/*Second - Check for the error bits in annotation area*/
	if (errors & DPAA2_FD_CTRL_FAERR) {
		fas = (struct dpaa2_fas *)
			(DPAA2_GET_FD_ADDR(fd) + DPAA2_ETH_PRIV_DATA_SIZE);
		status = odp_be_to_cpu_32(fas->status);
		mbuf->eth_flags =
				mbuf->eth_flags |
				DPAA2BUF_ERROR_TX;
		DPAA2_NOTE(ETH, "TxConf frame error(s): 0x%08x\n",
				status & DPAA2_ETH_TXCONF_ERR_MASK);
	}
	DPAA2_INFO(ETH, "Frame Descriptor parsing is completed\n");
	return;
}

/*todo - this function needs to be optimized*/
void *dpaa2_eth_cb_dqrr_tx_conf_err(
		struct qbman_swp *qm,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr)
{
	dpaa2_mbuf_pt mbuf;
	mbuf = dpaa2_eth_cb_dqrr_fd_to_mbuf(qm, fd, dqrr);
	if (mbuf)
		dpaa2_eth_parse_tx_conf_error(fd, mbuf);
	return (void *)mbuf;
}

/*! @} */
