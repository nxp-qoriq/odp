/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_eth_priv.h
 * @description		Private functions & MACRO definitions for DPAA2 Ethernet
			Type Device
 */

#ifndef _DPAA2_ETH_PRIV_H_
#define _DPAA2_ETH_PRIV_H_

/*Standard header files*/
#include <stddef.h>

/*DPAA2 header files*/
#include <dpaa2_ethdev.h>
#include <dpaa2_ether.h>
#include <dpaa2_dev.h>
#include <odp/api/hints.h>
#include <dpaa2_mpool.h>
#include <odp/api/std_types.h>

/*MC header files*/
#include <fsl_dpni.h>
/*QBMAN header files*/
#include <fsl_qbman_portal.h>

#ifdef __cplusplus
extern "C" {
#endif
/* Macros to define feature enable/disable options */
#define ETHDRV_DEVNAME 24
#define DPAA2_PROMISCIOUS_MODE_ENABLE	BIT_POS(0) /*!< Enable promiscious mode*/
#define DPAA2_CHECKSUM_ENABLE		BIT_POS(1) /*!< Enable csum validation
							mode*/
#define DPAA2_GRO_ENABLE			BIT_POS(2) /*!< Enable GRO*/
#define DPAA2_GSO_ENABLE			BIT_POS(3) /*!< Enable GSO*/
#define DPAA2_SG_ENABLE			BIT_POS(4) /*!< Enable SG support*/
#define DPAA2_FRAG_ENABLE		BIT_POS(5) /*!< Enable fragmentation
							support*/
#define DPAA2_REASSEMBLY_ENABLE		BIT_POS(6) /*!< Reassembly
							support enabled */
#define DPAA2_PAUSE_CNTRL_ENABLE		BIT_POS(7) /*!< Enable Pause control
							support*/
#define DPAA2_LOOPBACK_ENABLE		BIT_POS(8) /*!< Enable Loopback mode*/
#define DPAA2_TIMESTAMP_ENABLE		BIT_POS(9) /*!< Enable 1588 Timestamp*/

#define DPAA2_PROMISCUOUS_ENABLE		BIT_POS(10) /*!< Enable Promiscuous mode*/
#define DPAA2_MULTICAST_ENABLE		BIT_POS(11) /*!< Enable Multicast mode*/

/*Macros to define QBMAN enqueue options */
#define DPAA2_ETH_EQ_DISABLE		0	/*!< Dont Enqueue the Frame */
#define DPAA2_ETH_EQ_RESP_ON_SUCC	1	/*!< Enqueue the Frame with
							response after success*/
#define DPAA2_ETH_EQ_RESP_ON_FAIL	2	/*!< Enqueue the Frame with
							response after failure*/
#define DPAA2_ETH_EQ_NO_RESP		3	/*!< Enqueue the Frame without
							response*/
/*
  * Macros specific to Ethernet
  */
#define DPAA2_ETH_PRIV_DATA_SIZE	64	/*!< Ethernet Private data size*/

#define DPAA2_ETH_DEF_PRIO	0	/*!< Default Prioroty used for DPCON*/
/*
 * Definitions of all functions exported by an Ethernet driver through the
 * the generic structure of type *eth_config_fops*
 */


#define NET_IF_ADMIN_PRIORITY 4
#define NET_IF_RX_PRIORITY 4

/**
 * @internal Structure containing configuration
 *		parameters for an Ethernet driver.
 */
struct dpaa2_eth_config {
	uint32_t		hw_features;
	struct dpaa2_eth_link	link_info;
	uint16_t		headroom;
	/**< headroom required in device buffers */
	uint16_t		mtu;
	/**< MTU for this device */
	uint8_t name[ETHDRV_DEVNAME];
	/*TODO Think on this structure fields*/
	uint8_t			max_tcs;
	uint8_t			max_dist_per_tc[DPNI_MAX_TC];
	uint8_t			mac_addr[ETH_ADDR_LEN];
	/**< Ethernet MAC address */
};

/**
 * @internal A structure containing Operations & Configuration
 * parameters for an Ethernet driver.
 */
struct dpaa2_eth_priv {
	struct dpaa2_eth_config		cfg;
	struct dpni_cfg			default_param;
	struct queues_config		q_config;
};

/*!
 * @details	Ethernet API to register to DPAA2 framework. It will be called
 *		by DPAA2 core framework and it will register its device driver
 *		to DPAA2.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_driver_init(void);

/*!
 * @details	Ethernet API to unregister to DPAA2 framework. It will be called
 *		by DPAA2 core framework and it will unregister its device driver
 *		to DPAA2.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_driver_exit(void);

/*!
 * @details	Ethernet driver default configuration API. It reset the DPNI
 *		to its default state.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_defconfig(struct dpaa2_dev *dev);

/*!
 * @details	Ethernet driver probe function to initialize the device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_probe(struct dpaa2_dev *dev, const void *data);

/*!
 * @details	Ethernet driver open function to open and configure the device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_open(struct dpaa2_dev *dev);

/*!
 * @details	Ethernet driver remove function to remove the device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_remove(struct dpaa2_dev *dev);

/*!
 * @details	Ethernet driver close function to unconfigure and close the device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_close(struct dpaa2_dev *dev);

/*!
 * @details	Enable a ethernet device for use of RX/TX.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_start(struct dpaa2_dev *dev);

/*!
 * @details	Setup a RX virtual queues to a Ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	vq_index - Pointer to DPAA2 Ethernet device
 *
 * @param[in]   vq_cfg - Pointer vq configuration structure
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_setup_rx_vq(struct dpaa2_dev *dev,
				uint8_t vq_id,
				struct dpaa2_vq_param *vq_cfg);

/*!
 * @details	Setup a TX virtual queues to a Ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	num - Number of TX queues
 *
 * @param[in]  action - To define action on TX for confirmation/error
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_setup_tx_vq(struct dpaa2_dev *dev, uint32_t num,
					uint32_t action);

/*!
 * @details	Set the notification on the Ethernet device.
 *
 * @param[in]	dev - Pointer to Ethernet device.
 *
 * @param[in]	vq_index - Index of virtual queue out of total available RX VQs.
 *
 * @param[in]	user_context - User context provided by the user.
 *
 * @param[in]	cb - Callback function provided by the user.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int dpaa2_eth_set_rx_vq_notification(
		struct dpaa2_dev *dev,
		uint8_t vq_id,
		uint64_t user_context,
		dpaa2_notification_callback_t cb);

/*!
 * @details	Disable a ethernet device for use of RX/TX.
 *		After disabling no data can be Received or transmitted
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_stop(struct dpaa2_dev *dev);

/*!
 * @details	Receives frames from given DPAA2 device
 *		and VQ in optimal mode.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	vq - Pointer to Virtual Queue
 *
 * @param[in]	buf - Pointer to DPAA2 buffer which will be passed to user
 *
 * @param[in]	num - Number of frames to be received
 *
 * @returns	Actual total number of frames received on success.
 *		DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_prefetch_recv(struct dpaa2_dev *dev,
			void *vq,
			uint32_t num,
			dpaa2_mbuf_pt buf[]);


/*!
 * @details	Receives frames from given DPAA2 device and VQ.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	vq - Pointer to Virtual Queue
 *
 * @param[in]	buf - Pointer to DPAA2 buffer which will be passed to user
 *
 * @param[in]	num - Number of frames to be received
 *
 * @returns	Actual total number of frames received on success.
 *		DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_recv(struct dpaa2_dev *dev,
			void *vq,
			uint32_t num,
			dpaa2_mbuf_pt buf[]);

/*!
 * @details	Transmits frames to given DPAA2 device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	vq - Pointer to Virtual Queue
 *
 * @param[in]	buf - Pointer to DPAA2 buffers which are to be transmited.
 *
 * @param[in]	num - Number of frames to be transmited
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_xmit(struct dpaa2_dev *dev,
			void *vq,
			int32_t num,
			const dpaa2_mbuf_pt buf[]);

/*!
 * @details	Transmits frames to given fqid. API added
 *		to test the ODP queue's test
 *
 * @param[in]	vq - Pointer to Virtual Queue
 *
 * @param[in]	buf - Pointer to DPAA2 buffers which are to be transmited.
 *
 * @param[in]	num - Number of frames to be transmited
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_xmit_fqid(void *vq,
			uint32_t num,
			dpaa2_mbuf_pt buf[]);

/*!
 * @details	Internally loopback the frames from given
 *		Ethernet device and VQ.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	vq - Pointer to Virtual Queue
 *
 * @param[in]	buf - This is unused internally and is present here to
 *		maintain compatibility with the dpaa2_eth_recv
 *
 * @param[in]	num - This is unused internally and is present here to
 *		maintain compatibility with the dpaa2_eth_recv
 *
 * @returns	Actual total number of frames received on success.
 *		DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_loopback(struct dpaa2_dev *dev,
			void *vq,
			uint32_t num,
			dpaa2_mbuf_pt buf[]);


/*!
 * @details	Get the eventfd corresponding to a VQ
 *
 * @param[in]	vq - Pointer to Virtual Queue
 *
 * @returns	Corresponding eventfd
 *
 */
int dpaa2_eth_get_eventfd_from_vq(void *vq);


/*!
 * @details	Get the FQID corresponding to a Rx VQ
 *
 * @param[in]	vq - Pointer to Rx Virtual Queue
 *
 * @returns	Corresponding FQID
 *
 */
int dpaa2_eth_get_fqid(void *vq);


#ifdef __cplusplus
}
#endif

#endif /* _DPAA2_ETH_PRIV_H_ */
