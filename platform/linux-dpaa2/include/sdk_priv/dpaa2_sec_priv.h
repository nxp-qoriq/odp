/*-
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */


/**
 * @file		dpaa2_sec_priv.h
 * @description	Private function & definitions for DPAA2 Sec Device
 */

#ifndef _DPAA2_SEC_PRIV_H_
#define _DPAA2_SEC_PRIV_H_

/*Standard header files*/
#include <stdint.h>
#include <stddef.h>

/*DPAA2 header files*/
#include <dpaa2_dev.h>
#include <odp/api/hints.h>
#include <dpaa2_mpool.h>
#include <dpaa2_vq.h>

/*QBMAN header files*/
#include <fsl_qbman_portal.h>
#include <fsl_qbman_base.h>

#define MAX_DESC_SIZE	64

enum shr_desc_type {
	DESC_UPDATE,
	DESC_FINAL,
	DESC_INITFINAL,
};

struct dpaa2_sec_priv {
	/* More Info to be added */
	struct dpaa2_vq rx_vq[MAX_RX_VQS];
	struct dpaa2_vq tx_vq[MAX_TX_VQS];
};


/* SEC Flow Context Descriptor */
struct sec_flow_context {
	/* word 0 */
	uint16_t word0_sdid;		/* 11-0  SDID */
	uint16_t word0_res;		/* 31-12 reserved */

	/* word 1 */
	uint8_t word1_sdl;		/* 5-0 SDL */
					/* 7-6 reserved */

	uint8_t word1_bits_15_8;        /* 11-8 CRID */
					/* 14-12 reserved */
					/* 15 CRJD */

	uint8_t word1_bits23_16;	/* 16  EWS */
					/* 17 DAC */
					/* 18,19,20 ? */
					/* 23-21 reserved */

	uint8_t word1_bits31_24;	/* 24 RSC */
					/* 25 RBMT */
					/* 31-26 reserved */

	/* word 2  RFLC[31-0] */
	uint32_t word2_rflc_31_0;

	/* word 3  RFLC[63-32] */
	uint32_t word3_rflc_63_32;

	/* word 4 */
	uint16_t word4_iicid;		/* 15-0  IICID */
	uint16_t word4_oicid;		/* 31-16 OICID */

	/* word 5 */
	uint32_t word5_ofqid:24;		/* 23-0 OFQID */
	uint32_t word5_31_24:8;
					/* 24 OSC */
					/* 25 OBMT */
					/* 29-26 reserved */
					/* 31-30 ICR */

	/* word 6 */
	uint32_t word6_oflc_31_0;

	/* word 7 */
	uint32_t word7_oflc_63_32;

	/* Word 8-15 storage profiles */
	uint16_t dl;			/**<  DataLength(correction) */
	uint16_t reserved;		/**< reserved */
	uint16_t dhr;			/**< DataHeadRoom(correction) */
	uint16_t mode_bits;		/**< mode bits */
	uint16_t bpv0;			/**< buffer pool0 valid */
	uint16_t bpid0;			/**< Bypass Memory Translation */
	uint16_t bpv1;			/**< buffer pool1 valid */
	uint16_t bpid1;			/**< Bypass Memory Translation */
	uint64_t word_12_15[2];		/**< word 12-15 are reserved */
};

struct sec_flc_desc {
	struct sec_flow_context flc;
	uint32_t desc[MAX_DESC_SIZE];
};

struct ctxt_priv {
	struct sec_flc_desc flc_desc[0];
};

struct dpaa2_per_thread_info {
	struct qbman_swp *swp; /*!< I/O handle for this thread,
				* for the use of DPAA2 framework. This is
				* duplicated as will be used frequently */
	int32_t notification_eventfd; /*!< Eventfd registered for TX Error,
				* Tx Confirmation IO events. This will be
				* filled by DPAA2 and application will
				* listen on this fd to get TX Error &
				* Tx Confirmation events, if configured
				* to do so */
	struct dpaa2_dpio_dev *dpio_dev;
};

/*!
 * @details	SEC API to register to DPAA2 framework. It will be called
 *		by DPAA2 and will register its device driver to DPAA2.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_sec_driver_init(void);

/*!
 * @details	SEC API to unregister to DPAA2 framework. It will be called
 *		by DPAA2 and will unregister its device driver to DPAA2.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_sec_driver_exit(void);

/*!
 * @details	SEC driver probe function to initialize the device.
 *
 * @param[in]	dev - Pointer to DPAA2 SEC device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_sec_probe(struct dpaa2_dev *dev, const void *);

/*!
 * @details	SEC driver remove function to remove the device.
 *
 * @param[in]	dev - Pointer to DPAA2 SEC device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_sec_remove(struct dpaa2_dev *dev);

/*!
 * @details	Enable a SEC device for use of RX/TX.
 *
 * @param[in]	dev - Pointer to DPAA2 SEC device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_sec_start(struct dpaa2_dev *dev);

/*!
 * @details	Setup a RX virtual queues to a SEC device.
 *
 * @param[in]	dev - Pointer to DPAA2 SEC device
 *
 * @param[in]	vq_index - Pointer to DPAA2 SEC device
 *
 * @param[in]   vq_cfg - Pointer vq configuration structure
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_sec_setup_rx_vq(struct dpaa2_dev *dev,
				uint8_t vq_id,
				struct dpaa2_vq_param *vq_cfg);

/*!
 * @details	Disable a SEC device for use of RX/TX.
 *		After disabling no data can be Received or transmitted
 *
 * @param[in]	dev - Pointer to DPAA2 SEC device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_sec_stop(struct dpaa2_dev *dev);

/*!
 * @details	Receives frames from given DPAA2 device and VQ.
 *
 * @param[in]	dev - Pointer to DPAA2 SEC device
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
int32_t dpaa2_sec_recv(void *vq,
			uint32_t num,
			dpaa2_mbuf_pt buf[]);

void *dpaa2_sec_cb_dqrr_fd_to_mbuf(
		struct qbman_swp *qm,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr);

int32_t dpaa2_sec_dev_list_init(void);

/*!
 * @details	Returns the dpaa2_dev SEC object
 *
 * @param[in]	none
 *
 * @return	pointer to SEC object of dpaa2_dev type
 */
struct dpaa2_dev *dpaa2_sec_get_dev(void);

/*!
 * @details	Attach the given sec device to buffer pool list. User can
 *		add only one buffer pool list on a device, whereas user can
 *		attach same buffer pool list accross multiple devices.
 *
 * @param[in]	dev - Pointer to DPAA2 SEC device.
 *
 * @param[in]	bp_list - Buffer pool list handle.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
int32_t dpaa2_sec_attach_bp_list(struct dpaa2_dev *dev,
			void *bp_list);


/*!
 * @details	Add the given device to the sec device list.
 *
 * @param[in]	dev - Pointer to DPAA2 SEC device.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
int32_t dpaa2_sec_dev_list_add(struct dpaa2_dev *dev);

#endif /* _DPAA2_SEC_PRIV_H_ */
