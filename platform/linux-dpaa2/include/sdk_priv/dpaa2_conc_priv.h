/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_conc_priv.h
 * @description		Private functions & MACRO definitions for concentrator
			Type Device
 */

#ifndef _DPAA2_CONC_PRIV_H_
#define _DPAA2_CONC_PRIV_H_

/*Standard header files*/
#include <stddef.h>

/*DPAA2 header files*/
#include <dpaa2_dev.h>
#include <odp/api/hints.h>
#include <dpaa2_mpool.h>
#include <odp/api/std_types.h>
#include <odp/api/spinlock.h>


#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DEV_NAME_LENGTH		32

#define DPAA2_MAX_DEVICES_PER_CONC	16

#define DPAA2_INVALID_CHANNEL_ID		((uint32_t)(-1))

/*!
 * Structure to contain private information for DPCON devices.
 */
struct dpaa2_conc_priv {
	char name[MAX_DEV_NAME_LENGTH];
};

/*!
 * Structure to attributes for DPCON devices.
 */
struct conc_attr {
	int32_t obj_id;	/*!< DPCONC object ID */
	uint16_t ch_id;	/*!< Channel ID to be used for dequeue operation */
	uint8_t num_prio;/*!< Number of prioties within the Channel */
};

/*!
 * @details	Concentrator API to register to DPAA2 framework. It will be called
 *		by DPAA2 core framework and corresponding device driver will be
 *		added to DPAA2's driver list.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_conc_driver_init(void);

/*!
 * @details	Concentrator API to unregister to DPAA2 framework. It will be called
 *		by DPAA2 core framework and corresponding device driver will be
 *		removed	from DPAA2's driver list.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_conc_driver_exit(void);

/*!
 * @details	Concentrator driver probe function to initialize the device.
 *
 * @param[in]	dev - Pointer to DPAA2 concentrator device
 *
 * @param[in]	data - Pointer to device specific configuration. NULL otherwise.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_conc_probe(struct dpaa2_dev *dev, const void *data);

/*!
 * @details	Concentrator driver remove function to remove the device.
 *
 * @param[in]	dev - Pointer to DPAA2 Concentrator device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_conc_remove(struct dpaa2_dev *dev);

/*!
 * @details	Enable a Concentrator device for use of RX/TX.
 *
 * @param[in]	dev - Pointer to DPAA2 Concentrator device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_conc_start(struct dpaa2_dev *dev);

/*!
 * @details	Disable a  Concentrator device for use of RX/TX.
 *		After disabling no data can be Received or transmitted
 *
 * @param[in]	dev - Pointer to DPAA2 Concentrator device
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_conc_stop(struct dpaa2_dev *dev);

/*!
 * @details	Receives frames from given DPAA2 device and VQ.
 *
 * @param[in]	dev - Pointer to DPAA2 Concentrator device
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
int32_t dpaa2_conc_recv(struct dpaa2_dev *dev,
			void *vq,
			uint32_t num,
			dpaa2_mbuf_pt buf[]);


/*!
 * @details	Returns attributes for concentrator device.
 *
 * @param[in]	dev - Pointer to DPAA2 concentrator  device.
 *
 * @param[in,out] attr - Pointer to attributs structure.
 *
 */
void dpaa2_conc_get_attributes(struct dpaa2_dev *dev, struct conc_attr *attr);


int32_t dpaa2_attach_device_to_conc(struct dpaa2_dev *dev, uint8_t vq_id,
					struct dpaa2_dev *conc);


#ifdef __cplusplus
}
#endif

#endif /* _DPAA2_CONC_PRIV_H_ */
