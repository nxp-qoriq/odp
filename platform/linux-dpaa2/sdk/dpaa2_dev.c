/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		dpaa2_dev.c
 * @description	Generic Device framework functions
 */
#include <odp/api/std_types.h>
#include <dpaa2_common.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_internal.h>
#include <dpaa2_vq.h>

/************   GLobal parameters ****************/

/* The DPAA2 drivers– list of registered drivers */
/* Drivers required for NIC, SEC, AIOP_CI, PME, DCE */
struct dpaa2_driver *dpaa2_driver_list[DPAA2_MAX_DEV];

/**
 * The DPAA2 device table.
 * It has all devices except for DPIO devices
 */
struct dpaa2_device_list device_list;
int ndev_count;

/**
 *  Resource container's object counts
 */
struct dpaa2_container_objects dprc_objects = {0};

void dpaa2_register_driver(struct dpaa2_driver *drv)
{

	/* Check that driver data is filled properly */
	if (drv->dev_probe == NULL || drv->dev_shutdown == NULL) {
		DPAA2_ERR(FW, "Driver Probe or Shutdown function not exist\n");
		return;
	}

	/*  check for name as well. this shall be used
	    to match against the vfio device name. */
	if (drv->name == NULL) {
		DPAA2_ERR(FW, "Driver Name is missing\n");
		return;
	}
	/* Store the driver pointer */
	if (drv->dev_type >= DPAA2_MAX_DEV) {
		DPAA2_ERR(FW, "Device not supported.\n");
		return;
	}

	if (dpaa2_driver_list[drv->dev_type]) {
		DPAA2_ERR(FW, "Driver already registered.\n");
		return;
	} else
		dpaa2_driver_list[drv->dev_type] = drv;

	DPAA2_INFO(FW, "Driver [%p] registed for DEV %d.\n",
					drv, drv->dev_type);
}

void dpaa2_unregister_driver(struct dpaa2_driver *drv)
{
	if (drv->dev_type >= DPAA2_MAX_DEV) {
		DPAA2_ERR(FW, "Device not supported.\n");
		return;
	}

	if (dpaa2_driver_list[drv->dev_type])
		dpaa2_driver_list[drv->dev_type] = NULL;
}


int32_t dpaa2_dev_init(struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;

	return dev_priv->fn_dev_cfg(dev);
}

int32_t dpaa2_dev_get_max_rx_vq(struct dpaa2_dev *dev)
{
	return dev->num_rx_vqueues;
}

int32_t dpaa2_dev_get_max_tx_vq(struct dpaa2_dev *dev)
{
	return dev->num_tx_vqueues;
}

int32_t dpaa2_dev_hwid(struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	return dev_priv->hw_id;
}

/* dump device */
static void
dpaa2_dump_one_device(void *stream, struct dpaa2_dev *dev)
{
	fprintf(stream, " - device:%s. type =%d\n",
		dev->dev_string, dev->dev_type);

	dpaa2_dump_platform_device(dev);
}

/* dump all the devices on the bus */
void
dpaa2_device_dump(void *stream)
{
	struct dpaa2_dev *dev = NULL;

	TAILQ_FOREACH(dev, &device_list, next) {
		dpaa2_dump_one_device(stream, dev);
	}
}

struct dpaa2_dev *dpaa2_dev_from_vq(void *vq)
{
	return (vq ? ((struct dpaa2_vq *)vq)->dev : NULL);
}

/*!
 * @details     Set given user context handle to VQ.
 *
 * @param[in]   vq - Pointer to VQ
 *
 * @param[in]   uhandle - user context value which needs to be set.
 *
 *
 * @returns     DPAA2_SUCCESS on success, DPAA2_FAILURE otherwise.
 *
 */
int dpaa2_dev_set_vq_handle(void *vq, uint64_t uhandle)
{
	struct dpaa2_vq *mvq = (struct dpaa2_vq *)vq;
	if (mvq) {
		mvq->usr_ctxt = uhandle;
		return DPAA2_SUCCESS;
	}
	return DPAA2_FAILURE;
}

/*!
 * @details     Return user context handle associated to given VQ.
 *
 * @param[in]   vq - Pointer to VQ
 *
 * @returns     Handle of specified VQ on success, 0 otherwise.
 *
 */
uint64_t dpaa2_dev_get_vq_handle(void *vq)
{
	return (vq ? ((struct dpaa2_vq *)vq)->usr_ctxt : 0);
}
