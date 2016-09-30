/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <dpaa2_dev.h>
#include <odp/api/plat/sdk/aiop/dpaa2_aiop.h>
#include <odp_debug_internal.h>
#include <odp/api/plat/cmdif/odpfsl_cidev.h>
#include <odp_internal.h>
#include <dpaa2_aiop_priv.h>

int odpfsl_ci_init_global(void)
{
	/*Scan the device list for CI devices*/
	odp_dpaa2_scan_device_list(DPAA2_AIOP_CI);

	return 0;
}

int odpfsl_ci_term_global(void)
{
	uint32_t i;

	/*Graceful shutdown to all the CI devices*/
	for (i = 0; i < dpaa2_res.res_cnt.ci_dev_cnt; i++)
		dpaa2_aiop_stop(dpaa2_res.ci_dev[i]);

	return 0;
}

void *odpfsl_cidev_open(void)
{
	struct dpaa2_dev *dev = NULL;
	uint32_t i;
	int ret;

	for (i = 0; i < dpaa2_res.res_cnt.ci_dev_cnt; i++) {
		dev = dpaa2_res.ci_dev[i];
		if (dev->state == DEV_INACTIVE)
			break;
	}

	/* No device return NULL */
	if (!dev || dev->state != DEV_INACTIVE) {
		ODP_ERR("No more CIDEV available\n");
		return NULL;
	}

	if (dev->num_rx_vqueues != 2) {
		ODP_ERR("Number of queues is not 2\n");
		return NULL;
	}

	/* Setup the Rx VQ's */
	for (i = 0; i < dev->num_rx_vqueues; i++) {
		ret = dpaa2_aiop_setup_rx_vq(dev, i, NULL);
		if (ret != DPAA2_SUCCESS) {
			ODP_ERR("Unable to setup the RX queue\n");
			return NULL;
		}
	}

	/* Enable the device */
	ret = dpaa2_aiop_start(dev);
	if (ret != DPAA2_SUCCESS) {
		ODP_ERR("CI device start failure\n");
		return NULL;
	}

	return (void *)dev;
}

int odpfsl_cidev_internal_id(void *cidev)
{
	return get_aiop_dev_id(cidev);
}

void odpfsl_cmdif_sync_timeout_params(uint64_t wait_interval_us,
		uint64_t num_tries)
{
	cmdif_client_sync_wait_interval = wait_interval_us;
	cmdif_client_sync_num_tries = num_tries;
}
