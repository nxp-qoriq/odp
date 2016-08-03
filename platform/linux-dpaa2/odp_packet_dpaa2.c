/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <odp/api/hints.h>
#include <odp/api/thread.h>
#include <odp_debug_internal.h>
#include <odp_packet_dpaa2.h>
#include <dpaa2.h>
#include <dpaa2_dev.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_ethdev.h>
#include <dpaa2_eth_priv.h>
#include <dpaa2_sec_priv.h>

int setup_pkt_dpaa2(pkt_dpaa2_t * const pkt_dpaa2 ODP_UNUSED, void *dev,
							odp_pool_t pool)
{
	uint32_t max_rx_vq;
	int i, ret;
	struct dpaa2_dev *netdev = (struct dpaa2_dev *)dev;
	pool_entry_t *phandle = (pool_entry_t *)pool;
	struct dpaa2_dev_priv *dev_priv = netdev->priv;

	ODP_DBG("setup_pkt_dpaa2\n");

	if (dev_priv->bp_list) {
		ODP_ERR("Already setuped\n");
		return -1;
	}

	/* Get Max available RX & TX VQs for this device */
	DPAA2_NOTE(APP1, "port =>  %s being created",
		netdev->dev_string);

	/* Get Max available RX & TX VQs for this device */
	max_rx_vq = dpaa2_dev_get_max_rx_vq(netdev);
	if (max_rx_vq < 1) {
		ODP_ERR("Not enough Resource to run\n");
		goto fail_dpaa2start;
	}
	/* Add RX Virtual queues to this device */
	i = 0;
	{
		DPAA2_NOTE(APP1, "setup FQ %d", i);
		ret = dpaa2_eth_setup_rx_vq(netdev, i, NULL);
		if (DPAA2_FAILURE == ret) {
			DPAA2_ERR(APP1,
				"Fail to configure RX VQs\n");
			goto fail_dpaa2start;
		}
	}

	ret = dpaa2_eth_attach_bp_list(netdev, (void *)(phandle->s.int_hdl));
	if (DPAA2_FAILURE == ret) {
		ODP_ERR("Failure to attach buffers to the"
						"Ethernet device\n");
		goto fail_dpaa2start;
	}

	return 0;

fail_dpaa2start:
	return -1;
}

int32_t cleanup_pkt_dpaa2(pkt_dpaa2_t *const pkt_dpaa2)
{
	struct dpaa2_dev *net_dev;
	struct dpaa2_dev_priv *dev_priv;
	int ret;

	net_dev = pkt_dpaa2->dev;
	dev_priv = (struct dpaa2_dev_priv *)net_dev->priv;
	dev_priv->bp_list = NULL;
	ret = dpaa2_eth_reset(net_dev);
	if (ret)
		ODP_ERR("Failure to reset the device\n");

	return ret;
}

int start_pkt_dpaa2(pkt_dpaa2_t *const pkt_dpaa2)
{
	uint32_t max_tx_vq;
	int ret;
	struct dpaa2_dev *netdev = pkt_dpaa2->dev;
	max_tx_vq = dpaa2_dev_get_max_tx_vq(netdev);
	if (max_tx_vq < 1) {
		ODP_ERR("Not enough Resource to run\n");
		return -1;
	}
	ret = dpaa2_eth_start(netdev);
	if (DPAA2_FAILURE == ret) {
		ODP_ERR("Not enough Resource to run\n");
		return -1;
	}
	/*Error handling is not done as a workaround of failure of
	  below API after CTRL+C*/
	dpaa2_eth_setup_tx_vq(netdev, max_tx_vq, DPAA2BUF_TX_NO_ACTION);
	return 0;
}

int close_pkt_dpaa2(pkt_dpaa2_t *const pkt_dpaa2)
{
	struct dpaa2_dev *net_dev;
	int ret;

	net_dev = pkt_dpaa2->dev;
	ret = dpaa2_eth_stop(net_dev);
	if (DPAA2_FAILURE == ret) {
		ODP_ERR("Unable to stop device\n");
		return -1;
	}

	ODP_DBG("close pkt_dpaa2, %u\n", pkt_dpaa2->portid);

	return 0;
}
