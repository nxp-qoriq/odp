/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 *
 */

/*!
 * @file	dpaa2_ethdev.c
 *
 * @brief	Ethernet Configuration APIs implementation. It contains API for
 *		runtime configuration for DPAA2 Ethernet devices.
 *
 * @addtogroup	DPAA2_ETH
 * @ingroup	DPAA2_DEV
 * @{
 */

#include <dpaa2_dev.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_ethdev.h>
#include <dpaa2_eth_priv.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_ether.h>
#include <dpaa2_ethdev_priv_ldpaa.h>
#include <dpaa2_common.h>
#include <dpaa2_mpool.h>
#include <dpaa2_memzone.h>
#include <dpaa2_memconfig.h>
#include <odp/api/hints.h>

/*MC header files*/
#include <fsl_dpni.h>
#include <fsl_dpkg.h>

#define ENABLE 1
#define DISABLE 0


/* Size of the input SMMU mapped memory required by MC */
#define DIST_PARAM_IOVA_SIZE 256

struct queues_config *dpaa2_eth_get_queues_config(struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_eth_priv *eth_priv = dev_priv->drv_priv;

	return &(eth_priv->q_config);
}

int dpaa2_eth_mtu_set(struct dpaa2_dev *dev,
			uint16_t mtu)
{
	int ret;
	struct dpni_attr attr;
	struct dpaa2_dev_priv *dev_priv;
	struct dpaa2_eth_priv *eth_priv;
	struct fsl_mc_io *dpni;

	if (dev == NULL)
		return DPAA2_FAILURE;
	dev_priv = dev->priv;
	if (dev_priv == NULL)
		return DPAA2_FAILURE;
	eth_priv = (struct dpaa2_eth_priv *)(dev_priv->drv_priv);
	if (eth_priv == NULL)
		return DPAA2_FAILURE;
	dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL)
		return DPAA2_FAILURE;

	ret = dpni_get_attributes(dpni, CMD_PRI_LOW, dev_priv->token, &attr);
	if (ret) {
		DPAA2_ERR(ETH, "DPNI get attribute failed: Error Code = %0x\n",
								ret);
		return DPAA2_FAILURE;
	}
	/* Set the Max Rx frame length as 'mtu' +
	 * Maximum Ethernet header length */
	ret = dpni_set_max_frame_length(dpni, CMD_PRI_LOW, dev_priv->token,
			mtu + ETH_VLAN_HLEN);
	if (ret) {
		DPAA2_ERR(ETH, "setting the max frame length failed");
		return DPAA2_FAILURE;
	}
#ifdef ENABLE_SNIC_SUPPORT
	if (attr.options & DPNI_OPT_IPF) {
		ret = dpni_set_mtu(dpni, CMD_PRI_LOW, dev_priv->token, mtu);
		if (ret) {
			DPAA2_ERR(ETH, "Setting the MTU failed");
			return DPAA2_FAILURE;
		}
	}
#endif
	eth_priv->cfg.mtu = mtu;
	DPAA2_NOTE(ETH, "MTU set as %d for the %s", mtu, dev->dev_string);
	return DPAA2_SUCCESS;
}

uint16_t dpaa2_eth_mtu_get(struct dpaa2_dev *dev)
{
	uint16_t mtu = 0;
	struct dpaa2_dev_priv *dev_priv;
	struct dpaa2_eth_priv *eth_priv;

	if (dev == NULL)
		return mtu;

	dev_priv = dev->priv;
	if (dev_priv == NULL)
		return mtu;
	eth_priv = (struct dpaa2_eth_priv *)(dev_priv->drv_priv);
	if (eth_priv == NULL)
		return mtu;

	return eth_priv->cfg.mtu;
}

void dpaa2_eth_set_buf_headroom(ODP_UNUSED struct dpaa2_dev *dev,
			       ODP_UNUSED uint32_t headroom)
{
	DPAA2_NOTE(ETH, "Headroom is configured %d for the device", headroom);
	DPAA2_NOTE(ETH, "Not Implemented");
	return;
}

void dpaa2_eth_promiscuous_enable(ODP_UNUSED struct dpaa2_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_eth_priv *epriv = (struct dpaa2_eth_priv *)(dev_priv->drv_priv);
	if (dev_priv == NULL) {
		DPAA2_ERR(ETH, "dev_priv is NULL");
		return;
	}

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL) {
		DPAA2_ERR(ETH, "dpni is NULL");
		return;
	}

	ret = dpni_set_unicast_promisc(dpni, CMD_PRI_LOW, dev_priv->token, ENABLE);
	if (ret < 0)
		DPAA2_ERR(ETH, "Unable to enable promiscuous mode");
	epriv->cfg.hw_features |= DPAA2_PROMISCUOUS_ENABLE;
	return;
}

void dpaa2_eth_promiscuous_disable(struct dpaa2_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_eth_priv *epriv = (struct dpaa2_eth_priv *)(dev_priv->drv_priv);
	if (dev_priv == NULL) {
		DPAA2_ERR(ETH, "dev_priv is NULL");
		return;
	}

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL) {
		DPAA2_ERR(ETH, "dpni is NULL");
		return;
	}

	ret = dpni_set_unicast_promisc(dpni, CMD_PRI_LOW, dev_priv->token, DISABLE);
	if (ret < 0)
		DPAA2_ERR(ETH, "Unable to disable promiscuous mode");

	epriv->cfg.hw_features &= ~DPAA2_PROMISCUOUS_ENABLE;
	return;
}

int dpaa2_eth_promiscuous_get(struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *priv;
	struct dpaa2_eth_priv *epriv;
	priv = (struct dpaa2_dev_priv *)(dev->priv);
	epriv = (struct dpaa2_eth_priv *)(priv->drv_priv);

	return BIT_ISSET_AT_POS(epriv->cfg.hw_features, DPAA2_PROMISCUOUS_ENABLE);
}

void dpaa2_eth_multicast_enable(struct dpaa2_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_eth_priv *epriv = (struct dpaa2_eth_priv *)(dev_priv->drv_priv);
	if (dev_priv == NULL) {
		DPAA2_ERR(ETH, "dev_priv is NULL");
		return;
	}

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL) {
		DPAA2_ERR(ETH, "dpni is NULL");
		return;
	}

	ret = dpni_set_multicast_promisc(dpni, CMD_PRI_LOW, dev_priv->token, ENABLE);
	if (ret < 0)
		DPAA2_ERR(ETH, "Unable to enable multicast mode");
	epriv->cfg.hw_features |= DPAA2_MULTICAST_ENABLE;
	return;
}


void dpaa2_eth_multicast_disable(struct dpaa2_dev *dev)
{
	int ret;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_eth_priv *epriv = (struct dpaa2_eth_priv *)(dev_priv->drv_priv);
	if (dev_priv == NULL) {
		DPAA2_ERR(ETH, "dev_priv is NULL");
		return;
	}

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL) {
		DPAA2_ERR(ETH, "dpni is NULL");
		return;
	}

	ret = dpni_set_multicast_promisc(dpni, CMD_PRI_LOW, dev_priv->token, DISABLE);
	if (ret < 0)
		DPAA2_ERR(ETH, "Unable to disable multicast mode");
	epriv->cfg.hw_features &= ~DPAA2_MULTICAST_ENABLE;
	return;
}



void dpaa2_eth_offload_cheksum(ODP_UNUSED struct dpaa2_dev *dev,
			      ODP_UNUSED uint8_t en_rx_checksum,
				ODP_UNUSED uint8_t en_tx_checksum)
{
	DPAA2_NOTE(ETH, "Not Implemented");
	return;
}

int32_t dpaa2_eth_set_mac_addr(struct dpaa2_dev *dev,
			uint8_t *addr)
{
	int ret;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	if (dev_priv == NULL)
		return DPAA2_FAILURE;

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL)
		return DPAA2_FAILURE;

	ret = dpni_set_primary_mac_addr(dpni, CMD_PRI_LOW, dev_priv->token, addr);

	if (ret == 0)
		return DPAA2_SUCCESS;
	else
		return DPAA2_FAILURE;
}

int32_t dpaa2_eth_get_mac_addr(struct dpaa2_dev *dev,
			uint8_t *addr)
{
	int ret;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	if (dev_priv == NULL)
		return DPAA2_FAILURE;

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL)
		return DPAA2_FAILURE;

	ret = dpni_get_primary_mac_addr(dpni, CMD_PRI_LOW, dev_priv->token, addr);

	if (ret == 0)
		return DPAA2_SUCCESS;
	else
		return DPAA2_FAILURE;
}

int32_t dpaa2_eth_get_link_info(struct dpaa2_dev *dev,
				struct dpni_link_state *state)
{
	int ret;
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	if (dev_priv == NULL)
		return DPAA2_FAILURE;

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL)
		return DPAA2_FAILURE;

	ret = dpni_get_link_state(dpni, CMD_PRI_LOW, dev_priv->token,
							state);
	if (ret == 0) {
		return DPAA2_SUCCESS;
	} else {
		DPAA2_ERR(ETH,"Error while getting link state %d\n", ret);
		return DPAA2_FAILURE;
	}
}

int32_t dpaa2_eth_setup_flow_distribution(struct dpaa2_dev *dev,
		uint32_t req_dist_set,
		uint8_t tc_index,
		uint16_t dist_size)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = dev_priv->hw;
	struct dpaa2_eth_priv *eth_priv = dev_priv->drv_priv;
	struct dpni_rx_tc_dist_cfg tc_cfg;
	struct dpkg_profile_cfg kg_cfg;
	struct queues_config *q_config = &(eth_priv->q_config);
	void_t *p_params;
	int ret;

	if (dist_size > q_config->tc_config[tc_index].num_dist) {
		DPAA2_ERR(BUF, "Dist size greater than num_dist %d > %d",
			dist_size, q_config->tc_config[tc_index].num_dist);
		return -EINVAL;
	}
	p_params = dpaa2_data_malloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
	if (!p_params) {
		DPAA2_ERR(BUF, "Memory unavaialble");
		return -ENOMEM;
	}
	memset(p_params, 0, DIST_PARAM_IOVA_SIZE);
	memset(&tc_cfg, 0, sizeof(struct dpni_rx_tc_dist_cfg));

	dpaa2_distset_to_dpkg_profile_cfg(req_dist_set, &kg_cfg);
	tc_cfg.key_cfg_iova = (uint64_t)(DPAA2_VADDR_TO_IOVA(p_params));
	tc_cfg.dist_size = dist_size;
	tc_cfg.dist_mode = DPNI_DIST_MODE_HASH;
	q_config->tc_config[tc_index].num_dist_used = dist_size;

	if (dpkg_prepare_key_cfg(&kg_cfg, (uint8_t *)p_params))
		DPAA2_WARN(BUF, "Unable to prepare extract parameters");

	ret = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token, tc_index,
		&tc_cfg);
	dpaa2_data_free(p_params);
	if (ret) {
		DPAA2_ERR(ETH, "Setting distribution for Rx failed with"
			"err code: %d", ret);
		return ret;
	}

	q_config->tc_config[tc_index].dist_type = DPAA2_ETH_FLOW_DIST;

	return DPAA2_SUCCESS;
}

void dpaa2_eth_remove_flow_distribution(struct dpaa2_dev *dev,
		uint8_t tc_index)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	struct dpaa2_eth_priv *eth_priv = dev_priv->drv_priv;
	struct dpni_rx_tc_dist_cfg tc_cfg;
	struct dpkg_profile_cfg kg_cfg;
	struct queues_config *q_config;
	void_t *p_params;
	int ret;

	p_params = dpaa2_data_malloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
	if (!p_params) {
		DPAA2_ERR(BUF, "Memory unavaialble");
		return;
	}
	memset(&kg_cfg, 0, sizeof(struct dpkg_profile_cfg));
	memset(&tc_cfg, 0, sizeof(struct dpni_rx_tc_dist_cfg));
	memset(p_params, 0, DIST_PARAM_IOVA_SIZE);

	q_config = &(eth_priv->q_config);
	tc_cfg.key_cfg_iova = (uint64_t)(DPAA2_VADDR_TO_IOVA(p_params));
	tc_cfg.dist_size = 0;
	tc_cfg.dist_mode = DPNI_DIST_MODE_NONE;

	if (dpkg_prepare_key_cfg(&kg_cfg, (uint8_t *)p_params))
		DPAA2_WARN(BUF, "Unable to prepare extract parameters");

	ret = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token, tc_index,
		&tc_cfg);
	dpaa2_data_free(p_params);
	if (ret)
		DPAA2_ERR(ETH, "Unsetting distribution for Rx failed with"
			"err code: %d", ret);
	else
		q_config->tc_config[tc_index].dist_type = DPAA2_ETH_NO_DIST;

}

int dpaa2_eth_timestamp_enable(struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	struct dpni_buffer_layout layout = {0};
	int ret;

	layout.options = DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
	layout.pass_timestamp = TRUE;

	ret = dpni_set_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token,
				     DPNI_QUEUE_RX, &layout);
	if (ret) {
		DPAA2_ERR(ETH, "Enabling timestamp for Rx failed with"
			"err code: %d", ret);
		return ret;
	}
	ret = dpni_set_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token,
				     DPNI_QUEUE_TX, &layout);
	if (ret) {
		DPAA2_ERR(ETH, "Enabling timestamp failed for Tx with"
			"err code: %d", ret);
		return ret;
	}
	ret = dpni_set_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token,
				     DPNI_QUEUE_TX_CONFIRM, &layout);
	if (ret) {
		DPAA2_ERR(ETH, "Enabling timestamp failed for Tx-conf with"
			"err code: %d", ret);
		return ret;
	}

	return DPAA2_SUCCESS;
}

int dpaa2_eth_timestamp_disable(struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	struct dpni_buffer_layout layout = {0};
	int ret;

	layout.options = DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
	layout.pass_timestamp = FALSE;

	ret = dpni_set_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token,
				     DPNI_QUEUE_RX, &layout);
	if (ret) {
		DPAA2_ERR(ETH, "Disabling timestamp failed for Rx with"
			"err code: %d", ret);
		return ret;
	}
	ret = dpni_set_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token,
				     DPNI_QUEUE_TX, &layout);
	if (ret) {
		DPAA2_ERR(ETH, "Disabling timestamp failed for Tx with"
			"err code: %d", ret);
		return ret;
	}
	ret = dpni_set_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token,
				     DPNI_QUEUE_TX_CONFIRM, &layout);
	if (ret) {
		DPAA2_ERR(ETH, "Disabling timestamp failed for Tx-conf with"
			"err code: %d", ret);
		return ret;
	}

	return DPAA2_SUCCESS;
}

int dpaa2_eth_frag_enable(struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_eth_priv *epriv = (struct dpaa2_eth_priv *)(dev_priv->drv_priv);

#ifdef ENABLE_SNIC_SUPPORT
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	int ret;

	ret = dpni_set_ipf(dpni, CMD_PRI_LOW, dev_priv->token, 1);
	if (ret != 0) {
		DPAA2_ERR(ETH, "Enabling Ethernet device fragmentation "
			"feature failed with retcode: %d", ret);
		return ret;
	}
#endif
	epriv->cfg.hw_features |= DPAA2_FRAG_ENABLE;

	return DPAA2_SUCCESS;
}

int dpaa2_eth_frag_disable(struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_eth_priv *epriv = (struct dpaa2_eth_priv *)(dev_priv->drv_priv);

#ifdef ENABLE_SNIC_SUPPORT
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	int ret;

	ret = dpni_set_ipf(dpni, CMD_PRI_LOW, dev_priv->token, 0);
	if (ret != 0) {
		DPAA2_ERR(ETH, "Disabling Ethernet device fragmentation "
			"feature failed with retcode: %d", ret);
		return ret;
	}
#endif
	epriv->cfg.hw_features &= ~DPAA2_FRAG_ENABLE;

	return DPAA2_SUCCESS;
}

int dpaa2_eth_reassembly_enable(struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_eth_priv *epriv = (struct dpaa2_eth_priv *)(dev_priv->drv_priv);

#ifdef ENABLE_SNIC_SUPPORT
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	int ret;

	ret = dpni_set_ipr(dpni, CMD_PRI_LOW, dev_priv->token, 1);
	if (ret != 0) {
		DPAA2_ERR(ETH, "Enabling Ethernet device reassembly "
			"feature failed with retcode: %d", ret);
		return ret;
	}
#endif
	epriv->cfg.hw_features |= DPAA2_REASSEMBLY_ENABLE;

	return DPAA2_SUCCESS;
}

int dpaa2_eth_reassembly_disable(struct dpaa2_dev *dev)
{
	struct dpaa2_dev_priv *dev_priv = dev->priv;
	struct dpaa2_eth_priv *epriv = (struct dpaa2_eth_priv *)(dev_priv->drv_priv);

#ifdef ENABLE_SNIC_SUPPORT
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	int ret;

	ret = dpni_set_ipr(dpni, CMD_PRI_LOW, dev_priv->token, 0);
	if (ret != 0) {
		DPAA2_ERR(ETH, "Disabling Ethernet device reassembly "
			"feature failed with retcode: %d", ret);
		return ret;
	}
#endif
	epriv->cfg.hw_features &= ~DPAA2_REASSEMBLY_ENABLE;

	return DPAA2_SUCCESS;
}

/*! @} */
