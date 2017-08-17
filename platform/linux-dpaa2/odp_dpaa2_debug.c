/* Copyright (c) 2016, Freescale Semiconductor Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*
 * DEBUG FRAMEWORK
 */

#include <fsl_qbman_debug.h>

#include <odp/api/init.h>
#include <odp_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp/helper/linux.h>

/* Linux libc standard headers */
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include <dpaa2_dev.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_eth_priv.h>
#include <dpaa2_vq.h>
#include <dpaa2_conc_priv.h>
#include <fsl_dpseci.h>

#include <fsl_qbman_portal.h>
#define BUFLEN 64
#define DEFAULT_PLAT_DEBUG_PORT 10000
#define MAXLENGTH 10000
#define FAILURE (uint32_t)(-1)
char pr_buf[MAXLENGTH];

static inline  struct dpaa2_dev *get_dpaa2_dev(char *dev_name)
{
	struct dpaa2_dev *dev = NULL;

	TAILQ_FOREACH(dev, &device_list, next) {
		if (!(strcmp(dev->dev_string, dev_name)))
			return dev;
	}
	return NULL;
}

static inline struct dpaa2_dev_priv *get_dev_priv(char *dev_name)
{
	struct dpaa2_dev *dev;

	dev = get_dpaa2_dev(dev_name);

	if (!dev) {
		ODP_ERR("Error: DPAA2 DEV %s NOT FOUND!\n", dev_name);
		return NULL;
	}

	return dev->priv;
}

static inline uint32_t get_bpool_id(char *dev_name)
{
	pool_entry_t *pool_t;
	odp_pool_t pool;

	pool = odp_debug_pool_lookup(dev_name);

	if (pool == ODP_POOL_INVALID) {
		ODP_ERR("Error: ODP POOL INVALID!\n");
		return FAILURE;
	}

	pool_t = odp_pool_to_entry(pool);

	if (!pool_t) {
		ODP_ERR("Error: ODP POOL ENTRY NOT FOUND!\n");
		return FAILURE;
	}

	return pool_t->s.bpid;
}

static void get_dpni_stats(char *dev_name)
{
	struct dpaa2_dev_priv *dev_priv;
	struct fsl_mc_io *dpni;
	int32_t  retcode = -1;
	int nbytes;
	union dpni_statistics value;
	char *str = pr_buf;
	uint8_t page0 = 0, page1 = 1, page2 = 2;
	uint8_t param = 0;

	memset(&value, 0, sizeof(union dpni_statistics));

	dev_priv = get_dev_priv(dev_name);

	if (!dev_priv) {
		ODP_ERR("Error: DPAA2 DEV PRIV NOT FOUND!\n");
		return;
	}

	dpni = (struct fsl_mc_io *)dev_priv->hw;

	if (!dpni) {
		ODP_ERR("Error: FSL MC IO HANDLE NOT FOUND!\n");
		return;
	}

	/*Get Counters from page_0*/
	retcode = dpni_get_statistics(dpni, CMD_PRI_LOW, dev_priv->token,
				      page0, param, &value);
	if (retcode)
		goto error;

	/*total pkt/frames received */
	nbytes = sprintf(str, "\nDpni Stats\n%s:"
		"\t\t\tTotal Ingress Frames\t\t\t\t\t: %lu\n",
		dev_name, value.page_0.ingress_all_frames);
	str = str + nbytes;

	/* get ingress bytes */
	nbytes = sprintf(str, "\t\t\tTotal Ingress Bytes\t\t\t\t\t: %lu\n",
			 value.page_0.ingress_all_bytes);
	str = str + nbytes;

	/*Ingress Multicast Frames */
	nbytes = sprintf(str, "\t\t\tTotal Ingress Multicast Frames\t\t\t\t: %lu\n",
			 value.page_0.ingress_multicast_frames);
	str = str + nbytes;

	/* Ingress Broadcase frames*/
	nbytes = sprintf(str, "\t\t\tTotal Ingress Broadcast Frames\t\t\t\t: %lu\n",
			 value.page_0.ingress_multicast_frames);
	str = str + nbytes;

	/*Get Counters from page_1*/
	retcode =  dpni_get_statistics(dpni, CMD_PRI_LOW, dev_priv->token,
				       page1, param, &value);
	if (retcode)
		goto error;

	/* Egress frames */
	nbytes = sprintf(str, "\t\t\tTotal Egress Frames\t\t\t\t\t: %lu\n",
			 value.page_1.egress_all_frames);
	str = str + nbytes;

	/* Total Egress Bytes */
	nbytes = sprintf(str, "\t\t\tTotal Egress Bytes\t\t\t\t\t: %lu\n",
			 value.page_1.egress_all_bytes);
	str = str + nbytes;

	/*Get Counters from page_2*/
	retcode =  dpni_get_statistics(dpni, CMD_PRI_LOW, dev_priv->token,
				       page2, param, &value);
	if (retcode)
		goto error;

	/* Ingress frames dropped due to explicit 'drop' setting*/
	nbytes = sprintf(str, "\t\t\tTotal Ingress Frames dropped explicitly\t\t\t: %lu\n",
			 value.page_2.ingress_filtered_frames);
	str = str + nbytes;

	/* Ingress frames discarded due to errors */
	nbytes = sprintf(str, "\t\t\tTotal Ingress Errored Frames discarded\t\t\t: %lu\n",
			 value.page_2.ingress_discarded_frames);
	str = str + nbytes;

	/* Ingress frames discarded due to errors */
	nbytes = sprintf(str, "\t\t\tTotal Ingress No Buffer discarded\t\t\t: %lu\n",
			 value.page_2.ingress_nobuffer_discards);
	str = str + nbytes;
	/* Total Egress frames discarded due to errors */
	nbytes = sprintf(str, "\t\t\tTotal Egress Errored Frames discarded\t\t\t: %lu\n",
			 value.page_2.egress_discarded_frames);
	return;
error:
	ODP_ERR("DPNI STATS: Error Code = %d\n", retcode);
	return;
}

static void reset_dpni_stats(char *dev_name)
{
	struct dpaa2_dev_priv *dev_priv;
	struct fsl_mc_io *dpni;
	int32_t  retcode = -1;

	dev_priv = get_dev_priv(dev_name);

	if (!dev_priv) {
		ODP_ERR("Error: DPAA2 DEV PRIV NOT FOUND!\n");
		return;
	}

	dpni = (struct fsl_mc_io *)dev_priv->hw;

	if (!dpni) {
		ODP_ERR("Error: FSL MC IO HANDLE NOT FOUND!\n");
		return;
	}

	/* Reset ingress packets */
	retcode =  dpni_reset_statistics(dpni, CMD_PRI_LOW, dev_priv->token);
	if (retcode)
		goto error;

	return;
error:
	ODP_ERR("RESET PKTIO STATS: Error Code = %d\n", retcode);
	return;
}

static void event_handler(void *msg)
{
	ipc_msg_t *event_msg = (ipc_msg_t *)msg;
	char name[BUFLEN];
	char *str = pr_buf;

	memset(pr_buf, 0, sizeof(pr_buf));
	memset(name, 0, sizeof(name));
	memcpy(name, event_msg->buffer, event_msg->buffer_len);

	switch (event_msg->obj_id) {
	case DPAA2_DEBUG_DPNI_STATS:
		{
			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				get_dpni_stats(name);
			} else if ((event_msg->cmd) == DPAA2_DEBUG_CMD_RESET) {
				reset_dpni_stats(name);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_DPNI_ATTRIBUTES:
		{
			struct dpaa2_dev_priv *dev_priv;
			struct dpni_attr dpni_attr;
			struct dpni_attr *attr = &dpni_attr;
			struct fsl_mc_io *dpni_dev;
			uint16_t major, minor;

			dev_priv = get_dev_priv(name);

			if (!dev_priv) {
				ODP_ERR("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				ODP_ERR("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}
			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_api_version(dpni_dev, CMD_PRI_LOW,
						     &major, &minor);
				dpni_get_attributes(dpni_dev, CMD_PRI_LOW, dev_priv->token, &dpni_attr);
				sprintf(str, "Dpni_Attributes\n"
						"%s:"
						"\t\t\tDPNI major version \t\t\t\t\t: %hu\n"
						"\t\t\tDPNI minor version \t\t\t\t\t: %hu\n"
						"\t\t\tMaximum number of Rx Queues per TC\t\t\t: %u\n"
						"\t\t\tMaximum number of Tx Queues \t\t\t: %u\n"
						"\t\t\tMaximum number of RX traffic classes \t: %u\n"
						"\t\t\tMaximum number of TX traffic classes \t: %u\n"
						"\t\t\tMaximum number of MAC filters \t\t\t: %u\n"
						"\t\t\tMaximum number of VLAN filters	\t\t\t: %u\n"
						"\t\t\tMaximum entries in QoS table \t\t\t\t: %u\n"
						"\t\t\tMaximum key size for the QoS look-up \t\t\t: %u\n"
						"\t\t\tMaximum entries in FS table \t\t\t\t: %u\n"
						"\t\t\tMaximum key size for the distribution look-up \t\t: %u\n",
						name,
						major, minor, attr->num_queues,
						attr->num_queues, attr->num_rx_tcs,
						attr->num_tx_tcs,
						attr->mac_filter_entries,
						attr->vlan_filter_entries,
						attr->qos_entries,
						attr->qos_key_size,
						attr->fs_entries,
						attr->fs_key_size);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}

			break;
		}
	case DPAA2_DEBUG_DPNI_LINK_STATE:
		{
			struct dpaa2_dev_priv *dev_priv;
			struct dpni_link_state state;
			struct dpni_link_state *st = &state;
			struct fsl_mc_io *dpni_dev;

			dev_priv = get_dev_priv(name);

			if (!dev_priv) {
				ODP_ERR("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				ODP_ERR("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_link_state(dpni_dev, CMD_PRI_LOW, dev_priv->token, &state);
				sprintf(str, "Dpni Link State\n"
						"%s:"
						"\t\t\tlink rate \t\t\t\t\t\t: %u\n"
						"\t\t\tdpni link options\t\t\t\t\t: %lu\n"
						"\t\t\tlink up	\t\t\t\t\t\t: %d\n\n\n",
						name,
						st->rate, st->options, st->up);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}

			break;
		}
	case DPAA2_DEBUG_DPNI_MAX_FRAME_LENGTH:
		{
			struct dpaa2_dev_priv *dev_priv;
			uint16_t max_frame_length;
			struct fsl_mc_io *dpni_dev;

			dev_priv = get_dev_priv(name);

			if (!dev_priv) {
				ODP_ERR("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				ODP_ERR("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_max_frame_length(dpni_dev, CMD_PRI_LOW, dev_priv->token, &max_frame_length);
				sprintf(str, "%s:\t\t\tmax frame length\t\t\t\t\t"
					": %u\n\n\n",
					name, max_frame_length);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}

			break;
		}
	case DPAA2_DEBUG_DPNI_MTU:
		{
			struct dpaa2_dev_priv *dev_priv;
			uint16_t mtu = 1500;
			struct fsl_mc_io *dpni_dev;

			dev_priv = get_dev_priv(name);

			if (!dev_priv) {
				ODP_ERR("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				ODP_ERR("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}
#ifdef ENABLE_SNIC_SUPPORT
			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_mtu(dpni_dev, CMD_PRI_LOW, dev_priv->token, &mtu);
				sprintf(str, "%s:\t\t\tmtu\t\t\t\t\t\t\t: %u\n\n\n",
					name, mtu);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
#endif
			sprintf(str, "%s:\t\t\tmtu\t\t\t\t\t\t\t: %u\n\n\n",
				name, mtu);
			break;
		}
	case DPAA2_DEBUG_DPNI_L3_CHKSUM_VALIDATION:
		{
			struct dpaa2_dev_priv *dev_priv;
			uint32_t en;
			struct fsl_mc_io *dpni_dev;

			dev_priv = get_dev_priv(name);

			if (!dev_priv) {
				ODP_ERR("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				ODP_ERR("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_offload(dpni_dev, CMD_PRI_LOW,
						 dev_priv->token,
						 DPNI_OFF_RX_L3_CSUM, &en);
				sprintf(str, "L3 Checksum Hardware Offload Enable on %s"
						"\t\t\t\t\t: %d\n\n\n", name, en);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_DPNI_L4_CHKSUM_VALIDATION:
		{
			struct dpaa2_dev_priv *dev_priv;
			uint32_t en;
			struct fsl_mc_io *dpni_dev;

			dev_priv = get_dev_priv(name);

			if (!dev_priv) {
				ODP_ERR("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				ODP_ERR("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_offload(dpni_dev, CMD_PRI_LOW,
						 dev_priv->token,
						 DPNI_OFF_RX_L4_CSUM, &en);
				sprintf(str, "L4 Checksum Hardware Offload Enable on %s"
						"\t\t\t\t\t: %d\n\n\n", name, en);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_DPNI_PRIMARY_MAC_ADDR:
		{
			struct dpaa2_dev_priv *dev_priv;
			uint8_t mac_addr[6];
			struct fsl_mc_io *dpni_dev;

			dev_priv = get_dev_priv(name);

			if (!dev_priv) {
				ODP_ERR("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpni_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpni_dev) {
				ODP_ERR("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpni_get_primary_mac_addr(dpni_dev, CMD_PRI_LOW, dev_priv->token, mac_addr);
				sprintf(str, "%s:\t\t\tMac Address\t\t\t\t\t\t:"
						" %u.%u.%u.%u.%u.%u\n\n\n",
						name,
						mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
						mac_addr[4], mac_addr[5]);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_FQ_ATTR_CGRID:
		{
			struct dpaa2_dev *dev;
			int i = 0;
			int32_t num_tx_vqs, num_rx_vqs;
			int nbytes = sprintf(str, "%s:", name);

			dev = get_dpaa2_dev(name);

			if (!dev) {
				ODP_ERR("Error! DPAA2 DEV NOT FOUND!\n");
				return;
			}

			num_tx_vqs = dpaa2_dev_get_max_tx_vq(dev);
			num_rx_vqs = dpaa2_dev_get_max_rx_vq(dev);

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s = thread_io_info.dpio_dev->sw_portal;
				struct qbman_fq_query_rslt a;
				uint16_t cgrid;
				uint32_t fqid;
				struct dpaa2_vq *eth_vq;

				for (i = 0; i < num_rx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						cgrid = qbman_fq_attr_get_cgrid(&a);
						nbytes = sprintf(str, "\t\t\tCongestion group ID\t: %hu\t"
								"for RX FQID: %u\n", cgrid, fqid);
					}
				}

				for (i = 0; i < num_tx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						cgrid = qbman_fq_attr_get_cgrid(&a);
						nbytes = sprintf(str, "\t\t\tCongestion group ID\t: %hu\t"
								"for TX FQID: %u\n", cgrid, fqid);
					}
				}
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_FQ_ATTR_DESTWQ:
		{
			struct dpaa2_dev *dev;
			int i = 0;
			int32_t num_tx_vqs, num_rx_vqs;
			int nbytes = sprintf(str, "%s:", name);

			dev = get_dpaa2_dev(name);

			if (!dev) {
				ODP_ERR("Error! DPAA2 DEV NOT FOUND!\n");
				return;
			}

			num_tx_vqs = dpaa2_dev_get_max_tx_vq(dev);
			num_rx_vqs = dpaa2_dev_get_max_rx_vq(dev);

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s = thread_io_info.dpio_dev->sw_portal;
				struct qbman_fq_query_rslt a;
				uint16_t destwq;
				uint32_t fqid;
				struct dpaa2_vq *eth_vq;

				for (i = 0; i < num_rx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						destwq = qbman_fq_attr_get_destwq(&a);
						nbytes = sprintf(str, "\t\t\tScheduling Priority\t: %hu\t"
								"for RX FQID: %u\n", destwq, fqid);
					}
				}

				for (i = 0; i < num_tx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						destwq = qbman_fq_attr_get_destwq(&a);
						nbytes = sprintf(str, "\t\t\tScheduling Priority\t: %hu\t"
								"for TX FQID: %u\n", destwq, fqid);
					}
				}
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_FQ_ATTR_TDTHRESH:
		{
			struct dpaa2_dev *dev;
			int i = 0;
			int32_t num_tx_vqs, num_rx_vqs;
			int nbytes = 0;

			dev = get_dpaa2_dev(name);

			if (!dev) {
				ODP_ERR("Error! DPAA2 DEV NOT FOUND!\n");
				return;
			}

			num_tx_vqs = dpaa2_dev_get_max_tx_vq(dev);
			num_rx_vqs = dpaa2_dev_get_max_rx_vq(dev);
			nbytes = sprintf(str, "%s: Rx FQs= %d, Tx FQs= %d\n", name, num_rx_vqs, num_tx_vqs);

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s = thread_io_info.dpio_dev->sw_portal;
				struct qbman_fq_query_rslt a;
				uint16_t tdthresh;
				uint32_t fqid;
				struct dpaa2_vq *eth_vq;

				for (i = 0; i < num_rx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						tdthresh = qbman_fq_attr_get_tdthresh(&a);
						nbytes = sprintf(str, "\t\t\tTail drop threashold\t: %hu\t"
								"for RX FQID: %u\n", tdthresh, fqid);
					}
				}

				for (i = 0; i < num_tx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						tdthresh = qbman_fq_attr_get_tdthresh(&a);
						nbytes = sprintf(str, "\t\t\tTail drop threashold\t: %hu\t"
								"for TX FQID: %u\n", tdthresh, fqid);
					}
				}
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
#if 0
	case DPAA2_DEBUG_QBMAN_FQ_ATTR_CTX:
		{
			struct dpaa2_dev *dev;
			int i = 0;
			int32_t num_tx_vqs, num_rx_vqs;
			int nbytes = sprintf(str, "%s:", name);

			dev = get_dpaa2_dev(name);

			if (!dev) {
				ODP_ERR("Error! DPAA2 DEV NOT FOUND!\n");
				return;
			}

			num_tx_vqs = dpaa2_dev_get_max_tx_vq(dev);
			num_rx_vqs = dpaa2_dev_get_max_rx_vq(dev);

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s = thread_io_info.dpio_dev->sw_portal;
				struct qbman_attr a;
				uint32_t hi;
				uint32_t lo;
				uint64_t ctx;
				uint32_t fqid;
				struct dpaa2_vq *eth_vq;

				for (i = 0; i < num_rx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						qbman_fq_attr_get_ctx(&a, &hi, &lo);
						ctx = ((uint64_t)hi << 32) | lo;
						nbytes = sprintf(str, "\t\t\tFQ Context\t\t: %lu\t"
								"for RX FQID: %u\n", ctx, fqid);
					}
				}

				for (i = 0; i < num_tx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						str = str + nbytes;
						qbman_fq_query(s, fqid, &a);
						qbman_fq_attr_get_ctx(&a, &hi, &lo);
						ctx = ((uint64_t)hi << 32) | lo;
						nbytes = sprintf(str, "\t\t\tFQ Context\t\t: %lu\t"
								"for TX FQID: %u\n", ctx, fqid);
					}
				}
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
#endif
	case DPAA2_DEBUG_QBMAN_FQ_STATE_SCHEDSTATE:
		{
			struct dpaa2_dev *dev;
			int i = 0;
			int32_t num_tx_vqs, num_rx_vqs;
			int nbytes = sprintf(str, "%s:", name);

			dev = get_dpaa2_dev(name);

			if (!dev) {
				ODP_ERR("Error! DPAA2 DEV NOT FOUND!\n");
				return;
			}

			num_tx_vqs = dpaa2_dev_get_max_tx_vq(dev);
			num_rx_vqs = dpaa2_dev_get_max_rx_vq(dev);

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s = thread_io_info.dpio_dev->sw_portal;
				struct qbman_fq_query_np_rslt state;
				uint32_t fqid;
				uint32_t schd_st;
				struct dpaa2_vq *eth_vq;

				for (i = 0; i < num_rx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						if (0 == qbman_fq_query_state(s, fqid, &state)) {
							str = str + nbytes;
							schd_st = qbman_fq_state_schedstate(&state);
							nbytes = sprintf(str, "\t\t\tFQ State\t\t: %u\t"
								"for RX FQID: %u\n", schd_st, fqid);
						}
					}
				}

				for (i = 0; i < num_tx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						if (0 == qbman_fq_query_state(s, fqid, &state)) {
							str = str + nbytes;
							schd_st = qbman_fq_state_schedstate(&state);
							nbytes = sprintf(str, "\t\t\tFQ State\t\t: %u\t"
								"for TX FQID: %u\n", schd_st, fqid);
						}
					}
				}
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_FQ_STATE_FRAME_COUNT:
		{
			struct dpaa2_dev *dev;
			int i = 0;
			int32_t num_tx_vqs, num_rx_vqs;
			int nbytes;

			dev = get_dpaa2_dev(name);

			if (!dev) {
				ODP_ERR("Error! DPAA2 DEV NOT FOUND!\n");
				return;
			}

			num_tx_vqs = dpaa2_dev_get_max_tx_vq(dev);
			num_rx_vqs = dpaa2_dev_get_max_rx_vq(dev);
			nbytes = sprintf(str, "%s: Rx FQs= %d, Tx FQs= %d\n", name, num_rx_vqs, num_tx_vqs);
			str = str + nbytes;

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s = thread_io_info.dpio_dev->sw_portal;
				struct qbman_fq_query_np_rslt state;
				uint32_t fqid;
				uint32_t frame_cnt;
				struct dpaa2_vq *eth_vq;

				for (i = 0; i < num_rx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						if (0 == qbman_fq_query_state(s, fqid, &state)) {
							frame_cnt = qbman_fq_state_frame_count(&state);
							nbytes = sprintf(str, "\t\t\tNo. of frames\t\t: %u\t"
								"for RX FQID: %u\n", frame_cnt, fqid);
							str = str + nbytes;
						}
					}
				}

				for (i = 0; i < num_tx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						if (0 == qbman_fq_query_state(s, fqid, &state)) {
							frame_cnt = qbman_fq_state_frame_count(&state);
							nbytes = sprintf(str, "\t\t\tNo. of frames\t\t: %u\t"
								"for TX FQID: %u\n", frame_cnt, fqid);
							str = str + nbytes;
						}
					}
				}
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_FQ_STATE_BYTE_COUNT:
		{
			struct dpaa2_dev *dev;
			int i = 0;
			int32_t num_tx_vqs, num_rx_vqs;
			int nbytes;

			dev = get_dpaa2_dev(name);

			if (!dev) {
				ODP_ERR("Error! DPAA2 DEV NOT FOUND!\n");
				return;
			}

			num_tx_vqs = dpaa2_dev_get_max_tx_vq(dev);
			num_rx_vqs = dpaa2_dev_get_max_rx_vq(dev);
			nbytes = sprintf(str, "%s: Rx FQs= %d, Tx FQs= %d\n", name, num_rx_vqs, num_tx_vqs);
			str = str + nbytes;

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_swp *s = thread_io_info.dpio_dev->sw_portal;
				struct qbman_fq_query_np_rslt state;
				uint32_t fqid;
				uint32_t byte_cnt;
				struct dpaa2_vq *eth_vq;

				for (i = 0; i < num_rx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->rx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						if (0 == qbman_fq_query_state(s, fqid, &state)) {
							byte_cnt = qbman_fq_state_byte_count(&state);
							nbytes = sprintf(str, "\t\t\tNo. of bytes\t\t: %u\t"
								"for RX FQID: %u\n", byte_cnt, fqid);
							str = str + nbytes;
						}
					}
				}

				for (i = 0; i < num_tx_vqs; i++) {
					eth_vq = (struct dpaa2_vq *)(dev->tx_vq[i]);
					fqid = eth_vq->fqid;
					if (fqid > 0) {
						if (0 == qbman_fq_query_state(s, fqid, &state)) {
							byte_cnt = qbman_fq_state_byte_count(&state);
							nbytes = sprintf(str, "\t\t\tNo. of bytes\t\t: %u\t"
								"for TX FQID: %u\n", byte_cnt, fqid);
							str = str + nbytes;
						}
					}
				}
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_BP_INFO_HAS_FREE_BUFS:
		{
			uint32_t bpid = get_bpool_id(name);

			if (bpid == FAILURE) {
				ODP_ERR("BPID not found\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_bp_query_rslt a;
				struct qbman_swp *s = thread_io_info.dpio_dev->sw_portal;

				qbman_bp_query(s, bpid, &a);
				if (qbman_bp_has_free_bufs(&a))
					sprintf(str, "QBMAN buffers available for %s\t\t\t\t\t\t:"
							" YES\n\n\n", name);
				else
					sprintf(str, "QBMAN buffers available for %s\t\t\t\t\t\t:"
							" NO\n\n\n", name);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_BP_INFO_IS_DEPLETED:
		{
			uint32_t bpid = get_bpool_id(name);

			if (bpid == FAILURE) {
				ODP_ERR("BPID not found\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				struct qbman_bp_query_rslt a;
				struct qbman_swp *s = thread_io_info.dpio_dev->sw_portal;

				qbman_bp_query(s, bpid, &a);
				if (!qbman_bp_is_depleted(&a))
					sprintf(str, "QBMAN buffer pools depleted for %s\t\t\t\t\t\t:"
							" NO\n\n\n", name);
				else
					sprintf(str, "QBMAN buffer pools depleted for %s\t\t\t\t\t\t:"
							" YES\n\n\n", name);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_QBMAN_BP_INFO_NUM_FREE_BUFS:
		{
			uint32_t bpid = get_bpool_id(name);

			if (bpid == FAILURE) {
				ODP_ERR("BPID not found\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				uint32_t num_buf;
				struct qbman_bp_query_rslt a;
				struct qbman_swp *s = thread_io_info.dpio_dev->sw_portal;

				qbman_bp_query(s, bpid, &a);
				num_buf = qbman_bp_num_free_bufs(&a);
				sprintf(str, "Number of free QBMAN buffers for"
						" %s\t\t\t\t\t\t: %u\n\n\n", name, num_buf);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}
	case DPAA2_DEBUG_DPSECI_ATTRIBUTES:
		{
			struct dpaa2_dev_priv *dev_priv;
			struct dpseci_sec_attr sec_attr;
			struct fsl_mc_io *dpseci_dev;

			dev_priv = get_dev_priv(name);

			if (!dev_priv) {
				ODP_ERR("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpseci_dev = (struct fsl_mc_io *)dev_priv->hw;

			if (!dpseci_dev) {
				ODP_ERR("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				dpseci_get_sec_attr(dpseci_dev, CMD_PRI_LOW, dev_priv->token, &sec_attr);
				sprintf(str, "DPseci_Attributes\n"
						"%s:"
						"\t\tDPseci object id	\t\t\t\t: %u\n"
						"\t\t\tDPseci major version \t\t\t\t\t: %u\n"
						"\t\t\tDPseci minor version \t\t\t\t\t: %u\n"
						"\t\t\tSec Era \t\t\t\t\t\t: %u\n"
						"\t\t\tNumber of DECO copies implemented \t\t\t: %u\n"
						"\t\t\tNumber of ZUCA copies implemented \t\t\t: %u\n"
						"\t\t\tNumber of ZUCE copies implemented \t\t\t: %u\n"
						"\t\t\tNumber of SNOW-f8 module copies \t\t\t: %u\n"
						"\t\t\tNumber of SNOW-f9 module copies	\t\t\t: %u\n"
						"\t\t\tNumber of CRC module copies \t\t\t\t: %u\n"
						"\t\t\tNumber of Public key module copies \t\t\t: %u\n"
						"\t\t\tNumber of Kasumi module copies \t\t\t\t: %u\n"
						"\t\t\tNumber of Random Number Generator copies \t\t: %u\n"
						"\t\t\tNumber of MDHA (Hashing Module) copies \t\t\t: %u\n"
						"\t\t\tNumber of ARC4 module copies \t\t\t\t: %u\n"
						"\t\t\tNumber of DES module copies \t\t\t\t: %u\n"
						"\t\t\tNumber of AES module copies \t\t\t\t: %u\n\n\n",
						name,
						sec_attr.ip_id, sec_attr.major_rev, sec_attr.minor_rev,
						sec_attr.era, sec_attr.deco_num, sec_attr.zuc_auth_acc_num,
						sec_attr.zuc_enc_acc_num, sec_attr.snow_f8_acc_num,
						sec_attr.snow_f9_acc_num, sec_attr.crc_acc_num, sec_attr.pk_acc_num,
						sec_attr.kasumi_acc_num, sec_attr.rng_acc_num,
						sec_attr.md_acc_num, sec_attr.arc4_acc_num,
						sec_attr.des_acc_num, sec_attr.aes_acc_num);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}

			break;
		}
	case DPAA2_DEBUG_DPSECI_COUNTERS:
		{
			struct dpaa2_dev_priv *dev_priv;
			struct dpseci_sec_counters sec_cnt;
			struct fsl_mc_io *dpseci_dev;
			int ret;

			dev_priv = get_dev_priv(name);

			if (!dev_priv) {
				ODP_ERR("Error: DPAA2 DEV PRIV NOT FOUND!\n");
				return;
			}

			dpseci_dev = (struct fsl_mc_io *)dev_priv->hw;
			if (!dpseci_dev) {
				ODP_ERR("Error: FSL MC IO HANDLE NOT FOUND!\n");
				return;
			}

			ret = dpseci_get_sec_counters(dpseci_dev, CMD_PRI_LOW, dev_priv->token, &sec_cnt);
			if (ret) {
				ODP_ERR("Error while getting counters. Error Code = %d\n", ret);
				return;
			}
			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET) {
				ODP_PRINT("DPSECI_COUNTERS\n"
					"%s:"
					"\t\tNumber of Requests Dequeued \t\t\t\t: %lu\n"
					"\t\t\tNumber of Outbound Encrypt Requests \t\t\t: %lu\n"
					"\t\t\tNumber of Inbound Decrypt Requests \t\t\t: %lu\n"
					"\t\t\tNumber of Outbound Bytes Encrypted \t\t\t: %lu\n"
					"\t\t\tNumber of Outbound Bytes Protected \t\t\t: %lu\n"
					"\t\t\tNumber of Inbound Bytes Decrypted \t\t\t: %lu\n"
					"\t\t\tNumber of Inbound Bytes Validated \t\t\t: %lu\n\n\n",
					name,
					sec_cnt.dequeued_requests,
					sec_cnt.ob_enc_requests,
					sec_cnt.ib_dec_requests,
					sec_cnt.ob_enc_bytes,
					sec_cnt.ob_prot_bytes,
					sec_cnt.ib_dec_bytes,
					sec_cnt.ib_valid_bytes);
			} else {
				ODP_PRINT("Command not supported\n");
				return;
			}

			break;
		}
	case DPAA2_DEBUG_PER_SA_STATS:
		{
			if ((event_msg->cmd) == DPAA2_DEBUG_CMD_GET)
				odp_crypto_print_stats();
			else {
				ODP_PRINT("Command not supported\n");
				return;
			}
			break;
		}

	}

	/* Print debug data on console */
	str = pr_buf;
	if (str)
	printf("%s\n", str);
}

static void *open_socket(void *arg ODP_UNUSED)
{
	int udp_socket;
	char buffer[BUFLEN];
	struct sockaddr_in server_addr, client_addr;
	socklen_t client_addr_size;
	fd_set readset;
	odp_instance_t instance = 0;

	void *msg;
	char *port;
	uint16_t port_no = DEFAULT_PLAT_DEBUG_PORT;

	/* Calling odp_init_local to initialize dpaa2 dpio dev
	 *  to be used in event handler to talk with qbman.
	 *  */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		ODP_ERR("Error: ODP local init failed.\n");
		return NULL;
	}

	udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

	if (udp_socket == -1) {
		perror("Platform Debug Server Socket creation FAILED");
		return NULL;
	}

	memset((char *)&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	port = getenv("PLAT_DEBUG_PORT");

	if (port)
		port_no = atoi(port);

	if (port_no < 1024) {
		ODP_ERR("ERROR: Cannot use priviledged ports,"
				"Please use port number greater than 1023\n");
		goto close_ret;
	}

	server_addr.sin_port = htons(port_no);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if ((bind(udp_socket, (struct sockaddr *)&server_addr,
		  sizeof(server_addr))) == -1) {
		perror("Platform Debug Server Socket bind FAILED");
		goto close_ret;
	}

	client_addr_size = sizeof(client_addr);

	while (1) {
		/*wait on udpSocket for any msg */
		FD_ZERO(&readset);
		FD_SET(udp_socket, &readset);
		select(udp_socket + 1, &readset, NULL, NULL, NULL);

		if (recvfrom(udp_socket, buffer, BUFLEN, 0,
			     (struct sockaddr_in *)&client_addr,
					&client_addr_size) == -1) {
			perror("Platform Debug Server recvfrom FAILED");
			return NULL;
		}

		/*event_handler will be called if udpSocket is active*/
		msg = (void *)&buffer;
		event_handler(msg);
	}
close_ret:
	close(udp_socket);
	return NULL;
}

int odp_platform_debug_init(void)
{
	char *plat_debug_thd = NULL;
	int thd_created = 0;
	odph_linux_pthread_t debug_thread;
	odp_cpumask_t thd_mask;

	plat_debug_thd = getenv("PLAT_DEBUG_THREAD");
	if (plat_debug_thd) {
		memset(&debug_thread, 0, sizeof(debug_thread));
		odp_cpumask_zero(&thd_mask);
		/*TODO: */
		odp_cpumask_set(&thd_mask, 0xff);

		pthread_attr_init(&debug_thread.attr);
		pthread_attr_setaffinity_np(&debug_thread.attr,
					    sizeof(cpu_set_t), &thd_mask.set);

		thd_created = pthread_create(&debug_thread.thread,
					     &debug_thread.attr,
				open_socket,
				NULL);

		if (thd_created != 0) {
			perror("Platform Debug Thread creation failed!");
			return -1;
		}
		ODP_PRINT("Platform Debug Thread is Intialized\n");
	} else {
		ODP_DBG("PLATFORM DEBUG THREAD not initialized\n");
		return -1;
	}
	return 0;
}
