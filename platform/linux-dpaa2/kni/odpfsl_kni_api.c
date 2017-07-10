/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <stdio.h>

#include <odp/helper/linux.h>
#include <odp_internal.h>
#include <odp/api/thread.h>
#include <odp/api/init.h>
#include <odp/api/system_info.h>
#include <odp/api/plat/kni/odpfsl_kni_api.h>

#include <odp/api/plat/sdk/main/dpaa2_dev.h>
#include <odpfsl_kni_common.h>
#include <odpfsl_kni.h>

#include <odp_debug_internal.h>
#include <odp_packet_io_internal.h>

/*********************************************************************
			Global Constants/Macro Definitions
**********************************************************************/
/* @def KNI_MAX_ETHPORTS
 * @brief Maximum number of Ethports against which KNI devices can be created
 */
#define KNI_MAX_ETHPORTS		ODPFSL_MAX_ETHPORTS

/** @def DEF_KNI_MAX_PKT_SIZE
 * @brief Default size of single Packet for KNI Interface, passed to KNI alloc
 * routine of DPAA2 (odpfsl_kni_alloc). This is equal to buffer size allocated
 */
#define DEF_KNI_MAX_PKT_SIZE		2048
				/* Size of each Packet Buffer =
				Ethernet Header(14) + data(1500) + FCS*/

/** @def KNID_PKTBUF_HEADROOM
 * @brief Headroom space in the Packet mbuf, before the actual packet data
 */
#define KNI_PKTMBUF_HEADROOM		32

/** @def DEF_KNI_PKTMBUF_SIZE
 * @brief Default KNI buffer size for holding a single packet data + headroom
 */
#define DEF_KNI_PKTMBUF_SIZE \
	(DEF_KNI_MAX_PKT_SIZE + sizeof(struct kni_mbuf) + KNI_PKTMBUF_HEADROOM)

/** @def DEF_KNI_PKTMBUF_NUM
 * @brief Default number of buffers (packet mbuf) for KNI Interface
 * DEF_KNI_NUM_PKTBUF * DEF_KNI_BUF_SZ = space allocated for KNI buffer
 * DEF_KNI_PKTMBUF_NUM = KNI_FIFO_COUNT_MAX * total number of queues on
 * kni device.
 */
#define DEF_KNI_PKTMBUF_NUM		KNI_FIFO_COUNT_MAX * 4


/* @def DEF_KNI_DEFAULT_CORE_ID
 * @brief Default core on which first worker thread has to be spawned
 */
#define DEF_KNI_CORE_ID			0

/*********************************************************************
			Global Variables
**********************************************************************/
static odp_pool_t kni_buf_pool = ODP_POOL_INVALID;
static knidev_stats_t knidev_stats[KNI_MAX_ETHPORTS];

/* Configuration globals */
unsigned int g_buf_size;
unsigned int g_buf_count;
unsigned int g_max_pkt_size;
uint16_t g_def_core_id;
uint16_t g_max_pkt_poll;

/*********************************************************************
			Structure Definitions
**********************************************************************/
/*
 * Structure of port parameters
 */
struct kni_device {
	uint8_t port_id;/* Port ID */
	uint8_t nb_lcore_k; /* Number of lcores for KNI multi kernel threads */
	uint16_t nb_kni; /* Number of KNI devices to be created */
	uint8_t lcore_k[KNI_MAX_KTHREAD]; /* lcore ID list for kthreads */
	int kni_headroom;
	void *kni[KNI_MAX_KTHREAD]; /* KNI context pointers */
	odp_pktio_t	pktio; /* ODP Pktio context associated with this dev */
} ODP_ALIGNED_CACHE;

/*********************************************************************
			Function Definitions
**********************************************************************/

/******************* KNI/Helper Callback Functions ******************/

/**
 * @brief Default Callback for request of changing MTU
 *
 * odpfsl_kni_api provides default MTU change handler, if not being changed by
 * the calling application (@see kni_init). This function is passed to KNI user
 * space driver for a callback when User initiates MTU change operation
 *
 * For ODP, this is not yet supported
 *
 * @param [in] port_id KNI device port number
 * @param [in] new_mtu MTU to change to
 *
 * @return
 *     0 for Success
 *    <0 for Failure
 */
static int
kni_change_mtu_def(uint8_t port_id ODP_UNUSED, unsigned new_mtu ODP_UNUSED)
{
	int ret = -EINVAL;

	ODP_DBG("Debug: Changing MTU of interface not supported by ODP.\n");
	return ret;
}

/**
 * @brief Default Callback for requesting toggling of Interface status
 *
 * odpfsl_kni_api provides default function state change handler,
 * if not being overrided by the calling application (@see kni_init).
 * This function is passed to KNI user
 * space driver for a callback when User initiates interface status toggle
 * e.g. ifconfig <device name> IP <up>
 *
 * @param [in] port_id KNI device port number
 * @param [in] if_up 0 for 'down', 1 for 'up'
 *
 * @return
 *     0 for Success
 *    <0 for Failure
 *
 */
static int
kni_config_network_interface_def(uint8_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (port_id >= KNI_MAX_ETHPORTS) {
		ODP_ERR("Error: Invalid Port ID: %d.\n", port_id);
		ret = -EINVAL;
	} else {
		ODP_DBG("Debug: Toggling Network Interface status for "\
			"port:%d to %s.\n", port_id, if_up ? "up" : "down");
	}

	return ret;
}

/**
 * @brief Default Callback for Updating the MAC Address of the interface
 *
 * odpfsl_kni_api provides default function for changing MAC address of
 * interface, if not being overrided by the calling application (@see kni_init)
 * This function is passed to KNI user
 * space driver for a callback when User initiates MAC address update of
 * interface
 * for e.g. through ethtool
 *
 * ODP currently doesn't support this functionality
 *
 * @param [in] port_id KNI device port number
 * @param [in] mac_addr MAC address to be set on device
 *
 * @return
 *     0 for Success
 *    <0 for Failure
 *
 */
static int
kni_config_mac_address_def(uint8_t port_id ODP_UNUSED, uint8_t mac_addr[6] ODP_UNUSED)
{
	int ret = -EINVAL;

	ODP_DBG("Debug: Changing MAC Address not supported by ODP.\n");
	return ret;
}

/**
 * @brief Callback for changing Promiscuity of interface
 *
 * odpfsl_kni_api provides default handler for changing promiscuity of the
 * interface, if not overrided by the calling application (@see kni_init).
 * Default is unsupported operation.
 *
 * @param [in] port_id KNI device port number
 * @param [in] to_on '1' for Promiscuity ON and '0' for OFF
 *
 * @return
 *     0 for Success
 *    <0 for Failure
 *  *
 */
static int
kni_config_promiscusity_def(uint8_t port_id ODP_UNUSED, uint8_t to_on ODP_UNUSED)
{
	int32_t ret = -EINVAL;
	return ret;
}

/***************** End of KNI Helper/callback Interfaces **************/

odpfsl_knidev_t
odpfsl_knidev_alloc(int32_t port_id)
{
	struct kni_device *dev;

	dev = calloc(1, sizeof(struct kni_device));
	if (!dev) {
		ODP_ERR("Error: Unable to allocate space for KNI device.\n");
		return NULL;
	}

	dev->port_id = port_id;
	dev->lcore_k[0] = g_def_core_id;
	dev->nb_lcore_k = 0; /* Should not be more than KNI_MAX_THREAD */
	dev->pktio = ODP_PKTIO_INVALID;

	return dev;
}

void
odpfsl_knidev_free(odpfsl_knidev_t kdev)
{
	int i = 0;
	int kdev_count = 0;
	struct kni_device *kdev_p = (struct kni_device *)kdev;

	if (kdev_p) {
		kdev_count = kdev_p->nb_kni;

		for (i = 0; i < kdev_count; i++)
			odpfsl_kni_release(kdev_p->kni[i]);

		free(kdev_p);
		kdev_p = NULL;
	}
}


/**
 * @brief Internal method to extract dpaa2_dev from pktio structure
 *
 * Only used internal to odpfsl_kni_api; Takes odp_pktio_t and typecasts it to
 * pktio_entry_t and return pkt_dpaa2.dev field
 *
 * @param [in] pktio odp_pktio_t type device, from which corresponding DPAA2
 *                   device is expected
 * @return dpaa2_dev extracted DPAA2 device, or NULL
 */
static inline struct dpaa2_dev *
get_dpaa2_dev(odp_pktio_t pktio)
{
	pktio_entry_t *pktio_entry;

	pktio_entry = get_pktio_entry(pktio);
	return pktio_entry->s.pkt_dpaa2.dev;
}

/**
 * @brief Internal method to extract dpaa2_pool from odp_pool_t type
 *
 * Only used internal to odpfsl_kni_api; Takes odp_pool_t and typecasts it to
 * pool_entry_t and return s.int_hdl field
 *
 * @param [in] odp_p odp_pool_t type pool, from which corresponding DPAA2
 *                   pool (dpaa2_pool) is expected
 * @return dpaa2_pool extracted DPAA2 pool, or NULL
 */
static inline struct dpaa2_pool *
convert_odp_to_dpaa2_pool(odp_pool_t odp_p) {
	pool_entry_t *pt;

	pt = odp_pool_to_entry(odp_p);
	return pt->s.int_hdl;
}

void
odpfsl_knidev_get_stat_rx(odpfsl_knidev_t kdev, uint64_t *rx_packets, \
	uint64_t *rx_dropped)
{
	struct kni_device *kdev_p = kdev;

	if (!kdev_p)
		return;

	if (rx_packets)
		*rx_packets = knidev_stats[kdev_p->port_id].rx_packets;

	if (rx_dropped)
		*rx_dropped = knidev_stats[kdev_p->port_id].rx_dropped;
}

void
odpfsl_knidev_get_stat_tx(odpfsl_knidev_t kdev, uint64_t *tx_packets, \
	uint64_t *tx_dropped)
{
	struct kni_device *kdev_p = kdev;

	if (!kdev_p)
		return;

	if (tx_packets)
		*tx_packets = knidev_stats[kdev_p->port_id].tx_packets;

	if (tx_dropped)
		*tx_dropped = knidev_stats[kdev_p->port_id].tx_dropped;
}

odp_bool_t
odpfsl_knidev_check_valid(odpfsl_knidev_t dev)
{
	struct kni_device *kdev_p = dev;

	if (!kdev_p)
		return 0;
	return 1;
}

uint8_t
odpfsl_knidev_get_thread_count(odpfsl_knidev_t kdev)
{
	struct kni_device *kdev_p = kdev;

	return kdev_p->nb_kni;
}

odp_pktio_t
odpfsl_knidev_get_pktio(odpfsl_knidev_t kdev)
{
	struct kni_device *kdev_p = (struct kni_device *)kdev;

	return kdev_p->pktio;
}

/**
 * @brief Releasing an array of kni mbufs
 *
 * @param [in] pkts	array of kni_mbufs
 * @param [in] num	size of the array
 *
 * @return void
 */
static void
kni_release_buffers(struct kni_mbuf **pkts, unsigned num)
{
	unsigned i;

	if (!pkts)
		return;

	for (i = 0; i < num; i++) {
		dpaa2_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}

/**
 * @brief Converting ODP Packet buffers into KNI equivalent mbufs
 *
 * For all packets received on ODP interface, of odp_packet_t type, this routine
 * converts them into equivalent KNI packet (kni_mbuf) type.
 * This would also release all the ODP packets which have been converted.
 * This would convert a single packet; Caller needs to rotate for all packets
 *
 * @param IN odp_p odp_packet_t instance
 * @param OUT kbuf pointer to a kni_mbuf instance
 *
 * @return
 *      0 for Success
 *     -1 for Failure
 */
static int32_t
convert_odpbuf_to_knibuf(odp_packet_t odp_p, struct kni_mbuf **kbuf)
{
	struct kni_mbuf *m;
	struct dpaa2_pool *p;

	p = convert_odp_to_dpaa2_pool(kni_buf_pool);
	if (!p) {
		ODP_ERR("Error:Unable to convert from ODP -> KNI buffers.\n");
		return FAILURE;
	}

	m = dpaa2_pktmbuf_alloc(p);
	if (!m) {
		ODP_ERR("Error: Unable to allocate buffer from KNI Pool.\n");
		return FAILURE;
	}

	memcpy(m->pkt.data, odp_p->data, odp_p->frame_len);
	m->pkt.data_len = odp_p->frame_len;
	m->pkt.pkt_len = 0;

	*kbuf = m;

	return SUCCESS;
}

/**
 * @brief Converting KNI packet (buffer) into ODP equivalent odp_packet_t
 *
 * For all packets received on KNI interface, of kni_mbuf type, this routine
 * converts them into equivalent ODP packet (odp_packet_t) type.
 * This would also release all the KNI packets which have been converted.
 * This would convert a single packet; Caller needs to rotate for all packets
 *
 * @param IN kbuf kni_mbuf packet
 * @param OUT kbuf pointer to a kni_mbuf instance
 *
 * @return
 *      0 for Success
 *     -1 for Failure
 */
static int32_t
convert_knibuf_to_odpbuf(struct kni_mbuf *kbuf, odp_pool_t pool_p, \
		odp_packet_t *odp_p, int headroom)
{
	odp_packet_t p;
	int ret, size, extra_headroom = 0;

	if (!kbuf) {
		ODP_ERR("Error: Wrong argument to convert_knibuf_to_odpbuf.\n");
		return FAILURE;
	}

	size = kbuf->pkt.data_len;

	if (headroom > ODP_CONFIG_PACKET_HEADROOM)
		extra_headroom = headroom - ODP_CONFIG_PACKET_HEADROOM;

#if 0
	/* XXX Unhandled Scatter-Gather case */
	 if (kbuf->pkt.next)
		DPAA2_WARN(APP1, "mbuf is SG");
#endif

	p = odp_packet_alloc(pool_p, size + extra_headroom);
	if (ODP_PACKET_INVALID == p) {
		ODP_ERR("Error: Unable to allocate memory for ODP Packet.\n");
		dpaa2_pktmbuf_free(kbuf);
		return FAILURE;
	}
	odp_packet_reset(p, size);

	if(extra_headroom)
		odp_packet_pull_head(p, extra_headroom);

	/*TODO: Need to change with odp_packet_copyXXX API*/
	ret = dpaa2_mbuf_data_copy_in(p, (const uint8_t *)kbuf->pkt.data, 0, size);
	if (ret != SUCCESS) {
		ODP_ERR("Error: Unable to copy KNI buffer into ODP Packet.\n");
		return FAILURE;
	}
	p->frame_len = size;

	dpaa2_pktmbuf_free(kbuf);
	*odp_p = p;

	return SUCCESS;
}

int
odpfsl_kni_handle_events(odpfsl_knidev_t kdev, int32_t port_id) {
	struct kni_device *kdev_p = (struct kni_device *)kdev;

	return odpfsl_kni_handle_request(kdev_p->kni[port_id]);
}

unsigned
odpfsl_kni_tx(odpfsl_knidev_t kdev, int id, odp_packet_t odp_packets[], \
	unsigned num)
{
	uint8_t n;
	int32_t ret = 0;
	unsigned nb_tx = 0, max_packets;
	struct kni_device *kdev_p = (struct kni_device *)kdev;

	/* XXX: In future, put in global area to prevent load on stack winding*/
	struct kni_mbuf *kni_buf[DEF_KNI_MAX_PKT_POLL];

	if (num > g_max_pkt_poll)
		max_packets = g_max_pkt_poll;
	else
		max_packets = num;

	for (n = 0; n < max_packets; n++) {
		ret = convert_odpbuf_to_knibuf(odp_packets[n], &kni_buf[n]);
		if (ret < 0)
			break;
	}
	if (n < max_packets) {
		knidev_stats[kdev_p->port_id].rx_dropped += (max_packets - n);
		max_packets = n;
	}

	/* Burst tx to kni */
	nb_tx = odpfsl_kni_tx_burst(kdev_p->kni[id], kni_buf, max_packets);
	knidev_stats[kdev_p->port_id].rx_packets += nb_tx;
	if (odp_unlikely(nb_tx < max_packets)) {
		/* NOTE: This is an informational print, not an error. */
		ODP_DBG("Debug: Free unprocessed mbufs num(%d) - nb_tx (%d)", \
			max_packets, nb_tx);
		/* Free kbufs not tx to kni interface */
		kni_release_buffers(&kni_buf[nb_tx], (max_packets - nb_tx));
		knidev_stats[kdev_p->port_id].rx_dropped += \
							(max_packets - nb_tx);
	}
	return nb_tx;
}

unsigned
odpfsl_kni_rx(odpfsl_knidev_t kdev, int id, odp_pool_t odp_packet_pool, \
	odp_packet_t packets[], unsigned num)
{
	uint8_t n;
	unsigned rx_packets;
	int ret = 0;
	struct kni_device *kdev_p = (struct kni_device *)kdev;

	/* XXX: In future, put in global area to prevent load on stack winding*/
	struct kni_mbuf *pkts[DEF_KNI_MAX_PKT_POLL];

	if (num > g_max_pkt_poll)
		num = g_max_pkt_poll;

	/* RX from KNI interface */
	rx_packets = odpfsl_kni_rx_burst(kdev_p->kni[id], pkts, num);

	if (rx_packets == 0)
		return rx_packets;

	for (n = 0; n < rx_packets; n++) {
		ret = convert_knibuf_to_odpbuf(pkts[n], odp_packet_pool, \
				&packets[n], kdev_p->kni_headroom);
		if (ret < 0) {
			ODP_ERR("Error: Unable to convert from KNI buffer to "\
				"ODP Packet.\n");
			break;
		}
	}
	if (n < rx_packets) {
		/* Free kbufs not converted */
		kni_release_buffers(&pkts[n], rx_packets - n);
		knidev_stats[kdev_p->port_id].tx_dropped += rx_packets - n;
		rx_packets = n;
	}
	knidev_stats[kdev_p->port_id].tx_packets += rx_packets;
	return rx_packets;
}

int
odpfsl_knidev_open(odpfsl_knidev_t kdev, uint8_t port_id, \
	odp_pktio_t pktio, odpfsl_knidev_ops_t *ops, char *k_name)
{
	int ret = SUCCESS;
	int i = 0;

	struct odpfsl_kni *kni;
	struct odpfsl_kni_conf conf;
	odpfsl_knidev_ops_t in_ops;
	odpfsl_knidev_ops_t *ops_p;
	struct dpaa2_pool *p;
	struct dpaa2_dev *ndev;
	struct kni_device *kdev_p = (struct kni_device *)kdev;
	pktio_entry_t *pktio_entry;

	pktio_entry = get_pktio_entry(pktio);

	if (port_id >= KNI_MAX_ETHPORTS) {
		ODP_ERR("Error: Port count exceed maximum limit (Request: %d) "\
			"> (Max:%d)", port_id, KNI_MAX_ETHPORTS);
		ret = FAILURE;
		return ret;
	}

	/* from odpfsl_knidev_init, nb_lcore_k would have been set */
	kdev_p->nb_kni = kdev_p->nb_lcore_k ? kdev_p->nb_lcore_k : 1;
	kdev_p->pktio = pktio;
	kdev_p->port_id = port_id;
	kdev_p->kni_headroom = pktio_entry->s.pktio_headroom;
	ndev = get_dpaa2_dev(pktio);
	if (!ndev) {
		/* Unable to find dpaa2<=>pktio mapping; Can't continue */
		ODP_ERR("Error: Unable to find device for pktio.\n");
		ret = FAILURE;
		return ret;
	}

	if (!ops) {
		/* Installing Default Handlers if users hasn't provided one */
		memset(&in_ops, 0, sizeof(odpfsl_knidev_ops_t));
		in_ops.change_mtu = kni_change_mtu_def;
		in_ops.config_network_if = kni_config_network_interface_def;
		in_ops.config_mac_address = kni_config_mac_address_def;
		in_ops.config_promiscusity = kni_config_promiscusity_def;
		ops_p = &in_ops;
	} else {
		ops_p = ops;
	}

	memset(&conf, 0, sizeof(conf));

	conf.id.device_id = dpaa2_dev_hwid(ndev);
	if (kdev_p->nb_lcore_k) {
		snprintf(conf.name, DPAA2_KNI_NAMESIZE, "keth-%u_%u", \
			conf.id.device_id, i);
		conf.core_id = kdev_p->lcore_k[i];
		conf.force_bind = 1;
	} else {
		snprintf(conf.name, DPAA2_KNI_NAMESIZE, "keth-%u", \
			conf.id.device_id);
	}

	/* If user-defined name (k_name) is available, override the internally
	 * generated name of KNI device
	 */
	if (k_name && (strlen(k_name) < DPAA2_KNI_NAMESIZE))
		snprintf(conf.name, DPAA2_KNI_NAMESIZE, "%s", k_name);

	conf.group_id = (uint16_t)port_id;
	conf.kbuf_size = g_max_pkt_size;
	conf.mtu  = odp_pktio_mtu(kdev_p->pktio);
	odp_pktio_mac_addr(kdev_p->pktio, (void *)conf.macaddr, ETH_ADDR_LEN);

	/*
	 * The first KNI device associated to a port
	 * is the master, for multiple kernel thread
	 * environment.
	 */
	p = convert_odp_to_dpaa2_pool(kni_buf_pool);
	for (i = 0; i < kdev_p->nb_kni; i++) {
		if (i == 0)
			kni = odpfsl_kni_alloc(p, &conf, ops_p);
		else
			kni = odpfsl_kni_alloc(p, &conf, NULL);

		if (!kni) {
			ODP_ERR("Error: Failed to create kni for port: %d\n", \
					port_id);
			ret = FAILURE;
			break;
		}

		kdev_p->kni[i] = kni;
	}

	while (i > 0 && ret != SUCCESS) {
		if (!odpfsl_kni_release(kdev_p->kni[--i])) {
			/* Unable to clean the allocated KNI devices */
			ODP_ERR("Error: Unable to clean devices 0-%d.\n", i);
			break;
		}
	}

	return ret;
}

int
odpfsl_kni_init(odpfsl_kni_config_t *kconfig) {
	int ret = SUCCESS;
	odp_pool_param_t params;

	ODP_DBG("Debug: Initializing KNI Buffer pool.\n");

	if (!kconfig) {
		/* Assigning defaults values to configuration parameters */
		g_buf_size = DEF_KNI_PKTMBUF_SIZE;
		g_buf_count = DEF_KNI_PKTMBUF_NUM;
		g_def_core_id = DEF_KNI_CORE_ID;
		g_max_pkt_size = DEF_KNI_MAX_PKT_SIZE;
		g_max_pkt_poll = DEF_KNI_MAX_PKT_POLL;
	} else {
		/* Assiging user provided values to configurations parameters */
		g_buf_size = kconfig->mbuf_size;
		g_buf_count = kconfig->mbuf_count;
		g_def_core_id = kconfig->default_core_id;
		g_max_pkt_size = kconfig->max_packet_size;
		if (kconfig->max_packet_poll > DEF_KNI_MAX_PKT_POLL)
			g_max_pkt_poll = DEF_KNI_MAX_PKT_POLL;
		else
			g_max_pkt_poll = kconfig->max_packet_poll;
	}

	ODP_DBG("Debug: KNI initialized with: buffer Size=%u, Buffer Count=%u"\
		", Default Core=%d, Max packet Size=%u, Max Poll=%d.\n", \
		g_buf_size, g_buf_count, g_def_core_id, g_max_pkt_size, \
		g_max_pkt_poll);

	/* Creating a buffer pool for KNI device */
	memset(&params, 0, sizeof(params));
	params.type			= ODP_POOL_BUFFER;
	params.buf.num		= g_buf_count;
	params.buf.size		= g_buf_size;

	kni_buf_pool = odp_pool_create("kni_mempool", &params);
	if (ODP_POOL_INVALID == kni_buf_pool) {
		ODP_ERR("Error: Kni buffer pool creation failed. \n");
		ret = FAILURE;
	} else {
		ODP_DBG("Debug: Created KNI Buffer Pool.\n");
	}

	return ret;
}

int
odpfsl_kni_fini(void) {
	int ret = SUCCESS;

	/* Release the kni_buf_pool */
	if (ODP_POOL_INVALID != kni_buf_pool) {
		ret = odp_pool_destroy(kni_buf_pool);
		/* Even if above function fails, kni_buf_pool is set to
		 * invalid
		 */
		kni_buf_pool = ODP_POOL_INVALID;
	}
	return ret;
}
