/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */


/*!
 * @file	dpaa2_ethdev.h
 *
 * @brief	Ethernet device related macros & functions support for DPAA2 device
 *		framework based applications.
 *
 * @addtogroup	DPAA2_ETH
 * @ingroup	DPAA2_DEV
 * @{
 */

#ifndef _DPAA2_ETHDEV_H_
#define _DPAA2_ETHDEV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/sdk/main/dpaa2_dev.h>
#include <odp/api/plat/sdk/rts/dpaa2_mbuf.h>
#include <odp/api/plat/sdk/eth/dpaa2_ether.h>
#include <fsl_dpni.h>

/*! Maximum number of flow distributions per traffic class */
#define MAX_DIST_PER_TC 8
/*! Maximum number of traffic classes */
#define MAX_TCS 8

/* Flow header fields which should be set for flow distribution.
 * See the dpaa2_eth_setup_flow_distribution API */
/*! Ethernet Source MAC address */
#define DPAA2_FDIST_L2_SA BIT_POS(0)
/*! Ethernet Destination MAC address */
#define DPAA2_FDIST_L2_DA BIT_POS(1)
/*! Ethernet VLAN ID */
#define DPAA2_FDIST_L2_VID BIT_POS(2)
/*! IP source address */
#define DPAA2_FDIST_IP_SA BIT_POS(3)
/*! IP destination address */
#define DPAA2_FDIST_IP_DA BIT_POS(4)
/*! IP protocol (e.g. TCP/UDP/ICMP) */
#define DPAA2_FDIST_IP_PROTO BIT_POS(5)
/*! TCP source port */
#define DPAA2_FDIST_TCP_SP BIT_POS(6)
/*! TCP destination port */
#define DPAA2_FDIST_TCP_DP BIT_POS(7)
/*! UDP source port */
#define DPAA2_FDIST_UDP_SP BIT_POS(8)
/*! UDP destination port */
#define DPAA2_FDIST_UDP_DP BIT_POS(9)
/*! Source port (TCP & UDP) */
#define DPAA2_FDIST_L4_SP \
	(DPAA2_FDIST_TCP_SP | DPAA2_FDIST_UDP_SP)
/*! Destination port (TCP & UDP) */
#define DPAA2_FDIST_L4_DP \
	(DPAA2_FDIST_TCP_DP | DPAA2_FDIST_UDP_DP)

/* Type of Rx distribution set. This is within a traffic class */
enum dist_type {
	DPAA2_ETH_NO_DIST, /*!< No distribution is set */
	DPAA2_ETH_FLOW_DIST /*!< Flow distribution is set */
	/* TODO add exact match if and when required */
};

/*! Configuration of a traffic class */
struct tc_config {
	uint16_t num_dist; /*!<Number of Rx distributions in
			    * the traffic class */
	uint16_t num_dist_used; /*!<Number of Rx distributions in
			    * the traffic class being used. */
	enum dist_type dist_type; /*! Type of distribution */
};

/*! Queues configuration for a particular Ethernet device. */
struct queues_config {
	uint32_t num_rx_tcs;	 /*!< Number of RX traffic classes */
	uint32_t num_tx_tcs;	 /*!< Number of TX traffic classes */
	struct tc_config tc_config[MAX_TCS]; /*!< Traffic class
					    * configuration */
	/* TODO: Add senders if required */
};

/*!
 *  Extended Statistics counters for an Ethernet port.
 */
struct dpaa2_eth_xstats {
	uint64_t collisions;  /*!< Total number of collosions occur in RX. */
	uint64_t rx_length_errors; /*!< Receive length error */

	uint64_t rx_over_errors; /*!< Received ring buff overflow	*/
	uint64_t rx_crc_errors;	/*!< Received pkt with crc error	*/
	uint64_t rx_frame_errors; /*!< Received frame alignment error */
	uint64_t rx_fifo_errors; /*!< Received fifo overrun */
	uint64_t rx_missed_errors; /*!< Received missed packet	*/

	uint64_t tx_aborted_errors; /*!< Transmission aborted */
	uint64_t tx_carrier_errors; /*!< Carrier Errors */
	uint64_t tx_fifo_errors; /*!<  Transmit fifo overrun */
	uint64_t tx_heartbeat_errors; /*!< Transmit Link heartbeat Error */
	uint64_t tx_window_errors; /*!< Transmission window error */

	uint64_t rx_pause; /*!< Toatal number of pause frame received */
	uint64_t tx_pause; /*!< Toatal number of pause frame sent */

	/*TODO: Statistics are not SMP safe as not maintained per cpu.*/
	uint64_t tx_frm_len_err; /*!< Tx frame length error */
	uint64_t tx_sys_bus_err; /*!< Tx system bus error */
};

/*!
 * A structure used to store link-level information of an Ethernet port.
 */
struct dpaa2_eth_link {
	uint16_t link_speed;	/*!< ETH_LINK_SPEED_[10, 100, 1000, 10000] */
	uint8_t  link_duplex;	/*!< ETH_LINK_[HALF_DUPLEX, FULL_DUPLEX] */
	uint8_t  link_status;	/*!< 1 -> link up, 0 -> link down */
} __attribute__((aligned(8)));	/*!< aligned for atomic64 read/write */

#define ETH_LINK_SPEED_AUTONEG  0       /*!< Auto-negotiate link speed. */
#define ETH_LINK_SPEED_10       10      /*!< 10 megabits/second. */
#define ETH_LINK_SPEED_100      100     /*!< 100 megabits/second. */
#define ETH_LINK_SPEED_1000     1000    /*!< 1 gigabits/second. */
#define ETH_LINK_SPEED_10000    10000   /*!< 10 gigabits/second. */

#define ETH_LINK_AUTONEG_DUPLEX 0       /*!< Auto-negotiate duplex. */
#define ETH_LINK_HALF_DUPLEX    1       /*!< Half-duplex connection. */
#define ETH_LINK_FULL_DUPLEX    2       /*!< Full-duplex connection. */


/*!
 * @details	Get the queue configuration (tc's, distributions etc)
 *		for the ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	Queue configuration for the Ethernet device, NULL on failure
 *
 */
struct queues_config *dpaa2_eth_get_queues_config(struct dpaa2_dev *dev);

/*!
 * @details	Configures MTU for a given Ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	mtu - MTU value to be set
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */
int dpaa2_eth_mtu_set(struct dpaa2_dev *dev, uint16_t mtu);

/*!
 * @details	Get the Configured MTU for a given Ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	Valid MTU value; '0' otherwise
 *
 */
uint16_t dpaa2_eth_mtu_get(struct dpaa2_dev *dev);

/*!
 * @details	Configures the size of Headroom i.e. an available area which can
 *		be used. Actaul data content will be written after the Headroom.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	headroom - Size of headroom in bytes
 *
 */
void dpaa2_eth_set_buf_headroom(struct dpaa2_dev *dev,
				uint32_t headroom);

/*!
 * @details	Attach the given Ethernet device to buffer pool list. User can
 *		add only one buffer pool list on a device, whereas user can
 *		attach same buffer pool list accross multiple devices.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device.
 *
 * @param[in]	bp_list - Buffer pool list handle.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise
 *
 */

int32_t dpaa2_eth_attach_bp_list(struct dpaa2_dev *dev,
			void *bp_list);

/*!
 * @details	Reset the given Ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device.
 *
 * @returns	'0' on Success; Error code otherwise.
 *
 */

int32_t dpaa2_eth_reset(struct dpaa2_dev *dev);

/*!
 * @details	Configures the MAC address to a given DPAA2 ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	addr - Pointer to Ethernet MAC address structure.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_set_mac_addr(struct dpaa2_dev *dev,
			uint8_t *addr);

/*!
 * @details	Get the MAC address of a given DPAA2 ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[out]	addr - Pointer to Ethernet MAC address structure.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_get_mac_addr(struct dpaa2_dev *dev,
			uint8_t *addr);

/*!
 * @details	Add a filter entry for unicast/multicast MAC address to given
 *		ethernet device. Default all frames will be entertained.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	addr - Pointer to Ethernet MAC address structure.
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_add_mac_filter(struct dpaa2_dev *dev,
			uint8_t *addr);
/*!
 * @details	Remove a filter entry for unicast/multicast MAC address
 *		from given ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	addr - Pointer to Ethernet MAC address structure
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_remove_mac_filter(struct dpaa2_dev *dev,
			uint8_t *addr);

/*!
 * @details	Enable the RX promiscuous mode of an Ethernet device
 *		i.e. all the data packets will be entertained irrespective
 *		destination MAC address.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_promiscuous_enable(struct dpaa2_dev *dev);

/*!
 * @details	Disable RX promiscuous mode of an Ethernet device i.e.
 *		Frames, having same destination MAC address as of device, will
 *		be entertained only.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_promiscuous_disable(struct dpaa2_dev *dev);

/*!
 * @details	Get the RX promiscuous mode of an Ethernet device
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	TRUE for Promiscuouse mode enable of an ethernet device, false for disable.
 *
 */
int dpaa2_eth_promiscuous_get(struct dpaa2_dev *dev);

/*!
 * @details	Enables the Ethernet device to receive all multicast
 *		packets.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_multicast_enable(struct dpaa2_dev *dev);

/*!
 * @details	Disable the Ethernet device to drop multicast packets.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_multicast_disable(struct dpaa2_dev *dev);

/*!
 * @details	Get link speed, duplex mode and state (up/down) of
 *		an DPAA2 Ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[out]	state - Link information filled by DPAA2 ethernet driver.
 *
 */
int32_t dpaa2_eth_get_link_info(struct dpaa2_dev *dev,
				struct dpni_link_state *state);

/*!
 * @details	Get Extented I/O statistics of an Ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[out]	eth_xstats - Pointer to DPAA2 ethernet device extended statistics
 *
 * @param[in]	reset - reset = 1 to reset all the counters to 0
 *			otherwise reset = 0
 *
 */
void dpaa2_eth_xstats_get(struct dpaa2_dev *dev,
				struct dpaa2_eth_xstats *eth_xstats,
				int32_t reset);

/*!
 * A structure used to define Filter Rule set for an Ethernet port.
 */
struct dpaa2_eth_filter {
	uint32_t num_rules;	 /*!< Number of rules to configure */
	/* TODO Rule list */
};

/*!
 * @details	Configures the IP packet filter Rule/s for a given Ethernet
 *		device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	rules - Pointer to filter rules structure.
 *
 */
void dpaa2_eth_rx_filter_set(struct dpaa2_dev *dev,
				    struct dpaa2_eth_filter *rules);

/*!
 * @details	Enable/Disable Rx and/or TX Checksum offload
 *		for a given Ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	en_rx_checksum - 1 = Enable, 0 = Disable
 *
 * @param[in]	en_tx_checksum - 1 = Enable, 0 = Disable
 *
 */
void dpaa2_eth_offload_cheksum(struct dpaa2_dev *dev,
				      uint8_t en_rx_checksum,
				      uint8_t en_tx_checksum);

/*!
 * @details	Enable the GRO for a given Ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_gro_enable(struct dpaa2_dev *dev);

/*!
 * @details	Disable the GRO for a given Ethernet device
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_gro_disable(struct dpaa2_dev *dev);

/*!
 * @details	Enable the GSO for a given Ethernet device
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_gso_enable(struct dpaa2_dev *dev);

/*!
 * @details	Disable the GSO for a given Ethernet device
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_gso_disable(struct dpaa2_dev *dev);


/*!
 * @details	Enable Scatter-Gather support for a given Ethernet device
 *		i.e. A packet, of larger size than the configured buffers size,
 *		will be represented as a list of multiple packets.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_sg_enable(struct dpaa2_dev *dev);

/*!
 * @details	Disable Scatter-Gather support for a given Ethernet device
 *		i.e. Packet of larger size than the configured buffer size will
 *		will be dropped.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_sg_disable(struct dpaa2_dev *dev);

/*!
 * @details	Enable/Disable Rx VLAN extraction and TX VLAN insertion
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	rx_extraction - 1 = Enable, 0 = Disable
 *
 * @param[in]	tx_insertion - 1 = Enable, 0 = Disable
 *
 */
void dpaa2_eth_vlan_cfg(struct dpaa2_dev *dev,
			      uint8_t rx_extraction,
			      uint8_t tx_insertion);

/*!
 * @details	Add a VLAN filter to given device so that frames from the
 *		configured VLAN only will be received otherwise will be
 *		dropped.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	vlanid - VLAN ID which is to be set as filters
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_vlan_add(struct dpaa2_dev *dev, uint16_t vlanid);

/*!
 * @details	Remove a VLAN filter from given device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	vlanid - VLAN ID which is to be deleted from the filters
 *
 */
void dpaa2_eth_vlan_remove(struct dpaa2_dev *dev, uint16_t vlanid);

/*!
 * @details	Enable IP packet fragmentation support on a given Ethernet device
 *		i.e. the IP packets will be fragmented into multiple IP packets
 *		on the egress side according to MTU value set by
 *		dpaa2_eth_mtu_set() API (Default MTU is 1500).
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; error code otherwise.
 *
 */
int dpaa2_eth_frag_enable(struct dpaa2_dev *dev);

/*!
 * @details	Disable IP packet fragmentation support on a given Ethernet device
 *		i.e. the IP packets will be dropped on egress side at the
 *		Ethernet device if transmitted size is larger that the MTU.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; error code otherwise.
 *
 */
int dpaa2_eth_frag_disable(struct dpaa2_dev *dev);

/*!
 * @details	Enable IP packet reassembly support on a given Ethernet device.
 *		The fragmented IP packets will be reassembled at the device on
 *		the ingress side.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; error code otherwise.
 *
 */
int dpaa2_eth_reassembly_enable(struct dpaa2_dev *dev);

/*!
 * @details	Disable IP packet reassembly support on a given Ethernet device
 *		on the ingress side.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; error code otherwise.
 *
 */
int dpaa2_eth_reassembly_disable(struct dpaa2_dev *dev);

/*!
 * @details	Enable Ethernet Pause control frame support i.e. Ethernet device
 *		will be capable to transmit/receive pause control frames to
 *		maintain RX/TX flow control.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_pause_control_enable(struct dpaa2_dev *dev);

/*!
 * @details	Disable Ethernet Pause control frame support i.e. Ethernet device
 *		will be dropping the frames if receive rate is higher than
 *		device's capability
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_pause_control_disable(struct dpaa2_dev *dev);

/*!
 * @details	Enable Ethernet Loopback support i.e packet will be transmitted
 *		back to the same device on which packet is received.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_loopback_enable(struct dpaa2_dev *dev);

/*!
 * @details	Disable Ethernet Loopback support i.e. received packets will be
 *		forwarded to its normal data path.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 */
void dpaa2_eth_loopback_disable(struct dpaa2_dev *dev);


/*!
 * @details	Setup & enable Ethernet distribution for received packets by
 *		configuring rules to distribute packets among the queues
 *		of a particular traffic class.
 *		It should be called before setting up the Rx vq's on a
 *		disabled ethernet device. By default distribution is disabled
 *		on the ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	req_dist_set - The set of parameters, according to which traffic
 *		will be distributed among the VQs. This should be given like
 *		req_dist_set = DPAA2_FHDR_DIST_xxx | DPAA2_FHDR_DIST_yyy;
 *
 * @param[in]	tc_index - Traffic class index
 *
 * @param[in]	dist_size - Distribution size for rx flows in traffic class
 *
 * @returns	DPAA2_SUCCESS on success; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_eth_setup_flow_distribution(struct dpaa2_dev *dev,
		uint32_t req_dist_set,
		uint8_t tc_index,
		uint16_t dist_size);

/*!
 * @details	Disable Ethernet distribution for received packets.
 *		This function will also flush all the rules configured.
 *		It should be called before setting up the Rx vq's on a
 *		disabled ethernet device. By default distribution is disabled
 *		on the ethernet device.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @param[in]	tc_index - Traffic class index
 *
 */
void dpaa2_eth_remove_flow_distribution(struct dpaa2_dev *dev,
		uint8_t tc_index);

/*!
 * @details	Enable 1588 Timestamp support for the given device.
 *		It should be called only when device is not activated.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; error code otherwise.
 *
*/
int dpaa2_eth_timestamp_enable(struct dpaa2_dev *dev);

/*!
 * @details	Disable 1588 Timestamp support for the given device.
 *		It should be called only when device is disabled.
 *
 * @param[in]	dev - Pointer to DPAA2 Ethernet device
 *
 * @returns	DPAA2_SUCCESS on success; error code otherwise.
 *
 */
int dpaa2_eth_timestamp_disable(struct dpaa2_dev *dev);

/*! @} */
#endif /* _DPAA2_ETHDEV_H_ */
