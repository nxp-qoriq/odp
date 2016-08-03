/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP extensions for KNI (Kernel Network Interface)
 */

#ifndef _ODPFSL_KNI_API_H_
#define _ODPFSL_KNI_API_H_

/** @defgroup odpfsl_kni ODPFSL KNI
 *  KNI extension to ODP for User-space - Kernel communication
 *  @{
 */

#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <odp.h>
#include <odp/api/packet_io.h>
#include <odp/api/thread.h>
#include <odp/api/plat/kni/odpfsl_kni_mbuf.h>

/*********************************************************************
			Macro Definitions
**********************************************************************/

#ifndef SUCCESS
/** Suceess */
#define SUCCESS		EXIT_SUCCESS
#endif

#ifndef FAILURE
/** Failure */
#define FAILURE		(-EXIT_FAILURE)
#endif

/**< Maximum of ethernet ports */
#define ODPFSL_MAX_ETHPORTS 8

/**< Maximum number of Kernel threads for KNI */
#define	KNI_MAX_KTHREAD		1

/** Represents invalid KNI device */
#define ODPFSL_KNIDEV_INVALID	NULL

/** @def DEF_KNI_MAX_PKT_POLL
 * @brief Default size of maximum packets buffers read from KNI Interface for
 * a single rx/tx call. It is equal to maximum limit of packets for PKTIO
 * interface
 */
#define DEF_KNI_MAX_PKT_POLL		1

/*********************************************************************
			Structure Definitions
**********************************************************************/

/** Defines the KNI device handle */
typedef void * odpfsl_knidev_t;

/** Structure type for recording kni interface specific stats */
struct knidev_stats {
	uint64_t rx_packets; /**< number of pkts received from NIC, and sent to KNI */
	uint64_t rx_dropped; /**< number of pkts received from NIC, but failed to send to KNI */
	uint64_t tx_packets; /**< number of pkts received from KNI, and sent to NIC */
	uint64_t tx_dropped; /**< number of pkts received from KNI, but failed to send to NIC */
};

/** Typedef for knidev_stats structure */
typedef struct knidev_stats knidev_stats_t;

/**
 * Structure for configuration items for KNI instance
 */
struct kni_config {
	unsigned int mbuf_size; /**< mbuf block size for KNI buffer pool */
	unsigned int mbuf_count; /**< mbuf block count for KNI buffer pool */
	unsigned int max_packet_size; /**< Max packet size */
	uint16_t default_core_id; /**< Default GPP execution core ID */
	uint16_t max_packet_poll; /**< Max poll count for single call to tx/rx on KNI interface */
};

/** Typedef for kni_config structure */
typedef struct kni_config odpfsl_kni_config_t;

/*!
 * Structure which has the function pointers for KNI interface.
 */
typedef struct odpfsl_knidev_ops_s {
	uint8_t port_id; /*!< Port ID */

	int (*change_mtu)(uint8_t port_id, unsigned new_mtu); /*!< Pointer to
						function of changing MTU */

	int (*config_network_if)(uint8_t port_id, uint8_t if_up); /*!< Pointer
				to function of configuring network interface */
	int (*config_mac_address)(uint8_t port_id, uint8_t mac_addr[6]); /*!< Pointer
				to function of configuring mac address of network interface */
	int (*config_promiscusity)(uint8_t port_id, uint8_t to_on); /*!< Pointer
				to function of configuring promiscuous mode network interface */
} odpfsl_knidev_ops_t;

/*********************************************************************
			Function Definitions
**********************************************************************/
/* Global Routines */

/**
 * Obtaining a kni_device and setting it to default values
 *
 * @param [in] port_id KNI device port number to initialize
 *
 * @return odpfsl_knidev_t
 */
odpfsl_knidev_t odpfsl_knidev_alloc(int32_t port_id);

/**
 * Releasing an allocated kni_device
 *
 * For a given kni_device, odpfsl_kni_release is called to shutdown and release
 * it.
 *
 * @param [in] kdev odpfsl_knidev_t type device
 *
 * @return void
 */
void odpfsl_knidev_free(odpfsl_knidev_t kdev);

/**
 * Opening a KNI device against a given odp_pktio_t device
 *
 * For each ODP interface created by the caller, this would create a kni_device
 * and initialize it. This initialization would include populating the
 * kni_device structure.
 *
 * Caller can pass odpfsl_knidev_ops_t structure containing callback handler for
 * operations which can be performed on KNI device (MTU, toggling state etc.)
 * In case caller passes NULL, a default set of operation would be used.
 *
 * @param [in] kdev odpfsl_knidev_t instance to initialize
 * @param [in] port_id KNI Port number
 * @param [in] pktio odp_pktio_t type device, to map with KNI device
 * @param [in] ops OPTIONAL a structure of odpfsl_knidev_ops_t type, containing
 *                 callbacks for supported KNI operations
 * @param [in] k_name OPTIONAL a user-defined name for KNI device; if not
 *                 provided, 'keth-x' format would be used.
 * @return 0 for Success, -1 for Failure
 */
int odpfsl_knidev_open(odpfsl_knidev_t kdev, uint8_t port_id, \
		odp_pktio_t pktio, odpfsl_knidev_ops_t *ops, \
		char *k_name);

/**
 * Routine to extract pktio from kni_device structure
 *
 * odpfsl_kni_api internally maintains a structure which contains kni device to
 * pktio (ODP) device mapping, besides other information. This function returns
 * mapped ODP device for a given KNI device
 *
 * @param [in] kdev odpfsl_knidev_t device for which corresponding pktio
 *			device is required
 *
 * @return odp_pktio_t type device
 */
odp_pktio_t odpfsl_knidev_get_pktio(odpfsl_knidev_t kdev);

/**
 * Check if knidev instance is valid or not
 *
 * Compares passed instance handle to NULL for validing if the instance is
 * valid or not
 *
 * @param [in] kdev odpfsl_knidev_t
 *
 * @return 1 for Valid instance, 0 for invalid instance
 */
odp_bool_t odpfsl_knidev_check_valid(odpfsl_knidev_t kdev);

/**
 * Obtain number of KNI Thread against a KNI device
 *
 * @param kdev odpfsl_knidev_t
 *
 * @return count of KNI Threads
 */
uint8_t	odpfsl_knidev_get_thread_count(odpfsl_knidev_t kdev);

/**
 * RX packet stats of a KNI device
 *
 * Returns the RX Packets and RX Packets dropped counters
 *
 * @param [in] kdev odpfsl_knidev_t type device identifier
 * @param [out] rx_packets RX Packet count
 * @param [out] rx_dropped RX Packet dropped count
 *
 * @return void
 */
void odpfsl_knidev_get_stat_rx(odpfsl_knidev_t kdev, uint64_t *rx_packets, \
		uint64_t *rx_dropped);

/**
 * TX packet stats of a KNI device
 *
 * Returns the TX Packets and TX Packets dropped counters
 *
 * @param [in] kdev odpfsl_knidev_t type device identifier
 * @param [out] tx_packets TX Packet count
 * @param [out] tx_dropped TX Packet dropped count
 *
 * @return void
 */
void odpfsl_knidev_get_stat_tx(odpfsl_knidev_t kdev, uint64_t *tx_packets,\
		uint64_t *tx_dropped);

/**
 * Interface to send RX'd packets from ODP interface to KNI interface
 *
 * Caller would pass an array of packets received from ODP, which this function
 * would convert into appropriate kni_mbuf packets and send over the KNI
 * interface using the odpfsl_kni_tx_burst
 *
 * @param [in] kdev odpfsl_knidev_t type device identifier
 * @param [in] id KNI port ID
 * @param [in] odp_packets odp_packet_t type array of packets, from ODP interface
 * @param [in] num number of packets in the packet array
 *
 * @return (unsigned)
 *		number of packets transmitted successfully to KNI interface
 */
unsigned odpfsl_kni_tx(odpfsl_knidev_t kdev, int id, \
		odp_packet_t odp_packets[], unsigned num);

/**
 * Interface to receive packets from KNI and convert into ODP packets
 *
 * Packets are received from KNI device using odpfsl_kni_rx_burst in kni_mbuf
 * form and converted into odp_packet_t to be sent to ODP interface by caller
 * The caller needs to pass an array, in which ODP packets would be allocated
 * by this function. Maximum size of array limits the number of packets which
 * can be received on the KNI interface
 *
 * @param [in] kdev odpfsl_knidev_t type device identifier
 * @param [in] id KNI port ID
 * @param [in] odp_packet_pool odp_pool_t type pool from which converted packets
 *                             would be allocted before handing over to caller
 * @param [in] packets odp_packet_t type array of packets, from ODP interface
 * @param [out] num number of packets in the packet array
 *
 * @return (unsigned)
 *	number of packets received from KNI interface and converted to ODP
 */
unsigned odpfsl_kni_rx(odpfsl_knidev_t kdev, int id, \
		odp_pool_t odp_packet_pool, odp_packet_t packets[],\
		unsigned num);

/**
 * Handle any device operations pending on KNI devices
 *
 * KNI devices support operations like change of MTU, change of state,
 * promiscuity etc. This function allows the caller to provide CPU cycles for
 * parsing such requests and calling corresponding callback functions.
 * This is essentially a wrapper around odpfsl_kni_handle_request API
 *
 * @param [in] kdev odpfsl_knidev_t type device
 * @param [in] port_id KNI port
 * @return
 *      0 for Success
 *     !0 for Failure (as returned by odpfsl_kni_handle_request
 */
int odpfsl_kni_handle_events(odpfsl_knidev_t kdev, int32_t port_id);

/**
 * Initializing the KNI Subsystem
 *
 * When called, this would initialize a ODP buffer pool to store the kni_mbufs
 * in.
 *
 * @param kconfig odpfsl_kni_config_t type configuration structure
 *
 * @return O for Success or (-1) for Failure
 */
int odpfsl_kni_init(odpfsl_kni_config_t *kconfig);

/**
 * Releasing any kni resources created by libkni
 *
 * @return 0 for SUCCESS and -1 for FAILURE
 */
int odpfsl_kni_fini(void);

/**
 * @}
 */

#endif /* _ODPFSL_KNI_API_H_ */
