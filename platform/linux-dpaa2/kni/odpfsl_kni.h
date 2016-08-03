/*
 *  Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */
/*   Derived from DPDK's rte_kni.h
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DPAA2_KNI_H_
#define _DPAA2_KNI_H_

/*!
 * @file
 * RTE KNI
 *
 * The KNI library provides the ability to create and destroy kernel NIC
 * interfaces that may be used by the RTE application to receive/transmit
 * packets from/to Linux kernel net interfaces.
 *
 * This library provide two APIs to burst receive packets from KNI interfaces,
 * and burst transmit packets to KNI interfaces.
 *
 * @addtogroup	DPAA2_KNI
 * @ingroup	DPAA2_NCS
 * @{
 */

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <odp/api/plat/kni/odpfsl_kni_api.h>

#ifdef __cplusplus
extern "C" {
#endif

struct odpfsl_kni; /*!< kni context */

/*!
 * A structure describing an ID for a PCI driver. Each driver provides a
 * table of these IDs for each device that it supports.
 */
struct dpaa2_pci_id {
	uint32_t device_id;           /*!< Device ID or PCI_ANY_ID. */
	uint16_t vendor_id;           /*!< Vendor ID or PCI_ANY_ID. */
	uint16_t subsystem_vendor_id; /*!< Subsystem vendor ID or PCI_ANY_ID. */
	uint16_t subsystem_device_id; /*!< Subsystem device ID or PCI_ANY_ID. */
};

/*!
 * A structure describing the location of a PCI device.
 */
struct dpaa2_pci_addr {
	uint16_t domain;                /*!< Device domain */
	uint8_t bus;                    /*!< Device bus */
	uint8_t devid;                  /*!< Device ID */
	uint8_t function;               /*!< Device function. */
};

/*!
 * Structure for configuring KNI device.
 */
struct odpfsl_kni_conf {
	/*
	 * KNI name which will be used in relevant network device.
	 * Let the name as short as possible, as it will be part of
	 * memzone name.
	 */
	char name[DPAA2_KNI_NAMESIZE]; /*!< Name of KNI device */
	uint32_t core_id;   /*!< Core ID to bind kernel thread on */
	uint16_t group_id;  /*!< Group ID */
	unsigned kbuf_size; /*!< kbuf size */
	struct dpaa2_pci_addr addr; /*!< Not used. */
	struct dpaa2_pci_id id; /*!< Not used.*/
	char macaddr[ETH_ADDR_LEN]; /*!< MAC address assigned to KNI*/
	uint16_t mtu;	/*!< Maximum transmission Unit of KNI*/

	uint8_t force_bind; /*!< Flag to bind kernel thread */
};

/*!
 * Allocate KNI interface according to the port id, kbuf size, kbuf pool,
 * configurations and callbacks for kernel requests.The KNI interface created
 * in the kernel space is the net interface the traditional Linux application
 * talking to.
 *
 * @param pktmbuf_pool
 *  The mempool for allocting kbufs for packets.
 * @param conf
 *  The pointer to the configurations of the KNI device.
 * @param ops
 *  The pointer to the callbacks for the KNI kernel requests.
 *
 * @return
 *  - The pointer to the context of a KNI interface.
 *  - NULL indicate error.
 */
extern struct odpfsl_kni *odpfsl_kni_alloc(void *pktmbuf_pool,
				     const struct odpfsl_kni_conf *conf,
				     odpfsl_knidev_ops_t *ops);

/*!
 * Release KNI interface according to the context. It will also release the
 * paired KNI interface in kernel space. All processing on the specific KNI
 * context need to be stopped before calling this interface.
 *
 * @param kni
 *  The pointer to the context of an existant KNI interface.
 *
 * @return
 *  - 0 indicates success.
 *  - negative value indicates failure.
 */
extern int odpfsl_kni_release(struct odpfsl_kni *kni);

/*!
 * It is used to handle the request kbufs sent from kernel space.
 * Then analyzes it and calls the specific actions for the specific requests.
 * Finally constructs the response kbuf and puts it back to the resp_q.
 *
 * @param kni
 *  The pointer to the context of an existant KNI interface.
 *
 * @return
 *  - 0
 *  - negative value indicates failure.
 */
extern int odpfsl_kni_handle_request(struct odpfsl_kni *kni);

/*!
 * Retrieve a burst of packets from a KNI interface. The retrieved packets are
 * stored in kni_mbuf structures whose pointers are supplied in the array of
 * kbufs, and the maximum number is indicated by num. It handles the freeing of
 * the kbufs in the free queue of KNI interface.
 *
 * @param kni
 *  The KNI interface context.
 * @param kbufs
 *  The array to store the pointers of kbufs.
 * @param num
 *  The maximum number per burst.
 *
 * @return
 *  The actual number of packets retrieved.
 */
extern unsigned odpfsl_kni_rx_burst(struct odpfsl_kni *kni,
		struct kni_mbuf **kbufs, unsigned num);

/*!
 * Send a burst of packets to a KNI interface. The packets to be sent out are
 * stored in kni_mbuf structures whose pointers are supplied in the array of
 * kbufs, and the maximum number is indicated by num. It handles allocating
 * the kbufs for KNI interface alloc queue.
 *
 * @param kni
 *  The KNI interface context.
 * @param kbufs
 *  The array to store the pointers of kbufs.
 * @param num
 *  The maximum number per burst.
 *
 * @return
 *  The actual number of packets sent.
 */
extern unsigned odpfsl_kni_tx_burst(struct odpfsl_kni *kni,
		struct kni_mbuf **kbufs, unsigned num);

/*!
 * Get the port id from KNI interface.
 *
 * Note: It is deprecated and just for backward compatibility.
 *
 * @param kni
 *  The KNI interface context.
 *
 * @return
 *  On success: The port id.
 *  On failure: ~0x0
 */
extern uint8_t odpfsl_kni_get_port_id(struct odpfsl_kni *kni) \
				__attribute__ ((deprecated));

/*!
 * Get the KNI context of its name.
 *
 * @param name
 *  pointer to the KNI device name.
 *
 * @return
 *  On success: Pointer to KNI interface.
 *  On failure: NULL.
 */
extern struct odpfsl_kni *odpfsl_kni_get(const char *name);

/*!
 * Get the KNI context of the specific port.
 *
 * Note: It is deprecated and just for backward compatibility.
 *
 * @param port_id
 *  the port id.
 *
 * @return
 *  On success: Pointer to KNI interface.
 *  On failure: NULL
 */
extern struct odpfsl_kni *odpfsl_kni_info_get(uint8_t port_id) \
				__attribute__ ((deprecated));

/*!
 * Register KNI request handling for a specified port,and it can
 * be called by master process or slave process.
 *
 * @param kni
 *  Pointer to struct odpfsl_kni.
 * @param ops
 *  Ponter to struct odpfsl_kni_ops.
 *
 * @return
 *  On success: 0
 *  On failure: -1
 */
extern int odpfsl_kni_register_handlers(struct odpfsl_kni *kni,
			odpfsl_knidev_ops_t *ops);

/*!
 *  Unregister KNI request handling for a specified port.
 *
 *  @param kni
 *   Pointer to struct odpfsl_kni.
 *
 *  @return
 *   On success: 0
 *   On failure: -1
 */
extern int odpfsl_kni_unregister_handlers(struct odpfsl_kni *kni);

/*!
 *  Close KNI device.
 *
 *  @return
 *   void
 */
extern void odpfsl_kni_close(void);

#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _DPAA2_KNI_H_ */
