/*
 *  Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/*   Derived from DPDK's rte_kni_common.h
 *
 *   This file is provided under a dual BSD/LGPLv2 license.  When using or
 *   redistributing this file, you may do so under either license.
 *
 *   GNU LESSER GENERAL PUBLIC LICENSE
 *
 *   Copyright(c) 2007-2013 Intel Corporation. All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2.1 of the GNU Lesser General Public License
 *   as published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *   Contact Information:
 *   Intel Corporation
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _DPAA2_KNI_COMMON_H_
#define _DPAA2_KNI_COMMON_H_
#ifdef __KERNEL__
#include <linux/if.h>
#else

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <linux/types.h>
#endif
/*
 * KNI name is part of memzone name.
 */
#define DPAA2_KNI_NAMESIZE 32 /*!< Size of KNI device name */

#define KNI_FIFO_COUNT_MAX	256 /*!< Maximum number of ring entries */
#define KNI_FIFO_SIZE	(KNI_FIFO_COUNT_MAX * sizeof(void *) + sizeof(struct odpfsl_kni_fifo)) /*!< Size of the FIFO ring. */


/*
 * Request id.
 */
enum odpfsl_kni_req_id {
	DPAA2_KNI_REQ_UNKNOWN = 0, /*!< Unknown Request */
	DPAA2_KNI_REQ_CHANGE_MTU,
	DPAA2_KNI_REQ_CFG_NETWORK_IF,
	DPAA2_KNI_REQ_MAX,
	DPAA2_KNI_REQ_CHANGE_MAC_ADDR,
	DPAA2_KNI_REQ_CHANGE_PROMISC
};

/*
 * Structure for KNI request.
 */
struct odpfsl_kni_request {
	uint32_t req_id;             /*!< Request id */
	union {
		uint32_t new_mtu;    /*!< New MTU */
		uint8_t if_up;       /*!< 1: interface up, 0: interface down */
		uint8_t promiscusity;
		uint8_t mac_addr[6];
	};
	int32_t result;               /*!< Result for processing request */
} __attribute__((__packed__));

/*
 * Fifo struct mapped in a shared memory. It describes a circular buffer FIFO
 * Write and read should wrap arround. Fifo is empty when write == read
 * Writing should never overwrite the read position
 */
struct odpfsl_kni_fifo {
	volatile unsigned write;     /*< Next position to be written*/
	volatile unsigned read;      /*< Next position to be read */
	unsigned len;                /*< Circular buffer length */
	unsigned elem_size;          /*< Pointer size - for 32/64 bit OS */
	void *volatile buffer[0];   /*< The buffer contains kbuf pointers */
};

/*
 * The kernel image of the kni_mbuf struct, with only the relevant fields.
 * Padding is necessary to assure the offsets of these fields
 */
struct odpfsl_kni_mbuf {
	void *pool;
	void *buf_addr;
	char pad0[14];
	uint16_t ol_flags;	/*!< Offload features. */
	uint32_t ol_info;	/*!< TCP Segmentation Offload Information. */
	void *next;
	void *data;		/*!< Start address of data in segment buffer. */
	uint32_t data_len;	/*!< Amount of data in segment buffer. */
	uint32_t pkt_len;	/*!< Total pkt len: sum of all segment data_len. */
	char pad2[2];
} __attribute__((__aligned__(64)));

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
/*
 * Struct used to create a KNI device. Passed to the kernel in IOCTL call
 */

struct odpfsl_kni_device_info {
	char name[DPAA2_KNI_NAMESIZE];  /* Network device name for KNI */

	uint64_t tx_phys;
	uint64_t rx_phys;
	uint64_t alloc_phys;
	uint64_t free_phys;

	/* Used by Ethtool */
	uint64_t req_phys;
	uint64_t resp_phys;
	uint64_t sync_phys;
	void *sync_va;

	/* kbuf mempool */
	void *kbuf_va;
	uint64_t kbuf_phys;
	uint64_t kbuf_mem_size;

	/* PCI info */
	uint16_t vendor_id;			/*< Vendor ID or PCI_ANY_ID. */
	uint16_t device_id;			/*< Device ID or PCI_ANY_ID. */
	uint8_t bus;				/*< Device bus */
	uint8_t devid;				/*< Device ID */
	uint8_t function;			/*< Device function. */

	uint16_t group_id;			/*< Group ID */
	uint32_t core_id;			/*< core ID to bind for kernel thread */

	uint8_t force_bind;			/*< Flag for kernel thread binding */

	unsigned int kbuf_size;		/*< Mbuf size */
	unsigned int mtu;			/*< MTU */
	char macaddr[ETH_ALEN];
};

#define KNI_DEVICE "kni"

#define DPAA2_KNI_IOCTL_TEST    _IOWR(0, 1, int)
#define DPAA2_KNI_IOCTL_CREATE  _IOWR(0, 2, struct odpfsl_kni_device_info)
#define DPAA2_KNI_IOCTL_RELEASE _IOWR(0, 3, struct odpfsl_kni_device_info)

#endif /* _DPAA2_KNI_COMMON_H_ */
