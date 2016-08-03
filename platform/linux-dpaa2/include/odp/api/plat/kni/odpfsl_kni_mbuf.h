/*
 *  Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/*-
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

#ifndef _KNI_MBUF_H_
#define _KNI_MBUF_H_

/*!
 * @file
 * RTE Mbuf
 *
 * The kbuf library provides the ability to create and destroy buffers
 * that may be used by the RTE application to store message
 * buffers. The message buffers are stored in a mempool, using the
 * RTE mempool library.
 *
 * This library provide an API to allocate/free kbufs, manipulate
 * control message buffer (ctrlmbuf), which are generic message
 * buffers, and packet buffers (pktmbuf), which are used to carry
 * network packets.
 *
 * To understand the concepts of packet buffers or kbufs, you
 * should read "TCP/IP Illustrated, Volume 2: The Implementation,
 * Addison-Wesley, 1995, ISBN 0-201-63354-X from Richard Stevens"
 * http://www.kohala.com/start/tcpipiv2.html
 *
 * The main modification of this implementation is the use of kbuf for
 * transports other than packets. kbufs can have other types.
 *
 * @addtogroup	DPAA2_KNI
 * @ingroup	DPAA2_NCS
 * @{

 */

#include <stdint.h>
#include <odp/api/std_types.h>
#ifdef __cplusplus
extern "C" {
#endif

/*! Headroom required in the KNI buffer */
#define DPAA2_PKTMBUF_HEADROOM 32
/*! Size of a cache line */
#define ODP_CACHE_LINE_SIZE 64

/**
 * A packet message buffer.
 */
struct dpaa2_pktmbuf {
	/* valid for any segment */
	struct kni_mbuf *next;  /*!< Next segment of scattered packet. */
	void *data;             /*!< Start address of data in segment buffer. */
	uint32_t data_len;      /*!< Amount of data in segment buffer. */
	uint32_t pkt_len;       /*!< Total pkt len: sum of all segment data_len. */
	uint8_t nb_segs;        /*!< Number of segments. */
	uint8_t in_port;        /*!< Input port. */

};

/*!
 * The generic kni_mbuf, containing a packet kbuf or a control kbuf.
 */
struct kni_mbuf {
	void *pool; /*!< Pool from which kbuf was allocated. */
	void *buf_addr;           /*!< Virtual address of segment buffer. */
	uint64_t buf_physaddr; /*!< Physical address of segment buffer. */
	uint16_t buf_len;         /*!< Length of segment buffer. */
#ifdef KNI_MBUF_SCATTER_GATHER
	/*!
	 * 16-bit Reference counter.
	 * It should only be accessed using the following functions:
	 * kni_mbuf_refcnt_update(), kni_mbuf_refcnt_read(), and
	 * kni_mbuf_refcnt_set(). The functionality of these functions (atomic,
	 * or non-atomic) is controlled by the CONFIG_KNI_MBUF_REFCNT_ATOMIC
	 * config option.
	 */
	union {
		odp_atomic_u16_t refcnt_atomic;   /*!< Atomically accessed refcnt */
		uint16_t refcnt;                /*!< Non-atomically accessed refcnt */
	};
#else
	uint16_t refcnt_reserved;     /*!< Do not use this field */
#endif
	uint8_t type;                 /*!< Type of kbuf. */
	uint8_t reserved;             /*!< Unused field. Required for padding. */
	uint16_t ol_flags;            /*!< Offload features. */
	uint32_t ol_info;		/*!< TCP Segmentation Offload feature Information. */
	union {
		struct dpaa2_pktmbuf pkt; /*!< A packet message buffer. */
	};
} __attribute__((__aligned__(ODP_CACHE_LINE_SIZE)));

/*!
 * This enum indicates the kbuf type.
 */
enum kni_mbuf_type {
	KNI_MBUF_CTRL,  /*!< Control kbuf. */
	KNI_MBUF_PKT,   /*!< Packet kbuf. */
};

/*!
 * Allocate kbuf from given kbuf pool
 *
 * @param mp
 *  The mempool pointer for allocting kbufs for packets.
 *
 * @return
 *  - The pointer to the allocated kbuf.
 *  - NULL indicate error.
 */

struct kni_mbuf *dpaa2_pktmbuf_alloc(void *mp);

/*!
 * Free kbuf to kbuf pool
 *
 * @param _m
 *  The kbuf pointer which are to be freed
 *
 * @return
 *  void
 */
void dpaa2_pktmbuf_free(void *_m);

void dpaa2_pktmbuf_init(void *mp, void *_m);

/*! @} */
#endif
