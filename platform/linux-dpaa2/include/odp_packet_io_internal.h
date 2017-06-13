/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP packet IO - implementation internal
 */

#ifndef ODP_PACKET_IO_INTERNAL_H_
#define ODP_PACKET_IO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/spinlock.h>
#include <odp/api/plat/queue_types.h>
#include <odp_packet_dpaa2.h>
#include <odp_classification_datamodel.h>
#include <odp_align_internal.h>

#include <odp_config_internal.h>
#include <odp/api/hints.h>

/**
 * Packet IO types
 */
typedef enum {
	ODP_PKTIO_TYPE_SOCKET_BASIC = 0x1,
	ODP_PKTIO_TYPE_SOCKET_MMSG,
	ODP_PKTIO_TYPE_SOCKET_MMAP,
	ODP_PKTIO_TYPE_LOOPBACK,
} odp_pktio_type_t;

struct pktio_entry {
	odp_spinlock_t lock;		/**< entry spinlock */
	int taken;			/**< is entry taken(1) or free(0) */
	uint8_t conf_rx_queues;		/**< number of configured input queues*/
	uint8_t conf_tx_queues;		/**< number of configured out queues*/
	odp_queue_t loopq;		/**< loopback queue for "loop" device */
	odp_pktio_type_t type;		/**< pktio type */
	pkt_dpaa2_t pkt_dpaa2;		/**< using DPAA2 API for IO */
	odp_bool_t cls_init_done;	/**< Classifier is initialized or not ?*/
	classifier_t cls;		/**< classifier linked with this pktio*/
	char name[IFNAMSIZ];		/**< name of pktio provided to
					   pktio_open() */
	odp_pktio_config_t config;	/**< Device configuration */
	odp_pktio_param_t param; /*PKTIO params*/
	int pktio_headroom;		/* Pktio Headroom */
	odp_bool_t promisc;		/**< promiscuous mode state */
	odp_bool_t hash_enable;		/**<Hash distribution enabled */
	void	*priv;
};

typedef union {
	struct pktio_entry s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pktio_entry))];
} pktio_entry_t;

typedef struct {
	odp_spinlock_t lock;
	pktio_entry_t entries[ODP_CONFIG_PKTIO_ENTRIES];
} pktio_table_t;

extern void *pktio_entry_ptr[];


static inline pktio_entry_t *get_pktio_entry(odp_pktio_t id)
{
	if (odp_unlikely(id == ODP_PKTIO_INVALID ||
			 _odp_typeval(id) > ODP_CONFIG_PKTIO_ENTRIES))
		return NULL;

	return pktio_entry_ptr[_odp_typeval(id) - 1];
}

/**
 * Set the input queue to be associated with a pktio handle
 *
 * @param pktio         Packet IO handle
 * @param q_entry       queue entry
 * @param vq_id         virtual queue id of rx queue
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktio_inq_set(odp_pktio_t pktio, queue_entry_t *qentry, uint8_t vq_id);

/**
 * remove an input queue associated with a pktio handle
 *
 * @param pktio         Packet IO handle
 * @param vq_id		queue id
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktio_inq_rem(odp_pktio_t id, uint8_t vq_id);

void set_queue_entry_to_free(queue_entry_t *queue);
#ifdef __cplusplus
}
#endif

#endif
