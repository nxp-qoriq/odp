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
	odp_queue_t inq_default;	/**< default input queue, if set */
	odp_queue_t outq_default;	/**< default out queue */
	odp_queue_t loopq;		/**< loopback queue for "loop" device */
	odp_pktio_type_t type;		/**< pktio type */
	pkt_dpaa2_t pkt_dpaa2;		/**< using DPAA2 API for IO */
	odp_bool_t cls_init_done;	/**< Classifier is initialized or not ?*/
	classifier_t cls;		/**< classifier linked with this pktio*/
	char name[IFNAMSIZ];		/**< name of pktio provided to
					   pktio_open() */
	odp_pktio_param_t param; /*PKTIO params*/
	int pktio_headroom;		/* Pktio Headroom */
	odp_bool_t promisc;		/**< promiscuous mode state */
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
 * Set the default input queue to be associated with a pktio handle
 *
 * @param pktio         Packet IO handle
 * @param queue         default input queue set
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktio_inq_setdef(odp_pktio_t pktio, odp_queue_t queue);

/**
 * Query default output queue
 *
 * @param pktio Packet IO handle
 *
 * @return Default out queue
 * @retval ODP_QUEUE_INVALID on failure
 */
static inline odp_queue_t odp_pktio_outq_getdef(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (pktio_entry == NULL)
		return ODP_QUEUE_INVALID;

	return pktio_entry->s.outq_default;
}


/**
 * Get default input queue associated with a pktio handle
 *
 * @param pktio  Packet IO handle
 *
 * @return Default input queue set
 * @retval ODP_QUEUE_INVALID on failure
 */
static inline odp_queue_t odp_pktio_inq_getdef(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (pktio_entry == NULL)
		return ODP_QUEUE_INVALID;

	return pktio_entry->s.inq_default;
}

/**
 * remove the default input queue associated with a pktio handle
 *
 * @param pktio         Packet IO handle
 * @retval  0 on success
 * @retval <0 on failure
 */
int odp_pktio_inq_remdef(odp_pktio_t pktio);

#ifdef __cplusplus
}
#endif

#endif
