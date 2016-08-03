/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP Classification Internal
 * Describes the classification internal Functions
 */

#ifndef __ODP_CLASSIFICATION_INTERNAL_H_
#define __ODP_CLASSIFICATION_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/classification.h>
#include <odp/api/queue.h>
#include <odp_packet_internal.h>
#include <odp/api/packet_io.h>
#include <odp_packet_io_internal.h>
#include <odp_classification_datamodel.h>
#include <fsl_dpkg.h>

#define DIST_PARAM_IOVA_SIZE	256
#define ODP_CLS_DEFAULT_FLOW	0
#define ODP_CLS_DEFAULT_TC	0

typedef struct pmr_info_s {
	uint32_t	size;
	uint32_t	is_valid;
	odp_cls_pmr_term_t	type;
} pmr_info_t;

void set_pmr_info(void *rule);

int odp_setup_dist(pktio_entry_t *pktio_entry);

/** Classification Internal function **/

/**
Packet IO classifier init

This function does initialization of classifier object associated with pktio.
This function should be called during pktio initialization.
**/
int pktio_classifier_init(pktio_entry_t *pktio);

/**
Initialize shadow data base to store classfication rules
**/
void init_pktio_cls_rule_list(uint32_t index);

/**
@internal
match_pmr_cos

Match a PMR chain with a Packet and return matching CoS
This function gets called recursively to check the chained PMR Term value
with the packet.

**/
cos_t *match_pmr_cos(cos_t *cos, uint8_t *pkt_addr, pmr_t *pmr,
		     odp_packet_hdr_t *hdr);
/**
@internal
CoS associated with L3 QoS value

This function returns the CoS associated with L3 QoS value
**/
cos_t *match_qos_l3_cos(pmr_l3_cos_t *l3_cos, uint8_t *pkt_addr,
			odp_packet_hdr_t *hdr);

/**
@internal
CoS associated with L2 QoS value

This function returns the CoS associated with L2 QoS value
**/
cos_t *match_qos_l2_cos(pmr_l2_cos_t *l2_cos, uint8_t *pkt_addr,
			odp_packet_hdr_t *hdr);
/**
@internal
Flow Signature Calculation

This function calculates the Flow Signature for a packet based on
CoS and updates in Packet Meta Data
**/
int update_flow_signature(uint8_t *pkt_addr, cos_t *cos);

/**
@internal
Allocate a odp_pmr_set_t Handle
*/
odp_pmr_set_t alloc_pmr_set(pmr_t **pmr);

/**
@internal
Allocate a odp_pmr_t Handle
*/
odp_pmr_t alloc_pmr(pmr_t **pmr);

/**
@internal
Pointer to pmr_set_t Handle
This function checks for validity of pmr_set_t Handle
*/
pmr_set_t *get_pmr_set_entry(odp_pmr_set_t pmr_set_id);

/**
@internal
Pointer to pmr_set_t Handle
*/
pmr_set_t *get_pmr_set_entry_internal(odp_pmr_set_t pmr_set_id);

/**
@internal
Pointer to pmr_set_t Handle
This function checks for validity of pmr_set_t Handle
*/
pmr_t *get_pmr_entry(odp_pmr_t pmr_id);

/**
@internal
Pointer to pmr_set_t Handle
*/
pmr_t *get_pmr_entry_internal(odp_pmr_t pmr_id);

/**
@internal
Pointer to odp_cos_t Handle
*/
cos_t *get_cos_entry(odp_cos_t cos_id);

/**
@internal
Pointer to odp_cos_t Handle
This function checks for validity of odp_cos_t Handle
*/
cos_t *get_cos_entry_internal(odp_cos_t cos_id);

void odp_setup_extract_key(struct dpkg_profile_cfg *kg_cfg);

void convert_param_to_network_order(void *val, void *mask, uint32_t val_sz);

void odp_update_pmr_set_offset(pktio_entry_t *pktio, pmr_set_t *pmr_set);

void odp_update_pmr_offset(pktio_entry_t *pktio, pmr_t *pmr);

#ifdef __cplusplus
}
#endif
#endif
