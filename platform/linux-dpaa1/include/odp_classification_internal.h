/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
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

#include <configs/odp_config_platform.h>
#include <odp/api/spinlock.h>
#include <fm_port_ext.h>
#include <fm_pcd_ext.h>

/* L2 Priority Bits */
#define ODP_COS_L2_QOS_BITS		3
/* Max L2 QoS value */
#define ODP_COS_MAX_L2_QOS		(1 << ODP_COS_L2_QOS_BITS)
/* L2 DSCP Bits */
#define ODP_COS_L3_QOS_BITS		6
/* Max L3 QoS Value */
#define ODP_COS_MAX_L3_QOS		(1 << ODP_COS_L3_QOS_BITS)

#define FMC_SCHEMES_NUM 32
#define FMAN_COUNT 2
#define ODP_PMR_MAX_FIELDS (ODP_PMR_INNER_HDR_OFF + 1)
#define MAX_KEY_LEN 16
#define CCTREE_MAX_GROUPS 16
#define NUM_PROTOS 6
#define MAX_SET_KEY_LEN 56

enum action_type {
	ACTION_NONE,
	ACTION_ENQUEUE,
	ACTION_NEXT_CC,
};

enum qos_type {
	qos_VPRI,
	qos_DSCP
};

enum priority {
	default_pri = 0,
	l3_qos_pri,
	vlan_l2_qos_pri,
	eth_pri,
	vlan_pri,
	ipv4_pri,
	ipv6_pri,
	esp_pri,
	tcp_pri,
	udp_pri,
};

struct cos_entry {
	odp_spinlock_t lock;
	char name[ODP_COS_NAME_LEN];
	int taken;
	odp_cos_t cos_id;
	odp_pktio_t src_pktio; /**< pktio the packets come from */
	odp_queue_t queue;
	struct list_head src_filter_list; /**< packets filtered by pmrs in this
					       list, go to current cos */
	struct list_head dst_filter_list; /**< packets that come from cos are
					       filtered by pmrs in this list */
	struct list_head src_match_set_list;  /**< packets filtered by pmr sets
						in this list, go to current
						cos */
	struct list_head def_cos_list; /**< list of pktios that have this
						cos configured as default cos*/
	struct list_head err_cos_list; /**< list of pktios that have this
						cos configured as error cos*/
	bool is_default;/**< mark if this is a default cos */
	bool is_error; /**< mark if this is an error cos */
};

typedef union {
	struct cos_entry s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct cos_entry))];
} cos_entry_t;

struct priv_info {
	uint64_t proto;
	t_Handle cc_root_handle;  /**< handle to the scheme's root ccnode */
	t_Handle cc_last_handle;  /**< handle to the last ccnode in a scheme */
	t_FmPcdKgSchemeParams params;
	uint32_t queue_count;
	bool is_default;  /**< mark if this is a default scheme */
	uint8_t prio;
	int l2_root_id, l3_root_id;  /**< root id for l2 and l3 priority schemes */
	int qos_key_idx; /* last key index of the L2/3 class of service */
};

struct scheme_info {
	struct priv_info priv;
	t_Handle handle; /**< handle to the scheme */
	struct list_head scheme_node;
	uint8_t id;
	int taken;
};

struct pmr_entry {
	t_Handle ccnode_handle;
	t_Handle next_cc;/**< pmr entry action will point to another pmr that has
			  next_cc ccnode configured*/
	t_Handle miss_cc;/**< miss action ccnode of the current pmr ccnode */
	odp_spinlock_t lock;
	enum action_type next_act;
	odp_pktio_t pktio_in;
	odp_cos_t dst_cos, src_cos;
	int taken;
	odp_pmr_t pmr_id;
	odp_cls_pmr_term_t field;
	int key_index;
	uint8_t key[MAX_KEY_LEN];
	uint8_t mask[MAX_KEY_LEN];
	uint8_t key_size;
	struct list_head pmr_node;/**< pmr node from pmr_list for a pktio */
	struct list_head pmr_src_node;/**< pmr node from src_filter_list for a
				       cos */
	struct list_head pmr_dst_node;/**< pmr node from dst_filter_list for a
				       cos */
	int root_id;
	bool cascade;
};

typedef union {
	struct pmr_entry s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pmr_entry))];
} pmr_entry_t;


struct pmr_set_entry {
	t_Handle ccnode_handle;
	t_Handle miss_cc;/**< miss action ccnode of the current pmr ccnode */
	t_Handle next_cc;
	odp_spinlock_t lock;
	odp_pktio_t pktio_in;
	odp_cos_t dst_cos;
	int taken;
	odp_pmr_set_t pmr_set_id;
	uint8_t key[MAX_SET_KEY_LEN];
	uint8_t mask[MAX_SET_KEY_LEN];
	odp_cls_pmr_term_t pmr_set_fields[ODP_PMR_MAX_FIELDS];
	t_FmPcdCcNodeParams	cc_param;
	uint64_t field_mask, proto_mask;
	struct list_head pmr_set_node;
	struct list_head pmr_set_src_node;/**< pmr node from src_match_set_list
					       for a cos */
	uint8_t key_size;
	int key_index;
	uint8_t num_fields;
	int root_id;
};

typedef union {
	struct pmr_set_entry s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pmr_set_entry))];
} pmr_set_entry_t;

#define QTAG_LEN 4

#define GET_PORT_TYPE(port) \
		((port->mac_type == fman_mac_1g) ? \
		 e_FM_PORT_TYPE_RX : (port->mac_type == fman_mac_10g) ? \
		 e_FM_PORT_TYPE_RX_10G : e_FM_PORT_TYPE_OH_OFFLINE_PARSING)

#define SCHEME_PROTO_MATCH(prot, entry_prot) \
	((prot == HEADER_TYPE_IP) && \
	 ((entry_prot & (1 << HEADER_TYPE_IPv4)) == entry_prot || \
	  (entry_prot & (1 << HEADER_TYPE_IPv6)) == entry_prot))

#ifdef __cplusplus
}
#endif



#endif
