/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/packet_io.h>
#include <odp/api/packet.h>
#include <odp_internal.h>
#include <odp/api/spinlock.h>
#include <odp/api/shared_memory.h>
#include <odp/api/hints.h>
#include <odp_config_internal.h>
#include <odp/api/thread.h>
#include <odp/api/system_info.h>
#include <odp/api/classification.h>

#include <odp_queue_internal.h>
#include <odp_pool_internal.h>
#include <odp_schedule_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp_classification_internal.h>
#include <odp_debug_internal.h>

#include <configs/odp_config_platform.h>
#include <usdpaa/fsl_usd.h>
#include <usdpaa/of.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/usdpaa_netcfg.h>
#include <usdpaa/dma_mem.h>

#include <string.h>
#include <assert.h>

typedef struct cos_table_t {
	cos_entry_t  cos[ODP_COS_MAX_ENTRY];
	t_Handle fman_handle[FMAN_COUNT];
	t_Handle pcd_handle[FMAN_COUNT];
	uint8_t rel_scheme_id[FMAN_COUNT][FMC_SCHEMES_NUM];
	odp_spinlock_t lock;
} cos_table_t;

typedef struct pmr_pool_t {
	pmr_entry_t pmr[ODP_PMR_MAX_ENTRY];
	pmr_set_entry_t pmr_set[ODP_PMRSET_MAX_ENTRY];
	odp_spinlock_t lock;
} pmr_pool_t;

static pmr_pool_t *pmr_pool;
static cos_table_t *cos_tbl;

/* FMAN mac indexes mappings */
uint8_t mac_idx[] = {-1, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1};

/* l2 and l3 cos values */
static odp_cos_t l2_cos[ODP_COS_MAX_L2_QOS];
static odp_cos_t l3_cos[ODP_COS_MAX_L3_QOS];

struct odp_field_info {
	t_FmPcdExtractEntry extract[2];
	uint8_t offset;
	bool share_field; /* this field can be extracted for both ipv4 and ipv6
			  (e.g protocol) */
	uint8_t size;
	int header_type;
	enum priority prio;
	t_FmPcdCcNodeParams	cc_param;
};

static struct odp_field_info odp_fields[ODP_PMR_MAX_FIELDS];
static int fm_modify_cc_miss_act(t_Handle cc_src_handle, t_Handle cc_dst_handle,
				 int next_act, uint32_t fqid);

static enum qman_cb_dqrr_result dqrr_cb_cos(struct qman_fq *fq,
					 const struct qm_dqrr_entry *dqrr,
					 uint64_t *user_context);
static inline void odp_init_fields(void)
{
	memset(odp_fields, 0, sizeof(odp_fields));

	odp_fields[ODP_PMR_LEN].header_type = HEADER_TYPE_IP;
	odp_fields[ODP_PMR_LEN].prio = ipv4_pri;


	odp_fields[ODP_PMR_LEN].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_LEN].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_IPv4;
	odp_fields[ODP_PMR_LEN].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_LEN].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FROM_HDR;
	odp_fields[ODP_PMR_LEN].cc_param.extractCcParams.
			      extractByHdr.extractByHdrType.fromHdr.size = 2;
	odp_fields[ODP_PMR_LEN].cc_param.extractCcParams.
			      extractByHdr.extractByHdrType.fromHdr.offset = 2;

	odp_fields[ODP_PMR_LEN].extract[0].extractByHdr.hdr = HEADER_TYPE_IPv4;
	odp_fields[ODP_PMR_LEN].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_LEN].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_LEN].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_LEN].extract[0].extractByHdr.
	       extractByHdrType.fullField.ipv4 = NET_HEADER_FIELD_IPv4_TOTAL_LEN;

	odp_fields[ODP_PMR_LEN].extract[1].extractByHdr.hdr = HEADER_TYPE_IPv6;
	odp_fields[ODP_PMR_LEN].extract[1].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_LEN].extract[1].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_LEN].extract[1].extractByHdr.type =
						      e_FM_PCD_EXTRACT_FROM_HDR;
	odp_fields[ODP_PMR_LEN].extract[1].extractByHdr.
					    extractByHdrType.fromHdr.offset = 4;
	odp_fields[ODP_PMR_LEN].share_field = true;
	odp_fields[ODP_PMR_LEN].size = sizeof(uint16_t);


	odp_fields[ODP_PMR_ETHTYPE_0].header_type = HEADER_TYPE_ETH;
	odp_fields[ODP_PMR_ETHTYPE_0].prio = eth_pri;

	odp_fields[ODP_PMR_ETHTYPE_0].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_ETHTYPE_0].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_ETH;
	odp_fields[ODP_PMR_ETHTYPE_0].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_ETHTYPE_0].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_ETHTYPE_0].cc_param.extractCcParams.
				extractByHdr.extractByHdrType.
				      fullField.eth = NET_HEADER_FIELD_ETH_TYPE;

	odp_fields[ODP_PMR_ETHTYPE_0].extract[0].extractByHdr.hdr =
								HEADER_TYPE_ETH;
	odp_fields[ODP_PMR_ETHTYPE_0].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_ETHTYPE_0].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_ETHTYPE_0].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_ETHTYPE_0].extract[0].extractByHdr.
		     extractByHdrType.fullField.eth = NET_HEADER_FIELD_ETH_TYPE;
	odp_fields[ODP_PMR_ETHTYPE_0].size = sizeof(uint16_t);

	odp_fields[ODP_PMR_ETHTYPE_X].header_type = HEADER_TYPE_ETH;
	odp_fields[ODP_PMR_ETHTYPE_X].prio = eth_pri;

	odp_fields[ODP_PMR_ETHTYPE_X].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_ETHTYPE_X].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_ETH;
	odp_fields[ODP_PMR_ETHTYPE_X].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_ETHTYPE_X].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_ETHTYPE_X].cc_param.extractCcParams.
			      extractByHdr.extractByHdrType.
				      fullField.eth = NET_HEADER_FIELD_ETH_TYPE;

	odp_fields[ODP_PMR_ETHTYPE_X].extract[0].extractByHdr.hdr =
								HEADER_TYPE_ETH;
	odp_fields[ODP_PMR_ETHTYPE_X].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_ETHTYPE_X].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_ETHTYPE_X].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_ETHTYPE_X].extract[0].extractByHdr.
				    extractByHdrType.fullField.eth =
						      NET_HEADER_FIELD_ETH_TYPE;
	odp_fields[ODP_PMR_ETHTYPE_X].size = sizeof(uint16_t);


	odp_fields[ODP_PMR_VLAN_ID_0].header_type = HEADER_TYPE_VLAN;
	odp_fields[ODP_PMR_VLAN_ID_0].prio = vlan_pri;
	odp_fields[ODP_PMR_VLAN_ID_0].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_VLAN_ID_0].cc_param.extractCcParams.
					    extractByHdr.hdr = HEADER_TYPE_VLAN;
	odp_fields[ODP_PMR_VLAN_ID_0].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_VLAN_ID_0].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_VLAN_ID_0].cc_param.extractCcParams.
				     extractByHdr.extractByHdrType.
				     fullField.vlan = NET_HEADER_FIELD_VLAN_TCI;

	odp_fields[ODP_PMR_VLAN_ID_0].extract[0].extractByHdr.hdr =
							       HEADER_TYPE_VLAN;
	odp_fields[ODP_PMR_VLAN_ID_0].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_VLAN_ID_0].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_VLAN_ID_0].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_VLAN_ID_0].extract[0].extractByHdr.
		    extractByHdrType.fullField.vlan = NET_HEADER_FIELD_VLAN_TCI;
	odp_fields[ODP_PMR_VLAN_ID_0].size = sizeof(uint16_t);

	odp_fields[ODP_PMR_VLAN_ID_X].header_type = HEADER_TYPE_VLAN;
	odp_fields[ODP_PMR_VLAN_ID_X].prio = vlan_pri;
	odp_fields[ODP_PMR_VLAN_ID_X].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_VLAN_ID_X].cc_param.extractCcParams.
					    extractByHdr.hdr = HEADER_TYPE_VLAN;
	odp_fields[ODP_PMR_VLAN_ID_X].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_LAST;
	odp_fields[ODP_PMR_VLAN_ID_X].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_VLAN_ID_X].cc_param.extractCcParams.
				     extractByHdr.extractByHdrType.
				     fullField.vlan = NET_HEADER_FIELD_VLAN_TCI;

	odp_fields[ODP_PMR_VLAN_ID_X].extract[0].extractByHdr.hdr =
							       HEADER_TYPE_VLAN;
	odp_fields[ODP_PMR_VLAN_ID_X].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_VLAN_ID_X].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_VLAN_ID_X].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_VLAN_ID_X].extract[0].extractByHdr.
		    extractByHdrType.fullField.vlan = NET_HEADER_FIELD_VLAN_TCI;
	odp_fields[ODP_PMR_VLAN_ID_X].size = sizeof(uint16_t);

	odp_fields[ODP_PMR_DMAC].header_type = HEADER_TYPE_ETH;
	odp_fields[ODP_PMR_DMAC].prio = eth_pri;

	odp_fields[ODP_PMR_DMAC].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_DMAC].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_ETH;
	odp_fields[ODP_PMR_DMAC].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_DMAC].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_DMAC].cc_param.extractCcParams.
			      extractByHdr.extractByHdrType.
					fullField.eth = NET_HEADER_FIELD_ETH_DA;

	odp_fields[ODP_PMR_DMAC].extract[0].extractByHdr.hdr =
								HEADER_TYPE_ETH;
	odp_fields[ODP_PMR_DMAC].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_DMAC].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_DMAC].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_DMAC].extract[0].extractByHdr.
		       extractByHdrType.fullField.eth = NET_HEADER_FIELD_ETH_DA;
	odp_fields[ODP_PMR_DMAC].size = sizeof(uint64_t) - sizeof(uint16_t);

	odp_fields[ODP_PMR_IPPROTO].header_type = HEADER_TYPE_IP;
	odp_fields[ODP_PMR_IPPROTO].prio = ipv4_pri;

	odp_fields[ODP_PMR_IPPROTO].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_IPPROTO].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_IP;
	odp_fields[ODP_PMR_IPPROTO].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_LAST;
	odp_fields[ODP_PMR_IPPROTO].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_IPPROTO].cc_param.extractCcParams.
			      extractByHdr.extractByHdrType.
				       fullField.ip = NET_HEADER_FIELD_IP_PROTO;

	odp_fields[ODP_PMR_IPPROTO].extract[0].extractByHdr.hdr =
							       HEADER_TYPE_IPv4;
	odp_fields[ODP_PMR_IPPROTO].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_IPPROTO].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_IPPROTO].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_IPPROTO].extract[0].extractByHdr.
		extractByHdrType.fullField.ipv4 = NET_HEADER_FIELD_IPv4_PROTO;

	odp_fields[ODP_PMR_IPPROTO].extract[1].extractByHdr.hdr =
							       HEADER_TYPE_IPv6;
	odp_fields[ODP_PMR_IPPROTO].extract[1].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_IPPROTO].extract[1].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_IPPROTO].extract[1].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_IPPROTO].extract[1].extractByHdr.
	       extractByHdrType.fullField.ipv6 = NET_HEADER_FIELD_IPv6_NEXT_HDR;
	odp_fields[ODP_PMR_IPPROTO].share_field = true;
	odp_fields[ODP_PMR_IPPROTO].size = sizeof(uint8_t);

	odp_fields[ODP_PMR_SIP_ADDR].header_type = HEADER_TYPE_IPv4;
	odp_fields[ODP_PMR_SIP_ADDR].prio = ipv4_pri;

	odp_fields[ODP_PMR_SIP_ADDR].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_SIP_ADDR].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_IPv4;
	odp_fields[ODP_PMR_SIP_ADDR].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_SIP_ADDR].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_SIP_ADDR].cc_param.extractCcParams.
			     extractByHdr.extractByHdrType.
				  fullField.ipv4 = NET_HEADER_FIELD_IPv4_SRC_IP;

	odp_fields[ODP_PMR_SIP_ADDR].extract[0].extractByHdr.hdr =
							       HEADER_TYPE_IPv4;
	odp_fields[ODP_PMR_SIP_ADDR].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_SIP_ADDR].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_SIP_ADDR].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_SIP_ADDR].extract[0].extractByHdr.
		 extractByHdrType.fullField.ipv4 = NET_HEADER_FIELD_IPv4_SRC_IP;
	odp_fields[ODP_PMR_SIP_ADDR].size = sizeof(uint32_t);

	odp_fields[ODP_PMR_DIP_ADDR].header_type = HEADER_TYPE_IPv4;
	odp_fields[ODP_PMR_DIP_ADDR].prio = ipv4_pri;

	odp_fields[ODP_PMR_DIP_ADDR].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_DIP_ADDR].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_IPv4;
	odp_fields[ODP_PMR_DIP_ADDR].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_DIP_ADDR].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_DIP_ADDR].cc_param.extractCcParams.
			     extractByHdr.extractByHdrType.
				  fullField.ipv4 = NET_HEADER_FIELD_IPv4_DST_IP;

	odp_fields[ODP_PMR_DIP_ADDR].extract[0].extractByHdr.hdr =
							       HEADER_TYPE_IPv4;
	odp_fields[ODP_PMR_DIP_ADDR].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_DIP_ADDR].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_DIP_ADDR].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_DIP_ADDR].extract[0].extractByHdr.
		 extractByHdrType.fullField.ipv4 = NET_HEADER_FIELD_IPv4_DST_IP;
	odp_fields[ODP_PMR_DIP_ADDR].size = sizeof(uint32_t);

	odp_fields[ODP_PMR_SIP6_ADDR].header_type = HEADER_TYPE_IPv6;
	odp_fields[ODP_PMR_SIP6_ADDR].prio = ipv6_pri;

	odp_fields[ODP_PMR_SIP6_ADDR].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_SIP6_ADDR].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_IPv6;
	odp_fields[ODP_PMR_SIP6_ADDR].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_SIP6_ADDR].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_SIP6_ADDR].cc_param.extractCcParams.
			     extractByHdr.extractByHdrType.
				  fullField.ipv6 = NET_HEADER_FIELD_IPv6_SRC_IP;

	odp_fields[ODP_PMR_SIP6_ADDR].extract[0].extractByHdr.hdr =
							       HEADER_TYPE_IPv6;
	odp_fields[ODP_PMR_SIP6_ADDR].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_SIP6_ADDR].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_SIP6_ADDR].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_SIP6_ADDR].extract[0].extractByHdr.
		 extractByHdrType.fullField.ipv6 = NET_HEADER_FIELD_IPv6_SRC_IP;
	odp_fields[ODP_PMR_SIP6_ADDR].size = sizeof(uint64_t) +
					      sizeof(uint64_t);

	odp_fields[ODP_PMR_DIP6_ADDR].header_type = HEADER_TYPE_IPv6;
	odp_fields[ODP_PMR_DIP6_ADDR].prio = ipv6_pri;

	odp_fields[ODP_PMR_DIP6_ADDR].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_DIP6_ADDR].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_IPv6;
	odp_fields[ODP_PMR_DIP6_ADDR].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_DIP6_ADDR].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_DIP6_ADDR].cc_param.extractCcParams.
			     extractByHdr.extractByHdrType.
				  fullField.ipv6 = NET_HEADER_FIELD_IPv6_DST_IP;

	odp_fields[ODP_PMR_DIP6_ADDR].extract[0].extractByHdr.hdr =
							       HEADER_TYPE_IPv6;
	odp_fields[ODP_PMR_DIP6_ADDR].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_DIP6_ADDR].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_DIP6_ADDR].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_DIP6_ADDR].extract[0].extractByHdr.
		 extractByHdrType.fullField.ipv6 = NET_HEADER_FIELD_IPv6_DST_IP;
	odp_fields[ODP_PMR_DIP6_ADDR].size = sizeof(uint64_t) +
					      sizeof(uint64_t);

	odp_fields[ODP_PMR_UDP_DPORT].header_type = HEADER_TYPE_UDP;
	odp_fields[ODP_PMR_UDP_DPORT].prio = udp_pri;

	odp_fields[ODP_PMR_UDP_DPORT].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_UDP_DPORT].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_UDP;
	odp_fields[ODP_PMR_UDP_DPORT].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_UDP_DPORT].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_UDP_DPORT].cc_param.extractCcParams.
			     extractByHdr.extractByHdrType.
				  fullField.udp = NET_HEADER_FIELD_UDP_PORT_DST;

	odp_fields[ODP_PMR_UDP_DPORT].extract[0].extractByHdr.hdr =
							       HEADER_TYPE_UDP;
	odp_fields[ODP_PMR_UDP_DPORT].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_UDP_DPORT].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_UDP_DPORT].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_UDP_DPORT].extract[0].extractByHdr.
		 extractByHdrType.fullField.udp = NET_HEADER_FIELD_UDP_PORT_DST;
	odp_fields[ODP_PMR_UDP_DPORT].size = sizeof(uint16_t);

	odp_fields[ODP_PMR_UDP_SPORT].header_type = HEADER_TYPE_UDP;
	odp_fields[ODP_PMR_UDP_SPORT].prio = udp_pri;

	odp_fields[ODP_PMR_UDP_SPORT].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_UDP_SPORT].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_UDP;
	odp_fields[ODP_PMR_UDP_SPORT].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_UDP_SPORT].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_UDP_SPORT].cc_param.extractCcParams.
			     extractByHdr.extractByHdrType.
				  fullField.udp = NET_HEADER_FIELD_UDP_PORT_SRC;

	odp_fields[ODP_PMR_UDP_SPORT].extract[0].extractByHdr.hdr =
							       HEADER_TYPE_UDP;
	odp_fields[ODP_PMR_UDP_SPORT].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_UDP_SPORT].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_UDP_SPORT].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_UDP_SPORT].extract[0].extractByHdr.
		 extractByHdrType.fullField.udp = NET_HEADER_FIELD_UDP_PORT_SRC;
	odp_fields[ODP_PMR_UDP_SPORT].size = sizeof(uint16_t);

	odp_fields[ODP_PMR_TCP_DPORT].header_type = HEADER_TYPE_TCP;
	odp_fields[ODP_PMR_TCP_DPORT].prio = tcp_pri;

	odp_fields[ODP_PMR_TCP_DPORT].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_TCP_DPORT].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_TCP;
	odp_fields[ODP_PMR_TCP_DPORT].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_TCP_DPORT].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_TCP_DPORT].cc_param.extractCcParams.
			     extractByHdr.extractByHdrType.
				  fullField.tcp = NET_HEADER_FIELD_TCP_PORT_DST;

	odp_fields[ODP_PMR_TCP_DPORT].extract[0].extractByHdr.hdr =
							       HEADER_TYPE_TCP;
	odp_fields[ODP_PMR_TCP_DPORT].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_TCP_DPORT].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_TCP_DPORT].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_TCP_DPORT].extract[0].extractByHdr.
		 extractByHdrType.fullField.tcp = NET_HEADER_FIELD_TCP_PORT_DST;
	odp_fields[ODP_PMR_TCP_DPORT].size = sizeof(uint16_t);

	odp_fields[ODP_PMR_TCP_SPORT].header_type = HEADER_TYPE_TCP;
	odp_fields[ODP_PMR_TCP_SPORT].prio = tcp_pri;

	odp_fields[ODP_PMR_TCP_SPORT].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_TCP_SPORT].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_TCP;
	odp_fields[ODP_PMR_TCP_SPORT].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_TCP_SPORT].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_TCP_SPORT].cc_param.extractCcParams.
			     extractByHdr.extractByHdrType.
				  fullField.tcp = NET_HEADER_FIELD_TCP_PORT_SRC;

	odp_fields[ODP_PMR_TCP_SPORT].extract[0].extractByHdr.hdr =
							       HEADER_TYPE_TCP;
	odp_fields[ODP_PMR_TCP_SPORT].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_TCP_SPORT].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_TCP_SPORT].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_TCP_SPORT].extract[0].extractByHdr.
		 extractByHdrType.fullField.tcp = NET_HEADER_FIELD_TCP_PORT_SRC;
	odp_fields[ODP_PMR_TCP_SPORT].size = sizeof(uint16_t);

	odp_fields[ODP_PMR_IPSEC_SPI].header_type = HEADER_TYPE_IPSEC_ESP;
	odp_fields[ODP_PMR_IPSEC_SPI].prio = esp_pri;

	odp_fields[ODP_PMR_IPSEC_SPI].cc_param.extractCcParams.type =
							e_FM_PCD_EXTRACT_BY_HDR;
	odp_fields[ODP_PMR_IPSEC_SPI].cc_param.extractCcParams.
			      extractByHdr.hdr = HEADER_TYPE_IPSEC_ESP;
	odp_fields[ODP_PMR_IPSEC_SPI].cc_param.extractCcParams.
			      extractByHdr.hdrIndex = e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_IPSEC_SPI].cc_param.extractCcParams.extractByHdr.
			      type = e_FM_PCD_EXTRACT_FROM_HDR;
	odp_fields[ODP_PMR_IPSEC_SPI].cc_param.extractCcParams.
			      extractByHdr.extractByHdrType.fromHdr.size = 4;
	odp_fields[ODP_PMR_IPSEC_SPI].cc_param.extractCcParams.
			      extractByHdr.extractByHdrType.fromHdr.offset = 0;

	odp_fields[ODP_PMR_IPSEC_SPI].extract[0].extractByHdr.hdr =
							  HEADER_TYPE_IPSEC_ESP;
	odp_fields[ODP_PMR_IPSEC_SPI].extract[0].extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	odp_fields[ODP_PMR_IPSEC_SPI].extract[0].extractByHdr.
						   ignoreProtocolValidation = 0;
	odp_fields[ODP_PMR_IPSEC_SPI].extract[0].extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	odp_fields[ODP_PMR_IPSEC_SPI].extract[0].extractByHdr.
	     extractByHdrType.fullField.ipsecEsp =
						 NET_HEADER_FIELD_IPSEC_ESP_SPI;
	odp_fields[ODP_PMR_IPSEC_SPI].size = sizeof(uint32_t);
	/* TODO VNI and INNER_HDR_OFF fields */
}

static inline int set_fm_port_handle(netcfg_port_info  *port_info)
{
	t_FmPortParams	fm_port_params;
	int ret;
	int idx;

	if (!port_info->port_handle) {
		memset(&fm_port_params, 0, sizeof(fm_port_params));
		fm_port_params.h_Fm = port_info->fman_handle;
		fm_port_params.portType =
				       GET_PORT_TYPE(port_info->p_cfg->fman_if);
		if (fm_port_params.portType !=
		    e_FM_PORT_TYPE_OH_OFFLINE_PARSING)
			idx = mac_idx[port_info->p_cfg->fman_if->mac_idx];
		else
			idx = port_info->p_cfg->fman_if->mac_idx;
		fm_port_params.portId = idx;
		port_info->port_handle = FM_PORT_Open(&fm_port_params);
		if (!port_info->port_handle) {
			ODP_ERR("Could not open FMAN port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			ret = -1;
			return ret;
		}
	}

	return 0;
}

static inline int  set_fm_port_protos(netcfg_port_info	*port_info)
{
	int ret;

	if (!port_info->net_env_set) {
		memset(&port_info->dist_units, 0,
		       sizeof(port_info->dist_units));
		port_info->dist_units.numOfDistinctionUnits = NUM_PROTOS;
		port_info->dist_units.units[0].hdrs[0].hdr = HEADER_TYPE_ETH;
		port_info->dist_units.units[1].hdrs[0].hdr = HEADER_TYPE_VLAN;
		port_info->dist_units.units[2].hdrs[0].hdr = HEADER_TYPE_IPv4;
		port_info->dist_units.units[3].hdrs[0].hdr = HEADER_TYPE_IPv6;
		port_info->dist_units.units[4].hdrs[0].hdr = HEADER_TYPE_TCP;
		port_info->dist_units.units[5].hdrs[0].hdr = HEADER_TYPE_UDP;
		port_info->net_env_set = FM_PCD_NetEnvCharacteristicsSet(
						port_info->pcd_handle,
						&port_info->dist_units);
		if (!port_info->net_env_set) {
			ODP_ERR("Could not set distinction units on port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			ret = -1;
			return ret;
		}

		port_info->pcd_param.h_NetEnv = port_info->net_env_set;
	}

	return 0;
}

static inline int set_fm_port_cctree(netcfg_port_info *port_info)
{
	t_FmPcdCcTreeParams	cc_tree;
	int i, ret;

	memset(&cc_tree, 0, sizeof(cc_tree));
	cc_tree.numOfGrps = CCTREE_MAX_GROUPS - 1;
	cc_tree.h_NetEnv = port_info->net_env_set;
	for (i = 0; i < CCTREE_MAX_GROUPS; i++) {
		cc_tree.ccGrpParams[i].numOfDistinctionUnits = 0;
		cc_tree.ccGrpParams[i].nextEnginePerEntriesInGrp[0].
						     nextEngine = e_FM_PCD_DONE;
		cc_tree.ccGrpParams[i].nextEnginePerEntriesInGrp[0].params.
				     enqueueParams.action = e_FM_PCD_DROP_FRAME;
		port_info->cc_root[i] = 0;
	}

	port_info->tree_handle = FM_PCD_CcRootBuild(port_info->pcd_handle,
						    &cc_tree);
	if (!port_info->tree_handle) {
		ODP_ERR("Could not add tree to port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		ret = -1;
		return ret;
	}

	return 0;
}

static inline int update_cctree(netcfg_port_info *port_info,
				t_Handle ccnode_handle, int grp_id,
				int action)
{
	t_FmPcdCcNextEngineParams next_engine;
	int ret;


	memset(&next_engine, 0, sizeof(next_engine));
	if (action == e_FM_PCD_CC) {
		next_engine.nextEngine = action;
		next_engine.params.ccParams.h_CcNode = ccnode_handle;
	} else if (action == e_FM_PCD_DONE) {
		next_engine.nextEngine = action;
		next_engine.params.enqueueParams.action = e_FM_PCD_DROP_FRAME;
	}
	ret = FM_PCD_CcRootModifyNextEngine(port_info->tree_handle, grp_id, 0,
					    &next_engine);
	if (ret) {
		ODP_ERR("Could not modify cctree for port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	return 0;
}

static inline void copy_keys_bytes(uint8_t *arr, uint8_t *val, uint32_t size)
{
#if ODP_BYTE_ORDER == ODP_LITTLE_ENDIAN
	size_t i;

	for (i = 0; i < size; i++)
		arr[i] = val[size - i - 1];
#else
	memcpy(arr, val, size);
#endif
}

static int fm_apply_pcd(netcfg_port_info  *port_info,
			struct scheme_info *scheme,
			uint8_t pcd_support, t_FmPortPcdCcParams *cc)
{
	int ret = 0, i = 0;
	struct scheme_info *scheme_p;

	if (port_info->config_pcd) {
		ret = FM_PORT_DeletePCD(port_info->port_handle);
		if (ret) {
			ODP_ERR("Could not delete pcd from port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			return ret;
		}

	}

	if (!port_info->config_pcd)
		port_info->config_pcd = true;

	if (scheme) {
		/* before applying the PCD, add the scheme in the scheme list */
		if (!scheme->handle) {
			port_info->scheme_count++;
			/* add scheme to the scheme list */
			list_add_tail(&scheme->scheme_node,
				      &port_info->scheme_list);
		}
		scheme->handle = FM_PCD_KgSchemeSet(port_info->pcd_handle,
				 &scheme->priv.params);
		if (!scheme->handle) {
			ODP_ERR("Could not set scheme for port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			return ret;
		}

		port_info->kg_param.numOfSchemes = port_info->scheme_count;
		list_for_each_entry(scheme_p, &port_info->scheme_list,
				    scheme_node) {
			port_info->kg_param.h_Schemes[i++] = scheme_p->handle;
		}

		port_info->pcd_param.p_KgParams = &port_info->kg_param;
	} else
		port_info->pcd_param.p_KgParams = NULL;

	port_info->prs_param.parsingOffset = 0;
	port_info->prs_param.prsResultPrivateInfo = 0;
	port_info->prs_param.firstPrsHdr = HEADER_TYPE_ETH;
	port_info->pcd_param.pcdSupport = pcd_support;
	port_info->pcd_param.p_PrsParams = &port_info->prs_param;
	port_info->pcd_param.p_CcParams = cc;

	ret = FM_PORT_Disable(port_info->port_handle);
	if (ret != E_OK) {
		ODP_ERR("Could not disable port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}


	ret = FM_PORT_SetPCD(port_info->port_handle, &port_info->pcd_param);
	if (ret != E_OK) {
		ODP_ERR("Could not set PCD on port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	ret = FM_PORT_Enable(port_info->port_handle);
	if (ret != E_OK) {
		ODP_ERR("Could not enable port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	return 0;
}

static struct scheme_info *get_scheme_by_root(netcfg_port_info	*port_info,
					      t_Handle root_cc)
{
	struct scheme_info *scheme_p = NULL;

	list_for_each_entry(scheme_p, &port_info->scheme_list, scheme_node)
		if (scheme_p->priv.cc_root_handle == root_cc)
			return scheme_p;

	return NULL;
}

static int reorder_schemes(netcfg_port_info  *port_info)
{
	int i = 0, j, count;
	struct scheme_info *scheme_i, *scheme_j, scheme_tmp;
	bool reorder = false;
	void *schemes[FMC_SCHEMES_NUM];
	t_Handle cc_root_l2 = NULL, cc_root_l3 = NULL;

	memset(&scheme_tmp, 0, sizeof(scheme_tmp));
	list_for_each_entry(scheme_i, &port_info->scheme_list, scheme_node)
		schemes[i++] = scheme_i;

	count = i;
	if (port_info->l2_vpri)
		cc_root_l2 = port_info->l2_vpri->priv.cc_root_handle;
	if (port_info->l3_dscp)
		cc_root_l3 = port_info->l3_dscp->priv.cc_root_handle;

	/* reorder schemes based on relative scheme id */
	for (i = 0; i < count - 1; i++) {
		scheme_i = (struct scheme_info *)schemes[i];
		for (j = i + 1; j < count; j++) {
			scheme_j = (struct scheme_info *)schemes[j];
			if (scheme_i->id > scheme_j->id) {
				schemes[i] = scheme_j;
				schemes[j] = scheme_i;
			}
		}
	}

	/*
	 *  interchange scheme params and priority so that schemes with lower
	 * ids will have higher priorities
	 */
	for (i = 0; i < count - 1; i++) {
		scheme_i = (struct scheme_info *)schemes[i];
		for (j = i + 1; j < count; j++) {
			scheme_j = (struct scheme_info *)schemes[j];
			if (scheme_i->priv.prio < scheme_j->priv.prio) {
				scheme_tmp = *scheme_i;
				scheme_i->priv = scheme_j->priv;
				scheme_j->priv = scheme_tmp.priv;
				scheme_i->priv.params.id.h_Scheme =
							      scheme_i->handle;
				scheme_j->priv.params.id.h_Scheme =
							       scheme_j->handle;
				scheme_i->priv.params.modify = true;
				scheme_j->priv.params.modify = true;
				reorder = true;
			}
		}
	}

	if (reorder) {
		ODP_DBG("Schemes were reordered\n");
		/* set the new scheme pointers for l2 and l3 qos schemes */
		if (cc_root_l2)
			port_info->l2_vpri =
				      get_scheme_by_root(port_info, cc_root_l2);

		if (cc_root_l3)
			port_info->l3_dscp =
				      get_scheme_by_root(port_info, cc_root_l3);
		for (i = 0; i < count; i++) {
			scheme_i = (struct scheme_info *)schemes[i];
			assert(scheme_i->handle);
			/*
			 * if scheme is not configured to be modified or
			 * is the default scheme, continue
			 */
			if (!scheme_i->priv.params.modify)
				continue;

			scheme_i->handle = FM_PCD_KgSchemeSet(
							 port_info->pcd_handle,
							&scheme_i->priv.params);
			if (!scheme_i->handle) {
				ODP_ERR("Could not modify scheme on  port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				return -1;
			}
			scheme_i->priv.params.modify = false;
		}
	}

	return 0;
}

static int fm_init(int fman_id, t_Handle *fman_handle,
		   t_Handle *pcd_handle, uint8_t rel_id[][FMC_SCHEMES_NUM])
{
	t_Error err;
	t_FmPcdParams fmPcdParams = {0};

	*fman_handle = FM_Open(fman_id);
	if (!*fman_handle)
		return -1;

	fmPcdParams.h_Fm = *fman_handle;
	*pcd_handle = FM_PCD_Open(&fmPcdParams);
	if (!*pcd_handle)
		return -1;

	err = FM_PCD_Enable(*pcd_handle);
	if (err != E_OK)
		return err;

	memset(rel_id[fman_id], 0, FMC_SCHEMES_NUM);

	return 0;
}

static cos_entry_t *get_cos_entry_internal(odp_cos_t cos_id)
{
	return &(cos_tbl->cos[_odp_typeval(cos_id)]);
}

static pmr_set_entry_t *get_pmr_set_entry_internal(odp_pmr_set_t pmr_set_id)
{
	return &(pmr_pool->pmr_set[_odp_typeval(pmr_set_id)]);
}

static pmr_entry_t *get_pmr_entry_internal(odp_pmr_t pmr_id)
{
	return &(pmr_pool->pmr[_odp_typeval(pmr_id)]);
}

static cos_entry_t *get_cos_entry(odp_cos_t cos_id)
{
	if (_odp_typeval(cos_id) >= ODP_COS_MAX_ENTRY ||
	    cos_id == ODP_COS_INVALID)
		return NULL;

	return &(cos_tbl->cos[_odp_typeval(cos_id)]);
}

static pmr_entry_t *get_pmr_entry(odp_pmr_t pmr_id)
{
	if (_odp_typeval(pmr_id) >= ODP_PMR_MAX_ENTRY ||
	    pmr_id == ODP_PMR_INVAL)
		return NULL;


	return &(pmr_pool->pmr[_odp_typeval(pmr_id)]);
}


static pmr_set_entry_t *get_pmr_set_entry(odp_pmr_set_t pmr_set_id)
{
	if (_odp_typeval(pmr_set_id) >= ODP_PMRSET_MAX_ENTRY ||
		    pmr_set_id == ODP_PMR_SET_INVAL)
			return NULL;

	return &(pmr_pool->pmr_set[_odp_typeval(pmr_set_id)]);
}

/* set input pktio for the given queue */
static inline void odp_queue_set_pktin(odp_queue_t queue, odp_pktio_t pktio)
{
	queue_entry_t *queue_entry;

	if (queue == ODP_QUEUE_INVALID)
		return;

	queue_entry = queue_to_qentry(queue);
	queue_entry->s.pktin = pktio;
}

int odp_classification_init_global(void)
{
	uint32_t cos_id, pmr_id, pmr_set_id;
	int i, fman_id, ret;
	cos_entry_t *cos_entry;
	pmr_entry_t *pmr_entry;
	pmr_set_entry_t *pmr_set_entry;
	struct fm_eth_port_cfg *port_cfg;
	netcfg_port_info  *port_info;
	odp_shm_t shm;

	odp_init_fields();

	shm = odp_shm_reserve("odp_cos_entries", sizeof(cos_table_t),
			      sizeof(cos_entry_t), ODP_SHM_SW_ONLY);
	cos_tbl = odp_shm_addr(shm);
	if (cos_tbl == NULL)
		return -1;

	memset(cos_tbl, 0, sizeof(cos_table_t));
	for (cos_id = 0; cos_id < ODP_COS_MAX_ENTRY; cos_id++) {
		cos_entry = get_cos_entry_internal(_odp_cast_scalar(odp_cos_t,
								    cos_id));
		odp_spinlock_init(&cos_entry->s.lock);
		cos_entry->s.cos_id = _odp_cast_scalar(odp_cos_t, cos_id);
		cos_entry->s.src_pktio = ODP_PKTIO_INVALID;
		INIT_LIST_HEAD(&cos_entry->s.src_filter_list);
		INIT_LIST_HEAD(&cos_entry->s.dst_filter_list);
		INIT_LIST_HEAD(&cos_entry->s.src_match_set_list);
		INIT_LIST_HEAD(&cos_entry->s.def_cos_list);
		INIT_LIST_HEAD(&cos_entry->s.err_cos_list);
	}

	odp_spinlock_init(&cos_tbl->lock);

	for (i = 0; i < netcfg->num_ethports; i++) {
		port_cfg = &netcfg->port_cfg[i];
		if (port_cfg->fman_if->mac_type == fman_mac_less)
			continue;

		fman_id = port_cfg->fman_if->fman_idx;
		if (!cos_tbl->fman_handle[fman_id]) {
			ret = fm_init(fman_id, &cos_tbl->fman_handle[fman_id],
				      &cos_tbl->pcd_handle[fman_id],
				      &cos_tbl->rel_scheme_id[fman_id]);
			if (ret) {
				ODP_ERR("Could not initialize fman pcd (%d)\n",
					ret);
				return -1;
			}
		}
		port_info = pktio_get_port_info(port_cfg->fman_if);
		INIT_LIST_HEAD(&port_info->scheme_list);
		INIT_LIST_HEAD(&port_info->pmr_list);
		INIT_LIST_HEAD(&port_info->pmr_set_list);
		odp_spinlock_init(&port_info->lock);
		port_info->fman_handle = cos_tbl->fman_handle[fman_id];
		port_info->pcd_handle = cos_tbl->pcd_handle[fman_id];

		ret = set_fm_port_handle(port_info);
		if (ret)
			return ret;

		ret = set_fm_port_protos(port_info);
		if (ret)
			return ret;

		ret = set_fm_port_cctree(port_info);
		if (ret)
			return ret;

		memset(port_info->scheme, 0, sizeof(port_info->scheme));
		/* enable FMAN parser only */
		ret = fm_apply_pcd(port_info, NULL,
				   e_FM_PORT_PCD_SUPPORT_PRS_ONLY, NULL);
		if (ret)
			return ret;
	}

	shm = odp_shm_reserve("odp_pmr", sizeof(pmr_pool_t),
			      sizeof(pmr_pool_t), ODP_SHM_SW_ONLY);
	pmr_pool = odp_shm_addr(shm);
	if (pmr_pool == NULL)
		return -1;

	memset(pmr_pool, 0, sizeof(pmr_pool_t));
	odp_spinlock_init(&pmr_pool->lock);

	for (pmr_id = 0; pmr_id < ODP_PMR_MAX_ENTRY; pmr_id++) {
		pmr_entry = get_pmr_entry_internal(
					   _odp_cast_scalar(odp_pmr_t,
							    pmr_id));
		pmr_entry->s.pmr_id = _odp_cast_scalar(odp_pmr_t, pmr_id);
		odp_spinlock_init(&pmr_entry->s.lock);
	}

	for (pmr_set_id = 0; pmr_set_id < ODP_PMRSET_MAX_ENTRY;
	     pmr_set_id++) {
		pmr_set_entry = get_pmr_set_entry_internal(
						 _odp_cast_scalar(odp_pmr_set_t,
								  pmr_set_id));
		pmr_set_entry->s.pmr_set_id = _odp_cast_scalar(odp_pmr_set_t,
							       pmr_set_id);
		odp_spinlock_init(&pmr_set_entry->s.lock);
	}

	for (i = 0; i < ODP_COS_MAX_L2_QOS; i++)
		l2_cos[i] = ODP_COS_INVALID;

	for (i = 0; i < ODP_COS_MAX_L3_QOS; i++)
		l3_cos[i] = ODP_COS_INVALID;

	ODP_DBG("\nClassifier init global\n");

	return 0;
}

odp_cos_t odp_cls_cos_create(const char *name, odp_cls_cos_param_t *param)
{
	int i;
	int len;
	queue_entry_t *queue;
	odp_cos_t handle = ODP_COS_INVALID;

	/* Packets are dropped if Queue or Pool is invalid*/
	if (param->queue == ODP_QUEUE_INVALID)
		queue = NULL;
	else
		queue = queue_to_qentry(param->queue);

	if (queue && queue->s.type != ODP_QUEUE_TYPE_PLAIN)
		queue->s.fq.cb.dqrr_ctx = dqrr_cb_cos;

	for (i = 0; i < ODP_COS_MAX_ENTRY; i++) {
		odp_spinlock_lock(&cos_tbl->cos[i].s.lock);
		if (0 == cos_tbl->cos[i].s.taken) {
			len = strlen(name);
			if (len > (ODP_COS_NAME_LEN - 1))
				len = ODP_COS_NAME_LEN - 1;
			strncpy(cos_tbl->cos[i].s.name, name,
				len + 1);
			cos_tbl->cos[i].s.name[len] = 0;
			cos_tbl->cos[i].s.taken = 1;
			cos_tbl->cos[i].s.src_pktio = ODP_PKTIO_INVALID;
			cos_tbl->cos[i].s.queue = param->queue;
			cos_tbl->cos[i].s.is_default = false;
			cos_tbl->cos[i].s.is_error = false;
			handle = cos_tbl->cos[i].s.cos_id;
			odp_spinlock_unlock(&cos_tbl->cos[i].s.lock);
			return handle;
		}
		odp_spinlock_unlock(&cos_tbl->cos[i].s.lock);
	}

	ODP_ERR("ODP_COS_MAX_ENTRY reached");
	return ODP_COS_INVALID;
}

static enum qman_cb_dqrr_result dqrr_cb_cos(struct qman_fq *fq,
					 const struct qm_dqrr_entry *dqrr,
					 uint64_t *user_context)
{
	const struct qm_fd *fd;
	struct qm_sg_entry *sgt;
	pool_entry_t *pool;
	void *fd_addr;
	odp_buffer_hdr_t *buf_hdr;
	odp_buffer_t buf;
	odp_packet_hdr_t *pkthdr;
	odp_packet_t pkt;
	size_t off;
	uint32_t i;

	fd = &dqrr->fd;
	i = bpid_to_index(fd->bpid);
	if (i == ODP_BUFFER_MAX_POOLS) {
		ODP_ERR("Invalid BPID\n");
		/* Buffer need to be freed here */
		return qman_cb_dqrr_consume;
	}
	pool  = get_pool_entry(i);
	queue_entry_t *qentry = QENTRY_FROM_FQ(fq);

	assert(dqrr->stat & QM_DQRR_STAT_FD_VALID);

	assert(pool->s.params.type == ODP_POOL_PACKET);
	assert(qentry->s.buf_hdr == NULL);

	/* get packet header from frame start address */
	fd_addr = __dma_mem_ptov(qm_fd_addr(fd));
	buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);
	off = fd->offset;
	if (fd->format == qm_fd_sg) {
		unsigned	sgcnt;

		sgt = (struct qm_sg_entry *)(fd_addr + fd->offset);
		/* On LE CPUs, converts the SG entry from the BE format as
		 * is provided by the HW to LE as expected by the LE CPUs,
		 * on BE CPUs does nothing */
		hw_sg_to_cpu(&sgt[0]);

		fd_addr = __dma_mem_ptov(qm_sg_addr(sgt));/* first sg entry */
		buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);
		off = sgt->offset;
		sgcnt = 1;
		do {
			hw_sg_to_cpu(&sgt[sgcnt]);

			buf_hdr->addr[sgcnt] = __dma_mem_ptov(
						       qm_sg_addr(&sgt[sgcnt]));
			sgcnt++;
		} while (sgt[sgcnt - 1].final != 1);
		buf_hdr->addr[sgcnt] = __dma_mem_ptov(qm_fd_addr(fd));
		buf_hdr->segcount = sgcnt;
		/* use fd_addr for annotation */
		fd_addr = buf_hdr->addr[sgcnt];
	}

	pkthdr = (odp_packet_hdr_t *)buf_hdr;
	buf = odp_hdr_to_buf(buf_hdr);

	assert(pkthdr->addr[0] == ((void *)pkthdr + pool->s.buf_offset));

	/* setup and receive ODP packet */
	pkt = _odp_packet_from_buffer(buf);
	*user_context = (uint64_t)pkt;
	buf_set_input_queue(buf_hdr, queue_from_id(get_qid(qentry)));
	if (qentry->s.type == ODP_QUEUE_TYPE_PLAIN) {
		qentry->s.buf_hdr = buf_hdr;
		return qman_cb_dqrr_consume;
	}

	odp_pktio_set_input(pkthdr, qentry->s.pktin);
	pkthdr->headroom = pool->s.headroom;
	pkthdr->tailroom = pool->s.tailroom;
	_odp_packet_parse(pkthdr, fd->length20, off, fd_addr);

	if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_ORDERED) {
		pkthdr->orp.seqnum = dqrr->seqnum;
	} else if (qentry->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC) {
		pkthdr->dqrr = dqrr;
		return qman_cb_dqrr_defer;
	}

	return qman_cb_dqrr_consume;
}

int odp_cos_queue_set(odp_cos_t cos_id, odp_queue_t queue_id)
{
	cos_entry_t *cos_entry;
	queue_entry_t *cos_queue;

	cos_entry = get_cos_entry(cos_id);

	if (!cos_entry) {
		ODP_ERR("Could not get cos entry.\n");
		return -1;
	}

	odp_spinlock_lock(&cos_entry->s.lock);
	cos_entry->s.queue = queue_id;
	cos_queue = queue_to_qentry(cos_entry->s.queue);
	if (cos_queue->s.type != ODP_QUEUE_TYPE_PLAIN)
		cos_queue->s.fq.cb.dqrr_ctx = dqrr_cb_cos;
	odp_spinlock_unlock(&cos_entry->s.lock);

	return 0;
}

/* adjust queue count to be power of 2 */
static void update_dist_queue_count(uint32_t *dist_queues, uint32_t queue_count)
{
	while (!(!(queue_count & (queue_count - 1))))
		queue_count--;

	*dist_queues = queue_count;
}

static inline struct scheme_info *get_free_scheme(netcfg_port_info  *port_info)
{
	int i = 0;

	for (i = 0; i < FMC_SCHEMES_NUM; i++) {
		if (!port_info->scheme[i].taken) {
			memset(&port_info->scheme[i], 0,
			       sizeof(port_info->scheme[i]));
			port_info->scheme[i].taken = 1;
			return &port_info->scheme[i];
		}
	}

	return NULL;
}


/*
 * set scheme parameters for a specific port - port_info, before applying
 * a scheme
 */
static inline int set_scheme_params(struct scheme_info *scheme,
				     netcfg_port_info  *port_info,
				     uint32_t fqid, int num_protos,
				     uint8_t proto[], uint8_t next_engine,
				     uint8_t prio[],
				     odp_cls_pmr_term_t *field,
				     int num_fields)
{
	int i, fman_id, j, idx = 0;
	uint8_t tot_prio = prio[0];
	t_FmPcdExtractEntry *ext_param;
	bool ipv6_proto = false, ip_proto = false, found_id = false;

	fman_id = port_info->p_cfg->fman_if->fman_idx;
	if (!scheme->handle) {
		memset(&scheme->priv.params, 0, sizeof(scheme->priv.params));
		scheme->priv.qos_key_idx = -1;
		scheme->priv.params.baseFqid = fqid;
		scheme->priv.params.useHash = 1;
		scheme->priv.params.keyExtractAndHashParams.
						hashDistributionNumOfFqids = 1;
		scheme->priv.queue_count = 1;
		scheme->priv.params.netEnvParams.numOfDistinctionUnits =
								     num_protos;
		for (j = 0; j < num_protos; j++) {
			if (scheme->priv.proto & (1ULL << proto[j]))
				continue;

			/* check if we have ipv6 proto for this scheme */
			if (!ipv6_proto && proto[j] ==	HEADER_TYPE_IPv6)
				ipv6_proto = true;

			/*
			 * check if we have ip proto for this scheme
			 * ip proto includes ipv4 and ipv6 (it's a kind
			 * of ip generic from FMAN point of view)
			 */
			if (!ip_proto && proto[j] ==  HEADER_TYPE_IP)
				ip_proto = true;

			/* set scheme protocols */
			for (i = 0; i < NUM_PROTOS; i++)
				if (port_info->dist_units.units[i].hdrs[0].hdr
				     == proto[j]) {
					scheme->priv.params.netEnvParams.
							     unitIds[idx] = i;
					scheme->priv.proto |=  1ULL << proto[j];
					idx++;
					/* index 0 was already used */
					if (j > 0)
						tot_prio += prio[j];
					break;
				}

		}
		/* set scheme fields */
		if (field) {
			scheme->priv.params.keyExtractAndHashParams.
						 numOfUsedExtracts = num_fields;
			/*
			 * if scheme has fields, increment total priority by 1.
			 * this priority must be greater than the priority of
			 * a scheme with the same proto but with no fields
			 * (scheme with only one proto used for simple pmrs)
			 */
			tot_prio++;

			for (j = 0; j < num_fields; j++) {
				/*
				 * a shared field is a field that could be used
				 * for both ipv4 and ipv6 protos when defining
				 * a scheme
				 */
				if (ipv6_proto && odp_fields[field[j]].
				    share_field) {
					ext_param = &odp_fields[field[j]].
								     extract[1];
				} else {
					ext_param = &odp_fields[field[j]].
								     extract[0];
					/*
					 * default proto for a shared field
					 * (which has generic ip configured)
					 * will be ipv4.
					 */
					if (ip_proto)
						scheme->priv.proto = 1ULL <<
							       HEADER_TYPE_IPv4;
				}
				memcpy(&scheme->priv.params.
				       keyExtractAndHashParams.
				       extractArray[j], ext_param,
				       sizeof(t_FmPcdExtractEntry));
			}
		}

		scheme->priv.params.schemeCounter.update = 1;
		scheme->priv.params.modify = false;
		scheme->priv.params.nextEngine = next_engine;
		scheme->priv.params.netEnvParams.h_NetEnv =
							 port_info->net_env_set;
		scheme->priv.prio = tot_prio;
		/*
		 * relative scheme id establishes the priority when applying
		 * multiple schemes
		 * the lower the value is for a scheme, the higher priority will
		 * have when receiving traffic
		 */
		for (j = 0; j < FMC_SCHEMES_NUM; j++) {
			if (!cos_tbl->rel_scheme_id[fman_id][j]) {
				cos_tbl->rel_scheme_id[fman_id][j] = 1;
				found_id = true;
				break;
			}
		}

		if (!found_id) {
			ODP_ERR("Maximum number of schemes %d exceeded\n",
				FMC_SCHEMES_NUM);
			return -1;
		}

		scheme->priv.params.id.relativeSchemeId = j;
		scheme->id = j;
	} else {
		if (scheme->priv.params.baseFqid > fqid)
			scheme->priv.params.baseFqid = fqid;

		scheme->priv.queue_count++;
		update_dist_queue_count(&scheme->priv.params.
			    keyExtractAndHashParams.hashDistributionNumOfFqids,
					scheme->priv.queue_count);
		scheme->priv.params.modify = true;
		scheme->priv.params.id.h_Scheme = scheme->handle;
	}
	return 0;
}


static int fm_ccnode_remove_entry(t_Handle cc_handle, uint16_t index)
{
	int ret = 0;

	ret = FM_PCD_MatchTableRemoveKey(cc_handle, index);
	if (ret) {
		ODP_ERR("Could not remove entry index %d in ccnode %p\n",
			index, cc_handle);
		return ret;
	}

	return 0;
}

static int fm_ccnode_insert_entry(uint8_t key[], uint8_t mask[],
				  uint8_t key_size, int key_index,
				  t_Handle cc_handle, odp_cos_t dst_cos)
{
	t_FmPcdCcKeyParams key_params;
	uint8_t key_data[MAX_KEY_LEN];
	uint8_t mask_data[MAX_KEY_LEN];
	cos_entry_t *cos_entry;
	uint32_t fqid;
	queue_entry_t *queue;
	int ret;

	memset(&key_params, 0, sizeof(key_params));
	memcpy(key_data, key, key_size);
	key_params.p_Key = key_data;
	memcpy(mask_data, mask, key_size);
	key_params.p_Mask = mask_data;

	cos_entry = get_cos_entry(dst_cos);
	if (!cos_entry) {
		ODP_ERR("Could not get cos entry \n");
		return -1;
	}
	queue = queue_to_qentry(cos_entry->s.queue);
	fqid = queue->s.fq.fqid;
	key_params.ccNextEngineParams.nextEngine = e_FM_PCD_DONE;
	key_params.ccNextEngineParams.params.enqueueParams.action =
						     e_FM_PCD_ENQ_FRAME;
	key_params.ccNextEngineParams.params.enqueueParams.overrideFqid = true;
	key_params.ccNextEngineParams.params.enqueueParams.newFqid = fqid;
	key_params.ccNextEngineParams.statisticsEn = 1;

	ret = FM_PCD_MatchTableAddKey(cc_handle, key_index, key_size,
				      &key_params);
	if (ret) {
		ODP_ERR("Could not insert entry in ccnode %p\n", cc_handle);
		return ret;
	}

	return 0;
}

static int fm_ccnode_modify_entry_action(struct pmr_entry *pmr_id,
					 struct pmr_entry *dst_pmr)
{
	t_FmPcdCcNextEngineParams next_engine;
	cos_entry_t *cos_entry;
	queue_entry_t *queue;
	uint32_t fqid;
	int ret;

	memset(&next_engine, 0, sizeof(next_engine));
	next_engine.statisticsEn = 1;
	if (dst_pmr) {
		next_engine.nextEngine = e_FM_PCD_CC;
		next_engine.params.ccParams.h_CcNode = dst_pmr->ccnode_handle;
		pmr_id->next_act = ACTION_NEXT_CC;
		pmr_id->next_cc = dst_pmr->ccnode_handle;
	} else {
		cos_entry = get_cos_entry(pmr_id->dst_cos);
		if (!cos_entry) {
			ODP_ERR("Could not get cos entry \n");
			return -1;
		}
		queue = queue_to_qentry(cos_entry->s.queue);
		fqid = queue->s.fq.fqid;
		next_engine.nextEngine = e_FM_PCD_DONE;
		next_engine.params.enqueueParams.action = e_FM_PCD_ENQ_FRAME;
		next_engine.params.enqueueParams.overrideFqid = true;
		next_engine.params.enqueueParams.newFqid = fqid;
		pmr_id->next_cc = NULL;
		pmr_id->next_act = ACTION_ENQUEUE;
	}
	ret = FM_PCD_MatchTableModifyNextEngine(pmr_id->ccnode_handle,
						pmr_id->key_index,
						&next_engine);
	if (ret) {
		ODP_ERR("Could not modify entry %d in ccnode %p\n",
			pmr_id->key_index, pmr_id->ccnode_handle);
		return ret;
	}

	return 0;
}

static void set_pmrs_cc_miss_handle(t_Handle cc_handle, t_Handle cc_miss_handle,
				   netcfg_port_info  *port_info)
{
	struct pmr_entry *pmr;
	struct pmr_set_entry *pmr_set;

	if (cc_handle == cc_miss_handle)
		return;

	/* set miss action for all pmrs that have as ccnode the cc_handle */
	list_for_each_entry(pmr, &port_info->pmr_list, pmr_node) {
		if (pmr->ccnode_handle == cc_handle)
			pmr->miss_cc = cc_miss_handle;
	}

	/* set miss action for all pmr sets  that have as ccnode the cc_handle */
	list_for_each_entry(pmr_set, &port_info->pmr_set_list, pmr_set_node) {
		if (pmr_set->ccnode_handle == cc_handle)
			pmr_set->miss_cc = cc_miss_handle;
	}

}

static int update_pmrs_cc_action(t_Handle cc_handle,
				 netcfg_port_info  *port_info)
{
	struct pmr_entry *pmr;
	int ret = 0;

	list_for_each_entry(pmr, &port_info->pmr_list, pmr_node) {
		if (pmr->next_cc == cc_handle)
			ret |= fm_ccnode_modify_entry_action(pmr, NULL);
	}
	return ret;
}



static int config_scheme(struct scheme_info *scheme,
			 netcfg_port_info  *port_info,
			 uint32_t fqid,
			 bool is_direct, int count)
{
	int ret;
	uint8_t proto[] = {HEADER_TYPE_NONE};
	uint8_t prio[] = {default_pri};
	int num_protos = 0, num_fields = 0;
	odp_cls_pmr_term_t *field = NULL;
	struct scheme_info *p_scheme = NULL;
	uint8_t pcd_support = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG;
	t_FmPortPcdCcParams cc_param, *p_cc_param = NULL;

	ret = set_scheme_params(scheme, port_info, fqid, num_protos, proto,
				e_FM_PCD_DONE, prio, field, num_fields);
	if (ret) {
		ODP_ERR("Could set scheme_params on port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	if (is_direct)
		scheme->priv.params.alwaysDirect = true;

	scheme->priv.is_default = true;
	/* if other schemes were configured before default cos,
	 * make sure to set the correct pcd support and cc_params */
	if (count) {
		pcd_support = e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC;
		cc_param.h_CcTree = port_info->tree_handle;
		p_cc_param = &cc_param;
	}

	ret = fm_apply_pcd(port_info, scheme, pcd_support, p_cc_param);
	if (ret) {
		ODP_ERR("Could not apply pcd port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	ret = reorder_schemes(port_info);
	if (ret) {
		ODP_ERR("Could not reorder schemes for port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return ret;
	}

	/* if default cos is created after other pmrs, update last  miss ccnode
	 * to point to default cos fqid  */
	list_for_each_entry(scheme, &port_info->scheme_list, scheme_node) {
		if (!scheme->priv.is_default)
			p_scheme = scheme;
	}

	if (p_scheme && p_scheme->priv.cc_last_handle) {
		ret = fm_modify_cc_miss_act(p_scheme->priv.cc_last_handle,
					    NULL, e_FM_PCD_DONE, fqid);
		if (ret)
			return ret;
	}

	return 0;
}


static int set_default_scheme(netcfg_port_info	*port_info,
			      cos_entry_t *cos_entry,
			      odp_pktio_t pktio_in)
{
	struct scheme_info *scheme;
	int ret = 0;
	uint32_t fqid;
	queue_entry_t *queue;
	pktio_entry_t *pktio_entry;
	int scheme_cnt = 0;

	pktio_entry = get_pktio_entry(pktio_in);
	if (!pktio_entry)
		return -1;

	queue = queue_to_qentry(cos_entry->s.queue);
	fqid = queue->s.fq.fqid;
	/* set the input pktio for the default cos queue */
	odp_queue_set_pktin(cos_entry->s.queue, pktio_in);

	odp_spinlock_lock(&cos_tbl->lock);

	/*search for default scheme. Count the number of existing schemes */
	list_for_each_entry(scheme, &port_info->scheme_list, scheme_node) {
		if (odp_unlikely(scheme->priv.is_default))
			return -1;

		scheme_cnt++;
	}

	/* configure default scheme */
	scheme = get_free_scheme(port_info);
	if (odp_unlikely(!scheme)) {
		ODP_ERR("Could not configure default scheme  for port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		odp_spinlock_unlock(&cos_tbl->lock);
		return -1;
	}
	ret = config_scheme(scheme, port_info, fqid, false, scheme_cnt);
	cos_entry->s.is_default = true;
	cos_entry->s.src_pktio = pktio_in;
	list_add_tail(&pktio_entry->s.def_cos_node, &cos_entry->s.def_cos_list);
	odp_spinlock_unlock(&cos_tbl->lock);

	return ret;
}

int odp_pktio_default_cos_set(odp_pktio_t pktio_in, odp_cos_t default_cos)
{
	cos_entry_t *cos_entry;
	pktio_entry_t *pktio_entry;
	struct fman_if *__if;
	netcfg_port_info  *port_info;
	int ret;

	cos_entry = get_cos_entry(default_cos);
	if (!cos_entry)
		return -1;

	pktio_entry = get_pktio_entry(pktio_in);
	if (!pktio_entry)
		return -1;

	odp_spinlock_lock(&pktio_entry->s.lock);
	if (pktio_entry->s.default_cos != ODP_COS_INVALID) {
		ODP_ERR("Default cos (%"PRIu64" ) already set on pktio %"PRIu64" \n",
			odp_cos_to_u64(pktio_entry->s.default_cos),
			odp_pktio_to_u64(pktio_in));
		odp_spinlock_unlock(&pktio_entry->s.lock);
		return -1;
	}

	__if = pktio_entry->s.__if;
	port_info = pktio_get_port_info(__if);

	ret = set_default_scheme(port_info, cos_entry, pktio_in);
	if (ret) {
		ODP_ERR("Could not set default cos on port pktio %"PRIu64" \n",
			odp_pktio_to_u64(pktio_in));
		odp_spinlock_unlock(&pktio_entry->s.lock);
		return ret;
	}

	pktio_entry->s.default_cos = default_cos;
	odp_spinlock_unlock(&pktio_entry->s.lock);

	return 0;
}

static int is_valid_input(size_t val_sz, odp_cls_pmr_term_t term)
{
	switch (term) {
	case ODP_PMR_ETHTYPE_0:
	case ODP_PMR_ETHTYPE_X:
	case ODP_PMR_VLAN_ID_0:
	case ODP_PMR_VLAN_ID_X:
	case ODP_PMR_UDP_SPORT:
	case ODP_PMR_UDP_DPORT:
	case ODP_PMR_TCP_SPORT:
	case ODP_PMR_TCP_DPORT:
	case ODP_PMR_LEN:
		return (val_sz == sizeof(uint16_t));
	case ODP_PMR_IPPROTO:
	case ODP_PMR_INNER_HDR_OFF:
		return (val_sz == sizeof(uint8_t));
	case ODP_PMR_DMAC:
		return (val_sz == (sizeof(uint64_t) - sizeof(uint16_t)));
	case ODP_PMR_SIP_ADDR:
	case ODP_PMR_DIP_ADDR:
	case ODP_PMR_IPSEC_SPI:
	case ODP_PMR_LD_VNI:
		return (val_sz == (sizeof(uint32_t)));
	case ODP_PMR_SIP6_ADDR:
	case ODP_PMR_DIP6_ADDR:
		return (val_sz == (sizeof(uint64_t) + sizeof(uint64_t)));
	default:
		return false;
	}


	return false;
}

static bool is_supported(odp_cls_pmr_term_t term)
{
	switch (term) {
	case ODP_PMR_ETHTYPE_0:
	case ODP_PMR_VLAN_ID_0:
	case ODP_PMR_VLAN_ID_X:
	case ODP_PMR_UDP_SPORT:
	case ODP_PMR_UDP_DPORT:
	case ODP_PMR_TCP_SPORT:
	case ODP_PMR_TCP_DPORT:
	case ODP_PMR_IPPROTO:
	case ODP_PMR_DMAC:
	case ODP_PMR_SIP_ADDR:
	case ODP_PMR_DIP_ADDR:
	case ODP_PMR_IPSEC_SPI:
	case ODP_PMR_SIP6_ADDR:
	case ODP_PMR_DIP6_ADDR:
		return true;
	default:
		return false;
	}
}

static int fm_create_ccnode(t_Handle *ccnode_handle,
			    netcfg_port_info  *port_info,
			    uint8_t key_size,
			    t_FmPcdCcNodeParams	*cc_param,
			    uint32_t miss_fqid)
{
	if (!miss_fqid) {
		cc_param->keysParams.ccNextEngineParamsForMiss.nextEngine =
								  e_FM_PCD_DONE;
		cc_param->keysParams.ccNextEngineParamsForMiss.params.
				     enqueueParams.action = e_FM_PCD_DROP_FRAME;
	} else {
		cc_param->keysParams.statisticsMode = 1;
		cc_param->keysParams.ccNextEngineParamsForMiss.nextEngine =
							     e_FM_PCD_DONE;
		cc_param->keysParams.ccNextEngineParamsForMiss.params.
				     enqueueParams.action = e_FM_PCD_ENQ_FRAME;
		cc_param->keysParams.ccNextEngineParamsForMiss.params.
						     enqueueParams.newFqid =
								     miss_fqid;
		cc_param->keysParams.ccNextEngineParamsForMiss.params.
						enqueueParams.overrideFqid =
									   true;
	}

	cc_param->keysParams.numOfKeys = 0;
	cc_param->keysParams.keySize = key_size;
	*ccnode_handle = FM_PCD_MatchTableSet(port_info->pcd_handle,
						     cc_param);
	if (!*ccnode_handle) {
		ODP_ERR("Could not add ccnode to port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		return -1;
	}

	return 0;
}

static int fm_modify_cc_miss_act(t_Handle cc_src_handle, t_Handle cc_dst_handle,
				 int next_act, uint32_t fqid)
{
	t_FmPcdCcNextEngineParams miss_param;
	int ret = 0;

	/*
	 * if handle is the same, there is no sense in setting the miss
	 * action to itself
	 */
	if (cc_src_handle == cc_dst_handle)
		return ret;

	memset(&miss_param, 0, sizeof(miss_param));
	miss_param.nextEngine = next_act;
	if (next_act == e_FM_PCD_CC) {
		miss_param.params.ccParams.h_CcNode = cc_dst_handle;
	} else if (next_act == e_FM_PCD_KG) {
		miss_param.params.kgParams.overrideFqid = true;
		miss_param.params.kgParams.h_DirectScheme = cc_dst_handle;
	} else {
		miss_param.nextEngine = e_FM_PCD_DONE;
		if (fqid) {
			miss_param.params.enqueueParams.action =
							     e_FM_PCD_ENQ_FRAME;
			miss_param.params.enqueueParams.overrideFqid = true;
			miss_param.params.enqueueParams.newFqid = fqid;
		} else {
			miss_param.params.enqueueParams.action =
							    e_FM_PCD_DROP_FRAME;
		}
	}
	ret = FM_PCD_MatchTableModifyMissNextEngine(cc_src_handle, &miss_param);
	if (ret) {
		ODP_ERR("Could not change miss action for ccnode %p\n",
			cc_src_handle);
		return ret;
	}

	return 0;
}

static int fm_delete_ccnode(t_Handle *ccnode_handle)
{
	int ret;

	ret = FM_PCD_MatchTableDelete(ccnode_handle);
	if (ret) {
		ODP_ERR("Could not remove ccnode %p\n",
			ccnode_handle);
		return ret;
	}

	return 0;
}

static int fm_delete_scheme(t_Handle *ccnode_handle,
			    netcfg_port_info  *port_info)
{
	struct scheme_info *scheme = NULL;
	t_FmPcdPortSchemesParams params;
	int ret, fman_id, idx;

	if (list_empty(&port_info->scheme_list))
		return false;

	list_for_each_entry(scheme, &port_info->scheme_list, scheme_node) {
		/* ignore default scheme */
		if (scheme->priv.is_default)
			continue;

		if (scheme->priv.cc_root_handle == ccnode_handle) {
			memset(&params, 0, sizeof(params));
			params.numOfSchemes = 1;
			params.h_Schemes[0] = scheme->handle;
			ret = FM_PORT_PcdKgUnbindSchemes(port_info->port_handle,
							 &params);
			if (ret) {
				ODP_ERR("Could not unbind scheme %p\n",
					scheme);
				return ret;
			}

			ret = FM_PCD_KgSchemeDelete(scheme->handle);
			if (ret) {
				ODP_ERR("Could not delete scheme %p\n",
					scheme);
				return ret;
			}

			list_del(&scheme->scheme_node);
			port_info->scheme_count--;
			fman_id = port_info->p_cfg->fman_if->fman_idx;
			idx = scheme->id;
			cos_tbl->rel_scheme_id[fman_id][idx] = 0;
			scheme->taken = 0;
			ODP_DBG("Scheme was removed\n");
		}
	}
	return 0;
}

static int update_ccnodes_miss_act(t_Handle cc_handle,
				   netcfg_port_info  *port_info)
{
	struct pmr_entry *pmr;
	struct pmr_set_entry *pmr_set;
	cos_entry_t *cos_entry;
	uint32_t fqid;
	queue_entry_t *queue;
	int ret = 0;

	list_for_each_entry(pmr, &port_info->pmr_list, pmr_node) {
		if (pmr->miss_cc == cc_handle) {
			cos_entry = get_cos_entry(pmr->dst_cos);
			if (!cos_entry) {
				ODP_ERR("Could not get cos entry \n");
				return -1;
			}
			queue = queue_to_qentry(cos_entry->s.queue);
			fqid = queue->s.fq.fqid;
			ret = fm_modify_cc_miss_act(pmr->ccnode_handle,
						    NULL, e_FM_PCD_DONE, fqid);
			if (ret) {
				ODP_ERR("Could not change miss action for ccnode %p\n",
					pmr->miss_cc);
				return ret;
			}
			pmr->miss_cc = NULL;
		}
	}

	/* search all the pmr_sets and update their miss action if the miss
	 * action points to cc_handle */
	list_for_each_entry(pmr_set, &port_info->pmr_set_list, pmr_set_node) {
		if (pmr_set->miss_cc == cc_handle) {
			cos_entry = get_cos_entry(pmr_set->dst_cos);
			queue = queue_to_qentry(cos_entry->s.queue);
			fqid = queue->s.fq.fqid;
			ret = fm_modify_cc_miss_act(pmr_set->ccnode_handle,
						    NULL, e_FM_PCD_DONE, fqid);
			if (ret) {
				ODP_ERR("Could not change miss action for ccnode %p\n",
					pmr_set->miss_cc);
				return ret;
			}
			pmr_set->miss_cc = NULL;
		}
	}
	return 0;
}

static inline int get_root_id(netcfg_port_info	*port_info)
{
	int i;

	for (i = 0; i < CCTREE_MAX_GROUPS; i++) {
		if (port_info->cc_root[i] == 0) {
			port_info->cc_root[i] = 1;
			break;
		}
	}

	return i;
}

static inline int scheme_exist(netcfg_port_info  *port_info,
			       struct pmr_entry *pmr,
			       struct scheme_info **found_scheme)
{
	struct scheme_info *scheme = NULL;
	uint8_t num_fields;

	if (list_empty(&port_info->scheme_list))
		return false;

	list_for_each_entry(scheme, &port_info->scheme_list, scheme_node) {
		num_fields = scheme->priv.params.keyExtractAndHashParams.
			      numOfUsedExtracts;
		/*
		 * ignore default scheme or scheme used in pmr_sets (a
		 * scheme has at least 1 field in case of pmr_set)
		 */
		if (scheme->priv.is_default || num_fields)
			continue;


		/* header type ip is for both ipv4 and ipv6 */
		if (SCHEME_PROTO_MATCH(odp_fields[pmr->field].header_type,
				       scheme->priv.proto)) {
			*found_scheme = scheme;
			return true;
		}

		if ((scheme->priv.proto &
		     (1ULL << odp_fields[pmr->field].header_type)) ==
		      scheme->priv.proto) {
			*found_scheme = scheme;
			return true;
		}
	}

	return false;
}

static inline void set_scheme_cctree(netcfg_port_info  *port_info,
				     struct scheme_info *scheme,
				     uint8_t group_id)
{
	scheme->priv.params.kgNextEngineParams.cc.h_CcTree =
			port_info->tree_handle;
	scheme->priv.params.kgNextEngineParams.cc.grpId = group_id;
}

static netcfg_port_info *get_port(odp_pktio_t src_pktio)
{
	pktio_entry_t *pktio_entry;
	struct fman_if *__if = NULL;
	netcfg_port_info  *port_info = NULL;

	pktio_entry = get_pktio_entry(src_pktio);
	if (!pktio_entry)
		return NULL;

	__if = pktio_entry->s.__if;
	port_info = pktio_get_port_info(__if);

	return port_info;
}

static odp_pmr_t odp_pmr_create(const odp_pmr_param_t *param)
{
	pmr_entry_t *pmr = NULL;
	odp_pmr_t handle = ODP_PMR_INVAL;
	int i;

	if (!is_valid_input(param->val_sz, param->term)) {
		ODP_ERR("Invalid field size %d or field type %d\n",
			param->val_sz, param->term);
		return ODP_PMR_INVAL;
	}

	if (!is_supported(param->term)) {
		ODP_ERR("Field not supported for classification\n");
		return ODP_PMR_INVAL;
	}

	for (i = 0; i < ODP_PMR_MAX_ENTRY; i++) {
		pmr = &pmr_pool->pmr[i];

		if (pmr->s.taken != 0)
			continue;

		odp_spinlock_lock(&pmr->s.lock);
		pmr->s.taken = 1;
		pmr->s.key_size = param->val_sz;
		pmr->s.field = param->term;
		pmr->s.pktio_in = ODP_PKTIO_INVALID;
		pmr->s.dst_cos = ODP_COS_INVALID;
		pmr->s.src_cos = ODP_COS_INVALID;
		pmr->s.key_index = -1;
		pmr->s.ccnode_handle = NULL;
		pmr->s.next_cc = NULL;
		pmr->s.miss_cc = NULL;
		pmr->s.next_act = 0;
		pmr->s.root_id = -1;
		pmr->s.cascade = false;
		copy_keys_bytes(pmr->s.key, (uint8_t *)param->match.value, param->val_sz);
		copy_keys_bytes(pmr->s.mask, (uint8_t *)param->match.mask, param->val_sz);
		handle = pmr->s.pmr_id;
		odp_spinlock_unlock(&pmr->s.lock);
		break;
	}

	return handle;
}

static void update_ccnode_indexes(void *pmr_obj,
				  netcfg_port_info  *port_info,
				  bool is_pmr)
{
	struct pmr_entry *pmr, *pmr_id;
	struct pmr_set_entry *pmr_set, *pmr_set_id;

	if (is_pmr) {
		pmr_id = (struct pmr_entry *)pmr_obj;
		list_for_each_entry(pmr, &port_info->pmr_list, pmr_node) {
			if (pmr_id->ccnode_handle == pmr->ccnode_handle) {
				if (pmr->key_index > pmr_id->key_index)
					pmr->key_index--;
			}
		}
	} else {
		pmr_set_id = (struct pmr_set_entry *)pmr_obj;
		list_for_each_entry(pmr_set, &port_info->pmr_set_list,
				    pmr_set_node) {
			if (pmr_set_id->ccnode_handle ==
			    pmr_set->ccnode_handle) {
				if (pmr_set->key_index > pmr_set_id->key_index)
					pmr_set->key_index--;
			}
		}
	}
}

static bool last_ccnode(void *pmr_obj, netcfg_port_info  *port_info,
			bool is_pmr)
{
	struct pmr_entry *pmr, *pmr_id;
	struct pmr_set_entry *pmr_set, *pmr_set_id;
	int count_cc = 0;

	if (is_pmr) {
		pmr_id = (struct pmr_entry *)pmr_obj;
		list_for_each_entry(pmr, &port_info->pmr_list, pmr_node) {
			if (pmr_id->ccnode_handle == pmr->ccnode_handle) {
				count_cc++;
			}
		}
	} else {
		pmr_set_id = (struct pmr_set_entry *)pmr_obj;
		list_for_each_entry(pmr_set, &port_info->pmr_set_list,
				    pmr_set_node) {
			if (pmr_set_id->ccnode_handle ==
			    pmr_set->ccnode_handle) {
				count_cc++;
			}
		}
	}

	if (count_cc == 1)
		return true;
	else
		return false;
}

static void set_pmr_key_index(struct pmr_entry *pmr_id,
			      netcfg_port_info	*port_info)
{
	struct pmr_entry *pmr;
	int last_idx = -1;

	list_for_each_entry(pmr, &port_info->pmr_list, pmr_node) {
		if (pmr_id->ccnode_handle == pmr->ccnode_handle) {
			if (pmr->key_index > last_idx)
				last_idx = pmr->key_index;
		}
	}
	pmr_id->key_index = last_idx + 1;
}

static void set_key_index(struct pmr_set_entry *pmr_set_id,
			  netcfg_port_info  *port_info)
{
	struct pmr_set_entry *pmr_set;
	int last_idx = -1;

	list_for_each_entry(pmr_set, &port_info->pmr_set_list,
			    pmr_set_node) {
		if (pmr_set_id->ccnode_handle == pmr_set->ccnode_handle) {
			if (pmr_set->key_index > last_idx)
				last_idx = pmr_set->key_index;
		}
	}
	pmr_set_id->key_index = last_idx + 1;
}

static struct pmr_entry *get_next_pmr(struct pmr_entry *current)
{
	cos_entry_t *dst_cos;
	struct pmr_entry *next_pmr = NULL;

	dst_cos = get_cos_entry(current->dst_cos);
	if (!dst_cos) {
		ODP_ERR("Could not get cos entry \n");
		return NULL;
	}
	/* get the first entry from cos dest filter list */
	if (!list_empty(&dst_cos->s.dst_filter_list)) {
		next_pmr = list_entry(dst_cos->s.dst_filter_list.next,
				      struct pmr_entry, pmr_dst_node);
	}
	return next_pmr;
}

static int update_pmrs_ccnodes(struct pmr_entry *pmr_id,
			       netcfg_port_info  *port_info)
{
	cos_entry_t *dst_cos;
	struct pmr_entry *next_pmr = NULL, *pmr;
	int ret = 0;

	next_pmr = get_next_pmr(pmr_id);

	/* if there are no keys (index = -1), insert the pmr key */
	if (pmr_id->key_index == -1) {
		set_pmr_key_index(pmr_id, port_info);
		ret = fm_ccnode_insert_entry(pmr_id->key, pmr_id->mask,
					     pmr_id->key_size,
					     pmr_id->key_index,
					     pmr_id->ccnode_handle,
					     pmr_id->dst_cos);
		if (ret) {
			ODP_ERR("Could not insert key for port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			return ret;
		}
	}
	/*
	 * the pmr entry will point to the next_pmr, that corresponds to the
	 * destination cos of the pmr
	 * e.g pmr - has ip.src key and next_pmr has ip.dst key
	 * traffic must match both ip.src and ip.dst that is pmr will be linked
	 * with next_pmr
	 * pmr_id and next_pmr cannot have the same fields
	 */
	if (next_pmr) {
		if (next_pmr->field != pmr_id->field) {
			ret = fm_ccnode_modify_entry_action(pmr_id, next_pmr);
			if (ret) {
				ODP_ERR("Could not modify ccnode for port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				return ret;
			}
		} else {
			ODP_DBG("pmr %"PRIu64"  cannot be linked with pmr %"PRIu64" . Cannot cascade from one pmr with a field"
				" to other pmr with the same field\n",
				odp_pmr_to_u64(pmr_id->pmr_id),
				odp_pmr_to_u64(next_pmr->pmr_id));
			return -1;
		}
	}

	dst_cos = get_cos_entry(pmr_id->dst_cos);
	if (!dst_cos) {
		ODP_ERR("Could not get cos entry\n");
		return -1;
	}
	/* set the input pktio for the dst_cos queue */
	odp_queue_set_pktin(dst_cos->s.queue, pmr_id->pktio_in);
	list_for_each_entry(pmr, &dst_cos->s.dst_filter_list, pmr_dst_node) {
		ret = update_pmrs_ccnodes(pmr, port_info);
		if (ret) {
			ODP_ERR("Error during updating pmrs\n");
			return ret;
		}
	}

	return 0;
}


static int set_pmrs_ccnodes(struct pmr_entry *pmr_id,
			    netcfg_port_info  *port_info,
			    uint32_t miss_fqid)
{
	cos_entry_t *dst_cos, *cos_entry, *src_cos;
	queue_entry_t *queue;
	odp_pktio_t src_pktio;
	struct pmr_entry *pmr = NULL, *prev_pmr = NULL, *tmp;
	uint32_t fqid;
	bool found = false, found_cc = false;
	int ret = 0;

	src_cos = get_cos_entry(pmr_id->src_cos);

	/*
	 * iterate through all the pmrs that receive traffic from src_cos
	 * and check to see if current pmr(that must not be a root pmr)
	 * could be mapped to the same ccnode as prevoius pmrs. If this
	 * is true, do not create another ccnode and reuse the existing ccnode
	 */
	if (src_cos && (pmr_id->root_id == -1)) {
		list_for_each_entry(pmr, &src_cos->s.dst_filter_list,
				    pmr_dst_node) {
			if (pmr_id->field == pmr->field && pmr->ccnode_handle) {
				pmr_id->ccnode_handle = pmr->ccnode_handle;
				break;
			}
		}
	}

	/* previous check verified that we do not duplicate ccnodes.
	 * if all the pmrs in the list have null ccnodes, create the ccnode for
	 * current pmr_id. At next iteration in this recursive function,
	 * the next pmr_id that will have its field identical with the pmr_id
	 * that had its ccnode configured, will use the same ccnode(configured
	 * by the above check)*/
	if (!pmr_id->ccnode_handle) {
		pmr_id->next_act = ACTION_ENQUEUE;
		ret = fm_create_ccnode(&pmr_id->ccnode_handle, port_info,
				      pmr_id->key_size,
				      &odp_fields[pmr_id->field].cc_param,
				      miss_fqid);
		if (ret) {
			ODP_ERR("Could not create ccnode for port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			return ret;
		}
	}

	dst_cos = get_cos_entry(pmr_id->dst_cos);
	if (!dst_cos) {
		ODP_ERR("Could not get cos entry\n");
		return -1;
	}
	queue = queue_to_qentry(dst_cos->s.queue);
	fqid = queue->s.fq.fqid;
	src_pktio = pmr_id->pktio_in;
	/* set the input pktio for the miss queue */
	odp_queue_set_pktin(dst_cos->s.queue, pmr_id->pktio_in);

	list_for_each_entry(pmr, &dst_cos->s.dst_filter_list, pmr_dst_node) {
		/* set the port on the pmr destination cos */
		cos_entry = get_cos_entry(pmr->dst_cos);
		if (!cos_entry) {
			ODP_ERR("Could not get cos entry\n");
			return -1;
		}
		if (cos_entry->s.src_pktio == ODP_PKTIO_INVALID)
			cos_entry->s.src_pktio = src_pktio;
		set_pmrs_ccnodes(pmr, port_info, fqid);
		if (!prev_pmr) {
			prev_pmr = pmr;
		} else {
			/*
			 * iterate through all pmrs from dst cos and
			 * check if the current pmr has a ccnode associated
			 * if this is true, miss action of prev will not point
			 * to current pmr.(that means that prev pmr is on
			 * the miss chain from the found ccnode)
			 */
			list_for_each_entry(tmp, &dst_cos->s.dst_filter_list,
					    pmr_dst_node) {
				if (tmp == pmr)
					break;

				if (tmp->ccnode_handle == pmr->ccnode_handle) {
					found_cc = true;
					break;
				}
			}
			if (!found_cc) {
				ret = fm_modify_cc_miss_act(prev_pmr->
							    ccnode_handle,
							    pmr->ccnode_handle,
							    e_FM_PCD_CC,
							    0);
				if (ret) {
					ODP_ERR("Could not set miss for pmr %"PRIu64" \n",
						odp_pmr_to_u64(prev_pmr->pmr_id));
					return ret;
				}

				set_pmrs_cc_miss_handle(prev_pmr->ccnode_handle,
							pmr->ccnode_handle,
							port_info);
			}
			pmr->next_act = ACTION_ENQUEUE;
			prev_pmr = pmr;
		}
		if (!pmr->cascade) {
			pmr->cascade = true;
			list_add_tail(&pmr->pmr_node, &port_info->pmr_list);
		}
		found = true;
	}

	if (miss_fqid && !found) {
		if (!pmr_id->cascade) {
			pmr_id->cascade = true;
			list_add_tail(&pmr_id->pmr_node, &port_info->pmr_list);
		}
	}

	return 0;
}

/*
 * configure the miss action of the last pmr that has its ccnode different from
 * the current pmr (given as argument) ccnode
 */
static int update_pmrs_miss_action(struct pmr_entry *pmr,
			      cos_entry_t *cos_entry,
			      netcfg_port_info  *port_info)
{
	struct pmr_entry *tmp, *prev_pmr = NULL;
	bool found_cc = false;
	int ret = 0;

	list_for_each_entry(tmp, &cos_entry->s.dst_filter_list, pmr_dst_node) {
		if (tmp == pmr)
			break;

		if (tmp->ccnode_handle == pmr->ccnode_handle) {
			found_cc = true;
			break;
		} else
			prev_pmr = tmp;
	}

	if (!found_cc && prev_pmr) {
		ret = fm_modify_cc_miss_act(prev_pmr->ccnode_handle,
					    pmr->ccnode_handle, e_FM_PCD_CC, 0);
		if (ret) {
			ODP_ERR("Could not set miss for pmr %"PRIu64" \n",
				odp_pmr_to_u64(prev_pmr->pmr_id));
			return ret;
		}

		set_pmrs_cc_miss_handle(prev_pmr->ccnode_handle,
					pmr->ccnode_handle,
					port_info);
		pmr->next_act = ACTION_ENQUEUE;
	}
	return ret;
}

static int update_last_cc_miss_act(netcfg_port_info  *port_info)
{
	int i, count = 0, j;
	struct scheme_info *scheme_p, *scheme_n, *scheme_i, *scheme_j;
	void *schemes[FMC_SCHEMES_NUM];
	int ret = 0;

	list_for_each_entry(scheme_p, &port_info->scheme_list, scheme_node)
		schemes[count++] = scheme_p;

	/* reorder schemes based on relative scheme id */
	for (i = 0; i < count - 1; i++) {
		scheme_i = (struct scheme_info *)schemes[i];
		for (j = i + 1; j < count; j++) {
			scheme_j = (struct scheme_info *)schemes[j];
			if (scheme_i->id > scheme_j->id) {
				schemes[i] = scheme_j;
				schemes[j] = scheme_i;
			}
		}
	}

	for (i = 0; i < count - 1; i++) {
		t_Handle handle;
		t_FmPcdKgKeyExtractAndHashParams k_prm_n, k_prm_p;
		/*
		 * scheme_n has greater priority than scheme_p
		 * last ccnode miss' action from scheme_n will point to
		 * the root ccnode handle of the scheme_p
		 */
		scheme_n = (struct scheme_info *)schemes[i];
		scheme_p = (struct scheme_info *)schemes[i + 1];

		/*
		 * do not set miss between pmr_set --> pmr_set nor between
		 * pmr ---> pmr_set. For pmr_sets the ccnodes are exact
		 * match tables (the key is generated from the scheme not
		 * from the ccnode as in the pmr case)
		 */
		k_prm_n = scheme_n->priv.params.keyExtractAndHashParams;
		k_prm_p = scheme_p->priv.params.keyExtractAndHashParams;
		if ((k_prm_n.numOfUsedExtracts && k_prm_p.numOfUsedExtracts) ||
		    (!k_prm_n.numOfUsedExtracts && k_prm_p.numOfUsedExtracts))
			continue;

		if (scheme_p->priv.is_default)
			continue;
		else
			handle = scheme_p->priv.cc_root_handle;

		ret = fm_modify_cc_miss_act(scheme_n->priv.cc_last_handle,
					    handle, e_FM_PCD_CC, 0);
		if (ret) {
			ODP_ERR("Could modify miss action for ccnode %p from scheme %d\n",
				scheme_n->priv.cc_last_handle,
				scheme_n - port_info->scheme);
			return ret;
		}

		set_pmrs_cc_miss_handle(scheme_n->priv.cc_last_handle,
					handle, port_info);
	}
	return 0;
}

/*
 * update the action of the pmr match set and configure all the pmrs
 * that will cascade from it
 */
static int update_pmr_set_ccnode(struct pmr_set_entry *pmr_set_ent,
				 pmr_entry_t *pmr,
				 netcfg_port_info  *port_info,
				 uint32_t fqid)
{
	t_FmPcdCcNextEngineParams next_engine;
	int ret = 0;

	memset(&next_engine, 0, sizeof(next_engine));
	next_engine.statisticsEn = 1;
	/*
	 * if pmr is not NULL change the action of pmr_set to point to the
	 * pmr's ccnode
	 */
	if (pmr) {
		ret = set_pmrs_ccnodes(&pmr->s, port_info, fqid);
		if (ret) {
			ODP_ERR("Could not configure cascade ccnodes\n");
			return ret;
		}

		if (!pmr_set_ent->next_cc) {
			next_engine.nextEngine = e_FM_PCD_CC;
			next_engine.params.ccParams.h_CcNode =
							   pmr->s.ccnode_handle;
			ret = FM_PCD_MatchTableModifyNextEngine(
						     pmr_set_ent->ccnode_handle,
						     pmr_set_ent->key_index,
						     &next_engine);
			if (ret) {
				ODP_ERR("Could not modify entry %d in ccnode %p\n",
					pmr_set_ent->key_index,
					pmr_set_ent->ccnode_handle);
				return ret;
			}

			pmr_set_ent->next_cc = pmr->s.ccnode_handle;
		}

		ret |= update_pmrs_ccnodes(&pmr->s, port_info);
		if (ret) {
			ODP_ERR("Could not configure cascade ccnodes\n");
			return ret;
		}
	} else { /* change the action to point to the fqid */
		next_engine.nextEngine = e_FM_PCD_DONE;
		next_engine.params.enqueueParams.action = e_FM_PCD_ENQ_FRAME;
		next_engine.params.enqueueParams.overrideFqid = true;
		next_engine.params.enqueueParams.newFqid = fqid;

		ret = FM_PCD_MatchTableModifyNextEngine(
						     pmr_set_ent->ccnode_handle,
						     pmr_set_ent->key_index,
						     &next_engine);
		if (ret) {
			ODP_ERR("Could not modify entry %d in ccnode %p\n",
				pmr_set_ent->key_index,
				pmr_set_ent->ccnode_handle);
			return ret;
		}
	}

	return ret;
}

static int odp_pktio_pmr_cos(odp_pmr_t pmr_id, odp_pktio_t src_pktio,
		      odp_cos_t dst_cos)
{
	cos_entry_t *cos_entry, *def_cos_entry;
	pktio_entry_t *pktio_entry;
	struct scheme_info *scheme = NULL;
	struct pmr_entry *pmr_ent;
	pmr_entry_t *pmr;
	netcfg_port_info  *port_info = NULL, *cos_port_info;
	int ret = 0;
	queue_entry_t *queue;
	t_FmPortPcdCcParams cc_param;
	uint32_t fqid;
	int idx = -1;
	bool found = false, found_pmr = false;
	uint8_t proto[1], prio[1];
	int num_protos = 1, num_fields = 0;
	odp_cls_pmr_term_t *field = NULL;

	cos_entry = get_cos_entry(dst_cos);

	if (!cos_entry) {
		ODP_ERR("Invalid dst_cos %"PRIu64" \n",
			odp_cos_to_u64(dst_cos));
		return -1;
	}


	pmr = get_pmr_entry(pmr_id);
	if (!pmr) {
		ODP_ERR("Invalid pmr_id %"PRIu64" \n",
			odp_pmr_to_u64(pmr_id));
		return -1;
	}

	port_info = get_port(src_pktio);
	if (!port_info) {
		ODP_ERR("Invalid src_pktio %"PRIu64" \n",
			odp_pktio_to_u64(src_pktio));
		return -1;
	}

	pktio_entry = get_pktio_entry(src_pktio);
	if (!pktio_entry) {
		ODP_ERR("Cannot get entry\n");
		return -1;
	}
	if (odp_unlikely(pktio_entry->s.inq_default == ODP_QUEUE_INVALID)) {
		ODP_ERR("Invalid src_pktio %"PRIu64". Default rx queue was not"
			" configured\n", odp_pktio_to_u64(src_pktio));
		return -1;
	}

	def_cos_entry = get_cos_entry(pktio_entry->s.default_cos);
	if (!def_cos_entry) {
		/* get the fqid for the pktio device */
		queue = queue_to_qentry(pktio_entry->s.inq_default);
		fqid = queue->s.fq.fqid;
	} else {
		/* get the fqid for the pktio def cos */
		queue = queue_to_qentry(def_cos_entry->s.queue);
		fqid = queue->s.fq.fqid;
		/* set the input pktio for the miss queue */
		odp_queue_set_pktin(def_cos_entry->s.queue, src_pktio);
	}

	/* set the input pktio for the dst_cos queue */
	odp_queue_set_pktin(cos_entry->s.queue, src_pktio);

	cos_port_info = get_port(cos_entry->s.src_pktio);

	if ((cos_port_info) && (cos_port_info != port_info)) {
		ODP_ERR("dst_cos %"PRIu64" was already set for port %d\n",
			odp_cos_to_u64(dst_cos),
			cos_port_info->p_cfg->fman_if->mac_idx);
		return -1;
	}

	odp_spinlock_lock(&cos_tbl->lock);

	if (list_empty(&cos_entry->s.dst_filter_list))
		pmr->s.next_act = ACTION_ENQUEUE;
	else
		pmr->s.next_act = ACTION_NEXT_CC;

	if (pmr->s.pktio_in != ODP_PKTIO_INVALID) {
		ODP_ERR("pmr %"PRIu64" is already set on pktio %"PRIu64" \n",
			odp_pmr_to_u64(pmr_id),
			odp_pktio_to_u64(pmr->s.pktio_in));
		ret = -1;
		goto out;
	}

	pmr->s.pktio_in = src_pktio;
	pmr->s.dst_cos = dst_cos;
	pmr->s.src_cos = ODP_COS_INVALID;

	list_for_each_entry(pmr_ent, &port_info->pmr_list, pmr_node) {
		if (!pmr_ent->cascade && pmr->s.field == pmr_ent->field) {
			pmr->s.root_id = pmr_ent->root_id;
			pmr->s.ccnode_handle = pmr_ent->ccnode_handle;
			pmr->s.next_act = pmr_ent->next_act;
			found_pmr = true;
			break;
		}
	}

	/* there is no pmr with the same field */
	if (!found_pmr) {
		ret = fm_create_ccnode(&pmr->s.ccnode_handle, port_info,
				       pmr->s.key_size,
				       &odp_fields[pmr->s.field].cc_param,
				       fqid);
		if (ret) {
			ODP_ERR("Could not create ccnode for port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			goto out;
		}

		/* check if a new scheme should be created; ignore default
		 * scheme */
		found = scheme_exist(port_info, &pmr->s, &scheme);
		if (!found) {
			idx = get_root_id(port_info);
			if (odp_unlikely(idx >= CCTREE_MAX_GROUPS)) {
				ODP_ERR("Maximum number of ccroots reached for port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				goto out;
			}

			scheme = get_free_scheme(port_info);
			if (odp_unlikely(!scheme)) {
				ODP_ERR("Could not get scheme for port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				goto out;
			}

			/* add the ccnode corresponding to the pmr,
			 * in the cctree */
			ret = update_cctree(port_info,
					    pmr->s.ccnode_handle, idx,
					    e_FM_PCD_CC);
			if (ret) {
				ODP_ERR("Error updating cctree for port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				goto out;
			}

			pmr->s.root_id = idx;
			proto[0] = odp_fields[pmr->s.field].header_type;
			prio[0] = odp_fields[pmr->s.field].prio;
			ret = set_scheme_params(scheme, port_info, fqid,
						num_protos, proto, e_FM_PCD_CC,
						prio, field, num_fields);
			if (ret) {
				ODP_ERR("Could not set scheme params for  port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				goto out;
			}

			scheme->priv.cc_root_handle = pmr->s.ccnode_handle;
			set_scheme_cctree(port_info, scheme, pmr->s.root_id);
			cc_param.h_CcTree = port_info->tree_handle;
			ret = fm_apply_pcd(port_info, scheme,
				e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC,
				&cc_param);
			if (ret) {
				ODP_ERR("Could not apply pcd on  port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				goto out;
			}

			scheme->priv.cc_last_handle = pmr->s.ccnode_handle;
			ret = reorder_schemes(port_info);
			if (ret) {
				ODP_ERR("Could not reorder schemes for port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				goto out;
			}

		} else {
			if (odp_unlikely(!scheme->priv.cc_last_handle)) {
				ODP_ERR("Could not get last pmr for port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				goto out;
			}

			ret = fm_modify_cc_miss_act(scheme->priv.cc_last_handle,
						    pmr->s.ccnode_handle,
						    e_FM_PCD_CC, 0);
			if (ret) {
				ODP_ERR("Could modify miss action for ccnode %p from scheme %d\n",
					scheme->priv.cc_last_handle,
					scheme - port_info->scheme);
				goto out;
			}

			set_pmrs_cc_miss_handle(scheme->priv.cc_last_handle,
						pmr->s.ccnode_handle,
						port_info);
			scheme->priv.cc_last_handle = pmr->s.ccnode_handle;
		}
	}

	set_pmr_key_index(&pmr->s, port_info);
	/* add the pmr value in the ccnode */
	ret = fm_ccnode_insert_entry(pmr->s.key, pmr->s.mask,
				     pmr->s.key_size, pmr->s.key_index,
				     pmr->s.ccnode_handle, pmr->s.dst_cos);
	if (ret) {
		ODP_ERR("Could not insert key for port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		goto out;
	}

	list_add_tail(&pmr->s.pmr_node, &port_info->pmr_list);

	ret = update_last_cc_miss_act(port_info);
	if (ret) {
		ODP_ERR("Could not update miss action for ccnodes in the current pcd\n");
		/* remove the pmr from the pmr port list */
		list_del(&pmr->s.pmr_node);
		goto out;
	}

	if (pmr->s.next_act == ACTION_NEXT_CC) {
		ret = set_pmrs_ccnodes(&pmr->s, port_info, fqid);
		ret |= update_pmrs_ccnodes(&pmr->s, port_info);
		if (ret) {
			ODP_ERR("Could not configure cascade ccnodes\n");
			goto out;
		}
	}

	if (cos_entry->s.src_pktio == ODP_PKTIO_INVALID)
		cos_entry->s.src_pktio = src_pktio;
	/* set pmr filters in cos */
	list_add_tail(&pmr->s.pmr_src_node, &cos_entry->s.src_filter_list);

out:
	if (ret) {
		/* release root ccnode */
		if (idx >= 0 && idx < CCTREE_MAX_GROUPS)
			port_info->cc_root[idx] = 0;

		pmr->s.pktio_in = ODP_PKTIO_INVALID;
		pmr->s.dst_cos = ODP_COS_INVALID;
	}

	odp_spinlock_unlock(&cos_tbl->lock);



	return ret;
}

#if 0
static int odp_cos_pmr_cos(odp_pmr_t pmr_id, odp_cos_t src_cos, odp_cos_t dst_cos)
{
	cos_entry_t *dst_cos_entry, *src_cos_entry;
	netcfg_port_info  *port_info, *dst_port_info;
	struct pmr_entry *pmr_ent;
	struct pmr_set_entry *pmr_set_ent;
	pmr_entry_t *pmr;
	queue_entry_t *queue;
	uint32_t miss_fqid = 0;
	int ret = 0;

	dst_cos_entry = get_cos_entry(dst_cos);

	if (!dst_cos_entry) {
		ODP_ERR("Invalid dst_cos %"PRIu64" \n",
			odp_cos_to_u64(dst_cos));
		return -1;
	}

	src_cos_entry = get_cos_entry(src_cos);
	if (!src_cos_entry) {
		ODP_ERR("Invalid src_cos %"PRIu64" \n",
			odp_cos_to_u64(src_cos));
		return -1;
	}


	pmr = get_pmr_entry(pmr_id);
	if (!pmr) {
		ODP_ERR("Invalid pmr_id %"PRIu64" \n",
			odp_pmr_to_u64(pmr_id));
		return -1;
	}


	odp_spinlock_lock(&cos_tbl->lock);

	if (pmr->s.pktio_in != ODP_PKTIO_INVALID) {
		ODP_ERR("pmr %"PRIu64" is already configured on pktio %"PRIu64" \n",
			odp_pmr_to_u64(pmr_id),
			odp_pktio_to_u64(pmr->s.pktio_in));
		goto out;
	}

	if (pmr->s.dst_cos != ODP_COS_INVALID) {
		ODP_ERR("pmr %"PRIu64" is already configured or dst_cos %"PRIu64" \n",
			odp_pmr_to_u64(pmr_id), odp_cos_to_u64(pmr->s.dst_cos));
		goto out;
	}

	list_for_each_entry(pmr_ent, &src_cos_entry->s.dst_filter_list,
			    pmr_dst_node) {
		if (&pmr->s == pmr_ent) {
			ODP_ERR("pmr %"PRIu64" is already configured\n",
				odp_pmr_to_u64(pmr_id));
			goto out;
		}

		if (pmr->s.field == pmr_ent->field) {
			pmr->s.ccnode_handle = pmr_ent->ccnode_handle;
			break;
		}
	}

	pmr->s.dst_cos = dst_cos;
	pmr->s.src_cos = src_cos;
	port_info = get_port(src_cos_entry->s.src_pktio);
	if (port_info) {
		pmr->s.pktio_in = src_cos_entry->s.src_pktio;
		dst_port_info = get_port(dst_cos_entry->s.src_pktio);

		if ((dst_port_info) && (dst_port_info != port_info)) {
			ODP_ERR("dst_cos %"PRIu64" was set for port %d\n",
				odp_cos_to_u64(dst_cos),
				dst_port_info->p_cfg->fman_if->mac_idx);
			goto out;
		}

		if (!dst_port_info)
			dst_cos_entry->s.src_pktio = src_cos_entry->s.src_pktio;

		/* set the input pktio for the miss queue */
		odp_queue_set_pktin(src_cos_entry->s.queue,
				    src_cos_entry->s.src_pktio);
		queue = queue_to_qentry(src_cos_entry->s.queue);
		miss_fqid = queue->s.fq.fqid;

		/* this is a cascaded pmr. Mark this and add the pmr to
		 * the port */
		if (!pmr->s.cascade) {
			list_add_tail(&pmr->s.pmr_node,
				      &port_info->pmr_list);
			pmr->s.cascade = true;
		}

		/* if pmr has no ccnode, create one  */
		if (!pmr->s.ccnode_handle) {
			ret = fm_create_ccnode(&pmr->s.ccnode_handle,
					       port_info,
					       pmr->s.key_size,
					       &odp_fields[pmr->s.field].
					       cc_param, miss_fqid);
			if (ret) {
				ODP_ERR("Could not create ccnode for port %d\n",
					port_info->p_cfg->fman_if->
					mac_idx);
				goto out;
			}
		}
	}

	/* set pmr filters in cos */
	list_add_tail(&pmr->s.pmr_dst_node,
		      &src_cos_entry->s.dst_filter_list);
	/* set pmr filters in cos */
	list_add_tail(&pmr->s.pmr_src_node,
		      &dst_cos_entry->s.src_filter_list);
	/*
	 * update all the ccnodes from src_cos, which will direct traffic to
	 * this cascade pmr
	 */
	if (port_info) {
		list_for_each_entry(pmr_ent,
				    &src_cos_entry->s.src_filter_list,
				    pmr_src_node) {
			ret = set_pmrs_ccnodes(pmr_ent, port_info, miss_fqid);
			ret |= update_pmrs_ccnodes(pmr_ent, port_info);
			if (ret) {
				ODP_ERR("Could not configure cascade ccnodes\n");
				goto out;
			}
		}
		/*
		 * search all pmr_sets that direct the traffic to src_cos
		 * and update their action to point to the cascade pmr:
		 * pmr_set --> src_cos --> pmr
		 */
		list_for_each_entry(pmr_set_ent,
				    &src_cos_entry->s.src_match_set_list,
				    pmr_set_src_node) {
			ret = update_pmr_set_ccnode(pmr_set_ent, pmr,
						    port_info, miss_fqid);
			if (ret) {
				ODP_ERR("Could not update pmr_set  %"PRIu64" \n",
					odp_pmr_set_to_u64(
						      pmr_set_ent->pmr_set_id));
				goto out;
			}
		}

		/*
		 * establish the miss action for the last pmr from src cos
		 * (it will point to the ccnode of the current pmr, in case
		 * that traffic is received in src_cos - from a pmr match set)
		 */
		if (!list_empty(&src_cos_entry->s.src_match_set_list)) {
			ret = update_pmrs_miss_action(&pmr->s, src_cos_entry,
						 port_info);
		}
	}

out:
	odp_spinlock_unlock(&cos_tbl->lock);


	return ret;
}
#endif

static int fm_ccnode_insert_entries(t_Handle ccnode,
				    uint8_t key[],
				    odp_cos_t cos_val[],
				    size_t num_keys,
				    int *key_idx,
				    enum qos_type key_type)
{
	t_FmPcdCcKeyParams key_params;
	uint8_t key_data[MAX_KEY_LEN];
	uint8_t mask_data[MAX_KEY_LEN];
	cos_entry_t *cos_entry;
	uint32_t fqid;
	queue_entry_t *queue;
	int key_size;
	int ret;
	size_t i;

	memset(key_data, 0, sizeof(key_data));
	memset(mask_data, 0, sizeof(mask_data));
	if (key_type == qos_VPRI) {
		key_size = 4;
		mask_data[0] = 0xff;
		mask_data[1] = 0xff;
		mask_data[2] = 0xe0;
	} else {
		key_size = 1;
		mask_data[0] = 0xff;
	}
	for (i = 0; i < num_keys; i++) {
		memset(&key_params, 0, sizeof(key_params));
		if (key_type == qos_VPRI) {
			/* maximum priority value. priority is a 3 bit field */
			if (key[i] > 7)
				continue;

			key_data[0] = 0x81;
			key_data[2] = key[i] << 5;
		} else {
			/* maximum priority value. priority is a 6 bit field */
			if (key[i] > 63)
				continue;

			key_data[0] = key[i];
		}
		key_params.p_Key = key_data;
		key_params.p_Mask = mask_data;
		cos_entry = get_cos_entry(cos_val[i]);
		if (!cos_entry) {
			ODP_ERR("Cannot get cos entry\n");
			return -1;
		}
		queue = queue_to_qentry(cos_entry->s.queue);
		fqid = queue->s.fq.fqid;
		key_params.ccNextEngineParams.nextEngine = e_FM_PCD_DONE;
		key_params.ccNextEngineParams.params.enqueueParams.action =
							     e_FM_PCD_ENQ_FRAME;
		key_params.ccNextEngineParams.params.enqueueParams.
							    overrideFqid = true;
		key_params.ccNextEngineParams.params.enqueueParams.
								 newFqid = fqid;
		(*key_idx)++;
		ret = FM_PCD_MatchTableAddKey(ccnode, *key_idx, key_size,
					      &key_params);
		if (ret) {
			ODP_ERR("Could not insert entry in priority ccnode %p\n",
				ccnode);
		}
	}

	return 0;

}

static int set_miss_qos(struct scheme_info *l2_qos, struct scheme_info *l3_dscp)
{
	struct scheme_info *prev, *next;
	int ret;

	if (l2_qos && l3_dscp) {
		prev = l2_qos;
		next = l3_dscp;
		if (l2_qos->priv.prio < l3_dscp->priv.prio) {
			prev = l3_dscp;
			next = l2_qos;
		}
		ret = fm_modify_cc_miss_act(prev->priv.cc_last_handle,
					    next->priv.cc_last_handle,
					    e_FM_PCD_CC, 0);
		if (ret) {
			ODP_ERR("Could not modify miss action for %p scheme with priority %d\n",
				prev, prev->priv.prio);
			return ret;
		}
	}

	return 0;
}


int odp_cos_with_l2_priority(odp_pktio_t pktio_in,
			     uint8_t num_qos,
			     uint8_t qos_table[],
			     odp_cos_t cos_table[])
{
	cos_entry_t *cos_entry;
	pktio_entry_t *pktio_entry;
	netcfg_port_info  *port_info;
	struct scheme_info *scheme;
	uint32_t fqid, loop;
	queue_entry_t *queue;
	int ret = 0, idx;
	t_FmPortPcdCcParams cc_param;
	t_FmPcdCcNodeParams	cc_node;
	uint8_t proto[] = {HEADER_TYPE_VLAN}, prio[1];
	int num_protos = 1, num_fields = 0;
	odp_cls_pmr_term_t *field = NULL;
	int key_size = 4;

	port_info = get_port(pktio_in);
	if (!port_info) {
		ODP_ERR("Invalid pktio_in %"PRIu64" \n",
				odp_pktio_to_u64(pktio_in));
		return -1;
	}

	if (!cos_table) {
		ODP_ERR("Invalid cos_table parameter\n");
		return -1;
	}

	if (!qos_table) {
		ODP_ERR("Invalid qos_table parameter\n");
		return -1;
	}

	pktio_entry = get_pktio_entry(pktio_in);
	if (!pktio_entry) {
		ODP_ERR("Cannot get entry\n");
		return -1;
	}
	if (odp_unlikely(pktio_entry->s.inq_default == ODP_QUEUE_INVALID)) {
		ODP_ERR("Invalid pktio_in %"PRIu64". Default rx queue was not"
			" configured\n", odp_pktio_to_u64(pktio_in));
		return -1;
	}

	cos_entry = get_cos_entry(pktio_entry->s.default_cos);
	if (!cos_entry) {
		/* get the fqid for the pktio device */
		queue = queue_to_qentry(pktio_entry->s.inq_default);
		fqid = queue->s.fq.fqid;
	} else {
		/* get the fqid for the pktio def cos */
		queue = queue_to_qentry(cos_entry->s.queue);
		fqid = queue->s.fq.fqid;
		/* set input pktio for miss queue */
		odp_queue_set_pktin(cos_entry->s.queue, pktio_in);
	}

	odp_spinlock_lock(&cos_tbl->lock);
	/* l2 pri scheme was already created */
	if (port_info->l2_vpri)
		goto update_scheme;

	scheme = get_free_scheme(port_info);
	if (odp_unlikely(!scheme)) {
		ODP_ERR("Could not get scheme for port %d while trying to set l2 priority cos\n",
			 port_info->p_cfg->fman_if->mac_idx);
		ret = -1;
		goto out;
	}

	/* the highest priority is vlan_l2_qos_pri.
	 * if l3 dscp has precedence, vlan will have lower priority - that is
	 * the priority of dscp (l3_qos_pri)
	 * implicitly a l2 cos has vlan_l2_qos_pri and a l3 cos has
	 * l3_qos_pri
	 */
	if (port_info->l3_precedence)
		prio[0] = l3_qos_pri;
	else
		prio[0] = vlan_l2_qos_pri;

	ret = set_scheme_params(scheme, port_info, fqid, num_protos, proto,
				e_FM_PCD_CC, prio, field, num_fields);
	if (ret) {
		ODP_ERR("Could not set scheme params for l2 pri\n");
		goto out;
	}

	/* get a free root id*/
	idx = get_root_id(port_info);
	if (odp_unlikely(idx >= CCTREE_MAX_GROUPS)) {
		ODP_ERR("Maximum number of ccroots reached for port %d\n",
			 port_info->p_cfg->fman_if->mac_idx);
		goto out;
	}

	memset(&cc_node, 0, sizeof(cc_node));
	cc_node.extractCcParams.type = e_FM_PCD_EXTRACT_NON_HDR;
	cc_node.extractCcParams.extractNonHdr.src =
					      e_FM_PCD_EXTRACT_FROM_FRAME_START;
	cc_node.extractCcParams.extractNonHdr.offset = 2 * ETH_ALEN;
	cc_node.extractCcParams.extractNonHdr.size = QTAG_LEN;

	/* On miss go to fqid defined for pktio_in device */
	ret = fm_create_ccnode(&scheme->priv.cc_root_handle, port_info,
			       key_size, &cc_node, fqid);

	ret = update_cctree(port_info, scheme->priv.cc_root_handle, idx,
			    e_FM_PCD_CC);
	if (ret) {
		ODP_ERR("Error updating cctree for port %d\n",
			 port_info->p_cfg->fman_if->mac_idx);
		goto out;
	}

	set_scheme_cctree(port_info, scheme, idx);
	cc_param.h_CcTree = port_info->tree_handle;
	scheme->priv.l2_root_id = idx;
	ret = fm_apply_pcd(port_info, scheme,
			   e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC,
			   &cc_param);
	if (ret) {
		ODP_ERR("Could not apply pcd on  port %d\n",
			 port_info->p_cfg->fman_if->mac_idx);
		goto out;
	}

	scheme->priv.cc_last_handle = scheme->priv.cc_root_handle;
	port_info->l2_vpri = scheme;
	ret = reorder_schemes(port_info);
	if (ret) {
		ODP_ERR("Could not reorder schemes for port %d\n",
			 port_info->p_cfg->fman_if->mac_idx);
		goto out;
	}

update_scheme:
	scheme = port_info->l2_vpri;
	fm_ccnode_insert_entries(scheme->priv.cc_root_handle, qos_table,
				 cos_table, num_qos, &scheme->priv.qos_key_idx,
				 qos_VPRI);
	/* set the input pktio for each cos queue form cos_table */
	for (loop = 0; loop < num_qos; loop++) {
		cos_entry = get_cos_entry(cos_table[loop]);
		if (!cos_entry) {
			ODP_ERR("Could not get cos entry\n");
			return -1;
		}
		cos_entry->s.src_pktio = pktio_in;
		odp_queue_set_pktin(cos_entry->s.queue, pktio_in);
	}
	ret = set_miss_qos(port_info->l2_vpri, port_info->l3_dscp);
	/* save cos id */
	for (loop = 0; loop < num_qos; loop++)
		l2_cos[loop] = cos_table[loop];
out:
	odp_spinlock_unlock(&cos_tbl->lock);
	return ret;
}

int odp_cos_with_l3_qos(odp_pktio_t pktio_in,
			uint32_t num_qos,
			uint8_t qos_table[],
			odp_cos_t cos_table[],
			odp_bool_t l3_preference)
{
	cos_entry_t *cos_entry;
	pktio_entry_t *pktio_entry;
	netcfg_port_info  *port_info;
	struct scheme_info *scheme;
	uint32_t fqid, loop;
	queue_entry_t *queue;
	int ret = 0, idx;
	t_FmPortPcdCcParams cc_param;
	t_FmPcdCcNodeParams dscp_cc_param;
	uint8_t proto[] = {HEADER_TYPE_ETH}, prio[1];
	int num_protos = 1, num_fields = 0;
	odp_cls_pmr_term_t *field = NULL;
	int key_size = 1;

	port_info = get_port(pktio_in);
	if (!port_info) {
		ODP_ERR("Invalid pktio_in %"PRIu64" \n",
			odp_pktio_to_u64(pktio_in));
		return -1;
	}

	if (!cos_table) {
		ODP_ERR("Invalid cos_table parameter\n");
		return -1;
	}

	if (!qos_table) {
		ODP_ERR("Invalid qos_table parameter\n");
		return -1;
	}

	pktio_entry = get_pktio_entry(pktio_in);
	if (!pktio_entry) {
		ODP_ERR("Cannot get entry\n");
		return -1;
	}
	if (odp_unlikely(pktio_entry->s.inq_default == ODP_QUEUE_INVALID)) {
		ODP_ERR("Invalid pktio_in %"PRIu64". Default rx queue was not"
			" configured\n", odp_pktio_to_u64(pktio_in));
		return -1;
	}

	cos_entry = get_cos_entry(pktio_entry->s.default_cos);
	if (!cos_entry) {
		/* get the fqid for the pktio device */
		queue = queue_to_qentry(pktio_entry->s.inq_default);
		fqid = queue->s.fq.fqid;
	} else {
		/* get the fqid for the pktio def cos */
		queue = queue_to_qentry(cos_entry->s.queue);
		fqid = queue->s.fq.fqid;
		/* set input pktio for miss queue */
		odp_queue_set_pktin(cos_entry->s.queue, pktio_in);
	}

	odp_spinlock_lock(&cos_tbl->lock);
	/* l3 dscp scheme was already created */
	if (port_info->l3_dscp)
		goto update_scheme;

	scheme = get_free_scheme(port_info);
	if (odp_unlikely(!scheme)) {
		ODP_ERR("Could not get scheme for port %d while trying to set l3 dscp cos\n",
			 port_info->p_cfg->fman_if->mac_idx);
		ret = -1;
		goto out;
	}

	if (l3_preference) {
		prio[0] = vlan_l2_qos_pri;
		port_info->l3_precedence = true;
		/*
		 * if l2 qos was created and l3 has precedence over l2,
		 * adjust the priority of l2 scheme to be lower than l3
		 */
		if (port_info->l2_vpri)
			port_info->l2_vpri->priv.prio = l3_qos_pri;
	}  else
		prio[0] = l3_qos_pri;

	ret = set_scheme_params(scheme, port_info, fqid, num_protos, proto,
				e_FM_PCD_CC, prio, field, num_fields);
	if (ret) {
		ODP_ERR("Could not set scheme params for L3 dscp \n");
		goto out;
	}

	/* get a free root id*/
	idx = get_root_id(port_info);
	if (odp_unlikely(idx >= CCTREE_MAX_GROUPS)) {
		ODP_ERR("Maximum number of ccroots reached for port %d\n",
			 port_info->p_cfg->fman_if->mac_idx);
		goto out;
	}

	memset(&dscp_cc_param, 0, sizeof(dscp_cc_param));
	dscp_cc_param.extractCcParams.type = e_FM_PCD_EXTRACT_BY_HDR;
	dscp_cc_param.extractCcParams.extractByHdr.hdr = HEADER_TYPE_IP;
	dscp_cc_param.extractCcParams.extractByHdr.hdrIndex =
							e_FM_PCD_HDR_INDEX_NONE;
	dscp_cc_param.extractCcParams.extractByHdr.type =
						    e_FM_PCD_EXTRACT_FULL_FIELD;
	dscp_cc_param.extractCcParams.extractByHdr.extractByHdrType.
					fullField.ip = NET_HEADER_FIELD_IP_DSCP;
	/* On miss go to fqid defined for pktio_in device */
	ret = fm_create_ccnode(&scheme->priv.cc_root_handle, port_info,
			       key_size, &dscp_cc_param, fqid);

	ret = update_cctree(port_info, scheme->priv.cc_root_handle, idx,
			    e_FM_PCD_CC);
	if (ret) {
		ODP_ERR("Error updating cctree for port %d\n",
			 port_info->p_cfg->fman_if->mac_idx);
		goto out;
	}

	set_scheme_cctree(port_info, scheme, idx);
	cc_param.h_CcTree = port_info->tree_handle;
	scheme->priv.l3_root_id = idx;
	ret = fm_apply_pcd(port_info, scheme,
			   e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC,
			   &cc_param);
	if (ret) {
		ODP_ERR("Could not apply pcd on  port %d\n",
			 port_info->p_cfg->fman_if->mac_idx);
		goto out;
	}

	scheme->priv.cc_last_handle = scheme->priv.cc_root_handle;
	port_info->l3_dscp = scheme;
	ret = reorder_schemes(port_info);
	if (ret) {
		ODP_ERR("Could not reorder schemes for port %d\n",
			 port_info->p_cfg->fman_if->mac_idx);
		goto out;
	}

update_scheme:
	scheme = port_info->l3_dscp;
	fm_ccnode_insert_entries(scheme->priv.cc_root_handle, qos_table,
				 cos_table, num_qos, &scheme->priv.qos_key_idx,
				 qos_DSCP);
	/* set the input pktio for each cos queue form cos_table */
	for (loop = 0; loop < num_qos; loop++) {
		cos_entry = get_cos_entry(cos_table[loop]);
		if(!cos_entry) {
			ODP_ERR("Cannot get cos entry\n");
			return -1;
		}
		cos_entry->s.src_pktio = pktio_in;
		odp_queue_set_pktin(cos_entry->s.queue, pktio_in);
	}
	ret = set_miss_qos(port_info->l2_vpri, port_info->l3_dscp);
	/* save cos id */
	for (loop = 0; loop < num_qos; loop++)
		l3_cos[loop] = cos_table[loop];
out:
	odp_spinlock_unlock(&cos_tbl->lock);
	return ret;
}

static inline void update_pmr_set(struct pmr_set_entry *pmr_set,
				  struct pmr_set_entry *new_pmr_set)
{
	int loop, j, offset;
	odp_cls_pmr_term_t field, curr_field;
	uint8_t field_size;
	uint8_t key_data[MAX_SET_KEY_LEN];
	uint8_t mask_data[MAX_SET_KEY_LEN];
	uint8_t *p_key;
	uint8_t *p_mask;

	/*
	 *  update new_pmr_set key
	 *  e.g: pmr_set_key: (ip.src, ip.dst, udp.sport)
	 *	 new_pmr_set_key: (udp.sport1)
	 *	 updated_key: (0, 0, udp.sport1) - source and dest ip will be
	 *					   masked
	 */
	p_key = key_data;
	p_mask = mask_data;

	if (pmr_set->num_fields <= 0) {
		ODP_ERR("Num_fields is less or equal than zero\n");
		return;
	}

	for (loop = 0; loop < pmr_set->num_fields; loop++) {
		field = pmr_set->pmr_set_fields[loop];
		field_size = odp_fields[field].size;
		if (!(new_pmr_set->field_mask & (1ULL << field))) {
			memset(p_key, 0, field_size);
			memset(p_mask, 0, field_size);
		} else {
			offset = 0;
			/* determine offset in new_pmr_set key based on field position */
			for (j = 0; j < new_pmr_set->num_fields; j++) {
				curr_field = new_pmr_set->pmr_set_fields[j];
				if (field == curr_field)
					break;
				else {
					offset += odp_fields[curr_field].size;
				}
			}
			copy_keys_bytes(p_key, &new_pmr_set->key[offset],
				    field_size);
			copy_keys_bytes(p_mask, &new_pmr_set->mask[offset],
				   field_size);
		}
		p_key += field_size;
		p_mask += field_size;
	}
	new_pmr_set->num_fields = pmr_set->num_fields;
	/*
	 * update the new pmr set with the fields from the old set
	 * Fields will be used only for key extraction from the scheme
	 * field mask will not be updated. it will be used to get only the
	 * protocols of the present fields in the mask.
	 * e.g : pmr_set(ip.src, ip.dst, udp.sport) => scheme (ipv4, udp)
	 *	 new_pmr_set ([ip.src], ip.dst, [udp.sport])=> scheme (ipv4)
	 *	 [] -new added fields that are padded with 0 in the key
	 */
	memcpy(new_pmr_set->pmr_set_fields, pmr_set->pmr_set_fields,
	      new_pmr_set->num_fields * sizeof(new_pmr_set->pmr_set_fields[0]));
	new_pmr_set->key_size = pmr_set->key_size;
	memcpy(new_pmr_set->key, key_data, new_pmr_set->key_size);
	memcpy(new_pmr_set->mask, mask_data, new_pmr_set->key_size);
	new_pmr_set->ccnode_handle = pmr_set->ccnode_handle;
	new_pmr_set->cc_param = pmr_set->cc_param;
	new_pmr_set->root_id = pmr_set->root_id;
}

static int odp_pmr_match_set_create(int num_terms, const odp_pmr_param_t *terms,
			     odp_pmr_set_t *pmr_set_id)
{
	int loop, i;
	size_t val_sz = 0;
	uint8_t *key = NULL, *mask = NULL;
	pmr_set_entry_t *pmr_set;
	int ret = 0;
	int proto = 0;

	if (!pmr_set_id) {
		ODP_ERR(" Invalid value for pmr_set_id param\n");
		return -1;
	}

	if (!terms) {
		ODP_ERR(" Invalid value for terms param\n");
		return -1;
	}

	if (num_terms <= 0 ||
	    num_terms > FM_PCD_KG_MAX_NUM_OF_EXTRACTS_PER_KEY) {
		ODP_ERR(" Invalid value for num_terms param\n");
		return -1;
	}

	for (loop = 0; loop < num_terms; loop++) {
		if (!is_valid_input(terms[loop].val_sz,
		    terms[loop].term)) {
			ODP_ERR(" Invalid field size %d or field type %d\n",
				terms[loop].val_sz, terms[loop].term);
			return -1;
		}

		if (!is_supported(terms[loop].term)) {
			ODP_ERR("Field not supported for classification\n");
			return -1;
		}
	}

	for (i = 0; i < ODP_PMRSET_MAX_ENTRY; i++) {
		pmr_set = &pmr_pool->pmr_set[i];

		if (pmr_set->s.taken != 0)
			continue;

		odp_spinlock_lock(&pmr_set->s.lock);
		pmr_set->s.taken = 1;
		pmr_set->s.pktio_in = ODP_PKTIO_INVALID;
		pmr_set->s.dst_cos = ODP_COS_INVALID;
		pmr_set->s.key_index = -1;
		pmr_set->s.ccnode_handle = NULL;
		pmr_set->s.miss_cc = NULL;
		pmr_set->s.next_cc = NULL;
		pmr_set->s.root_id = -1;
		pmr_set->s.field_mask = 0;
		pmr_set->s.proto_mask = 0;
		/* save the compound key */
		key = pmr_set->s.key;
		mask = pmr_set->s.mask;
		for (loop = 0; loop < num_terms; loop++) {

			if (loop == ODP_PMR_MAX_FIELDS) {
				ODP_ERR("Invalid value for pmr_set_fields\n");
				return -1;
			}

			copy_keys_bytes(key, (uint8_t *)terms[loop].match.value,
				  terms[loop].val_sz);
			copy_keys_bytes(mask, (uint8_t *)terms[loop].match.mask,
				  terms[loop].val_sz);
			key += terms[loop].val_sz;
			mask += terms[loop].val_sz;
			val_sz += terms[loop].val_sz;
			pmr_set->s.pmr_set_fields[loop] =
							  terms[loop].term;
			pmr_set->s.field_mask |= 1ULL << terms[loop].term;
			proto = odp_fields[terms[loop].term].header_type;

			if (proto == HEADER_TYPE_IP)
				pmr_set->s.proto_mask |= 1ULL <<
							       HEADER_TYPE_IPv4;
			else
				pmr_set->s.proto_mask |= 1ULL << proto;
		}
		pmr_set->s.key_size = val_sz;
		pmr_set->s.num_fields = num_terms;
		ret = num_terms;
		pmr_set->s.cc_param.extractCcParams.type =
						       e_FM_PCD_EXTRACT_NON_HDR;
		pmr_set->s.cc_param.extractCcParams.extractNonHdr.src =
						      e_FM_PCD_EXTRACT_FROM_KEY;
		pmr_set->s.cc_param.extractCcParams.extractNonHdr.action =
						    e_FM_PCD_ACTION_EXACT_MATCH;
		pmr_set->s.cc_param.extractCcParams.extractNonHdr.
								     offset = 0;
		pmr_set->s.cc_param.extractCcParams.
						    extractNonHdr.size = val_sz;
		pmr_set->s.cc_param.keysParams.numOfKeys = 0;
		pmr_set->s.cc_param.keysParams.keySize = val_sz;
		*pmr_set_id = pmr_set->s.pmr_set_id;
		odp_spinlock_unlock(&pmr_set->s.lock);
		break;
	}

	return ret;
}

static struct scheme_info *search_scheme(netcfg_port_info  *port_info,
					 uint64_t proto_mask)
{
	struct scheme_info *scheme = NULL;
	uint8_t num_fields;

	if (list_empty(&port_info->scheme_list))
			return NULL;

	list_for_each_entry(scheme, &port_info->scheme_list, scheme_node) {
		num_fields = scheme->priv.params.keyExtractAndHashParams.
			      numOfUsedExtracts;
		/* ignore default scheme or scheme used in simple pmrs */
		if (scheme->priv.is_default || !num_fields)
			continue;

		if ((scheme->priv.proto & proto_mask) == scheme->priv.proto)
			return scheme;
	}
	return NULL;
}

static int odp_pktio_pmr_match_set_cos(odp_pmr_set_t pmr_set_id, odp_pktio_t src_pktio,
				odp_cos_t dst_cos)
{
	cos_entry_t *cos_entry, *def_cos_entry, *dst_cos_entry;
	pktio_entry_t *pktio_entry;
	struct pmr_set_entry *pmr_set_ent;
	struct pmr_entry *pmr_entry = NULL;
	pmr_entry_t *pmr;
	pmr_set_entry_t *pmr_set;
	netcfg_port_info  *port_info = NULL, *cos_port_info;
	struct scheme_info *scheme = NULL;
	queue_entry_t *queue;
	uint32_t fqid;
	bool found = false;
	int ret = 0, idx = -1, loop, num_protos = 0;
	uint8_t proto[ODP_PMR_MAX_FIELDS], prio[ODP_PMR_MAX_FIELDS];
	odp_cls_pmr_term_t field;
	t_FmPortPcdCcParams cc_param;

	cos_entry = get_cos_entry(dst_cos);

	if (!cos_entry) {
		ODP_ERR("Invalid dst_cos %"PRIu64" \n",
			odp_cos_to_u64(dst_cos));
		return -1;
	}

	pmr_set = get_pmr_set_entry(pmr_set_id);

	if (!pmr_set) {
		ODP_ERR("Invalid pmr_set_id %"PRIu64" \n",
			odp_pmr_set_to_u64(pmr_set_id));
		return -1;
	}

	port_info = get_port(src_pktio);
	if (!port_info) {
		ODP_ERR("Invalid src_pktio %"PRIu64" \n",
			odp_pktio_to_u64(src_pktio));
		return -1;
	}

	pktio_entry = get_pktio_entry(src_pktio);
	if (!pktio_entry) {
		ODP_ERR("Cannot get entry\n");
		return -1;
	}
	if (odp_unlikely(pktio_entry->s.inq_default == ODP_QUEUE_INVALID)) {
		ODP_ERR("Invalid src_pktio %"PRIu64". Default rx queue was not"
			" configured\n", odp_pktio_to_u64(src_pktio));
		return -1;
	}

	def_cos_entry = get_cos_entry(pktio_entry->s.default_cos);
	if (!def_cos_entry) {
		/* get the fqid for the pktio device */
		queue = queue_to_qentry(pktio_entry->s.inq_default);
		fqid = queue->s.fq.fqid;
	} else {
		/* get the fqid for the pktio def cos */
		queue = queue_to_qentry(def_cos_entry->s.queue);
		fqid = queue->s.fq.fqid;
		/* set the input pktio for the miss queue */
		odp_queue_set_pktin(def_cos_entry->s.queue, src_pktio);
	}

	/* set the input pktio for the dst_cos queue */
	odp_queue_set_pktin(cos_entry->s.queue, src_pktio);

	cos_port_info = get_port(cos_entry->s.src_pktio);
	if ((cos_port_info) && (cos_port_info != port_info)) {
		ODP_ERR("dst_cos %"PRIu64" was already set for port %d\n",
			odp_cos_to_u64(dst_cos),
			cos_port_info->p_cfg->fman_if->mac_idx);
		return -1;
	}

	odp_spinlock_lock(&cos_tbl->lock);

	if (pmr_set->s.pktio_in != ODP_PKTIO_INVALID) {
		ODP_ERR("pmr_set_id %"PRIu64" is already set on pktio %"PRIu64" \n",
			odp_pmr_set_to_u64(pmr_set_id),
			odp_pktio_to_u64(pmr_set->s.pktio_in));
		ret = -1;
		goto out;
	}

	pmr_set->s.pktio_in = src_pktio;
	pmr_set->s.dst_cos = dst_cos;
	/* one proto per field => num_proto = num_fields */
	num_protos = pmr_set->s.num_fields;
	for (loop = 0; loop < pmr_set->s.num_fields; loop++) {
		field = pmr_set->s.pmr_set_fields[loop];
		proto[loop] = odp_fields[field].header_type;
		prio[loop] = odp_fields[field].prio;

	}

	/* search if there is a pmr set which contains the compound key
	 * and the proto mask */
	list_for_each_entry(pmr_set_ent, &port_info->pmr_set_list,
			    pmr_set_node) {
		if (((pmr_set_ent->field_mask & pmr_set->s.field_mask) ==
		    pmr_set->s.field_mask) && ((pmr_set_ent->proto_mask &
		    pmr_set->s.proto_mask) == pmr_set->s.proto_mask)) {
			update_pmr_set(pmr_set_ent, &pmr_set->s);
			found = true;
			break;
		}
	}

	if (!found) {
		ret = fm_create_ccnode(&pmr_set->s.ccnode_handle, port_info,
				       pmr_set->s.key_size,
				       &pmr_set->s.cc_param, fqid);
		if (ret) {
			ODP_ERR("Could not create ccnode attached to pmr set %d for port %"PRIu64" \n",
				odp_pmr_set_to_u64(pmr_set_id),
				port_info->p_cfg->fman_if->mac_idx);
			goto out;
		}

		scheme = get_free_scheme(port_info);
		if (odp_unlikely(!scheme)) {
			ODP_ERR("Could not get scheme for pmr set %"PRIu64"  for port %d\n",
				odp_pmr_set_to_u64(pmr_set_id),
				port_info->p_cfg->fman_if->mac_idx);
			ret = -1;
			goto out;
		}

		idx = get_root_id(port_info);
		if (odp_unlikely(idx >= CCTREE_MAX_GROUPS)) {
			ODP_ERR("Maximum number of ccroots reached for port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			ret = -1;
			goto out;
		}

		ret = update_cctree(port_info, pmr_set->s.ccnode_handle, idx,
				    e_FM_PCD_CC);
		if (ret) {
			ODP_ERR("Error updating cctree for port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			goto out;
		}

		pmr_set->s.root_id = idx;
		ret = set_scheme_params(scheme, port_info, fqid,
					num_protos, proto,
					e_FM_PCD_CC, prio,
					pmr_set->s.pmr_set_fields,
					pmr_set->s.num_fields);
		if (ret) {
			ODP_ERR("Could not set scheme params for  port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			goto out;
		}

		scheme->priv.cc_root_handle = pmr_set->s.ccnode_handle;
		set_scheme_cctree(port_info, scheme, pmr_set->s.root_id);
		cc_param.h_CcTree = port_info->tree_handle;
		ret = fm_apply_pcd(port_info, scheme,
				   e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC,
				   &cc_param);
		if (ret) {
			ODP_ERR("Could not apply pcd on  port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			goto out;
		}

		scheme->priv.cc_last_handle = pmr_set->s.ccnode_handle;
		ret = reorder_schemes(port_info);
		if (ret) {
			ODP_ERR("Could not reorder schemes for port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			goto out;
		}
	} else {
		/* check if a new scheme should be created */
		scheme = search_scheme(port_info, pmr_set->s.proto_mask);
		if (!scheme) {
			scheme = get_free_scheme(port_info);
			if (odp_unlikely(!scheme)) {
				ODP_ERR("Could not get scheme for pmr set %"PRIu64" for port %d\n",
					odp_pmr_set_to_u64(pmr_set_id),
					port_info->p_cfg->fman_if->mac_idx);
				ret = -1;
				goto out;
			}
			ret = set_scheme_params(scheme, port_info, fqid,
						num_protos, proto,
						e_FM_PCD_CC, prio,
						pmr_set->s.pmr_set_fields,
						pmr_set->s.num_fields);
			if (ret) {
				ODP_ERR("Could not set scheme params for  port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				goto out;
			}

			scheme->priv.cc_root_handle = pmr_set->s.ccnode_handle;
			set_scheme_cctree(port_info, scheme,
					  pmr_set->s.root_id);
			cc_param.h_CcTree = port_info->tree_handle;
			ret = fm_apply_pcd(port_info, scheme,
					e_FM_PORT_PCD_SUPPORT_PRS_AND_KG_AND_CC,
					&cc_param);
			if (ret) {
				ODP_ERR("Could not apply pcd on  port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				goto out;
			}

			scheme->priv.cc_last_handle = pmr_set->s.ccnode_handle;
			ret = reorder_schemes(port_info);
			if (ret) {
				ODP_ERR("Could not reorder schemes for port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				goto out;
			}
		}
	}

	set_key_index(&pmr_set->s, port_info);
	ret = fm_ccnode_insert_entry(pmr_set->s.key, pmr_set->s.mask,
				     pmr_set->s.key_size,
				     pmr_set->s.key_index,
				     pmr_set->s.ccnode_handle,
				     pmr_set->s.dst_cos);
	if (ret) {
		ODP_ERR("Could not insert key for port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		goto out;
	}

	list_add_tail(&pmr_set->s.pmr_set_node, &port_info->pmr_set_list);
	list_add_tail(&pmr_set->s.pmr_set_src_node,
		      &cos_entry->s.src_match_set_list);

	ret = update_last_cc_miss_act(port_info);
	if (ret) {
		ODP_ERR("Could not update miss action for ccnodes in the current pcd\n");
		goto out;
	}

	if (cos_entry->s.src_pktio == ODP_PKTIO_INVALID)
		cos_entry->s.src_pktio = src_pktio;

	list_for_each_entry(pmr_entry, &cos_entry->s.dst_filter_list,
			    pmr_dst_node) {
		pmr = get_pmr_entry(pmr_entry->pmr_id);
		if (!pmr) {
			ODP_ERR("Cannot get pmr entry\n");
			return -1;
		}
		/*
		 * if the pmr is not a root pmr and was not marked as cascade,
		 * mark it and set its packetio
		 */
		if (pmr->s.root_id == -1) {
			if (!pmr->s.cascade) {
				pmr->s.cascade = true;
				list_add_tail(&pmr->s.pmr_node,
					      &port_info->pmr_list);
				pmr->s.pktio_in = src_pktio;
				dst_cos_entry = get_cos_entry(pmr->s.dst_cos);
				if (!dst_cos_entry) {
					ODP_ERR("Cannot get pmr entry\n");
					return -1;
				}
				if (dst_cos_entry->s.src_pktio ==
				    ODP_PKTIO_INVALID)
					dst_cos_entry->s.src_pktio = src_pktio;
			}
		}
		/*
		 * get the fqid of the pmr_set destination cos and configure
		 * it for miss, in case that traffic will not match the next
		 * pmr
		 */
		queue = queue_to_qentry(cos_entry->s.queue);
		fqid = queue->s.fq.fqid;
		ret = update_pmr_set_ccnode(&pmr_set->s, pmr, port_info, fqid);
		/*
		 * establish the miss action for each pmr that receive traffic
		 * from pmr match set
		 */
		ret = update_pmrs_miss_action(&pmr->s, cos_entry, port_info);
	}
out:
	odp_spinlock_unlock(&cos_tbl->lock);

	return ret;
}

static int odp_pmr_destroy(odp_pmr_t pmr_id)
{
	netcfg_port_info  *port_info = NULL;
	cos_entry_t *dst_cos_entry, *src_cos_entry;
	pmr_entry_t *pmr;
	struct pmr_set_entry *pmr_set_ent;
	queue_entry_t *queue;
	uint32_t fqid = 0;
	int ret = 0;

	pmr = get_pmr_entry(pmr_id);
	if (!pmr) {
		ODP_ERR("Invalid pmr_id %"PRIu64" \n", odp_pmr_to_u64(pmr_id));
		return -1;
	}


	odp_spinlock_lock(&cos_tbl->lock);
	if (!pmr->s.taken) {
		ODP_ERR("Invalid pmr_id %"PRIu64" \n", odp_pmr_to_u64(pmr_id));
		ret = -1;
		goto out;
	}

	src_cos_entry = get_cos_entry(pmr->s.src_cos);
	dst_cos_entry = get_cos_entry(pmr->s.dst_cos);
	if (!dst_cos_entry) {
		odp_spinlock_lock(&pmr->s.lock);

		pmr->s.taken = 0;
		if (src_cos_entry)
			list_del(&pmr->s.pmr_dst_node);

		odp_spinlock_unlock(&pmr->s.lock);
		goto out;
	}

	port_info = get_port(dst_cos_entry->s.src_pktio);
	if (!port_info) {
		odp_spinlock_lock(&pmr->s.lock);

		pmr->s.taken = 0;
		list_del(&pmr->s.pmr_src_node);
		if (src_cos_entry)
			list_del(&pmr->s.pmr_dst_node);

		odp_spinlock_unlock(&pmr->s.lock);
		goto out;
	}

	/*
	 * If pmr was bound to port, entries were inserted.
	 */
	ret = fm_ccnode_remove_entry(pmr->s.ccnode_handle,
				     pmr->s.key_index);
	if (ret) {
		ODP_ERR("Could not remove entry index %d from pmr %"PRIu64" \n",
			pmr->s.key_index, odp_pmr_to_u64(pmr_id));
		goto out;
	}

	update_ccnode_indexes(&pmr->s, port_info, true);
	/*
	 * if this pmr is the only one that uses this ccnode, then remove the
	 * ccnode
	 */
	if (last_ccnode(&pmr->s, port_info, true)) {
		/*
		 * update the ccnodes that pointed to this ccnode
		 * (update also the miss action that points to
		 * this ccnode) then remove the current ccnode
		 */
		ret = update_pmrs_cc_action(pmr->s.ccnode_handle, port_info);
		if (ret) {
			ODP_ERR("Could not update pmr key action\n");
			goto out;
		}
		/*
		 * update all pmrs & pmr_sets ccnodes that have miss action this
		 * ccnode
		 */
		ret = update_ccnodes_miss_act(pmr->s.ccnode_handle, port_info);
		if (ret) {
			ODP_ERR("Could not update miss ccnode action\n");
			goto out;
		}

		ret = fm_modify_cc_miss_act(pmr->s.ccnode_handle, NULL,
					    e_FM_PCD_DONE, 0);
		if (pmr->s.root_id >= 0) {
			ret = fm_delete_scheme(pmr->s.ccnode_handle,
					       port_info);
			if (ret) {
				ODP_ERR("Error deleting scheme for port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				goto out;
			}

			/* remove the ccnode from the cctree */
			ret = update_cctree(port_info, NULL, pmr->s.root_id,
					    e_FM_PCD_DONE);
			if (ret) {
				ODP_ERR("Error updating cctree for port %d\n",
					port_info->p_cfg->fman_if->mac_idx);
				goto out;
			}

			port_info->cc_root[pmr->s.root_id] = 0;
		}
		/*
		 * check if there are pmr_sets that send traffic to the src_cos
		 * and update their action to point to the frame queue
		 * configured on the src_cos.
		 */
		if (src_cos_entry) {
			/*
			 * get the fqid of the pmr_set destination cos and
			 * configure it for miss, in case that traffic will not
			 * match the next pmr
			 */
			queue = queue_to_qentry(src_cos_entry->s.queue);
			fqid = queue->s.fq.fqid;
			list_for_each_entry(pmr_set_ent,
					   &src_cos_entry->s.src_match_set_list,
					   pmr_set_src_node) {
				ret = update_pmr_set_ccnode(pmr_set_ent, NULL,
							    NULL, fqid);
				if (ret) {
					ODP_ERR("Could not update pmr_set  %"PRIu64" \n",
						odp_pmr_set_to_u64(
						      pmr_set_ent->pmr_set_id));
					goto out;
				}
			}
		}

		ret = fm_delete_ccnode(pmr->s.ccnode_handle);
		if (ret) {
			ODP_ERR("Could not delete ccnode for pmr %"PRIu64" \n",
				odp_pmr_to_u64(pmr_id));
			goto out;
		}
		ODP_DBG("Deleted ccnode bound to port\n");

	}

	odp_spinlock_lock(&pmr->s.lock);
	/* remove the pmr from the pmr port list */
	list_del(&pmr->s.pmr_node);
	list_del(&pmr->s.pmr_src_node);
	pmr->s.taken = 0;
	if (src_cos_entry)
		list_del(&pmr->s.pmr_dst_node);

	odp_spinlock_unlock(&pmr->s.lock);
out:
	odp_spinlock_unlock(&cos_tbl->lock);

	return ret;
}

static int odp_pmr_match_set_destroy(odp_pmr_set_t pmr_set_id)
{
	netcfg_port_info  *port_info = NULL;
	pmr_set_entry_t *pmr_set;
	int ret = 0;

	pmr_set = get_pmr_set_entry(pmr_set_id);
	if (!pmr_set) {
		ODP_ERR("Invalid pmr_set_id %"PRIu64" \n",
			odp_pmr_set_to_u64(pmr_set_id));
		return -1;
	}

	odp_spinlock_lock(&cos_tbl->lock);
	if (!pmr_set->s.taken) {
		ODP_ERR("Invalid pmr_set_id %"PRIu64" \n",
			odp_pmr_set_to_u64(pmr_set_id));
		ret = -1;
		goto out;
	}

	port_info = get_port(pmr_set->s.pktio_in);
	if (!port_info) {
		pmr_set->s.taken = 0;
		goto out;
	}

	if (pmr_set->s.key_index == -1)
		goto out_release;

	ret = fm_ccnode_remove_entry(pmr_set->s.ccnode_handle,
				     pmr_set->s.key_index);
	if (ret) {
		ODP_ERR("Could not remove entry index %d from pmr_set_id %"PRIu64" \n",
			pmr_set->s.key_index, odp_pmr_set_to_u64(pmr_set_id));
		odp_spinlock_unlock(&port_info->lock);
		goto out;
	}

	update_ccnode_indexes(&pmr_set->s, port_info, false);
	/*
	 * if this pmr set is the only one that uses this ccnode, then remove the
	 * ccnode
	 */
	if (last_ccnode(&pmr_set->s, port_info, false)) {
		/*
		 * update all pmrs & pmr_sets ccnodes that have miss action this
		 * ccnode
		 */
		ret = update_ccnodes_miss_act(pmr_set->s.ccnode_handle,
					      port_info);
		if (ret) {
			ODP_ERR("Could not update miss ccnode action\n");
			goto out;
		}

		ret = fm_delete_scheme(pmr_set->s.ccnode_handle, port_info);
		if (ret) {
			ODP_ERR("Error deleting scheme for port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			goto out;
		}

		/* remove the ccnode from the cctree */
		ret = update_cctree(port_info, NULL, pmr_set->s.root_id,
				    e_FM_PCD_DONE);
		if (ret) {
			ODP_ERR("Error updating cctree for port %d\n",
				port_info->p_cfg->fman_if->mac_idx);
			goto out;
		}

		port_info->cc_root[pmr_set->s.root_id] = 0;
		ret = fm_delete_ccnode(pmr_set->s.ccnode_handle);
		if (ret) {
			ODP_ERR("Could not delete ccnode for pmr set %"PRIu64" \n",
				odp_pmr_set_to_u64(pmr_set_id));
			goto out;
		}

		ODP_DBG("Deleted ccnode bound to port\n");
	}

	/* remove the pmr from the pmr port list */
	list_del(&pmr_set->s.pmr_set_node);
	/* remove the pmr set from the src_match_set_list */
	list_del(&pmr_set->s.pmr_set_src_node);
out_release:
	pmr_set->s.taken = 0;
out:
	odp_spinlock_unlock(&cos_tbl->lock);
	return ret;
}

static inline int fm_ccnode_set_drop(t_Handle ccnode_handle, int key_index)
{
	t_FmPcdCcNextEngineParams next_engine;
	int ret = 0;

	memset(&next_engine, 0, sizeof(next_engine));
	next_engine.statisticsEn = 1;

	next_engine.nextEngine = e_FM_PCD_DONE;
	next_engine.params.enqueueParams.action = e_FM_PCD_DROP_FRAME;
	ret = FM_PCD_MatchTableModifyNextEngine(ccnode_handle, key_index,
						&next_engine);
	if (ret) {
		ODP_ERR("Could not modify entry %d in ccnode %p\n",
			key_index, ccnode_handle);
		return ret;
	}

	return 0;
}

int odp_cos_destroy(odp_cos_t cos_id)
{
	cos_entry_t *cos;
	netcfg_port_info  *port_info = NULL;
	struct pmr_entry *pmr = NULL;
	struct pmr_set_entry *pmr_set = NULL;
	int ret = 0, i;

	cos = get_cos_entry(cos_id);
	if (!cos) {
		ODP_ERR("Invalid  cos_id %"PRIu64" \n",
			odp_cos_to_u64(cos_id));
		return -1;
	}

	odp_spinlock_lock(&cos_tbl->lock);

	if (!cos->s.taken) {
		ODP_ERR("Invalid  cos_id %"PRIu64" \n",
			odp_cos_to_u64(cos_id));
		ret = -1;
		goto out;
	}

	if (!list_empty(&cos->s.src_filter_list)) {
		list_for_each_entry(pmr, &cos->s.src_filter_list,
				    pmr_src_node) {
			ODP_DBG("Updating pmr %"PRIu64" that has target cos %"PRIu64" \n",
				odp_pmr_to_u64(pmr->pmr_id),
				odp_cos_to_u64(cos_id));
			ret = fm_ccnode_set_drop(pmr->ccnode_handle,
						 pmr->key_index);
			if (ret)
				goto out;
		}
	}

	if (!list_empty(&cos->s.dst_filter_list)) {
		list_for_each_entry(pmr, &cos->s.dst_filter_list,
				    pmr_dst_node) {
			ODP_DBG("Updating pmr %"PRIu64" that has source cos %"PRIu64" \n",
				odp_pmr_to_u64(pmr->pmr_id),
				odp_cos_to_u64(cos_id));
			ret = fm_ccnode_set_drop(pmr->ccnode_handle,
						 pmr->key_index);
			if (ret)
				goto out;
		}
	}

	if (!list_empty(&cos->s.src_match_set_list)) {
		list_for_each_entry(pmr_set, &cos->s.src_match_set_list,
				    pmr_set_src_node) {
			ODP_DBG("Updating pmr set %"PRIu64" that has target cos %"PRIu64" \n",
				odp_pmr_set_to_u64(pmr_set->pmr_set_id),
				odp_cos_to_u64(cos_id));
			ret = fm_ccnode_set_drop(pmr_set->ccnode_handle,
						 pmr_set->key_index);
			if (ret)
				goto out;
		}
	}

	/* if the cos belongs to a l2 or l3 pri, update the coresponding
	 * entries */
	for (i = 0; i < ODP_COS_MAX_L2_QOS; i++) {
		if (l2_cos[i] == cos_id) {
			port_info = get_port(cos->s.src_pktio);
			if (!port_info) {
				ODP_ERR("Could not get port_info for cos %"PRIu64" \n",
					odp_cos_to_u64(cos->s.cos_id));
				ret = -1;
				goto out;
			}

			ret = fm_ccnode_set_drop(
					port_info->l2_vpri->priv.cc_root_handle,
					i);
			if (ret)
				goto out;
		}
	}

	for (i = 0; i < ODP_COS_MAX_L3_QOS; i++) {
		if (l3_cos[i] == cos_id) {
			port_info = get_port(cos->s.src_pktio);
			if (!port_info) {
				ODP_ERR("Could not get port_info for cos %"PRIu64" \n",
					odp_cos_to_u64(cos->s.cos_id));
				ret = -1;
				goto out;
			}

			ret = fm_ccnode_set_drop(
					port_info->l3_dscp->priv.cc_root_handle,
					i);
			if (ret)
				goto out;
		}
	}

	cos->s.taken = 0;
out:
	odp_spinlock_unlock(&cos_tbl->lock);
	return ret;
}

int odp_pktio_skip_set(odp_pktio_t pktio_in, uint32_t offset)
{
	netcfg_port_info  *port_info = NULL;
	t_FmPcdPrsStart params;
	int ret = 0;

	port_info = get_port(pktio_in);
	if (!port_info) {
		ODP_ERR("Invalid pktio_in %"PRIu64" \n", odp_pktio_to_u64(pktio_in));
		return -1;
	}

	odp_spinlock_lock(&port_info->lock);

	ret = FM_PORT_DetachPCD(port_info->port_handle);
	if (ret) {
		ODP_ERR("Could not detach PCD from port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		goto out;
	}


	memset(&params, 0, sizeof(params));

	params.parsingOffset = offset;
	params.firstPrsHdr = HEADER_TYPE_ETH;

	ret = FM_PORT_AttachPCD(port_info->port_handle);
	if (ret) {
		ODP_ERR("Could not attach PCD to port %d\n",
			port_info->p_cfg->fman_if->mac_idx);
		goto out;
	}

out:
	odp_spinlock_unlock(&port_info->lock);

	return ret;
}

int odp_pktio_error_cos_set(odp_pktio_t pktio_in, odp_cos_t error_cos)
{
	cos_entry_t *cos_entry;
	pktio_entry_t *pktio_entry;
	queue_entry_t *queue;
	uint32_t fqid;
	struct fman_if *__if;

	cos_entry = get_cos_entry(error_cos);
	if (!cos_entry)
		return -1;

	pktio_entry = get_pktio_entry(pktio_in);
	if (!pktio_entry)
		return -1;


	odp_spinlock_lock(&cos_tbl->lock);

	if (pktio_entry->s.error_cos != ODP_COS_INVALID) {
		ODP_ERR("Error cos (%"PRIu64" ) already set on pktio %"PRIu64" \n",
			odp_cos_to_u64(pktio_entry->s.error_cos),
			odp_pktio_to_u64(pktio_in));
		odp_spinlock_unlock(&cos_tbl->lock);
		return -1;
	}

	queue = queue_to_qentry(cos_entry->s.queue);
	fqid = queue->s.fq.fqid;
	/* set the input pktio for the error cos queue */
	odp_queue_set_pktin(cos_entry->s.queue, pktio_in);
	__if = pktio_entry->s.__if;
	fman_if_set_err_fqid(__if, fqid);
	cos_entry->s.is_error = true;
	cos_entry->s.src_pktio = pktio_in;
	list_add_tail(&pktio_entry->s.err_cos_node, &cos_entry->s.err_cos_list);
	pktio_entry->s.error_cos = error_cos;

	odp_spinlock_unlock(&cos_tbl->lock);
	return 0;
}

int odp_pktio_headroom_set(odp_pktio_t pktio_in, uint32_t  headroom)
{
	(void)pktio_in;
	(void)headroom;

	ODP_UNIMPLEMENTED();

	return -1;
}

#if 0
static unsigned odp_pmr_terms_avail(void)
{
	uint32_t count = 0;
	int i;

	odp_spinlock_lock(&cos_tbl->lock);
	for (i = 0; i < ODP_PMR_MAX_ENTRY; i++) {
		odp_spinlock_lock(&pmr_pool->pmr[i].s.lock);

		if (!pmr_pool->pmr[i].s.taken)
			count++;

		odp_spinlock_unlock(&pmr_pool->pmr[i].s.lock);
	}


	odp_spinlock_unlock(&cos_tbl->lock);
	return count;
}

static unsigned long long odp_pmr_terms_cap(void)
{
	int field;
	unsigned long long field_mask = 0;

	for (field = 0; field < ODP_PMR_MAX_FIELDS; field++) {
		if (is_supported(field)) {
			field_mask |= (1ULL << field);
		}
	}

	return field_mask;
}
#endif

int odp_cos_drop_set(odp_cos_t cos_id, odp_cls_drop_t drop_policy)
{
	(void)cos_id;
	(void)drop_policy;

	ODP_UNIMPLEMENTED();

	return -1;
}

int odp_cls_cos_pool_set(odp_cos_t cos_id ODP_UNUSED, odp_pool_t pool_id ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}

/* clean all left pmrs, l2 & l3 priority pmrs, default scheme */
static int odp_classification_term(netcfg_port_info  *port_info)
{
	int err = 0;
	struct pmr_entry *pmr;
	struct pmr_set_entry *pmr_set;
	struct scheme_info *scheme_p;
	t_FmPcdPortSchemesParams params;
	int idx;

	list_for_each_entry(pmr, &port_info->pmr_list, pmr_node) {
		err |= odp_pmr_destroy(pmr->pmr_id);
		if (err)
			ODP_ERR("Could destroy pmr (%"PRIu64" ). Error (%d)\n",
				odp_pmr_to_u64(pmr->pmr_id), err);
	}

	list_for_each_entry(pmr_set, &port_info->pmr_set_list, pmr_set_node) {
		err |= odp_pmr_match_set_destroy(pmr_set->pmr_set_id);
		if (err)
			ODP_ERR("Could destroy pmr_set_id (%"PRIu64" ). Error (%d)\n\n",
				odp_pmr_set_to_u64(pmr_set->pmr_set_id), err);
	}

	list_for_each_entry(scheme_p, &port_info->scheme_list, scheme_node) {
		if (scheme_p->priv.is_default) {
			memset(&params, 0, sizeof(params));
			params.numOfSchemes = 1;
			params.h_Schemes[0] = scheme_p->handle;
			err |= FM_PORT_PcdKgUnbindSchemes(
							 port_info->port_handle,
							 &params);
			if (err)
				ODP_ERR("Could not unbind scheme %p\n",
					 scheme_p);

			err |= FM_PCD_KgSchemeDelete(scheme_p->handle);
			if (err)
				ODP_ERR("Could not delete scheme %p for port %d. Error (%d)\n",
					scheme_p,
					port_info->p_cfg->fman_if->mac_idx,
					err);
		}

		if (scheme_p == port_info->l2_vpri ||
		    scheme_p == port_info->l3_dscp) {
			memset(&params, 0, sizeof(params));
			params.numOfSchemes = 1;
			params.h_Schemes[0] = scheme_p->handle;
			err |= FM_PORT_PcdKgUnbindSchemes(
							 port_info->port_handle,
							 &params);
			if (err)
				ODP_ERR("Could not unbind scheme %p\n",
					 scheme_p);

			err |= FM_PCD_KgSchemeDelete(scheme_p->handle);
			if (err)
				ODP_ERR("Could not delete scheme %p for port %d. Error (%d)\n\n",
					scheme_p,
					port_info->p_cfg->fman_if->mac_idx,
					err);

			if (scheme_p == port_info->l2_vpri)
				idx = scheme_p->priv.l2_root_id;
			else
				idx = scheme_p->priv.l3_root_id;
			/* remove the ccnode from the cctree */
			err |= update_cctree(port_info, NULL, idx,
					    e_FM_PCD_DONE);
			err |= fm_delete_ccnode(scheme_p->priv.cc_root_handle);
			if (err)
				ODP_ERR("Could not delete root cc for port %d. Error (%d)\n",
					port_info->p_cfg->fman_if->mac_idx,
					err);
		}
	}
	return err;
}

int  odp_classification_term_global(void)
{
	int i, ret = 0;
	struct fm_eth_port_cfg *port_cfg;
	netcfg_port_info  *port_info;
	t_Handle net_env;

	ODP_DBG("odp_classification_term_global\n");

	/* PCD disable */
	for (i = 0; i < FMAN_COUNT; i++) {
		if (cos_tbl->pcd_handle[i]) {
			ret |= FM_PCD_Disable(cos_tbl->pcd_handle[i]);
			if (ret)
				ODP_ERR("Could not disable fman pcd (%d)\n",
					ret);
		}
	}
	/*
	 * for each port  delete ccnodes & schemes, delete the pcd,
	 * delete cctree, delete the netenv, close the port.
	 */
	for (i = 0; i < netcfg->num_ethports; i++) {
		port_cfg = &netcfg->port_cfg[i];
		port_info = pktio_get_port_info(port_cfg->fman_if);
		net_env = port_info->net_env_set;

		if (!list_empty(&port_info->scheme_list))
			ret = odp_classification_term(port_info);

		ret |= FM_PORT_DeletePCD(port_info->port_handle);
		if (ret)
			ODP_ERR("Could not delete pcd from port %d\n",
				port_info->p_cfg->fman_if->mac_idx);

		ret |= FM_PCD_CcRootDelete(port_info->tree_handle);
		if (ret)
			ODP_ERR("Could not delete cctree for port %d\n",
				port_info->p_cfg->fman_if->mac_idx);

		ret |= FM_PCD_NetEnvCharacteristicsDelete(net_env);
		if (ret)
			ODP_ERR("Could not delete net env for port %d\n",
				port_info->p_cfg->fman_if->mac_idx);

		FM_PORT_Close(port_info->port_handle);
	}

	/* close the pcd and port handles */
	for (i = 0; i < FMAN_COUNT; i++) {
		if (cos_tbl->pcd_handle[i]) {
			FM_PCD_Close(cos_tbl->pcd_handle[i]);
			cos_tbl->pcd_handle[i] = NULL;
		}
		if (cos_tbl->fman_handle[i]) {
			FM_Close(cos_tbl->fman_handle[i]);
			cos_tbl->fman_handle[i] = NULL;
		}
	}

	if (ret)
		return -1;
	else
		return 0;
}

void odp_cls_cos_param_init(odp_cls_cos_param_t *param)
{
	param->queue = ODP_QUEUE_INVALID;
	param->pool = ODP_POOL_INVALID;
	param->drop_policy = ODP_COS_DROP_NEVER;
}

void odp_cls_pmr_param_init(odp_pmr_param_t *param)
{
	memset(param, 0, sizeof(odp_pmr_param_t));
}

odp_pmr_t odp_cls_pmr_create(const odp_pmr_param_t *terms, int num_terms,
			     odp_cos_t src_cos, odp_cos_t dst_cos)
{
	odp_pmr_t pmr;
	odp_pmr_set_t pmr_set_id = _odp_cast_scalar(odp_pmr_set_t, 0);
	int32_t retcode;
	cos_entry_t *cos;

	cos = get_cos_entry(src_cos);
	if (!cos) {
		ODP_ERR("Invalid odp_cos_t handle");
		return ODP_PMR_INVAL;
	}
	if (num_terms > 1) {
		retcode = odp_pmr_match_set_create(num_terms, terms, &pmr_set_id);
		if (retcode < 0)
			return ODP_PMR_INVAL;
		retcode = odp_pktio_pmr_match_set_cos(pmr_set_id, cos->s.src_pktio, dst_cos);
		if (retcode < 0)
			return ODP_PMR_INVAL;
		return (odp_pmr_t)pmr_set_id;
	} else {
		pmr = odp_pmr_create(terms);
		retcode = odp_pktio_pmr_cos(pmr, cos->s.src_pktio, dst_cos);
		if (retcode < 0)
			return ODP_PMR_INVAL;
		return pmr;
	}
}

int odp_cls_pmr_destroy(odp_pmr_t pmr_id)
{
	pmr_entry_t *pmr;

	pmr = get_pmr_entry(pmr_id);
	if (!pmr) {
		ODP_ERR("Invalid odp_pmr_t handle");
		return -1;
	}
	return odp_pmr_destroy((odp_pmr_t)pmr_id);
}

odp_pool_t odp_cls_cos_pool(odp_cos_t cos_id ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return ODP_POOL_INVALID;
}

odp_queue_t odp_cos_queue(odp_cos_t cos_id ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return ODP_QUEUE_INVALID;
}

int odp_cls_capability(odp_cls_capability_t *capability ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return -1;
}

odp_cls_drop_t odp_cos_drop(odp_cos_t cos_id ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}
