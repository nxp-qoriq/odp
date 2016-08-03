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
 * ODP Classification Datamodel
 * Describes the classification internal data model
 */

#ifndef ODP_CLASSIFICATION_DATAMODEL_H_
#define ODP_CLASSIFICATION_DATAMODEL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/spinlock.h>
#include <odp/api/classification.h>
#include <odp_pool_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_queue_internal.h>
#include <fsl_dpni.h>
#include <dpaa2_queue.h>

/* Maximum Class Of Service Entry */
#define ODP_COS_MAX_ENTRY		64
/* Maximum PMR Set Entry */
#define ODP_PMRSET_MAX_ENTRY		64
/* Maximum PMR Entry */
#define ODP_PMR_MAX_ENTRY		64
/* Maximum PMR Terms in a PMR Set */
#define ODP_PMRTERM_MAX			8
/* Maximum PMRs attached in PKTIO Level */
#define ODP_PKTIO_MAX_PMR		8
/* L2 Priority Bits */
#define ODP_COS_L2_QOS_BITS		3
/* Max L2 QoS value */
#define ODP_COS_MAX_L2_QOS		(1 << ODP_COS_L2_QOS_BITS)
/* L2 DSCP Bits */
#define ODP_COS_L3_QOS_BITS		6
/* Max L3 QoS Value */
#define ODP_COS_MAX_L3_QOS		(1 << ODP_COS_L3_QOS_BITS)
/* Max PMR Term bits */
#define ODP_PMR_TERM_BYTES_MAX		8

/**
Packet Matching Rule Term Value

Stores the Term and Value mapping for a PMR.
The maximum size of value currently supported in 64 bits
**/
typedef struct pmr_term_value {
	odp_cls_pmr_term_t  term;	/**< PMR Term */
	uint64_t	val;	/**< Value to be matched */
	uint64_t	mask;	/**< Masked set of bits to be matched */
} pmr_term_value_t;

/*
Class Of Service
*/
struct cos_s {
	queue_entry_t	*queue;		/* Associated Target Queue*/
	union pmr_u	*next_pmr;	/* Next PMR table if chained PMR is
						configured, NULL Otherwise*/
	union cos_u	*next_cos;	/* CoS linked with the PMR */
	char		name[ODP_COS_NAME_LEN];
					/* CoS name. Must be globally unique*/
	bool		used;	/* Flag to define whether entry is in use
					or not*/
	uint8_t		tc_id;	/*Traffic Class ID which is mapped at H/W*/
	odp_spinlock_t	lock;	/* cos lock */
	odp_cls_cos_param_t param; /*User configured CoS parameters*/
	odp_pktio_t pktio_in;	/*Input pktio device*/
};

typedef union cos_u {
	struct cos_s s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct cos_s))];
} cos_t;


/**
Packet Matching Rule

**/
struct pmr_s {
	bool			valid;		/* Validity Flag */
	uint32_t		num_pmr;	/* Number of PMR*/
	odp_spinlock_t		lock;		/* pmr lock*/
	pmr_term_value_t	term_value[1];	/* Associated PMR Term */
	uint32_t		pos[1];		/* Position of PMR in pmr_info*/
	struct dpni_rule_cfg	rule;		/*H/W Specific rule strcuture*/
};

typedef union pmr_u {
	struct pmr_s s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pmr_s))];
} pmr_t;

/**
Packet Matching Rule Set

This structure is implemented as a extension over struct pmr_s
In order to use same pointer to access both pmr_s and pmr_set_s
'num_pmr' value is used to differentiate between pmr_s and pmr_set_s struct
**/
struct pmr_set_s {
	bool			valid;	/* Validity Flag */
	uint32_t		num_pmr;/*Number of PMR*/
	odp_spinlock_t		lock;	/* pmr lock*/
	pmr_term_value_t	term_value[ODP_PMRTERM_MAX];
				/* List of associated PMR Terms */
	uint32_t		pos[ODP_PMRTERM_MAX];
				/*Position array of PMR in pmr_info[]*/
	struct dpni_rule_cfg	rule;	/*H/W Specific rule strcuture*/
};

typedef union pmr_set_u {
	struct pmr_set_s s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pmr_set_s))];
} pmr_set_t;

/**
L2 QoS and CoS Map

This structure holds the mapping between L2 QoS value and
corresponding cos_t object
**/
typedef struct pmr_l2_cos {
	odp_spinlock_t lock;	/* pmr_l2_cos lock */
	cos_t *cos[ODP_COS_MAX_L2_QOS];	/* Array of CoS objects */
} pmr_l2_cos_t;

/**
L3 QoS and CoS Map

This structure holds the mapping between L3 QoS value and
corresponding cos_t object
**/
typedef struct pmr_l3_cos {
	odp_spinlock_t lock;	/* pmr_l3_cos lock */
	cos_t *cos[ODP_COS_MAX_L3_QOS];	/* Array of CoS objects */
} pmr_l3_cos_t;

/**
Linux Generic Classifier

This structure is stored in pktio_entry and holds all
the classifier configuration value.
**/
typedef struct classifier {
	odp_spinlock_t lock;		/* pktio_cos lock */
	uint32_t num_pmr;		/* num of PMRs linked to given PKTIO*/
	pmr_t *pmr[ODP_PKTIO_MAX_PMR];	/* PMRs linked with this PKTIO */
	cos_t *cos[ODP_PKTIO_MAX_PMR];	/* CoS linked with this PKTIO */
	cos_t *error_cos;		/* Associated Error CoS */
	cos_t *default_cos;		/* Associated Default CoS */
	uint32_t l3_precedence;		/* L3 QoS precedence */
	pmr_l2_cos_t l2_cos_table;	/* L2 QoS-CoS table map */
	pmr_l3_cos_t l3_cos_table;	/* L3 Qos-CoS table map */
	odp_cos_flow_set_t flow_set;	/* Flow Set to be calculated
					for this pktio */
	size_t skip;			/* Pktio Skip Offset */
	uint16_t flow_id;               /*Flow ID to be used for classfication*/
	struct dpni_rx_tc_dist_cfg tc_cfg; /*Platform dependent classification*/
} classifier_t;

/**
Class of Service Table
**/
typedef struct odp_cos_table {
	cos_t cos_entry[ODP_COS_MAX_ENTRY];
} cos_tbl_t;

/**
PMR set table
**/
typedef struct pmr_set_tbl {
	pmr_set_t pmr_set[ODP_PMRSET_MAX_ENTRY];
} pmr_set_tbl_t;

/**
PMR table
**/
typedef struct pmr_tbl {
	pmr_t pmr[ODP_PMR_MAX_ENTRY];
} pmr_tbl_t;

typedef enum exact_match_rule_type {
	EXACT_MATCH_RULE_PMR = 1,/*Type for PMR/PMR set based exact match rule*/
	EXACT_MATCH_RULE_L2,	/*Type for L2 prio based exact match rule*/
	EXACT_MATCH_RULE_L3	/*Type for L3 prio based exact match rule*/
} exact_match_rule_type_t;

struct exact_match_rule {
	TAILQ_ENTRY(exact_match_rule)	next; /*!< Next in list.*/
	uint8_t			tc_id;
	uint8_t			type;
	uint16_t		flow_id;
	struct dpni_rule_cfg	*rule;
};

/**
List of rules offloaded to hardware
**/
TAILQ_HEAD(rule, exact_match_rule);

#ifdef __cplusplus
}
#endif
#endif
