/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/classification.h>
#include <odp/api/align.h>
#include <odp/api/queue.h>
#include <odp/api/debug.h>
#include <odp_config_internal.h>
#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <odp_packet_internal.h>
#include <odp/api/packet_io.h>
#include <odp/api/byteorder.h>
#include <odp_packet_io_internal.h>
#include <odp_classification_datamodel.h>
#include <odp_classification_internal.h>
#include <odp_schedule_internal.h>
#include <odp_pool_internal.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_eth_priv.h>
#include <dpaa2_conc_priv.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_queue.h>
#include <dpaa2_vq.h>
#include <odp/api/shared_memory.h>
#include <odp/helper/eth.h>
#include <string.h>
#include <odp/api/spinlock.h>
#include <odp/api/hints.h>
#include <fsl_dpcon.h>
#include <fsl_dpni.h>
#include <fsl_dpkg.h>
#include <fsl_mc_sys.h>

#define CLS_LOCK(a)      odp_spinlock_lock(a)
#define CLS_UNLOCK(a)    odp_spinlock_unlock(a)
#define CLS_LOCK_INIT(a)	odp_spinlock_init(a)

static cos_tbl_t	*cos_tbl;
static pmr_tbl_t	*pmr_tbl;
static pmr_set_tbl_t	*pmr_set_tbl;

/*
 * Global index to define the next free location in pmr_info where extract type
 * value cab be added.
 */
uint32_t pmr_index;
/*
 * Global index to define maximum length of key extracted by the underlying
 * layer. It will be addeed with the length to the pmr type i.e. if pmr type
 * is ODP_PMR_UDP_DPORT then this will added with 2 bytes(size of UDP
 * destination port).
 *
 */
#define ODP_L2_PRIO_KEY_LEN	2
#define ODP_L3_DSCP_KEY_LEN	1
static uint32_t key_cfg_len = ODP_L2_PRIO_KEY_LEN + ODP_L3_DSCP_KEY_LEN;
/*
 * Global debug flag to enable/disable printing of rules
 */
static uint32_t print_rules;
/*
 * It is a local database which is used to configure key extract paramters
 * at underlying layer. Maximum 8 paramter can be updated.
 */
pmr_info_t pmr_info[DPKG_MAX_NUM_OF_EXTRACTS] = {
						{0, 0, 0xFFFF}, {0, 0, 0xFFFF},
						{0, 0, 0xFFFF}, {0, 0, 0xFFFF},
						{0, 0, 0xFFFF}, {0, 0, 0xFFFF},
						{0, 0, 0xFFFF}, {0, 0, 0xFFFF}
						};

/*Global list of rules configured at hardware*/
static struct rule pmr_rule_list[ODP_CONFIG_PKTIO_ENTRIES];
static struct rule l2_rule_list[ODP_CONFIG_PKTIO_ENTRIES];
static struct rule l3_rule_list[ODP_CONFIG_PKTIO_ENTRIES];

extern void *dpaa2_eth_cb_dqrr_fd_to_mbuf(
		struct qbman_swp *qm,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr);

cos_t *get_cos_entry_internal(odp_cos_t cos_id)
{
	return &(cos_tbl->cos_entry[_odp_typeval(cos_id)]);
}

pmr_set_t *get_pmr_set_entry_internal(odp_pmr_set_t pmr_set_id)
{
	return &(pmr_set_tbl->pmr_set[_odp_typeval(pmr_set_id)]);
}

pmr_t *get_pmr_entry_internal(odp_pmr_t pmr_id)
{
	return &(pmr_tbl->pmr[_odp_typeval(pmr_id)]);
}

static int32_t odp_offload_rules(odp_pktio_t pktio)
{
	pktio_entry_t *entry;
	struct exact_match_rule	*fs_rule;
	int32_t	retcode;
	uint32_t index = (uint64_t)pktio - 1;
	struct dpaa2_dev		*dev;
	struct dpaa2_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;
	uint16_t	idx = 0;
	struct dpni_fs_action_cfg action_cfg;

	/*Get pktio entry where rules are to be applied*/
	entry = get_pktio_entry(pktio);
	if (!entry) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}

	dev = entry->s.pkt_dpaa2.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;

	memset(&action_cfg, 0, sizeof(struct dpni_fs_action_cfg));
	/*Add all the Classification rules at underlying platform*/
	TAILQ_FOREACH(fs_rule, &pmr_rule_list[index], next) {
		fs_rule->rule->key_size = key_cfg_len;
		action_cfg.flow_id = fs_rule->flow_id;
		retcode = dpni_add_fs_entry(dpni, CMD_PRI_LOW, dev_priv->token,
					    fs_rule->tc_id, idx,
					    fs_rule->rule, &action_cfg);
		if (retcode < 0)
			goto pmr_add_failure;
		idx++;
	}
	if (entry->s.cls.l3_precedence) {
		TAILQ_FOREACH(fs_rule, &l3_rule_list[index], next) {
			fs_rule->rule->key_size = key_cfg_len;
			action_cfg.flow_id = fs_rule->flow_id;
			retcode = dpni_add_fs_entry(dpni, CMD_PRI_LOW,
						    dev_priv->token,
							fs_rule->tc_id, idx,
					fs_rule->rule, &action_cfg);
			if (retcode < 0)
				goto l3_rule_add_failure;
			idx++;
		}
		TAILQ_FOREACH(fs_rule, &l2_rule_list[index], next) {
			fs_rule->rule->key_size = key_cfg_len;
			action_cfg.flow_id = fs_rule->flow_id;
			retcode = dpni_add_fs_entry(dpni, CMD_PRI_LOW,
						    dev_priv->token,
							fs_rule->tc_id, idx,
					fs_rule->rule, &action_cfg);
			if (retcode < 0)
				goto l2_rule_add_failure;
			idx++;
		}
	} else {
		TAILQ_FOREACH(fs_rule, &l2_rule_list[index], next) {
			fs_rule->rule->key_size = key_cfg_len;
			action_cfg.flow_id = fs_rule->flow_id;
			retcode = dpni_add_fs_entry(dpni, CMD_PRI_LOW,
						    dev_priv->token,
							fs_rule->tc_id, idx,
					fs_rule->rule, &action_cfg);
			if (retcode < 0)
				goto l2_rule_add_failure;
			idx++;
		}
		TAILQ_FOREACH(fs_rule, &l3_rule_list[index], next) {
			fs_rule->rule->key_size = key_cfg_len;
			action_cfg.flow_id = fs_rule->flow_id;
			retcode = dpni_add_fs_entry(dpni, CMD_PRI_LOW,
						    dev_priv->token,
							fs_rule->tc_id, idx,
					fs_rule->rule, &action_cfg);
			if (retcode < 0)
				goto l3_rule_add_failure;
			idx++;
		}
	}
	return 0;

pmr_add_failure:
		ODP_DBG("Error in adding PMR to underlying hardware\n");
		return retcode;
l2_rule_add_failure:
		ODP_DBG("Error in adding l2 rule to underlying hardware\n");
		return retcode;
l3_rule_add_failure:
		ODP_DBG("Error in adding l3 rule to underlying hardware\n");
		return retcode;
}

static void odp_configure_l2_prio_rule(pktio_entry_t *pktio ODP_UNUSED,
				       pmr_t *pmr)
{
	uint8_t i, offset = 0;
	uint8_t *stream, *mask;
	uint8_t	size = 2;

	for (i = 0; pmr_info[i].is_valid; i++)
		offset = offset + pmr_info[i].size;

	/*Write rules on iova memory to be configured*/
	stream = (uint8_t *)(pmr->s.rule.key_iova + offset);
	mask = (uint8_t *)(pmr->s.rule.mask_iova + offset);

	memcpy((void *)stream, (void *)(pmr->s.term_value[0].val), size);
	memcpy((void *)mask, (void *)(pmr->s.term_value[0].mask), size);
	pmr->s.rule.key_size = key_cfg_len;
}

static void odp_configure_l3_prio_rule(pktio_entry_t *pktio ODP_UNUSED,
				       pmr_t *pmr)
{
	uint8_t i, offset = 0;
	uint8_t *stream, *mask;
	uint8_t	size = 1;

	for (i = 0; pmr_info[i].is_valid; i++)
		offset = offset + pmr_info[i].size;
	offset = offset + 2;

	/*Write rules on iova memory to be configured*/
	stream = (uint8_t *)(pmr->s.rule.key_iova + offset);
	mask = (uint8_t *)(pmr->s.rule.mask_iova + offset);

	memcpy(stream, (void *)(pmr->s.term_value[0].val), size);
	memcpy(mask, (void *)(pmr->s.term_value[0].mask), size);
	pmr->s.rule.key_size = key_cfg_len;
}

static void odp_insert_exact_match_rule(odp_pktio_t pktio,
					struct exact_match_rule *fs_rule)
{
	pktio_entry_t *pktio_entry;
	uint64_t idx = ((uint64_t)pktio - 1);

	pktio_entry = get_pktio_entry(pktio);
	if (!pktio_entry) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return;
	}

	switch (fs_rule->type) {
	case EXACT_MATCH_RULE_PMR:
		/*Insert at last into rule_list1*/
		TAILQ_INSERT_TAIL(&pmr_rule_list[idx], fs_rule, next);
		break;
	case EXACT_MATCH_RULE_L2:
		/*Insert at last into rule_list2*/
		TAILQ_INSERT_TAIL(&l2_rule_list[idx], fs_rule, next);
		break;
	case EXACT_MATCH_RULE_L3:
		/*Insert at last into rule_list3*/
		TAILQ_INSERT_TAIL(&l3_rule_list[idx], fs_rule, next);
		break;
	default:
		ODP_ERR("Invalid exact rule type = %d\n", fs_rule->type);
		break;
	}
}

static void print_all_rule_list(uint64_t pktio_idx)
{
	uint8_t *temp;
	struct exact_match_rule *temp_rule;
	uint32_t i = 0;

	/*Add all the Classification rules at underlying platform*/
	printf("Packet Matching rules information:\n");
	printf("======================Start PMR======================\n");
	TAILQ_FOREACH(temp_rule, &pmr_rule_list[pktio_idx], next) {
		temp_rule->rule->key_size = key_cfg_len;
		temp = (uint8_t *)temp_rule->rule->key_iova;
		printf("key Size = %d\n", temp_rule->rule->key_size);
		printf("Traffic Class ID = %d\n", temp_rule->tc_id);
		printf("Flow ID = %d\n", temp_rule->flow_id);
		printf("PMR:\n");
		i = 0;
		while (i < key_cfg_len) {
			printf("%0x\t", *temp);
			temp++;
			i++;
		}
		printf("\nMask:\n");
		i = 0;
		temp = (uint8_t *)temp_rule->rule->mask_iova;
		while (i < key_cfg_len) {
			printf("%0x\t", *temp);
			temp++;
			i++;
		}
		printf("\n");
	}
	printf("======================End PMR======================\n");
	printf("L2 Matching rules information:\n");
	printf("======================Start L2======================\n");
	TAILQ_FOREACH(temp_rule, &l2_rule_list[pktio_idx], next) {
		temp_rule->rule->key_size = key_cfg_len;
		temp = (uint8_t *)temp_rule->rule->key_iova;
		printf("key Size = %d\n", temp_rule->rule->key_size);
		printf("Traffic Class ID = %d\n", temp_rule->tc_id);
		printf("Flow ID = %d\n", temp_rule->flow_id);
		printf("PMR:\n");
		i = 0;
		while (i < key_cfg_len) {
			printf("%0x\t", *temp);
			temp++;
			i++;
		}
		printf("\nMask:\n");
		i = 0;
		temp = (uint8_t *)temp_rule->rule->mask_iova;
		while (i < key_cfg_len) {
			printf("%0x\t", *temp);
			temp++;
			i++;
		}
		printf("\n");
	}
	printf("======================End L2======================\n");
	printf("L3 Matching rules information:\n");
	printf("======================Start L3======================\n");
	TAILQ_FOREACH(temp_rule, &l3_rule_list[pktio_idx], next) {
		temp_rule->rule->key_size = key_cfg_len;
		temp = (uint8_t *)temp_rule->rule->key_iova;
		printf("key Size = %d\n", temp_rule->rule->key_size);
		printf("Traffic Class ID = %d\n", temp_rule->tc_id);
		printf("Flow ID = %d\n", temp_rule->flow_id);
		printf("PMR:\n");
		i = 0;
		while (i < key_cfg_len) {
			printf("%0x\t", *temp);
			temp++;
			i++;
		}
		printf("\nMask:\n");
		i = 0;
		temp = (uint8_t *)temp_rule->rule->mask_iova;
		while (i < key_cfg_len) {
			printf("%0x\t", *temp);
			temp++;
			i++;
		}
		printf("\n");
	}
	printf("======================End L3======================\n");
}

static odp_pmr_t odp_pmr_create(const odp_pmr_param_t *terms)

{
	uint8_t *params[2];
	uint8_t *uargs[2];
	pmr_t *pmr;
	odp_pmr_t id;

	if (terms->val_sz > ODP_PMR_TERM_BYTES_MAX) {
		ODP_ERR("val_sz greater than max supported limit");
		return ODP_PMR_INVAL;
	}

	id = alloc_pmr(&pmr);
	/*if alloc_pmr() is successful it returns with lock acquired*/
	if (id == ODP_PMR_INVAL)
		return ODP_PMR_INVAL;

	pmr->s.num_pmr = 1;
	/*Allocate memory for matching rule configuration at H/W.*/
	params[0] = dpaa2_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
	if (!params[0]) {
		ODP_ERR("Memory unavaialble");
		return ODP_PMR_INVAL;
	}
	/*Allocate memory for mask rule at H/W.*/
	params[1] = dpaa2_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
	if (!params[1]) {
		ODP_ERR("Memory unavaialble");
		dpaa2_data_free((void *)params[0]);
		return ODP_PMR_INVAL;
	}
	/* Allocate memory for mathcing rule provided by user. This memory will
	   be freed once matching rule is configured at H/W.
	*/
	uargs[0] = dpaa2_calloc(NULL, 1, terms->val_sz, ODP_CACHE_LINE_SIZE);
	if (!uargs[0]) {
		dpaa2_data_free((void *)params[0]);
		dpaa2_data_free((void *)params[1]);
		ODP_ERR("Memory unavaialble");
		return ODP_PMR_INVAL;
	}
	/* Allocate memory for masking rule provided by user. This memory will
	   be freed once matching rule is configured at H/W.
	*/
	uargs[1] = dpaa2_calloc(NULL, 1, terms->val_sz, ODP_CACHE_LINE_SIZE);
	if (!uargs[1]) {
		ODP_ERR("Memory unavaialble");
		dpaa2_data_free((void *)params[0]);
		dpaa2_data_free((void *)params[1]);
		dpaa2_free((void *)uargs[0]);
		return ODP_PMR_INVAL;
	}

	/*Updating ODP database for PMR*/
	pmr->s.term_value[0].term = terms->term;
	memcpy(uargs[0], terms->match.value, terms->val_sz);
	memcpy(uargs[1], terms->match.mask, terms->val_sz);
	convert_param_to_network_order(uargs[0], uargs[1], terms->val_sz);
	pmr->s.term_value[0].val = (uint64_t)uargs[0];
	pmr->s.term_value[0].mask = (uint64_t)uargs[1];
	pmr->s.rule.key_iova = (uint64_t)params[0];
	pmr->s.rule.mask_iova = (uint64_t)params[1];
	pmr->s.rule.key_size = 0;
	set_pmr_info((void *)pmr);
	CLS_UNLOCK(&pmr->s.lock);
	return id;
}

static int odp_pmr_destroy(pmr_t *pmr)
{
	uint32_t loop, pos;

	if (pmr == NULL)
		return -1;

	pos = pmr->s.pos[0];
	loop = pos + 1;
	key_cfg_len -= pmr_info[pos].size;

	/* Update local pmr_info array for deleted PMR entry. Below loop shifts
	   all the pmr_info entry at left so that all free entries are at right.
	*/
	while (pmr_info[loop].is_valid == 1) {
		pmr_info[loop - 1].type = pmr_info[loop].type;
		pmr_info[loop - 1].size = pmr_info[loop].size;
		pmr_info[loop - 1].is_valid = pmr_info[loop].is_valid;
		loop++;
	}
	/*Invalidated all the fields for particular pmr_info entry*/
	pmr_info[loop - 1].type = 0xFFFF;
	pmr_info[loop - 1].size = 0;
	pmr_info[loop - 1].is_valid = 0;
	pmr_index = loop - 1;

	/*Free pre-allocated memory for PMR rule and mask*/
	dpaa2_data_free((void *)(pmr->s.rule.key_iova));
	dpaa2_data_free((void *)(pmr->s.rule.mask_iova));
	if (pmr->s.term_value[0].val)
		dpaa2_free((void *)(pmr->s.term_value[0].val));
	if (pmr->s.term_value[0].mask)
		dpaa2_free((void *)(pmr->s.term_value[0].mask));
	pmr->s.rule.key_size = 0;
	pmr->s.valid = 0;
	pmr->s.num_pmr = 0;
	return 0;
}

static int odp_pktio_pmr_cos(odp_pmr_t pmr_id,
		      odp_pktio_t src_pktio,
		      odp_cos_t dst_cos)
{
	int32_t			retcode;
	pktio_entry_t		*pktio;
	queue_entry_t		*queue;
	pmr_t			*pmr;
	cos_t			*cos;
	/*Platform specific objects and variables*/
	struct dpaa2_vq_param	cfg;
	struct dpaa2_dev		*dev;
	struct dpaa2_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;
	uint16_t		flow_id;
	struct dpni_rx_tc_dist_cfg	*tc_cfg;
	struct exact_match_rule		*fs_rule;

	pktio = get_pktio_entry(src_pktio);
	if (pktio == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}

	pmr = get_pmr_entry(pmr_id);
	if (pmr == NULL) {
		ODP_ERR("Invalid odp_pmr_t handle");
		return -1;
	}

	cos = get_cos_entry(dst_cos);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle");
		return -1;
	}

	dev = pktio->s.pkt_dpaa2.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;
	flow_id = pktio->s.cls.flow_id;
	tc_cfg = &pktio->s.cls.tc_cfg;

	/*Configure distribution paramters*/
	tc_cfg->dist_size = dev->num_rx_vqueues;
	/*	if default CoS is created then:
			packet will be forwarded to default flow ID 0.
		Else packet will be dropped as a default action
	*/
	if (pktio->s.cls.default_cos) {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_EXPLICIT_FLOWID;
		tc_cfg->fs_cfg.default_flow_id = ODP_CLS_DEFAULT_FLOW;
	} else
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_DROP;

	/*Setup H/W for distribution configuration*/
	odp_setup_dist(pktio);
	retcode = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token,
					cos->s.tc_id, tc_cfg);
	if (retcode < 0) {
		ODP_ERR("Distribution can not be configured: %d\n", retcode);
		return -1;
	}
	retcode = dpni_clear_fs_entries(dpni, CMD_PRI_LOW, dev_priv->token,
					cos->s.tc_id);
	if (retcode < 0) {
		ODP_ERR("Error(%d) in clearing FS table\n", retcode);
		return -1;
	}

	/*Check for the Queue Type*/
	queue = cos->s.queue;
	retcode = fill_queue_configuration(queue, &cfg);
	if (retcode < 0)
		return -1;

	/*Update ODP database according to the H/W resource values*/
	cos->s.queue->s.priv = dev->rx_vq[++flow_id];
	/*TODO Need to update with variable value*/
	cos->s.tc_id = ODP_CLS_DEFAULT_TC;

	odp_update_pmr_offset(pktio, pmr);

	dpaa2_dev_set_vq_handle(dev->rx_vq[flow_id], (uint64_t)queue->s.handle);

	/*Update input and output dpaa2 device in ODP queue*/
	queue->s.pktin = src_pktio;
	queue->s.pktout = src_pktio;

	if (flow_id < dev->num_rx_vqueues) {
		retcode = dpaa2_eth_setup_rx_vq(dev, flow_id, &cfg);
		if (retcode < 0) {
			ODP_ERR("Error in setup Rx flow");
			return -1;
		}
	} else {
		ODP_ERR("Number of flows reached at maximum limit\n");
		return -1;
	}

	/*Update rule list*/
	fs_rule = dpaa2_malloc(NULL, sizeof(struct exact_match_rule));
	if (!fs_rule) {
		ODP_ERR(" NO memory for DEVICE.\n");
		return -1;
	}

	fs_rule->tc_id = cos->s.tc_id;
	fs_rule->flow_id = flow_id;
	fs_rule->type = EXACT_MATCH_RULE_PMR;
	fs_rule->rule = &(pmr->s.rule);

	/*First validate the correct order of rule in rule list and then
	insert the rule in list.*/
	odp_insert_exact_match_rule(src_pktio, fs_rule);

	/*Add all the Classification rules at underlying platform*/
	if (print_rules)
		print_all_rule_list((uint64_t)src_pktio - 1);

	retcode = odp_offload_rules(src_pktio);
	if (retcode < 0) {
		ODP_ERR("Error in adding FS entry:Error Code = %d\n", retcode);
		dpaa2_free((void *)fs_rule);
		return -1;
	}
	dpaa2_free((void *)(pmr->s.term_value[0].val));
	dpaa2_free((void *)(pmr->s.term_value[0].mask));
	pmr->s.term_value[0].val = (uint64_t)NULL;
	pmr->s.term_value[0].mask = (uint64_t)NULL;
	pktio->s.cls.flow_id = flow_id;
	return 0;
}

static int odp_pmr_match_set_create(int num_terms, const odp_pmr_param_t *terms,
			     odp_pmr_set_t *pmr_set_id)
{
	pmr_set_t *pmr;
	int i, count = 0, val_sz;
	odp_pmr_set_t id;
	uint8_t *params[2];
	uint8_t *args[2];

	if (num_terms > ODP_PMRTERM_MAX) {
		ODP_ERR("no of terms greater than supported ODP_PMRTERM_MAX");
		return -1;
	}

	id = alloc_pmr_set((pmr_t **)&pmr);
	/*if alloc_pmr_set is successful it returns with the acquired lock*/
	if (id == ODP_PMR_SET_INVAL) {
		*pmr_set_id = id;
		return -1;
	}
	/*Allocate memory for matching rule configuration at H/W */
	params[0] = dpaa2_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
	if (!params[0]) {
		ODP_ERR("Memory unavaialble");
		return -1;
	}
	params[1] = dpaa2_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
	if (!params[1]) {
		ODP_ERR("Memory unavaialble");
		dpaa2_data_free((void *)params[0]);
		return -1;
	}

	/*Updating ODP database for PMR SET*/
	pmr->s.num_pmr = num_terms;
	for (i = 0; i < num_terms; i++) {
		val_sz = terms[i].val_sz;
		if (val_sz > ODP_PMR_TERM_BYTES_MAX)
			continue;
		args[0] = dpaa2_calloc(NULL, 1, val_sz, ODP_CACHE_LINE_SIZE);
		if (!args[0]) {
			ODP_ERR("Memory unavaialble");
			dpaa2_data_free((void *)params[0]);
			dpaa2_data_free((void *)params[1]);
			return -1;
		}
		args[1] = dpaa2_calloc(NULL, 1, val_sz, ODP_CACHE_LINE_SIZE);
		if (!args[1]) {
			ODP_ERR("Memory unavaialble");
			dpaa2_data_free((void *)params[0]);
			dpaa2_data_free((void *)params[1]);
			dpaa2_free((void *)(args[0]));
			return -1;
		}
		pmr->s.term_value[i].term = terms[i].term;
		memcpy(args[0], terms[i].match.value, val_sz);
		memcpy(args[1], terms[i].match.mask, val_sz);
		convert_param_to_network_order(args[0], args[1], val_sz);
		pmr->s.term_value[i].val = (uint64_t)args[0];
		pmr->s.term_value[i].mask = (uint64_t)args[1];
		count++;
	}
	set_pmr_info((void *)pmr);
	pmr->s.rule.key_iova = (uint64_t)params[0];
	pmr->s.rule.mask_iova = (uint64_t)params[1];
	pmr->s.rule.key_size = 0;

	*pmr_set_id = id;
	CLS_UNLOCK(&pmr->s.lock);
	return count;
}

static int odp_pmr_match_set_destroy(pmr_set_t *pmr)
{
	int32_t pos, loop;
	uint32_t i;

	if (pmr == NULL)
		return -1;

	for (i = 0; i < pmr->s.num_pmr; i++) {
		pos = pmr->s.pos[i];
		loop = pos + 1;
		key_cfg_len -= pmr_info[pos].size;
		while (pmr_info[loop].is_valid == 1) {
			pmr_info[loop - 1].type = pmr_info[loop].type;
			pmr_info[loop - 1].size = pmr_info[loop].size;
			pmr_info[loop - 1].is_valid = pmr_info[loop].is_valid;
			loop++;
		}
		pmr_info[loop - 1].type = 0xFFFF;
		pmr_info[loop - 1].size = 0;
		pmr_info[loop - 1].is_valid = 0;
		pmr_index = loop - 1;
	}
	for (i = 0; i < pmr->s.num_pmr; i++) {
		if (pmr->s.term_value[i].val)
			dpaa2_free((void *)(pmr->s.term_value[i].val));
		if (pmr->s.term_value[i].mask)
			dpaa2_free((void *)(pmr->s.term_value[i].mask));
	}
	dpaa2_data_free((void *)(pmr->s.rule.key_iova));
	dpaa2_data_free((void *)(pmr->s.rule.mask_iova));
	pmr->s.rule.key_size = 0;
	pmr->s.valid = 0;
	pmr->s.num_pmr = 0;
	return 0;
}

static int odp_pktio_pmr_match_set_cos(odp_pmr_set_t pmr_set_id, odp_pktio_t src_pktio,
		odp_cos_t dst_cos)
{
	int32_t			retcode;
	uint32_t i;
	pktio_entry_t		*pktio;
	queue_entry_t		*queue;
	pmr_set_t		*pmr;
	cos_t			*cos;
	/*Platform specific objects and variables*/
	struct dpaa2_vq_param	cfg;
	struct dpaa2_dev		*dev;
	struct dpaa2_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;
	uint16_t		flow_id;
	struct dpni_rx_tc_dist_cfg	*tc_cfg;
	struct exact_match_rule		*fs_rule;

	pktio = get_pktio_entry(src_pktio);
	if (!pktio) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}

	pmr = (pmr_set_t *)get_pmr_set_entry(pmr_set_id);
	if (pmr == NULL) {
		ODP_ERR("Invalid odp_pmr_set_t handle");
		return -1;
	}

	cos = get_cos_entry(dst_cos);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle");
		return -1;
	}

	/*Get H/W device information first*/
	dev = pktio->s.pkt_dpaa2.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;
	flow_id = pktio->s.cls.flow_id;
	tc_cfg = &pktio->s.cls.tc_cfg;

	tc_cfg->dist_size = dev->num_rx_vqueues;
	if (pktio->s.cls.default_cos) {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_EXPLICIT_FLOWID;
		tc_cfg->fs_cfg.default_flow_id = ODP_CLS_DEFAULT_FLOW;
	} else
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_DROP;

	odp_setup_dist(pktio);
	retcode = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token,
					cos->s.tc_id, tc_cfg);
	if (retcode < 0) {
		ODP_ERR("Distribution can not be configured: %d\n", retcode);
		return -1;
	}
	retcode = dpni_clear_fs_entries(dpni, CMD_PRI_LOW, dev_priv->token,
					cos->s.tc_id);
	if (retcode < 0) {
		ODP_ERR("Error(%d) in clearing FS table\n", retcode);
		return -1;
	}

	/*Check for the Queue Type first and fill its required configuration*/
	queue = cos->s.queue;
	retcode = fill_queue_configuration(queue, &cfg);
	if (retcode < 0)
		return -1;

	/*Update ODP database according to the H/W resource values*/
	cos->s.queue->s.priv = dev->rx_vq[++flow_id];
	/*TODO Need to update with variable value*/
	cos->s.tc_id = ODP_CLS_DEFAULT_TC;
	odp_update_pmr_set_offset(pktio, pmr);
	dpaa2_dev_set_vq_handle(dev->rx_vq[flow_id], (uint64_t)queue->s.handle);
	queue->s.pktin = src_pktio;
	queue->s.pktout = src_pktio;

	if (flow_id < dev->num_rx_vqueues) {
		retcode = dpaa2_eth_setup_rx_vq(dev, flow_id, &cfg);
		if (retcode < 0) {
			ODP_ERR("Error in setup Rx flow");
			return -1;
		}
	} else {
		ODP_ERR("Number of flows reached at maximum limit\n");
		return -1;
	}

	/*Update rule list*/
	fs_rule = dpaa2_malloc(NULL, sizeof(struct exact_match_rule));
	if (!fs_rule) {
		ODP_ERR("NO memory for DEVICE.\n");
		return -1;
	}

	fs_rule->tc_id = cos->s.tc_id;
	fs_rule->flow_id = flow_id;
	fs_rule->type = EXACT_MATCH_RULE_PMR;
	fs_rule->rule = &(pmr->s.rule);

	/*First validate the correct order of rule in rule list and then
	insert the rule in list.*/
	odp_insert_exact_match_rule(src_pktio, fs_rule);

	if (print_rules)
		print_all_rule_list((uint64_t)src_pktio - 1);

	retcode = odp_offload_rules(src_pktio);
	if (retcode < 0) {
		ODP_ERR("Error in adding FS entry:Error Code = %d\n", retcode);
		dpaa2_free((void *)fs_rule);
		return -1;
	}

	/*Free user allocated pmr set memory*/
	for (i = 0; i < pmr->s.num_pmr; i++) {
		dpaa2_free((void *)(pmr->s.term_value[i].val));
		dpaa2_free((void *)(pmr->s.term_value[i].mask));
		pmr->s.term_value[i].val = (uint64_t)NULL;
		pmr->s.term_value[i].mask = (uint64_t)NULL;
	}
	pktio->s.cls.flow_id = flow_id;
	return 0;
}

/* Initialize different tables used for classification i.e. PMR table,
 * PMR set table, CoS table etc
 */
int odp_classification_init_global(void)
{
	odp_shm_t cos_shm;
	odp_shm_t pmr_shm;
	odp_shm_t pmr_set_shm;
	int i;

	/*Allocating CoS table*/
	cos_shm = odp_shm_reserve("shm_odp_cos_tbl",
			sizeof(cos_tbl_t),
			sizeof(cos_t), 0);

	if (cos_shm == ODP_SHM_INVALID) {
		ODP_ERR("shm allocation failed for shm_odp_cos_tbl");
		goto error;
	}

	cos_tbl = odp_shm_addr(cos_shm);
	if (cos_tbl == NULL)
		goto error_cos;

	memset(cos_tbl, 0, sizeof(cos_tbl_t));
	for (i = 0; i < ODP_COS_MAX_ENTRY; i++) {
		/* init locks */
		cos_t *cos =
			get_cos_entry_internal(_odp_cast_scalar(odp_cos_t, i));
		CLS_LOCK_INIT(&cos->s.lock);
	}

	/*Allocating PMR table*/
	pmr_shm = odp_shm_reserve("shm_odp_pmr_tbl",
			sizeof(pmr_tbl_t),
			sizeof(pmr_t), 0);

	if (pmr_shm == ODP_SHM_INVALID) {
		ODP_ERR("shm allocation failed for shm_odp_pmr_tbl");
		goto error_cos;
	}

	pmr_tbl = odp_shm_addr(pmr_shm);
	if (pmr_tbl == NULL)
		goto error_pmr;

	memset(pmr_tbl, 0, sizeof(pmr_tbl_t));
	for (i = 0; i < ODP_PMR_MAX_ENTRY; i++) {
		/* init locks */
		pmr_t *pmr =
			get_pmr_entry_internal(_odp_cast_scalar(odp_pmr_t, i));
		CLS_LOCK_INIT(&pmr->s.lock);
	}

	/*Allocating PMR Set table*/
	pmr_set_shm = odp_shm_reserve("shm_odp_pmr_set_tbl",
			sizeof(pmr_set_tbl_t), 0, 0);

	if (pmr_set_shm == ODP_SHM_INVALID) {
		ODP_ERR("shm allocation failed for shm_odp_pmr_set_tbl");
		goto error_pmr;
	}

	pmr_set_tbl = odp_shm_addr(pmr_set_shm);
	if (pmr_set_tbl == NULL)
		goto error_pmrset;

	memset(pmr_set_tbl, 0, sizeof(pmr_set_tbl_t));
	for (i = 0; i < ODP_PMRSET_MAX_ENTRY; i++) {
		/* init locks */
		pmr_set_t *pmr =
			get_pmr_set_entry_internal
			(_odp_cast_scalar(odp_pmr_set_t, i));
		CLS_LOCK_INIT(&pmr->s.lock);
	}

	return 0;

error_pmrset:
	odp_shm_free(pmr_set_shm);
error_pmr:
	odp_shm_free(pmr_shm);
error_cos:
	odp_shm_free(cos_shm);
error:
	return -1;
}

int odp_classification_term_global(void)
{
	int ret = 0;
	int rc = 0;

	ret = odp_shm_free(odp_shm_lookup("shm_odp_cos_tbl"));
	if (ret < 0) {
		ODP_ERR("shm free failed for shm_odp_cos_tbl");
		rc = -1;
	}

	ret = odp_shm_free(odp_shm_lookup("shm_odp_pmr_tbl"));
	if (ret < 0) {
		ODP_ERR("shm free failed for shm_odp_pmr_tbl");
		rc = -1;
	}

	ret = odp_shm_free(odp_shm_lookup("shm_odp_pmr_set_tbl"));
	if (ret < 0) {
		ODP_ERR("shm free failed for shm_odp_pmr_tbl");
		rc = -1;
	}

	return rc;
}

odp_cos_t odp_cls_cos_create(const char *name, odp_cls_cos_param_t *param)
{
	int i;

	/* "param" is manadatory parameter. Return Invalid CoS handle if
		"param" is NULL
	*/
	if (!param) {
		ODP_ERR("CoS parameter is NULL\n");
		return ODP_COS_INVALID;
	}
	for (i = 0; i < ODP_COS_MAX_ENTRY; i++) {
		CLS_LOCK(&cos_tbl->cos_entry[i].s.lock);
		if (0 == cos_tbl->cos_entry[i].s.used) {
			memset(&(cos_tbl->cos_entry[i].s), 0,
						sizeof(struct cos_s));
			strncpy(cos_tbl->cos_entry[i].s.name, name,
				ODP_COS_NAME_LEN - 1);
			cos_tbl->cos_entry[i].s.name[ODP_COS_NAME_LEN - 1] = 0;
			cos_tbl->cos_entry[i].s.next_pmr = NULL;
			cos_tbl->cos_entry[i].s.next_cos = NULL;
			cos_tbl->cos_entry[i].s.param.queue = param->queue;
			if (cos_tbl->cos_entry[i].s.param.queue == ODP_QUEUE_INVALID)
				cos_tbl->cos_entry[i].s.queue = NULL;
			else
				cos_tbl->cos_entry[i].s.queue =
						queue_to_qentry(cos_tbl->cos_entry[i].s.param.queue);
			cos_tbl->cos_entry[i].s.param.pool = param->pool;
			cos_tbl->cos_entry[i].s.param.drop_policy = param->drop_policy;
			cos_tbl->cos_entry[i].s.used = 1;
			CLS_UNLOCK(&cos_tbl->cos_entry[i].s.lock);
			return _odp_cast_scalar(odp_cos_t, i);
		}
		CLS_UNLOCK(&cos_tbl->cos_entry[i].s.lock);
	}
	ODP_ERR("ODP_COS_MAX_ENTRY reached");
	return ODP_COS_INVALID;
}

/*
 * It Allocates a block from pre-allocated PMR set table.
 */
odp_pmr_set_t alloc_pmr_set(pmr_t **pmr)
{
	int i;

	for (i = 0; i < ODP_PMRSET_MAX_ENTRY; i++) {
		CLS_LOCK(&pmr_set_tbl->pmr_set[i].s.lock);
		if (0 == pmr_set_tbl->pmr_set[i].s.valid) {
			pmr_set_tbl->pmr_set[i].s.valid = 1;
			pmr_set_tbl->pmr_set[i].s.num_pmr = 0;
			*pmr = (pmr_t *)&pmr_set_tbl->pmr_set[i];
			/* return as locked */
			return _odp_cast_scalar(odp_pmr_set_t, i);
		}
		CLS_UNLOCK(&pmr_set_tbl->pmr_set[i].s.lock);
	}
	ODP_ERR("ODP_PMRSET_MAX_ENTRY reached");
	return ODP_PMR_SET_INVAL;
}

/*
 * It Allocates a block from pre-allocated PMR table.
 */
odp_pmr_t alloc_pmr(pmr_t **pmr)
{
	int i;

	for (i = 0; i < ODP_PMR_MAX_ENTRY; i++) {
		CLS_LOCK(&pmr_tbl->pmr[i].s.lock);
		if (0 == pmr_tbl->pmr[i].s.valid) {
			pmr_tbl->pmr[i].s.valid = 1;
			*pmr = &pmr_tbl->pmr[i];
			/* return as locked */
			return _odp_cast_scalar(odp_pmr_t, i);
		}
		CLS_UNLOCK(&pmr_tbl->pmr[i].s.lock);
	}
	ODP_ERR("ODP_PMR_MAX_ENTRY reached");
	return ODP_PMR_INVAL;
}

cos_t *get_cos_entry(odp_cos_t cos_id)
{
	if (_odp_typeval(cos_id) >= ODP_COS_MAX_ENTRY ||
	    cos_id == ODP_COS_INVALID)
		return NULL;
	if (cos_tbl->cos_entry[_odp_typeval(cos_id)].s.used == 0)
		return NULL;
	return &(cos_tbl->cos_entry[_odp_typeval(cos_id)]);
}


pmr_set_t *get_pmr_set_entry(odp_pmr_set_t pmr_set_id)
{
	if (_odp_typeval(pmr_set_id) >= ODP_PMRSET_MAX_ENTRY ||
	    pmr_set_id == ODP_PMR_SET_INVAL)
		return NULL;
	if (pmr_set_tbl->pmr_set[_odp_typeval(pmr_set_id)].s.valid == 0)
		return NULL;
	return &(pmr_set_tbl->pmr_set[_odp_typeval(pmr_set_id)]);
}

pmr_t *get_pmr_entry(odp_pmr_t pmr_id)
{
	if (_odp_typeval(pmr_id) >= ODP_PMR_MAX_ENTRY ||
	    pmr_id == ODP_PMR_INVAL)
		return NULL;
	if (pmr_tbl->pmr[_odp_typeval(pmr_id)].s.valid == 0)
		return NULL;
	return &(pmr_tbl->pmr[_odp_typeval(pmr_id)]);
}

int odp_cos_destroy(odp_cos_t cos_id)
{
	cos_t *cos = get_cos_entry(cos_id);
	if (NULL == cos) {
		ODP_ERR("Invalid odp_cos_t handle");
		return -1;
	}

	cos->s.used = 0;
	return 0;
}

int odp_cos_queue_set(odp_cos_t cos_id, odp_queue_t queue_id)
{
	cos_t *cos = get_cos_entry(cos_id);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle");
		return -1;
	}
	/* Locking is not required as intermittent stale
	data during CoS modification is acceptable*/
	cos->s.queue = queue_to_qentry(queue_id);
	return 0;
}

odp_queue_t odp_cos_queue(odp_cos_t cos_id)
{
	cos_t			*cos;
	queue_entry_t	*queue;

	cos = get_cos_entry(cos_id);
	if (!cos) {
		ODP_ERR("Invalid odp_cos_t handle");
		return ODP_QUEUE_INVALID;
	}

	queue = cos->s.queue;
	return queue->s.handle;
}

int odp_cos_drop_set(odp_cos_t cos_id ODP_UNUSED, odp_cls_drop_t drop_policy ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}
int odp_cls_cos_pool_set(odp_cos_t cos_id ODP_UNUSED, odp_pool_t pool_id ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_pktio_default_cos_set(odp_pktio_t pktio_in, odp_cos_t default_cos)
{
	int32_t retcode;
	pktio_entry_t *entry;
	queue_entry_t *queue;
	cos_t *cos;
	struct dpaa2_vq_param cfg;
	struct dpaa2_dev *dev;
	struct dpaa2_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;
	struct dpni_rx_tc_dist_cfg	*tc_cfg;

	entry = get_pktio_entry(pktio_in);
	if (entry == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}
	cos = get_cos_entry(default_cos);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle");
		return -1;
	}

	/*Connect a default H/W FQ of given pktio*/
	dev = entry->s.pkt_dpaa2.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;
	tc_cfg = &entry->s.cls.tc_cfg;

	/*Configure distribution parameters*/
	tc_cfg->dist_size = dev->num_rx_vqueues;

	/*Check Queue parameter in CoS. If invalid then packets must be dropped*/
	if (cos->s.param.queue != ODP_QUEUE_INVALID) {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_EXPLICIT_FLOWID;
		tc_cfg->fs_cfg.default_flow_id = ODP_CLS_DEFAULT_FLOW;
	} else {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_DROP;
	}

	/*Setup H/W for distribution configuration*/
	odp_setup_dist(entry);
	retcode = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token,
				      cos->s.tc_id, tc_cfg);
	if (retcode < 0) {
		ODP_ERR("Distribution can not be configured: %d\n", retcode);
		return -1;
	}
	retcode = dpni_clear_fs_entries(dpni, CMD_PRI_LOW, dev_priv->token,
					cos->s.tc_id);
	if (retcode < 0) {
		ODP_ERR("Error(%d) in clearing FS table\n", retcode);
		return -1;
	}

	/*Check for the Queue Type first and fill its required configuration*/
	queue = cos->s.queue;
	retcode = fill_queue_configuration(queue, &cfg);
	if (retcode < 0)
		return -1;

	/* Configure queue handle into dpaa2 device vq so that ODP can retrieve
	 * queue handle from the dpaa2 device VQ.
	 */
	dpaa2_dev_set_vq_handle(dev->rx_vq[ODP_CLS_DEFAULT_FLOW],
						(uint64_t)queue->s.handle);

	/*Update input and output device in ODP queue structure*/
	queue->s.pktin = pktio_in;
	queue->s.pktout = pktio_in;

	/*Configure the queue propeties at H/W with configuration updated above*/
	retcode = dpaa2_eth_setup_rx_vq(dev, ODP_CLS_DEFAULT_FLOW, &cfg);
	if (retcode < 0) {
		ODP_ERR("Error in setup Rx flow");
		return -1;
	}
	/*Update ODP database according to the H/W resource values*/
	cos->s.queue->s.priv = dev->rx_vq[ODP_CLS_DEFAULT_FLOW];

	if (print_rules)
		print_all_rule_list((uint64_t)pktio_in - 1);

	/*Add all the Classification rules at underlying platform*/
	retcode = odp_offload_rules(pktio_in);
	if (retcode < 0) {
		ODP_ERR("Error in adding FS entry:Error Code = %d\n", retcode);
		return -1;
	}

	cos->s.tc_id = ODP_CLS_DEFAULT_TC; /*TODO Need to update with variable value*/
	cos->s.pktio_in = pktio_in;
	entry->s.cls.default_cos = cos;
	return 0;
}

int odp_pktio_error_cos_set(odp_pktio_t pktio_in, odp_cos_t error_cos)
{
	pktio_entry_t *entry;
	cos_t *cos;
	int32_t retcode;
	queue_entry_t *queue;
	struct dpaa2_dev *dev;
	struct dpaa2_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;
	struct dpni_queue cfg;
	struct dpni_queue_id qid;
	struct dpni_error_cfg	err_cfg;
	struct dpaa2_dev *conc_dev;
	struct dpaa2_vq *eth_err_vq;
	uint8_t options = 0;

	entry = get_pktio_entry(pktio_in);
	if (!entry) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}

	cos = get_cos_entry(error_cos);
	if (!cos) {
		ODP_ERR("Invalid odp_cos_t handle");
		return -1;
	}

	/*Connect a default H/W FQ of given pktio*/
	dev = entry->s.pkt_dpaa2.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;
	memset(&cfg, 0, sizeof(struct dpni_queue));
	memset(&qid, 0, sizeof(struct dpni_queue_id));
	memset(&err_cfg, 0, sizeof(struct dpni_error_cfg));

	/*Update input and output device in ODP queue structure*/
	queue = cos->s.queue;
	queue->s.pktin = pktio_in;
	queue->s.pktout = pktio_in;

	eth_err_vq = (struct dpaa2_vq *)dev->err_vq[DEF_ERR_VQ_INDEX];
	if (queue->s.param.type == ODP_QUEUE_TYPE_SCHED) {
		struct conc_attr attr;

		memset(&attr, 0, sizeof(struct conc_attr));
		conc_dev    = odp_get_conc_from_grp(queue->s.param.sched.group);
		/*Get DPCONC object attributes*/
		dpaa2_conc_get_attributes(conc_dev, &attr);

		/*Do settings to get the frame on a DPCON object*/
		if (queue->s.param.sched.sync & ODP_SCHED_SYNC_ATOMIC) {
			options |= DPNI_QUEUE_OPT_HOLD_ACTIVE;
			cfg.destination.hold_active	= TRUE;
		}
		options |= DPNI_QUEUE_OPT_DEST;
		cfg.destination.type	= DPNI_DEST_DPCON;
		cfg.destination.priority   = 0;
		cfg.destination.id	= attr.obj_id;
		dev->conc_dev		= conc_dev;
	}
	options |= DPNI_QUEUE_OPT_USER_CTX;
	cfg.user_context = (uint64_t)(eth_err_vq);

	/*Lets map user created to underlying error queue*/
	retcode = dpni_set_queue(dpni, CMD_PRI_LOW, dev_priv->token,
				 DPNI_QUEUE_RX_ERR, eth_err_vq->tc_index,
				eth_err_vq->flow_id, options, &cfg);
	if (retcode) {
		ODP_ERR("dpni_set_rx_err_queue() Failed: ErrorCode = %d\n",
			retcode);
		return -1;
	}

	memset(&cfg, 0, sizeof(cfg));
	retcode = dpni_get_queue(dpni, CMD_PRI_LOW, dev_priv->token,
				 DPNI_QUEUE_RX_ERR, eth_err_vq->tc_index,
				eth_err_vq->flow_id, &cfg, &qid);
	if (retcode) {
		ODP_ERR("dpni_get_rx_err_queue() Failed: ErrorCode = %d\n",
			retcode);
		return -1;
	}

	err_cfg.errors = DPNI_ERROR_EOFHE |
					DPNI_ERROR_FLE |
					DPNI_ERROR_FPE |
					DPNI_ERROR_PHE |
					DPNI_ERROR_L3CE |
					DPNI_ERROR_L4CE;

	if (cos->s.param.queue != ODP_QUEUE_INVALID)
		err_cfg.error_action = DPNI_ERROR_ACTION_SEND_TO_ERROR_QUEUE;
	else
		err_cfg.error_action = DPNI_ERROR_ACTION_DISCARD;
	err_cfg.set_frame_annotation = TRUE;

	retcode = dpni_set_errors_behavior(dpni, CMD_PRI_LOW, dev_priv->token,
					   &err_cfg);
	if (retcode) {
		ODP_ERR("dpni_set_errors_behavior() Failed: ErrorCode = %d\n",
			retcode);
		return -1;
	}

	retcode = odp_add_queue_to_group(queue->s.param.sched.group);
	if (retcode == 1)
		odp_affine_group(queue->s.param.sched.group, NULL);

	dpaa2_dev_set_vq_handle(eth_err_vq, (uint64_t)queue->s.handle);
	eth_err_vq->fq_type = DPAA2_FQ_TYPE_RX_ERR;
	eth_err_vq->qmfq.cb = dpaa2_eth_cb_dqrr_fd_to_mbuf;
	eth_err_vq->fqid = qid.fqid;
	cos->s.queue->s.priv = eth_err_vq;
	return 0;
}

int odp_pktio_skip_set(odp_pktio_t pktio_in ODP_UNUSED, uint32_t offset ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_pktio_headroom_set(odp_pktio_t pktio_in, uint32_t headroom)
{
	pktio_entry_t *entry;
	struct dpaa2_dev *dev;
	struct dpaa2_dev_priv *dev_priv;
	struct fsl_mc_io *dpni;
	struct dpni_buffer_layout layout;
	int ret, tot_size;

	/*Get pktio entry where rules are to be applied*/
	entry = get_pktio_entry(pktio_in);
	if (!entry) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}

	/*Check for maximum headroom value*/
	if (headroom > ODP_CONFIG_PACKET_HEADROOM) {
		ODP_ERR("headroom size %d exceeds the maximum limit\n",
			headroom);
		return -1;
	}

	dev = entry->s.pkt_dpaa2.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;

	/*Check alignment for buffer layouts first*/
	tot_size = dpaa2_mbuf_sw_annotation + DPAA2_MBUF_HW_ANNOTATION +
			 headroom;
	if ((mc_plat_info.svr & 0xffff0000) == SVR_LS2080A)
		tot_size = ODP_ALIGN_ROUNDUP(tot_size, 256);
	else
		tot_size = ODP_ALIGN_ROUNDUP(tot_size, 64);
	headroom = tot_size - (dpaa2_mbuf_sw_annotation +
					DPAA2_MBUF_HW_ANNOTATION);

	memset(&layout, 0, sizeof(struct dpni_buffer_layout));
	layout.options = DPNI_BUF_LAYOUT_OPT_DATA_HEAD_ROOM;
	layout.data_head_room = headroom;

	/*DPNI must be disable before configuring rx buffer layout*/
	ret = dpni_disable(dpni, CMD_PRI_LOW, dev_priv->token);
	if (ret) {
		ODP_ERR("dpni_disable() failed for device."
			"err code: %d\n", dev->dev_string, ret);
		return ret;
	}
	ret = dpni_set_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token,
				     DPNI_QUEUE_RX, &layout);
	if (ret) {
		ODP_ERR("Setting headroom failed for device %s."
			"err code: %d\n", dev->dev_string, ret);
		return ret;
	}
	ret = dpni_enable(dpni, CMD_PRI_LOW, dev_priv->token);
	if (ret) {
		ODP_ERR("dpni_enable() failed for device."
			"err code: %d\n", dev->dev_string, ret);
		return ret;
	}
	entry->s.pktio_headroom = headroom;;
	ODP_DBG("Configured headroom %d  for device %s\n", headroom,
		dev->dev_string);
	return 0;
}

static void odp_delete_l2_rule_list(odp_pktio_t pktio)
{
	struct exact_match_rule *temp_rule;
	uint32_t index = (uint64_t)pktio - 1;

	TAILQ_FOREACH(temp_rule, &l2_rule_list[index], next) {
		dpaa2_data_free((void *)temp_rule->rule->key_iova);
		dpaa2_data_free((void *)temp_rule->rule->mask_iova);
	}
}

static void odp_delete_l3_rule_list(odp_pktio_t pktio)
{
	struct exact_match_rule *temp_rule;
	uint32_t index = (uint64_t)pktio - 1;

	TAILQ_FOREACH(temp_rule, &l3_rule_list[index], next) {
		dpaa2_data_free((void *)temp_rule->rule->key_iova);
		dpaa2_data_free((void *)temp_rule->rule->mask_iova);
	}
}

int odp_cos_with_l2_priority(odp_pktio_t pktio_in, uint8_t num_qos,
			     uint8_t qos_table[], odp_cos_t cos_table[])
{
	uint16_t qos_mask = odp_cpu_to_be_16(0xE000);
	uint8_t *qos_value;
	uint32_t i, j;
	cos_t *cos;
	pmr_t *pmr[8];
	odp_pmr_t pmr_id[8];
	pktio_entry_t *entry;
	queue_entry_t *queue[8];
	void *params[2];
	int32_t retcode;
	struct dpaa2_vq_param	cfg[8];
	struct dpaa2_dev		*dev;
	struct dpaa2_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;
	uint16_t		flow_id;
	struct dpni_rx_tc_dist_cfg	*tc_cfg;
	struct exact_match_rule		*fs_rule;

	/*Get pktio entry where rules are to be applied*/
	entry = get_pktio_entry(pktio_in);
	if (!entry) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}
	dev = entry->s.pkt_dpaa2.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;
	flow_id = entry->s.cls.flow_id;
	tc_cfg = &entry->s.cls.tc_cfg;

	/*Configure distribution parameters*/
	tc_cfg->dist_size = dev->num_rx_vqueues;
	/*if default CoS is created then:
		packet will be forwarded to default flow ID 0.
	Else packet will be dropped as a default action
	*/
	if (entry->s.cls.default_cos) {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_EXPLICIT_FLOWID;
		tc_cfg->fs_cfg.default_flow_id = ODP_CLS_DEFAULT_FLOW;
	} else {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_DROP;
	}

	/*Setup H/W for distribution configuration*/
	odp_setup_dist(entry);
	retcode = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token,
				      ODP_CLS_DEFAULT_TC, tc_cfg);
	if (retcode < 0) {
		ODP_ERR("Distribution can not be configured: %d\n", retcode);
		return -1;
	}
	retcode = dpni_clear_fs_entries(dpni, CMD_PRI_LOW, dev_priv->token,
					ODP_CLS_DEFAULT_TC);
	if (retcode < 0) {
		ODP_ERR("Error(%d) in clearing FS table\n", retcode);
		return -1;
	}

	/*Now we are done with device information. Lets get some reuqired number
	of PMRs to store the rules*/
	for (i = 0; i < num_qos; i++) {
		pmr_id[i] = alloc_pmr(&pmr[i]);
		/*if alloc_pmr() is successful it returns with lock acquired*/
		if (pmr_id[i] == ODP_PMR_INVAL)
			return -1;

		qos_value = (uint8_t *)dpaa2_calloc(NULL, 1,
						sizeof(uint16_t), 0);
		if (!qos_value)
			goto unlock_pmr_and_clean;

		qos_value[0] = (qos_table[i] << 5);
		pmr[i]->s.num_pmr = 1;
		pmr[i]->s.term_value[0].val = (uint64_t)qos_value;
		pmr[i]->s.term_value[0].mask = (uint64_t)&qos_mask;

		/*Allocate memory for matching rule configuration at H/W.*/
		params[0] = dpaa2_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
		if (!params[0]) {
			ODP_ERR("Memory unavaialble");
			dpaa2_free(qos_value);
			goto unlock_pmr_and_clean;
		}
		/*Allocate memory for mask rule configuration at H/W.*/
		params[1] = dpaa2_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
		if (!params[1]) {
			ODP_ERR("Memory unavaialble");
			dpaa2_free(qos_value);
			dpaa2_data_free((void *)params[0]);
			goto unlock_pmr_and_clean;
		}
		/*Updating ODP database for PMR*/
		pmr[i]->s.rule.key_iova = (uint64_t)params[0];
		pmr[i]->s.rule.mask_iova = (uint64_t)params[1];
		pmr[i]->s.rule.key_size = 0;

		/*Collect CoS and associated queue configuration associated
		with pktio*/
		cos = get_cos_entry(cos_table[i]);
		if (cos) {
			/*Check for the Queue Type*/
			queue[i] = cos->s.queue;
			retcode = fill_queue_configuration(queue[i], &cfg[i]);
			if (retcode < 0) {
				dpaa2_free(qos_value);
				goto unlock_pmr_and_clean;
			}

			/*Update ODP database according to the H/W resource
			values*/
			queue[i]->s.priv = dev->rx_vq[++flow_id];
			/*TODO Need to update with variable value*/
			cos->s.tc_id = ODP_CLS_DEFAULT_TC;
			dpaa2_dev_set_vq_handle(dev->rx_vq[flow_id],
					       (uint64_t)queue[i]->s.handle);
			/*Update input and output dpaa2 device in ODP queue*/
			queue[i]->s.pktin = pktio_in;
			queue[i]->s.pktout = pktio_in;

			if (flow_id < dev->num_rx_vqueues) {
				retcode = dpaa2_eth_setup_rx_vq(dev, flow_id,
							       &cfg[i]);
				if (retcode < 0) {
					ODP_ERR("Error in setup Rx flow\n");
					dpaa2_free(qos_value);
					goto unlock_pmr_and_clean;
				}
			} else {
				ODP_ERR("flow_id out of range\n");
				dpaa2_free(qos_value);
				goto unlock_pmr_and_clean;
			}
		} else {
			ODP_ERR("NULL CoS entry found\n");
			dpaa2_free(qos_value);
			goto unlock_pmr_and_clean;
		}

		odp_configure_l2_prio_rule(entry, pmr[i]);
		/*Update rule list*/
		fs_rule = dpaa2_calloc(NULL, 1, sizeof(struct exact_match_rule),
				      0);
		if (!fs_rule) {
			ODP_ERR(" NO memory for DEVICE.\n");
			dpaa2_free(qos_value);
			goto unlock_pmr_and_clean;
		}
		fs_rule->tc_id = ODP_CLS_DEFAULT_TC;
		fs_rule->flow_id = flow_id;
		fs_rule->type = EXACT_MATCH_RULE_L2;
		fs_rule->rule = &pmr[i]->s.rule;

		/*First validate the correct order of rule in rule list and then
		insert the rule in list.*/
		odp_insert_exact_match_rule(pktio_in, fs_rule);

		/*Free allocated memory*/
		dpaa2_free(qos_value);

		/*Unlock PMR entry*/
		CLS_UNLOCK(&pmr[i]->s.lock);
	}

	if (print_rules)
		print_all_rule_list((uint64_t)pktio_in - 1);

	retcode = odp_offload_rules(pktio_in);
	if (retcode < 0) {
		ODP_ERR("Error in adding FS entry: Error Code = %d\n", retcode);
		goto clean_allocated_resources;
	}
	entry->s.cls.flow_id = flow_id;
	return 0;

unlock_pmr_and_clean:
	/*Unlock PMR entry*/
	CLS_UNLOCK(&pmr[i]->s.lock);

clean_allocated_resources:
	for (j = 0; j < i; j++) {
		dpaa2_data_free((void *)pmr[i]->s.rule.key_iova);
		dpaa2_data_free((void *)pmr[i]->s.rule.mask_iova);
	}

	/*Free allocated memory for L2 Shadow database*/
	odp_delete_l2_rule_list(pktio_in);
	return -1;
}

int odp_cos_with_l3_qos(odp_pktio_t pktio_in,
			uint32_t num_qos,
			uint8_t qos_table[],
			odp_cos_t cos_table[],
			odp_bool_t l3_preference)
{
	uint8_t qos_mask = 0xFC;
	uint8_t *qos_value;
	uint32_t i, j;
	cos_t *cos;
	pmr_t *pmr[8];
	odp_pmr_t pmr_id[8];
	pktio_entry_t *entry;
	queue_entry_t *queue[8];
	void *params[2];
	int32_t retcode;
	struct dpaa2_vq_param	cfg[8];
	struct dpaa2_dev		*dev;
	struct dpaa2_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;
	uint16_t		flow_id;
	struct dpni_rx_tc_dist_cfg	*tc_cfg;
	struct exact_match_rule		*fs_rule;

	/*Get pktio entry where rules are to be applied*/
	entry = get_pktio_entry(pktio_in);
	if (entry == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}
	entry->s.cls.l3_precedence = l3_preference;
	dev = entry->s.pkt_dpaa2.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;
	flow_id = entry->s.cls.flow_id;
	tc_cfg = &entry->s.cls.tc_cfg;

	/*Configure distribution parameters*/
	tc_cfg->dist_size = dev->num_rx_vqueues;
	/*if default CoS is created then:
		packet will be forwarded to default flow ID 0.
	Else packet will be dropped as a default action
	*/
	if (entry->s.cls.default_cos) {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_EXPLICIT_FLOWID;
		tc_cfg->fs_cfg.default_flow_id = ODP_CLS_DEFAULT_FLOW;
	} else {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_DROP;
	}

	/*Setup H/W for distribution configuration*/
	odp_setup_dist(entry);
	retcode = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token,
				      ODP_CLS_DEFAULT_TC, tc_cfg);
	if (retcode < 0) {
		ODP_ERR("Distribution can not be configured: %d\n", retcode);
		return -1;
	}
	retcode = dpni_clear_fs_entries(dpni, CMD_PRI_LOW, dev_priv->token,
					ODP_CLS_DEFAULT_TC);
	if (retcode < 0) {
		ODP_ERR("Error(%d) in clearing FS table\n", retcode);
		return -1;
	}

	/*Now we are done with device information. Lets get some reuqired number
	of PMRs to store the rules*/
	for (i = 0; i < num_qos; i++) {
		pmr_id[i] = alloc_pmr(&pmr[i]);
		/*if alloc_pmr() is successful it returns with lock acquired*/
		if (pmr_id[i] == ODP_PMR_INVAL)
			return -1;

		qos_value = (uint8_t *)dpaa2_calloc(NULL, 1, sizeof(uint8_t), 0);
		if (!qos_value) {
			ODP_ERR("Memory unavaialble");
			goto unlock_pmr_and_clean;
		}
		*qos_value = qos_table[i];
		pmr[i]->s.num_pmr = 1;
		pmr[i]->s.term_value[0].val = (uint64_t)qos_value;
		pmr[i]->s.term_value[0].mask = (uint64_t)&qos_mask;

		/*Allocate memory for matching rule configuration at H/W.*/
		params[0] = dpaa2_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
		if (!params[0]) {
			ODP_ERR("Memory unavaialble");
			dpaa2_free(qos_value);
			goto unlock_pmr_and_clean;
		}
		/*Allocate memory for mask rule configuration at H/W.*/
		params[1] = dpaa2_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
		if (!params[1]) {
			ODP_ERR("Memory unavaialble");
			dpaa2_free(qos_value);
			dpaa2_data_free((void *)params[0]);
			goto unlock_pmr_and_clean;
		}
		/*Updating ODP database for PMR*/
		pmr[i]->s.rule.key_iova = (uint64_t)params[0];
		pmr[i]->s.rule.mask_iova = (uint64_t)params[1];
		pmr[i]->s.rule.key_size = 0;

		/*Collect CoS and associated queue configuration associated
		with pktio*/
		cos = get_cos_entry(cos_table[i]);
		if (cos) {
			/*Check for the Queue Type*/
			queue[i] = cos->s.queue;
			retcode = fill_queue_configuration(queue[i], &cfg[i]);
			if (retcode < 0) {
				dpaa2_free(qos_value);
				goto unlock_pmr_and_clean;
			}

			/*Update ODP database according to the H/W resource
			values*/
			queue[i]->s.priv = dev->rx_vq[++flow_id];
			/*TODO Need to update with variable value*/
			cos->s.tc_id = ODP_CLS_DEFAULT_TC;
			dpaa2_dev_set_vq_handle(dev->rx_vq[flow_id],
					       (uint64_t)queue[i]->s.handle);
			/*Update input and output dpaa2 device in ODP queue*/
			queue[i]->s.pktin = pktio_in;
			queue[i]->s.pktout = pktio_in;

			if (flow_id < dev->num_rx_vqueues) {
				retcode = dpaa2_eth_setup_rx_vq(dev, flow_id,
							       &cfg[i]);
				if (retcode < 0) {
					dpaa2_free(qos_value);
					ODP_ERR("Error in setup Rx flow");
					goto unlock_pmr_and_clean;
				}
			} else {
				ODP_ERR("Number of flows reached at maximum limit\n");
				dpaa2_free(qos_value);
				goto unlock_pmr_and_clean;
			}
		} else {
			ODP_ERR("NULL CoS entry found\n");
			dpaa2_free(qos_value);
			goto unlock_pmr_and_clean;
		}

		odp_configure_l3_prio_rule(entry, pmr[i]);
		/*Update rule list*/
		fs_rule = dpaa2_calloc(NULL, 1, sizeof(struct exact_match_rule),
				      0);
		if (!fs_rule) {
			ODP_ERR(" NO memory for DEVICE.\n");
			dpaa2_free(qos_value);
			goto unlock_pmr_and_clean;
		}

		fs_rule->tc_id = ODP_CLS_DEFAULT_TC;
		fs_rule->flow_id = flow_id;
		fs_rule->type = EXACT_MATCH_RULE_L3;
		fs_rule->rule = &pmr[i]->s.rule;

		/*Unlock PMR entry*/
		CLS_UNLOCK(&pmr[i]->s.lock);
		/*First validate the correct order of rule in rule list and then
		insert the rule in list.*/
		odp_insert_exact_match_rule(pktio_in, fs_rule);
	}

	if (print_rules)
		print_all_rule_list((uint64_t)pktio_in - 1);

	retcode = odp_offload_rules(pktio_in);
	if (retcode < 0) {
		ODP_ERR("Error in adding FS entry:Error Code = %d\n", retcode);
		goto clean_allocated_resources;
	}
	entry->s.cls.flow_id = flow_id;
	return 0;

unlock_pmr_and_clean:
	/*Unlock PMR entry*/
	CLS_UNLOCK(&pmr[i]->s.lock);

clean_allocated_resources:
	for (j = 0; j < i; j++) {
		dpaa2_data_free((void *)pmr[i]->s.rule.key_iova);
		dpaa2_data_free((void *)pmr[i]->s.rule.mask_iova);
	}
	/*Free allocated memory for L2 Shadow database*/
	odp_delete_l3_rule_list(pktio_in);
	return -1;
}

/*
 * This API is used to create a key generation sceme from pre-updated data
 * pmr_info. This profile key will be provided to underlying layer(MC)
 * so that a packet can be extracted and built a matching key for these
 * paramters only.
 */
void odp_setup_extract_key(struct dpkg_profile_cfg *kg_cfg)
{
	uint64_t i = 0;

	while (pmr_info[i].is_valid) {
		switch (pmr_info[i].type) {
		case ODP_PMR_LEN:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_IPV4;
			kg_cfg->extracts[i].extract.from_hdr.field =
							NH_FLD_IPV4_TOTAL_LEN;
			break;
		case ODP_PMR_ETHTYPE_0:
		case ODP_PMR_ETHTYPE_X:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_ETH;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_ETH_TYPE;
			break;
		case ODP_PMR_VLAN_ID_0:
		case ODP_PMR_VLAN_ID_X:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_VLAN;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_VLAN_VID;
			break;
		case ODP_PMR_DMAC:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_ETH;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_ETH_DA;
			break;
		case ODP_PMR_IPPROTO:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_IP;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_IP_PROTO;
			break;
		case ODP_PMR_UDP_DPORT:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_UDP;
			kg_cfg->extracts[i].extract.from_hdr.field =
							NH_FLD_UDP_PORT_DST;
			break;
		case ODP_PMR_TCP_DPORT:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_TCP;
			kg_cfg->extracts[i].extract.from_hdr.field =
							NH_FLD_TCP_PORT_DST;
			break;
		case ODP_PMR_UDP_SPORT:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_UDP;
			kg_cfg->extracts[i].extract.from_hdr.field =
							NH_FLD_UDP_PORT_SRC;
			break;
		case ODP_PMR_TCP_SPORT:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_TCP;
			kg_cfg->extracts[i].extract.from_hdr.field =
							NH_FLD_TCP_PORT_SRC;
			break;
		case ODP_PMR_SIP_ADDR:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_IP;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_IP_SRC;
			break;
		case ODP_PMR_DIP_ADDR:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_IP;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_IP_DST;
			break;
		case ODP_PMR_SIP6_ADDR:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_IP;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_IP_SRC;
			break;
		case ODP_PMR_DIP6_ADDR:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_IP;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_IP_DST;
			break;
		default:
			ODP_ERR("Bad flow distribution option");
		}
		kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
		kg_cfg->extracts[i].extract.from_hdr.type = DPKG_FULL_FIELD;
		kg_cfg->num_extracts++;
		i++;
	}
	/*Configure for L2 priorioty*/
	kg_cfg->extracts[i].extract.from_hdr.prot = NET_PROT_VLAN;
	kg_cfg->extracts[i].extract.from_hdr.field = NH_FLD_VLAN_TCI;
	kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
	kg_cfg->extracts[i].extract.from_hdr.type = DPKG_FULL_FIELD;
	kg_cfg->num_extracts++;

	/*Configure for L3 priorioty*/
	i++;
	kg_cfg->extracts[i].extract.from_hdr.prot = NET_PROT_IP;
	kg_cfg->extracts[i].extract.from_hdr.field = NH_FLD_IP_TOS_TC;
	kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
	kg_cfg->extracts[i].extract.from_hdr.type = DPKG_FULL_FIELD;
	kg_cfg->num_extracts++;
}

/*
 *  It will create an extract parmeter key.
 */
int odp_setup_dist(pktio_entry_t *pktio_entry)
{
	struct dpkg_profile_cfg	*key_cfg;
	uint8_t			*param;

	key_cfg = pktio_entry->s.priv;
	param = (uint8_t *)pktio_entry->s.cls.tc_cfg.key_cfg_iova;
	memset(param, 0, DIST_PARAM_IOVA_SIZE);
	memset(key_cfg, 0, sizeof(struct dpkg_profile_cfg));

	odp_setup_extract_key(key_cfg);
	/* no need for mc portal lock*/
	if (dpkg_prepare_key_cfg(key_cfg, param) < 0) {
		ODP_ERR("Unable to prepare extract parameters");
		return -1;
	}
	return 0;
}

/*
 * It is a local function to convert from host order to network order
 */
void convert_param_to_network_order(void *val, void *mask, uint32_t val_sz)
{
	switch (val_sz) {
	case 2:
		*(uint16_t *)val = odp_cpu_to_be_16(*(uint16_t *)val);
		*(uint16_t *)mask = odp_cpu_to_be_16(*(uint16_t *)mask);
		break;
	case 4:
		*(uint32_t *)val = odp_cpu_to_be_32(*(uint32_t *)val);
		*(uint32_t *)mask = odp_cpu_to_be_32(*(uint32_t *)mask);
		break;
	case 8:
		*(uint64_t *)val = odp_cpu_to_be_64(*(uint64_t *)val);
		*(uint64_t *)mask = odp_cpu_to_be_64(*(uint64_t *)mask);
		break;
	case 1:
		break;
	default:
		ODP_ERR("Unsupported val_size");
		break;
	}
}

odp_pmr_t odp_cls_pmr_create(const odp_pmr_param_t *terms, int num_terms,
					 odp_cos_t src_cos , odp_cos_t dst_cos)

{
	odp_pmr_t pmr;
	odp_pmr_set_t pmr_set_id;
	int32_t retcode;
	cos_t *cos;

	cos = get_cos_entry(src_cos);
	if (!cos) {
		ODP_ERR("Invalid odp_cos_t handle");
		return ODP_PMR_INVAL;
	}
	if (num_terms > 1) {
		retcode = odp_pmr_match_set_create(num_terms, terms, &pmr_set_id);
		if (retcode < 0)
			return ODP_PMR_INVAL;
		retcode = odp_pktio_pmr_match_set_cos(pmr_set_id, cos->s.pktio_in, dst_cos);
		if (retcode < 0)
			return ODP_PMR_INVAL;
		return (odp_pmr_t)pmr_set_id;
	} else {
		pmr = odp_pmr_create(terms);
		retcode = odp_pktio_pmr_cos(pmr, cos->s.pktio_in, dst_cos);
		if (retcode < 0)
			return ODP_PMR_INVAL;
		return pmr;
	}
}

int odp_cls_pmr_destroy(odp_pmr_t pmr_id)
{
	pmr_t *pmr;
	pmr_set_t *pmr_set;

	pmr = get_pmr_entry((odp_pmr_t)pmr_id);
	pmr_set = get_pmr_set_entry((odp_pmr_set_t)pmr_id);
	if (!pmr && !pmr_set) {
		ODP_ERR("Invalid odp_pmr_t handle");
		return -1;
	}
	if (pmr_set)
		return odp_pmr_match_set_destroy(pmr_set);
	else
		return odp_pmr_destroy(pmr);
}

/*Update pmr_info array for created PMR and PMR set.*/
void set_pmr_info(void *rule)
{
	odp_cls_pmr_term_t  term;		/* PMR Term */
	int32_t loop = 0;
	uint32_t i = 0;
	pmr_set_t *pmr = (pmr_set_t *)rule;

	/*Check for valid PMR*/
	if (!pmr) {
		ODP_ERR("No PMR rule found");
		return;
	}

check_next:
	for (; i < pmr->s.num_pmr; i++) {
		term	= pmr->s.term_value[i].term;
		/* Scan list of pmr_info for any exiting PMR type.
		   If PMR type is not present then updated it with new one.
		*/
		for (loop = 0; loop < DPKG_MAX_NUM_OF_EXTRACTS; loop++) {
			if (pmr_info[loop].type == term) {
				++i;
				goto check_next;
			}
		}

		/*If pmr_info is full, No New pmr type can be added*/
		if (pmr_index >= DPKG_MAX_NUM_OF_EXTRACTS) {
			ODP_ERR("Maximum PMR limit reached\n");
			return;
		}

		/*No existing entry found. pmr_info updation starts from here*/
		switch (term) {
		case ODP_PMR_LEN:
			pmr_info[pmr_index].type = ODP_PMR_LEN;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_ETHTYPE_0:
			pmr_info[pmr_index].type = ODP_PMR_ETHTYPE_0;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_ETHTYPE_X:
			pmr_info[pmr_index].type = ODP_PMR_ETHTYPE_X;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_VLAN_ID_0:
			pmr_info[pmr_index].type = ODP_PMR_VLAN_ID_0;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_VLAN_ID_X:
			pmr_info[pmr_index].type = ODP_PMR_VLAN_ID_X;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_DMAC:
			pmr_info[pmr_index].type = ODP_PMR_DMAC;
			pmr_info[pmr_index].size = sizeof(uint64_t);
			break;
		case ODP_PMR_IPPROTO:
			pmr_info[pmr_index].type = ODP_PMR_IPPROTO;
			pmr_info[pmr_index].size = sizeof(uint8_t);
			break;
		case ODP_PMR_UDP_DPORT:
			pmr_info[pmr_index].type = ODP_PMR_UDP_DPORT;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_TCP_DPORT:
			pmr_info[pmr_index].type = ODP_PMR_TCP_DPORT;
			pmr_info[pmr_index].size = sizeof(uint16_t);
		break;
		case ODP_PMR_UDP_SPORT:
			pmr_info[pmr_index].type = ODP_PMR_UDP_SPORT;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_TCP_SPORT:
			pmr_info[pmr_index].type = ODP_PMR_TCP_SPORT;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_SIP_ADDR:
			pmr_info[pmr_index].type = ODP_PMR_SIP_ADDR;
			pmr_info[pmr_index].size = sizeof(uint32_t);
			break;
		case ODP_PMR_DIP_ADDR:
			pmr_info[pmr_index].type = ODP_PMR_DIP_ADDR;
			pmr_info[pmr_index].size = sizeof(uint32_t);
			break;
		case ODP_PMR_SIP6_ADDR:
			pmr_info[pmr_index].type = ODP_PMR_SIP6_ADDR;
			pmr_info[pmr_index].size = 16;
			break;
		case ODP_PMR_DIP6_ADDR:
			pmr_info[pmr_index].type = ODP_PMR_DIP6_ADDR;
			pmr_info[pmr_index].size = 16;
			break;
		case ODP_PMR_IPSEC_SPI:
			pmr_info[pmr_index].type = ODP_PMR_IPSEC_SPI;
			pmr_info[pmr_index].size = sizeof(uint32_t);
			break;
		case ODP_PMR_LD_VNI:
			pmr_info[pmr_index].type = ODP_PMR_LD_VNI;
			pmr_info[pmr_index].size = sizeof(uint32_t);
			break;
		default:
			ODP_PRINT("Term type does not supported");
			return;
		}
		if (pmr_info[pmr_index].is_valid == 0) {
			/*Save the position. It will be used while destroying
			  PMR*/
			pmr->s.pos[i] = pmr_index;
			key_cfg_len += pmr_info[pmr_index].size;
			pmr_info[pmr_index++].is_valid = 1;
		}
	}
}

/*
 * A packet matching rule is required to be written in the same order as key
 * extract paramaters are configured. This function updates the offset value
 * in PMR according to PMR type. Updated offset will be used to get correct
 * location in rule memory where data is to be written.
 */
void odp_update_pmr_set_offset(pktio_entry_t *pktio ODP_UNUSED,
			       pmr_set_t *pmr_set)
{
	uint8_t i, j, offset;
	uint8_t *stream, *mask;

	for (j = 0; j < pmr_set->s.num_pmr; j++) {
		offset = 0;
		for (i = 0; pmr_info[i].is_valid; i++) {
			if (pmr_info[i].type == (pmr_set->s.term_value[j].term))
				break;
			offset = offset + pmr_info[i].size;
		}

		/*Write rules on iova memory to be configured*/
		stream = (uint8_t *)(pmr_set->s.rule.key_iova + offset);
		mask = (uint8_t *)(pmr_set->s.rule.mask_iova + offset);
		memcpy(stream, (void *)(pmr_set->s.term_value[j].val), pmr_info[i].size);
		memcpy(mask, (void *)(pmr_set->s.term_value[j].mask), pmr_info[i].size);
		dpaa2_free((void *)(pmr_set->s.term_value[j].val));
		dpaa2_free((void *)(pmr_set->s.term_value[j].mask));
		pmr_set->s.term_value[j].val = (uint64_t)NULL;
		pmr_set->s.term_value[j].mask = (uint64_t)NULL;
	}
	pmr_set->s.rule.key_size = key_cfg_len;

}

/*
 * Similar function as above but works for single PMR only
 */
void odp_update_pmr_offset(pktio_entry_t *pktio ODP_UNUSED, pmr_t *pmr)
{
	uint8_t i, offset = 0;
	uint8_t *stream, *mask;

	for (i = 0; pmr_info[i].is_valid; i++) {
		if (pmr_info[i].type == (pmr->s.term_value[0].term))
			break;
		offset = offset + pmr_info[i].size;
	}

	/*Write rules on iova memory to be configured*/
	stream = (uint8_t *)(pmr->s.rule.key_iova + offset);
	mask = (uint8_t *)(pmr->s.rule.mask_iova + offset);

	memcpy(stream, (void *)(pmr->s.term_value[0].val), pmr_info[i].size);
	memcpy(mask, (void *)(pmr->s.term_value[0].mask), pmr_info[i].size);
	pmr->s.rule.key_size = key_cfg_len;
}

int odp_cls_capability(odp_cls_capability_t *capability)
{
	unsigned count = 0;
	int i;

	for (i = 0; i < ODP_PMR_MAX_ENTRY; i++)
		if (!pmr_tbl->pmr[i].s.valid)
			count++;

	capability->max_pmr_terms = ODP_PMR_MAX_ENTRY;
	capability->available_pmr_terms = count;
	capability->max_cos = ODP_COS_MAX_ENTRY;
	capability->pmr_range_supported = false;
	capability->supported_terms.all_bits = 0;

	/*Layer 2 header fields*/
	capability->supported_terms.bit.dmac = 1;
	capability->supported_terms.bit.ethtype_0 = 1;
	capability->supported_terms.bit.vlan_id_0 = 1;
	/*Layer 3 header fields*/
	capability->supported_terms.bit.len = 1;
	capability->supported_terms.bit.ip_proto = 1;
	capability->supported_terms.bit.sip_addr = 1;
	capability->supported_terms.bit.dip_addr = 1;
	capability->supported_terms.bit.sip6_addr = 1;
	capability->supported_terms.bit.dip6_addr = 1;
	/*Layer 4 header fields*/
	capability->supported_terms.bit.udp_dport = 1;
	capability->supported_terms.bit.udp_sport = 1;
	capability->supported_terms.bit.tcp_sport = 1;
	capability->supported_terms.bit.tcp_dport = 1;
	return 0;
}

/*
 *Internal function init shadow database of classfication rules lists
 */
void init_pktio_cls_rule_list(uint32_t index)
{
	/*Initialize locally maintained shadow database*/
	TAILQ_INIT(&pmr_rule_list[index]);
	TAILQ_INIT(&l2_rule_list[index]);
	TAILQ_INIT(&l3_rule_list[index]);
}

/*
 *Internal function init classifier module with its default configuration
 */
int pktio_classifier_init(pktio_entry_t *entry)
{
	classifier_t *cls;
	int i;
	uint8_t *param;
	struct dpkg_profile_cfg *key_cfg;

	/* classifier lock should be acquired by the calling function */
	if (entry == NULL)
		return -1;
	cls = &entry->s.cls;
	cls->num_pmr = 0;
	cls->flow_set = 0;
	cls->error_cos = NULL;
	cls->default_cos = NULL;
	cls->skip = 0;

	param = dpaa2_data_zmalloc(NULL, DIST_PARAM_IOVA_SIZE,
						ODP_CACHE_LINE_SIZE);
	if (!param) {
		ODP_ERR("Memory unavaialble");
		return -ENOMEM;
	}
	key_cfg = dpaa2_data_zmalloc(NULL, sizeof(struct dpkg_profile_cfg),
						ODP_CACHE_LINE_SIZE);
	if (!key_cfg) {
		ODP_ERR("Memory unavaialble");
		dpaa2_data_free((void *)param);
		return -ENOMEM;
	}
	cls->l3_precedence = 0;
	cls->flow_id = ODP_CLS_DEFAULT_FLOW;
	cls->tc_cfg.key_cfg_iova = (uint64_t)param;
	cls->tc_cfg.dist_mode = DPNI_DIST_MODE_FS;
	cls->tc_cfg.fs_cfg.miss_action = DPNI_FS_MISS_DROP;
	entry->s.priv = key_cfg;

	for (i = 0; i < ODP_PKTIO_MAX_PMR; i++) {
		cls->pmr[i] = NULL;
		cls->cos[i] = NULL;
	}
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

odp_pool_t odp_cls_cos_pool(odp_cos_t cos_id ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return ODP_POOL_INVALID;
}

odp_cls_drop_t odp_cos_drop(odp_cos_t cos_id ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}
