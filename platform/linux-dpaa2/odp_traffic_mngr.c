/* Copyright 2016 NXP
 *
 * Copyright 2015 EZchip Semiconductor Ltd. All Rights Reserved.
 *
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sched.h>
#include <unistd.h>
#include <pthread.h>
#include <odp/api/std_types.h>
#include <protocols/eth.h>
#include <protocols/ip.h>
#include <odp_traffic_mngr_internal.h>

#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <dpaa2_dev.h>
#include <dpaa2_ethdev.h>
#include <dpaa2_dev_priv.h>
#include <dpaa2_vq.h>
#include <fsl_dpni.h>
#include <fsl_dpni_cmd.h>
#include <fsl_mc_sys.h>

/* TM systems table. */
static tm_system_t *odp_tm_systems[ODP_TM_MAX_NUM_SYSTEMS];

/* TM systems shaper profile table. */
static tm_node_obj_t *odp_tm_nodes[ODP_TM_MAX_NUM_TM_NODES];

/* TM systems shaper profile table. */
static tm_shaper_obj_t odp_shaper_profiles[ODP_TM_MAX_TM_NODE_SHAPER_PROFILES];

/* TM systems Scheduler profile table. */
static tm_shaper_obj_t odp_sched_profiles[ODP_TM_MAX_TM_NODE_SCHED_PROFILES];

/* TM systems queue's threshold profile table. */
static tm_queue_thresholds_t
odp_threshold_profiles[ODP_TM_MAX_TM_NODE_QUEUE_THRES_PROFILES];

static struct dpni_tx_priorities_cfg tx_prio_cfg = {
			.tc_sched[0] = {DPNI_TX_SCHED_STRICT_PRIORITY,  0},
			.tc_sched[1] = {DPNI_TX_SCHED_STRICT_PRIORITY,  0},
			.tc_sched[2] = {DPNI_TX_SCHED_STRICT_PRIORITY,  0},
			.tc_sched[3] = {DPNI_TX_SCHED_STRICT_PRIORITY,  0},
			.tc_sched[4] = {DPNI_TX_SCHED_STRICT_PRIORITY,  0},
			.tc_sched[5] = {DPNI_TX_SCHED_STRICT_PRIORITY,  0},
			.tc_sched[6] = {DPNI_TX_SCHED_STRICT_PRIORITY,  0},
			.tc_sched[7] = {DPNI_TX_SCHED_STRICT_PRIORITY,  0}
};

static odp_ticketlock_t tm_profile_lock;

static tm_node_obj_t *tm_node_alloc(void)
{
	tm_node_obj_t *tm_node;
	uint32_t tm_node_idx;

	/* Find an open slot in the odp_tm_nodes array. */
	for (tm_node_idx = 0; tm_node_idx < ODP_TM_MAX_NUM_TM_NODES; tm_node_idx++) {
		if (!odp_tm_nodes[tm_node_idx]) {
			tm_node = malloc(sizeof(tm_node_obj_t));
			memset(tm_node, 0, sizeof(tm_node_obj_t));
			tm_node->tm_idx = tm_node_idx;
			odp_tm_nodes[tm_node_idx] = tm_node;
			return tm_node;
		}
	}

	return NULL;
}

static void tm_node_free(tm_node_obj_t *tm_node)
{
        odp_tm_nodes[tm_node->tm_idx] = NULL;
        free(tm_node);
}

static tm_system_t *tm_system_alloc(void)
{
	tm_system_t *tm_system;
	uint32_t tm_idx;

	/* Find an open slot in the odp_tm_systems array. */
	for (tm_idx = 0; tm_idx < ODP_TM_MAX_NUM_SYSTEMS; tm_idx++) {
		if (!odp_tm_systems[tm_idx]) {
			tm_system = malloc(sizeof(tm_system_t));
			memset(tm_system, 0, sizeof(tm_system_t));
			odp_tm_systems[tm_idx] = tm_system;
			tm_system->tm_idx = tm_idx;
			return tm_system;
		}
	}

	return NULL;
}

static void tm_system_free(tm_system_t *tm_system)
{
        odp_tm_systems[tm_system->tm_idx] = NULL;
        free(tm_system);
}

void odp_tm_requirements_init(odp_tm_requirements_t *requirements)
{
	memset(requirements, 0, sizeof(odp_tm_requirements_t));
}

void odp_tm_egress_init(odp_tm_egress_t *egress)
{
	memset(egress, 0, sizeof(odp_tm_egress_t));
}

int odp_tm_capabilities(odp_tm_capabilities_t capabilities[],
			uint32_t              capabilities_size)
{
#define MIN(a, b) ((a < b) ? a : b)
	odp_tm_level_capabilities_t *per_level_cap;
	odp_tm_capabilities_t       *cap_ptr;
	odp_packet_color_t           color;
	uint32_t                     level_idx, capa_count;
	int32_t		tm_system;

	if (capabilities_size == 0)
		return -1;

	capa_count = MIN(capabilities_size, ODP_TM_MAX_NUM_SYSTEMS);
	for (tm_system = 0; tm_system < capa_count; tm_system++) {
		cap_ptr = &capabilities[tm_system];
		memset(cap_ptr, 0, sizeof(odp_tm_capabilities_t));
	
		cap_ptr->max_tm_queues = ODP_TM_MAX_TM_QUEUES;
		cap_ptr->max_levels                    = ODP_TM_MAX_LEVELS;
		cap_ptr->tm_queue_shaper_supported     = false;
		cap_ptr->egress_fcn_supported          = false;
		cap_ptr->tm_queue_wred_supported       = true;
		cap_ptr->tm_queue_dual_slope_supported = true;
		cap_ptr->vlan_marking_supported        = false;
		cap_ptr->ecn_marking_supported         = false;
		cap_ptr->drop_prec_marking_supported   = false;
		for (color = 0; color < ODP_NUM_PACKET_COLORS; color++)
			cap_ptr->marking_colors_supported[color] = false;

		for (level_idx = 0; level_idx < cap_ptr->max_levels; level_idx++) {
			per_level_cap = &cap_ptr->per_level[level_idx];
			per_level_cap->max_num_tm_nodes   =
						ODP_TM_MAX_TM_NODES_PER_SYSTEM;
			per_level_cap->max_fanin_per_node =
						ODP_TM_MAX_TM_NODE_FANIN;
			per_level_cap->max_priority =
						ODP_TM_MAX_PRIORITIES;
			per_level_cap->min_weight =
						ODP_TM_MIN_SCHED_WEIGHT;
			per_level_cap->max_weight =
						ODP_TM_MAX_SCHED_WEIGHT;
			per_level_cap->tm_node_shaper_supported     = true;
			per_level_cap->tm_node_wred_supported       = false;
			per_level_cap->tm_node_dual_slope_supported = false;
			per_level_cap->fair_queuing_supported       = true;
			per_level_cap->weights_supported            = true;
		}

	}
	return ODP_TM_MAX_NUM_SYSTEMS;
}

odp_tm_t odp_tm_create(const char            *name,
		       odp_tm_requirements_t *requirements,
		       odp_tm_egress_t       *egress)
{
	tm_system_t *tm_system;
	odp_tm_t odp_tm;
	uint32_t                     level_idx;
	odp_tm_level_requirements_t *per_level_req;

	/*Verify input parameters first*/
	if (!requirements) {
		ODP_ERR("Requirements are mandatory. NULL Pointer is passed\n");
		return ODP_TM_INVALID;
	}
	if (requirements->max_tm_queues == 0) {
		ODP_ERR("Minimum one tm_queue is required\n");
		return ODP_TM_INVALID;
	}
	if (requirements->num_levels != ODP_TM_MAX_LEVELS) {
		ODP_ERR("Only one level is supported on tm_system\n");
		return ODP_TM_INVALID;
	}
	for (level_idx = 0; level_idx < requirements->num_levels; level_idx++) {
		per_level_req = &(requirements->per_level[level_idx]);
		if (per_level_req->max_num_tm_nodes != ODP_TM_MAX_TM_NODES_PER_SYSTEM) {
			ODP_ERR("Only one tm_node is supported per tm_system\n"
				"Input value = %u\n",
				per_level_req->max_num_tm_nodes);
			return ODP_TM_INVALID;
		}
		if (per_level_req->max_fanin_per_node > ODP_TM_MAX_TM_NODE_FANIN) {
			ODP_ERR("maximum supported fan-ins per tm_system %d\n",
						ODP_TM_MAX_TM_NODE_FANIN);
			return ODP_TM_INVALID;
		}
		if (per_level_req->max_priority > ODP_TM_MAX_PRIORITIES) {
			ODP_ERR("maximum supported prio level %d\n",
						ODP_TM_MAX_PRIORITIES);
			return ODP_TM_INVALID;
		}
		if (per_level_req->weights_needed &&
			per_level_req->min_weight < ODP_TM_MIN_SCHED_WEIGHT) {
			ODP_ERR("Range for supported weight values (%d-%d)\n",
						ODP_TM_MIN_SCHED_WEIGHT,
						ODP_TM_MAX_SCHED_WEIGHT);
			return ODP_TM_INVALID;

		}
	}
	if (!egress) {
		ODP_ERR("No Egress port is given. Egress port is mandatory.\n");
		return ODP_TM_INVALID;
	}
	if (egress->egress_kind == ODP_TM_EGRESS_FN) {
		ODP_ERR("Egress function as an output port is not supported.\n");
		return ODP_TM_INVALID;
	}
	if (egress->pktio == ODP_PKTIO_INVALID) {
		ODP_ERR("Invalid pktio device is given.\n");
		return ODP_TM_INVALID;
	}

	/* Allocate tm_system_t record. */
	tm_system = tm_system_alloc();
	if (!tm_system)
		return ODP_TM_INVALID;
	
	/*Successfully allocated block for tm_system. Save user passed 
	configuration.*/
	if ((name) && (name[0] != '\0')) {
		memcpy(tm_system->name, name, ODP_TM_NAME_LENGTH - 1);
		tm_system->name[strlen(tm_system->name)] = '\0';
	}

	memcpy(&tm_system->egress, egress, sizeof(odp_tm_egress_t));
	memcpy(&tm_system->requirements, requirements, sizeof(odp_tm_requirements_t));
	odp_tm = MAKE_ODP_TM_HANDLE(tm_system);
	return odp_tm;
}

int odp_tm_destroy(odp_tm_t odp_tm)
{
        tm_system_t *tm_system = GET_TM_SYSTEM(odp_tm);
        tm_system_free(tm_system);
        return 0;
}

void odp_tm_shaper_params_init(odp_tm_shaper_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_shaper_params_t));
}

odp_tm_shaper_t odp_tm_shaper_create(const char *name,
				     odp_tm_shaper_params_t *params)
{
	tm_shaper_params_t *profile_obj;
	odp_tm_shaper_t     shaper_handle = ODP_TM_INVALID;
	uint32_t loop;

	/*Validate input parameters*/
	if (!params) {
		ODP_ERR("Queue parameter pointer is NULL\n");
		return ODP_TM_INVALID;
	}
	if (params->peak_bps < ODP_TM_MIN_SHAPER_BW ||
		params->peak_bps > ODP_TM_MAX_SHAPER_BW) {
		ODP_ERR("Peak rate is out of range (%d-%d)\n",
				ODP_TM_MIN_SHAPER_BW / (1024 * 1024),
				ODP_TM_MAX_SHAPER_BW / (1024 * 1024));
		return ODP_TM_INVALID;
	}
	if (params->commit_bps < ODP_TM_MIN_SHAPER_BW ||
		params->commit_bps > ODP_TM_MAX_SHAPER_BW) {
		ODP_ERR("Commit rate is out of range (%d-%d)\n",
				ODP_TM_MIN_SHAPER_BW / (1024 * 1024),
				ODP_TM_MAX_SHAPER_BW / (1024 * 1024));
		return ODP_TM_INVALID;
	}
	if (params->peak_burst < ODP_TM_MIN_SHAPER_BURST ||
		params->peak_burst > ODP_TM_MAX_SHAPER_BURST) {
		ODP_ERR("Peak burst size is out of range (%d-%d)\n",
			ODP_TM_MIN_SHAPER_BURST / (1024 * 8),
			ODP_TM_MAX_SHAPER_BURST / (1024 * 8));
		return ODP_TM_INVALID;
	}
	if (params->commit_burst < ODP_TM_MIN_SHAPER_BURST ||
		params->commit_burst > ODP_TM_MAX_SHAPER_BURST) {
		ODP_ERR("Commit burst size is out of range (%d-%d)\n",
			ODP_TM_MIN_SHAPER_BURST / (1024 * 8),
			ODP_TM_MAX_SHAPER_BURST / (1024 * 8));
		return ODP_TM_INVALID;
	}
	if (params->dual_rate) {
		ODP_ERR("Dual rate shaping is not supported\n");
		return ODP_TM_INVALID;
	}
	for (loop = 0;  loop < ODP_TM_MAX_TM_NODE_SHAPER_PROFILES; loop++) {
		if (!odp_shaper_profiles[loop].taken) {
			profile_obj = &odp_shaper_profiles[loop].shaper_params;
			shaper_handle = (uint64_t)loop;
			odp_shaper_profiles[loop].taken = true;
			break;
		}
	}
	if (loop >= ODP_TM_MAX_TM_NODE_SHAPER_PROFILES) {
		ODP_ERR("Shaper profile can not be created."
			"Maximum  limit reached (%d)\n",
			ODP_TM_MAX_TM_NODE_SHAPER_PROFILES);
		return ODP_TM_INVALID;
	}

	/*Copy user input parameters */
	profile_obj->commit_rate = params->commit_bps;
	profile_obj->peak_rate = params->peak_bps;
	profile_obj->commit_burst = params->commit_burst;
	profile_obj->peak_burst = params->peak_burst;
	profile_obj->len_adjust = params->shaper_len_adjust;
	profile_obj->dual_rate = params->dual_rate;
	profile_obj->shaper_profile = shaper_handle;
	memcpy(profile_obj->name, name, ODP_TM_NAME_LENGTH - 1);
	profile_obj->name[strlen(profile_obj->name)] = '\0';
	return shaper_handle;
}

int odp_tm_shaper_destroy(odp_tm_shaper_t shaper_profile)
{
	uint32_t index;

	if (shaper_profile == ODP_TM_INVALID) {
		ODP_ERR("Input Handle is Invalid\n");
		return -1;
	}
	index = (uint32_t)shaper_profile;
	odp_shaper_profiles[index].taken = false;
	return 0;
}

void odp_tm_sched_params_init(odp_tm_sched_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_sched_params_t));
}


odp_tm_sched_t odp_tm_sched_create(const char *name,
				   odp_tm_sched_params_t *params)
{
	tm_sched_params_t *profile_obj;
	odp_tm_sched_t     sched_handle = ODP_TM_INVALID;
	uint32_t loop;

	if (!params) {
		ODP_ERR("Queue parameter pointer is NULL\n");
		return ODP_TM_INVALID;
	}
	for (loop = 0;  loop < ODP_TM_MAX_PRIORITIES; loop++) {
		if ((params->sched_modes[loop] != ODP_TM_BYTE_BASED_WEIGHTS) &&
			(params->sched_modes[loop] != ODP_TM_FRAME_BASED_WEIGHTS)) {
			ODP_ERR("Invalid scheduling mode\n");
			return ODP_TM_INVALID;
		}
	}
	for (loop = 0;  loop < ODP_TM_MAX_TM_NODE_SCHED_PROFILES; loop++) {
		if (!odp_sched_profiles[loop].taken) {
			profile_obj = &odp_sched_profiles[loop].sched_params;
			sched_handle = (uint64_t)loop;
			odp_sched_profiles[loop].taken = true;
			break;
		}
	}
	if (loop >= ODP_TM_MAX_TM_NODE_SCHED_PROFILES) {
		ODP_ERR("Scheduling profile can not be created."
			"Maximum  limit reached (%d)\n",
			ODP_TM_MAX_TM_NODE_SCHED_PROFILES);
		return ODP_TM_INVALID;
	}
	for (loop = 0;  loop < ODP_TM_MAX_PRIORITIES; loop++) {
		profile_obj->sched_modes[loop] = params->sched_modes[loop];
		profile_obj->inverted_weights[loop] = params->sched_weights[loop];
	}
	if (name && name[0] != '\0') {
		memcpy(profile_obj->name, name, ODP_TM_NAME_LENGTH -1 );
		profile_obj->name[strlen(profile_obj->name)] = '\0';
	}
	profile_obj->sched_profile = sched_handle;
	return sched_handle;
}

int odp_tm_sched_destroy(odp_tm_sched_t sched_profile)
{
	uint32_t index;

	if (sched_profile == ODP_TM_INVALID) {
		ODP_ERR("Input Handle is Invalid\n");
		return -1;
	}
	index = (uint32_t)sched_profile;
	odp_sched_profiles[index].taken = false;
	return 0;
}

void odp_tm_node_params_init(odp_tm_node_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_node_params_t));
}

odp_tm_node_t odp_tm_node_create(odp_tm_t             odp_tm,
				 const char           *name,
				 odp_tm_node_params_t *params)
{
	tm_node_obj_t *tm_node_obj;
	odp_tm_node_t odp_tm_node;
	tm_system_t *tm_system;
	tm_shaper_params_t *shaper_profile_obj;
	tm_queue_thresholds_t *threshold_profile_obj;
	pktio_entry_t *pktio_entry = NULL;
	struct dpaa2_dev *dev;
	struct dpaa2_dev_priv *dev_priv;
	struct queues_config *q_config;
	struct fsl_mc_io *dpni;
	struct dpni_tx_shaping_cfg tx_cr_shaper, tx_er_shaper;
	struct dpni_congestion_notification_cfg cong_notif_cfg;
	struct qbman_result *result;
	int32_t retcode;
	uint8_t tc_index;

	/* Allocate a tm_node_obj_t record. */
	tm_system = GET_TM_SYSTEM(odp_tm);
	if (!tm_system)
		return ODP_TM_INVALID;

	/*Validate mandatory input parameters*/
	if (params->level > ODP_TM_MAX_LEVELS)
		return ODP_TM_INVALID;

	if (params->max_fanin > ODP_TM_MAX_TM_NODE_FANIN)
		return ODP_TM_INVALID;

	tm_node_obj = tm_node_alloc();
	if (!tm_node_obj)
		return ODP_TM_INVALID;

	odp_tm_node = MAKE_ODP_TM_NODE(tm_node_obj);
	if ((name) && (name[0] != '\0')) {
		memcpy(tm_node_obj->name, name, ODP_TM_NAME_LENGTH - 1);
		tm_node_obj->name[strlen(tm_node_obj->name)] = '\0';
	}
	tm_node_obj->user_context = params->user_context;
	tm_node_obj->max_fanin = params->max_fanin;
	tm_node_obj->is_root_node = false;
	tm_node_obj->level = params->level;
	tm_node_obj->tm_system_idx = tm_system->tm_idx;

	pktio_entry = get_pktio_entry(tm_system->egress.pktio);
	dev = pktio_entry->s.pkt_dpaa2.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;

	/*Configure Shaping profile at underlying layers*/
	if (params->shaper_profile != ODP_TM_INVALID) {
		shaper_profile_obj =
			&(odp_shaper_profiles[params->shaper_profile].shaper_params);

		memset(&tx_er_shaper, 0, sizeof(struct dpni_tx_shaping_cfg));
		memset(&tx_cr_shaper, 0, sizeof(struct dpni_tx_shaping_cfg));
		/*User provided rate (bits per second) is converted to Mbps*/
		tx_cr_shaper.rate_limit =
				shaper_profile_obj->peak_rate / (1024 * 1024);
		/*User provided burst_size (bits) is converted to Bytes*/
		tx_cr_shaper.max_burst_size =
				shaper_profile_obj->peak_burst / 8;
		retcode = dpni_set_tx_shaping(dpni, CMD_PRI_LOW,
						dev_priv->token,
						&tx_cr_shaper,
						&tx_er_shaper, 0);
		if (retcode < 0) {
			ODP_ERR("Error in setting tx shaper: Error Code = %d\n", 
								retcode);
			free(tm_node_obj);
			return -1;
		}
		tm_node_obj->shaper_profile = params->shaper_profile;
	}

	/*Configure Threshold profile at underlying layers*/
	if (params->threshold_profile != ODP_TM_INVALID) {
		threshold_profile_obj =
			&odp_threshold_profiles[params->threshold_profile];
		/*Configure taildrop*/
		memset(&cong_notif_cfg, 0,
		       sizeof(struct dpni_congestion_notification_cfg));

		result = (struct qbman_result *)dev->notification_mem;
		q_config = dpaa2_eth_get_queues_config(dev);
		for (tc_index = 0; tc_index < q_config->num_tcs; tc_index++) {
			if (threshold_profile_obj->enable_max_pkts) {
				cong_notif_cfg.units =
						DPNI_CONGESTION_UNIT_FRAMES;
				cong_notif_cfg.threshold_entry =
					threshold_profile_obj->max_pkts;
				cong_notif_cfg.threshold_exit =
					threshold_profile_obj->max_pkts - 1;
			} else {
				cong_notif_cfg.units =
						DPNI_CONGESTION_UNIT_BYTES;
				cong_notif_cfg.threshold_entry =
					threshold_profile_obj->max_bytes;
				/*Setting 75 percent of bytes as exit point
				  total bytes - (25 % of total bytes) */
				cong_notif_cfg.threshold_exit =
					threshold_profile_obj->max_bytes -
					PERCENTAGE(threshold_profile_obj->max_bytes, 25);
			}
			/* Notify that the queue is not congested when the data
			 * in the queue is below this thershold.
			 */
			cong_notif_cfg.message_ctx = 0;
			cong_notif_cfg.message_iova = (uint64_t)
							(result + tc_index);
			cong_notif_cfg.dest_cfg.dest_type = DPNI_DEST_NONE;
			cong_notif_cfg.notification_mode =
					DPNI_CONG_OPT_WRITE_MEM_ON_ENTER |
					DPNI_CONG_OPT_WRITE_MEM_ON_EXIT |
					DPNI_CONG_OPT_COHERENT_WRITE;
			retcode = dpni_set_congestion_notification(dpni,
								   CMD_PRI_LOW,
						dev_priv->token, DPNI_QUEUE_TX,
						tc_index, &cong_notif_cfg);
			if (retcode) {
				ODP_ERR("Error: congesiton setting failure"
					" TC ID = %hhu (ErrorCode = %d)\n",
					tc_index, retcode);
				return ODP_TM_INVALID;
			}
		}
	}

	return odp_tm_node;
}

int odp_tm_node_destroy(odp_tm_node_t tm_node)
{
	tm_node_obj_t         *tm_node_obj;
	tm_system_t *tm_system;
	pktio_entry_t *pktio_entry = NULL;
	struct dpaa2_dev *dev;
	struct dpaa2_dev_priv *dev_priv;
	struct queues_config *q_config;
	struct fsl_mc_io *dpni;
	struct dpni_tx_shaping_cfg tx_cr_shaper, tx_er_shaper;
	struct dpni_tx_priorities_cfg tx_sched;
	struct dpni_congestion_notification_cfg cong_notif_cfg;
	int32_t retcode;
	uint8_t tc_index;

	if (tm_node == ODP_TM_INVALID) {
		ODP_ERR("Invalid Handle for tm_node\n");
		return -1;
	}
	/* Get tm_node object pointer. */
	 tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	tm_system = odp_tm_systems[tm_node_obj->tm_system_idx];
	if (tm_system) {
		ODP_ERR("Invalid tm_system is attached with tm_node\n");
		return -1;
	}
	pktio_entry = get_pktio_entry(tm_system->egress.pktio);
	dev = pktio_entry->s.pkt_dpaa2.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;

	q_config = dpaa2_eth_get_queues_config(dev);
	/*Configure dpni device with its default state*/
	if (tm_node_obj->shaper_profile != ODP_TM_INVALID) {
		memset(&tx_cr_shaper, 0, sizeof(struct dpni_tx_shaping_cfg));
		memset(&tx_er_shaper, 0, sizeof(struct dpni_tx_shaping_cfg));
		retcode = dpni_set_tx_shaping(dpni, CMD_PRI_LOW,
					dev_priv->token, &tx_cr_shaper,
					&tx_er_shaper, 0);
		if (retcode < 0) {
			ODP_ERR("Error in setting tx shaper: Error Code = %d\n",
								retcode);
			return -1;
		}
	}

	/*Reset taildrop*/
	memset(&cong_notif_cfg, 0,
	       sizeof(struct dpni_congestion_notification_cfg));
	for (tc_index = 0; tc_index < q_config->num_tcs; tc_index++) {
		retcode = dpni_set_congestion_notification(dpni,
							   CMD_PRI_LOW,
						dev_priv->token, DPNI_QUEUE_TX,
						tc_index, &cong_notif_cfg);
		if (retcode < 0) {
			ODP_ERR("Error: Congestion resetting failure"
				" TC ID = %hhu (ErrorCode = %d)\n",
				tc_index, retcode);
			return -1;
		}
	}
	/*Configure Scheduling profile to default i.e. Strict Priority*/
	memset(&tx_sched, 0, sizeof(struct dpni_tx_priorities_cfg));
	for (tc_index = 0; tc_index < q_config->num_tcs; tc_index++)
		tx_sched.tc_sched[tc_index].mode = DPNI_TX_SCHED_STRICT_PRIORITY;
	retcode =  dpni_set_tx_priorities(dpni, CMD_PRI_LOW, dev_priv->token,
								&tx_sched);
	if (retcode < 0) {
		ODP_ERR("Error in setting tx prioroties: Error Code = %d\n",
								retcode);
		return -1;
	}
	tm_node_free(tm_node_obj);
	return 0;
}

void odp_tm_threshold_params_init(odp_tm_threshold_params_t *params)
{
	memset(params, 0, sizeof(odp_tm_threshold_params_t));
}

odp_tm_threshold_t odp_tm_threshold_create(const char *name,
					odp_tm_threshold_params_t *params)

{
	tm_queue_thresholds_t *profile_obj;
	odp_tm_threshold_t     threshold_handle = ODP_TM_INVALID;
	uint32_t loop;

	/*Validate input parameters*/
	if (!params) {
		ODP_ERR("Threshold parameter pointer is NULL\n");
		return ODP_TM_INVALID;
	}

	for (loop = 0;  loop < ODP_TM_MAX_TM_NODE_QUEUE_THRES_PROFILES; loop++) {
		if (!odp_threshold_profiles[loop].taken) {
			profile_obj = &odp_threshold_profiles[loop];
			threshold_handle = (uint64_t)loop;
			odp_threshold_profiles[loop].taken = true;
			break;
		}
	}
	if (loop >= ODP_TM_MAX_TM_NODE_QUEUE_THRES_PROFILES) {
		ODP_ERR("Threshold profile can not be created."
			"Maximum  limit reached (%d)\n",
			ODP_TM_MAX_TM_NODE_QUEUE_THRES_PROFILES);
		return ODP_TM_INVALID;
	}

	if (name) {
		memcpy(profile_obj->name, name, ODP_TM_NAME_LENGTH - 1);
		profile_obj->name[strlen(profile_obj->name)] = '\0';
	}
	profile_obj->enable_max_pkts = params->enable_max_pkts;
	profile_obj->enable_max_bytes = params->enable_max_bytes;
	profile_obj->max_pkts = params->enable_max_pkts ? params->max_pkts : 0;
	profile_obj->max_bytes =
			params->enable_max_bytes ? params->max_bytes : 0;
	profile_obj->thresholds_profile = threshold_handle;
	return threshold_handle;
}

int odp_tm_threshold_destroy(odp_tm_threshold_t threshold_profile)
{
	uint32_t index;

	if (threshold_profile == ODP_TM_INVALID) {
		ODP_ERR("Input Handle is Invalid\n");
		return -1;
	}
	index = (uint32_t)threshold_profile;
	odp_threshold_profiles[index].taken = false;
	return 0;
}

void odp_tm_queue_params_init(odp_tm_queue_params_t *params)
{
	uint32_t loop;

	params->user_context = NULL;
	params->shaper_profile = ODP_TM_INVALID;
	params->threshold_profile = ODP_TM_INVALID;
	for (loop = 0; loop < ODP_NUM_PACKET_COLORS; loop++)
		params->wred_profile[loop] = ODP_TM_INVALID;
	params->priority = 0;
}

odp_tm_queue_t odp_tm_queue_create(odp_tm_t odp_tm,
				   odp_tm_queue_params_t *params)
{
	tm_system_t *tm_system;
	struct dpaa2_dev *dev;
	pktio_entry_t *pktio_entry;
	queue_entry_t *tm_queue_entry;
	odp_tm_requirements_t *requirements;
	uint32_t                     level_idx;

	if (!params) {
		ODP_ERR("Queue parameters are required\n");
		return ODP_TM_INVALID;
	}

	/* Allocate a tm_queue_obj_t record. */
	tm_system = GET_TM_SYSTEM(odp_tm);
	requirements = &tm_system->requirements;
	for (level_idx = 0; level_idx < requirements->num_levels; level_idx++) {
		if (params->priority >= requirements->per_level[level_idx].max_priority) {
			ODP_ERR("Input priority is beyonod supported\n");
			return ODP_TM_INVALID;
		}
	}
	tm_queue_entry = get_free_queue_entry();
	if (!tm_queue_entry) {
		ODP_ERR("tm_queues can not be created\n");
		return ODP_TM_INVALID;
	}
	/*Get Output device from tm_egress point*/
	pktio_entry = get_pktio_entry(tm_system->egress.pktio);
	dev = pktio_entry->s.pkt_dpaa2.dev;
	memcpy(&tm_queue_entry->s.tm_params, params, sizeof(odp_tm_queue_params_t));
	tm_queue_entry->s.tm_idx = tm_system->tm_idx;
	tm_queue_entry->s.pktout = tm_system->egress.pktio;
	tm_queue_entry->s.priv = dev->tx_vq[params->priority];
	tm_queue_entry->s.enqueue = pktout_enqueue;
	tm_queue_entry->s.enqueue_multi = pktout_enq_multi;
	tm_queue_entry->s.status = QUEUE_STATUS_READY;
	return (odp_tm_queue_t)tm_queue_entry;
}

int odp_tm_queue_destroy(odp_tm_queue_t tm_queue)
{
	queue_entry_t *tm_queue_entry = (queue_entry_t *)tm_queue;

	tm_queue_entry->s.priv = NULL;
	tm_queue_entry->s.enqueue = queue_enq_dummy;
	tm_queue_entry->s.enqueue_multi = queue_enq_multi_dummy;
	set_queue_entry_to_free(tm_queue_entry);
	return 0;
}

int odp_tm_queue_sched_config(odp_tm_node_t tm_node,
			      odp_tm_queue_t tm_fan_in_queue,
			      odp_tm_sched_t sched_profile)
{
	tm_node_obj_t *tm_node_obj;
	tm_sched_params_t *sched_params;
	tm_system_t *tm_system;
	pktio_entry_t *pktio_entry;
	struct dpaa2_dev *dev;
	struct dpaa2_dev_priv *dev_priv;
	struct fsl_mc_io *dpni;
	int32_t retcode;
	uint16_t weight;
	queue_entry_t *tm_queue_entry = (queue_entry_t *)tm_fan_in_queue;
	struct dpaa2_vq *tm_vq = (struct dpaa2_vq *)(tm_queue_entry->s.priv);
	uint8_t prio = (uint8_t)tm_vq->tc_index;

	tm_node_obj = GET_TM_NODE_OBJ(tm_node);
	if (!tm_node_obj) {
		ODP_ERR("NULL tm_node_object\n");
		return -1;
	}

	if (sched_profile == ODP_TM_INVALID) {
		ODP_ERR("Invalid scheduling profile\n");
		return -1;
	}

	sched_params = &odp_sched_profiles[sched_profile].sched_params;

	/*Get platform device*/
	tm_system = odp_tm_systems[tm_node_obj->tm_system_idx];
	pktio_entry = get_pktio_entry(tm_system->egress.pktio);
	dev = pktio_entry->s.pkt_dpaa2.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;

	odp_ticketlock_lock(&tm_profile_lock);
	if (sched_params->inverted_weights[prio] >= ODP_TM_MAX_SCHED_WEIGHT)
		sched_params->inverted_weights[prio] = ODP_TM_MAX_SCHED_WEIGHT;
	weight = sched_params->inverted_weights[prio] * 100;
	tx_prio_cfg.tc_sched[prio].mode = DPNI_TX_SCHED_WEIGHTED;
	tx_prio_cfg.tc_sched[prio].delta_bandwidth = weight;
	retcode =  dpni_set_tx_priorities(dpni, CMD_PRI_LOW, dev_priv->token, &tx_prio_cfg);
	if (retcode < 0) {
		ODP_ERR("Error in setting tx prioroties: Error Code = %d\n", 
		retcode);
		return -1;
	}
	odp_ticketlock_unlock(&tm_profile_lock);
	return 0;
}

int odp_tm_queue_connect(odp_tm_queue_t tm_queue, odp_tm_node_t dst_tm_node)
{
	queue_entry_t *src_tm_queue_obj;
	tm_node_obj_t  *dst_tm_node_obj;
	struct dpaa2_vq *tm_vq;

	if ((tm_queue == ODP_TM_INVALID) || (tm_queue == ODP_TM_ROOT) ||
	    (dst_tm_node == ODP_TM_INVALID))
		return -1;

	src_tm_queue_obj = (queue_entry_t *)tm_queue;

	dst_tm_node_obj  = GET_TM_NODE_OBJ(dst_tm_node);
	if ((!dst_tm_node_obj) || dst_tm_node_obj->is_root_node)
		return -1;

	dst_tm_node_obj->current_tm_queue_fanin++;

	/* Finally add this src_tm_queue_obj to the dst_tm_node_obj's fanin
	 * list. */
	tm_vq = (struct dpaa2_vq *)(src_tm_queue_obj->s.priv);
	tm_vq->tc_index = src_tm_queue_obj->s.tm_params.priority;
	return 0;
}

int odp_tm_queue_disconnect(odp_tm_queue_t tm_queue ODP_UNUSED)
{
	/*TBD: Nothing to do*/
	return 0;
}

int odp_tm_enq(odp_tm_queue_t tm_queue, odp_packet_t pkt)
{
	queue_entry_t *tm_qentry;
	odp_buffer_hdr_t *buf_hdr = (odp_buffer_hdr_t *)pkt;

	tm_qentry = (queue_entry_t *)tm_queue;
	return tm_qentry->s.enqueue(tm_qentry, buf_hdr);
}

int odp_tm_enq_with_cnt(odp_tm_queue_t tm_queue ODP_UNUSED, odp_packet_t pkt ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}
