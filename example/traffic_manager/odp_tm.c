/* Copyright 2017 NXP
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>

#include <example_debug.h>

#include "odp_tm.h"
#include <odp_api.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>
#include <odp/helper/tcp.h>

/** @def MAX_ROUTE
 * @brief Maximum number of route entries
 */
#define MAX_ROUTE            32

/** @def MAX_WORKERS
 * @brief Maximum number of worker threads
 */
#define MAX_WORKERS            32

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      (10000 * 2048)

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE  1856

/** @def MAX_PKT_BURST
 * @brief Maximum number of packet bursts
 */
#define MAX_PKT_BURST          1

/** @def MAX_TM_SYSTEM_PRIO
 * @brief Maximum number of Priorities
 */
#define MAX_TM_SYSTEM_PRIO          8

/** @def DEFAULT_THRESHOLD
 * @brief Default threshold value applied on tm_queues in number of packets.
 */
#define DEFAULT_THRESHOLD          250

/** @def DEFAULT_WEIGHT
 * @brief Default weight value applied on tm_queues
 */
#define DEFAULT_WEIGHT          128

/** @def DEFAULT_SHAPER_RATE
 * @brief Default shaping rate applied on shaping profile
 */
#define DEFAULT_SHAPER_RATE          10000

/** @def DEFAULT_SHAPER_BURST_SIZE
 * @brief Default burst size applied on shaping profile
 */
#define DEFAULT_SHAPER_BURST_SIZE          32

/** @def APPL_SCHED_MODE_STRICT_PRIO
 * @brief tm_queues will be configuerd in Strict Priority Scheduling
 */
#define APPL_SCHED_MODE_STRICT_PRIO	0

/** @def APPL_SCHED_MODE_WEIGHTED
 * @brief tm_queues will be configuerd in Weighted Scheduling Scheduling
 */
#define APPL_SCHED_MODE_WEIGHTED    1

/** @def PRINT_APPL_MODE(x)
 * @brief Macro to print the current status of how the application handles
 * packets.
 */
#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

/**
 * Structure to represent pool and pktio mapping
 */
typedef struct {
	/*tm_egress port for enqueue operation*/
	odp_pktio_t  pktio;
	/*tm_queues handles for dequeue operation*/
	odp_tm_queue_t *tm_node_queue;
	/*Corresponding attached pool on the pktio*/
	odp_pool_t pool;
} dev_pool_map_t;

/**
 * Parsed command line application arguments
 */
typedef struct {
	int cpu_count;	/**< Number of CPUs to use */
	int if_count;	/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	dev_pool_map_t *map; /**< Array of pointers to dev-pool map list */
	int mode;	/**< Scheduling mode */
	char *if_str;	/**< Storage for interface names */
	uint8_t	prio;	/**< Number of priorities. Valid only if mode is
				APPL_SCHED_MODE_STRICT_PRIO*/
	struct weight_s {
		char *queue[MAX_TM_SYSTEM_PRIO];
		uint8_t value[MAX_TM_SYSTEM_PRIO];
		uint8_t	num_queues;
	} weight;
	struct shaper_s {
		uint64_t	rate;	/*Shaping rate in Mbps*/
		uint32_t	burst_size; /*Burst size in KB*/
		odp_bool_t shaping;	/**< Flag to enable/disable shaping*/
	} shaper;
	uint32_t	threshold;
	char	*route_str[MAX_ROUTE];	/**< Storage for route entries*/
	int32_t	free_entries;	/**< Available number of flows that can be
				configured*/
} appl_args_t;

/**
 * Thread specific arguments
 */
typedef struct {
	char *pktio_dev;	/**< Interface name to use */
	int mode;	/**< Thread mode */
} thread_args_t;

/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
	/** Flag to exit worker threads */
	int exit_threads;
} args_t;

/** Global pointer to args */
static args_t *args;

/** Route index to track routing entry */
static int32_t route_index;

/**
 * Calculate hash value on given 5-tuple i.e. sip, dip, sport, dport, ip proto
 *
 * @param ip_src	Source IP Address
 * @param ip_dst	Destination IP Address
 * @param l4_sport	Source Port Number
 * @param l4_dport	Destination Port Number
 * @param ip_proto	IP protocol
 *
 * @return Resultant hash value
 */
#if ODP_TM_PERF_MODE
static inline uint64_t odp_calculate_hash(uint32_t ip_src, uint32_t ip_dst,
					  uint16_t l4_sport ODP_UNUSED,
						uint16_t l4_dport ODP_UNUSED,
						uint8_t	ip_proto ODP_UNUSED)
#else
static inline uint64_t odp_calculate_hash(uint32_t ip_src, uint32_t ip_dst,
					  uint16_t l4_sport,
						uint16_t l4_dport,
						uint8_t	ip_proto)
#endif
{
	uint64_t l4_ports = 0;

	ip_dst += JHASH_GOLDEN_RATIO;
#if !ODP_TM_PERF_MODE
	l4_ports = (((uint32_t)l4_sport << 16) | ((uint32_t)l4_dport));
#endif
	ODP_BJ3_MIX(ip_src, ip_dst, l4_ports);
#if !ODP_TM_PERF_MODE
	l4_ports += ip_proto;
	ODP_BJ3_MIX(ip_src, ip_dst, l4_ports);
#endif
	return l4_ports;
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	int i;
	char buf[16];

	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "CPU model:       %s\n"
	       "CPU freq (hz):   %"PRIu64"\n"
	       "Cache line size: %i\n"
	       "CPU count:       %i\n"
	       "\n",
	       odp_version_api_str(), odp_cpu_model_str(), odp_cpu_hz_max(),
	       odp_sys_cache_line_size(), odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n"
	       "Mode:            ");
	switch (appl_args->mode) {
	case APPL_SCHED_MODE_STRICT_PRIO:
		PRINT_APPL_MODE(APPL_SCHED_MODE_STRICT_PRIO);
		break;
	case APPL_SCHED_MODE_WEIGHTED:
		PRINT_APPL_MODE(APPL_SCHED_MODE_WEIGHTED);
		break;
	}
	if (appl_args->shaper.shaping)
		strcpy(buf, "enabled");
	else
		strcpy(buf, "disabled");
	buf[strlen(buf)] = '\0';
	printf("Shaper:\t\t%s\n", buf);
	printf("\n\n");
	fflush(NULL);
}

/**
 * Drop packets which input parsing marked as containing errors.
 *
 * Frees packets with error and modifies pkt_tbl[] to only contain packets with
 * no detected errors.
 *
 * @param pkt_tbl  Array of packet
 * @param len      Length of pkt_tbl[]
 *
 * @return Number of packets with no detected error
 */
static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	unsigned pkt_cnt = len;
	unsigned i, j;

	for (i = 0, j = 0; i < len; ++i) {
		pkt = pkt_tbl[i];

		if (odp_unlikely(odp_packet_has_error(pkt))) {
			odp_packet_free(pkt); /* Drop */
			pkt_cnt--;
		} else if (odp_unlikely(i != j++)) {
			pkt_tbl[j - 1] = pkt;
		}
	}

	return pkt_cnt;
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
		"Usage: %s OPTIONS\n"
		"  E.g. %s -i eth1,eth2,eth3 -m 0\n"
		"\n"
		"OpenDataPlane example application.\n"
		"\n"
		"Mandatory OPTIONS:\n"
		"  -i, --interface Eth interfaces(comma-separated, no spaces)\n"
		"\n"
		"Optional OPTIONS\n"
		"  -c, --count <number> CPU count.\n"
		"  -d, --Destination SubNet:Intf:NextHopMAC\n"
		"	SubNet: IPaddress with mask bits\n"
		"	\ti.e. aa:bb:cc:dd/maskbits\n"
		"	Intf: Interface name i.e. dpni.0\n"
		"	NextHopMAC: Destination Mac Address for next hop.\n"
		"	\tBytes are dot(.) separated i.e. 00.00.00.00.08.01\n"
		"  -m, --mode\n"
		"	0: Scheduling profile as Strict Priority\n"
		"	1: Scheduling profile as Weighted scheduling.\n"
		"	Default Scheduling profile as Strict Priority\n"
		"  -t,  --threshold <number> Value of thrshold applied on \n"
		"			tm_queues.\n"
		"			Values must be in range (1, 10000)\n"
		"			Default value is 250 packets\n"
		"  -s,  --shaping <boolean> Flag to enable/disable shaping.\n"
		"	0: To disable\n"
		"	1: To enable.\n"
		"	Default shaper is disabled\n"
		"  -r,  --rate <number> Shaping rate in Mbps. Valid only if\n"
		"			shaping is enabled\n"
		"			Values must be in range (1, 10000)\n"
		"			If shaping is enabled and rate is not\n"
		"			given then shaper will be configured\n"
		"			with full bandwidth i.e. 10000\n"
		"  -b, --burst-size <number> maximum burst size in KB.Valid\n"
		"			only if shaping is enabled\n"
		"			Values must be in range (1, 64)\n"
		"			If shaping is enabled and burst size\n"
		"			is not given then shaper will be\n"
		"			configured with 32KB\n"
		"  -n, --num-prio <number> Number of priority queues\n"
		"			configured on egress side. Only valid\n"
		"			if scheduling profile is strict prio\n"
		"			Default all supported priority queues\n"
		"			will be configured.\n"
		"  -w, --weight <queue_name>:<weight> Weight value\n"
		"			corresponding to each queue. multiple\n"
		"			queues configuration will be\n"
		"			comma-separated and no spaces.\n"
		"			Values must be in range (1, 255).\n"
		"			If mode = 1 and no weights are given\n"
		"			then scheduling will be round robin\n"
		"			E.g. odp_tm -w queue1:10,queue2:20\n"
		"  -h, --help           Display help and exit.\n"
		"\n", NO_PATH(progname), NO_PATH(progname)
	);
}

static void configure_tm(odp_pktio_t pktio, appl_args_t *appl_args, int map_index)
{
	odp_tm_egress_t tm_egress;
	odp_tm_requirements_t tm_requirements;
	odp_tm_node_params_t tm_node_params;
	odp_tm_shaper_params_t tm_shaper_params;
	odp_tm_queue_params_t tm_node_queue_params;
	odp_tm_sched_params_t tm_sched_params;
	odp_tm_capabilities_t capabilities[1];
	odp_tm_level_capabilities_t	*per_level_cap;
	odp_pktio_capability_t capa;
	odp_tm_t tm_system;
	odp_tm_node_t tm_node;
	odp_tm_shaper_t tm_node_shaper = ODP_TM_INVALID;
	odp_tm_threshold_t tm_node_queue_thres = ODP_TM_INVALID;
	odp_tm_sched_t tm_queue_sched = ODP_TM_INVALID;
	uint8_t prio;
	int32_t retcode;
	int32_t level;
	char name[32];
	uint8_t	num_queues = appl_args->prio;

	/*Initialize all the required objects with default configuration*/
	odp_tm_egress_init(&tm_egress);
	odp_tm_requirements_init(&tm_requirements);
	odp_tm_node_params_init(&tm_node_params);
	odp_tm_queue_params_init(&tm_node_queue_params);

	/*Get traffic management system capabilities*/
	retcode = odp_tm_capabilities(capabilities, 1);
	if (retcode < 0) {
		EXAMPLE_ERR("Error: Failed to get tm capabilities\n");
		return;
	}
	tm_requirements.max_tm_queues = capabilities[0].max_tm_queues;
	tm_requirements.num_levels = capabilities[0].max_levels;

	for (level = 0; level < capabilities[0].max_levels; level++) {
		per_level_cap = &capabilities[0].per_level[level];
		tm_requirements.per_level[level].max_num_tm_nodes = per_level_cap->max_num_tm_nodes;
		tm_requirements.per_level[level].max_fanin_per_node = per_level_cap->max_fanin_per_node;
		tm_requirements.per_level[level].max_priority = per_level_cap->max_priority;
		tm_requirements.per_level[level].tm_node_shaper_needed =
							appl_args->shaper.shaping;
		if (appl_args->weight.num_queues) {
			tm_requirements.per_level[level].min_weight =
						per_level_cap->min_weight;
			tm_requirements.per_level[level].max_weight =
						per_level_cap->max_weight;
			tm_requirements.per_level[level].weights_needed = true;
		}
	}
	tm_egress.egress_kind = ODP_TM_EGRESS_PKT_IO;
	tm_egress.pktio = pktio;
	sprintf(name, "%s-TM", appl_args->if_names[map_index]);
	tm_system = odp_tm_create(name, &tm_requirements, &tm_egress);

	if (appl_args->shaper.shaping == true) {
		odp_tm_shaper_params_init(&tm_shaper_params);
		tm_shaper_params.commit_bps =
			appl_args->shaper.rate * 1024 * 1024; /*Shaping rate in Mbps*/
		tm_shaper_params.peak_bps =
			appl_args->shaper.rate * 1024 * 1024; /*Shaping rate in Mbps*/
		tm_shaper_params.commit_burst =
			appl_args->shaper.burst_size * 1024 * 8; /*Burst size in KB*/
		tm_shaper_params.peak_burst =
			appl_args->shaper.burst_size * 1024 * 8; /*Burst size in KB*/
		tm_shaper_params.dual_rate = false; /*Only Single rate shaping is
						required*/
		sprintf(name, "%s-shaper", appl_args->if_names[map_index]);
		tm_node_shaper = odp_tm_shaper_create(name, &tm_shaper_params);
	}
	odp_tm_threshold_params_t tm_node_queue_thres_params;
	/*Create threshold profile to be attached with tm_node and applied on
	tm_queues*/
	odp_tm_threshold_params_init(&tm_node_queue_thres_params);
	tm_node_queue_thres_params.enable_max_pkts = true;
	tm_node_queue_thres_params.max_pkts = DEFAULT_THRESHOLD;

	if (appl_args->threshold)
		tm_node_queue_thres_params.max_pkts = appl_args->threshold;
	tm_node_queue_thres = odp_tm_threshold_create("queue-thres-profile",
						      &tm_node_queue_thres_params);

	odp_pktio_capability(pktio, &capa);
	tm_node_params.level = 0;
	tm_node_params.max_fanin = capa.max_output_queues;
	tm_node_params.shaper_profile = tm_node_shaper;
	tm_node_params.threshold_profile = tm_node_queue_thres;
	sprintf(name, "%s-tm-node", appl_args->if_names[map_index]);
	tm_node = odp_tm_node_create(tm_system, name, &tm_node_params);

	prio = 0;
	if (appl_args->mode == APPL_SCHED_MODE_WEIGHTED) {
		odp_tm_sched_params_init(&tm_sched_params);
		while (prio < capa.max_output_queues) {
			/*Initialize with user passed values*/
			tm_sched_params.sched_modes[prio] =
						ODP_TM_BYTE_BASED_WEIGHTS;
			tm_sched_params.sched_weights[prio] =
						appl_args->weight.value[prio];
			prio++;
		}
		sprintf(name, "%s-queue-sched-profile", appl_args->if_names[map_index]);
		tm_queue_sched = odp_tm_sched_create("queue-sched-profile",
						     &tm_sched_params);
		num_queues = appl_args->weight.num_queues;
	}

	/*Lets configure available queues only*/
	num_queues = num_queues <= capa.max_output_queues ? num_queues :
							capa.max_output_queues;
	for (prio = 0; prio < num_queues; prio++) {
		tm_node_queue_params.priority = prio;
		appl_args->map[map_index].tm_node_queue[prio] =
				odp_tm_queue_create(tm_system,
						    &tm_node_queue_params);
		odp_tm_queue_connect(appl_args->map[map_index].tm_node_queue[prio],
				     tm_node);
		if (appl_args->mode == APPL_SCHED_MODE_WEIGHTED)
			odp_tm_queue_sched_config(tm_node,
						  appl_args->map[map_index].tm_node_queue[prio],
				tm_queue_sched);
	}
	appl_args->prio = num_queues;
	if (appl_args->mode == APPL_SCHED_MODE_WEIGHTED)
		appl_args->weight.num_queues = num_queues;
	return;
}

/**
 * Create a pktio handle, optionally associating a default input queue.
 *
 * @param dev Name of device to open
 * @param pool Pool to associate with device for packet RX/TX
 * @param mode Packet processing mode for this device (BURST or QUEUE)
 *
 * @return The handle of the created pktio object.
 * @retval ODP_PKTIO_INVALID if the create fails.
 */
static odp_pktio_t create_and_configure_tm_system(const char *dev,
						  odp_pool_t pool,
							int map_index)
{
	odp_pktio_t pktio;
	int ret;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktio_capability_t capa;

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;
	pktio_param.out_mode = ODP_PKTOUT_MODE_TM;

	/* Open a packet IO instance */
	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		EXAMPLE_ABORT("Error: pktio create failed for %s\n", dev);

	/*Get pktio capability first then configure*/
	memset(&capa, 0, sizeof(odp_pktio_capability_t));
	ret  = odp_pktio_capability(pktio, &capa);
	if (ret < 0) {
		EXAMPLE_ERR("Error: Getting pktio capability failed\n");
		return ODP_PKTIO_INVALID;
	}

	odp_pktin_queue_param_init(&pktin_param);
	/*Configure Rx queues setup*/
	pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_NONE;
	pktin_param.queue_param.sched.group = ODP_SCHED_GROUP_ALL;
	pktin_param.queue_param.sched.prio = ODP_SCHED_PRIO_HIGHEST;
	pktin_param.hash_enable = TRUE;
	pktin_param.hash_proto.proto.ipv4_udp = TRUE;
	pktin_param.num_queues = capa.max_input_queues;
	if (odp_pktin_queue_config(pktio, &pktin_param))
		EXAMPLE_ABORT("Error: pktin config failed for %s\n", dev);

	/*Configure Tx queues setup*/
	if (odp_pktout_queue_config(pktio, NULL))
		EXAMPLE_ABORT("Error: pktout config failed for %s\n", dev);

	/*Before initializing traffic management, let's allocate memory for
		tm_queues*/
	args->appl.map[map_index].tm_node_queue =
				(odp_tm_queue_t *)calloc(capa.max_output_queues,
				sizeof(odp_tm_queue_t));
	if (!args->appl.map[map_index].tm_node_queue) {
		EXAMPLE_ABORT("Error: Memry allocation failures for tm_queues\n");
	}

	configure_tm(pktio, &args->appl, map_index);
	ret = odp_pktio_start(pktio);
	if (ret != 0)
		EXAMPLE_ABORT("Error: unable to start %s\n", dev);

	printf("  created pktio:%02" PRIu64
	       ", dev:%s, queue mode (ATOMIC queues)\n"
	       "  \tdefault pktio%02" PRIu64 "\n",
	       odp_pktio_to_u64(pktio), dev,
	       odp_pktio_to_u64(pktio));

	return pktio;
}

static  int32_t  get_vlan_tci(void *eth, uint16_t *vlan_tci_ptr)
{
	odph_ethhdr_t  *ether_hdr = (odph_ethhdr_t *)eth;
	odph_vlanhdr_t *vlan_hdr;
	uint16_t        vlan_tci;

	if (ether_hdr->type != odp_be_to_cpu_16(0x8100))
		return -1;

	vlan_hdr  = (odph_vlanhdr_t *)(ether_hdr + 1);
	vlan_tci  = odp_be_to_cpu_16(vlan_hdr->tci);
	if (vlan_tci_ptr)
		*vlan_tci_ptr = vlan_tci;

	return 0;
}

static inline int8_t get_pktio_mapped_tm_queue(odp_pktio_t pktio)
{
	uint8_t i;

	for (i = 0; i < args->appl.if_count; i++)  {
		if (pktio == args->appl.map[i].pktio)
			return i;
	}
	return -1;
}

/**
 * Packet processing function. packet will be looked up in the route table
 * and will forwarded to the interface accordingly
 *
 * @param pkt_tbl Packet array
 *
 * @param pkts_ok Total number of valid frames
 */
static void odp_process_and_send_packet(odp_packet_t pkt_tbl[],
					uint32_t pkts_ok)
{
	uint8_t		proto = 0xFD; /* Testing Protocol number*/
	uint16_t	sport = 0, dport = 0;
	uint32_t	loop, sip, dip;
	uint64_t	hash;
	odp_packet_t	pkt = ODP_PACKET_INVALID;
	odph_ethhdr_t	*eth;
#if !ODP_TM_PERF_MODE
	odph_udphdr_t	*udp;
#endif
	odph_ipv4hdr_t	*ip;
	odp_flow_entry_t *flow = NULL;
	fwd_db_entry_t	*fwd_entry;
	odp_pktio_t pktout;
	odp_tm_queue_t tm_queue;
	uint16_t vlan_tci;
	uint8_t prio, vlan_prio;
	int8_t index;

	for (loop = 0; loop < pkts_ok; loop++) {
		pkt = pkt_tbl[loop];
		if (odp_likely(odp_packet_has_ipv4(pkt))) {
			/* IPv4 */
			/*TODO: Following L3 features are to be supported:
				1. IP fragmenation
				2. IP Options handling
				3. IPv6
			*/
			ip = (odph_ipv4hdr_t *)
				odp_packet_l3_ptr(pkt, NULL);
			sip = odp_be_to_cpu_32(ip->src_addr);
			dip = odp_be_to_cpu_32(ip->dst_addr);
			ip->ttl--;
			ip->chksum = odph_ipv4_csum_update(pkt);
#if !ODP_TM_PERF_MODE
			proto = ip->proto;
			if (odp_packet_has_udp(pkt) || odp_packet_has_tcp(pkt)) {
				/* UDP or TCP*/
				udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
				sport = odp_be_to_cpu_16(udp->src_port);
				dport = odp_be_to_cpu_16(udp->dst_port);
			}
#endif
			hash = odp_calculate_hash(sip, dip, sport, dport,
						  proto);

			flow = odp_route_flow_lookup_in_bucket(sip, dip, sport,
							       dport, proto,
					&flow_table[hash & (bucket_count - 1)]);
			if (flow) {
#if ODP_TM_DEBUG
				EXAMPLE_DBG("Packet sent successfully.\n");
#endif
				goto send_packet;
			} else {
				/*Check into Routing table*/
				fwd_entry = find_fwd_db_entry(dip);
				if (fwd_entry) {
					/*First check for maximum number of flows limit*/
					if (!args->appl.free_entries) {
#if ODP_TM_DEBUG
						EXAMPLE_DBG("Flow entries are reached at maximum\n");
#endif
						goto drop_packet;
					}

					/*Entry found. Updated in Flow table first.*/
					flow = calloc(1, sizeof(odp_flow_entry_t));
					if (!flow) {
						EXAMPLE_ABORT("Failure to allocate memory");
					}
					flow->l3_src = sip;
					flow->l3_dst = dip;
					flow->l4_sport = sport;
					flow->l4_dport = dport;
					flow->l3_proto = proto;
					flow->out_port.pktio = fwd_entry->pktio;
					memcpy(flow->out_port.addr.addr,
					       fwd_entry->src_mac,
						ODPH_ETHADDR_LEN);
					memcpy(flow->out_port.next_hop_addr.addr,
					       fwd_entry->dst_mac,
						ODPH_ETHADDR_LEN);
					flow->next = NULL;
					/*Insert new flow into flow cache table*/
					/*TODO: Age out is not supported currently for route cache entries.
					All the configured flows will remain in table till the process
					terminates*/
					odp_route_flow_insert_in_bucket(flow,
									&flow_table[hash & (bucket_count - 1)]);
					args->appl.free_entries--;
					goto send_packet;
				} else {
#if ODP_TM_DEBUG
					EXAMPLE_DBG("No flow match found. Packet is dropped.\n");
#endif
					goto drop_packet;
				}
			}
		} else {
#if ODP_TM_DEBUG
			EXAMPLE_DBG("No IPv4 Header found. Packet is dropped.\n");
#endif
			goto drop_packet;
		}
send_packet:
		eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
		eth->dst = flow->out_port.next_hop_addr;
		eth->src = flow->out_port.addr;

		pktout = flow->out_port.pktio;
		/*By default all packets will be transmitted to lowest priority
		queue*/
		prio = args->appl.prio - 1;
		if (args->appl.mode == APPL_SCHED_MODE_WEIGHTED)
			prio = args->appl.weight.num_queues - 1;
		/*Now Update priority based on below criteria:
			1. If packet has VLAN header then use VLAN priority
			field.
			2. if VLAN priority is greater than supported
			priorities at platform then use lowest priority queue.*/
		if (get_vlan_tci((void *)eth, &vlan_tci) == 0) {
			vlan_prio = (vlan_tci >> ODPH_VLANHDR_PCP_SHIFT);
			if (vlan_prio <= prio)
				prio = vlan_prio;
		}

		/*Retrieve output queue based on Prio*/
		index = get_pktio_mapped_tm_queue(pktout);
		tm_queue = args->appl.map[index].tm_node_queue[prio];
		/* Enqueue the packet for output */
		if (odp_tm_enq(tm_queue, pkt) != 0) {
			odp_packet_free(pkt);
			continue;
		}
	}

	return;

drop_packet:
	odp_packet_free(pkt);
}

/**
 * Packet IO loopback worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static int tm_sched_thread(void *arg)
{
	odp_pktio_t pktio;
	thread_args_t *thr_args;
	odp_packet_t pkt[1];
	odp_event_t ev;
	unsigned long pkt_cnt = 0;
	unsigned long err_cnt = 0;
	int thr;

	thr = odp_thread_id();
	thr_args = arg;

	pktio = odp_pktio_lookup(thr_args->pktio_dev);
	if (pktio == ODP_PKTIO_INVALID) {
		EXAMPLE_ERR("  [%02i] Error: lookup of pktio %s failed\n",
			    thr, thr_args->pktio_dev);
		return -1;
	}

	printf("  [%02i] looked up pktio:%02" PRIu64
	       ", queue mode (ATOMIC queues)\n"
	       "         default pktio%02" PRIu64 "\n",
	       thr, odp_pktio_to_u64(pktio), odp_pktio_to_u64(pktio));

	/* Loop packets */
	while (!args->exit_threads) {
		ev = odp_schedule(NULL, ODP_SCHED_NO_WAIT);
		if (ev == ODP_EVENT_INVALID)
			continue;

		pkt[0] = odp_packet_from_event(ev);
		if (!odp_packet_is_valid(pkt[0]))
			continue;

		/* Drop packets with errors */
		if (odp_unlikely(drop_err_pkts(pkt, 1) == 0)) {
			EXAMPLE_ERR("Drop frame - err_cnt:%lu\n", ++err_cnt);
			continue;
		}

		odp_process_and_send_packet(pkt, 1);

		/* Print packet counts every once in a while */
		if (odp_unlikely(pkt_cnt++ % 100000 == 0)) {
			printf("  [%02i] pkt_cnt:%lu\n", thr, pkt_cnt);
			fflush(NULL);
		}
	}

	return 0;
}

static int32_t tm_parse_weight_option(appl_args_t *appl_args)
{
	char *token;
	char *options_string;
	int32_t len, i = 0;

	len = strlen(optarg);
	options_string = malloc(len + 1);
	strcpy(options_string, optarg);
	options_string[len] = '\0';

	token = strtok(options_string, ":");
	do {
		/* Queue Name */
		appl_args->weight.queue[i] = malloc(ODP_QUEUE_NAME_LEN);
		strncpy(appl_args->weight.queue[i], token,
			ODP_QUEUE_NAME_LEN - 1);
		/* Weight Value */
		token = strtok(NULL, ",");
		appl_args->weight.value[i] = atoi(token);
		if (appl_args->weight.value[i] < ODP_TM_MIN_SCHED_WEIGHT) {
			EXAMPLE_ERR("Weight value is out of range\n");
			return -1;
		}
		token = strtok(NULL, ":");

		i++;
	} while ((i < MAX_TM_SYSTEM_PRIO) && token);

	if (i > 8) {
		EXAMPLE_ERR("Supported upto 8 Prioritites only.\n");
		return -1;
	}
	appl_args->weight.num_queues = i;
	return 0;
}

static void tm_init_default_app_args(appl_args_t *appl_args)
{
	int i;

	appl_args->cpu_count = MAX_WORKERS;
	/* Scheduling parameters*/
	appl_args->mode = APPL_SCHED_MODE_STRICT_PRIO;
	appl_args->prio = MAX_TM_SYSTEM_PRIO;
	appl_args->free_entries = ODP_MAX_FLOW_COUNT; /*Free location count in
							Hash table*/

	for (i = 0; i < MAX_TM_SYSTEM_PRIO; i++)
		appl_args->weight.value[i] = DEFAULT_WEIGHT;

	/* Shaper parameters */
	appl_args->shaper.shaping = false;
	appl_args->shaper.rate = DEFAULT_SHAPER_RATE;
	appl_args->shaper.burst_size = DEFAULT_SHAPER_BURST_SIZE;
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void tm_parse_options(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *token, *local;
	size_t len;
	int i;
	static const struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},	/* return 'c' */
		{"destination", required_argument, NULL, 'd'},	/* return 'c' */
		{"threshold", required_argument, NULL, 't'},	/* return 't' */
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"mode", required_argument, NULL, 'm'},	/* return 'm' */
		{"shaping", required_argument, NULL, 's'},	/* return 's' */
		{"rate", required_argument, NULL, 'r'},		/* return 'r' */
		{"burst size", required_argument, NULL, 'b'},	/* return 'b' */
		{"weight", required_argument, NULL, 'w'},	/* return 'w' */
		{"num-prio", required_argument, NULL, 'n'},	/* return 'n' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	static const char *shortopts = "+c:d:i:m:w:n:s:t:b:r:h";

	/* let helper collect its own arguments (e.g. --odph_proc) */
	odph_parse_options(argc, argv, shortopts, longopts);

	opterr = 0; /* do not issue errors on helper options */

	while (1) {
		opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->cpu_count = atoi(optarg);
			break;
		case 't':
			appl_args->threshold = atoi(optarg);
			break;
			/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->if_str = malloc(len);
			if (appl_args->if_str == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL;
			     token = strtok(NULL, ","), i++)
				;

			appl_args->if_count = i;

			if (appl_args->if_count == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
			    calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL; token = strtok(NULL, ","), i++) {
				appl_args->if_names[i] = token;
			}
			break;

		case 'm':
			i = atoi(optarg);
			switch (i) {
			case 0:
				appl_args->mode = APPL_SCHED_MODE_STRICT_PRIO;
				break;
			case 1:
				appl_args->mode = APPL_SCHED_MODE_WEIGHTED;
				break;
			default:
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			break;
		/*Configure Route in forwarding database*/
		case 'd':
			if (route_index >= MAX_ROUTE) {
				printf("No more routes can be added\n");
				break;
			}
			local = calloc(1, strlen(optarg) + 1);
			if (!local) {
				EXAMPLE_ABORT("Failure to allocate memory");
				break;
			}
			memcpy(local, optarg, strlen(optarg));
			local[strlen(optarg)] = '\0';
			appl_args->route_str[route_index++] = local;
			break;
		case 's':
			appl_args->shaper.shaping = atoi(optarg);
			break;
		case 'r':
			appl_args->shaper.rate = atoi(optarg);
			break;
		case 'b':
			appl_args->shaper.burst_size = atoi(optarg);
			break;
		case 'w':
			i = tm_parse_weight_option(appl_args);
			if (i < 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			break;
		case 'n':
			appl_args->prio = atoi(optarg);
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}

	if (appl_args->if_count == 0 || appl_args->mode == -1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * ODP Traffic Manager example main function
 */
int main(int argc, char *argv[])
{
	odph_odpthread_t thread_tbl[MAX_WORKERS];
	odp_pool_t pool;
	odp_pktio_t pktio;
	int num_workers;
	int i;
	int cpu;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	odp_instance_t instance;
	odph_odpthread_params_t thr_params;
	char pool_name[ODP_POOL_NAME_LEN];
	uint8_t	mac[ODPH_ETHADDR_LEN];

	args = calloc(1, sizeof(args_t));
	if (!args) {
		EXAMPLE_ABORT("Error: args mem allocation failed.\n");
	}

	tm_init_default_app_args(&args->appl);
	/* Parse and store the application arguments */
	tm_parse_options(argc, argv, &args->appl);

	args->appl.map = (dev_pool_map_t *)calloc(args->appl.if_count,
						sizeof(dev_pool_map_t));
	if (!args->appl.map) {
		free(args);
		EXAMPLE_ABORT("Error: args mem allocation failed.\n");
	}

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		EXAMPLE_ABORT("Error: ODP global init failed.\n");
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		EXAMPLE_ABORT("Error: ODP local init failed.\n");
	}

	/*Configure flow entry with default values*/
	odp_init_routing_table();

	/*Populate routing entries into forwarding database*/
	for (i = 0; i < route_index; i++)
		create_fwd_db_entry(args->appl.route_str[i]);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &args->appl);

	/* Default to system CPU count unless user specified */
	num_workers = MAX_WORKERS;
	if (args->appl.cpu_count)
		num_workers = args->appl.cpu_count;

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE / SHM_PKT_POOL_BUF_SIZE;
	params.type        = ODP_POOL_PACKET;

	/* Create a pktio instance for each interface */
	for (i = 0; i < args->appl.if_count; ++i) {
		snprintf(pool_name, ODP_POOL_NAME_LEN - 1,
			 "%s pool", args->appl.if_names[i]);
		pool = odp_pool_create(pool_name, &params);
		if (pool == ODP_POOL_INVALID) {
			EXAMPLE_ABORT("Error: packet pool creation failed.\n");
		}
		odp_pool_print(pool);
		pktio = create_and_configure_tm_system(args->appl.if_names[i],
						       pool, i);
		args->appl.map[i].pktio = pktio;
		args->appl.map[i].pool = pool;
		odp_pktio_mac_addr(args->appl.map[i].pktio, mac, ODPH_ETHADDR_LEN);
		resolve_fwd_db(args->appl.if_names[i], args->appl.map[i].pktio, mac);
	}

	/* Create and start worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;

	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_workers; ++i) {
		odp_cpumask_t thd_mask;
		int if_idx;

		if_idx = i % args->appl.if_count;

		args->thread[i].pktio_dev = args->appl.if_names[if_idx];
		args->thread[i].mode = args->appl.mode;
		/*
		 * Create threads one-by-one instead of all-at-once,
		 * because each thread might get different arguments.
		 * Calls odp_thread_create(cpu) for each thread
		 */
		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);

		thr_params.start = tm_sched_thread;
		thr_params.arg   = &args->thread[i];

		odph_odpthreads_create(&thread_tbl[i], &thd_mask, &thr_params);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	/* Master thread waits for other threads to exit */
	for (i = 0; i < num_workers; ++i)
		odph_odpthreads_join(&thread_tbl[i]);

	for (i = 0; i < args->appl.if_count; ++i)
		odp_pktio_close(odp_pktio_lookup(args->thread[i].pktio_dev));

	for (i = 0; i < args->appl.if_count; ++i) {
		pool = args->appl.map[i].pool;
		odp_pool_destroy(pool);
	}
	free(args->appl.if_names);
	free(args->appl.if_str);
	free(args->appl.map);
	free(args);
	odp_term_local();
	return odp_term_global(instance);
}
