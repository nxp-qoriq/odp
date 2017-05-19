/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_l3fwd.c  ODP basic layer 3 forwarding application
 */

/** enable strtok */
#define _POSIX_C_SOURCE 200112L

/*********************************************************************
			Header inclusion
**********************************************************************/
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>

#include <example_debug.h>

#include "odp_l3fwd.h"
#include <odp_api.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>
#include <odp/helper/tcp.h>

/*********************************************************************
			Macro Definitions
**********************************************************************/
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
#define SHM_PKT_POOL_SIZE      (512 * 2048)

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE  1856

/** @def MAX_PKT_BURST
 * @brief Maximum number of packet bursts
 */
#define MAX_PKT_BURST          32

/** @def APPL_MODE_PKT_BURST
 * @brief The application will handle pakcets in bursts
 */
#define APPL_MODE_PKT_BURST    0

/** @def APPL_MODE_PKT_SCHED
 * @brief The application will handle packets in queues
 */
#define APPL_MODE_PKT_SCHED    1

/**
 * Maximum number of packet IO resources
 */
#define APPL_MAX_PKTIO_ENTRIES 64

/** @def PRINT_APPL_MODE(x)
 * @brief Macro to print the current status of how the application handles
 * packets.
 */
#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))


/*********************************************************************
			Structure Definitions
**********************************************************************/
/**
 * Parsed command line application arguments
 */
typedef struct {
	int32_t		cpu_count;	/**< Number of threads to be spawned */
	int32_t		if_count;	/**< Number of interfaces to be used */
	char		**if_names;	/**< Array of pointers to interface names */
	int32_t		mode;		/**< Packet IO mode */
	int32_t		flows;		/**< Number of flows to be created */
	int32_t		free_entries;	/**< Available number of flows that can be
						configured*/
	char		*route_str[MAX_ROUTE];	/**< Storage for route entries*/
	char		*if_str;	/**< Storage for interface names */
} appl_args_t;

/**
 * Thread specific arguments
 */
typedef struct {
	int32_t		src_idx;	/**< Source interface identifier */
} thread_args_t;

/**
 * Grouping of all global data
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t		appl;
	/** Thread specific arguments */
	thread_args_t		thread[MAX_WORKERS];
	/** Table of pktio handles */
	odp_pktio_t		pktios[APPL_MAX_PKTIO_ENTRIES];
} args_t;

/*********************************************************************
			Global Definitions
**********************************************************************/
/**
 * Pointer to user arguments
 */
static args_t *gbl_args;

/**
 * index value in route table
 */
static int32_t route_index;

void odp_process_and_send_packet(odp_packet_t pkt_tbl[], uint32_t pkts_ok);

/*********************************************************************
			Helper Functions
**********************************************************************/
/**
 * Drop the packets if any error found.
 *
 * Frees packets with error and modifies pkt_tbl[] to only contain packets with
 * no errors.
 *
 * @param pkt_tbl  Array of packet
 * @param len      Number of packet to be validated
 *
 * @return Number of valid packets
 */
static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len);

/**
 * Parse the argument vector passed by the user.
 *
 * Update the argument structure maintained in application.
 *
 * @param argc		Number of command line argument.
 * @param argv		Vector of command line arguemnt.
 * @param appl_args	application's argument structure pointer.
 *
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);

/**
 * Print system and application info
 *
 * @param progname	application's Name
 * @param appl_args	application's argument structure pointer.
 *
 */
static void print_info(char *progname, appl_args_t *appl_args);

/**
 * Print application's usage information
 *
 * @param progname	application's Name
 */
static void usage(char *progname);

/*********************************************************************
			Function Definitions
**********************************************************************/
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
#if ODP_L3FWD_PERF_MODE
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
#if !ODP_L3FWD_PERF_MODE
	l4_ports = (((uint32_t)l4_sport << 16) | ((uint32_t)l4_dport));
#endif
	ODP_BJ3_MIX(ip_src, ip_dst, l4_ports);
#if !ODP_L3FWD_PERF_MODE
	l4_ports += ip_proto;
	ODP_BJ3_MIX(ip_src, ip_dst, l4_ports);
#endif
	return l4_ports;
}

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

static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *token, *local;
	size_t len;
	int i, mem_failure = 0;
	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},	/* return 'c'*/
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"mode", required_argument, NULL, 'm'},		/* return 'm' */
		{"route", required_argument, NULL, 'r'},	/* return 'r' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	appl_args->mode = APPL_MODE_PKT_BURST;	/*By Default burst mode is enabled*/
	appl_args->flows = ODP_MAX_FLOW_COUNT; /*Maximum number of flows can be configured*/
	appl_args->free_entries = ODP_MAX_FLOW_COUNT; /*Free location count in
							Hash table*/

	while (1) {
		opt = getopt_long(argc, argv, "+c:i:m:f:r:h",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		/* parse number of worker threads to be run*/
		case 'c':
			appl_args->cpu_count = atoi(optarg);
			break;
		/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->if_str = (char *)malloc(len);
			if (!appl_args->if_str) {
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
				free(appl_args->if_str);
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
			    (char **)calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL; token = strtok(NULL, ","), i++) {
				appl_args->if_names[i] = token;
			}
			break;
		/* parse application mode to be executed*/
		case 'm':
			i = atoi(optarg);
			if (i != 0)
				appl_args->mode = APPL_MODE_PKT_SCHED;
			break;
		/*Configure Route in forwarding database*/
		case 'r':
			if (route_index >= MAX_ROUTE) {
				printf("No more routes can be added\n");
				break;
			}
			local = (char *)calloc(1, strlen(optarg) + 1);
			if (!local) {
				mem_failure = 1;
				break;
			}
			memcpy(local, optarg, strlen(optarg));
			local[strlen(optarg)] = '\0';
			appl_args->route_str[route_index++] = local;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;

		default:
			break;
		}
	}

	if (appl_args->if_count == 0 || appl_args->mode == -1 ||
	    mem_failure == 1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	printf("Number of flows = %d and bucket = %d\n", appl_args->flows,
	       bucket_count);

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

static void print_info(char *progname, appl_args_t *appl_args)
{
	int i;

	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "CPU model:       %s\n"
	       "CPU freq (hz):   %" PRIu64 "\n"
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
	if (appl_args->mode == APPL_MODE_PKT_BURST)
		PRINT_APPL_MODE(APPL_MODE_PKT_BURST);
	else
		PRINT_APPL_MODE(APPL_MODE_PKT_SCHED);
	printf("\n\n");
	fflush(NULL);
}

static void usage(char *progname)
{
	printf("\n"
	       "OpenDataPlane L3 forwarding application.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth0,eth1,eth2,eth3 -m 0 -t 1\n"
	       " In the above example,\n"
	       " eth0 will send pkts to eth1 and vice versa\n"
	       " eth2 will send pkts to eth3 and vice versa\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       "  -r, --route SubNet:Intf:NextHopMAC\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -m, --mode      0: Burst send & receive packets (no queues)\n"
	       "                  1: Send & receive packets through ODP Schedular.\n"
	       "			Default: Packet burst mode.\n"
	       "  -c, --count <number> CPU count.\n"
	       "  -h, --help           Display help and exit.\n\n"
	       " environment variables: ODP_PKTIO_DISABLE_SOCKET_MMAP\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_MMSG\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_BASIC\n"
	       " can be used to advanced pkt I/O selection for linux-generic\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
}

/**
 * Packet processing function. packet will be looked up in the route table
 * and will forwarded to the interface accordingly
 *
 * @param pkt_tbl Packet array
 *
 * @param pkts_ok Total number of valid frames
 */
void odp_process_and_send_packet(odp_packet_t pkt_tbl[], uint32_t pkts_ok)
{
	uint8_t		proto;
	uint16_t	sport = 0, dport = 0;
	uint32_t	loop, sip, dip;
	uint64_t	hash;
	odp_packet_t	pkt = ODP_PACKET_INVALID;
	odph_ethhdr_t	*eth;
	odph_udphdr_t	*udp;
	odph_ipv4hdr_t	*ip;
	odp_flow_entry_t *flow = NULL;
	fwd_db_entry_t	*fwd_entry;
	odp_pktout_queue_t pktout;

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
			proto = ip->proto;
			ip->ttl--;
			ip->chksum = odph_ipv4_csum_update(pkt);

			if (odp_packet_has_udp(pkt) || odp_packet_has_tcp(pkt)) {
				/* UDP or TCP*/
				udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
				sport = odp_be_to_cpu_16(udp->src_port);
				dport = odp_be_to_cpu_16(udp->dst_port);
			}
			hash = odp_calculate_hash(sip, dip, sport, dport,
							proto);

			flow = odp_route_flow_lookup_in_bucket(sip, dip, sport,
								dport, proto,
					&flow_table[hash & (bucket_count - 1)]);
			if (flow) {
#if ODP_L3FWD_DEBUG
				EXAMPLE_DBG("Packet sent successfully.\n");
#endif
				goto send_packet;
			} else {
				/*Check into Routing table*/
				fwd_entry = find_fwd_db_entry(dip);
				if (fwd_entry) {
					/*First check for maximum number of flows limit*/
					if (!gbl_args->appl.free_entries) {
						EXAMPLE_DBG("Flow entries are reached at maximum\n");
						goto drop_packet;
					}

					/*Entry found. Updated in Flow table first.*/
					flow = (odp_flow_entry_t *)calloc(1, sizeof(odp_flow_entry_t));
					if (!flow) {
						EXAMPLE_ABORT("Failure to allocate memory");
					}
					flow->l3_src = sip;
					flow->l3_dst = dip;
					flow->l4_sport = sport;
					flow->l4_dport = dport;
					flow->l3_proto = proto;
					flow->out_port.pktio = fwd_entry->pktio;
					memcpy(flow->out_port.addr.addr, fwd_entry->src_mac, ODPH_ETHADDR_LEN);
					memcpy(flow->out_port.next_hop_addr.addr, fwd_entry->dst_mac, ODPH_ETHADDR_LEN);
					flow->next = NULL;
					/*Insert new flow into flow cache table*/
					/*TODO: Age out in not supported currently for route cache entries.
					All the configured flows will remain in table till the process
					terminates*/
					odp_route_flow_insert_in_bucket(flow, &flow_table[hash & (bucket_count - 1)]);
					gbl_args->appl.free_entries--;
					goto send_packet;
				} else {
#if ODP_L3FWD_DEBUG
					EXAMPLE_DBG("No flow match found. Packet is dropped.\n");
#endif
					goto drop_packet;
				}
			}
		} else {
#if ODP_L3FWD_DEBUG
			EXAMPLE_DBG("No IPv4 Header found. Packet is dropped.\n");
#endif
		goto drop_packet;
		}
send_packet:
		eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);
		eth->dst = flow->out_port.next_hop_addr;
		eth->src = flow->out_port.addr;

		if (odp_pktout_queue(flow->out_port.pktio, &pktout, 1) != 1) {
			EXAMPLE_ERR(" Error: no pktout queue\n");
			goto drop_packet;
		}

		/* Enqueue the packet for output */
		if (odp_pktout_send(pktout, &pkt, 1) != 1) {
			odp_packet_free(pkt);
		}
	}

	return;

drop_packet:
	odp_packet_free(pkt);
}

/**
 * Packet IO worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_queue_thread(void *arg EXAMPLE_UNUSED)
{
	int thr;
	odp_packet_t pkt[1];
	odp_event_t ev;
#if ODP_L3FWD_DEBUG
	unsigned long tmp = 0, pkt_cnt = 0;
#endif

	thr = odp_thread_id();

	printf("[%02i] QUEUE mode\n", thr);

	/* Loop packets */
	while (1) {
		/* Use schedule to get buf from any input queue */
		ev  = odp_schedule(NULL, ODP_SCHED_WAIT);
		pkt[0] = odp_packet_from_event(ev);

		/* Drop packets with errors */
		if (odp_unlikely(drop_err_pkts(pkt, 1) == 0))
			continue;

		odp_process_and_send_packet(pkt, 1);

#if ODP_L3FWD_DEBUG
		/* Print packet counts every once in a while */
		tmp += 1;
		if (odp_unlikely((tmp >= 100000) || /* OR first print:*/
		    ((pkt_cnt == 0) && ((tmp-1) < MAX_PKT_BURST)))) {
			pkt_cnt += tmp;
			printf("  [%02i] pkt_cnt:%lu\n", thr, pkt_cnt);
			fflush(NULL);
			tmp = 0;
		}
#endif
	}

	return NULL;
}

/**
 * Packet IO worker thread using bursts from/to IO resources
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_ifburst_thread(void *arg)
{
	int thr;
	thread_args_t *thr_args;
	int pkts, pkts_ok;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	int src_idx;
	odp_pktio_t pktio_src;
	odp_pktin_queue_t pktin;
#if ODP_L3FWD_DEBUG
	unsigned long tmp = 0, pkt_cnt = 0;
#endif

	thr = odp_thread_id();
	thr_args = (thread_args_t *)arg;

	src_idx = thr_args->src_idx;
	pktio_src = gbl_args->pktios[src_idx];

	printf(" [%02i] srcif:%s spktio:%lu BURST mode\n",
		thr, gbl_args->appl.if_names[src_idx],
		odp_pktio_to_u64(pktio_src));

	if (odp_pktin_queue(pktio_src, &pktin, 1) != 1) {
		EXAMPLE_ERR("Error: no pktin queue\n");
		return NULL;
	}

	/* Loop packets */
	while (1) {
		pkts = odp_pktin_recv(pktin, pkt_tbl, MAX_PKT_BURST);
		if (pkts <= 0)
			continue;

		/* Drop packets with errors */
		pkts_ok = drop_err_pkts(pkt_tbl, pkts);
		if (pkts_ok > 0)
			odp_process_and_send_packet(pkt_tbl, pkts_ok);

#if ODP_L3FWD_DEBUG
		/* Print packet counts every once in a while */
		tmp += pkts_ok;
		if (odp_unlikely((tmp >= 100000) || /* OR first print:*/
		    ((pkt_cnt == 0) && ((tmp-1) < MAX_PKT_BURST)))) {
			pkt_cnt += tmp;
			printf("  [%02i] pkt_cnt:%lu\n", thr, pkt_cnt);
			fflush(NULL);
			tmp = 0;
		}
#endif
		if (pkts_ok == 0)
			continue;
	}

	return NULL;
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
static odp_pktio_t create_pktio(const char *name, odp_pool_t pool,
				int mode)
{
	odp_pktio_t pktio;
	int ret;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;

	odp_pktio_param_init(&pktio_param);

	if (mode == APPL_MODE_PKT_BURST)
		pktio_param.in_mode = ODP_PKTIN_MODE_DIRECT;
	else
		pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;

	pktio = odp_pktio_open(name, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		EXAMPLE_ERR("Error: failed to open %s\n", name);
		return ODP_PKTIO_INVALID;
	}

	printf("created pktio %" PRIu64 " (%s)\n",
	       odp_pktio_to_u64(pktio), name);

	odp_pktin_queue_param_init(&pktin_param);

	if (mode == APPL_MODE_PKT_SCHED) {
		pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
		pktin_param.queue_param.sched.group = ODP_SCHED_GROUP_ALL;
		pktin_param.queue_param.sched.prio = ODP_SCHED_PRIO_DEFAULT;
	}

	if (odp_pktin_queue_config(pktio, &pktin_param))
		EXAMPLE_ABORT("Error: pktin config failed for %s\n", name);

	if (odp_pktout_queue_config(pktio, NULL) < 0)
		EXAMPLE_ABORT("Error: pktout config failed for %s\n", name);

	ret = odp_pktio_start(pktio);
	if (ret != 0)
		EXAMPLE_ABORT("Error: unable to start %s\n", name);

	printf("  created pktio:%02" PRIu64
	       ", name:%s, queue mode (ATOMIC queues)\n"
	       "  \tdefault pktio%02" PRIu64 "\n",
	       odp_pktio_to_u64(pktio), name,
	       odp_pktio_to_u64(pktio));

	return pktio;
}

/**
 * ODP L3 forwarding main function
 */
int main(int argc, char *argv[])
{
	odp_pool_t		pool;
	odp_pool_param_t	params;
	odp_cpumask_t		cpumask;
	odph_linux_pthread_t	thread_tbl[MAX_WORKERS];
	int32_t			i, cpu, num_workers;
	char			cpumaskstr[ODP_CPUMASK_STR_SIZE];
	uint8_t			mac[ODPH_ETHADDR_LEN];
	odp_instance_t instance;
	odph_linux_thr_params_t thr_params;

	gbl_args = (args_t *)calloc(1, sizeof(args_t));
	if (gbl_args == NULL) {
		EXAMPLE_ABORT("Error: args mem alloc failed.\n");
	}

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

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
		create_fwd_db_entry(gbl_args->appl.route_str[i]);

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &gbl_args->appl);

	/* Default to system CPU count unless user specified */
	num_workers = MAX_WORKERS;
	if (gbl_args->appl.cpu_count)
		num_workers = gbl_args->appl.cpu_count;

	/*
	 * By default CPU #0 runs Linux kernel background tasks.
	 * Start mapping thread from CPU #1
	 */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	if ((gbl_args->appl.mode == APPL_MODE_PKT_BURST) && (num_workers < gbl_args->appl.if_count)) {
		EXAMPLE_ABORT("Error: CPU count %d less than interface count\n",
			      num_workers);
	}

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE / SHM_PKT_POOL_BUF_SIZE;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet pool", &params);

	if (pool == ODP_POOL_INVALID) {
		EXAMPLE_ABORT("Error: packet pool create failed.\n");
	}

	/*Dump the created packet pool*/
	odp_pool_print(pool);

	for (i = 0; i < gbl_args->appl.if_count; ++i) {
		gbl_args->pktios[i] = create_pktio(gbl_args->appl.if_names[i],
						   pool, gbl_args->appl.mode);
		if (gbl_args->pktios[i] == ODP_PKTIO_INVALID)
			exit(EXIT_FAILURE);
		odp_pktio_mac_addr(gbl_args->pktios[i], mac, ODPH_ETHADDR_LEN);
		resolve_fwd_db(gbl_args->appl.if_names[i], gbl_args->pktios[i], mac);
	}
	gbl_args->pktios[i] = ODP_PKTIO_INVALID;

	memset(thread_tbl, 0, sizeof(thread_tbl));
	/* Create worker threads */
	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_workers; ++i) {
		odp_cpumask_t thd_mask;
		void *(*thr_run_func) (void *);

		if (gbl_args->appl.mode == APPL_MODE_PKT_BURST)
			thr_run_func = pktio_ifburst_thread;
		else /* APPL_MODE_PKT_SCHED */
			thr_run_func = pktio_queue_thread;

		gbl_args->thread[i].src_idx = i % gbl_args->appl.if_count;

		memset(&thr_params, 0, sizeof(thr_params));
		thr_params.start    = thr_run_func;
		thr_params.arg      = &gbl_args->thread[i];
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;

		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);
		odph_linux_pthread_create(&thread_tbl[i], &thd_mask,
					  &thr_params);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	/* Master thread waits for other threads to exit */
	odph_linux_pthread_join(thread_tbl, num_workers);

	for (i = 0; i < route_index; i++)
		free(gbl_args->appl.route_str[i]);
	free(gbl_args->appl.if_names);
	free(gbl_args->appl.if_str);
	free(gbl_args);

	printf("Maximum bucket depth in this run: %u\n",
		get_max_bucket_depth());
	printf("Exit\n\n");

	return 0;
}
