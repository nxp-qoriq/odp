/* Copyright (c) 2016 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_lpmfwd.c  ODP LPM forwarding application
 * based on destination IP address
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
#include <error.h>
#include <mqueue.h>

#include <example_debug.h>

#include <odp_api.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>
#include <odp/helper/tcp.h>

#include "arp/arp.h"
#include "ip/fib.h"
#include "ip/ip_protos.h"
#include "ip/ip_appconf.h"
#include "ip/ip_handler.h"
#include "ip/ip_output.h"
#include "net/neigh.h"
#include <sys/stat.h>

/** \brief	Holds all IP-related data structures */
struct ip_stack_t {
	struct ip_statistics_t *ip_stats;	/**< IPv4 Statistics */
	struct ip_protos_t protos;		/**< Protocol Handler */
	struct neigh_table_t arp_table;		/**< ARP Table */
};

struct odp_dev_map {
	struct {
		struct odp_dev_map *tqe_next;	/* next element */
		struct odp_dev_map **tqe_prev;	/* address of previous next element */
	} next;
	odp_pktio_t pktio;
	in_addr_t ip_addr;
	struct node_t local_nodes[23];
	uint32_t index;
};

struct odp_dev_map_list {
	struct odp_dev_map *tqh_first;	/* first element */
	struct odp_dev_map **tqh_last;	/* addr of last next element */
};
struct odp_dev_map_list dev_map_list;
struct odp_dev_map	odp_dev_map[6];

struct ip_stack_t stack;
static mqd_t mq_fd_rcv = -1, mq_fd_snd = -1;
static struct sigevent notification;

/*********************************************************************
			Macro Definitions
**********************************************************************/
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define ETHERNET_ADDR_MAGIC	0x0200
#define MAX_MQ_NAME_LEN		20

/**
 * Enabling/Disable Debug prints
 */
#define ODP_LPMFWD_DEBUG		0

/** @def MAX_WORKERS
 * @brief Maximum number of worker threads
 */
#define MAX_WORKERS            32

/** @def MAX_DEQ_PACKETS
 * @brief Maximum number of packets that can be dequeue'd at once
 */
#define MAX_DEQ_PACKETS            4

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      (1856 * 2048)

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE  1856

/** @def MAX_PKT_BURST
 * @brief Maximum number of packet bursts
 */
#define MAX_PKT_BURST          MAX_DEQ_PACKETS

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

/** ODP application data memory size.
 * 256 MB will be allocated to application at init time
 * for application-specific use.
 * */
#define APPL_DATA_MEM_SIZE  ((uint64_t)64 * 1024 * 1024) /*64 MB*/

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
	char		*if_str;	/**< Storage for interface names */
} appl_args_t;

/**
 * Thread specific arguments
 */
typedef struct {
	int32_t		src_idx;	/**< Source interface identifier */
} thread_args_t;

/**
 * Held Buffer information in each thread
 */
typedef struct {
	struct neigh_t neigh;
	odp_packet_t buf_list[MAX_DEQ_PACKETS];
	int32_t	buf_count;
} thread_buf_info_t;

/*Pointer to hold held buffers for*/
__thread thread_buf_info_t *buf_info;

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

static int receive_data(mqd_t mqdes);

void destroy_mq(void);

static int ipfwd_show_intf(const struct app_ctrl_op_info *route_info ODP_UNUSED);

static odp_pktio_t ipfwd_get_iface_for_ip(in_addr_t ipaddr);

static void odp_process_and_send_packet(odp_packet_t pkt_tbl[], uint32_t pkts_ok);

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
	char *token;
	size_t len;
	int i, mem_failure = 0;
	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},	/* return 'c'*/
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"mode", required_argument, NULL, 'm'},		/* return 'm' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	appl_args->mode = APPL_MODE_PKT_BURST;	/*By Default burst mode is enabled*/
	while (1) {
		opt = getopt_long(argc, argv, "+c:i:m:f:h",
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

			appl_args->if_str = malloc(len);
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
			    calloc(appl_args->if_count, sizeof(char *));

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
	       "OpenDataPlane LPM forwarding application.\n"
	       "\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i eth1,eth2 -m 0 -c 1\n"
	       " In the above example,\n"
	       " eth1 and eth2 are the interfaces from which pkts will be forwarded\n"
	       " depends upon the routes\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface eth interfaces (comma-separated, no spaces)\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -m, --mode      0: Burst send & receive packets (no queues)\n"
	       "                  1: Send & receive packets through ODP Schedular.\n"
	       "			Default: Packet burst mode.\n"
	       "  -c, --count <number> CPU count.\n"
	       "  -h, --help           Display help and exit.\n\n"
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
static void odp_process_and_send_packet(odp_packet_t pkt_tbl[],
					uint32_t pkts_ok)
{
	odp_packet_t	pkt = ODP_PACKET_INVALID;
	uint32_t		tx_pkts = 0;
	uint32_t		loop, ret;
	uint32_t gwaddr;
	struct neigh_t neighbor;
	odph_ipv4hdr_t *ip_hdr;
	odp_pktio_t old_pktio = ODP_PKTIO_INVALID;

	buf_info->buf_count = 0;
	buf_info->neigh.pktio = ODP_PKTIO_INVALID;
tx_rest_packets:
	for (loop = tx_pkts; loop < pkts_ok; loop++) {
		pkt = pkt_tbl[loop];
		ip_hdr = (odph_ipv4hdr_t *)(odp_packet_l3_ptr(pkt, NULL));
		ret = ip_route_lookup(htonl(ip_hdr->dst_addr), &gwaddr,
				      &neighbor);
		if (odp_unlikely(ret != 0)) {
			EXAMPLE_ERR("error in lookup for IP%x\n",
				    htonl(ip_hdr->dst_addr));
			odp_packet_free(pkt);
			goto process_and_tx;
		}
		if ((old_pktio != ODP_PKTIO_INVALID) &&
		    (old_pktio != neighbor.pktio)) {
			old_pktio = ODP_PKTIO_INVALID;
			goto process_and_tx;
		}
		if (odp_likely(ip_hdr->ttl > 1)) {
			ip_hdr->ttl -= 1;
			if (ip_hdr->chksum >= odp_cpu_to_be_16(0xffff - 0x100))
				ip_hdr->chksum += odp_cpu_to_be_16(0x100) + 1;
			else
				ip_hdr->chksum += odp_cpu_to_be_16(0x100);
		}

		buf_info->buf_list[buf_info->buf_count++] = pkt;
		if (old_pktio == ODP_PKTIO_INVALID) {
			memcpy(&buf_info->neigh, &neighbor,
			       sizeof(struct neigh_t));
			old_pktio = buf_info->neigh.pktio;
		}
	}
process_and_tx:
	ret = ip_send_multi(buf_info->buf_list, &buf_info->neigh,
			    buf_info->buf_count);
	tx_pkts += ret;
	buf_info->buf_count = 0;
	if (pkts_ok - tx_pkts)
		goto tx_rest_packets;

}

/**
 * Packet IO worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_queue_thread(void *arg EXAMPLE_UNUSED)
{
	int thr, ret, i;
	odp_packet_t pkt[MAX_DEQ_PACKETS];
	odp_event_t ev[MAX_DEQ_PACKETS];
#if ODP_LPMFWD_DEBUG
	unsigned long tmp = 0, pkt_cnt = 0;
#endif

	thr = odp_thread_id();

	printf("[%02i] QUEUE mode\n", thr);

	/*Allocate memory to hold list of buffers for batch transmission*/
	buf_info = calloc(1, sizeof(thread_buf_info_t));
	if (!buf_info) {
		printf("Error in memory allocaiton");
		return NULL;
	}
	for (i = 0; i < MAX_DEQ_PACKETS; i++)
		buf_info->buf_list[i] = ODP_PACKET_INVALID;
	/* Loop packets */
	while (1) {
		/* Use schedule to get buf from any input queue */
		ret = odp_schedule_multi(NULL, ODP_SCHED_WAIT, ev,
					 MAX_DEQ_PACKETS);
		if (odp_likely(ret > 0)) {
			for (i = 0; i < ret; i++) {
				if (ev[i] != ODP_EVENT_INVALID)
					pkt[i] = odp_packet_from_event(ev[i]);
			}
			/* Drop packets with errors */
			ret = drop_err_pkts(pkt, ret);
			if (odp_unlikely(ret == 0))
				continue;
		} else {
			continue;
		}
		odp_process_and_send_packet(pkt, ret);

#if ODP_LPMFWD_DEBUG
		/* Print packet counts every once in a while */
		tmp += 1;
		if (odp_unlikely((tmp >= 100000) || /* OR first print:*/
		    ((pkt_cnt == 0) && ((tmp - 1) < MAX_PKT_BURST)))) {
			pkt_cnt += tmp;
			printf("  [%02i] pkt_cnt:%lu\n", thr, pkt_cnt);
			fflush(NULL);
			tmp = 0;
		}
#endif
	}

	free(buf_info);
	return NULL;
}

/**
 * Packet IO worker thread using bursts from/to IO resources
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_ifburst_thread(void *arg)
{
	int thr, i;
	thread_args_t *thr_args;
	int pkts, pkts_ok;
	odp_packet_t pkt_tbl[MAX_PKT_BURST];
	int src_idx;
	odp_pktio_t pktio_src;
	odp_pktin_queue_t pktin;
#if ODP_LPMFWD_DEBUG
	unsigned long tmp = 0, pkt_cnt = 0;
#endif

	thr = odp_thread_id();
	thr_args = arg;

	src_idx = thr_args->src_idx;
	pktio_src = gbl_args->pktios[src_idx];

	printf(" [%02i] srcif:%s spktio:%lu BURST mode\n",
		thr, gbl_args->appl.if_names[src_idx],
		odp_pktio_to_u64(pktio_src));

	if (odp_pktin_queue(pktio_src, &pktin, 1) != 1) {
		EXAMPLE_ERR("Error: no pktin queue\n");
		return NULL;
	}
	/*Allocate memory to hold list of buffers for batch transmission*/
	buf_info = calloc(1, sizeof(thread_buf_info_t));
	if (!buf_info) {
		printf("Error in memory allocaiton");
		return NULL;
	}
	for (i = 0; i < MAX_DEQ_PACKETS; i++)
		buf_info->buf_list[i] = ODP_PACKET_INVALID;

	/* Loop packets */
	while (1) {
		pkts = odp_pktin_recv(pktin, pkt_tbl, MAX_PKT_BURST);
		if (pkts <= 0)
			continue;

		/* Drop packets with errors */
		pkts_ok = drop_err_pkts(pkt_tbl, pkts);
		if (pkts_ok > 0)
			odp_process_and_send_packet(pkt_tbl, pkts_ok);

#if ODP_LPMFWD_DEBUG
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

	free(buf_info);
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
static odp_pktio_t create_pktio(const char *dev, odp_pool_t pool,
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

	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID) {
		EXAMPLE_ERR("Error: failed to open %s\n", dev);
		return ODP_PKTIO_INVALID;
	}

	printf("created pktio %" PRIu64 " (%s)\n",
	       odp_pktio_to_u64(pktio), dev);

	odp_pktin_queue_param_init(&pktin_param);

	if (mode == APPL_MODE_PKT_SCHED) {
		odp_pktio_capability_t capa;

		ret = odp_pktio_capability(pktio, &capa);
		if (ret != 0)
			EXAMPLE_ABORT("Error: Unable to get pktio capability %s\n", dev);

		pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
		pktin_param.queue_param.type = ODP_QUEUE_TYPE_SCHED;
		pktin_param.num_queues = capa.max_input_queues;
		if (pktin_param.num_queues > 1)
			pktin_param.hash_enable = 1;
	}

	if (odp_pktin_queue_config(pktio, &pktin_param))
		EXAMPLE_ABORT("Error: pktin config failed for %s\n", dev);

	if (odp_pktout_queue_config(pktio, NULL) < 0)
		EXAMPLE_ABORT("Error: pktout config failed for %s\n", dev);

	ret = odp_pktio_start(pktio);
	if (ret)
		EXAMPLE_ABORT("Error: unable to start %s\n", dev);

	return pktio;
}

static odp_pktio_t ipfwd_get_iface_for_ip(in_addr_t ipaddr)
{
	struct odp_dev_map *dev_map;

	for (dev_map = dev_map_list.tqh_first; dev_map; dev_map = dev_map->next.tqe_next) {
		if ((dev_map->ip_addr >> 8) == (ipaddr >> 8))
			return dev_map->pktio;
	}
	EXAMPLE_ERR("PKTIO not found for ip: 0x%x", ipaddr);
	return NULL;
}

/**
 \brief Initialize IPSec Statistics
 \param[in] void
 \param[out] struct ip_statistics_t *
 */
static struct ip_statistics_t *ipfwd_stats_init(void)
{
	int _errno;
	void *ip_stats = NULL;

	_errno = posix_memalign(&ip_stats,
				__alignof__(struct ip_statistics_t),
				sizeof(struct ip_statistics_t));
	return odp_unlikely(_errno < 0) ? NULL : ip_stats;
}

/**
 \brief Initialize IP Stack
 \param[in] struct ip_stack_t * IPFwd Stack pointer
 \param[out] Return Status
 */
static int initialize_ip_stack(struct ip_stack_t *ip_stack)
{
	int _errno;

	_errno = arp_table_init(&ip_stack->arp_table);

	_errno = neigh_table_init(&ip_stack->arp_table);
	if (odp_unlikely(_errno < 0)) {
		EXAMPLE_ERR("Failed to init ARP Table\n");
		return _errno;
	}
	_errno = fib_init();
	if (odp_unlikely(_errno < 0)) {
		EXAMPLE_ERR("Failed in fib initialized\n");
		return _errno;
	}
	ip_stack->ip_stats = ipfwd_stats_init();
	if (odp_unlikely(ip_stack->ip_stats == NULL)) {
		EXAMPLE_ERR("Unable to allocate ip stats structure for stack\n");
		return -ENOMEM;
	}
	memset(ip_stack->ip_stats, 0, sizeof(*ip_stack->ip_stats));

	return 0;
}

/**
 \brief Adds a new Route Cache entry
 \param[out] app_ctrl_route_info contains Route parameters
 \return Integer status
 */
static int ipfwd_add_route(const struct app_ctrl_op_info *route_info)
{
	in_addr_t gw_ipaddr = route_info->ip_info.gw_ipaddr;
	uint32_t fib_cnt, mask, daddr;
	uint32_t i;
	nh_action_t act;
	uint16_t port;
	struct neigh_t *neighbor;

	fib_cnt = route_info->ip_info.fib_cnt;
	mask = route_info->ip_info.mask;
	daddr = route_info->ip_info.dst_ipaddr;
	for (i = 0; i < fib_cnt; i++) {
		neighbor = neigh_lookup(&stack.arp_table,
				gw_ipaddr, stack.arp_table.proto_len);
		if (neighbor == NULL) {
			EXAMPLE_DBG("neighbour NULL\n");
			return -1;
		}
		act = NH_FWD;
		port = 1;
		fib_add_route(daddr + i, mask, gw_ipaddr, port, act, neighbor);
	}
	return 0;
}

/**
 \brief Deletes an entry in FIB table
 \param[out] app_ctrl_route_info contains Route parameters
 \return Integer status
 */
static int ipfwd_del_route(const struct app_ctrl_op_info *route_info ODP_UNUSED)
{
	return 0;
}

/**
 \brief Adds a new Arp Cache entry
 \param[out] app_ctrl_route_info contains ARP parameters
 \return Integer status
 */
static int ipfwd_add_arp(const struct app_ctrl_op_info *route_info)
{
	in_addr_t ip_addr = route_info->ip_info.src_ipaddr;
	odp_pktio_t pktio;
	struct neigh_t *n;

	n = neigh_lookup(&stack.arp_table, ip_addr, stack.arp_table.proto_len);

	if (n == NULL) {

		pktio = ipfwd_get_iface_for_ip(ip_addr);
		if (pktio == NULL) {
			EXAMPLE_DBG("ipfwd_add_arp: Exit: Failed\n");
			return -1;
		}

		n = neigh_create(&stack.arp_table);
		if (odp_unlikely(!n)) {
			EXAMPLE_DBG("ipfwd_add_arp: Exit: Failed\n");
			return -1;
		}
		if (NULL == neigh_init(&stack.arp_table, n, pktio, &ip_addr)) {
			EXAMPLE_DBG("ipfwd_add_arp: Exit: Failed\n");
			pthread_mutex_destroy(&n->wlock);
			return -1;
		}

		if (false == neigh_add(&stack.arp_table, n)) {
			EXAMPLE_DBG("ipfwd_add_arp: Exit: Failed\n");
			pthread_mutex_destroy(&n->wlock);
			return -1;
		}
	} else {
		n->neigh_state = NEIGH_STATE_UNKNOWN;
		if (route_info->ip_info.replace_entry) {
			if (false == neigh_replace(&stack.arp_table, n)) {
				EXAMPLE_DBG("ipfwd_add_arp: Exit: Failed\n");
				return -1;
			}
		}
	}
	/* Update ARP cache entry */
	if (NULL == neigh_update(n,
			route_info->ip_info.mac_addr.addr,
			NEIGH_STATE_PERMANENT)) {
		EXAMPLE_DBG("ipfwd_add_arp: Exit: Failed\n");
		pthread_mutex_destroy(&n->wlock);
		return -1;
	}

	return 0;
}

/**
 \brief Deletes an Arp Cache entry
 \param[out] app_ctrl_route_info contains ARP parameters
 \return Integer status
 */
static int ipfwd_del_arp(const struct app_ctrl_op_info *route_info)
{
	struct neigh_t *neighbor = NULL;

	/*
	 ** Do a Neighbour LookUp for the entry to be deleted
	 */
	neighbor = neigh_lookup(&stack.arp_table,
				route_info->ip_info.src_ipaddr,
				stack.arp_table.proto_len);
	if (neighbor == NULL) {
		EXAMPLE_DBG
		    ("Could not find neighbor entry for link-local address\n");
		return -1;
	}

	/*
	 ** Find out if anyone is using this entry
	 */
	if (*(neighbor->refcnt) != 0) {
		EXAMPLE_ERR
		    ("Could not delete neighbor entry as it is being used\n");
		return -1;
	}

	/*
	 ** Delete the ARP Entry
	 */
	if (false == neigh_remove(&stack.arp_table,
				  route_info->ip_info.src_ipaddr,
				  stack.arp_table.proto_len)) {
		EXAMPLE_ERR("Could not delete neighbor entry\n");
		return -1;
	}

	return 0;
}

/**
 \brief Show Interfaces
 \param[out] app_ctrl_route_info contains intf parameters
 \return Integer status
 */
static int ipfwd_show_intf(const struct app_ctrl_op_info *route_info ODP_UNUSED)
{
	struct odp_dev_map *i;
	uint8_t *ip;

	for (i = dev_map_list.tqh_first; i; i = i->next.tqe_next) {
		ip = (typeof(ip))&i->ip_addr;
		if (i->index != 0) {
			printf("\nNetwork Interface number: %d\n"
				"IP Address: %d.%d.%d.%d\n",
				i->index, ip[3], ip[2], ip[1], ip[0]);
		}
	}

	return 0;
}

/**
 \brief Change Interface Configuration
 \param[out] app_ctrl_route_info contains intf config parameters
 \return Integer status
 */
static int ipfwd_conf_intf(const struct app_ctrl_op_info *route_info)
{
	struct odp_dev_map *i;
	uint16_t addr_hi;
	uint8_t *ip;
	uint32_t ifnum, node;
	int _errno = 1;

	addr_hi = ETHERNET_ADDR_MAGIC;
	ifnum = route_info->ip_info.intf_conf.ifnum;
	for (i = dev_map_list.tqh_first; i; i = i->next.tqe_next) {
		if (i->index == ifnum) {
			i->ip_addr = route_info->ip_info.intf_conf.ip_addr;
			ip = (typeof(ip))&i->ip_addr;
			printf("IPADDR assigned = %d.%d.%d.%d"
					" to interface num %d\n",
					ip[3], ip[2], ip[1], ip[0], i->index);
			for (node = 0; node < ARRAY_SIZE(i->local_nodes);
					node++) {
				i->local_nodes[node].ip = i->ip_addr + 1 + node;
				memcpy(&i->local_nodes[node].mac, &addr_hi,
					sizeof(addr_hi));
				memcpy(i->local_nodes[node].mac.addr
					+ sizeof(addr_hi),
					&i->local_nodes[node].ip,
					sizeof(i->local_nodes[node].ip));
			}
			_errno = 0;
		}
	}
	if (_errno)
		EXAMPLE_ERR("Interface %d is not an enabled interface\n",
			 ifnum);

	return _errno;
}

/**
 \brief Message handler for message coming from Control plane
 \param[in] app_ctrl_op_info contains SA parameters
 \return NULL
*/
static void process_req_from_mq(struct app_ctrl_op_info *sa_info)
{
	int32_t s32Result = 0;

	sa_info->result = IPC_CTRL_RSLT_FAILURE;
	switch (sa_info->msg_type) {
	case IPC_CTRL_CMD_TYPE_ROUTE_ADD:
		s32Result = ipfwd_add_route(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_ROUTE_DEL:
		s32Result = ipfwd_del_route(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_ARP_ADD:
		s32Result = ipfwd_add_arp(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_ARP_DEL:
		s32Result = ipfwd_del_arp(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_INTF_CONF_CHNG:
		s32Result = ipfwd_conf_intf(sa_info);
		break;

	case IPC_CTRL_CMD_TYPE_SHOW_INTF:
		s32Result = ipfwd_show_intf(sa_info);
		break;

	default:
		break;
	}

	if (s32Result == 0)
		sa_info->result = IPC_CTRL_RSLT_SUCCESSFULL;
	else
		EXAMPLE_DBG("%s: CP Request can't be handled\n", __func__);

	return;
}

static int receive_data(mqd_t mqdes)
{
	ssize_t size;
	struct app_ctrl_op_info *ip_info = NULL;
	struct mq_attr attr;
	int _err = 0;

	ip_info = (struct app_ctrl_op_info *)malloc
			(sizeof(struct app_ctrl_op_info));
	if (odp_unlikely(!ip_info)) {
		EXAMPLE_ERR("%s: %dError getting mem for ip_info\n",
			 __FILE__, __LINE__);
		return -ENOMEM;
	}
	memset(ip_info, 0, sizeof(struct app_ctrl_op_info));

	_err = mq_getattr(mqdes, &attr);
	if (odp_unlikely(_err)) {
		EXAMPLE_ERR("%s: %dError getting MQ attributes\n",
			 __FILE__, __LINE__);
		goto error;
	}
	size = mq_receive(mqdes, (char *)ip_info, attr.mq_msgsize, 0);
	if (odp_unlikely(size == -1)) {
		EXAMPLE_ERR("%s: %dRcv msgque error\n", __FILE__, __LINE__);
		goto error;
	}
	process_req_from_mq(ip_info);
	/* Sending result to application configurator tool */
	_err = mq_send(mq_fd_snd, (const char *)ip_info,
			sizeof(struct app_ctrl_op_info), 10);
	if (odp_unlikely(_err != 0)) {
		EXAMPLE_DBG("%s: %d Error in sending msg on MQ\n",
			__FILE__, __LINE__);
		goto error;
	}

	return 0;
error:
	free(ip_info);
	return _err;
}
static void mq_handler(union sigval sval EXAMPLE_UNUSED)
{
	receive_data(mq_fd_rcv);
	mq_notify(mq_fd_rcv, &notification);
}

void destroy_mq(void)
{
	char name[MAX_MQ_NAME_LEN];

	if (mq_fd_snd >= 0) {
		if (mq_close(mq_fd_snd) == -1)
			error(0, errno, "%s():mq_close send", __func__);
		mq_fd_snd = -1;
		snprintf(name, MAX_MQ_NAME_LEN, "/mq_snd_%d", getpid());
		if (mq_unlink(name) == -1)
			error(0, errno, "%s():mq_unlink send", __func__);
	}
	if (mq_fd_rcv >= 0) {
		if (mq_close(mq_fd_rcv) == -1)
			error(0, errno, "%s():mq_close rcv", __func__);
		mq_fd_rcv = -1;
		snprintf(name, MAX_MQ_NAME_LEN, "/mq_rcv_%d", getpid());
		if (mq_unlink(name) == -1)
			error(0, errno, "%s():mq_unlink rcv", __func__);
	}
}

static int create_mq(void)
{
	struct mq_attr attr_snd, attr_rcv;
	int _err = 0, ret;
	char name[MAX_MQ_NAME_LEN];

	if ((mq_fd_snd != -1) || (mq_fd_rcv != -1))
		return 0;
	memset(&attr_snd, 0, sizeof(attr_snd));

	/* Create message queue to send the response */
	attr_snd.mq_maxmsg = MAX_MQ_NAME_LEN;
	attr_snd.mq_msgsize = 8192;
	snprintf(name, MAX_MQ_NAME_LEN, "/mq_snd_%d", getpid());
	printf("Message queue to send: %s\n", name);
	mq_fd_snd = mq_open(name, O_CREAT | O_WRONLY,
				(S_IRWXU | S_IRWXG | S_IRWXO), &attr_snd);
	if (mq_fd_snd == -1) {
		EXAMPLE_ERR("%s: %dError opening SND MQ\n",
				__FILE__, __LINE__);
		_err = -errno;
		goto error;
	}

	memset(&attr_rcv, 0, sizeof(attr_rcv));

	snprintf(name, MAX_MQ_NAME_LEN, "/mq_rcv_%d", getpid());
	printf("Message queue to receive: %s\n", name);
	/* Create message queue to read the message */
	attr_rcv.mq_maxmsg = MAX_MQ_NAME_LEN;
	attr_rcv.mq_msgsize = 8192;
	mq_fd_rcv = mq_open(name, O_CREAT | O_RDONLY,
				 (S_IRWXU | S_IRWXG | S_IRWXO), &attr_rcv);
	if (mq_fd_rcv == -1) {
		EXAMPLE_ERR("%s: %dError opening RCV MQ\n",
				 __FILE__, __LINE__);
		_err = -errno;
		goto error;
	}

	notification.sigev_notify = SIGEV_THREAD;
	notification.sigev_notify_function = mq_handler;
	notification.sigev_value.sival_ptr = &mq_fd_rcv;
	notification.sigev_notify_attributes = NULL;
	ret =  mq_notify(mq_fd_rcv, &notification);
	if (ret) {
		EXAMPLE_DBG("%s: %dError in mq_notify call\n",
				 __FILE__, __LINE__);
		_err = -errno;
		goto error;
	}
	return 0;
error:
	if (mq_fd_snd)
		mq_close(mq_fd_snd);

	if (mq_fd_rcv)
		mq_close(mq_fd_rcv);

	return _err;
}

/**
 * ODP L3 forwarding main function
 */
int main(int argc, char *argv[])
{
	odp_pool_t		pool;
	odp_pool_param_t	params;
	odp_platform_init_t plat_init;
	odp_cpumask_t		cpumask;
	odph_linux_pthread_t	thread_tbl[MAX_WORKERS];
	int32_t			i, cpu, num_workers, err = 0;
	char			cpumaskstr[ODP_CPUMASK_STR_SIZE];
	uint8_t			mac[ODPH_ETHADDR_LEN];
	odp_instance_t instance;
	odph_linux_thr_params_t thr_params;

	gbl_args = calloc(1, sizeof(args_t));
	if (gbl_args == NULL) {
		EXAMPLE_ABORT("Error: args mem alloc failed.\n");
	}

	/* Parse and store the application arguments */
	parse_args(argc, argv, &gbl_args->appl);

	plat_init.dq_schedule_mode = ODPFSL_PUSH;
	plat_init.data_mem_size = APPL_DATA_MEM_SIZE;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, &plat_init)) {
		EXAMPLE_ABORT("Error: ODP global init failed.\n");
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		EXAMPLE_ABORT("Error: ODP local init failed.\n");
	}


	err = initialize_ip_stack(&stack);
	if (odp_unlikely(err)) {
		EXAMPLE_ABORT("Error Initializing IP Stack\n");
	}

	/* Create Message queues to send and receive */
	err = create_mq();
	if (odp_unlikely(err)) {
		EXAMPLE_ABORT("Error in creating message queues\n");
	}

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

	if (num_workers < gbl_args->appl.if_count && gbl_args->appl.mode == APPL_MODE_PKT_BURST) {
		destroy_mq();
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
		destroy_mq();
		EXAMPLE_ABORT("Error: packet pool create failed.\n");
	}

	/*Dump the created packet pool*/
	odp_pool_print(pool);

	dev_map_list.tqh_first = NULL;
	dev_map_list.tqh_last = &dev_map_list.tqh_first;

	for (i = 0; i < gbl_args->appl.if_count; ++i) {
		gbl_args->pktios[i] = create_pktio(gbl_args->appl.if_names[i],
						   pool, gbl_args->appl.mode);
		if (gbl_args->pktios[i] == ODP_PKTIO_INVALID) {
			destroy_mq();
			exit(EXIT_FAILURE);
		}
		odp_pktio_mac_addr(gbl_args->pktios[i], mac, ODPH_ETHADDR_LEN);
		odp_dev_map[i].pktio = gbl_args->pktios[i];
		odp_dev_map[i].ip_addr = 0;
		odp_dev_map[i].index = i + 1;
		printf("Interface Index: %u mapped to %s\n",
				odp_dev_map[i].index,
				gbl_args->appl.if_names[i]);

		odp_dev_map[i].next.tqe_next = dev_map_list.tqh_first;
		if (odp_dev_map[i].next.tqe_next != NULL)
			dev_map_list.tqh_first->next.tqe_prev = &(odp_dev_map[i].next.tqe_next);
		else
			dev_map_list.tqh_last = &(odp_dev_map[i].next.tqe_next);
		dev_map_list.tqh_first = &odp_dev_map[i];
		odp_dev_map[i].next.tqe_prev = &(dev_map_list.tqh_first);
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

		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);

		memset(&thr_params, 0, sizeof(thr_params));
		thr_params.start    = thr_run_func;
		thr_params.arg      = &gbl_args->thread[i].src_idx;
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;

		odph_linux_pthread_create(&thread_tbl[i], &thd_mask,
					  &thr_params);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	/* Master thread waits for other threads to exit */
	odph_linux_pthread_join(thread_tbl, num_workers);

	destroy_mq();
	free(gbl_args->appl.if_names);
	free(gbl_args->appl.if_str);
	free(gbl_args);
	printf("Exit\n\n");

	return 0;
}
