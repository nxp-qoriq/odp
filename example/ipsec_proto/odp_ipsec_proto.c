/* Copyright (c) 2013, Linaro Limited
 * Copyright (C) 2015 Freescale Semiconductor,Inc
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_ipsec_proto.c  ODP basic packet IO cross connect with IPsec
 * test application
 */

#define _DEFAULT_SOURCE
/* enable strtok */
#define _POSIX_C_SOURCE 200112L
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>

#include <example_debug.h>

#include <odp_api.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/icmp.h>
#include <odp/helper/udp.h>
#include <odp/helper/ipsec.h>

#include <stdbool.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <odp_ipsec_proto_misc.h>
#include <odp_ipsec_proto_sa_db.h>
#include <odp_ipsec_proto_sp_db.h>
#include <odp_ipsec_proto_fwd_db.h>
#include <odp_ipsec_proto_cache.h>

#define MAX_WORKERS     32   /**< maximum number of worker threads */
#define DEFAULT_BUDGET	16
#define DEBUG 0

/**
 * Parsed command line application arguments
 */
typedef struct {
	int cpu_count;
	int flows;
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	crypto_api_mode_e mode;	/**< Crypto API preferred mode */
	odp_pool_t pool;	/**< Buffer pool for packet IO */
	char *if_str;		/**< Storage for interface names */
} appl_args_t;

/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
} args_t;

/* helper funcs */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

/** Global pointer to args */
static args_t *args;

/**
 * Buffer pool for packet IO
 */
#define SHM_PKT_POOL_BUF_COUNT 1024
#define SHM_PKT_POOL_BUF_SIZE  4096
#define SHM_PKT_POOL_SIZE      (SHM_PKT_POOL_BUF_COUNT * SHM_PKT_POOL_BUF_SIZE)

static odp_pool_t pkt_pool = ODP_POOL_INVALID;

/**
 * Buffer pool for crypto session output packets
 */
#define SHM_OUT_POOL_BUF_COUNT 1024
#define SHM_OUT_POOL_BUF_SIZE  4096
#define SHM_OUT_POOL_SIZE      (SHM_OUT_POOL_BUF_COUNT * SHM_OUT_POOL_BUF_SIZE)

static odp_pool_t out_pool = ODP_POOL_INVALID;

/** Synchronize threads before packet processing begins */
static odp_barrier_t sync_barrier;

/**
 * Packet processing result codes
 */
typedef enum {
	PKT_CONTINUE,    /**< No events posted, keep processing */
	PKT_POSTED,      /**< Event posted, stop processing */
	PKT_DROP,        /**< Reason to drop detected, stop processing */
	PKT_DONE         /**< Finished with packet, stop processing */
} pkt_disposition_e;

/**
 * Example supports either polling queues or using odp_schedule
 */
typedef odp_queue_t (*queue_create_func_t)
			(const char *, const odp_queue_param_t *);

typedef int (*schedule_multi_func_t)
			(odp_queue_t *, uint64_t, odp_event_t events[], int);

static queue_create_func_t queue_create;
static schedule_multi_func_t schedule_multi;

#define MAX_POLL_QUEUES 256
#define MAX_COMPL_QUEUES		24
#define GET_THR_QUEUE_ID(x)		((odp_thread_id()-1) % (x))

/** ORDERED queue (eventually) for per packet crypto API completion events */
static odp_queue_t completionq[MAX_COMPL_QUEUES];

static odp_queue_t poll_queues[MAX_POLL_QUEUES];
static int num_polled_queues;
static int num_compl_queues;
static int num_workers;


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
#if ODP_IPSEC_PERF_MODE
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
#if !ODP_IPSEC_PERF_MODE
	l4_ports = (((uint32_t)l4_sport << 16) | ((uint32_t)l4_dport));
#endif
	ODP_BJ3_MIX(ip_src, ip_dst, l4_ports);
#if !ODP_IPSEC_PERF_MODE
	l4_ports += ip_proto;
	ODP_BJ3_MIX(ip_src, ip_dst, l4_ports);
#endif
	return l4_ports;
}


/**
 * odp_queue_create wrapper to enable polling versus scheduling
 */
static
odp_queue_t polled_odp_queue_create(const char *name,
				const odp_queue_param_t *param)
{
	odp_queue_t my_queue;
	odp_queue_type_t type = param->type;

	if (ODP_QUEUE_TYPE_SCHED == type) {
		printf("%s: change %s to POLL\n", __func__, name);
		type = ODP_QUEUE_TYPE_PLAIN;
	}

	my_queue = odp_queue_create(name, param);

	if (ODP_QUEUE_TYPE_PLAIN == type) {
		poll_queues[num_polled_queues++] = my_queue;
		printf("%s: adding %"PRIu64"\n", __func__,
		       odp_queue_to_u64(my_queue));
	}

	return my_queue;
}

/**
 * odp_schedule replacement to poll queues versus using ODP scheduler
 */
static
int polled_odp_schedule_multi(odp_queue_t *from, uint64_t wait,
		odp_event_t events[], int num)
{
	odp_time_t next;
	odp_time_t wtime;
	int first = 1;
	int i, idx;


	while (1) {
		int num_pkt = 0;

		idx = GET_THR_QUEUE_ID(num_compl_queues);
		num_pkt = odp_queue_deq_multi(
				completionq[idx],
				events, num);
		if (num_pkt > 0) {
			*from = completionq[idx];
			return num_pkt;
		}

		idx = GET_THR_QUEUE_ID(num_polled_queues);
		for (i = 0; (i * num_workers + idx) < num_polled_queues; i++) {
			num_pkt = odp_queue_deq_multi(
					poll_queues[i * num_workers + idx],
					events, num);
			if (num_pkt > 0) {
				*from = poll_queues[i * num_workers + idx];
				return num_pkt;
			}
		}
		if (ODP_SCHED_WAIT == wait)
			continue;

		if (ODP_SCHED_NO_WAIT == wait)
			break;

		if (first) {
			wtime = odp_time_local_from_ns(wait);
			next = odp_time_sum(odp_time_local(), wtime);
			first = 0;
			continue;
		}

		if (odp_time_cmp(next, odp_time_local()) < 0)
			break;
	}

	*from = ODP_QUEUE_INVALID;
	return -1;
}

/**
 * IPsec pre argument processing intialization
 */
static
void ipsec_init_pre(void)
{
	odp_pool_param_t params;

	/* Create output buffer pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_OUT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_OUT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_BUF_COUNT;
	params.type        = ODP_POOL_PACKET;

	out_pool = odp_pool_create("out_pool", &params);

	if (ODP_POOL_INVALID == out_pool) {
		EXAMPLE_ERR("Error: message pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Initialize our data bases */
	init_sp_db();
	init_sa_db();
	init_tun_db();
	init_ipsec_cache();
}

/**
 * IPsec post argument processing intialization
 *
 * Resolve SP DB with SA DB and create corresponding IPsec cache entries
 *
 * @param api_mode  Mode to use when invoking per packet crypto API
 */
static
void ipsec_init_post(crypto_api_mode_e api_mode)
{
	sp_db_entry_t *entry;
	int queue_id = 0;

	/* Attempt to find appropriate SA for each SP */
	for (entry = sp_db->list; NULL != entry; entry = entry->next) {
		sa_db_entry_t *cipher_sa = NULL;
		sa_db_entry_t *auth_sa = NULL;
		tun_db_entry_t *tun = NULL;
		queue_id %= num_workers;
		if (num_compl_queues < num_workers)
			num_compl_queues++;
		queue_id++;
		if (entry->esp) {
			cipher_sa = find_sa_db_entry(&entry->src_subnet,
					&entry->dst_subnet, 1);
			tun = find_tun_db_entry(cipher_sa->src_ip,
					cipher_sa->dst_ip);
		}
		if (entry->ah) {
			auth_sa = find_sa_db_entry(&entry->src_subnet,
					&entry->dst_subnet, 0);
			tun = find_tun_db_entry(auth_sa->src_ip,
					auth_sa->dst_ip);
		}

		if (cipher_sa && auth_sa) {
			if (create_ipsec_cache_entry(cipher_sa,
						     auth_sa,
						     tun,
						     api_mode,
						     entry->input,
						     completionq[queue_id - 1],
						     out_pool)) {
				EXAMPLE_ERR("Error: IPSec cache entry failed.\n");
				exit(EXIT_FAILURE);
			}
		} else {
			printf(" WARNING: SA not found for SP\n");
			dump_sp_db_entry(entry);
		}
	}
}

/**
 * Initialize interface
 *
 * Initialize ODP pktio and queues, query MAC address and update
 * forwarding database.
 *
 * @param intf     Interface name string
 */
static void initialize_intf(char *intf)
{
	odp_pktio_t pktio;
	odp_pktout_queue_t pktout;
	odp_queue_t inq_def;
	int ret;
	uint8_t src_mac[ODPH_ETHADDR_LEN];
	char src_mac_str[MAX_STRING];
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;

	odp_pktio_param_init(&pktio_param);
	odp_pktin_queue_param_init(&pktin_param);

	/*SM: Now there are no poll queues need to change this later */
	if (getenv("ODP_IPSEC_USE_POLL_QUEUES")) {
		pktio_param.in_mode = ODP_PKTIN_MODE_QUEUE;
	} else {
		pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;
		pktin_param.queue_param.type = ODP_QUEUE_TYPE_SCHED;
		pktin_param.queue_param.sched.sync = ODP_SCHED_SYNC_ATOMIC;
		pktin_param.queue_param.sched.prio = ODP_SCHED_PRIO_DEFAULT;
	}

	/*
	 * Open a packet IO instance for thread and get default output queue
	 */
	pktio = odp_pktio_open(intf, pkt_pool, &pktio_param);
	if (ODP_PKTIO_INVALID == pktio) {
		EXAMPLE_ERR("Error: pktio create failed for %s\n", intf);
		exit(EXIT_FAILURE);
	}

	/*
	 * Create and set the default INPUT queue associated with the 'pktio'
	 * resource
	 */
	if (odp_pktin_queue_config(pktio, &pktin_param))
		EXAMPLE_ABORT("Error: pktin config failed for %s\n", intf);

	if (odp_pktout_queue_config(pktio, NULL))
		EXAMPLE_ABORT("Error: pktout config failed for %s\n", intf);

	if (odp_pktin_event_queue(pktio, &inq_def, 1) != 1)
		EXAMPLE_ABORT("Error: failed to get input queue for %s\n", intf);

	if (odp_pktout_queue(pktio, &pktout, 1) != 1)
		EXAMPLE_ABORT("Error: failed to get pktout queue for %s\n", intf);

	ret = odp_pktio_start(pktio);
	if (ret) {
		EXAMPLE_ERR("Error: unable to start %s\n", intf);
		exit(EXIT_FAILURE);
	}

	/* Read the source MAC address for this interface */
	ret = odp_pktio_mac_addr(pktio, src_mac, sizeof(src_mac));
	if (ret < 0) {
		EXAMPLE_ERR("Error: failed during MAC address get for %s\n",
			    intf);
		exit(EXIT_FAILURE);
	}

	printf("Created pktio:%02" PRIu64 ", queue mode (ATOMIC queues)\n"
	       "          default pktio%02" PRIu64 "-INPUT queue:%" PRIu64 "\n"
	       "          source mac address %s\n",
	       odp_pktio_to_u64(pktio), odp_pktio_to_u64(pktio),
	       odp_queue_to_u64(inq_def),
	       mac_addr_str(src_mac_str, src_mac));

	/* Resolve any routes using this interface for output */
	resolve_fwd_db(intf, pktout, src_mac);
}

/**
 * Packet Processing - Input verification
 *
 * @param pkt  Packet to inspect
 *
 * @return PKT_CONTINUE if good, supported packet else PKT_DROP
 */
static pkt_disposition_e do_input_verify(odp_packet_t pkt)
{
	if (odp_unlikely(odp_packet_has_error(pkt))) {
		odp_packet_free(pkt);
		return PKT_DROP;
	}

	if (!odp_packet_has_eth(pkt)) {
		odp_packet_free(pkt);
		return PKT_DROP;
	}

	if (!odp_packet_has_ipv4(pkt)) {
		odp_packet_free(pkt);
		return PKT_DROP;
	}

	return PKT_CONTINUE;
}

/**
 * Packet Processing - Route lookup in forwarding database
 *
 * @param pkt  Packet to route
 *
 * @return PKT_CONTINUE if route found else PKT_DROP
 */
static
pkt_disposition_e do_route_fwd_db(odp_packet_t pkt)
{
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	fwd_db_entry_t *fwd_entry;
	uint16_t	sport = 0, dport = 0;
	uint32_t	sip, dip;
	uint8_t		proto;
	uint64_t	hash;
	odph_ethhdr_t	*eth;
	odp_flow_entry_t *flow = NULL;

	if (ip->ttl > 1) {
		ip->ttl -= 1;
		if (ip->chksum >= odp_cpu_to_be_16(0xffff - 0x100))
			ip->chksum += odp_cpu_to_be_16(0x100) + 1;
		else
			ip->chksum += odp_cpu_to_be_16(0x100);
	} else {
		odp_packet_free(pkt);
		return PKT_DROP;
	}

	sip = odp_be_to_cpu_32(ip->src_addr);
	dip = odp_be_to_cpu_32(ip->dst_addr);
	proto = ip->proto;

#if !ODP_IPSEC_PERF_MODE
	odph_udphdr_t	*udp;

	if (odp_packet_has_udp(pkt) || odp_packet_has_tcp(pkt)) {
		/* UDP or TCP*/
		udp = (odph_udphdr_t *)odp_packet_l4_ptr(pkt, NULL);
		sport = odp_be_to_cpu_16(udp->src_port);
		dport = odp_be_to_cpu_16(udp->dst_port);
	}
#endif

	hash = odp_calculate_hash(sip, dip, sport, dport, proto);

	flow = odp_route_flow_lookup_in_bucket(sip, dip, sport,
								dport, proto,
					&flow_table[hash & (bucket_count - 1)]);
	if (flow) {
		goto do_opt;
	} else {
		/*Check into Routing table*/
		fwd_entry = find_fwd_db_entry(dip);
		if (fwd_entry) {
			/*Entry found. Updated in Flow table first.*/
			flow = calloc(1, sizeof(odp_flow_entry_t));
			if (!flow) {
				EXAMPLE_ERR("Failure to allocate memory");
				exit(EXIT_FAILURE);
			}
			flow->l3_src = sip;
			flow->l3_dst = dip;
			flow->l4_sport = sport;
			flow->l4_dport = dport;
			flow->l3_proto = proto;
			flow->out_port.pktout = fwd_entry->pktout;
			memcpy(flow->out_port.addr.addr, fwd_entry->src_mac, ODPH_ETHADDR_LEN);
			memcpy(flow->out_port.next_hop_addr.addr, fwd_entry->dst_mac, ODPH_ETHADDR_LEN);
			flow->next = NULL;
			/*Insert new flow into flow cache table*/
			/*TODO: Age out in not supported currently for route cache entries.
			All the configured flows will remain in table till the process
			terminates*/
			odp_route_flow_insert_in_bucket(flow, &flow_table[hash & (bucket_count - 1)]);
		} else {
			EXAMPLE_DBG("No flow match found. Packet is dropped.\n");
			odp_packet_free(pkt);
			return PKT_DROP;

		}
	}

do_opt:
	eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);

	eth->dst = flow->out_port.next_hop_addr;
	eth->src = flow->out_port.addr;
	odp_packet_user_ptr_set(pkt, &(flow->out_port.pktout));

	return PKT_CONTINUE;
}


/**
 * Packet Processing - Input IPsec packet classification
 *
 * Verify the received packet has IPsec headers and a match
 * in the IPsec cache, if so issue crypto request else skip
 * input crypto.
 *
 * @param pkt   Packet to classify
 * @param result   result of crypto operation
 *
 * @return PKT_CONTINUE if done else PKT_POSTED
 */
static
pkt_disposition_e do_ipsec_in_classify(odp_packet_t pkt,
				       odp_crypto_op_result_t *result)
{
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	odph_esphdr_t *esp = (odph_esphdr_t *)((char *)ip +
				sizeof(odph_ipv4hdr_t));
	ipsec_cache_entry_t *entry;
	odp_crypto_op_params_t params;
	odp_bool_t posted = 0;
	uint32_t	sip, dip;
	uint64_t	hash;
	odp_flow_entry_t *flow = NULL;

	sip = odp_be_to_cpu_32(ip->src_addr);
	dip = odp_be_to_cpu_32(ip->dst_addr);

	/* Check IP header for IPSec protocols and look it up */
	if (ip->proto != IPPROTO_ESP)
		return PKT_CONTINUE;

	hash = odp_calculate_hash(sip, dip, 0, 0, 0);

	flow = odp_route_flow_lookup_in_bucket(sip, dip, 0, 0, 0,
					&ipsec_in_flow_table[hash & (bucket_count - 1)]);
	if (flow) {
		goto do_opt;
	} else {
		/*Check into Routing table*/
		entry = find_ipsec_cache_entry_in(sip, dip, esp);
		if (!entry) {
			return PKT_CONTINUE;
		} else {
			/*Entry found. Updated in Flow table first.*/
			flow = calloc(1, sizeof(odp_flow_entry_t));
			if (!flow) {
				EXAMPLE_ERR("Failure to allocate memory");
				exit(EXIT_FAILURE);
			}
			flow->l3_src = sip;
			flow->l3_dst = dip;
			flow->l4_sport = 0;
			flow->l4_dport = 0;
			flow->l3_proto = 0;
			flow->out_port.session = entry->state.session;
			flow->out_port.imode = entry->in_place;
			flow->next = NULL;
			/*Insert new flow into flow cache table*/
			/*TODO: Age out in not supported currently for route cache entries.
			All the configured flows will remain in table till the process
			terminates*/
			odp_route_flow_insert_in_bucket(flow, &ipsec_in_flow_table[hash & (bucket_count - 1)]);
		}
	}

do_opt:
	/* Initialize parameters block */
	memset(&params, 0, sizeof(params));
	params.session = flow->out_port.session;
	params.pkt = pkt;
	params.out_pkt =  flow->out_port.imode ? pkt : ODP_PACKET_INVALID;
	params.cipher_range.offset = sizeof(odph_ethhdr_t);

	/* Issue crypto request */
	if (odp_crypto_operation(&params,
				 &posted,
				 result)) {
		abort();
	}
	return (posted) ? PKT_POSTED : PKT_CONTINUE;
}

/**
 * Packet Processing - Output IPsec packet classification
 *
 * Verify the outbound packet has a match in the IPsec cache,
 * if so issue prepend IPsec headers and prepare parameters
 * for crypto API call.  Post the packet to ATOMIC queue so
 * that sequence numbers can be applied in packet order as
 * the next processing step.
 *
 * @param pkt   Packet to classify
 * @param result   result of crypto operation
 *
 * @return PKT_CONTINUE if done else PKT_POSTED
 */
static
pkt_disposition_e do_ipsec_out_classify(odp_packet_t pkt,
					odp_crypto_op_result_t *result)
{
	odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
	ipsec_cache_entry_t *entry;
	odp_crypto_op_params_t params;
	odp_bool_t posted = 0;
	uint32_t	sip, dip;
	uint64_t	hash;
	odp_flow_entry_t *flow = NULL;

	sip = odp_be_to_cpu_32(ip->src_addr);
	dip = odp_be_to_cpu_32(ip->dst_addr);

	hash = odp_calculate_hash(sip, dip, 0, 0, 0);

	flow = odp_route_flow_lookup_in_bucket(sip, dip, 0, 0, 0,
					&ipsec_out_flow_table[hash & (bucket_count - 1)]);
	if (flow) {
		goto do_opt;
	} else {
		/*Check into Routing table*/
		entry = find_ipsec_cache_entry_out(sip, dip, ip->proto);
		if (!entry) {
			return PKT_CONTINUE;
		} else {
			/*Entry found. Updated in Flow table first.*/
			flow = calloc(1, sizeof(odp_flow_entry_t));
			if (!flow) {
				EXAMPLE_ERR("Failure to allocate memory");
				exit(EXIT_FAILURE);
			}
			flow->l3_src = sip;
			flow->l3_dst = dip;
			flow->l4_sport = 0;
			flow->l4_dport = 0;
			flow->l3_proto = 0;
			flow->out_port.session = entry->state.session;
			flow->out_port.imode = entry->in_place;
			flow->next = NULL;
			/*Insert new flow into flow cache table*/
			/*TODO: Age out in not supported currently for route cache entries.
			All the configured flows will remain in table till the process
			terminates*/
			odp_route_flow_insert_in_bucket(flow, &ipsec_out_flow_table[hash & (bucket_count - 1)]);
		}
	}

do_opt:
	/* Initialize parameters block */
	memset(&params, 0, sizeof(params));
	params.session = flow->out_port.session;
	params.pkt = pkt;
	params.out_pkt = flow->out_port.imode ? pkt : ODP_PACKET_INVALID;
	params.cipher_range.offset = sizeof(odph_ethhdr_t);

	/* Issue crypto request */
	if (odp_crypto_operation(&params,
				 &posted,
				 result)) {
		abort();
	}
	return (posted) ? PKT_POSTED : PKT_CONTINUE;
}

/**
 * Packet IO worker thread
 *
 * Loop calling odp_schedule_multi to obtain packets from the two sources,
 * and continue processing the packet.
 *
 *  - Input interfaces (i.e. new work)
 *  - Per packet crypto API completion queue
 *
 * @param arg  Required by "odph_linux_pthread_create", unused
 *
 * @return NULL (should never return)
 */
static
void *pktio_thread(void *arg EXAMPLE_UNUSED)
{
	int thr;
	odp_packet_t pkt;
	odp_event_t ev[DEFAULT_BUDGET] = {NULL};
	odp_crypto_op_result_t result;
#if DEBUG
	unsigned long pkt_cnt = 0;
#endif
	thr = odp_thread_id();

	printf("Pktio thread [%02i] starts\n", thr);
	odp_barrier_wait(&sync_barrier);

	/* Loop packets */
	for (;;) {
		pkt_disposition_e rc;
		odp_queue_t  dispatchq;
		int i, num;

		num = schedule_multi(&dispatchq, ODP_SCHED_WAIT, ev, DEFAULT_BUDGET);
		/* Use schedule to get event from any input queue */

		for (i = 0; i < num; i++) {
			/* Determine new work versus completion or sequence number */
			if (ODP_EVENT_PACKET == odp_event_type(ev[i])) {
				pkt = odp_packet_from_event(ev[i]);

				rc = do_input_verify(pkt);
				if (odp_unlikely(rc))
					continue;

				rc = do_ipsec_in_classify(pkt, &result);
				if (rc)
					continue;

				rc = do_route_fwd_db(pkt);
				if (odp_unlikely(rc))
					continue;

				rc = do_ipsec_out_classify(pkt, &result);
				if (rc)
					continue;

				if (odp_unlikely(odp_pktout_send(*((odp_pktout_queue_t *)odp_packet_user_ptr(pkt)), &pkt, 1) < 0))
					odp_packet_free(pkt);
#if DEBUG
				else
					rc = PKT_DONE;
#endif

			} else if (ODP_EVENT_CRYPTO_COMPL == odp_event_type(ev[i])) {
				odp_crypto_compl_t compl;

				compl = odp_crypto_compl_from_event(ev[i]);
				odp_crypto_compl_result(compl, &result);
				odp_crypto_compl_free(compl);
				pkt = result.pkt;
				if (odp_unlikely(!result.ok)) {
					odp_packet_free(pkt);
					continue;
				}
				odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)odp_packet_l3_ptr(pkt, NULL);
				if (ip->proto != IPPROTO_ESP) {
					rc = do_route_fwd_db(pkt);
					if (odp_unlikely(rc))
						continue;
				}

				if (odp_unlikely(odp_pktout_send(*((odp_pktout_queue_t *)odp_packet_user_ptr(pkt)), &pkt, 1) < 0))
					odp_packet_free(pkt);
#if DEBUG
				else
					rc = PKT_DONE;
#endif
			} else {
				abort();
			}
#if DEBUG
			/* Print packet counts every once in a while */
			if (PKT_DONE == rc) {
				if (odp_unlikely(pkt_cnt++ % 100000 == 0)) {
					printf("[%02i] pkt_cnt:%lu\n", thr, pkt_cnt);
					fflush(NULL);
				}
			}
#endif
		}
	}

	/* unreachable */
	return NULL;
}

/**
 * ODP ipsec example main function
 */
int
main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	int i;
	odp_shm_t shm;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	odp_queue_param_t qparam;
	odp_instance_t instance;
	odph_linux_thr_params_t thr_params;

	/*Validate if user has passed only help option*/
	if (argc == 2) {
		if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
			usage(argv[0]);
			exit(EXIT_SUCCESS);
		}
	}

	/* create by default scheduled queues */
	queue_create = odp_queue_create;
	schedule_multi = odp_schedule_multi;

	/* check for using poll queues */
	if (getenv("ODP_IPSEC_USE_POLL_QUEUES")) {
		queue_create = polled_odp_queue_create;
		schedule_multi = polled_odp_schedule_multi;
	}
	/* Initialize ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}
	/* Initialize this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}
	/* Reserve memory for arguments from shared memory */
	shm = odp_shm_reserve("shm_args", sizeof(args_t),
			      ODP_CACHE_LINE_SIZE, 0);
	args = odp_shm_addr(shm);

	if (NULL == args) {
		EXAMPLE_ERR("Error: shared mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}
	memset(args, 0, sizeof(*args));

	/* Must init our databases before parsing args */
	ipsec_init_pre();
	init_fwd_db();

	/* Parse and store the application arguments */
	parse_args(argc, argv, &args->appl);

	/*Initialize route table for user given parameter*/
	odp_init_routing_table();

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &args->appl);

	/* Default to system CPU count unless user specified */
	num_workers = MAX_WORKERS;
	if (args->appl.cpu_count && args->appl.cpu_count <= MAX_WORKERS)
		num_workers = args->appl.cpu_count;

	/*
	 * By default CPU #0 runs Linux kernel background tasks.
	 * Start mapping thread from CPU #1
	 */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	/*
	 * Create completion queues
	 */
	odp_queue_param_init(&qparam);
	qparam.type       = ODP_QUEUE_TYPE_SCHED;
	qparam.sched.prio  = ODP_SCHED_PRIO_HIGHEST;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	for (i = 0; i < num_workers; i++) {
		completionq[i] = queue_create("completion", &qparam);
		if (ODP_QUEUE_INVALID == completionq[i]) {
			EXAMPLE_ERR("Error: completion queue creation failed\n");
			exit(EXIT_FAILURE);
		}
	}
	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	/* Create a barrier to synchronize thread startup */
	odp_barrier_init(&sync_barrier, num_workers);

	/* Create packet buffer pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_BUF_COUNT;
	params.type        = ODP_POOL_PACKET;

	pkt_pool = odp_pool_create("packet_pool", &params);

	if (ODP_POOL_INVALID == pkt_pool) {
		EXAMPLE_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Populate our IPsec cache */
	printf("Using %s mode for crypto API\n\n",
	       (CRYPTO_API_SYNC == args->appl.mode) ? "SYNC" :
	       (CRYPTO_API_ASYNC_IN_PLACE == args->appl.mode) ?
	       "ASYNC_IN_PLACE" : "ASYNC_NEW_BUFFER");
	ipsec_init_post(args->appl.mode);

	/* Initialize interfaces (which resolves FWD DB entries */
	for (i = 0; i < args->appl.if_count; i++) {
		initialize_intf(args->appl.if_names[i]);
	}

	memset(&thr_params, 0, sizeof(thr_params));
	thr_params.start    = pktio_thread;
	thr_params.arg      = NULL;
	thr_params.thr_type = ODP_THREAD_WORKER;
	thr_params.instance = instance;

	/* Create and initialize worker threads */
	odph_linux_pthread_create(thread_tbl, &cpumask,
					  &thr_params);
	odph_linux_pthread_join(thread_tbl, num_workers);

	free(args->appl.if_names);
	free(args->appl.if_str);
	printf("Exit\n\n");
	return 0;
}

/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *token;
	size_t len;
	int rc = 0;
	int i;

	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"mode", required_argument, NULL, 'm'},		/* return 'm' */
		{"route", required_argument, NULL, 'r'},	/* return 'r' */
		{"policy", required_argument, NULL, 'p'},	/* return 'p' */
		{"ah", required_argument, NULL, 'a'},		/* return 'a' */
		{"esp", required_argument, NULL, 'e'},		/* return 'e' */
		{"tunnel", required_argument, NULL, 't'},       /* return 't' */
		{"flows", no_argument, NULL, 'f'},		/* return 'f' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	printf("\nParsing command line options\n");

	appl_args->mode = 0;  /* turn off async crypto API by default */
	appl_args->flows = 1;

	while (!rc) {
		opt = getopt_long(argc, argv, "+c:i:m:h:r:p:a:e:t:s:f:",
				  longopts, &long_index);
		if (opt < 0)
			break;	/* No more options */
		switch (opt) {
		case 'f':
			appl_args->flows = atoi(optarg);
			if (appl_args->flows > 256) {
				printf("Maximum acceptable value for -f is 256\n");
				rc = -1;
			}
			if (optind != 3) {
				printf("-f must be the 1st argument of the command\n");
				rc = -1;
			}
			EXAMPLE_DBG("Bucket count = %d\n", bucket_count);
			break;
		case 'c':
			appl_args->cpu_count = atoi(optarg);
			break;
		case 'i':
			/* parse packet-io interface names */
			len = strlen(optarg);
			if (0 == len) {
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
			     token; token = strtok(NULL, ","), i++);
			appl_args->if_count = i;
			if (!appl_args->if_count) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			/* Allocate storage for the if names */
			appl_args->if_names =
				calloc(appl_args->if_count, sizeof(char *));
			if (!appl_args->if_names) {
				EXAMPLE_ERR("Memory allocation failure\n");
				exit(EXIT_SUCCESS);
			}
			/* Store the if names (reset names string) */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token; token = strtok(NULL, ","), i++) {
				appl_args->if_names[i] = token;
			}
			break;
		case 'm':
			appl_args->mode = atoi(optarg);
			break;
		case 'r':
			rc = create_fwd_db_entry(optarg, appl_args->if_names,
						 appl_args->if_count, appl_args->flows);
			break;
		case 'p':
			rc = create_sp_db_entry(optarg, appl_args->flows);
			break;
		case 'a':
			rc = create_sa_db_entry(optarg, FALSE, appl_args->flows);
			break;
		case 'e':
			rc = create_sa_db_entry(optarg, TRUE, appl_args->flows);
			break;
		case 't':
			rc = create_tun_db_entry(optarg, appl_args->flows);
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	if (rc) {
		printf("ERROR: failed parsing -%c option\n", opt);
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (0 == appl_args->if_count) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	int i;

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
	printf("Running ODP application: \"%s\"\n"
	       "------------------------\n"
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n");
	dump_fwd_db();
	dump_sp_db();
	dump_sa_db();
	dump_tun_db();
	printf("\n\n");
	fflush(NULL);
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
	       " -i, --interface Eth interfaces (comma-separated, no spaces)\n"
	       " -m, --mode   0: SYNC\n"
	       "              1: ASYNC_IN_PLACE\n"
	       "              2: ASYNC_NEW_BUFFER\n"
	       "         Default: 0: SYNC api mode\n"
	       "\n"
	       "Routing / IPSec OPTIONS:\n"
	       " -r, --route SubNet:Intf:NextHopMAC\n"
	       " -p, --policy SrcSubNet:DstSubNet:(in|out):(ah|esp|both)\n"
	       " -e, --esp SrcIP:DstIP:(3des|null):SPI:Key192\n"
	       " -a, --ah SrcIP:DstIP:(md5|null):SPI:Key128\n"
	       "\n"
	       "  Where: NextHopMAC is raw hex/dot notation, i.e. 03.BA.44.9A.CE.02\n"
	       "         IP is decimal/dot notation, i.e. 192.168.1.1\n"
	       "         SubNet is decimal/dot/slash notation, i.e 192.168.0.0/16\n"
	       "         SPI is raw hex, 32 bits\n"
	       "         KeyXXX is raw hex, XXX bits long\n"
	       "\n"
	       "  Examples:\n"
	       "     -r 192.168.222.0/24:p8p1:08.00.27.F5.8B.DB\n"
	       "     -p 192.168.111.0/24:192.168.222.0/24:out:esp\n"
	       "     -e 192.168.111.2:192.168.222.2:3des:201:656c8523255ccc23a66c1917aa0cf30991fce83532a4b224\n"
	       "     -a 192.168.111.2:192.168.222.2:md5:201:a731649644c5dee92cbd9c2e7e188ee6\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -f, --flows <number> routes count.\n"
	       "  -c, --count <number> CPU count.\n"
	       "  -h, --help           Display help and exit.\n"
	       " environment variables: ODP_PKTIO_DISABLE_SOCKET_MMAP\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_MMSG\n"
	       "                        ODP_PKTIO_DISABLE_SOCKET_BASIC\n"
	       " can be used to advanced pkt I/O selection for linux-generic\n"
	       "                        ODP_IPSEC_USE_POLL_QUEUES\n"
	       " to enable use of poll queues instead of scheduled (default)\n"
	       "                        ODP_IPSEC_STREAM_VERIFY_MDEQ\n"
	       " to enable use of multiple dequeue for queue draining during\n"
	       " stream verification instead of single dequeue (default)\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
		);
}
