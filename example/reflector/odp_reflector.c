/* Copyright (C) 2015 Freescale Semiconductor,Inc
 * All rights reserved.
 * Copyright 2017 NXP
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <example_debug.h>

#include <odp_api.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>

#define MAX_STRING      32   /**< maximum string length */

/*#define PERF_MONITOR	1*/
/** @def MAX_WORKERS
 * @brief Maximum number of worker threads
 */
#define MAX_WORKERS            16

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE	2048

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      (2048 * SHM_PKT_POOL_BUF_SIZE)

/* ODP application data memory size include packet buffers */
#define ODPAPP_DATA_MEM_SIZE  ((uint64_t)256 * 1024 * 1024) /*256 MB*/

/** @def APPL_MODE_PKT_SCHED_PULL
 * @brief The application will handle packets with sheduler in Normal/PULL Mode
 */
#define APPL_MODE_PKT_SCHED_PULL	0

/** @def APPL_MODE_PKT_SCHED_PUSH
 * @brief The application will handle packets with sheduler in PUSH Mode
 */
#define APPL_MODE_PKT_SCHED_PUSH	1

/* Push mode with packet allocation and free */
#define APPL_MODE_PKT_ALLOC_SCH_PUSH	 2

/* Shuould not be used by User */
#define APPL_MODE_BENCHMARK		3

#define ALL_GROUPS			0xFF

/** @def MAX_PKTIOS
 * @brief Maximum allowed pktios for application
 */
#define MAX_PKTIOS      8

/** @def MAX_DEQ_PACKETS
 * @brief Maximum packets fetch at a time
 */
#define MAX_DEQ_PACKETS      4

/** @def PRINT_APPL_MODE(x)
 * @brief Macro to print the current status of how the application handles
 * packets.
 */
#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))
#define ODP_APP_DEBUG 0
/**
 * Parsed command line application arguments
 */
typedef struct {
	int cpu_count;		/**< system CPU count */
	const char *mask;	/**< CPU mask */
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	int mode;		/**< Packet IO mode */
	int buf_size;		/**< Size of each buffer in packet pool, not valid for ordered queues*/
	char *if_str;		/**< Storage for interface names */
	int queue_type;		/**< Scheduler Queue synchronization type*/
} appl_args_t;

/**
 * Thread specific arguments
 */
typedef struct {
	int mode;		/**< Thread mode */
	int grp_idx;		/**< scheduler group index */
} thread_args_t;

/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
	/** Lookup table for destination pktios */
	odp_pktio_t dest_pktios[MAX_PKTIOS];
} args_t;

/** Global pointer to args */
static args_t *args;

/** Global buffer pool */
static odp_pool_t pool;

/** Global pointor to scheduler groups */
odp_schedule_group_t *sched_grp;

/* helper funcs */
static odp_packet_t copy_pkt_addrs(odp_packet_t spkt);
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);
#if 0
static void swap_spkt_addrs(odp_packet_t pkt)
{
	odph_ethhdr_t *eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);

	if (!eth)
		return;
	odph_ethaddr_t tmp_addr = eth->dst;

	eth->dst = eth->src;
	eth->src = tmp_addr;

	if (odp_packet_has_ipv4(pkt)) {
		odph_ipv4hdr_t *ip = (odph_ipv4hdr_t *)
			odp_packet_l3_ptr(pkt, NULL);

		odp_u32be_t ip_tmp_addr = ip->src_addr;

		ip->src_addr = ip->dst_addr;
		ip->dst_addr = ip_tmp_addr;
	}
}
#endif

/**
 * Generate text string representing MAC address
 *
 * @param b     Pointer to buffer to store string
 * @param mac   Pointer to MAC address
 *
 * @return Pointer to supplied buffer
 */
static inline
char *mac_addr_str(char *b, uint8_t *mac)
{
        sprintf(b, "%02X.%02X.%02X.%02X.%02X.%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return b;
}

/**
 * Create a pktio handle, optionally associating a default input queue.
 *
 * @param dev Name of device to open
 * @param pool Pool to associate with device for packet RX/TX
 * @param queue_type type of queue to configure.
 *
 * @return The handle of the created pktio object.
 * @retval ODP_PKTIO_INVALID if the create fails.
 */
static odp_pktio_t create_pktio(const char *name, odp_pool_t pool, int queue_type, odp_schedule_group_t grp)
{
	odp_pktio_t pktio;
	int ret;
	odp_pktio_param_t pktio_param;
	odp_pktin_queue_param_t pktin_param;
	odp_pktio_capability_t capa;

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;
	/* Open a packet IO instance */
	pktio = odp_pktio_open(name, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		EXAMPLE_ABORT("Error: pktio create failed for %s\n", name);

	odp_pktin_queue_param_init(&pktin_param);
	pktin_param.queue_param.sched.sync = queue_type;
	pktin_param.queue_param.sched.group = grp;
	pktin_param.queue_param.sched.prio = ODP_SCHED_PRIO_DEFAULT;
	pktin_param.queue_param.type = ODP_QUEUE_TYPE_SCHED;
	ret = odp_pktio_capability(pktio, &capa);
	if (ret != 0)
		EXAMPLE_ABORT("Error: Unable to get pktio capability %s\n", name);

	pktin_param.num_queues = capa.max_input_queues;
	if (pktin_param.num_queues > 1)
		pktin_param.hash_enable = 1;

	if (odp_pktin_queue_config(pktio, &pktin_param))
		EXAMPLE_ABORT("Error: pktin config failed for %s\n", name);

	if (odp_pktout_queue_config(pktio, NULL))
		EXAMPLE_ABORT("Error: pktin config failed for %s\n", name);

	ret = odp_pktio_start(pktio);
	if (ret != 0)
		EXAMPLE_ABORT("Error: unable to start %s\n", name);

	if (capa.set_op.op.promisc_mode == 1) {
		ret = odp_pktio_promisc_mode_set(pktio, 1);
		if (ret != 0)
			EXAMPLE_ABORT("Error: Unable to set up promiscuous mode for %s\n", name);
	}

	return pktio;
}

/**
 * Loopback worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_alloc_thread(void *arg)
{
	int thr, i, ret;
	thread_args_t *thr_args;
	odp_packet_t pkt, pkt2;
	odp_pktout_queue_t pktout;
	odp_event_t ev;
	odp_thrmask_t thread_mask;

	thr = odp_thread_id();
	odp_thrmask_zero(&thread_mask);
	odp_thrmask_set(&thread_mask, thr);

#ifdef PERF_MONITOR
	uint64_t pkt_cnt = 0;
	uint64_t read1 = 0, read2 = 0, diff = 0;

	arm_enable_cycle_counter();
#endif
	thr_args = arg;

	if (thr_args->grp_idx != ALL_GROUPS ) {
		odp_schedule_group_info_t info;

		ret = odp_schedule_group_join(sched_grp[thr_args->grp_idx], &thread_mask);
		if (ret)
			EXAMPLE_ABORT("failed to join sched group to thread %d\n", thr);

		odp_schedule_group_info(sched_grp[thr_args->grp_idx], &info);
		printf("  Thread[%02i], CPU[%02i] looked up scheduler group (%s)\n", thr, odp_cpu_id(), info.name);
	} else {
		for (i = 0; i < args->appl.if_count; i++) {
			ret = odp_schedule_group_join(sched_grp[i], &thread_mask);
			if (ret)
				EXAMPLE_ABORT("failed to join sched group to thread %d\n", thr);
		}
		printf("  Thread[%02i], CPU[%02i] looked up scheduler groups (sched_grp_0 ... sched_grp_%d)\n",
				thr, odp_cpu_id(), i);
	}

	/* Loop packets */
	for (;;) {
		odp_pktio_t pktio_tmp;
#ifdef PERF_MONITOR
		read1 = arm_read_counter(PM_COUNTER_1);
#endif
		ev = odp_schedule(NULL, ODP_SCHED_WAIT);
		pkt = odp_packet_from_event(ev);

		pkt2 = copy_pkt_addrs(pkt);
		if (pkt2 == ODP_PACKET_INVALID) {
			EXAMPLE_ERR("  [%i] copy packet failed.\n", thr);
			odp_packet_free(pkt);
			continue;
		}
		/* Enqueue the packet for output */
		pktio_tmp = odp_packet_input(pkt);

		if (odp_pktout_queue(args->dest_pktios[odp_pktio_index(pktio_tmp)], &pktout, 1) != 1) {
			EXAMPLE_ERR("  [%02i] Error: no pktout queue\n", thr);
			return NULL;
		}

		if (odp_pktout_send(pktout, &pkt, 1) != 1) {
			EXAMPLE_ERR("  [%i] Queue enqueue failed.\n", thr);
			odp_packet_free(pkt);
			odp_packet_free(pkt2);
			continue;
		}
		odp_packet_free(pkt2);

#ifdef PERF_MONITOR
		read2 = arm_read_counter(PM_COUNTER_1);
		diff += (read2 - read1);
		/* Print packet counts every once in a while */
		if (odp_unlikely(pkt_cnt++ % 1000000 == 0)) {
			printf("  [%02i] pkt_cnt:%lu  -- cycles diff: %lu\n", thr, pkt_cnt, diff / 1000000);
			diff = 0;
			fflush(NULL);
		}
#endif
	}

#ifdef PERF_MONITOR
	arm_disable_cycle_counter();
#endif
/* unreachable */
	return NULL;
}

/**
 * Loopback worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_thread(void *arg)
{
	int thr, ret, i = 0, j = 0;
	odp_pktout_queue_t pktout;
	thread_args_t *thr_args;
	odp_packet_t pkt[MAX_DEQ_PACKETS];
	odp_event_t ev[MAX_DEQ_PACKETS];
	odp_thrmask_t thread_mask;

	thr = odp_thread_id();
	odp_thrmask_zero(&thread_mask);
	odp_thrmask_set(&thread_mask, thr);
	thr_args = arg;

	if (thr_args->grp_idx != ALL_GROUPS ) {
		odp_schedule_group_info_t info;

		ret = odp_schedule_group_join(sched_grp[thr_args->grp_idx], &thread_mask);
		if (ret)
			EXAMPLE_ABORT("failed to join sched group to thread %d\n", thr);

		odp_schedule_group_info(sched_grp[thr_args->grp_idx], &info);
		printf("  Thread[%02i], CPU[%02i] looked up scheduler group (%s)\n", thr, odp_cpu_id(), info.name);
	} else {
		for (i = 0; i < args->appl.if_count; i++) {
			ret = odp_schedule_group_join(sched_grp[i], &thread_mask);
			if (ret)
				EXAMPLE_ABORT("failed to join sched group to thread %d\n", thr);
		}
		printf("  Thread[%02i], CPU[%02i] looked up scheduler groups (sched_grp_0 ... sched_grp_%d)\n",
				thr, odp_cpu_id(), i);
	}
#ifdef PERF_MONITOR
	uint64_t pkt_cnt = 0, read1 = 0, read2 = 0, diff = 0;

	arm_enable_cycle_counter();
#endif

	/* Loop packets */
	for (;;) {
		odp_pktio_t pktio_tmp;
#ifdef PERF_MONITOR
		read1 = arm_read_cycle_counter();
#endif
		ret = odp_schedule_multi(NULL, ODP_SCHED_WAIT,
					 ev, MAX_DEQ_PACKETS);
		if (ret > 0) {
			for (i = 0; i < ret; i++) {
			if (ev[i] != ODP_EVENT_INVALID)
				pkt[i] = odp_packet_from_event(ev[i]);
			}
			pktio_tmp = odp_packet_input(pkt[0]);

			if (odp_pktout_queue(args->dest_pktios[odp_pktio_index(pktio_tmp)], &pktout, 1) != 1) {
				EXAMPLE_ERR("  [%02i] Error: no pktout queue\n", thr);
				return NULL;
			}
			j = odp_pktout_send(pktout, &pkt[0], ret);
			if (j < ret) {
				EXAMPLE_ERR("  [%i] Queue enqueue failed. j = %d\n", thr, j);
				for (;j < ret; j++)
					odp_packet_free(pkt[j]);
			}
		}
#ifdef PERF_MONITOR
		read2 = arm_read_cycle_counter();
		diff += (read2 - read1);
		/* Print packet counts every once in a while */
		if (odp_unlikely(pkt_cnt++ % 1000000 == 0)) {
			printf("  [%02i] pkt_cnt:%lu  -- cycles diff: %lu\n", thr, pkt_cnt, diff / 1000000);
			diff = 0;
			fflush(NULL);
		}
#endif
	}
#ifdef PERF_MONITOR
	arm_disable_cycle_counter();
#endif

/* unreachable */
	return NULL;
}

static void stats_prints(odp_pktio_t pktio, odp_pktio_stats_t *stats)
{
	printf(" [%lu]stats are:", odp_pktio_to_u64(pktio));
	printf("\n   in_octets  = %lu ", stats->in_octets);
	printf("in_ucast_pkts = %lu ", stats->in_ucast_pkts);
	printf("in_discards = %lu ", stats->in_discards);
	printf("in_errors = %lu ", stats->in_errors);
	printf("in_unknown_protos = %lu ", stats->in_unknown_protos);
	printf("\n   out_octets = %lu ", stats->out_octets);
	printf("out_ucast_pkts = %lu ", stats->out_ucast_pkts);
	printf("out_discards = %lu ", stats->out_discards);
	printf("out_errors = %lu\n ", stats->out_errors);
}

/**
 * ODP packet example main function
 */
int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	int num_workers;
	int i;
	int cpu, workers_per_if, workers_to_all_if;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	odp_platform_init_t plat_init;
	odp_pktio_stats_t stats;
	odp_pktio_t pktio;
	odp_instance_t instance;
	odph_linux_thr_params_t thr_params;
	odp_pool_t *eth_pool;
	odp_thrmask_t zeromask;

	/* Create temporary pktios to populate dest_pktio table */
	odp_pktio_t pktio_tmp, pktio_prev, pktio_first;

	args = calloc(1, sizeof(args_t));
	if (args == NULL) {
		EXAMPLE_ABORT("Error: args mem alloc failed.\n");
	}

	memset(args, 0, sizeof(*args));
	/* Parse and store the application arguments */
	parse_args(argc, argv, &args->appl);

	/* Init ODP before calling anything else */

	eth_pool = malloc(sizeof(odp_pool_t) * args->appl.if_count);
	if (!eth_pool)
		EXAMPLE_ABORT("Error: pool mem alloc failed\n");

	sched_grp = malloc(sizeof(odp_schedule_group_t) * args->appl.if_count);
	if (!sched_grp)
		EXAMPLE_ABORT("Error: scheduler group mem alloc failed\n");

	switch (args->appl.mode) {
	case  APPL_MODE_PKT_SCHED_PULL:
		plat_init.dq_schedule_mode = ODPFSL_PULL;
		break;
	case APPL_MODE_PKT_SCHED_PUSH:
	case APPL_MODE_PKT_ALLOC_SCH_PUSH:
		plat_init.dq_schedule_mode = ODPFSL_PUSH;
		break;
	case APPL_MODE_BENCHMARK:
		plat_init.dq_schedule_mode = ODPFSL_PUSH;
		/* Following BIT is for internal use only
		   and not meant for User application */
		plat_init.dq_schedule_mode |= (1 << 31) ;
		break;
	}
	plat_init.data_mem_size = ODPAPP_DATA_MEM_SIZE;
	if (odp_init_global(&instance, NULL, &plat_init)) {
		EXAMPLE_ABORT("Error: ODP global init failed.\n");
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		EXAMPLE_ABORT("Error: ODP local init failed.\n");
	}

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &args->appl);

	/* Default to system CPU count unless user specified */
	num_workers = odp_cpu_count();
	if (args->appl.cpu_count)
		num_workers = args->appl.cpu_count;

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	if (args->appl.mask) {
		odp_cpumask_from_str(&cpumask, args->appl.mask);
		num_workers = odp_cpumask_count(&cpumask);
	}

	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n\n", cpumaskstr);

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = args->appl.buf_size;
	params.pkt.len     = args->appl.buf_size;
	params.pkt.num     = SHM_PKT_POOL_SIZE / args->appl.buf_size;

	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("default_packet_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		EXAMPLE_ABORT("Error: packet pool create failed.\n");
	}

	odp_thrmask_zero(&zeromask);
	pktio_tmp = ODP_PKTIO_INVALID;
	pktio_prev = ODP_PKTIO_INVALID;
	pktio_first = ODP_PKTIO_INVALID;
	/* Create a pktio instance for each interface */
	for (i = 0; i < args->appl.if_count; ++i) {
		char pool_name[ODP_POOL_NAME_LEN];
		odp_pool_info_t info;
		char grp_name[32];

		snprintf(pool_name, sizeof(pool_name), "pkt_pool_%s", args->appl.if_names[i]);
		snprintf(grp_name, sizeof(grp_name), "sched_grp_%d", i);
		sched_grp[i] = odp_schedule_group_create(grp_name, &zeromask);
		if (sched_grp[i] == ODP_SCHED_GROUP_INVALID)
			EXAMPLE_ABORT("Error: scheduler group create failed.\n");
		eth_pool[i] = odp_pool_create(pool_name, &params);
		if (eth_pool[i] == ODP_POOL_INVALID)
			EXAMPLE_ABORT("Error: packet pool create failed.\n");
		if (i == 0) {
			pktio_first = create_pktio(args->appl.if_names[i], eth_pool[i], args->appl.queue_type, sched_grp[i]);
			pktio_prev = pktio_first;
		} else {
			pktio_tmp = create_pktio(args->appl.if_names[i], eth_pool[i], args->appl.queue_type, sched_grp[i]);
			args->dest_pktios[odp_pktio_index(pktio_prev)] = pktio_tmp;
			pktio_prev = pktio_tmp;
		}
		odp_pool_info(eth_pool[i], &info);
		printf(" Attached pool\t\t\t= pkt_pool_%s, buffers = %d\n",
				args->appl.if_names[i], info.params.buf.num);
		printf(" Affined scheduler grp\t= %s\n", grp_name);
	}
	/* Last pktio will reflect packets to first pktio */
	args->dest_pktios[odp_pktio_index(pktio_prev)] = pktio_first;

	printf("  \nConfigured queues SYNC type: [%s]\n", (args->appl.queue_type == 0)?
							"PARALLEL":(args->appl.queue_type == 1)?
							"ATOMIC":"ORDERED");
	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));

	workers_per_if = num_workers / args->appl.if_count;
	workers_to_all_if = num_workers % args->appl.if_count;

	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_workers; ++i) {
		odp_cpumask_t thd_mask;

		if ((i + workers_to_all_if) < num_workers)
			args->thread[i].grp_idx = i / workers_per_if;
		else
			args->thread[i].grp_idx = ALL_GROUPS;

		args->thread[i].mode = args->appl.mode;

		/*
		 * Create threads one-by-one instead of all-at-once,
		 * because each thread might get different arguments.
		 * Calls odp_thread_create(cpu) for each thread
		 */
		memset(&thr_params, 0, sizeof(thr_params));
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.instance = instance;
		thr_params.start = (args->appl.mode == APPL_MODE_PKT_ALLOC_SCH_PUSH) ?
			pktio_alloc_thread : pktio_thread;
		thr_params.arg   = &args->thread[i];

		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);

		odph_linux_pthread_create(&thread_tbl[i], &thd_mask,
					  &thr_params);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	/* Master thread waits for other threads to exit */
	odph_linux_pthread_join(thread_tbl, num_workers);

	for (i = 0; i < args->appl.if_count; ++i) {
		memset(&stats, 0, sizeof(stats));
		printf("\nPacket stats I/F - %s", args->appl.if_names[i]);
		pktio = odp_pktio_lookup(args->appl.if_names[i]);
		if (pktio == ODP_PKTIO_INVALID)
			continue;
		odp_pktio_stats(pktio, &stats);
		stats_prints(pktio, &stats);
	}

	for (i = 0; i < args->appl.if_count; ++i) {
		odp_pool_destroy(eth_pool[i]);
	}

	odp_pool_destroy(pool);

	free(eth_pool);
	free(sched_grp);
	free(args->appl.if_names);
	free(args->appl.if_str);
	free(args);
	printf("Exit\n\n");

	return 0;
}

static odp_packet_t copy_pkt_addrs(odp_packet_t spkt)
{
	odp_packet_t pkt2;
	odph_ethhdr_t *eth, *srceth;
	odph_ipv4hdr_t *ip, *sip;

	pkt2 = odp_packet_alloc(pool, odp_packet_len(spkt));
	if (pkt2 == ODP_PACKET_INVALID)
		return pkt2;

	srceth = (odph_ethhdr_t *)odp_packet_l2_ptr(spkt, NULL);
	sip = (odph_ipv4hdr_t *)((char *)srceth + ODPH_ETHHDR_LEN);
	/* ether */
	eth = (odph_ethhdr_t *)odp_packet_data(pkt2);
	memcpy((char *)eth->src.addr, srceth->dst.addr, ODPH_ETHADDR_LEN);
	memcpy((char *)eth->dst.addr, srceth->src.addr, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

	/* ip */
	ip = (odph_ipv4hdr_t *)((char *)eth + ODPH_ETHHDR_LEN);
	ip->dst_addr = sip->src_addr;
	ip->src_addr = sip->dst_addr;
	ip->ver_ihl = sip->ver_ihl;
	ip->tot_len = sip->tot_len;
	ip->proto = ODPH_IPPROTO_UDP;
	ip->chksum = 0;
	return pkt2;
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
	odp_cpumask_t cpumask, cpumask_args, cpumask_and;
	int i, num_workers;
	static struct option longopts[] = {
		{"workers", required_argument, NULL, 'w'},
		{"cpumask", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"mode", required_argument, NULL, 'm'},		/* return 'm' */
		{"bufsize", required_argument, NULL, 's'},	/* return 's' */
		{"queue type", required_argument, NULL, 'q'},	/* return 'q' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	appl_args->mode = APPL_MODE_PKT_SCHED_PUSH;
	appl_args->buf_size = SHM_PKT_POOL_BUF_SIZE;
	appl_args->queue_type = ODP_SCHED_SYNC_ATOMIC;

	while (1) {
		opt = getopt_long(argc, argv, "+c:+w:i:+m:s:q:h",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'w':
			appl_args->cpu_count = atoi(optarg);
			break;
		case 's':
			appl_args->buf_size = atoi(optarg);
			break;
		case 'c':
			appl_args->mask = optarg;
			odp_cpumask_from_str(&cpumask_args, args->appl.mask);
			num_workers = odp_cpumask_default_worker(&cpumask, 0);
			odp_cpumask_and(&cpumask_and, &cpumask_args, &cpumask);
			if (odp_cpumask_count(&cpumask_and) <
			    odp_cpumask_count(&cpumask_args)) {
				EXAMPLE_ABORT("Wrong cpu mask, max cpu's:%d\n",
					      num_workers);
			}
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
				free((void *)appl_args->if_str);
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
				appl_args->mode = APPL_MODE_PKT_SCHED_PULL;
				break;
			case 1:
				appl_args->mode = APPL_MODE_PKT_SCHED_PUSH;
				break;
			case 2:
				appl_args->mode = APPL_MODE_PKT_ALLOC_SCH_PUSH;
				break;
			case 3:
				appl_args->mode = APPL_MODE_BENCHMARK;
				break;
			default:
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			break;

		case 'q':
			i = atoi(optarg);
			if (i > ODP_SCHED_SYNC_ORDERED || i < ODP_SCHED_SYNC_PARALLEL) {
				printf("Invalid queue type: setting default to atomic");
				break;
			}
			appl_args->queue_type = i;
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);

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
	case APPL_MODE_PKT_SCHED_PULL:
		PRINT_APPL_MODE(APPL_MODE_PKT_SCHED_PULL);
		break;
	case APPL_MODE_PKT_SCHED_PUSH:
		PRINT_APPL_MODE(APPL_MODE_PKT_SCHED_PUSH);
		break;
	case APPL_MODE_PKT_ALLOC_SCH_PUSH:
		PRINT_APPL_MODE(APPL_MODE_PKT_ALLOC_SCH_PUSH);
		break;
	case APPL_MODE_BENCHMARK:
		PRINT_APPL_MODE(APPL_MODE_BENCHMARK);
		break;
	}
	printf("\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i dpni.1,dpni.2 -m 1 --cpumask 0x2\n"
	       "\n"
	       "FSL OpenDataPlane reflector application.\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface pktio interfaces (comma-separated, no spaces)\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -w, --workers specify number of workers need to be assigned to application\n"
	       "	         default is to assign all\n"
	       "  -c, --cpumask to set on cores\n"
	       "  -m, --mode      0:	Receive Packets in Schedule PULL Mode.\n"
	       "                  1:	Receive Packets in Schedule PUSH Mode.\n"
		"                  2:	Receive Packets in Schedule PUSH Mode - with alloc and free\n"
		"  -q		specify the queue type\n"
		"		0:	ODP_SCHED_SYNC_PARALLEL\n"
		"		1:	ODP_SCHED_SYNC_ATOMIC\n"
		"		2:	ODP_SCHED_SYNC_ORDERED\n"
		"			default is ODP_SCHED_SYNC_ATOMIC\n"
	       "  -h, --help		Display help and exit.\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
}
