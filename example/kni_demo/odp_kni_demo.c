/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * @example odp_kni_demo.c ODP-KNI interfacing for packet transaction
 */

#include <odp_kni_demo.h>

/*********************************************************************
			Global Constants/Macro Definitions
**********************************************************************/

/* XXX In future, should be converted into application specific wrapper */
#ifndef SUCCESS
	#define SUCCESS			EXIT_SUCCESS
#endif
#ifndef FAILURE
	#define FAILURE			(-EXIT_FAILURE)
#endif

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

#define DEBUG_ON			1
#define DEBUG_OFF			0

/* ============= PKTIO Interface Values =========================== */

/** @def MAX_WORKERS_THREADS
 * @brief Maximum number of worker threads
 */
#define MAX_WORKER_THREADS		8

/** @def KNID_PKTIO_NUM_PKT
 * @brief Size of the shared memory block
 */
#define KNID_PKTIO_NUM_PKT		512

/** @def KNID_PKTIO_PKT_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define KNID_PKTIO_PKT_SIZE		2048

/** @def KNID_MAX_PKT_BURST
 * @brief Maximum number of packet bursts to handle;
 */
#define KNID_MAX_PKT_BURST		DEF_KNI_MAX_PKT_POLL

/* @def KNID_MAX_THREADS
 * @brief Maximum KNID application threads which can spawned, controlled by
 * physical interface limit.
 */
#define KNID_MAX_THREADS		ODPFSL_MAX_ETHPORTS

/* ============= KNI Interface Values =========================== */

/** @def KNI_PKT_HEADROOM
 * @brief Headroom space in the Packet mbuf, before the actual packet data
 */
#define KNI_PKT_HEADROOM		32

/** @def KNI_PKTMBUF_SIZE
 * @brief Default KNI buffer size for holding a single packet data + headroom
 */
#define KNI_PKTMBUF_SIZE \
	(KNID_PKTIO_PKT_SIZE + sizeof(struct kni_mbuf) + KNI_PKT_HEADROOM)

/** @def KNI_PKTMBUF_NUM
 * @brief Default number of buffers (packet mbuf) for KNI Interface
 * KNI_PKTMBUF_NUM * KNI_PKTMBUF_SIZE = space allocated for KNI buffer
 */
#define KNI_PKTMBUF_NUM		KNID_PKTIO_NUM_PKT

/** @def KNI_MAX_PKT_SIZE
 * @brief Default size of single Packet for KNI Interface, passed to KNI alloc
 * routine of DPAA2 (odpfsl_kni_alloc). This is equal to buffer size allocated
 */
#define KNI_MAX_PKT_SIZE		KNID_PKTIO_PKT_SIZE

/** @def KNI_MAX_PKT_POLL
 * @brief Default size of maximum packets buffers read from KNI Interface for
 * a single rx/tx call. It is equal to maximum limit of packets for PKTIO
 * interface
 */
#define KNI_MAX_PKT_POLL		KNID_MAX_PKT_BURST

/* @def KNI_DEFAULT_CORE_ID
 * @brief Default core on which first worker thread has to be spawned
 */
#define KNI_DEFAULT_CORE_ID		0

/*********************************************************************
			Global Variables
**********************************************************************/

/** KNI device structure */
odpfsl_knidev_t knidev_array[KNID_MAX_THREADS];

/* Global count of devices */
static uint8_t eth_dev_cnt;

/* Pools on which User passed and KNI Interface would work */
odp_pool_t packet_pool;	/* Packet Pool */

/* Flags for toggling Debug output; Updated from parsed cmdline args */
uint8_t debug_flag = DEBUG_OFF;
unsigned debug_pkt_cnt;
int packet_dump = DEBUG_OFF;

/*********************************************************************
			Function Definitions
**********************************************************************/

/*
 * KNI interface Change MTU Operation
 * This is currently not supported by ODP. In future versions, this would be
 * updated - till then, returns error.
 */
static int
kni_change_mtu(uint8_t port_id, unsigned new_mtu) {

	int32_t ret = -EINVAL;
	odp_pktio_t pktio = ODP_PKTIO_INVALID;

	if (port_id >= eth_dev_cnt) {
		EXAMPLE_ERR("Error: Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	pktio = odpfsl_knidev_get_pktio(knidev_array[port_id]);

	ret = odpfsl_pktio_mtu_set(pktio, new_mtu);
	EXAMPLE_DBG("Debug: MTU set operation status: %d.\n", ret);

	return ret;
}

/*
 * KNI interface status toggling callback
 * For a given KNI interface, this would toggle the state
 */
static int
kni_config_network_interface(uint8_t port_id, uint8_t if_up) {
	int ret = 0;
	odp_pktio_t pktio;
	odpfsl_knidev_t kdev_p;

	if (port_id >= eth_dev_cnt) {
		EXAMPLE_ERR("Error: Invalid port number while toggling "\
			"state:%d.\n", port_id);
		return -EINVAL;
	}

	kdev_p = knidev_array[port_id];
	if (!odpfsl_knidev_check_valid(kdev_p)) {
		EXAMPLE_ERR("Error: Invalid port number while toggling "\
			"state:%d.\n", port_id);
		return -EINVAL;
	}

	pktio = odpfsl_knidev_get_pktio(kdev_p);
	if (pktio != ODP_PKTIO_INVALID) {
		/* if_up = 1 is pktio_start; else pktio_stop */
		EXAMPLE_DBG("Debug: Toggling Network Interface status for "\
			"port:%d to %s.\n", port_id, if_up ? "up" : "down");
		if (if_up) {
			ret = odp_pktio_start(pktio);
		} else if (!if_up) {
			/* re-checking if_up as a precautionary step */
			ret = odp_pktio_stop(pktio);
		}
		if (ret) {
			EXAMPLE_ERR("Error: Unable to toggle interface "\
				"status.\n");
			/* Normalizing the error */
			ret = -EINVAL;
		}
	} else {
		EXAMPLE_ERR("Error: Unable to extract pktio associated with "\
			"KNI device. Interface toggling failed.\n");
		/* Normalizing the error */
		ret = -EINVAL;
	}

	return ret;
}

/*
 * Callback for configuring MAC Address on KNI interface
 * Currently not supported by the ODP implementation
 */
static int
kni_config_mac_address(uint8_t port_id,
			uint8_t mac_addr[6])
{
	int32_t ret = -EINVAL;
	odp_pktio_t pktio = ODP_PKTIO_INVALID;

	if (port_id >= eth_dev_cnt) {
		EXAMPLE_ERR("Error: Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	pktio = odpfsl_knidev_get_pktio(knidev_array[port_id]);

	ret = odpfsl_pktio_mac_addr_set(pktio,
		(void *)mac_addr, ODPH_ETHHDR_LEN);
	EXAMPLE_DBG("Debug: MAC addr set operation status: %d.\n", ret);

	return ret;
}

/*
 * Callback for toggling promiscuity state of the KNI interface
 *
 */
static int
kni_config_promiscusity(uint8_t port_id, uint8_t to_on)
{
	int32_t ret = -EINVAL;
	odp_bool_t p_enable = 1;
	odp_pktio_t pktio = ODP_PKTIO_INVALID;

	if (port_id >= eth_dev_cnt) {
		EXAMPLE_ERR("Error: Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	p_enable = to_on ? 1 : 0;

	pktio = odpfsl_knidev_get_pktio(knidev_array[port_id]);

	ret = odp_pktio_promisc_mode_set(pktio, p_enable);
	EXAMPLE_DBG("Debug: Promiscuity set operation status: %d.\n", ret);

	return ret;
}

/**
 * Dumping Interface statistics
 */
static void
kni_dump_interface_stats(void)
{
	uint8_t i;
	uint64_t rx_packets, rx_dropped, tx_packets, tx_dropped;

	EXAMPLE_DBG("Debug: Called kni_dump_interface_stats\n");

	printf("\n**KNI example application statistics**\n"
	       "======  ==============  ============  ============  ========"\
			"====  ============\n"
	       " Port    Lcore(RX/TX)    rx_packets    rx_dropped    "\
			"tx_packets    tx_dropped\n"
	       "------  --------------  ------------  ------------  --------"\
			"----  ------------\n");
	for (i = 0; i < eth_dev_cnt; i++) {
		if (!knidev_array[i])
			continue;

		odpfsl_knidev_get_stat_rx(knidev_array[i], &rx_packets,\
			&rx_dropped);
		odpfsl_knidev_get_stat_tx(knidev_array[i], &tx_packets,\
			&tx_dropped);

		printf("%7d %13"PRIu64"%13"PRIu64"%13"PRIu64" %13"PRIu64" %13"\
			PRIu64"\n", i, \
			rx_packets + tx_packets, \
			rx_packets, rx_dropped, \
			tx_packets, tx_dropped);
	}
	printf("======  ==============  ============  ============  ========"\
			"====  ============\n");
}

/**
 * Dumping transacted packets
 */
static inline void
kni_dump_packet(odp_packet_t packets[], int num)
{
	int j;
	odp_packet_t p;

	/* Packet Dump for debugging */
	if (debug_flag && packet_dump) {
		for (j = 0; j < num; j++) {
			p = packets[j];
			EXAMPLE_DBG("******* Start of Packet Dump *********"\
				"**\n\n");
			EXAMPLE_DBG("Debug: Packets rx'd from KNI, tx'd to "\
				"ODP.\n\n");
			odp_packet_print(p);
			EXAMPLE_DBG("******* End of Packet Dump ***********"\
				"**\n\n");
		}
	}
}

/**
 * Packets received on ODP interfaces are TX'd to KNI interface
 */
int32_t
handle_ingress_packets(odpfsl_knidev_t kdev, unsigned *pktin)
{
	uint8_t i, j;
	uint8_t kdev_t_count = 0;
	unsigned kni_tx_packets = 0, rx_packets = 0;
	int32_t pkt_count = 0, pkt_count_nodrop = 0, drop_packets = 0;
	odp_pktio_t pktio;
	odp_pktin_queue_t queues[8];

	odp_packet_t packets[KNID_MAX_PKT_BURST];

	if (!odpfsl_knidev_check_valid(kdev))
		return FAILURE;

	kdev_t_count = odpfsl_knidev_get_thread_count(kdev);
	pktio = odpfsl_knidev_get_pktio(kdev);

	for (i = 0; i < kdev_t_count; i++) {
		odp_pktin_queue(pktio, queues, 1);
		pkt_count = odp_pktin_recv(queues[0], packets,
				KNID_MAX_PKT_BURST);
		if (pkt_count > 0) {
			pkt_count_nodrop = drop_err_pkts(packets,
				(unsigned)pkt_count);

			if (pkt_count != pkt_count_nodrop)
				drop_packets += (pkt_count - pkt_count_nodrop);

			if (pkt_count_nodrop <= 0) {
				EXAMPLE_DBG("Debug: All packets received are "\
					"dropped.\n");
				continue;
			}

			/* 'tx' it to Kni interface */
			kni_tx_packets = odpfsl_kni_tx(kdev, i, packets,\
							pkt_count_nodrop);
			if (kni_tx_packets != (unsigned)pkt_count_nodrop)
				drop_packets += \
					(pkt_count_nodrop - kni_tx_packets);

			rx_packets += kni_tx_packets;

			/* Releasing all ODP Packet buffers consumed, which
			 * are not already dropped
			 */
			kni_dump_packet(packets, pkt_count_nodrop);
			for (j = 0; j < pkt_count_nodrop; j++)
				odp_packet_free(packets[j]);

		} else if (pkt_count <= 0) {
			/* Handling any other raised kni events while no
			 * packets arrive.
			 */
			odpfsl_kni_handle_events(kdev, i);
		}
	}

	*pktin = rx_packets;
	return SUCCESS;
}

/**
 * Packets received on KNI interface and tx'd to ODP interface
 */
int32_t
handle_egress_packets(odpfsl_knidev_t kdev, unsigned *pktout)
{
	uint8_t i, j;
	uint8_t kdev_t_count = 0;
	unsigned kni_rx_packets = 0, tx_packets = 0;
	uint32_t pkt_count = 0;
	odp_pktio_t pktio;
	odp_pktout_queue_t queues[8];

	/* XXX Only 1 frame is being received from kni_rx each cycle.
	 * This is performance hog! KNID_MAX_PKT_BURST = 1
	 */
	odp_packet_t packets[KNID_MAX_PKT_BURST];

	if (!odpfsl_knidev_check_valid(kdev))
		return FAILURE;

	kdev_t_count = odpfsl_knidev_get_thread_count(kdev);
	pktio = odpfsl_knidev_get_pktio(kdev);

	for (i = 0; i < kdev_t_count; i++) {
		kni_rx_packets = odpfsl_kni_rx(kdev, i, packet_pool,\
				packets, KNID_MAX_PKT_BURST);
		if (kni_rx_packets > 0) {
			kni_dump_packet(packets, kni_rx_packets);

			odp_pktout_queue(pktio, queues, 1);
			/* Send the packet out towards the ODP interface */
			pkt_count = odp_pktout_send(queues[0], packets, \
							kni_rx_packets);
			if (pkt_count <= 0) {
				/* Unable to send the frame */
				for (j = pkt_count; j < kni_rx_packets; j++)
					odp_packet_free(packets[j]);

				EXAMPLE_ERR("Error: Unable to send packet "\
						"to pktio interface.\n");
				break;
			}
			tx_packets += pkt_count;
		}

		/* Releasing all completed packets */
		if ((kni_rx_packets > 0) && (pkt_count < kni_rx_packets)) {
			EXAMPLE_DBG("Debug: Releasing unsent packets; pkt"\
				" idx:%d-%d.\n", pkt_count, kni_rx_packets);
			for (j = pkt_count; j < kni_rx_packets; j++)
				odp_packet_free(packets[j]);
		}
	}

	*pktout = tx_packets;

	return SUCCESS;
}

/**
 * Drop error packets before sending to KNI interface
 */
int32_t
drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len)
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
 * Parse and store the command line arguments
 */
int parse_cmdline_args(int argc, char *argv[], args_t *args)
{
	int opt;
	int long_index;
	char *token;
	size_t len;
	int i;

	struct option longopts[] = {
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"debug", required_argument, NULL, 'd'},	/* return 'd' */
		{"packetdump", no_argument, NULL, 'p'},		/* return 'p' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	while (1) {
		opt = getopt_long(argc, argv, "+i:d:ph",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'i':/* Case for Interface input */
			len = strlen(optarg);
			if (len == 0) {
				EXAMPLE_ERR("Error: Incorrect interface "\
					"string, or string not passed.\n");
				usage(argv[0]);
				return FAILURE;
			}
			len += 1; /* including \0 */

			args->if_str = malloc(len);
			if (!args->if_str) {
				EXAMPLE_ERR("Error: Unable to allocate "\
					"memory to parse command line "\
					"arguments.(2)\n");
				/* Internal error in binary */
				return FAILURE;
			}

			/* count the number of tokens separated by ',' */
			strcpy(args->if_str, optarg);
			token = strtok(args->if_str, ",");
			for (i = 0; token != NULL; i++)
				token = strtok(NULL, ",");

			args->if_count = i;

			/* Interface count passed as arg cannot be less than
			 * 1 and more than number of possible threads
			 */
			if (args->if_count <= 0 || \
				args->if_count > KNID_MAX_THREADS) {
				EXAMPLE_ERR("Error: Wrong number of "\
					"interfaces passed.\n");
				free(args->if_str);
				usage(argv[0]);
				return FAILURE;
			}

			/* allocate storage for the if names */
			args->if_names =
			    calloc(args->if_count, sizeof(char *));
			if (!args->if_names) {
				EXAMPLE_ERR("Error: Unable to allocate "\
					"memory to parse command"\
					" line arguments.(2)\n");
				free(args->if_str);
				return FAILURE;
			}

			/* store the if names (reset names string) */
			strcpy(args->if_str, optarg);
			token = strtok(args->if_str, ",");
			for (i = 0; token != NULL; i++) {
				args->if_names[i] = token;
				token = strtok(NULL, ",");
			}
			break;

		case 'd':
			len = strlen(optarg);
			if (len == 0) {
				EXAMPLE_ERR("Error: Incorrect packet count.\n");
				usage(argv[0]);
				return FAILURE;
			}

			i = atoi(optarg);
			if (i < 0) {
				usage(argv[0]);
				return FAILURE;
			}

			/* Creating globals from arguments */
			debug_pkt_cnt = i; /* less than INT_MAX acceptable */
			debug_flag = DEBUG_ON;

			break;

		case 'p':
			packet_dump = DEBUG_ON;

			break;

		case 'h':
			usage(argv[0]);
			/* This is not failure, but using failure path flow */
			return FAILURE;
		default:
			usage(argv[0]);
			return FAILURE;
		}
	}

	if (!args->if_count) {
		/* No interfaces passed to binary */
		printf("Error: Incorrect Interface(s) or Interface not provided.\n");
		usage(argv[0]);
		return FAILURE;
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
	return SUCCESS;
}

/**
 * Extract the number of applicable CPUs and correspondingly maximum worker
 * threads; Also, return the CPU mask and first CPU id.
 */
int
get_cpu_workers(odp_cpumask_t *cpumask, int32_t *cpu)
{
	int num_workers = 0;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];

	/*
	 * By default CPU #0 runs Linux kernel background tasks.
	 * Start mapping thread from CPU #1
	 */
	num_workers = odp_cpumask_default_worker(cpumask, num_workers);
	(void)odp_cpumask_to_str(cpumask, cpumaskstr, sizeof(cpumaskstr));

	EXAMPLE_DBG("Debug: num worker threads: %i\n", num_workers);
	EXAMPLE_DBG("Debug: first CPU:          %i\n", \
			odp_cpumask_first(cpumask));
	EXAMPLE_DBG("Debug: cpu mask:           %s\n", cpumaskstr);

	*cpu = odp_cpumask_first(cpumask);

	return num_workers;
}

/**
 * Initializing the ODP context (Global and Local)
 */
void
initialize_odp(void)
{
	odp_instance_t instance;
	/* Initializing the Global context for ODP */
	if (odp_init_global(&instance, NULL, NULL)) {
		EXAMPLE_ABORT("Error: ODP global initialization failed.\n");
	}

	/* Initializing the Local Context for the main process context */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		odp_term_global(instance);	/* Ignore error in this */
		EXAMPLE_ABORT("Error: ODP local initialization failed.\n");
	}
}

/**
 * De-initializing the ODP context (Local and Global)
 */
void
finish_odp(void)
{
	odp_instance_t instance = 0xdeadbeef;
	/* Deinitializing ODP from caller's context */
	if (odp_term_local()) {
		EXAMPLE_ERR("Error: ODP Local cleanup failed.\n");
		/* XXX No Error pause; Continue to Global de-init */
	}

	if (odp_term_global(instance)) {
		EXAMPLE_ERR("Error: ODP Global Cleanup failed.\n:");
		/* XXX No Error pause; Continue to caller */
	}
}

/**
 * Packet pool for ODP interface
 */
int
create_pool(void)
{
	int err_flag = SUCCESS;
	odp_pool_param_t params;

	/* Creating a packet pool for network interfaces */
	memset(&params, 0, sizeof(params));
	params.type        = ODP_POOL_PACKET;
	params.pkt.seg_len = KNID_PKTIO_PKT_SIZE;
	params.pkt.len     = KNID_PKTIO_PKT_SIZE;
	params.pkt.num     = KNID_PKTIO_NUM_PKT;

	packet_pool = odp_pool_create("packet_pool", &params);
	if (ODP_POOL_INVALID == packet_pool) {
		EXAMPLE_ERR("Error: Packet pool creation for dpni failed.\n");
		err_flag = FAILURE;
		goto out;
	}

	if (debug_flag)
		odp_pool_print(packet_pool);

	EXAMPLE_DBG("Debug: Successfully Created Packet Pool for "\
			"Pktio device.\n");
out:
	return err_flag;
}

/**
 * Destroying the kni device array by releasing the memory allocated for it.
 * This routine assumes that knidev_array was memset before being filled in
 */
void
destroy_knidev_array(void)
{
	int i = 0;
	odpfsl_knidev_t kdev_p;
	odp_pktio_t pktio;

	while (i < eth_dev_cnt) {
		kdev_p = knidev_array[i];
		if (odpfsl_knidev_check_valid(kdev_p)) {
			/* Closing the pktio device associated with
			 * this KNI device
			 */
			pktio = odpfsl_knidev_get_pktio(kdev_p);
			if (pktio != ODP_PKTIO_INVALID)
				odp_pktio_stop(pktio);

			/* Releasing the KNI device */
			odpfsl_knidev_free(kdev_p);
		}
		knidev_array[i++] = NULL;
	}
}

/**
 * Function for initializing and filling-in the Kni device array.
 */
int32_t
initialize_knidev_array(args_t *args)
{
	int i;
	int ret = SUCCESS;

	odpfsl_knidev_t kdev_p;
	odp_pktio_t pktio;
	odpfsl_knidev_ops_t kdev_ops;
	odp_pktio_param_t pktio_params;

	memset(knidev_array, 0, sizeof(knidev_array));
	memset(&kdev_ops, 0, sizeof(odpfsl_knidev_ops_t));
	memset(&pktio_params, 0, sizeof(odp_pktio_param_t));

	for (i = 0; i < KNID_MAX_THREADS; i++) {
		knidev_array[i] = odpfsl_knidev_alloc(i);
		if (NULL == knidev_array[i]) {
			/* Unable to allocate enough space for device array */
			EXAMPLE_ERR("Error: Unable to allocate space for"\
				" devices.\n");
			eth_dev_cnt = i - 1;
			destroy_knidev_array();
			return FAILURE;
		}
	}

	/* Filling up the odpfsl_knidev_operations structure for callbacks
	 * If this is not passed to odpfsl_knidev_open, default operations
	 * defined in odpfsl_kni_api would be used
	 */
	kdev_ops.change_mtu = kni_change_mtu;
	kdev_ops.config_network_if = kni_config_network_interface;
	kdev_ops.config_mac_address = kni_config_mac_address;
	kdev_ops.config_promiscusity = kni_config_promiscusity;

	/* Pktio recv associated with this application is of poll type
	 * Pktio send is of direct output
	 */
	pktio_params.in_mode = ODP_PKTIN_MODE_DIRECT;
	pktio_params.out_mode = ODP_PKTOUT_MODE_DIRECT;

	eth_dev_cnt = 0; /* XXX Unnecessary; already global */

	for (i = 0; i < args->if_count; i++) {
		kdev_p = knidev_array[i];

		/* Creating a Packet IO device */
		pktio = odp_pktio_open(args->if_names[i], packet_pool,\
					 &pktio_params);
		if (ODP_PKTIO_INVALID == pktio) {
			EXAMPLE_ERR("Error: Unable to allocate ODP Pktio"\
				" device for port: %d, interface:%s.\n", \
				i, args->if_names[i]);
			ret = FAILURE;
			break;
		}

		if (odp_pktin_queue_config(pktio, NULL))
			EXAMPLE_ABORT("Error: pktin config failed for pktio\n");

		/* Allocating KNI dev */
		ret = odpfsl_knidev_open(kdev_p, i, pktio, &kdev_ops, NULL);
		if (SUCCESS != ret) {
			EXAMPLE_ERR("Error, Unable to create kni device "\
				"for port:%d.\n", i);
			pktio = ODP_PKTIO_INVALID;
			ret = FAILURE;
			break;
		}

		/* Starting the Packet IO device */
		ret = odp_pktio_start(pktio);
		if (ret != 0) {
			EXAMPLE_ERR("Error: Unable to start Pktio device.\n");
			pktio = ODP_PKTIO_INVALID;
			ret = FAILURE;
			break;
		}

		eth_dev_cnt++;
	}

	if (ret != SUCCESS)
		destroy_knidev_array();

	return ret;
}

/**
 * Core I/O performing thread
 */
static void *
perform_io_thread(void *arg)
{
	int32_t i = 0, ret;
	uint32_t pkt_rcvd = 0, pktin = 0, pktout = 0, t_pkt_count = 0;
	uint32_t ports_mask = 0xff;

	struct timespec t_sleep;

	if (NULL == arg) {
		/* Wrong invocation of the pthread */
		EXAMPLE_ERR("Error: Wrong invocation of thread.\n");
		pthread_exit(NULL);
	}

	EXAMPLE_DBG("Debug: Thread for IO initiated.\n");

	memset(&t_sleep, 0, sizeof(t_sleep));
	t_sleep.tv_nsec = 1000000; /* Millisecond sleep */

	/* XXX Signal handling is already being done in odp_dpaa2_init_global*/

	while (1) {
		pkt_rcvd = 0;

		/* process all interfaces for packet */
		for (i = 0; i < eth_dev_cnt; i++) {
			if (!(ports_mask & (1 << i)))
				continue;
			ret = handle_ingress_packets(knidev_array[i],\
					&pktin);
			if (ret != SUCCESS) {
				EXAMPLE_ERR("Error: Unable to RX packets "\
					"from interface.\n");
				break;
			}
			ret = handle_egress_packets(knidev_array[i],\
					&pktout);
			if (ret != SUCCESS) {
				EXAMPLE_ERR("Error: Unable to TX packets "\
					"to interface.\n");
				break;
			}
			if (pktin || pktout) {
				pkt_rcvd = 1;
				t_pkt_count += (pktin + pktout);
			}
		}
		if (pkt_rcvd == 0)
			nanosleep(&t_sleep, NULL);	/* No error checking */

		/* Debugging output, if the debug flags have been set */
		if (debug_flag && t_pkt_count >= debug_pkt_cnt) {
			kni_dump_interface_stats();
			t_pkt_count = 0;
		}
	}

	return NULL;
}

/**
 * Main routine
 */
int
main(int argc, char **argv)
{
	int i;
	int ret = 0;
	int err_flag = SUCCESS;
	int32_t num_workers = 0;
	int32_t cpu;
	odph_linux_pthread_t thread_tbl[MAX_WORKER_THREADS];
	odp_cpumask_t cpumask, l_cpumask;
	odpfsl_kni_config_t kconfig;
	packet_pool = ODP_POOL_INVALID;
	args_t *args;
	thread_args_t t_data[MAX_WORKER_THREADS];
	odph_linux_thr_params_t thr_params[MAX_WORKER_THREADS];

	/* Handling command line arguments */
	args = calloc(1, sizeof(args_t));
	if (!args) {
		EXAMPLE_ABORT("Error: Failed to allocate memory for args.\n");
	}
	/* Parsing and storing the arguments */
	ret = parse_cmdline_args(argc, argv, args);
	if (ret != SUCCESS) {
		free(args);
		EXAMPLE_ABORT("Error: Commandline argument parsing not successful.\n");
	}

	EXAMPLE_DBG("Debug: Initializing ODP (Global and Local Init).\n");
	initialize_odp();

	EXAMPLE_DBG("Debug: Creating Packet Pool for Pktio Devices.\n");
	ret = create_pool();
	if (ret != SUCCESS) {
		err_flag = FAILURE;
		goto cleanup;
	}

	memset(&kconfig, 0, sizeof(kconfig));
	kconfig.mbuf_size = KNI_PKTMBUF_SIZE;
	kconfig.mbuf_count = KNI_PKTMBUF_NUM;
	kconfig.max_packet_size = KNI_MAX_PKT_SIZE;
	kconfig.max_packet_poll = KNI_MAX_PKT_POLL;
	kconfig.default_core_id = KNI_DEFAULT_CORE_ID;

	/* Initializing KNI */
	ret = odpfsl_kni_init(&kconfig);
	if (ret != SUCCESS) {
		EXAMPLE_ERR("Error: Unable to initialize KNI.\n");
		err_flag = FAILURE;
		goto cleanup;
	}
	EXAMPLE_DBG("Debug: Initialized KNI.Device(s)\n");

	/* Once global and local initialization is done, initializing the ncs
	 * array for kni init
	 */
	ret = initialize_knidev_array(args);
	if (ret != SUCCESS) {
		err_flag = FAILURE;
		EXAMPLE_ERR("Error: Unable to instantiate KNI device array.\n");
		goto cleanup;
	}
	EXAMPLE_DBG("Debug: Initialized KNI devices.\n");

	/* Else, simply reset the thread_tbl */
	memset(thread_tbl, 0, sizeof(thread_tbl));
	memset(t_data, 0, sizeof(t_data));

	/* Fetching number of CPU for valid number of workers */
	/* XXX: Even though KNI Demo has been designed for multi-threaded, it
	 * currently works only as a single threaded application; This
	 * limitation is derived from KNI kernel thread.
	 */
	num_workers = get_cpu_workers(&cpumask, &cpu);
	if (num_workers <= 0) {
		/* Error case; At least one CPU/Worker should be available */
		EXAMPLE_ERR("Error: No CPU or Worker context available.\n");
		err_flag = FAILURE;
		goto cleanup;
	}
	num_workers = 1; /* XXX: Hard coded value for limiting thread count */

	memset(thr_params, 0, (sizeof(odph_linux_thr_params_t) * MAX_WORKER_THREADS));
	/* Create the thread */
	for (i = 0; i < num_workers; i++) {
		odp_cpumask_zero(&l_cpumask);
		odp_cpumask_set(&l_cpumask, cpu);

		t_data[i].dev_idx = i; /* Can be used as knidev_array index */
		EXAMPLE_DBG("Debug: Spawning I/O Thread for Port:%d.\n", \
			t_data[i].dev_idx);
		thr_params[i].thr_type = ODP_THREAD_WORKER;
		thr_params[i].start = perform_io_thread;
		thr_params[i].arg   = &t_data[i];
		odph_linux_pthread_create(&thread_tbl[i], &l_cpumask, \
					  &thr_params[i]);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	/* Wait for all thread instances to complete */
	odph_linux_pthread_join(thread_tbl, num_workers);
	err_flag = SUCCESS;

cleanup:
	EXAMPLE_DBG("Debug: Cleanup of application initiated.\n");
	/* Terminate/cleanup the pools created */
	if (ODP_POOL_INVALID != packet_pool)
		odp_pool_destroy(packet_pool);

	destroy_knidev_array();
	odpfsl_kni_fini();

	/* Cleaning up memory allocated for command line arguments */
	if (args && args->if_str)
		free(args->if_str);

	if (args && args->if_names)
		free(args->if_names);

	if (args)
		free(args);

	/* Finishing ODP */
	finish_odp(); /* Handling error by this is irrelevant */

	return err_flag;

} /* End of main */

/**
 * Prinf usage information
 */
void usage(char *progname)
{
	printf("\n"
		"Application for KNI Demonstration over OpenDataPlane.\n"
		"\n"
		"Usage: %s OPTIONS\n"
		"  E.g. %s -i eth0,eth1 -d 100\n"
		" In the above example,\n"
		" KNI interface mapping with eth0 and eth1 would be created;\n"
		" Thereafter, any packets received on ethX would be sent to KNIx,\n"
		" and any packets received on KNIx interface would be sent to ethX.\n"
		"\n"
		"Mandatory OPTIONS:\n"
		"  -i, --interface <Eth interfaces> (comma-separated, no spaces)\n"
		"\n"
		"Optional OPTIONS\n"
		"  -d, --debug <pkt count>  For printing debugging information\n"
		"                  after every <pkt count> packets have been \n"
		"                  transacted.\n"
		"                  <pkt_count> value is [0,INT_MAX]\n"
		"  -p, --packetdump   For Dumping packet contents of all packets\n"
		"                     transacted\n"
		"  -h, --help      Display help and exit.\n"
		"\n"
		" Mandatory Environment Variables:\n"
		"                  DPRC=<dprc>"
		"\n", NO_PATH(progname), NO_PATH(progname)
	    );
}
