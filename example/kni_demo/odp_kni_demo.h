/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file odp_kni_demo.h
 *
 * @brief ODP-KNI interfacing for packet transaction
 */

/*********************************************************************
			Header inclusion
**********************************************************************/
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <example_debug.h>

#include <odp_api.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>

#include <odp/api/plat/kni/odpfsl_kni_api.h>

/*********************************************************************
			Structure Definitions
**********************************************************************/
/**
 * @brief Parsed command line application arguments
 */
typedef struct {
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	char *if_str;		/**< Storage for interface names */
} args_t;

/**
 * @brief Structure to pass along to threads instantiated
 */
typedef struct {
	int8_t	dev_idx;	/* Index of device in device array */
	void *data;			/*XXX Unused: For future, or removal */
} thread_args_t;

/*********************************************************************
			Function declarations
**********************************************************************/
/**
 * @brief Printing Interface statistics on screen
 *
 * The odpfsl_kni_api would record all packet transactions occurring on ODP and
 * KNI interfaces. This function, called in debug mode, would be called after
 * a certain number of packets, configurable through command line parameter
 *
 * @param void
 * @return void
 */
static void kni_dump_interface_stats(void);

/**
 * @brief Printing packet content on screen (DEBUG)
 *
 * kni_demo can print the packets transacted between the ODP and KNI Interfaces.
 * This is done only once the '-p' argument is passed on commandline.
 * printing is being done using odp_print_packet() function
 *
 * @see odp_print_packet
 *
 * @param void
 * @return void
 */
static inline void kni_dump_packet(odp_packet_t packets[], int num);

/**
 * @brief Handling ODP->KNI traffic
 *
 * Packets received on ODP interfaces are TX'd to KNI interface
 *
 * @param [in] kdev_p odpfsl_knidev_t type kni device ptr
 * @param [out] pktin number of packets received and successfully sent to KNI
 *
 * @return
 *		0 for SUCCESS
 *		1 for FAILURE
 */
int32_t handle_ingress_packets(odpfsl_knidev_t kdev, \
	unsigned *pktin);

/**
 * @brief Handling KNI->ODP Traffic
 *
 * Packets received on KNI Interface are TX'd to ODP Interface
 *
 * @param [in] kdev_p odpfsl_knidev_t type KNI device ptr
 * @param [out] pktout number of packets received and successfully sent to ODP
 *
 * @return
 *		0 for SUCCESS
 *		1 for FAILURE
 */
int32_t handle_egress_packets(odpfsl_knidev_t kdev, \
	unsigned *pktout);

/**
 * @brief Drop packets which are input after parsing for errors.
 *
 * For the packets received from ODP interface, those which have packet errors
 * are dropped by this routine. Once packets are dropped, the array of packets
 * is adjusted to contain only valid packets. All dropped packets are free'd.
 *
 * @param [in] pkt_tbl  Array of packet
 * @param [in] len      Length of pkt_tbl[]
 *
 * @return Number of packets with no detected error
 */
int32_t drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len);

/**
 * @brief Parsing command line parameters
 *
 * @param [in] argc		argument count
 * @param [in] argv[]	argument vector
 * @param [out] args	argument structure (args_t type)
 *
 * @return
 *     0 for Success
 *    -1 for Failure
 */
int parse_cmdline_args(int argc, char *argv[], args_t *args);

/**
 * @brief Get CPU Count
 *
 * Extract the number of applicable CPUs and correspondingly maximum worker
 * threads; Also, return the CPU mask and first CPU id.
 * Using this information, maximum number of I/O threads to be spawned can
 * extracted
 *
 * @param [out] cpumask	CPU mask
 * @param [out] cpu		First CPU id
 *
 * @return Number of workers (CPU)
 *
 */
int get_cpu_workers(odp_cpumask_t *cpumask, int32_t *cpu);

/**
 * @brief Initializing ODP Context
 *
 * Global and Local context of ODP are initiated in caller's context
 *
 * @param void
 * return void
 */
void initialize_odp(void);

/**
 * @brief De-initializing the ODP Context
 *
 * @param void
 * @return void
 */
void finish_odp(void);

/**
 * @brief Creating Packet Pool
 *
 * The pktio devices created for connecting to underlying hardware (for e.g.
 * DPAA2 DPNIs), require a Packet pool for storing incoming and outgoing packets.
 * This function creates a odp_pool_t type Packet Pool
 *
 * @param void
 * @return
 *     0 for Success
 *    -1 for Failure
 */
int create_pool(void);

/**
 * @brief Initializing and filling-in the Kni device array
 *
 * The Kni_demo works on a array of KNI<=>ODP devices. This function initializes
 * such an array, fills it with appropriate value. It would also call necessary
 * ODP and KNI routines to initialize the device and associate pools with them.
 *
 * @param void
 * @return void
 */
int initialize_knidev_array(args_t *args);

/**
 * @brief De-initialize the KNI device array created
 *
 * Destroying the kni device array by releasing the memory allocated for it.
 * This routine assumes that knidev_array was memset before being filled in
 *
 * @param void
 * @return void
 */
void destroy_knidev_array(void);

/**
 * @brief Print Application Usage
 *
 * @param [in] progname String containing name of application (argv[0])
 * @return void
 */
void usage(char *progname);
