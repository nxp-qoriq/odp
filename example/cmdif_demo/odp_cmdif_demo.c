/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/* System headers */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <getopt.h>
#include <unistd.h>

/* ODP headers */
#include <odp_api.h>
#include <example_debug.h>
#include <odp/helper/linux.h>
#include <odp/api/plat/cmdif/odpfsl_cidev.h>
#include <odp/api/plat/malloc/odpfsl_data_malloc.h>
#include <odp/api/plat/cmdif/fsl_cmdif_client.h>
#include <odp/api/plat/cmdif/fsl_cmdif_server.h>

/* Application client mode */
#define CMDIF_DEMO_CLIENT_MODE 0x1
/* Application server mode */
#define CMDIF_DEMO_SERVER_MODE 0x2
/* Parsed command line application arguments */
typedef struct {
	int mode;	/**< Application mode - client or server */
} appl_args_t;
/** Global args */
appl_args_t args;

/* CMDIF application specific commands */
#define OPEN_CMD 0x100
#define NORESP_CMD 0x101
#define ASYNC_CMD 0x102
#define SYNC_CMD 0x103
#define IC_TEST 0x106
#define MODULE_NAME "IRA"

/* Maximum number of open commands */
#define MAX_OPEN_CMDS 10

/* Number of times to test the GPP client sync commands */
#define CMDIF_CLIENT_SYNC_NUM 100
/* Number of times to test the GPP server async commands */
#define CMDIF_SERVER_ASYNC_NUM 10

/* Buffer and packet related macros */
#define CMDIF_BUF_NUM 64
#define CMDIF_BUF_SIZE 512
#define CMDIF_DATA_SIZE 64

/* Additional space required for async commands */
#define CMDIF_ASYNC_OVERHEAD 16
/* Maximum number of tries for receiving the async response */
#define CMDIF_DEMO_NUM_TRIES 100
/* Wait before each try (in milli-secconds) */
#define CMDIF_DEMO_ASYNC_WAIT 100

struct cmdif_desc cidesc[MAX_OPEN_CMDS];
/* Global pointers to store the CI device handle */
void *client_cidev;
void *server_cidev;

void *open_cmd_mem[MAX_OPEN_CMDS];
static odp_pool_t cmdif_memory_pool = ODP_POOL_INVALID;
static odp_pool_t cmdif_packet_pool = ODP_POOL_INVALID;

odp_buffer_t old_buf;
int async_count1;
int async_count2;
uint32_t num_req, num_reply;

/* Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))

/* Prin usage information */
static void usage(char *progname)
{
	printf("\n*********************************************");
	printf("\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -c -s\n"
	       "\n"
	       "OpenDataPlane example application.\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -c, --client         Client mode.\n"
	       "  -s, --server         Server mode.\n"
	       "  -h, --help           Display help and exit.\n",
	       NO_PATH(progname), NO_PATH(progname)
	    );
	printf("*********************************************\n");
}

/*
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static inline void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt, long_index;
	static struct option longopts[] = {
		{"client", no_argument, NULL, 'c'},
		{"server", no_argument, NULL, 's'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};

	appl_args->mode = 0;
	while (1) {
		opt = getopt_long(argc, argv, "+csh", longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->mode |= CMDIF_DEMO_CLIENT_MODE;
			break;
		case 's':
			appl_args->mode |= CMDIF_DEMO_SERVER_MODE;
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	if (appl_args->mode == 0)
		appl_args->mode =
			CMDIF_DEMO_CLIENT_MODE | CMDIF_DEMO_SERVER_MODE;

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

static int open_for_cmdif(uint64_t ind)
{
	uint8_t *data;
	int ret = 0;

	data = odpfsl_data_malloc(NULL, CMDIF_OPEN_SIZE, 0);
	if (!data) {
		EXAMPLE_ERR("Unable to get the memory\n");
		return -ENOMEM;
	}

	/* cidesc->regs is required to be set to ODP device */
	cidesc[ind].regs = (void *)client_cidev;
	ret = cmdif_open(&cidesc[ind], "TEST0", 0, data,
		CMDIF_OPEN_SIZE);
	if (ret != 0) {
		EXAMPLE_ERR("cmdif_open failed\n");
		odpfsl_data_free(data);
		return ret;
	}

	open_cmd_mem[ind] = data;
	return 0;
}

static int close_for_cmdif(int ind)
{
	int ret;

	ret = cmdif_close(&cidesc[ind]);
	if (ret)
		EXAMPLE_ERR("cmdif_close_failed\n");

	odpfsl_data_free(open_cmd_mem[ind]);
	return ret;
}

static int async_cb1(void *async_ctx ODP_UNUSED, int err,
		uint16_t cmd_id ODP_UNUSED,
		uint32_t size, void *data)
{
	uint32_t j;
	uint8_t *v_data = (uint8_t *)(data);

	if (err != 0) {
		EXAMPLE_ERR("ERROR inside async_cb\n");
		return err;
	}

	/* Check for modified data from the AIOP server */
	for (j = 0; j < size; j++) {
		if ((v_data)[j] != 0xDA) {
			EXAMPLE_ERR("Invalid data from AIOP!!!\n");
			return 0;
		}
	}

	async_count1++;
	return 0;
}

static int async_cb2(void *async_ctx ODP_UNUSED, int err,
		uint16_t cmd_id ODP_UNUSED,
		uint32_t size, void *data)
{
	uint32_t j;
	uint8_t *v_data = (uint8_t *)(data);

	if (err != 0) {
		EXAMPLE_ERR("ERROR inside async_cb\n");
		return err;
	}

	/* Check for modified data from the AIOP server */
	for (j = 0; j < size; j++) {
		if ((v_data)[j] != 0xDA) {
			EXAMPLE_ERR("Invalid data from AIOP!!!\n");
			return 0;
		}
	}

	async_count2++;
	return 0;
}

static void *cmdif_client_io_thread(void *thread_args ODP_UNUSED)
{
	odp_buffer_t data_buf;
	uint8_t *data;
	int ret, thr, t;
	int ret1 = -1, ret2 = -1;
	uint8_t i, j;

	/* Calling this API is must to do thread specific initialization */
	thr = odp_thread_id();

	printf("\n*******************************************\n");
	printf("[%d] Started thread %s\n", thr, __func__);

	printf("Executing open commands\n");
	ret = open_for_cmdif(0);
	if (ret) {
		EXAMPLE_ERR("Open for cmdif failed\n");
		return NULL;
	}

	ret = open_for_cmdif(1);
	if (ret) {
		EXAMPLE_ERR("Open for cmdif failed\n");
		return NULL;
	}
	printf("PASSED open commands\n");

	/* Get a memory block */
	/* NOTE: Here we are using the same memory and same data_buf,
	* but separate memory can also be used i.e. odp_buffer_alloc
	* can be done in the below 'for' loop */
	data_buf = odp_buffer_alloc(cmdif_memory_pool);
	if (odp_unlikely(ODP_BUFFER_INVALID == data_buf)) {
		EXAMPLE_ERR("Buffer allocation failure\n");
		return NULL;
	}
	data = odp_buffer_addr(data_buf);

	printf("Executing sync commands\n");
	for (i = 0; i < CMDIF_CLIENT_SYNC_NUM; i++) {
		for (j = 0; j < CMDIF_DATA_SIZE; j++)
			data[j] = i + j;
		ret = cmdif_send(&cidesc[0], i, /* cmd_id */
				CMDIF_DATA_SIZE, /* size */
				(i & 1), /* priority */
				(uint64_t)(data) /* data */,
				NULL, 0);
		if (ret)
			EXAMPLE_ERR("FAILED sync_send %d\n", i);
	}
	printf("PASSED synchronous send commands\n");

	printf("Executing async commands\n");
	for (i = 0; i < 1; i++) {
		t = 0;
		for (j = 0; j < CMDIF_DATA_SIZE; j++)
			data[j] = i + j;
		/* Multiple sends can be done without calling cmdif_resp_read */
		ret = cmdif_send(&cidesc[0], (i | CMDIF_ASYNC_CMD), /*cmd_id*/
				CMDIF_DATA_SIZE + CMDIF_ASYNC_OVERHEAD, /*size*/
				(i & 1), /* priority */
				(uint64_t)(data) /* data */,
				async_cb1, /*async_cb */
				0); /* async_ctx */
		if (ret)
			EXAMPLE_ERR("FAILED async_send %d\n", i);

		/* Now read the response */
		while (!async_count1 && (t < CMDIF_DEMO_NUM_TRIES)) {
			odpfsl_msleep(CMDIF_DEMO_ASYNC_WAIT);
			ret = cmdif_resp_read(&cidesc[0], (i & 1));
			if (ret)
				EXAMPLE_ERR("FAILED cmdif_resp_read %d\n", i);
			t++;
		}
		if (!async_count1)
			EXAMPLE_ERR("FAILED: asynchronous command\n");
	}

	for (i = 0; i < 1; i++) {
		t = 0;
		for (j = 0; j < CMDIF_DATA_SIZE; j++)
			data[j] = i + j;
		/* Multiple sends can be done without calling cmdif_resp_read */
		ret = cmdif_send(&cidesc[1], (i | CMDIF_ASYNC_CMD), /*cmd_id*/
				CMDIF_DATA_SIZE + CMDIF_ASYNC_OVERHEAD, /*size*/
				(i & 1), /* priority */
				(uint64_t)(data) /* data */,
				async_cb2, /*async_cb */
				0); /* async_ctx */
		if (ret)
			EXAMPLE_ERR("FAILED async_send %d\n", i);

		/* Now read the response */
		while (!async_count2 && (t < CMDIF_DEMO_NUM_TRIES)) {
			odpfsl_msleep(CMDIF_DEMO_ASYNC_WAIT);
			ret = cmdif_resp_read(&cidesc[1], (i & 1));
			if (ret)
				EXAMPLE_ERR("FAILED cmdif_resp_read %d\n", i);
			t++;
		}
		if (!async_count2)
			EXAMPLE_ERR("FAILED: asynchronous command\n");
	}

	if (async_count1 && async_count2)
		printf("PASSED asynchronous send/receive commands\n");

	/* Clean-up */
	odp_buffer_free(data_buf);

	printf("Executing close commands\n");
	ret1 = close_for_cmdif(1);
	if (ret1 != 0)
		EXAMPLE_ERR("FAILED: Close command\n");

	ret2 = close_for_cmdif(0);
	if (ret2 != 0)
		EXAMPLE_ERR("FAILED: Close command\n");

	if (ret1 == 0 && ret2 == 0)
		printf("PASSED: close commands\n");

	printf("Exiting thread %s\n", __func__);
	printf("*******************************************\n");
	pthread_exit(NULL);
}

static int open_cb(uint8_t instance_id ODP_UNUSED,
		void **dev ODP_UNUSED)
{
	return 0;
}

static int close_cb(void *dev ODP_UNUSED)
{
	return 0;
}

static int ctrl_cb(void *dev ODP_UNUSED, uint16_t cmd ODP_UNUSED,
		uint32_t size, void *data)
{
	num_reply++;

	if (old_buf)
		odp_buffer_free(old_buf);
	memset((uint8_t *)data, 0x01, size);

	/* AIOP demo application has incremented the data by 'size'
	 * provided in the async command trigger (GPP->AIOP in cmdif_send())
	 * from the one we provided */
	old_buf = odpfsl_buffer_from_addr(data - CMDIF_DATA_SIZE);

	return 0;
}

static struct cmdif_module_ops ops = {
			       .open_cb = open_cb,
			       .close_cb = close_cb,
			       .ctrl_cb = ctrl_cb
};

static void *cmdif_server_io_thread(void *thread_args ODP_UNUSED)
{
	uint8_t *data, *session_data;
	odp_buffer_t data_buf;
	odp_packet_t pkt_buf;
	uint16_t auth_id = 0;
	int ret, i, thr, t = 0;

	/* Calling this API is must to do thread specific initialization */
	thr = odp_thread_id();

	printf("\n*******************************************\n");
	printf("[%d] Started thread %s\n", thr, __func__);

	ret = open_for_cmdif(0);
	if (ret) {
		EXAMPLE_ERR("Open for cmdif failed\n");
		return NULL;
	}

	printf("Registering the module...\n");
	ret = cmdif_register_module(MODULE_NAME, &ops);
	if (ret) {
		EXAMPLE_ERR("Server registration failed\n");
		return NULL;
	}

	/* Get a memory block */
	session_data = odpfsl_data_malloc(NULL, CMDIF_SESSION_OPEN_SIZE, 0);
	if (!session_data) {
		EXAMPLE_ERR("Unable to get the memory\n");
		return NULL;
	}

	ret = cmdif_session_open(&cidesc[0], MODULE_NAME, 0, 50, session_data,
		server_cidev, &auth_id);
	if (ret) {
		EXAMPLE_ERR("FAILED cmdif session open\n");
		return NULL;
	}

	printf("PASSED cmdif session open\n");

	data_buf = odp_buffer_alloc(cmdif_memory_pool);
	if (odp_unlikely(ODP_BUFFER_INVALID == data_buf)) {
		EXAMPLE_ERR("Buffer allocation failure\n");
		return NULL;
	}
	data = odp_buffer_addr(data_buf);

	/* Trigger open for AIOP client */
	/* Pass the device ID while triggerring the open.
	 * This is required by the AIOP client */
	data[0] = (uint8_t)(odpfsl_cidev_internal_id(server_cidev));
	ret = cmdif_send(&cidesc[0], OPEN_CMD, CMDIF_DATA_SIZE,
		CMDIF_PRI_LOW, (uint64_t)data, NULL, 0);
	if (ret)
		EXAMPLE_ERR("FAILED open on client\n");

	/* Reusing the previous buffer */
	memset((uint8_t *)data, 0, CMDIF_BUF_SIZE);

	printf("Triggering commands on AIOP client\n");
	ret = cmdif_send(&cidesc[0], NORESP_CMD, CMDIF_DATA_SIZE,
		CMDIF_PRI_LOW, (uint64_t)(data), NULL, 0);
	num_req++;
	if (ret) {
		EXAMPLE_ERR("FAILED to send no resp cmd on client\n");
	} else {
		ret = -1;
		while (ret != 0 && (t < CMDIF_DEMO_NUM_TRIES)) {
			odpfsl_msleep(CMDIF_DEMO_ASYNC_WAIT);
			ret = cmdif_srv_cb(CMDIF_PRI_LOW, server_cidev);
			t++;
		}
		if (ret != 0)
			printf("FAILED cmdif_srv_cb\n");
	}

	ret = cmdif_send(&cidesc[0], (SYNC_CMD | CMDIF_NORESP_CMD), 0,
		CMDIF_PRI_LOW, 0, NULL, 0);
	if (ret)
		EXAMPLE_ERR("FAILED sync command\n");
	else
		printf("PASSED sync command\n");

	printf("Activate cmdif_cl_isr() on AIOP\n");
	for (i = 0; i < CMDIF_SERVER_ASYNC_NUM; i++) {
		t = 0;
		data_buf = odp_buffer_alloc(cmdif_memory_pool);
		if (odp_unlikely(ODP_BUFFER_INVALID == data_buf)) {
			EXAMPLE_ERR("Buffer allocation failure\n");
			return NULL;
		}
		data = odp_buffer_addr(data_buf);
		memset((uint8_t *)data, 0, CMDIF_BUF_SIZE);

		/* Here we are allocating and passing the data
		 * using mempool. This data is used by the AIOP in the
		 * AIOP->GPP communication to pass the data. Buffer pool
		 * can be used for this communication and there will be no
		 * requirement of passing this data here */
		ret = cmdif_send(&cidesc[0], ASYNC_CMD, CMDIF_DATA_SIZE,
			CMDIF_PRI_LOW, (uint64_t)(data), NULL, 0);
		num_req++;
		if (ret) {
			EXAMPLE_ERR("FAILED to send async cmd on client\n");
		} else {
			ret = -1;
			while (ret != 0 && (t < CMDIF_DEMO_NUM_TRIES)) {
				odpfsl_msleep(CMDIF_DEMO_ASYNC_WAIT);
				ret = cmdif_srv_cb(CMDIF_PRI_LOW,
					server_cidev);
				t++;
			}
			if (ret != 0)
				EXAMPLE_ERR("FAILED cmdif_srv_cb\n");
		}
	}

	if  (num_reply != num_req)
		printf("FAILED Async commands\n");
	else
		printf("PASSED Async commands\n");

	odp_buffer_free(old_buf);

	/* Isolation context test */
	pkt_buf = odp_packet_alloc(cmdif_packet_pool, CMDIF_DATA_SIZE);
	if (odp_unlikely(ODP_PACKET_INVALID == pkt_buf)) {
		EXAMPLE_ERR("Buffer allocation failure\n");
		return NULL;
	}
	data = odp_packet_head(pkt_buf);

	data[0] = (uint8_t)(odpfsl_cidev_internal_id(server_cidev));
	/* Assuming BPID will fit into uint8_t */
	data[1] = (uint8_t)(odpfsl_packet_pool_internal_id(cmdif_packet_pool));
	ret = cmdif_send(&cidesc[0], IC_TEST, CMDIF_DATA_SIZE, CMDIF_PRI_LOW,
		(uint64_t)data, NULL, 0);
	if (ret)
		EXAMPLE_ERR("FAILED Isolation context command send\n");

	/* Get the packet buffer back from the address */
	pkt_buf = odpfsl_packet_from_addr(cmdif_packet_pool, data);
	if (pkt_buf)
		odp_packet_free(pkt_buf);
	else
		EXAMPLE_ERR("Unable to fetch and release Packet.\n");

	/* Clean-up */
	printf("Executing session close\n");
	ret = cmdif_session_close(&cidesc[0],  auth_id, 50, session_data,
		server_cidev);
	if (ret)
		EXAMPLE_ERR("FAILED cmdif session close\n");
	else
		printf("PASSED cmdif session close\n");

	odpfsl_data_free(session_data);

	ret = cmdif_unregister_module(MODULE_NAME);
	if (ret)
		EXAMPLE_ERR("Server deregistration failed\n");

	close_for_cmdif(0);

	printf("Exiting thread %s\n", __func__);
	printf("*******************************************\n");
	pthread_exit(NULL);
}

/* The main() function/thread creates the worker threads */
int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl;
	odp_cpumask_t thd_mask;
	odp_pool_param_t params;
	odp_instance_t instance;
	odph_linux_thr_params_t thr_params;

	/* Init ODP before calling anything else */
	if (odp_init_global(&instance, NULL, NULL)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(instance, ODP_THREAD_CONTROL)) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Parse and store the application arguments */
	parse_args(argc, argv, &args);

	/* Get the client and the server device */
	client_cidev = odpfsl_cidev_open();
	server_cidev = odpfsl_cidev_open();

	if (!client_cidev || !server_cidev) {
		printf("Not enough Resource to run\n");
		exit(EXIT_FAILURE);
	}

	/* Create the memory pool */
	odp_pool_param_init(&params);
	params.type = ODP_POOL_BUFFER;
	params.buf.num = CMDIF_BUF_NUM;
	params.buf.size = CMDIF_BUF_SIZE;
	cmdif_memory_pool = odp_pool_create("cmdif_memory_pool", &params);
	if (ODP_POOL_INVALID == cmdif_memory_pool) {
		EXAMPLE_ERR("Error: cmdif_memory_pool creation failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Create the buffer pool */
	odp_pool_param_init(&params);
	params.type = ODP_POOL_PACKET;
	params.buf.num = CMDIF_BUF_NUM;
	params.buf.size = CMDIF_BUF_SIZE;
	cmdif_packet_pool = odp_pool_create("cmdif_packet_pool", &params);
	if (ODP_POOL_INVALID == cmdif_packet_pool) {
		EXAMPLE_ERR("Error: cmdif_packet_pool creation failed.\n");
		exit(EXIT_FAILURE);
	}

	if (args.mode & CMDIF_DEMO_CLIENT_MODE) {
		/* Create the CMDIF GPP client thread */
		memset(&thread_tbl, 0, sizeof(thread_tbl));
		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, 0);
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.start = cmdif_client_io_thread;
		thr_params.arg   = NULL;
		odph_linux_pthread_create(&thread_tbl, &thd_mask,
								&thr_params);
		/* Wait for the thread to join */
		odph_linux_pthread_join(&thread_tbl, 1);
	}

	if (args.mode & CMDIF_DEMO_SERVER_MODE) {
		memset(&thread_tbl, 0, sizeof(thread_tbl));
		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, 0);
		thr_params.thr_type = ODP_THREAD_WORKER;
		thr_params.start = cmdif_server_io_thread;
		thr_params.arg   = NULL;
		/* Create the CMDIF GPP server thread */
		odph_linux_pthread_create(&thread_tbl, &thd_mask,
								&thr_params);
		/* Wait for the thread to join */
		odph_linux_pthread_join(&thread_tbl, 1);
	}

	printf("Main Finished\n");
	return 0;
}
