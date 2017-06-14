/* Copyright (c) 2015, Freescale Semiconductor Inc.
 * Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/init.h>
#include <odp_internal.h>
#include <odp/api/debug.h>
#include <odp_debug_internal.h>
#include <odp_packet_dpaa2.h>
#include <odp/api/thread.h>
#include <odp_packet_internal.h>
#include <odp/api/cpu.h>

/* Linux libc standard headers */
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <stdbool.h>
#include <pthread.h>

#include <dpaa2.h>
#include <odp/api/std_types.h>
#include <dpaa2_common.h>
#include <dpaa2_dev.h>
#include <dpaa2_mbuf.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_eth_priv.h>

struct odp_global_data_s odp_global_data;
struct dpaa2_resources dpaa2_res;
/* Global Lock for calling MC FLIB APIs */
odpfsl_dq_schedule_mode_t dq_schedule_mode = ODPFSL_PUSH;

/*TODO after testing signal handler.*/
/*atomic32_t received_sigint = DPAA2_ATOMIC32_INIT(0);*/
int received_sigint;
/*Variable to check ODP intialization*/
static int odp_init = FALSE;
char *vfio_container;

/*===== sigproc =====*/
/**
handles SIGINT signal(When the app is stopped using Ctrl C the IPC is removed)
handles SIGTERM signal(when app process is nicely killed)
handles SIGHUP signal(When the parent telnet connection is broken)

@param	signum	[IN] The received signal.
*/
static void sigproc(int signum, siginfo_t *info ODP_UNUSED, void *ptr ODP_UNUSED)
{
	static volatile sig_atomic_t fatal_error_in_progress;

	/* Since this handler is established for more than one kind of signal,
	it might still get invoked recursively by delivery of some other kind
	of signal.  Use a static variable to keep track of that. */
	if (fatal_error_in_progress)
		raise (signum);
	fatal_error_in_progress = 1;

	if (signum == SIGSEGV)
		printf("\nSegmentation Fault");

	ODP_DBG("\nERR:SIGNAL(%d) is received, and the APP processing is"
			" going to stop\n", signum);


	/*Since it is a process exit handler, for graceful exist from
		the current process, set the handler as default */
	if ((signum == SIGSEGV) || (signum == SIGILL) || (signum == SIGBUS)) {
		signal(signum, SIG_IGN);
		if (raise(signum) != 0) {
			printf("Raising the signal %d", signum);
			return;
		}
	} else if ((signum == SIGINT) && received_sigint == 1) {
		printf("\nCalling the default signal handler\n");
		signal(signum, SIG_DFL);
		if (raise(signum) != 0) {
			printf("Raising the signal %d", signum);
			return;
		}
		printf("\nSignal Handler Finished\n");
	}
	received_sigint = 1;
	if (dq_schedule_mode & ODPFSL_PUSH_INTR)
		dpaa2_write_all_intr_fd();
}

static void catch_signal(int snum, struct sigaction act, struct sigaction tact)
{
	if (sigaction(snum, NULL, &tact) == -1) {
		printf("\nSignal registration failed\n");
		exit(EXIT_FAILURE);
	}
	if (tact.sa_handler != SIG_IGN) {
		if (sigaction(snum, &act, NULL) == -1) {
			printf("\nSignal registration failed\n");
			exit(EXIT_FAILURE);
		}
	}
}

/**
Installing signal handler to handle the Ctrl C and other kill handlers
Please note that this does not handle the SIGKILL or kill -9 and other
ungracefull crashes.
*/
static void install_signal_handler(void)
{
	struct sigaction action, tmpaction;
	/* Asynchronous signals that result in attempted graceful exit */
	/* Set up the structure to specify the new action. */
	sigemptyset(&action.sa_mask);
	action.sa_sigaction = &sigproc;
	action.sa_flags = SA_SIGINFO;
	catch_signal(SIGHUP, action, tmpaction);
	catch_signal(SIGINT, action, tmpaction);
	catch_signal(SIGQUIT, action, tmpaction);
	catch_signal(SIGTERM, action, tmpaction);
	catch_signal(SIGSEGV, action, tmpaction);
	catch_signal(SIGABRT, action, tmpaction);
}

static void __attribute__((destructor(102))) odp_finish(void)
{
	odp_instance_t instance = 0xdeadbeef;
	ODP_DBG("odp_finish\n");
	if (!vfio_container)
		return;
	if (odp_term_global(instance))
		DPAA2_ERR(APP1, "Error: ODP Global term failed.\n");
	/*Clear buffer library*/
	dpaa2_mbuf_finish();
	/* Do cleanup and exit */
	dpaa2_cleanup();
	printf("DPAA2 framework resources deintialized\n");
}

struct dpaa2_dev *odp_get_dpaa2_eth_dev(const char *dev_name)
{
	uint32_t i;

	for (i = 0; i < dpaa2_res.res_cnt.eth_dev_cnt; i++) {
		if (!(strcmp(dpaa2_res.net_dev[i]->dev_string, dev_name)))
			return dpaa2_res.net_dev[i];
	}
	return NULL;
}

struct dpaa2_dev *odp_get_inactive_conc_dev(void)
{
	uint32_t i = 0;

	for (i = 0; i < dpaa2_res.res_cnt.conc_dev_cnt; i++) {
		if (dpaa2_res.conc_dev[i]->state == DEV_INACTIVE)
			return dpaa2_res.conc_dev[i];
	}
	return NULL;
}

int32_t odp_dpaa2_scan_device_list(uint32_t dev_type)
{
	struct dpaa2_dev *dev;
	int32_t dev_found = 0;

	/* Get List of devices assigned to me */
	TAILQ_FOREACH(dev, &device_list, next) {
		if (dev_type != dev->dev_type)
			continue;

		DPAA2_DBG(APP1, "%s being created", dev->dev_string);
		dev_found = 1;
		switch (dev->dev_type) {
		case DPAA2_NIC:
			dpaa2_res.net_dev[dpaa2_res.res_cnt.eth_dev_cnt++] = dev;
			break;
		case DPAA2_CONC:
			dpaa2_res.conc_dev[dpaa2_res.res_cnt.conc_dev_cnt++] =
									dev;
			break;
		case DPAA2_AIOP_CI:
			dpaa2_res.ci_dev[dpaa2_res.res_cnt.ci_dev_cnt++] =
									dev;
			break;
		case DPAA2_SEC:
		case DPAA2_PME:
		case DPAA2_DCE:
		case DPAA2_SW:
		case DPAA2_IO_CNTXT:
			ODP_UNIMPLEMENTED();
			break;
		case DPAA2_MAX_DEV:
			ODP_DBG("Maximum limit reached for device\n");
			break;
		}
	}
	return dev_found;
}

/*
 * Function to initalize all the Ethernet devices.
 */
static int odp_dpaa2_init_global(const odp_platform_init_t *platform_params)
{
	struct dpaa2_init_cfg cfg;

	install_signal_handler();
	memset(&cfg, 0, sizeof(struct dpaa2_init_cfg));
	vfio_container = getenv("DPRC");
	if (vfio_container == NULL) {
		ODP_ERR("\n\nEnviroment varialble DPRC is not set\n\n");
		return -1;
	}

	cfg.vfio_container	= vfio_container;
	if (getenv("APPL_MEM_SIZE"))
		cfg.data_mem_size = (atoi(getenv("APPL_MEM_SIZE")) * 1024 * 1024);
	else if (platform_params && platform_params->data_mem_size)
		cfg.data_mem_size = platform_params->data_mem_size;
	else
		cfg.data_mem_size = 0;
	cfg.buf_mem_size	= 0;
	cfg.log_level		= DPAA2_LOG_WARNING;
	cfg.flags		= DPAA2_SOFTQ_SUPPORT;

	if (dq_schedule_mode & ODPFSL_PUSH_INTR)
		cfg.flags |= DPAA2_ENABLE_INTERRUPTS;

	/* Till now DPAA2 framework is not initialized so that cannot use DPAA2
	 * logging mechanism. DPAA2 logging will be usable after dpaa2_init.
	 */
	printf("\nDPAA2 framework intialization parameters:\n");
	printf("-----------------------------------------\n");
	printf("Resource container	:%s\n", cfg.vfio_container);
	printf("Scheduler Interrupts	:%s\n", (cfg.flags & DPAA2_ENABLE_INTERRUPTS)?
						"Enable":"Disable");

	if (dpaa2_init(&cfg) < 0) {
		ODP_ERR("dpaa2_init failed\n");
		return -1;
	}


	/* Get Total available I/O contexts. We are required atleast 1 I/O
	context*/
	memset(&dpaa2_res, 0, sizeof(struct dpaa2_resources));
	dpaa2_res.res_cnt.io_context_cnt = dpaa2_get_io_context_count();
	if (dpaa2_res.res_cnt.io_context_cnt == 0) {
		ODP_ERR("Not enough Resource to run\n");
		goto dpaa2_failure;
	}

	return DPAA2_SUCCESS;
dpaa2_failure:
	dpaa2_cleanup();
	return DPAA2_FAILURE;
}

/*
 * Function to initialize all the global data, lock variables etc.
 */
static void odp_data_init_global(void)
{
	/* Nothing for Now */
}
/*
 * Function to Free/Reset all the global data, lock variables etc.
 */
static void odp_data_term_global(void)
{
	/* Nothing for Now */
}

int odp_init_global(odp_instance_t *instance,
		const odp_init_t *params,
		const odp_platform_init_t *platform_params)
{
	int intr = 1;

	if (odp_init)
		return 0;

	if (getenv("ODP_SCH_PULL_MODE")) {
		dq_schedule_mode = ODPFSL_PULL;
		ODP_DBG("\n Using Scheduler in SW-PULL mode\n ");
	}

	if (platform_params)
		dq_schedule_mode = platform_params->dq_schedule_mode;

	if(getenv("ODP_SCH_PUSH_INTR"))
		intr = atoi(getenv("ODP_SCH_PUSH_INTR"));

	if (intr) {
		if (dq_schedule_mode & ODPFSL_PUSH) {
			dq_schedule_mode = ODPFSL_PUSH_INTR;
			ODP_DBG("\nUsing Scheduler in SW-PUSH mode with INTERRUPTS\n\n");
		}
	}

	odp_global_data.log_fn = odp_override_log;
	odp_global_data.abort_fn = odp_override_abort;

	if (params != NULL) {
		if (params->log_fn != NULL)
			odp_global_data.log_fn = params->log_fn;
		if (params->abort_fn != NULL)
			odp_global_data.abort_fn = params->abort_fn;
	}

	odp_system_info_init();
	odp_data_init_global();

	if (odp_dpaa2_init_global(platform_params)) {
		ODP_ERR("ODP dpaa2 init failed.\n");
		return -1;
	}

	if (odp_thread_init_global()) {
		ODP_ERR("ODP thread init failed.\n");
		return -1;
	}

	if (odp_pool_init_global()) {
		ODP_ERR("ODP pool init failed.\n");
		return -1;
	}

	if (odp_queue_init_global()) {
		ODP_ERR("ODP queue init failed.\n");
		return -1;
	}

	if (odp_schedule_init_global()) {
		ODP_ERR("ODP schedule init failed.\n");
		return -1;
	}

	if (odp_pktio_init_global()) {
		ODP_ERR("ODP packet io init failed.\n");
		return -1;
	}

	if (odp_timer_init_global()) {
		ODP_ERR("ODP timer init failed.\n");
		return -1;
	}

	if (odp_crypto_init_global()) {
		ODP_ERR("ODP crypto init failed.\n");
		return -1;
	}
	if (odp_classification_init_global()) {
		ODP_ERR("ODP classification init failed.\n");
		return -1;
	}

	if (odpfsl_ci_init_global()) {
		ODP_ERR("ODP CI init failed.\n");
		return -1;
	}

	if (odp_platform_debug_init()) {
		ODP_DBG("ODP Platform debug init failed.\n");
	}

	odp_init = TRUE;

	/* Dummy support for single instance */
	*instance = INSTANCE_ID;

	return 0;
}

int odp_term_global(odp_instance_t instance ODP_UNUSED)
{
	int rc = 0;

	if (!odp_init)
		return rc;

	if (odpfsl_ci_term_global()) {
		ODP_ERR("ODP CI term failed.\n");
		rc = -1;
	}
	if (odp_classification_term_global()) {
		ODP_ERR("ODP classificatio term failed.\n");
		rc = -1;
	}
	if (odp_crypto_term_global()) {
		ODP_ERR("ODP crypto term failed.\n");
		rc = -1;
	}

	if (odp_pktio_term_global()) {
		ODP_ERR("ODP pktio term failed.\n");
		rc = -1;
	}

	if (odp_schedule_term_global()) {
		ODP_ERR("ODP schedule term failed.\n");
		rc = -1;
	}

	if (odp_queue_term_global()) {
		ODP_ERR("ODP queue term failed.\n");
		rc = -1;
	}

	if (odp_pool_term_global()) {
		ODP_ERR("ODP buffer pool term failed.\n");
		rc = -1;
	}

	if (odp_thread_term_global()) {
		ODP_ERR("ODP thread term failed.\n");
		rc = -1;
	}

	odp_data_term_global();
	odp_init = FALSE;

	return rc;
}

int odp_init_local(odp_instance_t instance ODP_UNUSED,
			odp_thread_type_t thr_type)
{
	int ret = 0;
	cpu_set_t cpuset;

	if (odp_thread_init_local(thr_type)) {
		ODP_ERR("ODP thread local init failed.\n");
		return -1;
	}

	/* Affine the threads to CPU. We don't support migrating threads */
	CPU_ZERO(&cpuset);
	CPU_SET(odp_cpu_id(), &cpuset);
	ret = pthread_setaffinity_np(pthread_self(),
			sizeof(cpu_set_t), &cpuset);
	if (ret) {
		ODP_ERR("ODP pthread_setaffinity_np failed.\n");
		return -1;
	}

	ret = dpaa2_thread_affine_io_context(DPAA2_IO_PORTAL_ANY_FREE);
	if (ret) {
		ODP_ERR("dpaa2_thread_affine_io_context failed.\n");
		return -1;
	}

	if (odp_pktio_init_local()) {
		ODP_ERR("ODP pktio local init failed.\n");
		return -1;
	}

	if (odp_schedule_init_local()) {
		ODP_ERR("ODP schedule local init failed.\n");
		return -1;
	}

	return 0;
}

int odp_term_local(void)
{
	int rc = 0;
	int rc_thd = 0;

	if (odp_schedule_term_local()) {
		ODP_ERR("ODP schedule local term failed.\n");
		rc = -1;
	}

	if (odp_pool_term_local()) {
		ODP_ERR("ODP buffer pool local term failed.\n");
		rc = -1;
	}

	dpaa2_thread_deaffine_io_context();

	rc_thd = odp_thread_term_local();
	if (rc_thd < 0) {
		ODP_ERR("ODP thread local term failed.\n");
		rc = -1;
	} else {
		if (!rc)
			rc = rc_thd;
	}

	return rc;
}
