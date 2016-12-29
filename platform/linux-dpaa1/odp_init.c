/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/*ODP generic headers */
#include <odp/api/init.h>
#include <odp_internal.h>
#include <odp/api/debug.h>
#include <odp/api/thread.h>
#include <odp/api/crypto.h>
#include <odp/api/cpu.h>

/* Internal headers */
#include <odp_debug_internal.h>
#include <odp_queue_internal.h>
#include <odp_schedule_internal.h>
#include <configs/odp_config_platform.h>

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

/* FSL headers*/
#include <usdpaa/fsl_usd.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/fsl_bman.h>
#include <usdpaa/of.h>
#include <usdpaa/usdpaa_netcfg.h>
#include <usdpaa/dma_mem.h>

#define ENABLE_CLASSIFICATION 0

static const char __PCD_PATH[] = __stringify(DEF_PCD_PATH);
static const char __CFG_PATH[] = __stringify(DEF_CFG_PATH);
static const char *PCD_PATH = __PCD_PATH;
static const char *CFG_PATH = __CFG_PATH;

struct usdpaa_netcfg_info *netcfg;
uint32_t sdqcr_default;
static uint32_t pchannels[NUM_POOL_CHANNELS];
int received_sigint;
/*Variable to check ODP intialization*/
static int odp_init = FALSE;

struct odp_global_data_s odp_global_data;

uint16_t get_next_rx_channel(void)
{
	static uint32_t pchannel_idx;
	uint16_t ret = pchannels[pchannel_idx];
	pchannel_idx = (pchannel_idx + 1) % NUM_POOL_CHANNELS;
	return ret;
}

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
		raise(signum);
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
			ODP_DBG("Raising the signal %d", signum);
			return;
		}
	} else if ((signum == SIGINT) && received_sigint == 1) {
		ODP_DBG("\nCalling the default signal handler\n");
		signal(signum, SIG_DFL);
		if (raise(signum) != 0) {
			ODP_DBG("Raising the signal %d", signum);
			return;
		}
		ODP_DBG("\nSignal Handler Finished\n");
	}
	received_sigint = 1;
}

static void catch_signal(int snum, struct sigaction act, struct sigaction tact)
{
	if (sigaction(snum, NULL, &tact) == -1) {
		ODP_DBG("\nSignal registration failed\n");
		exit(EXIT_FAILURE);
	}
	if (tact.sa_handler != SIG_IGN) {
		if (sigaction(snum, &act, NULL) == -1) {
			ODP_DBG("\nSignal registration failed\n");
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
	if (!netcfg)
		return;
	ODP_DBG("odp_finish\n");
	odp_term_global(instance);
}

int odp_init_global(odp_instance_t *instance,
		    const odp_init_t *params ODP_UNUSED,
		    const odp_platform_init_t *platform_params)
{
	int i, ret;
	const char *env_cfg, *env_pcd;
	uint64_t dma_map_size = DMA_MAP_SIZE;

	if (odp_init)
		return 0;

	install_signal_handler();
	odp_global_data.log_fn = odp_override_log;
	if (params != NULL && params->log_fn != NULL)
		odp_global_data.log_fn = params->log_fn;

	if (platform_params)
		dma_map_size = platform_params->data_mem_size;

	ret = of_init();
	if (ret) {
		ODP_ERR("ODP : of_init failed.\n");
		return ret;
	}

	env_cfg = getenv(CFG_PATH);
	env_pcd = getenv(PCD_PATH);
	netcfg = usdpaa_netcfg_acquire(env_pcd, env_cfg);
	if (!netcfg) {
		ODP_ERR("ODP : usdpaa_netcfg_acquire failed.\n");
		return -1;
	}

	dma_mem_generic = dma_mem_create(DMA_MAP_FLAG_ALLOC,
					 NULL, dma_map_size);
	if (!dma_mem_generic) {
		ODP_ERR("ODP : dma_mem_create fail.\n");
		return -1;
	}

	ret = bman_global_init();
	if (ret) {
		ODP_ERR("ODP : bman_global_init failed.\n");
		return ret;
	}

	ret = qman_global_init();
	if (ret) {
		ODP_ERR("Sched init: qman_global_init failed.\n");
		return -1;
	}

	ret = qman_alloc_pool_range(&pchannels[0], NUM_POOL_CHANNELS, 1, 0);
	if (ret != NUM_POOL_CHANNELS) {
		ODP_ERR("No pool channels available\n");
		return -1;
	}

	for (i = 0; i < NUM_POOL_CHANNELS; i++)
		sdqcr_default |= QM_SDQCR_CHANNELS_POOL_CONV(pchannels[i]);

	odp_system_info_init();

	if (odp_shm_init_global()) {
		ODP_ERR("ODP shm init failed.\n");
		return -1;
	}

	if (odp_thread_init_global()) {
		ODP_ERR("ODP thread init failed.\n");
		return -1;
	}

	if (odp_pool_init_global()) {
		ODP_ERR("ODP buffer pool init failed.\n");
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

#if ENABLE_CLASSIFICATION
	if (!getenv("APP_RESTART")) {
		if (odp_classification_init_global()) {
			ODP_ERR("ODP classification init failed.\n");
			return -1;
		}
	}
#endif
	odp_init = TRUE;

	/* Dummy support for single instance */
	*instance = INSTANCE_ID;
	return 0;
}

int odp_term_global(odp_instance_t instance)
{
	/* Workaround for App-Restart */
	/* When proper cleanup is done remove if 0 */
#if ENABLE_CLASSIFICATION
	odp_classification_term_global();
#endif
	if (!odp_init)
		return 0;

	odp_pktio_term_global();
	odp_schedule_term_global();
	odp_queue_term_global();
	odp_thread_term_global();

	qman_release_pool_range(pchannels[0], NUM_POOL_CHANNELS);
	usdpaa_netcfg_release(netcfg);
	of_finish();

	odp_init = FALSE;

	return 0;
}

int odp_init_local(odp_instance_t instance, odp_thread_type_t thr_type)
{
	int ret = 0;
	cpu_set_t cpuset;

	if (odp_thread_init_local(thr_type)) {
		ODP_ERR("ODP thread local init failed.\n");
		return -1;
	}

	CPU_ZERO(&cpuset);
	CPU_SET(odp_cpu_id(), &cpuset);
	ret = pthread_setaffinity_np(pthread_self(),
				     sizeof(cpu_set_t), &cpuset);
	if (ret) {
		ODP_ERR("ODP pthread_setaffinity_np failed.\n");
		return -1;
	}

	ret = bman_thread_init();
	if (ret) {
		ODP_ERR("ODP : bman_thread_init failed.\n");
		return -1;
	}

	ret = qman_thread_init();
	if (ret) {
		ODP_ERR("ODP : qman_thread_init failed.\n");
		return -1;
	}

	if (odp_pktio_init_local()) {
		ODP_ERR("ODP pktio local init failed.\n");
		return -1;
	}

	if (odp_schedule_init_local(sdqcr_default)) {
		ODP_ERR("ODP schedule local init failed.\n");
		return -1;
	}

	return 0;
}

int odp_term_local(void)
{
	int i, calm_down = MAX_DEQ;
	ODP_DBG("odp_term_local\n");
	int rc_thd = 0, rc = 0;

	qman_static_dequeue_del(~(u32)0);
	/* reset all the bufs for the current thread*/
	for (i = 0; i < MAX_DEQ; i++) {
		sched_local.buf[i] = ODP_BUFFER_INVALID;
		sched_local.buf_ctx[i] = NULL;
	}

	while (calm_down--) {
		qman_poll_slow();
		qman_poll_dqrr(MAX_DEQ);
	}
	odp_pktio_term_local();
	qman_thread_finish();
	bman_thread_finish();

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
