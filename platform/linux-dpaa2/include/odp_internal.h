/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP HW system information
 */

#ifndef ODP_INTERNAL_H_
#define ODP_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/init.h>
#include <odp/api/thread.h>
#include <odp/api/spinlock.h>

extern __thread int __odp_errno;

#define INSTANCE_ID    0xdeadbeef
#define MAX_CPU_NUMBER 12

typedef struct {
	uint64_t cpu_hz;
	uint64_t huge_page_size;
	uint64_t page_size;
	int      cache_line_size;
	int      cpu_count;
	char     model_str[128];
} odp_system_info_t;

struct odp_global_data_s {
	odp_log_func_t log_fn;
	odp_abort_func_t abort_fn;
	odp_system_info_t system_info;
	odp_cpumask_t control_cpus;
	odp_cpumask_t worker_cpus;
	int num_cpus_installed;
};

enum init_stage {
	NO_INIT = 0,    /* No init stages completed */
	CPUMASK_INIT,
	TIME_INIT,
	SYSINFO_INIT,
	SHM_INIT,
	THREAD_INIT,
	POOL_INIT,
	QUEUE_INIT,
	SCHED_INIT,
	PKTIO_INIT,
	TIMER_INIT,
	CRYPTO_INIT,
	CLASSIFICATION_INIT,
	TRAFFIC_MNGR_INIT,
	NAME_TABLE_INIT,
	ALL_INIT      /* All init stages completed */
};

extern struct odp_global_data_s odp_global_data;

int _odp_term_global(enum init_stage stage);
int _odp_term_local(enum init_stage stage);

int odp_cpumask_init_global(const odp_init_t *params);
int odp_cpumask_term_global(void);

int odp_system_info_init(void);

int odp_thread_init_global(void);
int odp_thread_init_local(odp_thread_type_t type);
int odp_thread_term_local(void);
int odp_thread_term_global(void);

int odp_shm_init_global(void);
int odp_shm_term_global(void);
int odp_shm_init_local(void);

int odp_pool_init_global(void);
int odp_pool_term_global(void);
int odp_pool_term_local(void);

int odp_pktio_init_global(void);
int odp_pktio_term_global(void);
int odp_pktio_init_local(void);

int odp_classification_init_global(void);
int odp_classification_term_global(void);

int odp_queue_init_global(void);
int odp_queue_term_global(void);

int odp_crypto_init_global(void);
int odp_crypto_term_global(void);

int odp_schedule_init_global(void);
int odp_schedule_term_global(void);
int odp_schedule_init_local(void);
int odp_schedule_term_local(void);

int odp_timer_init_global(void);
int odp_timer_disarm_all(void);

int odp_time_init_global(void);
int odp_time_term_global(void);

int odpfsl_ci_init_global(void);
int odpfsl_ci_term_global(void);

void _odp_flush_caches(void);
int odp_platform_debug_init(void);

/*DPAA2 specific Definitions*/

/*******************MACRO*******************/
#define DPAA2_MAX_ETH_DEV        16
#define DPAA2_MAX_CONC_DEV        8
#define DPAA2_MAX_CI_DEV		128

/* Enable QBMan Short Circuit Mode with ISOL CPU for benchmarking purpose */
#define  ODPFSL_DRIVER_LB		0
#define  ODPFSL_MAX_PLATFORM_CORE	8

/************DATA STRUCTURE*******************/
/*
 * Structure to contains available resource count at underlying layers.
 */
struct dpaa2_resource_cnt {
	uint32_t eth_dev_cnt;
	uint32_t conc_dev_cnt;
	uint32_t ci_dev_cnt;
	uint32_t io_context_cnt;
	uint32_t cpu_cnt;
};

/*
 * Structure to contains available resources.
 */
struct dpaa2_resources {
	struct dpaa2_resource_cnt res_cnt;
	struct dpaa2_dev *net_dev[DPAA2_MAX_ETH_DEV];
	struct dpaa2_dev *conc_dev[DPAA2_MAX_CONC_DEV];
	struct dpaa2_dev *ci_dev[DPAA2_MAX_CI_DEV];
};

/************EXTERN DEFINITION*******************/
extern struct dpaa2_resources dpaa2_res;

struct dpaa2_dev *odp_get_inactive_conc_dev(void);

struct dpaa2_dev *odp_get_dpaa2_eth_dev(const char *dev_name);

int32_t odp_dpaa2_scan_device_list(uint32_t dev_type);

#ifdef __cplusplus
}
#endif

#endif
