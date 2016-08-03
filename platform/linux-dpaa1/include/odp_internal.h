/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
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

#include <odp/api/std_types.h>
#include <odp/api/init.h>
#include <odp/api/thread.h>
#include <odp/api/plat/schedule_types.h>

#define INSTANCE_ID    0xdeadbeef
#define MAX_CPU_NUMBER 12

extern int received_sigint;
extern __thread int __odp_errno;

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
};

extern struct odp_global_data_s odp_global_data;

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
void odp_pktio_term_local(void);

int odp_classification_init_global(void);
int odp_classification_term_global(void);

int odp_queue_init_global(void);
int odp_queue_term_global(void);

int odp_crypto_init_global(void);
int odp_crypto_term_global(void);

int odp_schedule_init_global(void);
int odp_schedule_term_global(void);
int odp_schedule_init_local(uint32_t sdqcr);
int odp_schedule_term_local(void);

int odp_timer_init_global(void);
int odp_timer_disarm_all(void);

int odp_time_init_global(void);
int odp_time_term_global(void);

void _odp_flush_caches(void);
uint16_t get_next_rx_channel(void);
int get_group_channel(odp_schedule_group_t group, uint16_t *pchannel);

uint64_t odp_cpu_hz_current(int id);
#ifdef __cplusplus
}
#endif

#endif
