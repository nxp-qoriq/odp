/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file	dpaa2_internal.h
 *
 * @brief	DPAA2 HW system information
 */

#ifndef DPAA2_INTERNAL_H_
#define DPAA2_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <dpaa2.h>


/*!
 * The global DPAA2 configuration structure.
 */
struct dpaa2_config {
	/*!
	 * Pointer to memory configuration, which may be shared across multiple
	 * DPAA2 instances
	 */
	struct dpaa2_mem_config *mem_config;
} __attribute__((__packed__));


/* Convert the timer cycles to the CPU cycles */
#define TIMER_TO_PERF_CYCLES(t_cycle_count)	(t_cycle_count * 64)

/* Get the timer counter */
static inline uint64_t read_cntvct(void)
{
	uint64_t ret, ret_new;
	int timeout = 10;
	/* uint64_t ret_new, timeout = 200; */
	asm volatile ("mrs %0, cntvct_el0" : "=r" (ret));
	/* ERR008585 */
	asm volatile ("mrs %0, cntvct_el0" : "=r" (ret_new));
	while (ret != ret_new && timeout--) {
		ret = ret_new;
		asm volatile ("mrs %0, cntvct_el0" : "=r" (ret_new));
	}
	if (!timeout && (ret != ret_new))
		printf("BUG IN getting CPU counters\n");

	return ret;
}

/*!
 * Get the global configuration structure.
 *
 * @returns
 *   A pointer to the global configuration structure.
 */
struct dpaa2_config *dpaa2_eal_get_configuration(void);

struct dpaa2_mem_config *dpaa2_get_mem_config(void);

int32_t dpaa2_platform_init(struct dpaa2_init_cfg *cfg);
void dpaa2_platform_exit(void);
void dpaa2_dump_platform_device(void *dev);

int32_t dpaa2_io_portal_init(void);
int32_t dpaa2_io_portal_exit(void);

int dpaa2_notif_init(void);
void dpaa2_notif_close(void);

int dpaa2_eal_memory_init(struct dpaa2_init_cfg *cfg);
int dpaa2_eal_memory_exit(void);
int dpaa2_eal_has_hugepages(void);
int dpaa2_eal_hugepage_exit(void);

int dpaa2_shm_init_global(void);
int dpaa2_shm_init_local(void);

int dpaa2_timer_init_global(void);

extern int dpaa2_vlog(uint32_t level, uint32_t logtype,
	const char *format, va_list ap);

/*!
 * Init early logs
 *
 * This function is private to DPAA2
 *
 * @return
 *   0 on success, negative on error
 */
int dpaa2_eal_log_early_init(void);

/*!
 * Init the default log stream
 *
 * This function is private to DPAA2
 *
 * @return
 *   0 on success, negative on error
 */
int dpaa2_eal_log_init(struct dpaa2_init_cfg *cfg, const char *id, int facility);
int dpaa2_eal_log_exit(void);

int dpaa2_openearlylog_stream(FILE *f);

/*!
 * called by environment-specific log init function to initialize log
 * history
 */
int dpaa2_eal_common_log_init(struct dpaa2_init_cfg *cfg);
int dpaa2_eal_common_log_exit(void);

/*!
 * Add a log message to the history.
 *
 * This function can be called from a user-defined log stream. It adds
 * the given message in the history that can be dumped using
 * dpaa2_log_dump_history().
 *
 * @param buf
 *   A data buffer containing the message to be saved in the history.
 * @param size
 *   The length of the data buffer.
 * @return
 *   - 0: Success.
 *   - (-ENOBUFS) if there is no room to store the message.
 */
int dpaa2_log_add_in_history(const char *buf, size_t size);

/*!
 * @details Initialize the memzone subsystem (private to eal).
 *
 * @returns
 *   - 0 on success
 *   - Negative on error
 */
int dpaa2_eal_memzone_init(void);

int dpaa2_memzone_exit(void);
/*!
 * @details Allocate a pool channel and update its channel
 *		ID to ch_id.
 *
 * @param[in,out] Pointer to channel id which will be updated by
 *		API if a channel is allocated succesfully.
 *
 * @returns
 *   - DPAA2_SUCCESS on success
 *   - DPAA2_FAILURE on failure i.e. failure to allocate a channel or
 *	NULL ch_id pointer is passed etc.
 */
extern int dpaa2_alloc_pool_channel(uint32_t *ch_id);

/*!
 * @details De-allocate a pool channel
 *
 * @param[in] Pointer to channel id which is to be de-allocated
 *
 */
extern void dpaa2_free_pool_channel(uint32_t ch_id);

#ifndef DPAA2_MBUF_MALLOC
extern int32_t dpaa2_mbuf_shell_mpool_init(uint32_t num_global_blocks);
extern int32_t dpaa2_mbuf_shell_mpool_exit(void);
#endif

void *get_mc_portal(uint32_t idx);

enum dpaa2_dev_type mc_to_dpaa2_dev_type(const char *dev_name);

void destroy_dmamap(void);

int eal_parse_sysfs_value(const char *filename, unsigned long *val);

void dpaa2_print_system_info(void);

#ifdef __cplusplus
}
#endif

#endif
