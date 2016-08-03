/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	dpaa2_core.c
 *
 * @brief	DPAA2 framework Common functionalities.
 *
 */

#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <dpaa2.h>
#include <odp.h>
#include "dpaa2_internal.h"
#include <dpaa2_eth_priv.h>
#include <dpaa2_conc_priv.h>
#include <dpaa2_common.h>
#include <odp/api/atomic.h>
#include <dpaa2_timer.h>

#include <sys/file.h>
#include "eal_internal_cfg.h"
#include "eal_hugepages.h"

#include <dpaa2_aiop_priv.h>
#include <dpaa2_sec_priv.h>
#include <dpaa2_memconfig.h>

#ifndef DPAA2_MBUF_MALLOC
/* @internal Number of buffer to be reserved for DPAA2 Shell mpool */
#define DPAA2_MBUF_SHELL_NUM 1024
#endif

/* internal configuration */
struct internal_config internal_config;

/* early configuration structure, when memory config is not mmapped */
static struct dpaa2_mem_config early_mem_config;

/* Address of global and public configuration */
static struct dpaa2_config sys_config = {
		.mem_config = &early_mem_config,
};

/* Return a pointer to the configuration structure */
struct dpaa2_config *
dpaa2_eal_get_configuration(void)
{
	return &sys_config;
}

/* Return a pointer to the configuration structure */
struct dpaa2_mem_config *dpaa2_get_mem_config(void)
{
	return dpaa2_eal_get_configuration()->mem_config;
}

/* parse a sysfs (or other) file containing one integer value */
int
eal_parse_sysfs_value(const char *filename, unsigned long *val)
{
	FILE *f;
	char buf[BUFSIZ];
	char *end = NULL;

	if ((f = fopen(filename, "r")) == NULL) {
		DPAA2_LOG(ERR, FW, "%s(): cannot open sysfs value %s\n",
			__func__, filename);
		return -1;
	}

	if (fgets(buf, sizeof(buf), f) == NULL) {
		DPAA2_LOG(ERR, FW, "%s(): cannot read sysfs value %s\n",
			__func__, filename);
		fclose(f);
		return -1;
	}
	*val = strtoul(buf, &end, 0);
	if ((buf[0] == '\0') || (end == NULL) || (*end != '\n')) {
		DPAA2_LOG(ERR, FW, "%s(): cannot parse sysfs value %s\n",
				__func__, filename);
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

/* Unlocks hugepage directories that were locked by eal_hugepage_info_init */
static void
eal_hugedirs_unlock(void)
{
	int i;

	for (i = 0; i < MAX_HUGEPAGE_SIZES; i++) {
		/* skip uninitialized */
		if (internal_config.hugepage_info[i].lock_descriptor <= 0)
			continue;
		/* unlock hugepage file */
		flock(internal_config.hugepage_info[i].lock_descriptor, LOCK_UN);
		close(internal_config.hugepage_info[i].lock_descriptor);
		/* reset the field */
		internal_config.hugepage_info[i].lock_descriptor = -1;
	}
}

int dpaa2_eal_has_hugepages(void)
{
	return !internal_config.no_hugetlbfs;
}

/**
 * Print system information
 */
void dpaa2_print_system_info(void)
{
	printf("\nDPAA2 system info");
	printf("\n----------------------------------------------");
	printf("\nCPU model:       %s", odp_cpu_model_str());
	printf("\nCPU freq (hz):   %"PRIu64"", odp_cpu_hz_max());
	printf("\nCache line size: %i", odp_sys_cache_line_size());
	printf("\nCore count:      %i\n", odp_cpu_count());
}

static int32_t dpaa2_rts_init(struct dpaa2_init_cfg *cfg)
{
	if (internal_config.no_hugetlbfs == 0 &&
			eal_hugepage_info_init() < 0) {
		DPAA2_ERR(FW, "Cannot get hugepage information\n");
		return DPAA2_FAILURE;
	}

	if (internal_config.memory == 0) {
		internal_config.memory = cfg->data_mem_size;
	}

	if (cfg->data_mem_size == 0) {
		DPAA2_ERR(FW, "Data memory not specified\n");
		return DPAA2_FAILURE;
	}

	if (dpaa2_eal_memory_init(cfg) < 0) {
		DPAA2_ERR(FW, "FAIL - dpaa2_eal_memory_init\n");
		return DPAA2_FAILURE;
	}

	/* the directories are locked during eal_hugepage_info_init */
	eal_hugedirs_unlock();

	if (dpaa2_eal_memzone_init() < 0) {
		DPAA2_ERR(FW, "FAIL - dpaa2_eal_memzone_init\n");
		return DPAA2_FAILURE;
	}

#ifndef DPAA2_LOGLIB_DISABLE
	if (!(cfg->flags & DPAA2_LOG_DISABLE)) {
		const char *logid = "dpaa2";
		if (dpaa2_eal_log_init(cfg, logid, LOG_USER))
			return DPAA2_FAILURE;
		dpaa2_set_log_type(DPAA2_LOGTYPE_APP1 | DPAA2_LOGTYPE_ALL, 1);
#ifdef DPAA2_DEBUG
		dpaa2_set_log_level(DPAA2_LOG_DEBUG);
#else
		dpaa2_set_log_level(cfg->log_level ?
			cfg->log_level : DPAA2_LOG_NOTICE);
#endif
	}
#endif

	dpaa2_timer_subsystem_init();
#ifndef DPAA2_MBUF_MALLOC
	if (dpaa2_mbuf_shell_mpool_init(DPAA2_MBUF_SHELL_NUM))
		dpaa2_panic("Cannot init DPAA2 mbuf shell mpool\n");
#endif
	return DPAA2_SUCCESS;
}

static int32_t dpaa2_rts_exit(void)
{
#ifndef DPAA2_MBUF_MALLOC
	dpaa2_mbuf_shell_mpool_exit();
#endif
	dpaa2_eal_log_exit();

	dpaa2_memzone_exit();

	dpaa2_eal_hugepage_exit();

	dpaa2_eal_memory_exit();

	memset(&internal_config, 0, sizeof(struct internal_config));

	return DPAA2_SUCCESS;
}

/*!
 * @details	Initialize the Network Application Development Kit Layer (DPAA2).
 *		This function must be the first function invoked by an
 *		application and is to be executed once.
 *
 * @param[in]	cfg - A pointer to dpaa2_init_cfg structure.
 *
 * @returns     DPAA2_SUCCESS in case of successfull intialization of
 *		DPAA2 Layer; DPAA2_FAILURE otherwise.
 *
 */
int32_t dpaa2_init(struct dpaa2_init_cfg *cfg)
{

#ifndef DPAA2_LOGLIB_DISABLE
	if (!(cfg->flags & DPAA2_LOG_DISABLE)) {
		if (dpaa2_eal_log_early_init() < 0)
			dpaa2_panic("Cannot init early logs\n");
		dpaa2_set_log_level(DPAA2_LOG_DEBUG);
	}
#endif

	/* Init the run-time services memory, Buffers, Locks .. etc
	 * On the basis of input parameters cfg.data_mem_size & cfg.buf_mem_size
	*/
	if (dpaa2_rts_init(cfg))
		goto failure;

	if (cfg->flags & DPAA2_SYSTEM_INFO)
		dpaa2_print_system_info();

	/* Call init for each driver
	* Each driver calls dpaa2_register_driver with its dev_type and file_ops
	*/
	if (dpaa2_io_portal_init())
		goto failure;

	if (dpaa2_eth_driver_init())
		goto failure;
	if (dpaa2_sec_driver_init())
		goto failure;
	if (dpaa2_aiop_driver_init())
		goto failure;
	if (dpaa2_conc_driver_init())
		goto failure;
	/* Other drivers to be added */
	if (dpaa2_platform_init(cfg))
		goto failure;

	dpaa2_notif_init();

	return DPAA2_SUCCESS;

failure:
	dpaa2_cleanup();
	return DPAA2_FAILURE;
}

/*!
 * @details	Do Clean up and exit for in context of a given application. This
 *		function must be invoked by an application before exiting.
 *
 * @returns     Not applicable.
 *
 */
void dpaa2_cleanup(void)
{
	dpaa2_notif_close();

	dpaa2_platform_exit();

	dpaa2_eth_driver_exit();
	dpaa2_sec_driver_exit();
	dpaa2_aiop_driver_exit();
	dpaa2_conc_driver_exit();
	dpaa2_rts_exit();
}
