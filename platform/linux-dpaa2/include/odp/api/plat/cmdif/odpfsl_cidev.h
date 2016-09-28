/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP extensions API's for CMDIF
 */

#ifndef _ODPFSL_CIDEV_H_
#define _ODPFSL_CIDEV_H_

extern uint64_t cmdif_client_sync_wait_interval;
extern uint64_t cmdif_client_sync_num_tries;

/** @defgroup odpfsl_cmdif ODPFSL CMDIF
 *  Command interface extension to ODP for GPP - AIOP communication.
 *  @{
 */

/**
 * @brief Get the CI device from ODP
 *
 * @return Initalized CI device handle. NULL in case of failure.
 */
void *odpfsl_cidev_open(void);

/**
 * @brief Get the internal device ID corresponding to the CI device
 *
 * @param [in]	cidev	CI device handle
 *
 * @return CI device internal ID
 */
int odpfsl_cidev_internal_id(void *cidev);

/**
 * @brief Set the timeout parameters for CMDIF sync command.
 *
 * @param [in]	wait_interval_us - wait interval in micro-seconds
 *
 * @param [in]	num_tries - number of tries to poll for sync command completion
 *
 * @return	none
 */
void odpfsl_cmdif_sync_timeout_params(uint64_t wait_interval_us,
		uint64_t num_tries);

/**
 * @}
 */

#endif
