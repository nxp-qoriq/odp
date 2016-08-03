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
 * @}
 */

#endif
