/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP initialization.
 */

#ifndef ODP_PLAT_INIT_H_
#define ODP_PLAT_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/init_types.h>

/** @ingroup odp_initialization
 *  @{
 */

/**
 * @}
 */

#include <odp/api/spec/init.h>

extern char *vfio_container;

/** This variable is set when signal interrupt is received. */
extern int received_sigint;

#ifdef __cplusplus
}
#endif

#endif
