/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * Standard C language types and definitions for ODP.
 */

#ifndef ODP_PLAT_STD_TYPES_H_
#define ODP_PLAT_STD_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>

/** @addtogroup odp_system ODP SYSTEM
 *  @{
 */

typedef int odp_bool_t;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define DPAA1_SUCCESS 0
#define DPAA1_FAILURE -1

/**
 * @}
 */

#include <odp/api/spec/std_types.h>

#ifdef __cplusplus
}
#endif

#endif
