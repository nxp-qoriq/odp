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
 * ODP time
 */

#ifndef ODP_PLAT_TIME_H_
#define ODP_PLAT_TIME_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_time ODP TIME
 *  @{
 */

#include <odp/api/std_types.h>

#include <sys/time.h>
#include <time.h>

#include <odp/api/plat/time_types.h>
#include <odp/api/spec/time.h>


/**
 * Sleep for millisecond
 *
 * @param[in]	mst  Time in miliseconds
 *
 */
static inline
void odpfsl_msleep(uint32_t mst)
{
	struct timespec t1;

	t1.tv_sec = 0;
	t1.tv_nsec = mst * ODP_TIME_MSEC_IN_NS;
	nanosleep(&t1, NULL);
}

/**
 * Sleep for microsecond
 *
 * @param[in]	ust  Time in microseconds
 *
 */
static inline
void odpfsl_usleep(uint32_t ust)
{
	struct timespec t1;

	t1.tv_sec = 0;
	t1.tv_nsec = ust * ODP_TIME_USEC_IN_NS;
	nanosleep(&t1, NULL);
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
