/* Copyright (c) 2015, Linaro Limited
 *  * All rights reserved.
 *   *
 *    * SPDX-License-Identifier:     BSD-3-Clause
 *     */
#define _POSIX_C_SOURCE 200809L

#include <odp/api/time.h>
#include <odp/api/hints.h>
#include <odp/api/system_info.h>
#include <odp/api/spec/cpu.h>
#include <usdpaa/fsl_usd.h>

uint64_t odp_cpu_cycles(void)
{
	/* This is referred from odp_time_cycle.c and may be wrong. */
	return mfatb();
}

uint64_t odp_cpu_cycles_max(void)
{
	return UINT64_MAX;
}

uint64_t odp_cpu_cycles_resolution(void)
{
	return 1;
}
uint64_t odp_cpu_cycles_diff(uint64_t c2, uint64_t c1)
{
	uint64_t ret = 0;
	/* Done this to avoid compilation error for un-used variables. */
	c1 = c2 - c1;
	return ret;
}
