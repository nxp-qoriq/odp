/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#include <time.h>
#include <odp/api/std_types.h>
#include <odp/api/hints.h>
#include <dpaa2_time.h>
#include <odp/api/system_info.h>
#include <dpaa2_common.h>

#if defined __x86_64__ || defined __i386__

uint64_t dpaa2_time_get_cycles(void)
{
	union {
		uint64_t tsc_64;
		struct {
			uint32_t lo_32;
			uint32_t hi_32;
		};
	} tsc;

	asm volatile("rdtsc" :
			"=a" (tsc.lo_32),
			"=d" (tsc.hi_32) : : "memory");

	return tsc.tsc_64;
}

uint64_t dpaa2_time_cycles_to_ns(uint64_t cycles)
{
	uint64_t hz = dpaa2_sys_cpu_hz();

	if (cycles > (UINT64_MAX / 1000000000))
		return 1000000000*(cycles/hz);

	return (1000000000*cycles)/hz;
}

#else

#include <sys/time.h>
#include <stdlib.h>

uint64_t dpaa2_time_get_cycles(void)
{
	struct timespec cur_time;

	clock_gettime(CLOCK_REALTIME, &cur_time);
	return (cur_time.tv_sec * NS_PER_S + cur_time.tv_nsec);
}

uint64_t dpaa2_time_cycles_to_ns(uint64_t cycles)
{
	return cycles;
}

#endif

uint64_t dpaa2_time_diff_cycles(uint64_t t2, uint64_t t1)
{
	if (odp_likely(t2 > t1))
		return t2 - t1;

	return t2 + (UINT64_MAX - t1);
}

#define NANO_TO_MS 1000000L /* 1 millisecond = 1,000,000 Nanoseconds*/
#define NANO_TO_US 1000  /* 1 microsecond = 1,000 Nanoseconds*/

void dpaa2_msleep(uint32_t mst)
{
	struct timespec t1;

	t1.tv_sec = 0;
	t1.tv_nsec = mst * NANO_TO_MS;
	nanosleep(&t1, NULL);
}

void dpaa2_usleep(uint32_t ust)
{
	struct timespec t1;

	t1.tv_sec = 0;
	t1.tv_nsec = ust * NANO_TO_US;
	nanosleep(&t1, NULL);
}
