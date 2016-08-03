/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <pthread.h>

#include <odp/api/cpu.h>
#include <odp/api/cpumask.h>
#include <odp_debug_internal.h>

int odp_cpumask_default_worker(odp_cpumask_t *mask, int num)
{
	int cpu, i;


	odp_cpumask_zero(mask);
	cpu = odp_cpu_count();
	/*
	 * If no user supplied number or it's too large, then attempt
	 * to use all CPUs
	 */
	if (0 == num || cpu < num)
		num = cpu;

	/* build the mask, allocating down from highest numbered CPU */
#if ODPFSL_DRIVER_LB
	/* For GPP proof point performance benchmarking, we are isolating
	   the CPUs so, hard coding is required to use isolated cores */
	for (cpu = 0, i = 7; i >= 0 && cpu < num; --i) {
		odp_cpumask_set(mask, i);
		cpu++;
	}
#else
	for (cpu = 0, i = num - 1; i >= 0 && cpu < num; --i) {
		odp_cpumask_set(mask, i);
		cpu++;
	}
#endif
	return cpu;
}

int odp_cpumask_default_control(odp_cpumask_t *mask, int num ODP_UNUSED)
{
	odp_cpumask_zero(mask);
	/* By default all control threads on CPU 0 */
	odp_cpumask_set(mask, 0);
	return 1;
}

int odp_cpumask_all_available(odp_cpumask_t *mask)
{
	odp_cpumask_or(mask, &odp_global_data.worker_cpus,
		       &odp_global_data.control_cpus);

	return odp_cpumask_count(mask);
}
