/*
 * GPL LICENSE SUMMARY
 *
 *   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *   The full GNU General Public License is included in this distribution
 *   in the file called LICENSE.GPL.
 *
 */
#include <linux/module.h>/* Needed by all modules */
#include <linux/kernel.h>/* Needed for KERN_INFO */
#include <linux/types.h>

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Freescale Semiconductor");
MODULE_DESCRIPTION("Kernel Module for ARMv8 performance counters");

#define ENABLE_COUNTERS 1

#if defined(__ARM_ARCH_7A__)
static void enable_performance_counters(void* data)
{
        /* Enable user-mode access to counters. */
        asm volatile("mcr p15, 0, %0, c9, c14, 0" :: "r"(ENABLE_COUNTERS));
        /* Program PMU and enable all counters */
        asm volatile("mcr p15, 0, %0, c9, c12, 0" :: "r"(ENABLE_COUNTERS));
}
static void disable_performance_counters(void* data)
{
        /* Enable user-mode access to counters. */
        asm volatile("mcr p15, 0, %0, c9, c14, 0" :: "r"(~ENABLE_COUNTERS));
        /* Program PMU and enable all counters */
        asm volatile("mcr p15, 0, %0, c9, c12, 0" :: "r"(~ENABLE_COUNTERS));
}
#endif
#if defined(__aarch64__)
static void
enable_performance_counters(void *data)
{

	asm volatile("msr pmuserenr_el0, %0" : : "r"(ENABLE_COUNTERS));
	asm volatile("msr pmcr_el0, %0" : : "r"(ENABLE_COUNTERS));
}

static void
disable_performance_counters(void *data)
{
	asm volatile("msr pmuserenr_el0, %0" : : "r"(~ENABLE_COUNTERS));
	asm volatile("msr pmcr_el0, %0" : : "r"(~ENABLE_COUNTERS));
}
#endif

static int __init
init(void)
{
	on_each_cpu(enable_performance_counters, NULL, 1);
	return 0;
}

static void __exit
fini(void)
{
	on_each_cpu(disable_performance_counters, NULL, 1);
}

module_init(init);
module_exit(fini);
