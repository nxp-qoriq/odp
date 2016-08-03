/*-
 *   Derived from DPDK's rte_memory.h
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _DPAA2_MEMORY_H_
#define _DPAA2_MEMORY_H_

/**
 * @file
 *
 * Memory-related RTE API.
 */

#include <odp/api/std_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Physical memory segment descriptor.
 */
struct dpaa2_memseg {
	phys_addr_t phys_addr;      /* Start physical address. */
	union {
		void *addr;         /* Start virtual address. */
		uint64_t addr_64;   /* Makes sure addr is always 64 bits */
	};

	size_t len;               /* Length of the segment. */
	size_t hugepage_sz;       /* The pagesize of underlying memory */
} __attribute__((__packed__));

/*!
 * @details Get the layout of the available physical memory.
 *
 * It can be useful for an application to have the full physical
 * memory layout to decide the size of a memory zone to reserve. This
 * table is stored in dpaa2_config (see dpaa2_eal_get_configuration()).
 *
 * @returns
 *  - On success, return a pointer to a read-only table of struct
 *    dpaa2_physmem_desc elements, containing the layout of all
 *    addressable physical memory. The last element of the table
 *    contains a NULL address.
 *  - On error, return NULL. This should not happen since it is a fatal
 *    error that will probably cause the entire system to panic.
 */
const struct dpaa2_memseg *dpaa2_eal_get_physmem_layout(void);

/*!
 * @details Dump the physical memory layout to the console.
 *
 * @param[in] f
 *	A pointer to a file for output
 */
void dpaa2_dump_physmem_layout(FILE *f);

/*!
 * @details Get the total amount of available physical memory.
 *
 * @returns
 *    The total amount of available physical memory in bytes.
 */
uint64_t dpaa2_eal_get_physmem_size(void);

#ifdef __cplusplus
}
#endif

#endif /* _DPAA2_MEMORY_H_ */
