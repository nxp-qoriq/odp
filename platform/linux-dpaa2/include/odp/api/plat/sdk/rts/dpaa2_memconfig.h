/*-
 *   Derived from DPDK's rte_eal_memconfig.h
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

#ifndef _DPAA2_EAL_MEMCONFIG_H_
#define _DPAA2_EAL_MEMCONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <dpaa2_memory.h>
#include <dpaa2_memzone.h>
#include <dpaa2_malloc_heap.h>

#include <dpaa2.h>
#include <dpaa2_common.h>
#include <dpaa2_lock.h>
#include <dpaa2_internal.h>
#include "dpaa2_tailq.h"

#define DPAA2_MAX_MEMSEG 256
#define DPAA2_MAX_MEMZONE 2560
#define DPAA2_MAX_TAILQ 32
#define DPAA2_MAX_HEAPS 1
#define DPAA2_MALLOC_MEMZONE_SIZE 1M


/*!
 * the structure for the memory configuration for the DPAA2.
 * Used by the dpaa2_config structure.
 */
struct dpaa2_mem_config {
	rwlock_t qlock;   /**< used for tailq operation for thread safe. */
	rwlock_t mlock;   /* only used by memzone LIB for thread-safe. */
	rwlock_t mplock;   /**< only used by mempool LIB for thread safe. */

	uint32_t memzone_idx; /* Index of memzone */

	/* memory segments and zones */
	struct dpaa2_memseg memseg[DPAA2_MAX_MEMSEG];    /* Physmem descriptors. */
	struct dpaa2_memzone memzone[DPAA2_MAX_MEMZONE]; /* Memzone descriptors. */

	/* Runtime Physmem descriptors. */
	struct dpaa2_memseg free_memseg[DPAA2_MAX_MEMSEG];

	/* Heaps of Malloc */
	struct malloc_heap malloc_heaps[DPAA2_MAX_HEAPS];

	struct dpaa2_tailq_head tailq_head[DPAA2_MAX_TAILQ]; /**< Tailqs for objects */
} __attribute__((__packed__));

/**
 * macro to get the lock of tailq in mem_config
 */
#define DPAA2_EAL_TAILQ_RWLOCK (dpaa2_eal_get_configuration()->mem_config->qlock)

/**
 * macro to get the multiple lock of mempool shared by mutiple-instance
 */
#define DPAA2_EAL_MEMPOOL_RWLOCK (dpaa2_eal_get_configuration()->mem_config->mplock)

#ifdef ODP_USE_PHYS_IOVA
/*
 * When we are using Physical addresses as IO Virtual Addresses,
 * we call conversion routines dpaa2_mem_vtop & dpaa2_mem_ptov wherever required.
 * These routines are called with help of below MACRO's
 */

/**
 * macro to convert Virtual address to IOVA
 */
#define DPAA2_VADDR_TO_IOVA(_vaddr) dpaa2_mem_vtop((void *)_vaddr)

/**
 * macro to convert IOVA to Virtual address
 */
#define DPAA2_IOVA_TO_VADDR(_iova) dpaa2_mem_ptov((phys_addr_t)(_iova))

/**
 * macro to convert modify the memory containing Virtual address to IOVA
 */
#define DPAA2_MODIFY_VADDR_TO_IOVA(_mem, _type) \
	{_mem = (_type)(dpaa2_mem_vtop((void *)(_mem))); }

/**
 * macro to convert modify the memory containing IOVA to Virtual address
 */
#define DPAA2_MODIFY_IOVA_TO_VADDR(_mem, _type) \
	{_mem = (_type)(dpaa2_mem_ptov((phys_addr_t)(_mem))); }

#else
#define DPAA2_VADDR_TO_IOVA(_vaddr) (phys_addr_t)(_vaddr)
#define DPAA2_IOVA_TO_VADDR(_iova) (void *)(_iova)
#define DPAA2_MODIFY_VADDR_TO_IOVA(_mem, _type)
#define DPAA2_MODIFY_IOVA_TO_VADDR(_mem, _type)
#endif

static ODP_UNUSED phys_addr_t dpaa2_mem_vtop(void *vaddr)
{
	const struct dpaa2_memseg *memseg = dpaa2_eal_get_physmem_layout();
	int i;

	for (i = 0; i < DPAA2_MAX_MEMSEG && memseg[i].addr != NULL; i++) {
		if (vaddr >= memseg[i].addr && vaddr <
			memseg[i].addr + memseg[i].len)
			return memseg[i].phys_addr + (vaddr - memseg[i].addr);
	}

	return (phys_addr_t)(NULL);
}

static ODP_UNUSED void *dpaa2_mem_ptov(phys_addr_t paddr)
{
	const struct dpaa2_memseg *memseg = dpaa2_eal_get_physmem_layout();
	int i;

	for (i = 0; i < DPAA2_MAX_MEMSEG && memseg[i].addr != NULL; i++) {
		if (paddr >= memseg[i].phys_addr && paddr <
			memseg[i].phys_addr + memseg[i].len)
			return memseg[i].addr + (paddr - memseg[i].phys_addr);
	}

	return NULL;
}

#ifdef __cplusplus
}
#endif

#endif /*__DPAA2_EAL_MEMCONFIG_H_*/
