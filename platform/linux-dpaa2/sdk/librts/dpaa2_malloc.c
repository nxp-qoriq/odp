/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/*-
 *   Derived from DPDK's rte_malloc.c
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

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <odp/api/hints.h>
#include <dpaa2_memory.h>
#include <dpaa2_memzone.h>
#include <dpaa2_tailq.h>
#include <dpaa2_memconfig.h>
#include <odp/api/spinlock.h>
#include <dpaa2_internal.h>
#include <dpaa2_memcpy.h>

#include <dpaa2_malloc.h>
#include <malloc_elem.h>
#include <malloc_heap.h>


/* Free the memory space back to heap */
void dpaa2_data_free(void *addr)
{
	if (addr == NULL)
		return;
	if (malloc_elem_free(malloc_elem_from_data(addr)) < 0)
		DPAA2_ERR(MALLOC, "Fatal error: Invalid memory");
}

/*
 * Allocate memory on heap.
 */
void *
dpaa2_data_malloc(const char *type, size_t size, unsigned align)
{
	struct dpaa2_mem_config *mcfg = dpaa2_eal_get_configuration()->mem_config;
	void *ret;

	/* return NULL if size is 0 or alignment is not power-of-2 */
	if (size <= 0 || !dpaa2_is_power_of_2(align))
		return NULL;

	ret = malloc_heap_alloc(&mcfg->malloc_heaps[0], type,
				size, align == 0 ? 1 : align);
	return ret;
}

/*
 * Allocate zero'd memory on heap.
 */
void *
dpaa2_data_zmalloc(const char *type, size_t size, unsigned align)
{
	void *ptr = dpaa2_data_malloc(type, size, align);

	if (ptr != NULL)
		memset(ptr, 0, size);
	return ptr;
}

/*
 * Allocate zero'd memory on heap.
 */
void *
dpaa2_data_calloc(const char *type, size_t num, size_t size, unsigned align)
{
	return dpaa2_data_zmalloc(type, num * size, align);
}

/*
 * Resize allocated memory.
 */
void *
dpaa2_data_realloc(void *ptr, size_t size, unsigned align)
{
	if (ptr == NULL)
		return dpaa2_data_malloc(NULL, size, align);

	struct malloc_elem *elem = malloc_elem_from_data(ptr);
	if (elem == NULL) {
		DPAA2_ERR(MALLOC, "Fatal error: memory corruption detected");
		return NULL;
	}

	size = CACHE_LINE_SIZE_ROUNDUP(size), align =
		CACHE_LINE_SIZE_ROUNDUP(align);
	/* check alignment matches first, and if ok, see if we
	   can resize block */
	if (DPAA2_PTR_ALIGN(ptr, align) == ptr &&
			malloc_elem_resize(elem, size) == 0)
		return ptr;

	/* either alignment is off, or we have no room to expand,
	 * so move data. */
	void *new_ptr = dpaa2_data_malloc(NULL, size, align);
	if (new_ptr == NULL)
		return NULL;
	const unsigned old_size = elem->size - MALLOC_ELEM_OVERHEAD;
	dpaa2_memcpy(new_ptr, ptr, old_size < size ? old_size : size);
	dpaa2_data_free(ptr);

	return new_ptr;
}

/*
 * If malloc debug is enabled, check mem block for header and trailer markers
 */
int
dpaa2_data_malloc_validate(const void *ptr, size_t *size)
{
	const struct malloc_elem *elem = malloc_elem_from_data(ptr);
	if (!malloc_elem_cookies_ok(elem))
		return -1;
	if (size != NULL)
		*size = elem->size - elem->pad - MALLOC_ELEM_OVERHEAD;
	return 0;
}

/*
 * Function to retrieve data for heap
 */
int
dpaa2_data_malloc_get_stats(struct dpaa2_data_malloc_stats *stats)
{
	struct dpaa2_mem_config *mcfg = dpaa2_eal_get_configuration()->mem_config;

	return malloc_heap_get_stats(&mcfg->malloc_heaps[0], stats);
}

/*
 * Print stats on memory type. If type is NULL, info on all types is printed
 */
void
dpaa2_data_malloc_dump_stats(FILE *f, ODP_UNUSED const char *type)
{
	struct dpaa2_data_malloc_stats stats;
	/* Iterate through all initialised heaps */
	if ((dpaa2_data_malloc_get_stats(&stats) < 0))
		fprintf(f, "\tUnable to get the stats\n");

	fprintf(f, "\tHeap_size:%zu,\n", stats.heap_totalsz_bytes);
	fprintf(f, "\tFree_size:%zu,\n", stats.heap_freesz_bytes);
	fprintf(f, "\tAlloc_size:%zu,\n", stats.heap_allocsz_bytes);
	fprintf(f, "\tGreatest_free_size:%zu,\n",
			stats.greatest_free_size);
	fprintf(f, "\tAlloc_count:%u,\n", stats.alloc_count);
	fprintf(f, "\tFree_count:%u,\n", stats.free_count);
	return;
}

/*
 * Return the physical address of a virtual address obtained through dpaa2_malloc
 */
phys_addr_t
dpaa2_data_malloc_virt2phy(const void *addr)
{
	const struct malloc_elem *elem = malloc_elem_from_data(addr);
	if (elem == NULL)
		return 0;
	return elem->mz->phys_addr +
		((uintptr_t)addr - (uintptr_t)elem->mz->addr);
}
