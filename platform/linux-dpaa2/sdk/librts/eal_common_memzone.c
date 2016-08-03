/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/*   Derived from DPDK's eal_common_memzone.h
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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include <dpaa2_internal.h>
#include <dpaa2_log.h>
#include <dpaa2_memory.h>
#include <dpaa2_memzone.h>
#include <dpaa2_memconfig.h>
#include <dpaa2_string_fns.h>


#include <dpaa2_mpool.h>
#include <dpaa2_lock.h>

/* internal copy of free memory segments */
static struct dpaa2_memseg *free_memseg;

static inline struct dpaa2_memzone *
memzone_lookup_thread_unsafe(const char *name)
{
	struct dpaa2_mem_config *mcfg;
	unsigned i = 0;

	/* get pointer to global configuration */
	mcfg = dpaa2_eal_get_configuration()->mem_config;

	/*
	 * the algorithm is not optimal (linear), but there are few
	 * zones and this function should be called at init only
	 */
	for (i = 0; i < DPAA2_MAX_MEMZONE && mcfg->memzone[i].addr != NULL; i++) {
		if (!strncmp(name, mcfg->memzone[i].name, DPAA2_MZ_NAMESIZE))
			return &mcfg->memzone[i];
	}

	return NULL;
}


/*
 * Helper function for memzone_reserve_aligned_thread_unsafe().
 * Calculate address offset from the start of the segment.
 * Align offset in that way that it satisfy istart alignmnet and
 * buffer of the  requested length would not cross specified boundary.
 */
static inline phys_addr_t
align_phys_boundary(const struct dpaa2_memseg *ms, size_t len, size_t align,
	size_t bound)
{
	phys_addr_t addr_offset, bmask, end, start;
	size_t step;

	step = DPAA2_MAX(align, bound);
	bmask = ~((phys_addr_t)bound - 1);

	/* calculate offset to closest alignment */
	start = DPAA2_ALIGN_CEIL(ms->phys_addr, align);
	addr_offset = start - ms->phys_addr;

	while (addr_offset + len < ms->len) {

		/* check, do we meet boundary condition */
		end = start + len - (len != 0);
		if ((start & bmask) == (end & bmask))
			break;

		/* calculate next offset */
		start = DPAA2_ALIGN_CEIL(start + 1, step);
		addr_offset = start - ms->phys_addr;
	}

	return addr_offset;
}

static const struct dpaa2_memzone *
memzone_reserve_aligned_thread_unsafe(const char *name, size_t len,
		int socket_id, unsigned flags, unsigned align, unsigned bound)
{
	struct dpaa2_mem_config *mcfg;
	unsigned i = 0;
	int memseg_idx = -1;
	uint64_t addr_offset, seg_offset = 0;
	size_t requested_len;
	size_t memseg_len = 0;
	phys_addr_t memseg_physaddr;
	void *memseg_addr;

	/* get pointer to global configuration */
	mcfg = dpaa2_eal_get_configuration()->mem_config;

	/* no more room in config */
	if (mcfg->memzone_idx >= DPAA2_MAX_MEMZONE) {
		DPAA2_ERR(MEMZONE, "No more room in config \n");
		return NULL;
	}

	/* zone already exist */
	if ((memzone_lookup_thread_unsafe(name)) != NULL) {
		DPAA2_ERR(MEMZONE, "memzone <%s> already exists \n", name);
		return NULL;
	}

	/* if alignment is not a power of two */
	if (!dpaa2_is_power_of_2(align)) {
		DPAA2_ERR(MEMZONE, "Invalid alignment: %u \n", align);
		return NULL;
	}

	/* alignment less than cache size is not allowed */
	if (align < ODP_CACHE_LINE_SIZE)
		align = ODP_CACHE_LINE_SIZE;


	/* align length on cache boundary. Check for overflow before doing so */
	if (len > SIZE_MAX - ODP_CACHE_LINE_MASK) {
		DPAA2_ERR(MEMZONE, "requested size too big \n");
		return NULL;
	}

	len += ODP_CACHE_LINE_MASK;
	len &= ~((size_t)ODP_CACHE_LINE_MASK);

	/* save minimal requested  length */
	requested_len = DPAA2_MAX((size_t)ODP_CACHE_LINE_SIZE,  len);

	/* check that boundary condition is valid */
	if (bound != 0 &&
			(requested_len > bound || !dpaa2_is_power_of_2(bound))) {
		DPAA2_ERR(MEMZONE, "boundary condition is not valid \n");
		return NULL;
	}

	/* find the smallest segment matching requirements */
	for (i = 0; i < DPAA2_MAX_MEMSEG; i++) {
		/* last segment */
		if (free_memseg[i].addr == NULL)
			break;

		/* empty segment, skip it */
		if (free_memseg[i].len == 0)
			continue;

		/*
		 * calculate offset to closest alignment that
		 * meets boundary conditions.
		 */
		addr_offset = align_phys_boundary(free_memseg + i,
			requested_len, align, bound);

		/* check len */
		if ((requested_len + addr_offset) > free_memseg[i].len)
			continue;

		/* check flags for hugepage sizes */
		if ((flags & DPAA2_MZ_2MB) &&
				free_memseg[i].hugepage_sz != DPAA2_PGSIZE_2M)
			continue;
		if ((flags & DPAA2_MZ_4MB) &&
				free_memseg[i].hugepage_sz != DPAA2_PGSIZE_4M)
			continue;
		if ((flags & DPAA2_MZ_16MB) &&
				free_memseg[i].hugepage_sz != DPAA2_PGSIZE_16M)
			continue;
		if ((flags & DPAA2_MZ_64MB) &&
				free_memseg[i].hugepage_sz != DPAA2_PGSIZE_64M)
			continue;
		if ((flags & DPAA2_MZ_256MB) &&
				free_memseg[i].hugepage_sz != DPAA2_PGSIZE_256M)
			continue;
		if ((flags & DPAA2_MZ_1GB) &&
				free_memseg[i].hugepage_sz != DPAA2_PGSIZE_1G)
			continue;


		/* this segment is the best until now */
		if (memseg_idx == -1) {
			memseg_idx = i;
			memseg_len = free_memseg[i].len;
			seg_offset = addr_offset;
		}
		/* find the biggest contiguous zone */
		else if (len == 0) {
			if (free_memseg[i].len > memseg_len) {
				memseg_idx = i;
				memseg_len = free_memseg[i].len;
				seg_offset = addr_offset;
			}
		}
		/*
		 * find the smallest (we already checked that current
		 * zone length is > len
		 */
		else if (free_memseg[i].len + align < memseg_len ||
				(free_memseg[i].len <= memseg_len + align &&
				addr_offset < seg_offset)) {
			memseg_idx = i;
			memseg_len = free_memseg[i].len;
			seg_offset = addr_offset;
		}
	}

	/* no segment found */
	if (memseg_idx == -1) {
		/*
		 * If DPAA2_MZ_SIZE_HINT_ONLY flag is specified,
		 * try allocating again without the size parameter otherwise -fail.
		 */
		if ((flags & DPAA2_MZ_SIZE_HINT_ONLY) && (flags & DPAA2_MZ_SIZES))
			return memzone_reserve_aligned_thread_unsafe(name,
				len, socket_id, 0, align, bound);

		return NULL;
	}

	/* save aligned physical and virtual addresses */
	memseg_physaddr = free_memseg[memseg_idx].phys_addr + seg_offset;
	memseg_addr = DPAA2_PTR_ADD(free_memseg[memseg_idx].addr,
			(uintptr_t) seg_offset);

	/* if we are looking for a biggest memzone */
	if (len == 0) {
		if (bound == 0)
			requested_len = memseg_len - seg_offset;
		else
			requested_len = DPAA2_ALIGN_CEIL(memseg_physaddr + 1,
				bound) - memseg_physaddr;
	}

	/* set length to correct value */
	len = (size_t)seg_offset + requested_len;

	/* update our internal state */
	free_memseg[memseg_idx].len -= len;
	free_memseg[memseg_idx].phys_addr += len;
	free_memseg[memseg_idx].addr =
		(char *)free_memseg[memseg_idx].addr + len;

	/* fill the zone in config */
	struct dpaa2_memzone *mz = &mcfg->memzone[mcfg->memzone_idx++];
	snprintf(mz->name, sizeof(mz->name), "%s", name);
	mz->phys_addr = memseg_physaddr;
	mz->addr = memseg_addr;
	mz->len = requested_len;
	mz->hugepage_sz = free_memseg[memseg_idx].hugepage_sz;
	mz->flags = 0;
	mz->memseg_id = memseg_idx;
	mz->align = align;
	mz->bound = bound;

	return mz;
}

/*
 * Return a pointer to a correctly filled memzone descriptor (with a
 * specified alignment). If the allocation cannot be done, return NULL.
 */
const struct dpaa2_memzone *
dpaa2_memzone_reserve_aligned(const char *name, size_t len,
		int socket_id, unsigned flags, unsigned align)
{
	struct dpaa2_mem_config *mcfg;
	const struct dpaa2_memzone *mz = NULL;

	/* both sizes cannot be explicitly called for */
	if ((flags & DPAA2_MZ_1GB) && (flags & DPAA2_MZ_2MB)) {
		DPAA2_ERR(MEMZONE, "both sizes 1GB and 2MB set in flags \n");
		return NULL;
	}
	/* get pointer to global configuration */
	mcfg = dpaa2_eal_get_configuration()->mem_config;

	RWLOCK_WLOCK(mcfg->mlock);

	mz = memzone_reserve_aligned_thread_unsafe(
		name, len, socket_id, flags, align, 0);


	RWLOCK_WUNLOCK(mcfg->mlock);

	return mz;
}

/*
 * Return a pointer to a correctly filled memzone descriptor (with a
 * specified alignment and boundary).
 * If the allocation cannot be done, return NULL.
 */
const struct dpaa2_memzone *
dpaa2_memzone_reserve_bounded(const char *name, size_t len,
		int socket_id, unsigned flags, unsigned align, unsigned bound)
{
	struct dpaa2_mem_config *mcfg;
	const struct dpaa2_memzone *mz = NULL;

	/* both sizes cannot be explicitly called for */
	if ((flags & DPAA2_MZ_1GB) && (flags & DPAA2_MZ_2MB)) {
		DPAA2_ERR(MEMZONE, "both sizes 1GB and 2MB set in flags \n");
		return NULL;
	}

	/* get pointer to global configuration */
	mcfg = dpaa2_eal_get_configuration()->mem_config;

	RWLOCK_WLOCK(mcfg->mlock);

	mz = memzone_reserve_aligned_thread_unsafe(
		name, len, socket_id, flags, align, bound);

	RWLOCK_WUNLOCK(mcfg->mlock);

	return mz;
}

/*
 * Return a pointer to a correctly filled memzone descriptor. If the
 * allocation cannot be done, return NULL.
 */
struct dpaa2_memzone *
dpaa2_memzone_reserve(const char *name, size_t len, int socket_id,
		      unsigned flags)
{
	if (!free_memseg) {
		DPAA2_ERR(MEMZONE, "memory not initialized");
		return NULL;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	return (struct dpaa2_memzone *)dpaa2_memzone_reserve_aligned(name,
			len, socket_id, flags, ODP_CACHE_LINE_SIZE);
#pragma GCC diagnostic pop
}

/*
 * Free the memzone memory
 */
int
dpaa2_memzone_free(struct dpaa2_memzone *mzone __attribute__((unused)))
{
	struct dpaa2_mem_config *mcfg;

	mcfg = dpaa2_eal_get_configuration()->mem_config;

	RWLOCK_RLOCK(mcfg->mlock);

	DPAA2_DBG(MEMZONE, "Not IMPLEMENTED");

	RWLOCK_RUNLOCK(mcfg->mlock);

	return DPAA2_SUCCESS;

}

/*
 * Unallocate all memzones reserved
 */
int
dpaa2_memzone_exit(void)
{
	int memseg_idx = 0;
	int memzone_idx = 0;
	struct dpaa2_mem_config *mcfg;
	size_t requested_len, len;
	uint32_t align, bound;
	uint64_t addr_offset = 0;

	mcfg = dpaa2_eal_get_configuration()->mem_config;

	if (!free_memseg)
		return DPAA2_SUCCESS;

	RWLOCK_RLOCK(mcfg->mlock);

	/* cycle through all memzones */
	for (memzone_idx = DPAA2_MAX_MEMZONE-1; memzone_idx >= 0;
			memzone_idx--) {

		/* Skip the zone not allocated*/
		if (mcfg->memzone[memzone_idx].addr == NULL)
			continue;

		/* Memory segment to which the memory zone belongs*/
		memseg_idx = mcfg->memzone[memzone_idx].memseg_id;

		/* Length of the memory zone*/
		len = mcfg->memzone[memzone_idx].len;

		len += ODP_CACHE_LINE_MASK;
		len &= ~((size_t)ODP_CACHE_LINE_MASK);

		/* minimal requested  length*/
		requested_len = DPAA2_MAX((size_t)ODP_CACHE_LINE_SIZE,  len);

		/* Alignment of the memzone*/
		align = mcfg->memzone[memzone_idx].align;

		/* Bound of the memzone*/
		bound = mcfg->memzone[memzone_idx].bound;

		len = requested_len;

		/* update our internal state */
		free_memseg[memseg_idx].len += len;
		free_memseg[memseg_idx].phys_addr -= len;
		free_memseg[memseg_idx].addr =
			(char *)free_memseg[memseg_idx].addr - len;

		/* Address offset*/
		addr_offset = align_phys_boundary(free_memseg + memseg_idx,
			requested_len, align, bound);

		/* Correcting alignment */
		free_memseg[memseg_idx].len += addr_offset;
		free_memseg[memseg_idx].phys_addr -= addr_offset;
		free_memseg[memseg_idx].addr =
			(char *)free_memseg[memseg_idx].addr - addr_offset;

		/* unset the memzones allocated*/
		memset(mcfg->memzone[memzone_idx].name, 0,
				sizeof(mcfg->memzone[memzone_idx].name));
		mcfg->memzone[memzone_idx].phys_addr = 0;
		mcfg->memzone[memzone_idx].addr = NULL;
		mcfg->memzone[memzone_idx].len = 0;
	}

	for (memseg_idx = 0; memseg_idx < DPAA2_MAX_MEMSEG;
				memseg_idx++) {
		free_memseg[memseg_idx].addr = NULL;
		free_memseg[memseg_idx].len = 0;
		free_memseg[memseg_idx].phys_addr = 0;
	}

	RWLOCK_RUNLOCK(mcfg->mlock);

	return DPAA2_SUCCESS;
}


/*
 * Lookup for the memzone identified by the given name
 */
struct dpaa2_memzone *
dpaa2_memzone_lookup(const char *name)
{
	struct dpaa2_mem_config *mcfg;
	struct dpaa2_memzone *memzone = NULL;

	mcfg = dpaa2_eal_get_configuration()->mem_config;

	RWLOCK_RLOCK(mcfg->mlock);

	memzone = memzone_lookup_thread_unsafe(name);

	RWLOCK_RUNLOCK(mcfg->mlock);

	return memzone;
}

/* Dump all reserved memory zones on console */
void
dpaa2_memzone_dump(FILE *f)
{
	struct dpaa2_mem_config *mcfg;
	unsigned i = 0;

	/* get pointer to global configuration */
	mcfg = dpaa2_eal_get_configuration()->mem_config;

	RWLOCK_RLOCK(mcfg->mlock);
	/* dump all zones */
	for (i = 0; i < DPAA2_MAX_MEMZONE; i++) {
		if (mcfg->memzone[i].addr == NULL)
			break;
		fprintf(f, "Zone %u: name:<%s>, phys:0x%"PRIx64", len:0x%zx"
			", virt:%p, flags:%"PRIx32"\n", i,
			mcfg->memzone[i].name,
			mcfg->memzone[i].phys_addr,
			mcfg->memzone[i].len,
			mcfg->memzone[i].addr,
			mcfg->memzone[i].flags);
	}
	RWLOCK_RUNLOCK(mcfg->mlock);
}


void dpaa2_memzone_dump_one(FILE *f, const void_t *mzone)
{
	struct dpaa2_mem_config *mcfg;
	const struct dpaa2_memzone *memzone = (const struct dpaa2_memzone *)mzone;
	unsigned i = 0;

	/* get pointer to global configuration */
	mcfg = dpaa2_eal_get_configuration()->mem_config;

	RWLOCK_RLOCK(mcfg->mlock);

	if (memzone->addr == NULL) {
		RWLOCK_RUNLOCK(mcfg->mlock);
		return;
	}
	fprintf(f, "Zone %u: name:<%s>, phys:0x%"PRIx64", len:0x%zx"
		", virt:%p, flags:%"PRIx32"\n", i,
		memzone->name,
		memzone->phys_addr,
		memzone->len,
		memzone->addr,
		memzone->flags);
	RWLOCK_RUNLOCK(mcfg->mlock);
}


/*
 * called by init: modify the free memseg list to have cache-aligned
 * addresses and cache-aligned lengths
 */
static int
memseg_sanitize(struct dpaa2_memseg *memseg)
{
	unsigned phys_align;
	unsigned virt_align;
	unsigned off;

	phys_align = memseg->phys_addr & ODP_CACHE_LINE_MASK;
	virt_align = (unsigned long)memseg->addr & ODP_CACHE_LINE_MASK;

	/*
	 * sanity check: phys_addr and addr must have the same
	 * alignment
	 */
	if (phys_align != virt_align)
		return -1;

	/* memseg is really too small, don't bother with it */
	if (memseg->len < (2 * ODP_CACHE_LINE_SIZE)) {
		memseg->len = 0;
		return 0;
	}

	/* align start address */
	off = (ODP_CACHE_LINE_SIZE - phys_align) & ODP_CACHE_LINE_MASK;
	memseg->phys_addr += off;
	memseg->addr = (char *)memseg->addr + off;
	memseg->len -= off;

	/* align end address */
	memseg->len &= ~((uint64_t)ODP_CACHE_LINE_MASK);

	return 0;
}

/*
 * Init the memzone subsystem
 */
int
dpaa2_eal_memzone_init(void)
{
	struct dpaa2_mem_config *mcfg;
	const struct dpaa2_memseg *memseg;
	unsigned i = 0;

	/* get pointer to global configuration */
	mcfg = dpaa2_eal_get_configuration()->mem_config;

	/* mirror the runtime memsegs from config */
	free_memseg = mcfg->free_memseg;

	memseg = dpaa2_eal_get_physmem_layout();
	if (memseg == NULL) {
		DPAA2_ERR(MEMZONE, "%s(): Cannot get physical layout\n", __func__);
		return -1;
	}

	RWLOCK_WLOCK(mcfg->mlock);

	/* fill in uninitialized free_memsegs */
	for (i = 0; i < DPAA2_MAX_MEMSEG; i++) {
		if (memseg[i].addr == NULL)
			break;
		if (free_memseg[i].addr != NULL)
			continue;
		memcpy(&free_memseg[i], &memseg[i], sizeof(struct dpaa2_memseg));
	}

	/* make all zones cache-aligned */
	for (i = 0; i < DPAA2_MAX_MEMSEG; i++) {
		if (free_memseg[i].addr == NULL)
			break;
		if (memseg_sanitize(&free_memseg[i]) < 0) {
			DPAA2_ERR(MEMZONE, "%s(): Sanity check failed\n", __func__);
			RWLOCK_WUNLOCK(mcfg->mlock);
			return -1;
		}
	}

	/* delete all zones */
	mcfg->memzone_idx = 0;
	memset(mcfg->memzone, 0, sizeof(mcfg->memzone));

	RWLOCK_WUNLOCK(mcfg->mlock);

	return 0;
}

/* Walk all reserved memory zones */
void dpaa2_memzone_walk(void (*func)(const struct dpaa2_memzone *, void *),
		      void *arg)
{
	struct dpaa2_mem_config *mcfg;
	unsigned i;

	mcfg = dpaa2_eal_get_configuration()->mem_config;

	RWLOCK_RLOCK(mcfg->mlock);
	for (i = 0; i < DPAA2_MAX_MEMZONE; i++) {
		if (mcfg->memzone[i].addr != NULL)
			(*func)(&mcfg->memzone[i], arg);
	}
	RWLOCK_RUNLOCK(mcfg->mlock);
}
