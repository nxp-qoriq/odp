/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "private.h"

/* OK, this will be ugly as all allocators are, but ugliness will be minimised
 * at the expense of (a) optimisation and (b) fragmentation. W.r.t. (a)
 * (de)allocation is not expected to be a performance-critical operation, and in
 * particular requires a kernel ioctl() to lock and unlock each time. W.r.t. (b)
 * there is not expected to be a wide array of memory allocation sizes and
 * alignments within each memory region (often a memory region will used
 * entirely for a single buffer geometry). Here's a brief attempt to explain how
 * we'll implement this.
 *
 * The book-keeping for the region will be hard-aligned to the right of the
 * memory region. Buffers will be, as much as possible, hard-aligned to the left
 * of the memory region. The final word of the book-keeping area (and thus the
 * entire region) will be <numbufs>, indicating how many allocations have been
 * made, and from this the boundary can be calculated. Prior to <numbufs> is an
 * array of that many "bufinfo" structures representing all allocated buffers in
 * reverse address order. Allocations (insertions) and deallocations (deletes)
 * are therefore linear and may each involve a memmove() in order to keep the
 * array packed.  Allocation always involves looking for the first satisfactory
 * "gap" in the allocation space and returning that. As such, a burst of
 * allocations will typically be of increasing addresses, which is why the
 * "bufinfo" array is in reverse-order, as this would minimise memmove()s as the
 * array expands downwards.
 *
 * All allocations and deallocations occur with the entire region locked (if
 * locking for the region is enabled). Within that, a process-local pthread
 * mutext is locked also. (Ie. we assert the multi-thread lock within the
 * multi-process lock.)
 */

struct bufinfo {
	uint32_t offset;
	uint32_t len;
};

/* Return a pointer to <numbufs> */
static inline uint32_t *get_numbufs(struct dma_mem *map)
{
	uint32_t *p = map->addr.virt + map->sz;
	return &p[-1];
}

/* Return a pointer to the <idx>th item of the <bufinfo> array */
static inline struct bufinfo *get_bufinfo(struct dma_mem *map, int idx)
{
	struct bufinfo *b = (struct bufinfo *)get_numbufs(map);
	return b - (idx + 1);
}

#undef ALLOC_DEBUG
#ifdef DEBUG_DMA_ALLOC
#define ALLOC_DEBUG
#endif

#ifdef ALLOC_DEBUG
#define DPRINT		printf
#define DUMP(x)		dma_mem_print(x)
#define DUMP_LOCK(x)	dma_mem_print_lock(x)
#else
#define DPRINT(x...)	do { ; } while(0)
#define DUMP(x)		do { ; } while(0)
#define DUMP_LOCK(x)	do { ; } while(0)
#endif

void dma_mem_allocator_init(struct dma_mem *map)
{
	*get_numbufs(map) = 0;
	DPRINT("%s\n", __func__);
	DUMP_LOCK(map);
}

/* These internal local_*() functions don't need to worry about locking */

static void *local_memalign(struct dma_mem *map, size_t align, size_t size)
{
	uint32_t *p_numbufs = get_numbufs(map), numbufs = *p_numbufs;
	/* Initialise 'buf' to the last bufinfo */
	struct bufinfo *buf = get_bufinfo(map, numbufs - 1);
	uint32_t lastend, boundary;
	unsigned int idx;

	/* Check that the bufinfo array can be expanded */
	boundary = numbufs ? (buf->offset + buf->len) : 0;
	buf--;
	if (((unsigned long)buf - (unsigned long)map->addr.virt) < boundary)
		return NULL;
	/* Treat align==0 the same as align==1 */
	if (!align)
		align = 1;
	if (align & (align - 1))
		return NULL;
	/* Iterate bufinfos, looking for a good gap */
	for (lastend = 0, idx = 0, buf = get_bufinfo(map, 0); idx < numbufs;
			lastend = buf->offset + buf->len, buf--, idx++) {
		/* Is there space between 'lastend' and 'buf'? To find out,
		 * round 'lastend' up to the required alignment */
		lastend = (lastend + align - 1) & ~(uint32_t)(align - 1);
		if ((lastend + size) <= buf->offset)
			break;
	}
	if (idx == numbufs) {
		/* No insertion point, so we could only go on the tail. */
		lastend = (lastend + align - 1) & ~(uint32_t)(align - 1);
		if (((unsigned long)buf - (unsigned long)map->addr.virt) <
				(lastend + size))
			/* Nope, the allocation space would overlap the bufinfo
			 * array. */
			return NULL;
	}
	/* 'buf' and 'idx' now point to the insertion location in the bufinfo
	 * array - either within existing entries, or on the tail. */
	if (idx < numbufs)
		/* need to shift some bufinfo's for the insertion */
		memmove(get_bufinfo(map, numbufs),
			get_bufinfo(map, numbufs - 1),
			(numbufs - idx) * sizeof(*buf));
	buf->offset = lastend;
	buf->len = size;
	(*p_numbufs)++;
	return map->addr.virt + buf->offset;
}

static void local_free(struct dma_mem *map, void *ptr)
{
	uint32_t *p_numbufs = get_numbufs(map), numbufs = *p_numbufs;
	uint32_t offset = (unsigned long)ptr - (unsigned long)map->addr.virt;
	struct bufinfo *buf;
	unsigned int idx;
	for (idx = 0, buf = get_bufinfo(map, 0); idx < numbufs; buf--, idx++) {
		if (buf->offset == offset) {
			numbufs = --(*p_numbufs);
			if (idx < numbufs)
				memmove(get_bufinfo(map, numbufs - 1),
					get_bufinfo(map, numbufs),
					(numbufs - idx) * sizeof(*buf));
			return;
		}
		if (buf->offset > offset)
			break;
	}
	fprintf(stderr, "DMA free, bad pointer!\n");
	return;
}

static inline int map_lock(struct dma_mem *map)
{
	int ret;
	if (map->has_locking) {
		ret = process_dma_lock(map->addr.virt);
		if (ret) {
			perror("Failed to lock DMA region");
			return -ENODEV;
		}
	}
	ret = pthread_mutex_lock(&map->alloc_lock);
	assert(!ret);
	return 0;
}
static inline int map_unlock(struct dma_mem *map)
{
	int ret;
	ret = pthread_mutex_unlock(&map->alloc_lock);
	assert(!ret);
	if (map->has_locking) {
		ret = process_dma_unlock(map->addr.virt);
		if (ret) {
			perror("Failed to unlock DMA region");
			return -ENODEV;
		}
	}
	return 0;
}

/* The exported functions provide locking wrappers around internal code */

void *dma_mem_memalign(struct dma_mem *map, size_t align, size_t size)
{
	void *ptr;
	int ret;
	if (!(map->flags & DMA_MAP_FLAG_ALLOC)) {
		fprintf(stderr, "DMA map not initialised for allocation\n");
		return NULL;
	}
	ret = map_lock(map);
	if (ret)
		return NULL;
	ptr = local_memalign(map, align, size);
	DPRINT("dma_mem_align(%p,0x%x,0x%x) returning %p\n",
	       map, align, size, ptr);
	DUMP(map);
	map_unlock(map);
	return ptr;
}

void dma_mem_free(struct dma_mem *map, void *ptr)
{
	map_lock(map);
	local_free(map, ptr);
	DPRINT("dma_mem_free(%p,%p)\n", map, ptr);
	DUMP(map);
	map_unlock(map);
}

void dma_mem_print(struct dma_mem *map)
{
	uint32_t *p_numbufs, numbufs;
	struct bufinfo *buf;
	unsigned int idx;

	p_numbufs = get_numbufs(map);
	numbufs = *p_numbufs;
	buf = get_bufinfo(map, numbufs - 1);
	printf("Map %p: v=%p,p=%"PRIu64",sz=0x%zx,bufs=0x%x\n", map, map->addr.virt,
	       map->addr.phys, map->sz, numbufs);
	for (idx = 0, buf = get_bufinfo(map, idx); idx < numbufs; buf--, idx++)
		printf("  [0x%x-0x%x] len=0x%x, bufinfo=%p\n",
		       buf->offset, buf->offset + buf->len, buf->len, buf);
}

void dma_mem_print_lock(struct dma_mem *map)
{
	map_lock(map);
	dma_mem_print(map);
	map_unlock(map);
}

int dma_mem_query(uint64_t *free_bytes, uint64_t *total_bytes)
{
	return process_query_dma_mem(free_bytes, total_bytes);
}
