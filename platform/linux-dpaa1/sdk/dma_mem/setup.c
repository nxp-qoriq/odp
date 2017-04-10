/* Copyright (c) 2010-2011 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
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

/* Store all maps in a static array and only lock it when adding. This works
 * because a process can only add maps, not remove them. When searching, we
 * won't lock but we must be sure to test that maps[x] is non-NULL even if x is
 * less than num_maps, because there is no synchronisation guarantee that
 * maps[x] has been set non-NULL before the num_maps increment is visible. */
#define MAX_DMA_MAPS 64
static struct dma_mem *maps[MAX_DMA_MAPS];
static unsigned int num_maps;
static pthread_mutex_t maps_lock = PTHREAD_MUTEX_INITIALIZER;

/* The "default" map, which apps can set if they wish to use the legacy-style
 * __dma_mem_*() APIs. */
struct dma_mem *dma_mem_generic;

struct dma_mem *dma_mem_create(uint32_t flags, const char *map_name,
			       size_t len)
{
	struct usdpaa_ioctl_dma_map params;
	struct dma_mem *map;
	int ret;

	/* If we exceed the number of maps, there's a chance our process will
	 * leak mappings (process exit will fix that just fine, but trying to
	 * keep the process running will not). So this is just an unlocked check
	 * before we start, and there's a locked check later on when we actually
	 * update the array (and leak the mapping if the array is full at that
	 * point). Of course, none of this is an issue if you don't try to do
	 * too many mapping initialisations from distinct threads
	 * simultaneously. */
	if (num_maps >= MAX_DMA_MAPS) {
		fprintf(stderr, "Too many DMA maps!\n");
		return NULL;
	}
	if ((flags & DMA_MAP_FLAG_SHARED) && (!map_name || !strlen(map_name) ||
			(strlen(map_name) >= USDPAA_DMA_NAME_MAX))) {
		fprintf(stderr, "Bad DMA mapping name '%s'\n", map_name);
		return NULL;
	}
	if (!(flags & DMA_MAP_FLAG_SHARED) && map_name) {
		fprintf(stderr, "Private DMA maps should be name-less\n");
		return NULL;
	}
	/* Implement the checks mentioned in the documentation of the flags */
	if (((flags & DMA_MAP_FLAG_NEW) && !(flags & DMA_MAP_FLAG_SHARED)) ||
		((flags & DMA_MAP_FLAG_LAZY) &&
			((flags & (DMA_MAP_FLAG_SHARED | DMA_MAP_FLAG_NEW)) !=
			(DMA_MAP_FLAG_SHARED | DMA_MAP_FLAG_NEW))) ||
		((flags & DMA_MAP_FLAG_READONLY) &&
			((flags & (DMA_MAP_FLAG_SHARED | DMA_MAP_FLAG_ALLOC)) !=
			DMA_MAP_FLAG_SHARED))) {
		fprintf(stderr, "Invalid set of DMA map flags 0x%08x\n", flags);
		return NULL;
	}
	map = malloc(sizeof(*map));
	if (!map)
		return NULL;
	params.len = len;
	/* Flag translation is possible because USDPAA_DMA_FLAG_* (ioctl
	 * definitions) are matched to DMA_MAP_FLAG_* (dma_mem API) */
	params.flags = flags;
	if (flags & DMA_MAP_FLAG_SHARED) {
		strncpy(params.name, map_name, USDPAA_DMA_NAME_MAX);
		/* Use locking iff it's a shared mapping with an allocator */
		params.has_locking = (flags & DMA_MAP_FLAG_ALLOC) ? 1 : 0;
	} else {
		params.name[0]= '\0';
		params.has_locking = 0;
	}
	ret = process_dma_map(&params);
	if (ret) {
		free(map);
		return NULL;
	}
	map->addr.virt = params.ptr;
	map->addr.phys = params.phys_addr;
	map->sz = params.len;
	map->flags = flags;
	map->has_locking = params.has_locking;
	ret = pthread_mutex_init(&map->alloc_lock, NULL);
	if (ret) {
		perror("pthread_mutex_init failed");
		process_dma_unmap(map->addr.virt);
		free(map);
		return NULL;
	}
	strncpy(map->name, params.name, USDPAA_DMA_NAME_MAX);
	if (params.did_create && (flags & DMA_MAP_FLAG_ALLOC))
		dma_mem_allocator_init(map);
	ret = pthread_mutex_lock(&maps_lock);
	assert(!ret);
	if (num_maps < MAX_DMA_MAPS)
		maps[num_maps++] = map;
	else {
		fprintf(stderr, "Too many DMA maps, caught in a race!\n");
		free(map);
		map = NULL;
	}
	ret = pthread_mutex_unlock(&maps_lock);
	assert(!ret);
	return map;
}

void dma_mem_destroy(struct dma_mem *map)
{
	unsigned int idx;
	int ret;

	ret = pthread_mutex_lock(&maps_lock);
	assert(!ret);
	for (idx = 0; idx < num_maps; idx++)
		if (maps[idx] == map) {
			/* Delete the array entry, and if it wasn't at the end
			 * of the array, promote the entry that is at the tail
			 * to fill the gap. */
			if (idx < --num_maps)
				maps[idx] = maps[num_maps];
			break;
		}
	ret = pthread_mutex_unlock(&maps_lock);
	assert(!ret);
	process_dma_unmap(map->addr.virt);
	free(map);
}

void dma_mem_params(struct dma_mem *map, uint32_t *flags, const char **map_name,
		    size_t *len)
{
	if (flags)
		*flags = map->flags;
	if (map_name)
		*map_name = map->name;
	if (len)
		*len = map->sz;
}

void *dma_mem_raw(struct dma_mem *map, size_t *len)
{
	if (map->flags & DMA_MAP_FLAG_ALLOC)
		return NULL;
	if (len)
		*len = map->sz;
	return map->addr.virt;
}

struct dma_mem *dma_mem_findv(void *v)
{
	struct dma_mem *map;
	unsigned int idx;
	int ret;

	ret = pthread_mutex_lock(&maps_lock);
	assert(!ret);
	for (map = maps[0], idx = 0; (idx < MAX_DMA_MAPS) && map;
				     map = maps[idx++]) {
		if ((v >= map->addr.virt) && (v < (map->addr.virt + map->sz)))
			goto found;
	}
	map = NULL;
found:
	ret = pthread_mutex_unlock(&maps_lock);
	assert(!ret);

	return map;
}

struct dma_mem *dma_mem_findp(dma_addr_t p)
{
	struct dma_mem *map;
	unsigned int idx;
	int ret;

	ret = pthread_mutex_lock(&maps_lock);
	assert(!ret);
	for (map = maps[0], idx = 0; (idx < MAX_DMA_MAPS) && map;
				     map = maps[idx++]) {
		if ((p >= map->addr.phys) && (p < (map->addr.phys + map->sz)))
			goto found;
	}
	map = NULL;
found:
	ret = pthread_mutex_unlock(&maps_lock);
	assert(!ret);
	return map;
}
