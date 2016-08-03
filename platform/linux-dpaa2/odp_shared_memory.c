/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/shared_memory.h>
#include <odp/api/debug.h>
#include <odp_config_internal.h>
#include <odp_debug_internal.h>


int odp_shm_term_global(void)
{
	return 0;
}

int odp_shm_init_local(void)
{
	return 0;
}

int odp_shm_capability(odp_shm_capability_t *capa)
{
	memset(capa, 0, sizeof(odp_shm_capability_t));

	capa->max_blocks = ODP_CONFIG_SHM_BLOCKS;
	capa->max_size   = 0;
	capa->max_align  = 0;

	return 0;
}

odp_shm_t odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
			  uint32_t flags)
{
	if (flags & ODP_SHM_PROC) {
		/*TODO - support share memory between processes*/
		ODP_ERR("Process Shared memory currently not supported");
		return ODP_SHM_NULL;
	}
	return (odp_shm_t)dpaa2_memzone_reserve_aligned(name, size,
						SOCKET_ID_ANY, 0, align);
}

int odp_shm_info(odp_shm_t shm, odp_shm_info_t *info)
{
	struct dpaa2_memzone *mz = (struct dpaa2_memzone *)shm;
	info->name      = mz->name;
	info->addr      = (void *)dpaa2_memzone_virt(mz);
	info->size      = mz->len;
	info->page_size = mz->hugepage_sz;
	info->flags     = 0;
	return 0;
}

void odp_shm_print_all(void)
{
	dpaa2_memzone_dump(stdout);
}
