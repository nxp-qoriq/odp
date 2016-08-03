/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013-2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP shared memory
 */

#ifndef ODP_PLAT_SHARED_MEMORY_H_
#define ODP_PLAT_SHARED_MEMORY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/plat/shared_memory_types.h>

/** @ingroup odp_shared_memory
 *  @{
 */
static inline int odp_shm_free(odp_shm_t shm)
{
	return dpaa2_memzone_free(shm);
}


static inline odp_shm_t odp_shm_lookup(const char *name)
{
	return dpaa2_memzone_lookup(name);
}


static inline void *odp_shm_addr(odp_shm_t shm)
{
	return (void *)dpaa2_memzone_virt(shm);
}

/**
 * @}
 */

#include <odp/api/spec/shared_memory.h>

#ifdef __cplusplus
}
#endif

#endif
