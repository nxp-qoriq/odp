/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/api/plat/malloc/odpfsl_data_malloc.h>
#include <dpaa2_malloc.h>

void *
odpfsl_data_malloc(const char *type, size_t size, unsigned align)
{
	return dpaa2_data_malloc(type, size, align);
}

void *
odpfsl_data_zmalloc(const char *type, size_t size, unsigned align)
{
	return dpaa2_data_zmalloc(type, size, align);
}

void *
odpfsl_data_calloc(const char *type, size_t num, size_t size, unsigned align)
{
	return dpaa2_data_calloc(type, num, size, align);
}

void *
odpfsl_data_realloc(void *ptr, size_t size, unsigned align)
{
	return dpaa2_data_realloc(ptr, size, align);
}

void
odpfsl_data_free(void *ptr)
{
	dpaa2_data_free(ptr);
}

int
odpfsl_data_malloc_validate(const void *ptr, size_t *size)
{
	return dpaa2_data_malloc_validate(ptr, size);
}

phys_addr_t
odpfsl_data_malloc_virt2phy(const void *addr)
{
	return dpaa2_data_malloc_virt2phy(addr);
}
