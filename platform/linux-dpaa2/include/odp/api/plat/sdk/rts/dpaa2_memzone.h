/*-
 * Copyright (c) 2015 - 2016 Freescale Semiconductor, Inc
 *   Derived from DPDK's rte_memzone.h
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

#ifndef _DPAA2_MEMZONE_H_
#define _DPAA2_MEMZONE_H_

/*!
 * @file dpaa2_memzone.h
 *
 * @brief The memzone allocator is to reserve contiguous portions of
 *	physical memory. These zones are identified by a name.
 *
 *	The memzone descriptors are shared by all partitions and are
 *	located in a known place of physical memory. This zone is accessed
 *	using dpaa2_eal_get_configuration(). The lookup (by name) of a
 *	memory zone can be done in any partition and returns the same
 *	physical address.
 *
 *	A reserved memory zone cannot be unreserved. The reservation shall
 *	be done at initialization time only.
 *
 * @addtogroup DPAA2_MEMZONE
 * @ingroup DPAA2_RTS
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#define SOCKET_ID_ANY	-1

#define DPAA2_MZ_4KB		BIT_POS(1)  /*!< Use 4KB pages. */
#define DPAA2_MZ_2MB		BIT_POS(2)   /*!< Use 2MB pages. */
#define DPAA2_MZ_4MB		BIT_POS(3)   /*!< Use 4MB pages. */
#define DPAA2_MZ_16MB		BIT_POS(4)   /*!< Use 16MB pages. */
#define DPAA2_MZ_64MB		BIT_POS(5)   /*!< Use 64MB pages. */
#define DPAA2_MZ_256MB		BIT_POS(6)   /*!< Use 256MB pages. */
#define DPAA2_MZ_1GB		BIT_POS(7)   /*!< Use 1GB pages. */
#define DPAA2_MZ_SIZE_HINT_ONLY	BIT_POS(8)   /*!< Use available page size */


#define DPAA2_MZ_SIZES		(DPAA2_MZ_2MB | DPAA2_MZ_1GB)

enum dpaa2_page_sizes {
	DPAA2_PGSIZE_4K = 1 << 12,	/*!< Page size 4K */
	DPAA2_PGSIZE_2M = DPAA2_PGSIZE_4K << 9,	/*!< Huge page size 2 Mb */
	DPAA2_PGSIZE_4M = DPAA2_PGSIZE_2M << 1,	/*!< Huge page size 4 Mb */
	DPAA2_PGSIZE_16M = DPAA2_PGSIZE_4M << 2,	/*!< Huge page size 16 Mb */
	DPAA2_PGSIZE_64M = DPAA2_PGSIZE_16M << 2,	/*!< Huge page size 64 Mb */
	DPAA2_PGSIZE_256M = DPAA2_PGSIZE_64M << 2,/*!< Huge page size 256 Mb */
	DPAA2_PGSIZE_1G = DPAA2_PGSIZE_2M << 9	/*!< Huge page size 1 Gb */
};

#define DPAA2_MZ_NAMESIZE 32	/*!< Maximum length of memory zone name.*/
/*!
 * A structure describing a memzone, which is a contiguous portion of
 * physical memory identified by a name.
 */
struct dpaa2_memzone {

	char name[DPAA2_MZ_NAMESIZE];/* Name of the memory zone. */
	phys_addr_t phys_addr;		/* Start physical address. */
	union {
		void *addr;		/* Start virtual address. */
		uint64_t addr_64;	/* Makes sure addr is always 64-bits */
	};
	size_t len;			/* Length of the memzone. */
	size_t hugepage_sz;		/* The page size of underlying memory */
	int32_t socket_id;		/* Socket ID. */
	uint32_t flags;			/* Characteristics of this memzone. */
	uint32_t memseg_id;		/* store the memzone is from which memseg.*/
	uint32_t align;			/* store alignment for the memzone*/
	uint32_t bound;			/* store bound for the memzone*/
} __attribute__((__packed__));

/*!
 * Reserve a portion of physical memory.
 *
 * This function reserves some memory and returns a pointer to a
 * correctly filled memzone descriptor. If the allocation cannot be
 * done, return NULL. Note: A reserved zone cannot be freed.
 *
 * @param[in] name
 *   The name of the memzone. If it already exists, the function will
 *   fail and return NULL.
 * @param[in] len
 *   The size of the memory to be reserved. If it
 *   is 0, the biggest contiguous zone will be reserved.
 * @param[in] socket_id
 *   There is no concept of NUMA in LS SOC. Hence it is always 0.
 *   The value can be SOCKET_ID_ANY if there is no NUMA
 *   constraint for the reserved zone.
 * @param[in] flags
 *   The flags parameter is used to request memzones to be
 *   taken from specific hugepage size only.
 *   - DPAA2_MZ_2MB - Reserve from 2MB pages, only of ARM
 *   - DPAA2_MZ_4MB - Reserve from 4MB pages, only for PowerPC
 *   - DPAA2_MZ_16MB - Reserve from 16MB pages, only for PowerPC
 *   - DPAA2_MZ_64MB - Reserve from 64MB pages, only for PowerPC
 *   - DPAA2_MZ_256MB - Reserve from 256MB pages, only for PowerPC
 *   - DPAA2_MZ_1GB - Reserve from 1GB pages
 *   - DPAA2_MZ_SIZE_HINT_ONLY - Allow alternative page size to be used if
 *                                  the requested page size is unavailable.
 *                                  If this flag is not set, the function
 *                                  will return error on an unavailable size
 *                                  request.
 * @returns
 *   A pointer to a correctly-filled read-only memzone descriptor, or NULL
 *   on error.
 *   On error case, dpaa2_errno will be set appropriately:
 *    - E_DPAA2_NO_CONFIG - function could not get pointer to dpaa2_config structure
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 *    - EINVAL - invalid parameters
 */
struct dpaa2_memzone *dpaa2_memzone_reserve(const char *name,
					      size_t len, int socket_id,
					      unsigned flags);

/*!
 * Reserve a portion of physical memory with alignment on a specified
 * boundary.
 *
 * This function reserves some memory with alignment on a specified
 * boundary, and returns a pointer to a correctly filled memzone
 * descriptor. If the allocation cannot be done or if the alignment
 * is not a power of 2, returns NULL.
 * Note: A reserved zone cannot be freed.
 *
 * @param[in] name
 *   The name of the memzone. If it already exists, the function will
 *   fail and return NULL.
 * @param[in] len
 *   The size of the memory to be reserved. If it
 *   is 0, the biggest contiguous zone will be reserved.
 * @param[in] socket_id
 *	No concept of NUMA in LS SOC. Always 0.
 *   The value can be SOCKET_ID_ANY if there is no NUMA
 *   constraint for the reserved zone.
 * @param[in] flags
 *   The flags parameter is used to request memzones to be
 *   taken from specific hugepage size only.
 *   - DPAA2_MZ_2MB - Reserve from 2MB pages, only of ARM
 *   - DPAA2_MZ_4MB - Reserve from 4MB pages, only for PowerPC
 *   - DPAA2_MZ_16MB - Reserve from 16MB pages, only for PowerPC
 *   - DPAA2_MZ_64MB - Reserve from 64MB pages, only for PowerPC
 *   - DPAA2_MZ_256MB - Reserve from 256MB pages, only for PowerPC
 *   - DPAA2_MZ_1GB - Reserve from 1GB pages
 *   - DPAA2_MZ_SIZE_HINT_ONLY - Allow alternative page size to be used if
 *                                  the requested page size is unavailable.
 *                                  If this flag is not set, the function
 *                                  will return error on an unavailable size
 *                                  request.
 * @param[in] align
 *   Alignment for resulting memzone. Must be a power of 2.
 * @returns
 *   A pointer to a correctly-filled read-only memzone descriptor, or NULL
 *   on error.
 *   On error case, dpaa2_errno will be set appropriately:
 *    - E_DPAA2_NO_CONFIG - function could not get pointer to dpaa2_config structure
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 *    - EINVAL - invalid parameters
 */
const struct dpaa2_memzone *dpaa2_memzone_reserve_aligned(const char *name,
			size_t len, int socket_id,
			unsigned flags, unsigned align);

/*!
 * Reserve a portion of physical memory with specified alignment and
 * boundary.
 *
 * This function reserves some memory with specified alignment and
 * boundary, and returns a pointer to a correctly filled memzone
 * descriptor. If the allocation cannot be done or if the alignment
 * or boundary are not a power of 2, returns NULL.
 * Memory buffer is reserved in a way, that it wouldn't cross specified
 * boundary. That implies that requested length should be less or equal
 * then boundary.
 * Note: A reserved zone cannot be freed.
 *
 * @param[in] name
 *   The name of the memzone. If it already exists, the function will
 *   fail and return NULL.
 * @param[in] len
 *   The size of the memory to be reserved. If it
 *   is 0, the biggest contiguous zone will be reserved.
 * @param[in] socket_id
 *	NO concept of NUMA in LS SOC. ALways 0.
 *   NUMA. The value can be SOCKET_ID_ANY if there is no NUMA
 *   constraint for the reserved zone.
 * @param[in] flags
 *   The flags parameter is used to request memzones to be
 *   taken from specific hugepage size only.
 *   - DPAA2_MZ_2MB - Reserve from 2MB pages, only of ARM
 *   - DPAA2_MZ_4MB - Reserve from 4MB pages, only for PowerPC
 *   - DPAA2_MZ_16MB - Reserve from 16MB pages, only for PowerPC
 *   - DPAA2_MZ_64MB - Reserve from 64MB pages, only for PowerPC
 *   - DPAA2_MZ_256MB - Reserve from 256MB pages, only for PowerPC
 *   - DPAA2_MZ_1GB - Reserve from 1GB pages
 *   - DPAA2_MZ_SIZE_HINT_ONLY - Allow alternative page size to be used if
 *                                  the requested page size is unavailable.
 *                                  If this flag is not set, the function
 *                                  will return error on an unavailable size
 *                                  request.
 * @param[in] align
 *   Alignment for resulting memzone. Must be a power of 2.
 * @param[in] bound
 *   Boundary for resulting memzone. Must be a power of 2 or zero.
 *   Zero value implies no boundary condition.
 * @returns
 *   A pointer to a correctly-filled read-only memzone descriptor, or NULL
 *   on error.
 *   On error case, dpaa2_errno will be set appropriately:
 *    - E_DPAA2_NO_CONFIG - function could not get pointer to dpaa2_config structure
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 *    - EINVAL - invalid parameters
 */
const struct dpaa2_memzone *dpaa2_memzone_reserve_bounded(const char *name,
			size_t len, int socket_id,
			unsigned flags, unsigned align, unsigned bound);


/*!
 * Free the memzone and it's memory.
 *
 * @param[in] name
 *   The name of the memzone.
 * @returns
 *   DPAA2_SUCCESS or DPAA2_FAILURE
 */
int dpaa2_memzone_free(struct dpaa2_memzone *mzone);

/*!
 * Lookup for a memzone.
 *
 * Get a pointer to a descriptor of an already reserved memory
 * zone identified by the name given as an argument.
 *
 * @param[in] name
 *   The name of the memzone.
 * @returns
 *   A pointer to a memzone descriptor.
 */
struct dpaa2_memzone *dpaa2_memzone_lookup(const char *name);

/*!
 * Dump all reserved memzones to the console.
 *
 * @param[in] f
 *	A pointer to a file for output
 */
void dpaa2_memzone_dump(FILE *f);


/*!
 * Dump a given memzone.
 *
 * @param[in] f
 *   A pointer to a file for output.
 * @param[in] mzone
 *   Pointer to a given memzone.
 */
void dpaa2_memzone_dump_one(FILE *f, const void_t *mzone);

/*!
 * Return the size of a given memzone.
 *
 * @param[in] mzone
 *   Pointer to a given memzone.
 * @returns
 *   Size of the given memzone.
 */
static inline size_t dpaa2_memzone_size(void_t *mzone)
{
	if (mzone)
		return ((struct dpaa2_memzone *)mzone)->len;
	else
		return 0;
}

/*!
 * Return the virtual addr of a given memzone.
 *
 * @param[in] mzone
 *   Pointer to a given memzone.
 * @returns
 *   virtual addr of the given memzone.
 */
static inline uintptr_t dpaa2_memzone_virt(void_t *mzone)
{
	if (mzone)
#ifdef	CONFIG_64BIT
		return (uintptr_t)((struct dpaa2_memzone *)mzone)->addr_64;
#else
		return (uintptr_t)((struct dpaa2_memzone *)mzone)->addr;
#endif
	else
		return (uintptr_t)0;
}


/*!
 * Walk list of all memzones
 *
 * @param[in] func
 *   Iterator function
 * @param[in] arg
 *   Argument passed to iterator
 */
void dpaa2_memzone_walk(void (*func)(const struct dpaa2_memzone *, void *arg),
		void *arg);

#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _DPAA2_MEMZONE_H_ */
