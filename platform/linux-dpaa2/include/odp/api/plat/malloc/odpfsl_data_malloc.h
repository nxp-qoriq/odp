/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * Copyright(c) 2010-2014 Intel Corporation.
 * All rights reserved.
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP extension API's for memory allocations from the dma-able memory.
 */

#ifndef ODP_DATA_MALLOC_H
#define ODP_DATA_MALLOC_H

/** @defgroup odpfsl_data_malloc ODPFSL DATA MALLOC
 *  ODP extension to support dma-able memory allocation
 *  @{
 */

#include <stdio.h>
#include <odp/api/std_types.h>

/*!
 * This function allocates memory from the huge-page area of memory. The memory
 * is not cleared.
 *
 * @param type
 *   A string identifying the type of allocated objects (useful for debug
 *   purposes, such as identifying the cause of a memory leak). Can be NULL.
 * @param size
 *   Size (in bytes) to be allocated.
 * @param align
 *   If 0, the return is a pointer that is suitably aligned for any kind of
 *   variable (in the same manner as malloc()).
 *   Otherwise, the return is a pointer that is a multiple of *align*. In
 *   this case, it must be a power of two. (Minimum alignment is the
 *   cacheline size, i.e. 64-bytes)
 * @return
 *   - NULL on error. Not enough memory, or invalid arguments (size is 0,
 *     align is not a power of two).
 *   - Otherwise, the pointer to the allocated object.
 */
void *
odpfsl_data_malloc(const char *type, size_t size, unsigned align);

/*!
 * Allocate zero'ed memory from the heap.
 *
 * Equivalent to odpfsl_data_malloc() except that the memory zone is
 * initialised with zeros.
 *
 * @param type
 *   A string identifying the type of allocated objects (useful for debug
 *   purposes, such as identifying the cause of a memory leak). Can be NULL.
 * @param size
 *   Size (in bytes) to be allocated.
 * @param align
 *   If 0, the return is a pointer that is suitably aligned for any kind of
 *   variable (in the same manner as malloc()).
 *   Otherwise, the return is a pointer that is a multiple of *align*. In
 *   this case, it must obviously be a power of two. (Minimum alignment is the
 *   cacheline size, i.e. 64-bytes)
 * @return
 *   - NULL on error. Not enough memory, or invalid arguments (size is 0,
 *     align is not a power of two).
 *   - Otherwise, the pointer to the allocated object.
 */
void *
odpfsl_data_zmalloc(const char *type, size_t size, unsigned align);

/*!
 * Replacement function for calloc(), using huge-page memory. Memory area is
 * initialised with zeros.
 *
 * @param type
 *   A string identifying the type of allocated objects (useful for debug
 *   purposes, such as identifying the cause of a memory leak). Can be NULL.
 * @param num
 *   Number of elements to be allocated.
 * @param size
 *   Size (in bytes) of a single element.
 * @param align
 *   If 0, the return is a pointer that is suitably aligned for any kind of
 *   variable (in the same manner as malloc()).
 *   Otherwise, the return is a pointer that is a multiple of *align*. In
 *   this case, it must obviously be a power of two. (Minimum alignment is the
 *   cacheline size, i.e. 64-bytes)
 * @return
 *   - NULL on error. Not enough memory, or invalid arguments (size is 0,
 *     align is not a power of two).
 *   - Otherwise, the pointer to the allocated object.
 */
void *
odpfsl_data_calloc(const char *type, size_t num, size_t size, unsigned align);

/*!
 * Replacement function for realloc(), using huge-page memory. Reserved area
 * memory is resized, preserving contents.
 *
 * @param ptr
 *   Pointer to already allocated memory
 * @param size
 *   Size (in bytes) of new area. If this is 0, memory is freed.
 * @param align
 *   If 0, the return is a pointer that is suitably aligned for any kind of
 *   variable (in the same manner as malloc()).
 *   Otherwise, the return is a pointer that is a multiple of *align*. In
 *   this case, it must obviously be a power of two. (Minimum alignment is the
 *   cacheline size, i.e. 64-bytes)
 * @return
 *   - NULL on error. Not enough memory, or invalid arguments (size is 0,
 *     align is not a power of two).
 *   - Otherwise, the pointer to the reallocated memory.
 */
void *
odpfsl_data_realloc(void *ptr, size_t size, unsigned align);

/*!
 * Frees the memory space pointed to by the provided pointer. This pointer
 * must have been returned by a previous call to odpfsl_data_malloc(),
 * odpfsl_data_zmalloc(), odpfsl_data_calloc() or odpfsl_data_realloc().
 * The behaviour of odpfsl_data_free() is undefined if the pointer does not
 * match this requirement. If the pointer is NULL, the function does nothing.
 *
 * @param ptr
 *   The pointer to memory to be freed.
 */
void
odpfsl_data_free(void *ptr);

/*!
 * If malloc debug is enabled, check a memory block for header
 * and trailer markers to indicate that all is well with the block.
 * If size is non-null, also return the size of the block.
 *
 * @param ptr
 *   pointer to the start of a data block, must have been returned
 *   by a previous call to odpfsl_data_malloc(), odpfsl_data_zmalloc(),
 *   odpfsl_data_calloc() or odpfsl_data_realloc()
 * @param size
 *   if non-null, and memory block pointer is valid, returns the size
 *   of the memory block
 * @return
 *   -1 on error, invalid pointer passed or header and trailer markers
 *   are missing or corrupted
 *   0 on success
 */
int
odpfsl_data_malloc_validate(const void *ptr, size_t *size);

/*!
 * Set the maximum amount of allocated memory for this type.
 *
 * This is not yet implemented
 *
 * @param type
 *   A string identifying the type of allocated objects.
 * @param max
 *   The maximum amount of allocated bytes for this type.
 * @return
 *   - 0: Success.
 *   - (-1): Error.
 */
int
odpfsl_data_malloc_set_limit(const char *type, size_t max);

/*!
 * Return the physical address of a virtual address obtained through
 * odpfsl_data_malloc
 *
 * @param addr
 *   Address obtained from a previous odpfsl_data_malloc call
 * @return
 *   NULL on error
 *   otherwise return physical address of the buffer
 */
phys_addr_t
odpfsl_data_malloc_virt2phy(const void *addr);

/**
 * @}
 */

#endif /* _ODPFSL_DATA_MALLOC_H_ */
