/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */

#ifndef __FSL_SHBP_H
#define __FSL_SHBP_H

/*!
 * @file	fsl_shbp.h
 *
 * @brief Shared Buffer Pool (b/w GPP and AIOP) API's for GPP.
 *
 * @addtogroup DPAA2_CMDIF
 * @ingroup DPAA2_DEV
 * @{
 */

/* DPAA2 header files */
#include <odp/api/std_types.h>

/*! GPP is the allocation master */
#define SHBP_GPP_MASTER		0x1

/*! This is an internal DPAA2 SHBP structure, not required
 * to be known to the user */
struct shbp;

/*!
 * @details	Calculator for 'mem_ptr' size for shbp_create(). num_bufs must
 *		be 2^x and higher than 8.
 *
 * @param[in]	num_bufs - Number of buffers which will be added into the
 *		SHBP pool. num_bufs must be 2^x and higher than 8.
 *
 * @returns	The 'mem_ptr' size required by shbp_create()
 *
 */
uint64_t shbp_mem_ptr_size(uint32_t num_bufs);

/*!
 * @details	Get buffer from shared pool
 *
 * @param[in]	bp - Buffer pool handle
 *
 * @returns	Address on Success; or NULL code otherwise
 *
 */
void *shbp_acquire(struct shbp *bp);

/*!
 * @details	Return or add buffer into the shared pool
 *
 * @param[in]	bp  - Buffer pool handle
 * @param[in]	buf - Pointer to buffer
 *
 * @returns	0 on Success; or POSIX error code otherwise
 *
 */
int shbp_release(struct shbp *bp, void *buf);

/*!
 * @details	Create shared pool from a given buffer
 *
 * The shared pool is created as empty, use shbp_release() to fill it
 *
 * @param[in]	mem_ptr  - Pointer to memory to be used for shared management;
 *		it should be aligned to cache line
 * @param[in]	size     - Size of mem_ptr
 * @param[in]	flags    - Flags to be used for pool creation, 0 means AIOP is
 *		the allocation master. See #SHBP_GPP_MASTER.
 * @param[out]  bp       - Pointer to shared pool handle
 *
 * @returns	0 on Success; or POSIX error code otherwise
 *
 *
 */
int shbp_create(void *mem_ptr, uint32_t size, uint32_t flags, struct shbp **bp);

/*!
 * @details	Move free buffers into allocation queue
 *
 * @param[in]	bp  - Buffer pool handle
 *
 * @returns	POSIX error code on failure or the number of the buffers added
 *		to the allocation queue
 *
 */
int shbp_refill(struct shbp *bp);


/*!
 * @details	Returns the pointers from pool that need to be freed upon pool
 *		destruction
 *
 * Pointer to struct shbp will not be returned by shbp_destroy() but it
 * must be freed by user
 *
 * @param[in]	bp       - Buffer pool handle
 * @param[out]	ptr      - Pointer to be freed for pool destruction
 *
 * @returns	POSIX error code until there are buffers inside shared pool
 *		that need to be freed, 0 if there are no buffers to be freed
 *
 */
int shbp_destroy(struct shbp *bp, void **ptr);

/*! @} */
#endif
