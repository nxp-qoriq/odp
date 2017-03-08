/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP buffer pool - internal header
 */

#ifndef ODP_POOL_INTERNAL_H_
#define ODP_POOL_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/api/std_types.h>
#include <odp/api/align.h>
#include <odp_align_internal.h>
#include <odp/api/pool.h>
#include <odp/api/hints.h>
#include <odp_config_internal.h>
#include <odp/api/debug.h>
#include <odp/api/shared_memory.h>
#include <odp/api/atomic.h>
#include <odp_atomic_internal.h>
#include <odp_buffer_internal.h>

#include <string.h>
/* for DPAA2 */
#include <odp/api/plat/sdk/rts/dpaa2_mpool.h>

/**
 * Buffer initialization routine prototype
 *
 * @note Routines of this type MAY be passed as part of the
 * _odp_buffer_pool_init_t structure to be called whenever a
 * buffer is allocated to initialize the user metadata
 * associated with that buffer.
 */
typedef void (_odp_buf_init_t)(odp_buffer_t buf, void *buf_init_arg);

/* Use ticketlock instead of spinlock */
#define POOL_USE_TICKETLOCK

/* Extra error checks */
/* #define POOL_ERROR_CHECK */


#ifdef POOL_USE_TICKETLOCK
#include <odp/api/ticketlock.h>
#define POOL_LOCK(a)      odp_ticketlock_lock(a)
#define POOL_UNLOCK(a)    odp_ticketlock_unlock(a)
#define POOL_LOCK_INIT(a) odp_ticketlock_init(a)
#else
#include <odp/api/spinlock.h>
#define POOL_LOCK(a)      odp_spinlock_lock(a)
#define POOL_UNLOCK(a)    odp_spinlock_unlock(a)
#define POOL_LOCK_INIT(a) odp_spinlock_init(a)
#endif

struct pool_entry_s {
#ifdef POOL_USE_TICKETLOCK
	odp_ticketlock_t        lock ODP_ALIGNED_CACHE;
	odp_ticketlock_t        buf_lock;
	odp_ticketlock_t        blk_lock;
#else
	odp_spinlock_t          lock ODP_ALIGNED_CACHE;
	odp_spinlock_t          buf_lock;
	odp_spinlock_t          blk_lock;
#endif
	char                    name[ODP_POOL_NAME_LEN];
	odp_pool_param_t        params;
	void			*int_hdl;
	uint32_t                pool_id;
	odp_shm_t               pool_shm;
	union {
		uint32_t all;
		struct {
			uint32_t has_name:1;
			uint32_t user_supplied_shm:1;
			uint32_t unsegmented:1;
			uint32_t zeroized:1;
			uint32_t predefined:1;
		};
	} flags;
	size_t                  pool_size;
	uint32_t                headroom;
	uint32_t                tailroom;
	uint16_t		bpid;
};

typedef union pool_entry_u {
	struct pool_entry_s s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pool_entry_s))];
} pool_entry_t;

extern void *pool_entry_ptr[];

static inline void *get_blk(struct pool_entry_s *pool)
{
	return dpaa2_mpool_getblock((void *)pool->int_hdl, NULL);
}

static inline void ret_blk(struct pool_entry_s *pool, void *block)
{
	dpaa2_mpool_relblock((void *)pool->int_hdl, block);
}

static inline odp_buffer_hdr_t *get_buf(struct pool_entry_s *pool)
{
	odp_buffer_hdr_t *buf = (odp_buffer_hdr_t *)get_blk(pool);
	if (!buf)
		return ODP_BUFFER_INVALID;
	buf->buf_pool = (uint64_t)pool;
	/* the actual data starts just after the buffer */
	buf->data = (uint8_t *)(buf + 1);
	return buf;
}

static inline void ret_buf(struct pool_entry_s *pool, odp_buffer_hdr_t *buf)
{
	ret_blk(pool, buf);
}


static inline uint32_t dpaa2_handle_to_index(void *int_hdl)
{
	int i = ODP_BUFFER_MAX_POOLS;
	for (i = 0; i <= ODP_BUFFER_MAX_POOLS; i++)
		if (((pool_entry_t *)pool_entry_ptr[i])->s.int_hdl == int_hdl)
			break;
	return i;
}

static inline uint32_t bpid_to_index(uint16_t bpid)
{
	int i;
	for (i = 0; i < ODP_BUFFER_MAX_POOLS; i++)
		if (((pool_entry_t *)pool_entry_ptr[i])->s.bpid == bpid)
			break;
	return i;
}

static inline void *get_pool_entry(uint32_t pool_id)
{
	if (pool_id >= ODP_BUFFER_MAX_POOLS)
		return NULL;
	return pool_entry_ptr[pool_id];
}

static inline pool_entry_t *odp_pool_to_entry(odp_pool_t pool)
{
	if (pool != ODP_POOL_INVALID)
		return (pool_entry_t *)pool;
	else
		return NULL;
}

static inline pool_entry_t *odp_buf_to_pool(odp_buffer_hdr_t *buf)
{
	/* for packet buffer, head will always be set*/
	if (buf->head) {
		int i = bpid_to_index(buf->bpid);
		return ((pool_entry_t *)pool_entry_ptr[i]);
	} else {
		return (pool_entry_t *) (buf->buf_pool);
	}
}

/**
 * Find a pool by name, name as provided by user
 *
 * @param name Name of the pool like dpbp.x
 *
 * @return Handle of found pool
 *
 * @retval ODP_POOL_INVALID  Pool could not be found
 *
 * @note This routine can be used while debugging and getting counters.
 * (when PLAT_DEBUG_THREAD is enabled)
 *
 */
odp_pool_t odp_debug_pool_lookup(const char *name);

int pool_type_is_packet(odp_pool_t pool);

#ifdef __cplusplus
}
#endif

#endif
