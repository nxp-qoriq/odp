/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

#ifndef DPAA2_MPOOL_INTERNAL_H
#define DPAA2_MPOOL_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif

#include <dpaa2_mpool.h>
#include <odp/api/atomic.h>
#include <dpaa2_lock.h>

struct dpaa2_pool_link_node {
	char heap;
	struct dpaa2_pool_link_node *pNext;
};

struct dpaa2_pool {
	char name[DPAA2_MAX_POOL_NAME_LEN];
	char in_use;
	lock_t pool_mutex;
	void *p_memory;
	struct dpaa2_pool_link_node *head;
	struct dpaa2_pool_link_node *tail;
	unsigned int align_size;
	unsigned int data_size;
	unsigned int data_elem_size;
	unsigned int priv_data_size;/* Size of private data */
	uint64_t zone_size;
	uintptr_t phys_addr;
	uintptr_t virt_addr;
	unsigned int num_allocs;
	unsigned int num_heap_allocs;
	unsigned int num_frees;
	unsigned int num_per_core_static_entries;
	unsigned int num_per_core_max_entries;
	unsigned int num_entries;
	unsigned int num_max_entries;
};

struct dpaa2_shm_meta {
	int offset;
};

int dpaa2_mpool_init(void);
void dpaa2_mpool_exit(void);

struct dpaa2_pool *dpaa2_getfree_pool(void);

#ifdef __cplusplus
}
#endif

#endif /* DPAA2_MPOOL_INTERNAL_H */
